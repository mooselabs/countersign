# Approvers

An approver is the part of countersign that turns a pending request into a
human decision. It is the security boundary of the whole tool: everything else
(the agent, `cn`, the shell, the transcript) runs as the developer's uid and
can be driven by the agent. This document defines the approver interface, how
approvers are combined, the three adapters (`polkit`, `fido2`, `command`),
the trusted-display problem, and the default recommended for the owner's
machine. Phase 1 builds the `polkit` adapter only (decision 14); `fido2` and
`command` are Phase 2.

Related: request codes and the canonical request digest are specified in
[design.md](design.md#6-grants); the threats referred to as T3, T4, T13 and
T16 are in [threat-model.md](threat-model.md); the commands are in
[cli.md](cli.md).

## What an approval must establish

An approval has to show two things:

1. **Presence.** A human, not the agent, took an action: touched the key,
   answered a dialog the agent cannot type into.
2. **Intent.** The human saw *this* request (these secrets, this mode, this
   TTL, this session) and agreed to it.

Presence is solved by hardware or by an input path the agent cannot reach.
Intent is harder: it needs the request to be shown on a surface the agent
cannot alter. That is the [trusted-display problem](#the-trusted-display-problem),
and it decides the recommended default.

What an approver never has to establish is the integrity of what was
approved. `cnd` builds the canonical request, computes its digest, and makes
the polkit call itself (in Phase 2 it also verifies FIDO2 signatures over its
own digest). No client can change what a successful approval applies to.

## Approval kinds

Each request has a kind, and config chooses an approver chain per kind:

| Kind | Raised by | Typical stakes |
| --- | --- | --- |
| `use` | `cn request` (default mode) | A value is injected into a child process for up to `max_ttl`. |
| `reveal` | `cn request --mode reveal` | A raw value goes wherever the caller's stdout goes, permanently. |
| `mutate` | `cn add`, `set`, `edit`, `rm`, `import` | Store contents or prose change for every later session. |
| `export` | `cn export` (Phase 2) | The whole store, decrypted, goes to an age recipient. |

## The interface

`countersign-approve` runs approvers; the chain and approver config types
belong to `countersign_core::config`, and `ApprovalKind` and the digest to
`countersign_proto`. Phase 1 has daemon-driven approvers only. In outline:

```rust
/// Everything an approver is given. Built once per request by cnd; fields
/// are read through accessors.
pub struct ApprovalRequest {
    request_id: String,       // "r_...", from the canonical request
    canonical: Vec<u8>,       // RFC 8785 (JCS) bytes of the canonical request (design.md section 6)
    digest: [u8; 32],         // SHA-256 of `canonical`, computed here so the two cannot disagree
    digest_short: String,     // "3QF8-ZK2M", the same function cn uses
    code: String,             // "K7M-Q2X"
    kind: ApprovalKind,       // Use | Reveal | Mutate | Export
    display: DisplayView,     // sanitised, length-limited strings; never values
    session: SessionRef,      // uid, anchor pid, start time and comm, logind session if known
    expires_at: SystemTime,
}

pub enum Outcome {
    Approved(Evidence),
    Denied(Evidence),
}

pub enum ApproverError {
    /// Cannot run here: polkitd not on the bus, no authentication agent for
    /// the subject, no graphical session, not Wayland under require_wayland.
    Unavailable(String),
    /// The request expired, or the dialog's own timeout ran out.
    Timeout,
    /// cnd withdrew the request, or another any_of member decided.
    Cancelled,
    /// A response arrived and failed verification. No Phase 1 adapter
    /// returns it.
    Invalid(String),
    /// Bug, misconfiguration or system fault. Fails closed.
    Internal(String),
}

/// Recorded in the audit log with the request.approve / request.deny record.
pub struct Evidence {
    pub approver: String,           // configured instance name: "polkit"
    pub adapter: &'static str,      // "polkit"
    pub at: SystemTime,
    pub detail: serde_json::Value,  // adapter-specific; never values
}

/// cnd runs the whole interaction (polkit; later command).
pub trait DaemonApprover: Send + Sync {
    fn info(&self) -> ApproverInfo;   // name, adapter, trusted_display, notes
    fn present<'a>(
        &'a self,
        req: &'a ApprovalRequest,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Outcome, ApproverError>>;
}

/// Runs a chain (countersign_core::config::Chain: One, AllOf, AnyOf) against
/// the configured instances and reports every member's result.
pub async fn evaluate(
    chain: &Chain,
    registry: &Registry,
    req: &ApprovalRequest,
    cancel: &CancellationToken,
) -> ChainReport; // { result: Result<Decision, ApproverError>, members }
```

`present` honours the cancellation token and `expires_at`, and dropping the
future or cancelling it withdraws the prompt (for polkit,
`CancelCheckAuthorization`). `ApproverInfo.trusted_display` is false for the
polkit process subject and true for the session subject; `config.load`
records it. Phase 2 adds a `ClientApprover` trait for `fido2`, where `cnd`
issues a challenge, `cn approve` answers it and `cnd` verifies it.

Rules every adapter follows:

- The only request data an adapter may show a human is `display`, and it shows
  agent-supplied fields labelled as such ("Agent's reason: ...").
- An adapter never receives a secret value. Even a `mutate` request carries
  only the value's length class and source.
- `Evidence.detail` must be enough for a later reader to tell what happened,
  and where possible to re-check it (FIDO2 will store the signature).
- `present` must honour `cancel` and `expires_at`. An adapter that cannot
  cancel (a running command) is killed.

## Daemon-driven and client-driven

| | Daemon-driven | Client-driven (Phase 2) |
| --- | --- | --- |
| Adapters | `polkit`; `command` in Phase 2 | `fido2` |
| Who starts it | `cnd`, as soon as the request is created | The human, by running `/usr/bin/cn approve CODE` |
| Where the request is displayed | A surface outside the developer's uid's control: the compositor's polkit dialog, a phone | `cn`'s output in the terminal, inside the agent's environment |
| Where the decision is made | polkitd / the command | The security key, then `cnd` verifies the assertion |
| What the agent can do | Nothing beyond creating requests (rate-limited) | Run `cn approve` itself (reaches the touch prompt and stops), or tamper with what the terminal shows |

`cnd` runs as `countersign` and cannot open the developer's session bus or
draw on the desktop. polkit is the standard way for a system service to get an
authenticated decision from the user at the desktop, which is why it is the
only daemon-driven adapter with a trusted display in v1.

## Chaining

Config gives each kind a chain. A chain is an approver name, or `all_of` /
`any_of` over chains, nested at most three levels. Approver instance names
use lower-case letters, digits and `-`. A Phase 2 example:

```toml
[approval]
use    = "polkit"
reveal = { all_of = ["polkit", "desk-key"] }
mutate = { all_of = ["polkit", "desk-key"] }
export = { all_of = ["polkit", "desk-key"] }
```

### `all_of`

- Every member must approve. Members run in listed order, one at a time, so
  the human is never asked for two things at once.
- The first `Denied` denies the request; later members are not asked.
- Any error (`Unavailable`, `Timeout`, `Invalid`, `Internal`) ends the chain
  with that error; later members are not asked.

### `any_of`

- Every member starts when the request is created.
- The first approval or denial decides and cancels the others, and the chain
  waits up to 5 seconds for them to withdraw their prompts. A `Denied` from
  any member denies the request: an explicit no is never overridden by
  trying another approver.
- `Internal` from any member ends the chain with that error (fail closed).
- `Unavailable`, `Timeout` and `Invalid` members are skipped. If no member
  decides, the chain ends with the first error that is not `Unavailable`, or
  with `Unavailable` when every member was unavailable.

### How `cnd` ends the request

| Chain result | Request | Audit |
| --- | --- | --- |
| Approved | approved: the grant becomes active, or the store change commits | `request.approve` per approving member |
| Denied | denied; the secrets go into deny cooldown for the uid, in every session | `request.deny` per denying member |
| `Timeout` | expired | `request.expire` |
| `Cancelled` | as `cnd` set it when it cancelled (`cn deny`, expiry, the anchor's exit) | |
| `Unavailable`, `Invalid`, `Internal` | denied by `cnd`, with the reason; no deny cooldown. When no approver could run, the decision carries `error: approver_unavailable` (`cn` exit 14). | `request.deny` with approver `cnd` and `evidence.error` |

Phase 1 has no way to raise a dialog again for the same request. After a
timeout or an unavailable approver, the agent requests again.

### Strength of a chain

An `any_of` chain is as weak as its weakest member, for presence and for
intent. If `use = { any_of = ["polkit", "desk-key"] }`, an approval can always
come from `desk-key` through `cn approve`, whose display is the terminal, even
while a polkit dialog is open. A chain's display strength is the strength of
the strongest display that *every* approving path must pass through.

An `any_of` also invites downgrade: if the agent can make the stronger member
`Unavailable` (for example by running in a session with no polkit agent), the
weaker one decides. Use `any_of` for convenience across environments, knowing
it costs the stronger member's guarantees.

## The trusted-display problem

The human approves what they see. The agent's goal, if it is malicious, is to
make the human see request A while approving request B.

### Which surfaces the agent can alter

| Surface | Rendered by | Can a same-uid agent change what it shows? |
| --- | --- | --- |
| `cn approve` output in a `!` command | `cn`, run by the agent's shell, in the agent's environment, output in the agent's transcript | Yes: see below. |
| `cn approve` in a separate terminal the human opened | `cn` under the human's shell | Yes, if the agent has edited rc files, `PATH` directories or the terminal profile beforehand. No, if not. |
| GNOME Shell polkit dialog (Wayland) | gnome-shell, from text polkitd received from `cnd` | Not the dialog itself. But with the Phase 1 process subject the agent can register its own authentication agent for the anchor and draw the prompt instead (decision 15). A persistent agent can also install a GNOME Shell extension that runs inside the shell after the next login. |
| Polkit dialog on X11 | the polkit agent | Input can be synthesized (XTEST) and the screen read; not trusted. |
| A phone app showing a push (via `command`) | a separate device | No, if the response is authenticated. |
| The YubiKey | no display | Shows nothing. A touch proves presence only. |

### How a terminal display is subverted

In Phase 1 the terminal is only a cross-check: `cn approve` prints the
request, and the approval is the dialog. This section matters for the Phase 2
`fido2` path, where the terminal is the approver's display.

`!` commands in Claude Code run in the same shell setup as the agent's Bash
tool: same uid, same environment, the same shell snapshot the harness sources
before each command. Any of these lets an agent show request A while the touch
signs request B:

- a `cn` earlier on `PATH` (`~/.local/bin`, `~/bin`, a project `bin/` added by
  direnv);
- an alias or function named `cn`; bash also accepts a function named
  `/usr/bin/cn`, so typing the absolute path does not bypass a function;
- edits to `~/.bashrc`, `~/.profile`, fish config, or the harness's shell
  snapshot;
- a modified harness binary (the Claude Code native install is under
  `~/.local`, writable by the uid);
- a terminal emulator profile that runs a wrapper.

The substitute shows A's details and A's short digest, but asks `cnd` for B's
challenge and has the key sign B's digest. `cnd` verifies a correct signature
over B and grants B. `cn` being non-dumpable and `cn approve` refusing a
tracer stop only ptrace tricks against the genuine binary.
Nothing in the terminal can prove it is genuine to the human reading it.

This attack needs a deliberately malicious agent that plans ahead. A careless
or confused agent will not do it. That is why the terminal path is acceptable
as a fallback and not as the default.

### How the polkit display is subverted, and what stops it

| Attack | Mitigation |
| --- | --- |
| `cnd` passes the session anchor as a `unix-process` subject (the Phase 1 default, decision 15); a same-uid agent registers its own per-process authentication agent for it (as `pkttyagent --process` does) and receives the prompt instead of gnome-shell. | The prompt still runs the human's factor through PAM: a hijacking agent can draw its own prompt, but it gets an approval only if the human types their password into it or touches the key. It spoofs the display; it does not bypass approval. A careless or confused agent does not do this. With `subject = "session"`, once polkit-org/polkit#699 is fixed, one authentication agent per session is allowed and gnome-shell holds it. |
| The agent draws a lookalike dialog. | A lookalike collects nothing: with `pam_u2f`, the touch only completes the real PAM conversation run by `polkit-agent-helper-1`. On GNOME Wayland, client windows cannot cover the shell's modal dialog, so the real one is visible. |
| The agent ptraces gnome-shell. | gnome-shell is not a descendant of the agent; Yama `ptrace_scope=1` refuses. |
| The agent synthesizes a click or keystrokes in the dialog. | Not possible on Wayland. On X11 it is. `cn doctor` warns in an X11 session, and the polkit adapter refuses unless the uid's logind graphical session is Wayland (`require_wayland = true`, the default). |
| The agent installs a GNOME Shell extension that rewrites the dialog. | Takes effect after the next login or shell restart. Lock user extensions off through the system dconf database (below), or accept the residual risk. |
| The agent spams requests until one is approved by habit. | Limits on pending requests and request rate, per session and per uid, so a new session does not reset them; at most two dialogs open at once per uid (`[limits] max_prompts_per_uid`), the rest wait their turn; a cooldown after a deny, for the uid in every session; the dialog says how the session was found and shows the agent's reason as the agent's. |
| A polkit rule or a `*_keep` default makes later checks pass without a prompt. | Writing either needs root. Phase 1 does not detect it: `cnd` logs polkitd's version at start but does not test the actions, and `cn doctor` does not read the policy or the rules. Check the installed policy and `/etc/polkit-1/rules.d/` yourself. |

### Cross-checking codes and digests

Every surface shows the request code and short digest, and the agent is told
to repeat them in its message to the human. Comparing the polkit dialog with
the agent's message catches a confused agent that mixed up requests. It does
not help on the terminal-only path, where both the message and the display
come from the agent's side.

### Conclusion

Presence is solved by every adapter. Intent is only solved where the display
is rendered outside the developer's uid's control: the polkit dialog on
Wayland, against an agent that has not planted persistence in the desktop, or
a separate device. The default below follows from that.

In Phase 1, with the process subject, the polkit dialog is a trusted display
against careless and confused agents. A deliberately malicious same-uid agent
can take the prompt over (above) and show something else while the human
supplies their factor.

---

## Adapter: `polkit`

Daemon-driven. `cnd` asks polkitd to authorize an action for the session
anchor (the agent process); polkitd asks the authentication agent of that
process's login session (gnome-shell on GNOME) to authenticate the user, and
the shell shows its dialog.

### Actions

The package installs
[`packaging/computer.mooselabs.countersign.policy`](../packaging/computer.mooselabs.countersign.policy)
as `/usr/share/polkit-1/actions/computer.mooselabs.countersign.policy`. Its
actions, which that file must match:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>countersign</vendor>
  <vendor_url>https://github.com/mooselabs/countersign</vendor_url>

  <action id="computer.mooselabs.countersign.approve">
    <description>Approve use of a secret by an agent session</description>
    <message>countersign request $(code), digest $(digest): USE $(secrets) for $(ttl). $(session). Agent's reason: $(reason)</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:countersign</annotate>
  </action>

  <action id="computer.mooselabs.countersign.reveal">
    <description>Reveal a secret value to an agent session</description>
    <message>countersign request $(code), digest $(digest): REVEAL $(secrets) to the agent; the value enters its transcript permanently. $(session). Agent's reason: $(reason)</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:countersign</annotate>
  </action>

  <action id="computer.mooselabs.countersign.mutate">
    <description>Change or export the countersign secret store</description>
    <message>countersign request $(code), digest $(digest): $(operation). $(session).</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:countersign</annotate>
  </action>
</policyconfig>
```

Every message starts with "countersign", the request code and the short
digest. GNOME and `pkexec` shorten a long message by cutting its middle (spike
finding 7), and the human must be able to tell countersign's dialog from any
other polkit prompt.

`export` uses the `mutate` action with an `operation` text that says so.

Notes on the defaults:

- **`auth_self`**: the session's user authenticates as themselves, with the
  factor chosen at install ([below](#approval-factor-password-or-key-touch)):
  their password, a key touch, or both.
- **`auth_admin`**: an administrator authenticates. On openSUSE the default
  admin identity is root, so this asks for the root password. It is useful
  only if you want approval to need a credential the developer's day-to-day
  password is not; with `pam_u2f` it adds nothing for a solo developer.
- **Never `auth_self_keep` or `auth_admin_keep`.** polkit then remembers the
  authorization for the subject for a few minutes, so the next request in the
  same session would be approved with no prompt. Never `yes`.
- **`allow_any` and `allow_inactive` are `no`**: no approvals from ssh
  sessions or a session that is not in the foreground on its seat.
- **`org.freedesktop.policykit.owner`** lets a non-root caller (`cnd` as
  `countersign`) check this action for another user's subject. Without it
  polkitd refuses the call. Needs polkit 0.114 or later.

### The call

`cnd` calls, on the system bus, with `zbus`:

```text
org.freedesktop.PolicyKit1.Authority.CheckAuthorization(
    subject         = ("unix-process", {"pid": <u 41210>,
                                        "start-time": <t 8812345>,
                                        "uid": <i 1000>}),
    action_id       = "computer.mooselabs.countersign.approve",
    details         = {"code": "K7M-Q2X",
                       "digest": "3QF8-ZK2M",
                       "secrets": "clickhouse-password",
                       "ttl": "30m",
                       "session": "agent claude (pid 41210, registered by cn session exec); agent-reported: label \"orchestrator\", cwd \"~/projects/moose/liskov-agent-orchestrator\"",
                       "reason": "row counts for the weekly cost report via ...",
                       "operation": "none"},
    flags           = 0x1,           # AllowUserInteraction
    cancellation_id = "countersign-r_9w1k...-1")
  -> (is_authorized: b, is_challenge: b, details: a{ss})
```

The dialog then reads:

```text
countersign request K7M-Q2X, digest 3QF8-ZK2M: USE clickhouse-password for 30m.
agent claude (pid 41210, registered by cn session exec); agent-reported: label
"orchestrator", cwd "~/projects/moose/liskov-agent-orchestrator".
Agent's reason: row counts for the weekly cost report via ...
```

- **Subject.** Config `[approvers.polkit] subject = "process" | "session"`,
  default `"process"` (decision 15).
  - `"process"`: the session anchor, the long-lived agent process `cnd`
    resolved for the request (design.md section 5), as a `unix-process`
    subject with its `pid`, `start-time` (field 22 of `/proc/PID/stat`) and
    `uid`. The anchor must be the developer's own process: the spike found
    that a subject process not owned by the developer returns `(false,
    false)`. polkitd asks the authentication agent of the process's login
    session, or, for a process outside any login session (a terminal
    started by GNOME runs in the user manager's), of the uid's graphical
    session. The limit is the hijack described in
    [How the polkit display is subverted](#how-the-polkit-display-is-subverted-and-what-stops-it).
  - `"session"`: the uid's logind graphical session (the `Display` property
    of `org.freedesktop.login1.User`) as a `unix-session` subject. This is
    the stronger subject, but polkitd 127 and 128 abort on it
    ([polkit-org/polkit#699](https://github.com/polkit-org/polkit/issues/699)),
    so it is for a polkit with that fixed.
- **`require_wayland`** (default `true`). Before each check the adapter
  reads the type of the uid's logind graphical session, the session polkit
  shows the dialog in, and refuses (`Unavailable`) unless it is `wayland`.
  It does not look at the anchor's own session: terminal apps on GNOME run
  in the user manager's session, which has no type. No graphical session, or
  no answer from logind, is also `Unavailable`.
- **Details.** The adapter always sets every key the messages use: `code`,
  `digest`, `secrets`, `ttl`, `session`, `reason` and `operation`. An empty
  value is sent as "none", so the dialog never shows a raw `$(key)`.
  `session` first says how `cnd` found the session, from what it read
  itself, then what the client reported, marked as such:
  - `agent claude (pid 41210, registered by cn session exec); agent-reported: label "x", cwd "~/p"`
    for an anchor started with `cn session exec`;
  - `agent claude (pid 41210, matched comm = "claude"); agent-reported: cwd "~/p"`
    for an anchor found by a `[sessions] matchers` entry;
  - `terminal, no agent session (shell bash, pid 3001); client-reported: cwd "~/p"`
    for a store change made from a terminal outside any session.

  The label and cwd are left out when the client sent none. Keys
  beginning `polkit.` are reserved by polkit and are never set. Only an
  action owner may pass details at all (spike finding 3), so an agent cannot
  write this text.
- **Sanitising.** Every value is cleaned before it is sent: terminal escape
  sequences (CSI, OSC, DCS and the rest, 7-bit and C1 forms) are removed
  whole, and an unterminated OSC or DCS string hides the rest of its field;
  control and format characters are removed (bidi overrides and isolates,
  zero-width characters, tag characters), as are private-use characters,
  noncharacters and variation selectors; line breaks and runs of spaces
  become one space; combining marks are cut to two per base character. Then
  each field is length-limited, counting characters: reason 300, each
  secret name 80 (a name is at most 64; `cnd` may add " (other project)"),
  the cwd 120 with the middle elided (the home directory shown as `~`), the
  label 40 inside its quotes, the anchor's `comm` 32, the matcher 48, and the
  secret list 10 names then "and N more". The parts of `session` and
  `secrets` are bounded so the whole stays under 320 and 850 characters.
  In `session` the label and the cwd are quoted, with `"` and `\` escaped,
  so neither can pose as the text after it: the label as the cwd, the cwd
  as the `Agent's reason:` the message puts next. Their limits count the
  escapes inside the quotes.
- **Store changes.** The `operation` of a store change is limited to 600
  characters, and its parts are bounded so that the longest text of every
  kind (`add`, `set`, `edit`, `rm`, `import`) stays under that and is never
  cut; a test checks each. Agent text in it (description, usage, each
  project and tag) is quoted with `"` and `\` escaped, so it cannot close
  its quotes and pose as a change. Its bounds, inside the quotes and
  counting escapes: an `add` description 60 and usage 120, an `edit`
  description or usage 40, a project 24 (the middle cut), a tag 12, then 2
  projects or tags and "and N more"; `rm` and `import` list 8 names then
  "and N more". A cut description or usage ends in an ellipsis and says how
  long the text was. `add` shows the value's size class, its source and the
  high entropy flag first, then the description, usage, projects and tags.
  `edit` shows each changed field as old -> new, what `cnd` acts on first:
  the high entropy flag, saying what it means for `cn hide`, then projects,
  where no projects reads `any (all projects)`; then tags, the description
  and the usage. A description or usage longer than 40 characters shows as
  its new text only (`usage becomes "..."`). For example:
  `EDIT db: high entropy off (cn hide matches it only when granted); projects
  ["~/work/prod"] -> any (all projects); description "prod" -> "prod
  primary"`.
- **Result.** `is_authorized = true` -> `Approved`.
  `details["polkit.dismissed"] = "true"` (the human pressed Cancel) ->
  `Denied`, or `Unavailable` when the approver has `on_dismiss = "ignore"`
  (for an `any_of` in Phase 2). `is_challenge = true` -> `Unavailable` (no
  authentication agent for the subject). Otherwise -> `Denied`. An answer
  that arrives after the request expired counts as `Timeout`. polkitd not
  on the bus is `Unavailable`; polkitd refusing `cnd` as a caller (the policy
  is missing or names another owner) is `Internal`.
- **Timeout.** A dialog stays open until the request lapses (`[grants]
  pending_expiry`, 5 minutes by default, counted from when the request was
  made, also while it waits its turn behind other dialogs). `timeout` has no
  default; set, it closes the dialog sooner, and the request lapses at
  whichever comes first. Then the adapter withdraws the dialog and returns
  `Timeout`, and the request expires.
- **Cancellation.** When the request expires, is denied by `cn deny`, its
  anchor exits, or another `any_of` member decides, `cnd` calls
  `CancelCheckAuthorization` and the dialog closes. Each call has its own
  cancellation id, `countersign-<request id>-<n>`, because polkitd refuses a
  second check in flight with the same id. `cnd` must enforce expiry itself:
  with a key-touch factor, GNOME retries the touch about every 30 seconds for
  as long as the dialog is open (spike U3), so without the cancel the dialog
  would stay up.
- **Evidence.** `{action_id, subject, is_authorized, dismissed,
  duration_ms}`. polkit gives no signature; the evidence is "polkitd said
  yes". That is why Phase 2 proposes adding `fido2` for `reveal`, `mutate` and
  `export` (P1).

### Approval factor: password or key touch

polkit authenticates `auth_self` through the PAM service `polkit-1`. What the
dialog asks for is chosen at install (decision 19), with
`packaging/install.sh --factor` ([packaging/README.md](../packaging/README.md#approval-factors)):

| Factor | The dialog asks for | `polkit-1` auth lines |
| --- | --- | --- |
| `password` (default) | The user's password. | The distribution's, unchanged. |
| `touch` | A security key touch, nothing else. No key, no approval. | `auth [success=done default=die] pam_u2f.so authfile=/etc/countersign/u2f_mappings origin=pam://countersign appid=pam://countersign cue` |
| `touch+password` | A touch, then the password. | `auth [success=ok default=die] pam_u2f.so ...` (same arguments), then the distribution's auth lines. |

For both touch factors, the `pam_u2f` line is preceded by one that skips it
for every user except the developer:

```text
auth  [success=1 default=ignore]  pam_succeed_if.so quiet user notin <developer>
```

Any error in that line leads to the key, never past it. The distribution's
auth lines stay as they are after the two new ones; with `touch`, the
`pam_u2f` line ends the stack for the developer.

There is no click-only factor: polkit has no confirm-only mode
([polkit#463](https://github.com/polkit-org/polkit/issues/463)), and with the
process subject a prompt that needs no credential could be answered by an
agent that drew its own prompt (decision 15).

Points that matter for the touch factors:

- **`authfile=/etc/countersign/u2f_mappings`, root-owned.** By default
  `pam_u2f` reads `~/.config/Yubico/u2f_keys`, which the agent can write. A
  user-writable mapping lets the agent add a credential of its own.
- **Its own origin**, `pam://countersign`, so the enrolment is not shared with
  another PAM service. The installer enrols with `pamu2fcfg` run as the user;
  a key with a FIDO2 PIN asks for it, so enrolment needs a real terminal (not
  a Claude Code `!` command).
- Do not set `nouserok`.
- `cue` makes PAM send "touch the device"; gnome-shell shows it in the dialog.
- **polkit 125 and later run their PAM helper sandboxed** as
  `polkit-agent-helper@.service`, which hides the key. The installer adds a
  drop-in with `DevicePolicy=auto`, `DeviceAllow=char-hidraw rw` and
  `PrivateDevices=no`, as polkit-agent-helper(8) asks of PAM modules that
  need hardware.
- **This changes the developer's polkit prompts only, for every action**
  (`pkexec`, NetworkManager, systemd, package tools, when they authenticate
  as the developer). polkit has no per-action PAM service. Other users, root
  included, keep the distribution's stack, so on openSUSE administrator
  prompts still ask for root's password.
- Touch only while the countersign dialog is showing: a touch approves
  whatever request is pending.

### Locking out user GNOME Shell extensions (optional)

A persistent agent's strongest attack on the polkit display is a user-installed
GNOME Shell extension. If you do not need user extensions, lock them off for
the uid through the system dconf database, which the uid cannot write:

```console
$ sudo mkdir -p /etc/dconf/db/local.d/locks
$ printf '[org/gnome/shell]\ndisable-user-extensions=true\n' | sudo tee /etc/dconf/db/local.d/00-countersign
$ printf '/org/gnome/shell/disable-user-extensions\n' | sudo tee /etc/dconf/db/local.d/locks/00-countersign
$ sudo dconf update
```

Extensions installed system-wide under `/usr/share/gnome-shell/extensions` by
root keep working. This requires `/etc/dconf/profile/user` to include
`system-db:local`.

---

## Adapter: `fido2` (Phase 2)

Deferred to Phase 2 by decision 14; nothing below is built in Phase 1.

Client-driven. The human runs `/usr/bin/cn approve CODE`; `cn` asks the
security key for an assertion over the request digest; `cnd` verifies it
against an enrolled public key.

### Enrollment

`/usr/bin/cn approver enroll --name desk-key [--uv required|preferred|discouraged] [--out FILE]`:

1. `cn` gets an enrollment nonce from `cnd`.
2. `authenticatorMakeCredential` with:
   - `rp.id = "countersign"`, `rp.name = "countersign"`;
   - `user.id` = 16 random bytes, `user.name = "patrick@<hostname>"`;
   - `pubKeyCredParams` = ES256 (-7), EdDSA (-8);
   - `rk = false` (non-discoverable: nothing is stored on the key, and the
     credential cannot be listed or used without the credential id);
   - `uv` per `--uv` (default `discouraged`), which should match the
     approver's `user_verification` setting in config;
   - `clientDataHash = SHA-256("countersign/enroll/v1" || 0x00 || nonce || name)`;
   - attestation requested (`packed` on YubiKeys).
3. `cn` writes `desk-key.approver.toml`: name, credential id, COSE public key,
   algorithm, AAGUID, uv policy, attestation statement (format, signature,
   certificate chain), the enrollment nonce, and the time.
4. Root installs it into `/etc/countersign/approvers.d/` and reloads `cnd`
   (`sudo install -o root -g root -m 0644 desk-key.approver.toml
   /etc/countersign/approvers.d/`, then `sudo systemctl reload countersign`).
5. On load, `cnd` verifies the attestation signature and chain against the
   configured roots (default: the Yubico FIDO root CA) and, optionally, an
   AAGUID allowlist. A software authenticator, including one a shadowed `cn`
   could fake, has no valid chain and is rejected; the `config.load` audit
   record lists each record as loaded or rejected.

Credential storage is split by who may change it:

| Data | Path | Owner | Why |
| --- | --- | --- | --- |
| Credential record (id, public key, attestation) | `/etc/countersign/approvers.d/NAME.approver.toml` | root, 0644 | Approver policy: the agent must not add or swap keys (T13). |
| Signature counter | `/var/lib/countersign/approvers/NAME.counter` | `countersign`, 0600 | Changes on every approval; `cnd` must write it. |

### Approval

1. `cn approve CODE` fetches the request with `get_request`: the canonical
   request, the digest, the display view, the allowed credential ids and the
   uv policy.
2. `cn` recomputes `SHA-256(canonical)` and refuses if it differs from the
   digest `cnd` sent (protects against a confused or mismatched daemon; not
   against a shadowed `cn`).
3. `cn` prints the display view and short digest, then calls
   `authenticatorGetAssertion` with `rpId = "countersign"`,
   `clientDataHash = digest`, `allowList` = the enrolled credential ids,
   `up = true`, and `uv` per `user_verification`.
4. The key blinks; the human touches it.
5. `cn` sends `approve` with the code, the approver name and the assertion
   (credential id, authenticator data and signature, base64url) to `cnd`.

`cnd` then checks, in order, and fails with `approval_invalid` on any miss:

- the request is still pending and not expired (single use: it leaves
  `pending` on the first valid assertion);
- the credential id is enrolled and named in this kind's chain;
- `authenticatorData.rpIdHash == SHA-256("countersign")`;
- the UP flag is set (CTAP2 allows `up = false` assertions without a touch);
- the UV flag is set when `user_verification = "required"`;
- the signature verifies over `authenticatorData || digest` with the stored
  public key (ES256: ECDSA P-256 over SHA-256, DER signature; EdDSA: Ed25519);
- the signature counter is greater than the stored one, unless both are zero
  (some authenticators always report zero); a counter that goes backwards
  suggests a cloned credential and is refused.

**Evidence:** `{credential_id, aaguid, flags, sign_count, authenticator_data,
signature, digest}`, base64url. With the canonical request in the audit log
(`request.create` records it) and the public key from the approver record,
anyone can re-verify an approval later; `cn audit verify --approvals` does.

### User verification (PIN)

`user_verification = "required"` makes the key check a PIN or fingerprint. A PIN needs a
terminal to type it into, and a PIN typed into a Claude Code `!` command would
land in the transcript. So:

- With a PIN-only key, `"required"` means approving from a real
  terminal, not with `!`. `cn` refuses to read a PIN without a TTY.
- A key with built-in fingerprint (YubiKey Bio) does UV on the key itself and
  works from `!`.
- Default `discouraged`: presence is what this approver is for; UV mainly
  protects a stolen key.

### Daemon-side option

With a udev rule that gives the `countersign` group the key, `cnd` can talk to
the key itself (`side = "daemon"`), and `cn approve` only
tells `cnd` which request to sign. That keeps the assertion out of the
developer's uid but does not change the display problem: the human still
learns what they are approving from `cn`'s output. It is mainly useful for
`cn unlock`, where it keeps the `hmac-secret` output out of the uid.

```text
# /usr/lib/udev/rules.d/70-countersign.rules
SUBSYSTEM=="hidraw", ENV{ID_FIDO_TOKEN}=="1", GROUP="countersign", MODE="0660", TAG+="uaccess"
```

The unit then sets `PrivateDevices=no` and `DeviceAllow=char-hidraw rw`.
`TAG+="uaccess"` keeps the seat user's access, so `cn approve` still works.

### Store unlock

A `fido2` key slot wraps the data key with `KEK = HKDF(hmac-secret(salt),
"countersign/kek/v1")`. A `cnd` whose only usable slot is `fido2` starts
sealed and answers `store_sealed` until `/usr/bin/cn unlock`: `cn` gets the
slot's credential id and salt from `cnd`, asks the key for its `hmac-secret`
output (touch required), and sends it to `cnd`, which unwraps the data key.
With `[unlock] fido2_side = "daemon"`, `cnd` talks to the key itself and
`cn unlock` only triggers it. `cn unlock --enroll` adds a `fido2` slot for the
inserted key, under a `mutate` approval. The audit log records `unlock`,
`store.unseal` and `keyslot.add`.

### Library choice (open)

| Option | Where | For | Against |
| --- | --- | --- | --- |
| `libfido2` (Yubico, C) via Rust FFI bindings | `cn` | Mature; PIN, bio, `hmac-secret`, hidraw; packaged in Tumbleweed | C dependency; static linking pulls in libcbor, libcrypto and libudev, which conflicts with a statically linked `cn` |
| `ctap-hid-fido2` (pure Rust) | `cn` | No C library; covers make/get assertion and `hmac-secret` | Smaller user base; HID access through `hidapi`, whose Linux backend links libudev unless the hidraw backend is selected |
| `authenticator` (Mozilla authenticator-rs) | `cn` | Used in Firefox; CTAP2 over Linux hidraw | API shaped for WebAuthn in a browser; crypto backend choice |
| `coset` + `p256` / `ecdsa` + `ed25519-dalek` + an X.509 chain verifier | `cnd` | Verification needs no device library at all; small, pure Rust | Attestation chain checking must be written carefully |

`cnd` should not link a device library unless `side = "daemon"` is enabled.
`webauthn-rs` is not a fit for verification: it expects a browser's
`clientDataJSON`, while countersign signs a raw `clientDataHash`.

---

## Adapter: `command` (Phase 2)

Daemon-driven, generic. Runs an executable for each request and reads the
decision from its exit code. Covers phone push (ntfy, Pushover), a chat bot,
or a site-specific check.

### Protocol

`cnd` executes `argv` directly (no shell), with an empty environment except
`PATH=/usr/bin:/bin` and the variables named in `env`, cwd `/`, and this on
stdin, then closes stdin:

```json
{
  "countersign_approver": 1,
  "kind": "use",
  "code": "K7M-Q2X",
  "digest": "<64 hex chars>",
  "digest_short": "3QF8-ZK2M",
  "expires_at": "2026-11-08T09:25:11Z",
  "canonical_b64": "<JCS bytes, base64>",
  "display": {
    "session": "agent claude (pid 41210, registered by cn session exec); agent-reported: label \"orchestrator\", cwd \"~/projects/moose/liskov-agent-orchestrator\"",
    "secrets": ["clickhouse-password"],
    "mode": "use",
    "ttl_seconds": 1800,
    "cwd": "~/projects/moose/liskov-agent-orchestrator",
    "reason": "row counts for the weekly cost report via scripts/clickhouse_rows.py",
    "agent_supplied": ["reason", "cwd", "label"]
  }
}
```

| Exit | Meaning |
| --- | --- |
| 0 | Approved. |
| 1 | Denied. |
| 2 | Unavailable (e.g. phone unreachable); an `any_of` tries the next member. |
| anything else, a signal, or `timeout` reached | Error; fails closed (`Internal`). |

Stdout may carry one JSON object (at most 16 KiB) that `cnd` stores as
`Evidence.detail`. Stderr goes to the daemon log, truncated to 4 KiB. The
process is killed with SIGTERM, then SIGKILL after 2 seconds, on timeout or
cancellation.

`cnd` refuses to load a `command` approver whose executable, or any directory
above it, is not root-owned or is writable by group or others (T13).

### Why it is the weakest

- **Its strength is the script's.** The exit code is the entire result. A bug,
  a misconfiguration or a `true` in the wrong place approves everything.
- **The response channel is usually unauthenticated.** An ntfy topic is a
  shared secret at best; if it is guessable or leaks, anyone, including the
  agent with network access, can post "approve". A safe phone adapter needs a
  response signed by a key on the phone over the request digest, verified by
  the script.
- **Its input is attacker-controlled.** `reason` and `cwd` come from the agent.
  A script that pastes them into a shell command line, a URL or a markdown
  message without escaping is an injection point.
- **No standard evidence.** Unless the script returns a signature, the audit
  log can only record "the script exited 0".
- **It runs with the daemon's privileges** if `cnd` simply forks it: as user
  `countersign`, with access to the state directory and the audit log. See
  open question 4.

Its strength is also real in one case: a phone that shows the request and
signs its answer is an out-of-band trusted display, the only one that does not
depend on the desktop at all.

---

## Recommended default for the owner

The owner runs GNOME on Wayland (openSUSE Tumbleweed), has a YubiKey and
prefers it, and approves requests while working in Claude Code.

### Phase 1

polkit for every kind, with the touch factor (decisions 14 and 19):

```toml
[approval]
use    = "polkit"
reveal = "polkit"
mutate = "polkit"
export = "polkit"

[approvers.polkit]
type = "polkit"
subject = "process"
```

- The request is shown by gnome-shell from text that went `cnd` -> polkitd
  -> gnome-shell; nothing on that path runs code the agent controls, as long
  as the agent has not installed a shell extension or registered its own
  authentication agent for the anchor (the process-subject limit).
- The approval is a YubiKey touch, the gesture the owner wants. It works from
  any terminal and any agent, because `cnd` raises the dialog itself.
- `use`, `reveal` and `mutate` have their own actions and messages
  (`export` uses `mutate`), so the dialog says plainly when a value would
  enter the transcript or the store would change.

Setup, in order:

1. Install through `packaging/trusted-build.sh --factor touch`, from a
   terminal you opened yourself ([packaging/README.md](../packaging/README.md#install)).
2. Optionally lock user GNOME Shell extensions off ([above](#locking-out-user-gnome-shell-extensions-optional)).
3. `/usr/bin/cn doctor` from a terminal you opened yourself.
4. Start agents with `cn session exec -- claude`, so the dialog can name the
   session.

### Phase 2

The candidates once `fido2` exists:

**A. polkit backed by `pam_u2f`**, as in Phase 1: a trusted display (within
the subject's limit) and a touch.

**B. `fido2` through `! cn approve`, with a daemon-rendered notification as
the trusted cross-check.** The touch is bound cryptographically to the request
digest, which is better evidence than polkit's. But there is no
daemon-rendered notification to cross-check against: `cnd` runs as
`countersign` and cannot reach the developer's session bus
(`/run/user/1000` is 0700), so any desktop notification would have to be
posted by a process in the developer's uid, which the agent can run or
imitate (GNOME notifications carry a sender-chosen name and icon). Without
polkit, B's display is the terminal, which a planning agent controls.

**Proposal (P1): A, with `fido2` added for the rare high-stakes kinds.**

```toml
[approval]
use    = "polkit"                                  # one touch, trusted display
reveal = { all_of = ["polkit", "desk-key"] }       # trusted display + signed digest
mutate = { all_of = ["polkit", "desk-key"] }
export = { all_of = ["polkit", "desk-key"] }
```

- `use` is frequent. One touch on a dialog the agent cannot alter is the right
  cost.
- `reveal`, `mutate` and `export` are rare and their damage is permanent or
  affects every later session. Two touches buy both properties: the polkit
  dialog shows the true request, and the FIDO2 signature over the digest goes
  into the audit log, where it can be re-verified. Because polkit is in the
  `all_of`, a shadowed `cn` gains nothing: the human sees the true request in
  the dialog before the second touch.
- `fido2` is not in an `any_of` with polkit by default, because that would make
  the terminal path sufficient for every request (see
  [Strength of a chain](#strength-of-a-chain)).
- For ssh or a machine with no graphical session, where polkit is
  `Unavailable`, the owner can switch `use` to `{ any_of = ["polkit",
  "desk-key"] }` knowingly, accepting a terminal display. A phone push
  approver (decision 19) would be the better answer there.

## Open questions

1. ~~**polkit message expansion and display.**~~ Settled by the
   [spike](../spikes/polkit-dialog/README.md) on polkit 128 and GNOME Shell
   51: polkitd expands `$(key)` from the details an action owner passes, and
   gnome-shell shows the whole message. KDE's agent is still unchecked.
2. ~~**`org.freedesktop.policykit.owner` and the session subject.**~~ Settled
   by the spike: the owner annotation works across uids with a process
   subject; a session subject aborts polkitd 127/128 (polkit#699), hence
   decision 15.
3. **Resolving the graphical session** (`subject = "session"`, and the
   `require_wayland` check). Using the uid's logind `Display` session works
   for a solo desktop. It is wrong if the developer has two graphical
   sessions, or approves from a remote desktop. Should the approver refuse
   when the uid has more than one graphical session?
4. **Where `command` adapters run.** Forking them from `cnd` gives them the
   `countersign` uid (store and audit access) and the unit's
   `RestrictAddressFamilies=AF_UNIX`, which blocks any network push. Proposed:
   a socket-activated helper, `countersign-approve-command.socket` with
   `Accept=yes`, whose instances run as `DynamicUser=yes` with network allowed;
   `cnd` connects over AF_UNIX and passes the JSON. Needs a decision.
5. **Dismissal semantics.** A dismissed polkit dialog is a deny by default.
   With `on_dismiss = "ignore"` a dismissal is `Unavailable`: in an `any_of`
   the human can approve another way; with polkit alone the request ends
   denied by `cnd`. Is a deny the right default, given that the agent then
   gets exit 5 and is told not to retry?
6. **Attestation for keys without a usable chain.** Some authenticators ship
   with self or no attestation. `attestation = "none"` re-opens enrollment of
   a software key by a shadowed `cn`. Should `cnd` then require that the record
   be produced by `cn` run as root (a different, root-owned environment)?
7. **Lookalike dialogs for the password factor.** With `--factor password`
   (or a hijacked process subject), the human types their password into a
   prompt. A lookalike window, or the agent's own registered prompt, could
   collect it. That gives the agent nothing in countersign on Wayland it could
   not get by asking, but the password also unlocks sudo. Should `cn doctor`
   warn when the factor is `password`?
