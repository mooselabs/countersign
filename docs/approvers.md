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
approved. `cnd` builds the canonical request, computes its digest, and either
makes the polkit call itself or verifies a FIDO2 signature over its own digest.
No client can change what a successful approval applies to.

## Approval kinds

Each request has a kind, and config chooses an approver chain per kind:

| Kind | Raised by | Typical stakes |
| --- | --- | --- |
| `use` | `cn request` (default mode) | A value is injected into a child process for up to `max_ttl`. |
| `reveal` | `cn request --mode reveal` | A raw value goes wherever the caller's stdout goes, permanently. |
| `mutate` | `cn add`, `set`, `edit`, `rm`, `import`, `unlock --enroll` | Store contents or prose change for every later session. |
| `export` | `cn export` | The whole store, decrypted, goes to an age recipient. |

## The interface

`countersign-approve` defines two traits, because approvers differ in who
drives the interaction, and wraps them in one enum that the chain evaluator
uses. Sketch (not final API):

```rust
/// Everything an approver is given. Built once per request by cnd.
pub struct ApprovalRequest {
    /// RFC 8785 (JCS) bytes of the canonical request (design.md section 6).
    pub canonical: Vec<u8>,
    /// SHA-256 of `canonical`. Used verbatim as the FIDO2 clientDataHash.
    pub digest: [u8; 32],
    /// "3QF8-ZK2M": first 8 Crockford base32 chars of `digest`, for humans.
    pub digest_short: String,
    pub code: String,                 // "K7M-Q2X"
    pub kind: ApprovalKind,           // Use | Reveal | Mutate | Export
    /// Escaped, length-limited strings for display. Agent-supplied fields
    /// (reason, cwd, labels) are marked as such. Never values.
    pub display: DisplayView,
    /// Resolved by cnd: session id, anchor (pid, starttime, comm), uid,
    /// and the uid's logind graphical session if there is one.
    pub session: SessionRef,
    pub expires_at: SystemTime,
}

pub enum Outcome {
    Approved(Evidence),
    Denied(Evidence),
}

pub enum ApproverError {
    /// Cannot run here: no polkit agent for the session, no key enrolled,
    /// no graphical session. Lets an `any_of` chain try the next member.
    Unavailable(String),
    /// The human did not answer before the deadline.
    Timeout,
    /// A response arrived and failed verification (bad signature, UP flag
    /// clear, counter went backwards). Audited as `request.approve_fail`.
    Invalid(String),
    /// Bug or system fault. Fails closed.
    Internal(String),
}

/// Recorded in the audit log with the `request.approve` / `request.deny` record.
pub struct Evidence {
    pub approver: String,           // configured instance name: "polkit", "desk-key"
    pub adapter: &'static str,      // "polkit" | "fido2" | "command"
    pub at: SystemTime,
    pub detail: serde_json::Value,  // adapter-specific; never values
}

/// cnd runs the whole interaction (polkit, command).
pub trait DaemonApprover: Send + Sync {
    fn info(&self) -> ApproverInfo;   // name, adapter, strength notes for `cn doctor`
    fn present<'a>(
        &'a self,
        req: &'a ApprovalRequest,
        cancel: CancellationToken,    // fired when another chain member decided
    ) -> BoxFuture<'a, Result<Outcome, ApproverError>>;
}

/// cnd issues a challenge, `cn approve` answers it, cnd verifies (fido2).
pub trait ClientApprover: Send + Sync {
    fn info(&self) -> ApproverInfo;
    /// What `cn approve` needs: rp id, allowed credential ids, uv policy.
    /// The challenge itself is always `req.digest`.
    fn challenge(&self, req: &ApprovalRequest) -> Result<ClientChallenge, ApproverError>;
    /// Verify the client's response against enrolled credentials.
    fn verify(
        &self,
        req: &ApprovalRequest,
        resp: &ClientResponse,
    ) -> Result<Outcome, ApproverError>;
}

pub enum Approver {
    Daemon(Box<dyn DaemonApprover>),
    Client(Box<dyn ClientApprover>),
}

/// Parsed from config.
pub enum Chain {
    One(String),          // approver instance name
    AllOf(Vec<Chain>),
    AnyOf(Vec<Chain>),
}
```

In Phase 1 only `DaemonApprover` is implemented. `ClientApprover` and the
`Approver::Client` variant arrive with `fido2` in Phase 2. `present` returns a
boxed `Send` future; it honours the cancellation token and `expires_at`, and
dropping the future or cancelling it withdraws the prompt (for polkit,
`CancelCheckAuthorization`). `ApprovalRequest.session` carries the subject
data `cnd` resolved: the developer's uid, the anchor's pid and start time, and
the logind session id when there is one.

Rules every adapter follows:

- The only request data an adapter may show a human is `display`, and it shows
  agent-supplied fields labelled as such ("Agent's reason: ...").
- An adapter never receives a secret value. Even a `mutate` request carries
  only the value's length class and source.
- `Evidence.detail` must be enough for a later reader to tell what happened,
  and where possible to re-check it (FIDO2 stores the signature).
- `present` must honour `cancel` and `expires_at`. An adapter that cannot
  cancel (a running command) is killed.

## Daemon-driven and client-driven

| | Daemon-driven | Client-driven |
| --- | --- | --- |
| Adapters | `polkit`, `command` | `fido2` |
| Who starts it | `cnd`, as soon as the request is created (or when `cn approve` re-triggers it) | The human, by running `/usr/bin/cn approve CODE` |
| Where the request is displayed | A surface outside the developer's uid's control: the compositor's polkit dialog, a phone | `cn`'s output in the terminal, inside the agent's environment |
| Where the decision is made | polkitd / the command | The security key, then `cnd` verifies the assertion |
| What the agent can do | Nothing beyond creating requests (rate-limited) | Run `cn approve` itself (reaches the touch prompt and stops), or tamper with what the terminal shows |

`cnd` runs as `countersign` and cannot open the developer's session bus or
draw on the desktop. polkit is the standard way for a system service to get an
authenticated decision from the user at the desktop, which is why it is the
only daemon-driven adapter with a trusted display in v1.

## Chaining

Config gives each kind a chain. A chain is an approver name, or `all_of` /
`any_of` over chains, nested at most three levels.

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
- `Timeout` or `Unavailable` leaves that member unsatisfied and the request
  pending until `pending_expiry`; the human can retry with `cn approve`.
- `Invalid` is audited as `request.approve_fail` and counts toward the per-session
  approval-attempt limit; the member stays unsatisfied.
- `Internal` denies (fail closed).

### `any_of`

- Daemon-driven members start when the request is created; client-driven
  members accept a `cn approve` at any time while the request is pending.
- The first decisive outcome wins. `Approved` creates the grant and cancels
  the others (`CancelCheckAuthorization` for polkit, SIGTERM for a command).
  `Denied` from any member denies the request: an explicit no is never
  overridden by trying another approver.
- `Unavailable` members are skipped. If every member is unavailable the
  request fails with `approver_unavailable`.

### Strength of a chain

An `any_of` chain is as weak as its weakest member, for presence and for
intent. If `use = { any_of = ["polkit", "desk-key"] }`, an approval can always
come from `desk-key` through `cn approve`, whose display is the terminal, even
while a polkit dialog is open. A chain's display strength is the strength of
the strongest display that *every* approving path must pass through. `cn
doctor` prints, for each kind, the weakest path through its chain.

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
over B and grants B. `cn` being statically linked, non-dumpable and refusing a
tracer stops only `LD_PRELOAD` and ptrace tricks against the genuine binary.
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
| The agent synthesizes a click or keystrokes in the dialog. | Not possible on Wayland. On X11 it is; `cn doctor` warns, and the polkit adapter can be set to refuse non-Wayland sessions (`require_wayland = true`). |
| The agent installs a GNOME Shell extension that rewrites the dialog. | Takes effect after the next login or shell restart. Lock user extensions off through the system dconf database (below), or accept the residual risk; `cn doctor` warns when user extensions are enabled. |
| The agent spams requests until one is approved by habit. | Per-session limits on pending requests and request rate; cooldown after a deny; the dialog names the session and shows the agent's reason as the agent's. |
| A polkit rule or a `*_keep` default makes later checks pass without a prompt. | `cnd` self-tests at start: a non-interactive check of each action must return "challenge", never "authorized". If not, the polkit approver is disabled and `cnd` logs why. |

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
                       "session": "agent claude (pid 41210) in ~/projects/moose/liskov-agent-orchestrator",
                       "reason": "row counts for the weekly cost report via ..."},
    flags           = 0x1,           # AllowUserInteraction
    cancellation_id = "r_9w1k...")   # the request id
  -> (is_authorized: b, is_challenge: b, details: a{ss})
```

The dialog then reads:

```text
countersign request K7M-Q2X, digest 3QF8-ZK2M: USE clickhouse-password for 30m.
agent claude (pid 41210) in ~/projects/moose/liskov-agent-orchestrator.
Agent's reason: row counts for the weekly cost report via ...
```

- **Subject.** Config `[approvers.polkit] subject = "process" | "session"`,
  default `"process"` (decision 15).
  - `"process"`: the session anchor, the long-lived agent process `cnd`
    resolved for the request (design.md section 5), as a `unix-process`
    subject with its `pid`, `start-time` (field 22 of `/proc/PID/stat`) and
    `uid`. The anchor must be the developer's own process: the spike found
    that a subject process not owned by the developer returns `(false,
    false)`. polkitd finds the authentication agent through the process's
    login session. The limit is the hijack described in
    [How the polkit display is subverted](#how-the-polkit-display-is-subverted-and-what-stops-it).
  - `"session"`: the uid's logind graphical session (the `Display` property
    of `org.freedesktop.login1.User`), required to be local, active, on a
    seat and, with `require_wayland = true`, of type `wayland`. This is the
    stronger subject, but polkitd 127 and 128 abort on it
    ([polkit-org/polkit#699](https://github.com/polkit-org/polkit/issues/699)),
    so it is for a polkit with that fixed.
- **Details.** The adapter always sets every key its action's message uses:
  `code`, `digest`, `secrets`, `ttl`, `session` and `reason` for `approve`
  and `reveal`; `code`, `digest`, `operation` and `session` for `mutate`.
  An empty value is sent as "none", so the dialog never shows a raw `$(key)`.
  `session` reads like `agent claude (pid 41210) in ~/projects/x`. Every value
  is sanitised: control characters, ANSI escapes, newlines and Unicode bidi
  overrides are removed. Each is length-limited: reason 300 characters, the
  cwd inside `session` 120 with the middle elided, the secret list 10 names
  then "and N more". Keys beginning `polkit.` are reserved by polkit and are
  never set. Only an action owner may pass details at all (spike finding 3),
  so an agent cannot write this text.
- **Result.** `is_authorized = true` -> `Approved`. `details["polkit.dismissed"]
  = "true"` (the human pressed Cancel) -> `Denied` (dismissed), or ignored
  when the approver has `on_dismiss = "ignore"` (useful in an `any_of` in
  Phase 2). `is_challenge = true` with no interaction -> `Unavailable` (no
  authentication agent for the session). Otherwise -> `Denied`.
- **Cancellation.** When the request expires, is denied by `cn deny`, or
  another `any_of` member approves, `cnd` calls `CancelCheckAuthorization` with
  the request id and the dialog closes. `cnd` must enforce expiry itself: with
  a key-touch factor, GNOME retries the touch about every 30 seconds for as
  long as the dialog is open (spike U3), so without the cancel the dialog
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
| `touch+password` | A touch, then the password. | `auth requisite pam_u2f.so ...` (same arguments), then the distribution's auth lines. |

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
- **This changes every polkit prompt on the machine** (`pkexec`,
  NetworkManager, systemd, package tools). polkit has no per-action PAM
  service. The installer says so before it makes the change.
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

`cn approver enroll --name desk-key` (see [cli.md](cli.md#cn-approver-enroll-phase-2)):

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
4. Root installs it into `/etc/countersign/approvers.d/` and reloads `cnd`.
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

With the udev rule in [design.md](design.md#daemon-side-fido2-phase-2-optional),
`cnd` can talk to the key itself (`side = "daemon"`), and `cn approve` only
tells `cnd` which request to sign. That keeps the assertion out of the
developer's uid but does not change the display problem: the human still
learns what they are approving from `cn`'s output. It is mainly useful for
`cn unlock`, where it keeps the `hmac-secret` output out of the uid.

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
    "session": "Agent session \"orchestrator\" (claude, pid 41210)",
    "secrets": ["clickhouse-password"],
    "mode": "use",
    "ttl_seconds": 1800,
    "cwd": "~/projects/moose/liskov-agent-orchestrator",
    "reason": "row counts for the weekly cost report via scripts/clickhouse_rows.py",
    "agent_supplied": ["reason", "cwd"]
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
- `reveal`, `mutate` and `export` get their own actions and messages, so the
  dialog says plainly when a value would enter the transcript or the store
  would change.

Setup, in order:

1. `sudo packaging/install.sh --factor touch` from a terminal you opened
   yourself ([packaging/README.md](../packaging/README.md)).
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
3. **Resolving the graphical session** (`subject = "session"` only). Using
   the uid's logind `Display` session works for a solo desktop. It is wrong if the developer has two
   graphical sessions, or approves from a remote desktop. Should the
   approver refuse when the uid has more than one graphical session?
4. **Where `command` adapters run.** Forking them from `cnd` gives them the
   `countersign` uid (store and audit access) and the unit's
   `RestrictAddressFamilies=AF_UNIX`, which blocks any network push. Proposed:
   a socket-activated helper, `countersign-approve-command.socket` with
   `Accept=yes`, whose instances run as `DynamicUser=yes` with network allowed;
   `cnd` connects over AF_UNIX and passes the JSON. Needs a decision.
5. **Dismissal semantics.** A dismissed polkit dialog is a deny by default.
   With `on_dismiss = "ignore"` a human can dismiss and approve another way.
   Is a deny the right default, given that the agent then gets exit 5 and is
   told not to retry?
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
