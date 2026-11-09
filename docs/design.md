# countersign design

This document describes how countersign is built: the processes, where state
lives, the IPC protocol, how sessions and grants work, and how values reach a
child process without entering an agent's context. The threat model, the
approver adapters, the CLI reference and the audit log each have their own
documents; this one links to them where they overlap. The audit log is
specified in [audit.md](audit.md).

Scope for v1: Linux, systemd, one developer per machine, agents running as the
developer's uid. Containers and PID namespaces are out of scope.

## 1. Components and process layout

```text
 developer uid (e.g. 1000)                        uid countersign (system user)
 ┌───────────────────────────────────────┐        ┌──────────────────────────────┐
 │ terminal / tmux pane                  │        │ cnd  (countersign.service)   │
 │  └─ cn session exec -- claude  ◄─anchor│        │  - store (decrypted index)   │
 │      └─ claude (same pid after exec)  │        │  - sessions, grants (memory) │
 │          ├─ bash -c 'cn list'         │ unix   │  - audit writer              │
 │          ├─ cn run --use db -- ./x.py ├──sock──►  - hide engine               │
 │          │    └─ ./x.py (env: DB=…)   │        │  - approver chains           │
 │          └─ make | cn hide            │        └──────────────┬───────────────┘
 └───────────────────────────────────────┘                       │ system D-Bus
                                                                  ▼
 graphical session                                             polkitd
 ┌───────────────────────────────────────┐                       │
 │ polkit agent (gnome-shell) – dialog   ◄───────────────────────┘ asks the
 │   factor: password, or a key touch    │                         session's agent
 │   through pam_u2f                     │
 └───────────────────────────────────────┘
```

| Process | uid | Role |
| --- | --- | --- |
| `cn` | developer | Client. Talks to `cnd`; starts the child for `cn run`; scrubs its output locally. |
| `cnd` | `countersign` | Owns the store, grants, sessions and audit log. Decides every request. Never runs agent-supplied commands. |
| polkitd + polkit agent | root / developer | The approver. `cnd` calls `CheckAuthorization`; the desktop renders the dialog. |
| YubiKey | n/a | With a touch factor, the dialog's credential, through `pam_u2f`. |
| `cn session exec` | developer | Launcher that registers itself as a session anchor and then `exec`s the agent, keeping the same pid. |

In Phase 1 polkit is the only approver (decision 14): every approval is the
desktop dialog. The `fido2` approver (`cn approve` with a key touch) and FIDO2
store unlock are Phase 2 ([roadmap](roadmap.md)).

`cnd` is the only process that can read the store file or write the audit log.
`cn` is an ordinary client: nothing it tells `cnd` is trusted except what the
kernel attests (peer credentials, pidfd).

## 2. Installation layout

| Path | Owner / mode | Contents |
| --- | --- | --- |
| `/usr/bin/cn` | root 0755 | CLI. Documentation tells humans to type `/usr/bin/cn` by absolute path for store changes. |
| `/usr/libexec/countersign/cnd` | root 0755 | Daemon. |
| `/usr/lib/systemd/system/countersign.{socket,service}` | root 0644 | Units ([below](#systemd-units)). |
| `/usr/lib/sysusers.d/countersign.conf`, `/usr/lib/tmpfiles.d/countersign.conf` | root 0644 | User, group and directories. |
| `/usr/share/polkit-1/actions/computer.mooselabs.countersign.policy` | root 0644 | The three polkit actions ([approvers.md](approvers.md#actions)). |
| `/etc/countersign/config.toml` | root 0644 | Policy: approvers, TTL limits, matchers, allowed users. Not writable by the agent; `cnd` refuses a config that is not root-owned or is writable by group or others. `cnd --config PATH` overrides the path. |
| `/etc/countersign/u2f_mappings` | root 0644 | Touch factors only: the `pam_u2f` key enrolment, origin `pam://countersign`. Root-owned so the agent cannot add a key. |
| `/etc/pam.d/polkit-1` | root 0644 | Touch factors only: polkit's PAM stack with `pam_u2f`, written by the installer from the distribution's `/usr/lib/pam.d/polkit-1`. Machine-wide. |
| `/etc/systemd/system/polkit-agent-helper@.service.d/countersign-hidraw.conf` | root 0644 | Touch factors only: lets polkit's sandboxed PAM helper open the key. |
| `/etc/credstore.encrypted/countersign-mk` | root 0600 | Master key, 32 random bytes sealed with `systemd-creds` (TPM2 if present, else host key) by the installer. |
| `/var/lib/countersign/` | countersign 0700 | `store.v1`, `store.v1.prev`, `keyslots.json`, `audit/`. `$STATE_DIRECTORY` or `cnd --state-dir PATH` overrides the path. |
| `/run/countersign/` | root 0755 | Holds the socket. Root-owned, so no other process can replace the socket. |
| `/run/countersign/cnd.sock` | countersign:countersign-users 0660 | IPC socket. |

[`packaging/install.sh`](../packaging/install.sh) installs all of it; see
[packaging/README.md](../packaging/README.md).

### Fixed user, not DynamicUser

The service runs as a fixed system user `countersign` created by
`sysusers.d`, not `DynamicUser=yes`:

- The store and audit log must keep a stable owner across reboots, package
  upgrades and restores from backup. DynamicUser state lives under
  `/var/lib/private` with a uid that can change, which complicates restores
  and manual inspection by root.
- The `countersign-users` group (members: the developer, and later a sandbox
  uid) gates the socket. A dynamic user cannot own a stable group for that.

```text
# /usr/lib/sysusers.d/countersign.conf
u countersign - "countersign secret daemon" /var/lib/countersign
g countersign-users -
```

`cnd` refuses to run as root, and refuses to run as a uid that `[access]
users` lets connect: the store must not belong to the agent's uid.

### systemd units

The units are [`packaging/countersign.socket`](../packaging/countersign.socket)
and [`packaging/countersign.service`](../packaging/countersign.service); the
files are the reference, and each directive carries a comment. In short:

- The socket listens on `/run/countersign/cnd.sock`, `countersign:countersign-users`
  0660, and is the unit that gets enabled. The service has no `[Install]`
  section; it starts on the first connection.
- `Type=notify-reload`, so systemd 253 or later. `cnd` sends `READY=1` once
  it serves. `systemctl reload countersign` sends SIGHUP: `cnd` re-reads its
  config, writes `config.load`, and applies the new grant limits to new
  requests. A config that does not load leaves the old one in force; the
  error is in the journal.
- `cnd` runs as `countersign` with no capabilities, `NoNewPrivileges=yes`,
  `ProtectSystem=strict` (only `StateDirectory=countersign` is writable),
  `ProtectHome=yes`, `PrivateDevices=yes`, `PrivateTmp=yes`,
  `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, a
  `@system-service` system call filter without `@privileged` and
  `@resources`, `MemoryDenyWriteExecute=yes` and `LimitCORE=0`.
- `ProtectProc=default`, not `invisible`, because `cnd` walks the
  developer's processes through `/proc/<pid>/stat`; no `ProcSubset=pid`,
  because it reads `/proc/sys/kernel/random/boot_id`.
- AF_UNIX is enough for the system D-Bus, which `cnd` uses to reach polkitd
  and logind. Both are filesystem sockets, so the private network namespace
  does not hide them.
- `LoadCredentialEncrypted=countersign-mk` hands `cnd` the master key at
  `$CREDENTIALS_DIRECTORY/countersign-mk`.
- No `RuntimeDirectory=`. systemd would chown it recursively to
  `countersign:countersign`, socket included, and lock the
  `countersign-users` group out. `/run/countersign` is root-owned instead
  (tmpfiles).

`cnd` also calls `prctl(PR_SET_DUMPABLE, 0)` first thing, and zeroizes value
buffers after use. It locks its memory when the memlock limit allows; see the
unit for the limit it runs under.

`cnd` holds **no capabilities**. That has a consequence: `/proc/<pid>/exe`,
`/proc/<pid>/cwd` and `/proc/<pid>/environ` of the developer's processes are
not readable by another uid without `CAP_SYS_PTRACE`. `cnd` therefore relies
only on world-readable `/proc/<pid>/stat`, `/proc/<pid>/cmdline` and
`/proc/<pid>/comm`, and treats the cwd that `cn` reports as an untrusted label.
Project scope is organizational, so an untrusted cwd is acceptable. If the host
mounts `/proc` with `hidepid=`, the `countersign` user must be given the
`gid=` exemption group.

### Configuration

An excerpt; the full annotated file is [examples/config.toml](../examples/config.toml).
Every key is optional and unknown keys are errors, so a typo cannot weaken
policy silently.

```toml
# /etc/countersign/config.toml
[access]
users = ["patrick"]              # users allowed on the socket; must also be in countersign-users
allow_root_clients = false

[grants]
default_ttl = "1h"
max_ttl = "8h"
max_reveal_ttl = "10m"
pending_expiry = "5m"

[sessions]
matchers = [
  { comm = "claude" },
  { cmdline_regex = '(^|/)codex(\s|$)' },
  { comm = "grok" },
]
label_env = ["CLAUDE_CODE_SESSION_ID", "CODEX_SESSION_ID"]

[approval]                       # chains name approver instances from [approvers.*]
use     = "polkit"               # Phase 1: polkit for every kind (decision 14)
reveal  = "polkit"
mutate  = "polkit"
export  = "polkit"

[approvers.polkit]
type = "polkit"
subject = "process"              # the session anchor; "session" once polkit#699 is fixed
timeout = "2m"                   # one dialog stays open at most this long

[hide]
max_streams_per_minute = 30

[unlock]
slots = ["systemd-creds", "recovery"]   # Phase 1; "fido2" is Phase 2
```

A config that names a Phase 2 approver type (`fido2`, `command`) or
`fido2_side` is refused. `cnd` accepts, warns about and ignores
`[approval] list_requires_approval`, `[[audit.sink]]`, `[audit] retention`,
`[audit] checkpoint_command` and `[[standing]]`.

The default chains follow [approvers.md](approvers.md#recommended-default-for-the-owner).
Phase 2 proposes adding a `fido2` approver to `reveal`, `mutate` and `export`
with `all_of`, never `any_of`: an `any_of` is only as strong as its weakest
member, and a `fido2` approver on its own has only the terminal, which the
agent can alter, as its display.

## 3. Store

### Data model

| Field | Type | Notes |
| --- | --- | --- |
| `name` | string | `^[a-z0-9][a-z0-9._-]{0,63}$`. Unique. |
| `value` | bytes | 1 byte to 64 KiB. Never returned by `list`. |
| `description` | string | One line, ≤ 200 characters. |
| `usage` | string | Prose, ≤ 4 KiB. Shown to the agent by `cn show` and `cn list --long`. |
| `projects` | [glob] | Matched against the session's reported cwd and its parents; `~` is the caller's home. Empty = all projects. At most 32 entries of 256 bytes. |
| `tags` | [string] | Free-form. At most 32 entries of 256 bytes. |
| `high_entropy` | bool | Set by the human; `cn add` estimates it and asks when unsure. Controls the default `hide` pattern set. |
| `created`, `updated`, `rotated` | RFC 3339 | `updated` on any change, `rotated` only on value change. |

The default environment variable for a secret is its name in upper snake case:
`.` and `-` become `_`, letters are upper-cased. `clickhouse-prod` maps to
`CLICKHOUSE_PROD`.

### Key hierarchy

```text
MK  master key: 32 random bytes made by the installer, sealed with systemd-creds
    in /etc/credstore.encrypted/countersign-mk; cnd reads it from
    $CREDENTIALS_DIRECTORY/countersign-mk
DK  data key: 32 random bytes, generated by `cnd init`
 ├─ wrapped by key slots (keyslots.json), any one unseals:
 │    systemd-creds   KEK = HKDF-SHA256(MK, "countersign/v1/kek/systemd-creds")
 │    recovery        KEK = Argon2id(recovery phrase), m = 64 MiB, t = 3, p = 1;
 │                    the parameters are stored in the slot
 │    fido2           Phase 2: KEK = HKDF(hmac-secret(salt), "countersign/kek/v1")
 ├─ FK  = HKDF-SHA256(DK, info="countersign/v1/file")       seals store.v1
 ├─ VK  = HKDF-SHA256(DK, info="countersign/v1/value")      seals each value
 └─ AK  = HKDF-SHA256(DK, info="countersign/v1/audit-sign") seed of the Ed25519 checkpoint key
```

"Wrapped" means XChaCha20-Poly1305 with a random nonce. In Phase 1 `cnd init`
always creates both slots, so every store has a portable one.

The recovery phrase is 20 random bytes written as 32 Crockford base32
characters in groups of four, then one 4-character checksum group (the first
20 bits of `SHA-256("countersign/recovery/v1\0" || bytes)`). Input ignores
case, dashes and spaces, and reads `O` as `0` and `I`/`L` as `1`.

- `cnd init` runs once, as the `countersign` user with the credential (the
  installer uses `systemd-run`). It refuses if a store exists, or if the
  audit directory already holds another store's `checkpoint.pub`. It writes
  `keyslots.json` first and `store.v1` last, writes `store.init` as the
  first audit record, and prints the recovery phrase and the audit
  checkpoint public key once on stdout.
- `cnd recover` reads the phrase from stdin, unwraps the data key with it,
  and wraps it again for the `systemd-creds` slot with the current master
  key: the path after a lost or replaced machine key. The store, its data
  key and the checkpoint key stay the same. It writes `keyslot.add`. It
  takes no lock against a running daemon, so stop the service first.
- At start `cnd` unseals with the `systemd-creds` slot without interaction.

Algorithm: **XChaCha20-Poly1305** (RustCrypto `chacha20poly1305`) with random
192-bit nonces, so no nonce counter has to survive crashes. age was considered
for the store and rejected because key slots, FIDO2 `hmac-secret` and per-value
sealing would all sit outside it; Phase 2 uses age for exports (below).

### On-disk format

`store.v1` is one file, rewritten whole on each mutation. A solo developer has
tens to hundreds of secrets, so whole-file rewrites are cheap.

```text
line 1: {"magic":"countersign-store","format":1,"generation":42,"nonce":"<b64>"}
rest:   XChaCha20-Poly1305(FK, nonce, aad=line 1, plaintext=body)
body:   JSON {"secrets":[{name, description, usage, projects, tags, high_entropy,
                          created, updated, rotated,
                          value: {"nonce":"<b64>","ct":"<b64>"}}]}
value.ct = XChaCha20-Poly1305(VK, nonce, aad="countersign/v1/value\0" || name, value)
```

`cnd` keeps the decrypted body in memory as its index. Values stay sealed in
memory and are opened only for `run`, `reveal` and `hide` pattern building,
then zeroized. Binding the name into the value's AAD stops a value from being
moved to another name by editing the file.

### Atomic writes

1. Serialize, encrypt, write `store.v1.tmp` (mode 0600) in the same directory
   and `fsync` it.
2. Hard-link the current `store.v1` to `store.v1.prev.tmp` and rename that
   over `store.v1.prev`; rename the temp file over `store.v1`; `fsync` the
   directory. There is no moment without a `store.v1`.
3. Append the audit records for the change only after step 2 succeeds. If
   they cannot be written, `cnd` restores `store.v1.prev` and the request ends
   denied by `cnd`, with the reason. No partial state is visible.

### Backup

- The raw `store.v1` is safe to copy anywhere, but on a TPM-sealed machine
  it can only be opened elsewhere with the `recovery` slot. Back up
  `keyslots.json` with it.
- Phase 2 adds `cn export --recipient age1...`, which writes the decrypted
  store, values included, encrypted to an age recipient the human controls,
  under an `export` approval, and `cn import --from backup.age` to restore it.

## 4. IPC protocol

### Framing

Each frame is:

```text
u32 big-endian length (of kind + payload) | u8 kind | payload
kind 0x01 = JSON message (UTF-8), max 1 MiB
kind 0x02 = stream data (raw bytes), max 64 KiB, only inside a hide stream
```

### Handshake and versioning

The first frame from the client must be `hello`; anything else closes the
connection. `cnd` then checks the peer's uid (`forbidden_peer`, audited as
`peer.reject`) and the protocol (`unsupported_version`), and answers.

```json
{"type":"hello","id":1,"protocols":[1],"client":"cn/0.1.0",
 "labels":{"CLAUDE_CODE_SESSION_ID":"9f3c…"},"cwd":"/home/patrick/projects/x"}
{"type":"hello_ok","id":1,"protocol":1,"server":"cnd/0.1.0",
 "session":{"id":"s_7k2mq9d4x1ha","anchor":{"pid":41210,"starttime":8812345,"comm":"claude","registered":true}, …}}
```

`cnd` resolves the session (section 5) during the handshake, from the
connection's peer credentials. The session is fixed for the connection.
`hello` never fails for want of a session: `session` is `null` then, and the
requests that need one answer `no_session`. `cnd` keeps the labels named in
`label_env` (at most 8, each at most 128 bytes of printable ASCII) and the
first 4096 bytes of the cwd, both as untrusted text.

Each request carries an `id`; the response echoes it. One request is in flight
per connection, except that a `run` connection stays open until `run_finish`
and a `hide` connection carries stream frames.

Protocol rules: unknown fields are ignored; unknown `type` values return
`unknown_request`; a breaking change increments the protocol number, and
`cnd` supports the previous version for one minor release. Times on the wire
are RFC 3339 UTC strings with whole seconds; durations are integer seconds in
fields ending `_seconds`.

### Messages

| Request | Key fields | Response |
| --- | --- | --- |
| `hello` | `protocols`, `client`, `labels`, `cwd` | `hello_ok` with the session view, or `null` |
| `session` | — | `session`: anchor, chain, labels, cwd, grant count |
| `list` | `all_projects` | `list`: each secret's metadata, usage included, default variable, in-project flag, this session's grant and last use |
| `request` | `names[]`, `mode` (`use`/`reveal`), `ttl_seconds` (optional), `reason` | `request_created` with the request view, or `already_granted` |
| `get_request` | `code`, `wait_seconds` (optional) | `request_status` with the request view; with a wait, answers when the request leaves `pending` or the wait ends (`cnd` caps one wait at 60 s) |
| `approve` | `code`, `approver`, `assertion` | Phase 2. Phase 1 answers `bad_request`. |
| `deny` | `code`, `reason` (optional) | `denied` |
| `grants` | `all_sessions` | `grants` |
| `revoke` | exactly one of `grant_ids[]`, `secret`, `all`; `all_sessions` | `revoked` with the grants ended |
| `run` | `uses[]: {name, env}`, `argv0`, `argc` | `run_ok`: `run_id`, `values[]: {name, env, value_b64}`, `patterns_extra[]: {name, value_b64}` |
| `run_finish` | `run_id`, `exit`, `signal`, `duration_ms`, `hits{name:n}` | `ok` |
| `hide` | `secrets[]` (extra granted names) | `hide_ok`, then stream frames both ways; client sends `hide_end`, `cnd` answers `hide_summary {bytes_in, bytes_out, hits}` |
| `reveal` | `name` | `reveal`: `value_b64`, `reveals_left` |
| `add` | `meta` (name and metadata), `value_b64`, `source` | `request_created` (kind `mutate`) |
| `set` | `name`, `value_b64`, `source` | `request_created` |
| `edit` | `meta` (the full new metadata; `meta.name` selects the secret) | `request_created` |
| `rm` | `names[]` | `request_created` (one request for all) |
| `import` | `secrets[]: {meta, value_b64}` | `request_created` (one request for the batch) |
| `audit_query` | `session`, `secret`, `events[]`, `since`, `until`, `after_seq`, `limit` | `audit_records`: the newest matches in `seq` order, at most 1000 |
| `audit_segments` | `from_seq` | `audit_segments`: complete JSONL lines (`data_b64`), `next_seq` when more follow, and `checkpoint.pub` |
| `session_register` | `label` | `registered` (anchor = the caller's pid and start time) |
| `unlock` | — | Phase 2. Phase 1 answers `unknown_request`. |

The request view is the canonical request (section 6) plus `state`
(`pending`, `approved`, `denied`, `expired`), `digest`, `digest_short`, the
chain's approvers, and once decided a `decision`: when, by whom, why, and the
grant it created or the number of grants a store change revoked. A decided
request stays findable by its code for `pending_expiry`.

### Errors

```json
{"type":"error","id":7,"code":"grant_required","message":"no active use grant for clickhouse-prod","detail":{"names":["clickhouse-prod"]}}
```

| Code | Meaning |
| --- | --- |
| `unsupported_version` | No common protocol version. |
| `forbidden_peer` | Peer uid not allowed on the socket. |
| `no_session` | No anchor found for the caller (section 5), or the request needs an agent session. |
| `session_dead` | Anchor exited. |
| `unknown_secret` | Name not in store. |
| `grant_required` | No active grant covering name and mode. |
| `request_expired`, `request_not_found` | Bad, stale or already decided code. |
| `rate_limited` | A per-session limit: pending requests, requests per hour, deny cooldown, `list` calls, hide streams or bytes. |
| `limit_exceeded` | TTL above its maximum, too many names, reason too long, reveal disabled, another project under `cross_project = "deny"`. |
| `bad_request` | Invalid arguments: a bad name or metadata, a value too large, a `revoke` without exactly one selector. |
| `secret_exists` | `add` or `import` of a name already in the store. |
| `unknown_request` | The request `type` is not known, or not in this version. |
| `internal` | Server fault; details only in the daemon log. |
| `approval_invalid`, `approver_unavailable`, `store_sealed` | Defined for Phase 2; `cnd` does not send them in Phase 1. |

## 5. Sessions

### Anchor discovery

Run once per connection, during `hello`:

1. **Peer.** Get `SO_PEERPIDFD`, which gives a pidfd for the connecting
   process without a pid-reuse race, and `SO_PEERCRED` for its uid. Linux 6.5
   or later is required; `cnd` refuses to start without `SO_PEERPIDFD`
   (decision 16). Reject the peer if its uid is not in `[access]`, or is 0 and
   `allow_root_clients` is false.
2. **Read stat.** Parse `/proc/<pid>/stat` from the *last* `)` (the `comm`
   field may contain spaces and parentheses). Take field 4 (`ppid`) and field
   22 (`starttime`, clock ticks since boot).
3. **Walk.** Step to the parent, requiring `parent.starttime <=
   child.starttime` and re-reading the child afterwards to confirm it was not
   reparented meanwhile; a violation fails closed. Stop at pid 1, at a
   process whose uid differs from the peer's (sshd, sudo, a system service),
   at a registered anchor, or after 64 steps.
4. **Choose the anchor.** The nearest process registered by `cn session exec`
   wins, even over a nearer process a matcher accepts. Without one, the
   nearest process whose `/proc/<pid>/comm` or `/proc/<pid>/cmdline` a
   configured matcher accepts is the anchor. Otherwise there is no session.
   The process sets its own `comm` and `cmdline`, so a matcher identifies a
   session; it does not authenticate one. Only the launcher gives a session
   boundary the human chose.
5. **Confirm.** After the walk, the peer's pidfd must still be unreadable
   (peer alive), so the chain was valid at one instant.
6. **Record.** Session id = `"s_"` + the first 12 lower-case Crockford base32
   characters of `SHA-256("countersign/session/v1\0" || boot_id || "\0" ||
   pid || "\0" || starttime)`, pid and start time in decimal, `boot_id` from
   `/proc/sys/kernel/random/boot_id`. The first time `cnd` sees a session it
   writes `session.start`, opens a pidfd for the anchor and confirms it is
   the same process (start time).

Labels and the cwd are stored with the session and shown in approval displays
and audit records, always marked untrusted.

### Human sessions

A store change (`add`, `set`, `edit`, `rm`, `import`) is meant to be run from
a terminal outside any agent session, where the walk finds no anchor. For
that case `cnd` makes a pseudo-session anchored at the peer's parent (normally
the human's shell), with an `h_` id. It is accepted for store changes and
read-only calls (`list`, `grants`, `revoke`, `hide`, the audit reads), never
for `request`, `run`, `reveal` or `session`: those need an agent session and
answer `no_session`.

### Liveness

`cnd` adds each anchor pidfd to an epoll set. When the pidfd becomes
readable, the anchor has exited: `cnd` expires the session's grants and
pending requests (withdrawing their dialogs), and writes `grant.expire`,
`request.expire` and `session.end`. Grants live only in memory; stopping
`cnd` revokes every grant (`grant.revoke` with `by: "restart"`). That is
deliberate: a restart fails closed.

### `cn session exec`

```sh
/usr/bin/cn session exec --label "liskov drift" -- claude
```

`cn` connects, sends `session_register` with the label, and `cnd` records the
peer's `(pid, starttime)` from the kernel as an anchor. `cn` then `execve`s the
agent with its `COUNTERSIGN_*` variables removed. `execve` keeps the pid and
the start time, so the agent process *is* the registered anchor; there is no
extra process to keep alive and nothing an intermediate shell can break.
Registration ends when the anchor exits. The label is kept as at most 128
printable ASCII characters.

`cn session` prints what `cnd` resolved:

```text
session   s_7k2mq9d4x1ha  (registered by cn session exec, label "liskov drift")
anchor    pid 41210  comm claude  started 2026-11-08T09:14:03Z
chain     41377 cn <- 41376 bash <- 41210 claude
cwd       /home/patrick/projects/x  (reported, untrusted)
labels    CLAUDE_CODE_SESSION_ID=9f3c… (untrusted)
grants    2 active
```

### Edge cases

| Case | Behaviour |
| --- | --- |
| `nohup cmd &` | Parent unchanged; still under the anchor; grants apply. |
| `setsid`, new process group | `ppid` unchanged; grants apply. |
| Double-fork daemon, `disown` after parent exit | Reparented to init or a subreaper outside the anchor; `no_session`. Fails closed. |
| Agent itself is a subreaper | Orphans reparent to the agent, still under the anchor. |
| tmux: agent runs inside a pane | Anchor is inside the pane; works. |
| tmux: agent creates a new window | The new shell is a child of the tmux server, not of the agent; `no_session`. |
| `systemd-run --user`, `at`, cron | Not descendants; `no_session`. |
| `sudo cn …` | Peer is root; rejected unless `allow_root_clients`. A walk never crosses a uid change. |
| SSH | sshd's session process has another uid, so the walk stops there; an anchor below it (the agent, or `cn session exec`) works as on a local terminal. |
| Nested `cn session exec` inside a session | Creates a new, nearer session with no grants. No escalation: every grant still needs approval. |
| Agent creates a long-lived anchor (`systemd-run --user cn session exec -- sleep inf`) | Possible. Its grants still need approval, and the display shows the anchor. Bounded by `max_ttl`. |
| PID namespaces, containers | Out of scope v1; pids from a namespace do not match host `/proc`. |

## 6. Grants

### Lifecycle

```text
                 approve (the whole chain)
  ┌─────────┐ ─────────────────────────────────► ┌──────────┐  ttl elapsed     ┌─────────┐
  │ pending │                                    │  active  │ ────────────────►│ expired │
  └─────────┘ ─── deny ──► denied                └──────────┘                  └─────────┘
      │       ─── no decision possible ──► denied (by cnd)  │  cn revoke / anchor exit /
      │       ─── pending_expiry, dialog timeout ──► expired │  value change / restart
      │       ─── anchor exit ──► expired                    └──────────────► revoked/expired
```

`pending` → `approved` is immediate when the chain approves; the grant becomes
`active` at that moment, and its TTL is counted from approval, not from the
request. Denied, expired and revoked are terminal. A reveal grant is also
consumed after `max_reveal_uses` reveals (default 1).

How the chain's result ends a request ([approvers.md](approvers.md#chaining)):

| Chain result | Request | Notes |
| --- | --- | --- |
| Approved | approved | The grant becomes active, or the store change commits. |
| Denied (the human pressed Cancel, or failed to authenticate) | denied | The secrets go into deny cooldown for the session. |
| Timeout (the request expired, or the polkit dialog's own `timeout`, 2 minutes by default) | expired | `request.expire`. |
| Unavailable, fault or invalid answer | denied, by `cnd` | The reason is in the decision and the audit log (`request.deny` with approver `cnd`). No deny cooldown. |
| Cancelled (`cn deny`, expiry, anchor exit) | as the canceller set it | |

Phase 1 has no way to raise a dialog again for the same request. After a
timeout or an unavailable approver, the agent requests again.

| Limit | Default | Config |
| --- | --- | --- |
| Use grant TTL | 1h | `default_ttl`; at most `max_ttl` (8h), above which a request is refused |
| Reveal grant TTL | `min(default_ttl, max_reveal_ttl)`, 10m; 1 use | `max_reveal_ttl`, `max_reveal_uses`; `allow_reveal = false` refuses reveal |
| Pending request lifetime | 5m | `pending_expiry` |
| Names per request | 16 | `[limits] max_names_per_request`; may be lowered, not raised. `import` is not limited. |
| Pending requests per session | 3 | `[limits] max_pending_requests` |
| Requests per session per hour | 30 | `[limits] requests_per_hour` |
| Deny cooldown for the same secrets | 2m | `[limits] deny_cooldown` |
| Reason | 2048 bytes | fixed |

With `[audit] redact_agent_text` (the default), the reason passes through the
session's hide set (section 8) before anything else sees it: the dialog, the
digest and `request.create` all carry the redacted reason.

### Request codes

A code is 6 characters of Crockford base32 shown as `K7M-Q2X` (30 bits),
random, unique among pending requests and those decided within
`pending_expiry`. Input is case-insensitive, the dash is optional, and per
Crockford `O` reads as `0` and `I`/`L` as `1`. The code is a handle for
humans, not a credential: knowing it lets anyone see the request or deny it,
not approve it.

### Request digest

The human compares, and in Phase 2 a FIDO2 approver signs, a digest over a
canonical request:

```json
{
  "domain": "countersign/approve/v1",
  "request_id": "r_<26 base32 characters>",
  "code": "K7M-Q2X",
  "host": "<machine-id>",
  "boot_id": "<boot id>",
  "session": "s_7k2mq9d4x1ha",
  "anchor": {"pid": 41210, "starttime": 8812345, "comm": "claude", "registered": true},
  "cwd": "/home/patrick/projects/x",
  "secrets": ["clickhouse-prod", "github-token"],
  "mode": "use",
  "ttl_seconds": 3600,
  "reason": "run the drift report against prod",
  "created_at": "2026-11-08T09:20:11Z",
  "expires_at": "2026-11-08T09:25:11Z",
  "nonce": "<256-bit random from cnd, base64url>"
}
```

- `mode` is `use`, `reveal` or `mutate` (`export` in Phase 2).
- `ttl_seconds` is present for `use` and `reveal` only.
- `operation` is present for `mutate` only, in a short form: `add NAME`,
  `set NAME`, `edit NAME`, `rm a b`, `import a b`. A store change carries an
  empty `reason`.
- `cwd` is `null` when the client reported none. An absent optional field is
  left out of the bytes, not written as `null`.

Canonical encoding is RFC 8785 (JCS): sorted keys, no whitespace, UTF-8.
`secrets` is sorted. `digest = SHA-256(JCS(request))`. The short form shown
to humans is the first 8 Crockford base32 characters of the digest (its first
40 bits), e.g. `digest 3QF8-ZK2M`. It appears in `cn request` and
`cn approve` output and in the polkit message, so a shadowed `cn` that shows a
different request also shows a different short digest from the one the
dialog shows. `cn` recomputes the digest from the canonical request `cnd`
returns and refuses if it differs.

## 7. `cn run`

```sh
cn run --use clickhouse-prod --use github-token=GH_TOKEN -- ./scripts/drift.py --env prod
```

1. `cn` connects and sends `run` with `uses`, `argv0` and `argc`. Full argv
   is not sent; it can contain anything.
2. `cnd` checks that each name has an active `use` grant in the caller's
   session, writes `use.start` with a `run_id`, and returns the values, plus
   in `patterns_extra` the values of the session's other `use`-granted
   secrets, so `cn` scrubs those too. The connection stays open.
3. `cn` builds the child's environment: its own environment minus any
   `COUNTERSIGN_*` variables, plus each `ENV=value`. It refuses with exit 125
   if two uses map to one variable, a mapped variable name is not a valid
   identifier, or it starts with `COUNTERSIGN_`.
4. `cn` builds a redaction engine (`countersign-hide`) from all those values
   and their encodings.
5. `cn` starts the child with the built environment, stdin inherited and
   stdout and stderr on pipes. The child stays in `cn`'s process group so a
   terminal `^C` reaches it directly. `cn` drops its own copies of the values
   (the engine keeps its patterns).
6. `cn` copies child stdout and stderr through the engine to its own stdout
   and stderr, each stream with its own carry-over buffer (section 8).
7. On child exit `cn` flushes both streams, sends `run_finish` with the exit
   status, duration and per-secret hit counts, and exits.

| Concern | Behaviour |
| --- | --- |
| Exit code | Child's exit code. Killed by signal N: 128+N. `cn` itself: 125 before exec, 126 not executable, 127 not found (as `env(1)`). |
| Signals | `cn` forwards SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGWINCH to the child; ignores SIGINT itself (the child gets it from the terminal) and keeps scrubbing until the child exits. |
| TTY | The child's stdout/stderr are pipes, so it sees no TTY. `--pty` (later) will run the child on a pseudo-terminal and scrub the pty master. Stdin is passed through untouched. |
| `cn` killed | `cnd` sees the connection close and writes `use.end` with `status: "client_lost"`. |
| Grant expires mid-run | The child keeps running; values are already in its environment. TTL governs when a value can be *issued* (threat model T8). |

## 8. `cn hide`

```sh
make deploy 2>&1 | cn hide
```

### Stream

`cn` sends `hide`, then forwards stdin as stream frames of up to 64 KiB. `cnd`
returns scrubbed stream frames. At EOF `cn` sends `hide_end`; `cnd` flushes
the remainder, writes a `hide` audit record with byte counts, per-secret hit
counts and the number of patterns, and returns `hide_summary`. A stream the
client abandons is audited too. Values never enter the developer's uid for
hiding.

### Pattern set

By default (`[hide] include = ["granted", "high_entropy"]`): every secret with
an active grant in the caller's session, plus every secret marked
`high_entropy`, plus any granted secret named with `--secret`. A low-entropy
secret that is not granted is never in the set, so `hide` cannot be used as a
guessing oracle for it. Outside an agent session (a human's terminal) nothing
is granted, so the set is the high-entropy secrets. Values shorter than 8
bytes (`min_value_len`) are never patterns (false positives, and they are
guessable); `cn add` warns about them.

For each value the engine adds:

- the raw bytes;
- base64 standard and URL-safe, padded and unpadded, and the three alignment
  variants of the value embedded in a longer base64 string (encode with 0, 1
  and 2 bytes of prefix, then drop the characters that depend on unknown
  neighbours), which covers `Authorization: Basic` headers;
- percent-encoding, upper- and lower-case hex;
- JSON string escaping;
- hex, lower and upper case.

The raw form of a multi-line value (a PEM key) is split into per-line
patterns, each line of at least 16 bytes (shorter lines are not matched),
instead of one pattern containing `\n`. So no pattern contains
a newline, which the flush rule below relies on.

All patterns go into one Aho-Corasick automaton (`aho-corasick` crate,
leftmost-longest). Each pattern maps to its secret name, and a match is
replaced with `[countersign:NAME]`.

### Chunk boundaries

Let `L` be the longest pattern length. For each incoming chunk:

1. `buf = carry || chunk`.
2. Find all leftmost-longest matches in `buf`.
3. Safe boundary `b = len(buf) - (L - 1)`. No match that ends past the end of
   `buf` can start before `b`.
4. Commit, in order, every match that starts before `b`, and extend `b` to
   the end of any committed match that crosses it. Matches that start at or
   after `b` are not committed: a longer pattern may still complete there.
5. Emit `buf[0..b]` with committed matches replaced; `carry = buf[b..]`.

The carry is therefore never longer than `L - 1` bytes.

### Flush semantics

- Because no pattern contains `\n`, everything up to and including the last
  newline in `buf` is also safe to emit, so line-oriented output passes with
  no visible delay. Only a partial last line can be held back, at most `L - 1`
  bytes.
- At EOF the carry is scanned once more and emitted.
- No idle-timeout flush: emitting a held tail early could split a value. A
  prompt without a newline waits until more output or EOF. This is the price
  of correctness and is documented.

### Rate limiting

Per session: `max_streams_per_minute` new hide streams (default 30) and a
byte budget, `max_bytes_per_minute` (default 256 MiB). Excess returns
`rate_limited` and ends the stream. Every stream is audited with hit counts,
so repeated probing is visible.

## 9. Store mutations

| Command | Approval kind | `operation` (signed) | The dialog shows |
| --- | --- | --- | --- |
| `cn add NAME` | `mutate` | `add NAME` | `ADD secret NAME: description (value 16 to 63 bytes, from the clipboard, high entropy)` |
| `cn set NAME` | `mutate` | `set NAME` | `SET a new value for NAME (16 to 63 bytes, from stdin); grants for it are revoked` |
| `cn edit NAME` | `mutate` | `edit NAME` | `EDIT NAME: changes usage, projects` |
| `cn rm NAME...` | `mutate` | `rm a b` | `REMOVE 2 secrets: a, b` |
| `cn import` | `mutate` | `import a b c` | `IMPORT 3 secrets: a, b, c` |
| `cn export` | `export` | Phase 2 | |

The value's size is shown only as a class (`under 16 bytes`, `16 to 63
bytes`, `64 to 1023 bytes`, `1 KiB or more`), and never reaches the audit
log. The dialog also shows the session the change came from (section 5,
human sessions). A store change carries no reason.

The value travels with the `add`/`set` request and is held by `cnd` with the
pending request, so an approval applies to the exact value submitted; nothing
can be swapped in after the human approves. `cnd` checks the change against
the store when the request is created (`secret_exists`, `unknown_secret`,
`bad_request`) and applies it when the chain approves. `set` and `rm` revoke
every grant for the secrets they change (`grant.revoke` with `by:
"store_change"`). Value sources, in order of preference:

```sh
/usr/bin/cn set clickhouse-prod                 # no-echo prompt, needs a real TTY
/usr/bin/cn set clickhouse-prod --from-clipboard
/usr/bin/cn set clickhouse-prod --from-file ./key.txt --wait   # file overwritten and removed once approved
printf %s "$V" | /usr/bin/cn set clickhouse-prod --from-stdin
```

Without a TTY (a Claude Code `!` command) the prompt path is refused with a
message naming the other options; `cn` never blocks waiting on a read.

## 10. Unattended sessions (phase 2 sketch)

A host running agents with no human present cannot answer prompts. A
**standing grant** is declared in `/etc/countersign/config.toml` (writing it is
a root act) and activated once by a human approval:

```toml
[[standing]]
id = "factory-ci-read"
anchor = { systemd_unit = "gascity-agent@*.service" }   # or { exe = "/usr/bin/foo", uid = 1001 }
secrets = ["github-token-ro"]
mode = "use"
issue_ttl = "15m"          # each issuance; renewed per run
expires = "2026-12-31"
```

`cnd` resolves the anchor through `/proc/<pid>/cgroup` (unit name) instead of
the ppid walk. Activation is `cn standing activate factory-ci-read`, approved
like a request; the approval's signature is stored. Reveal and mutate are
never standing. Every use is audited as usual with `standing: id`.

## 11. Crate responsibilities

| Crate | Responsibilities |
| --- | --- |
| `countersign-proto` | Frame codec, request and response enums (serde), protocol version, error codes, request codes, `ApprovalKind`, the canonical request and its JCS digest (shared so `cn` and `cnd` compute the same bytes). |
| `countersign-core` | Config parsing and validation, including the chain and approver config types; store format and crypto, key slots, recovery phrase, atomic writes, data-model validation; session discovery; request and grant state machine and limits; audit writer, chain, checkpoints, query and verifier. Used by `cnd`; the verifier also by `cn`. |
| `countersign-approve` | The `DaemonApprover` trait, the approver `Registry`, chain evaluation (`countersign_approve::evaluate`), the display sanitiser, the `polkit` adapter (zbus), and `insecure-auto` behind the debug-only `insecure-test` feature (decision 17). Phase 2: `fido2`, `command`. |
| `countersign-hide` | Pattern generation from values and encodings, Aho-Corasick engine, chunk-boundary carry-over, newline flush. Used by `cnd` for `hide` and by `cn` for `run`. |
| `countersign-daemon` | `cnd`: socket activation, accept loop (tokio), peer credentials, anchor liveness (epoll on pidfds), request dispatch, approver chains, timers, reload, `sd_notify`, `init` and `recover`. |
| `countersign-cli` | `cn`: argument parsing, `run` and scrubbing, `hide` streaming, `audit verify`, `session exec`, `import`, `doctor`. Phase 2: FIDO2 client side for `approve` and `unlock`. |

## 12. Open questions

1. ~~**polkit message rendering.**~~ Settled by the
   [spike](../spikes/polkit-dialog/README.md): polkit 128 interpolates the
   details `cnd` passes as the action owner, and GNOME Shell shows the whole
   message. KDE is unchecked.
2. ~~**Peer start-time check on pre-6.5 kernels.**~~ Settled by decision 16:
   Linux 6.5 or later, `SO_PEERPIDFD` only.
3. **Mutation previews.** The human approving `cn set` for a DSN cannot see
   whether the new value points at an attacker's host. Show a masked preview
   for URL-shaped values (scheme and host, no userinfo) in the trusted
   display? That reveals part of the value to the screen but not to the agent.
4. **File-shaped secrets.** Some tools want a path, not an env var
   (`GOOGLE_APPLICATION_CREDENTIALS`). A `--use-file NAME=VAR` that passes a
   `memfd` as `/proc/self/fd/N` is the likely answer; not designed yet.
5. ~~**Recovery slot at init.**~~ Settled for Phase 1: `cnd init` always
   creates the recovery slot and prints the phrase once (decision 14).
6. **Grants surviving a `cnd` restart.** In-memory grants mean a package
   upgrade revokes everything mid-task. Accept, or persist grants bound to
   (boot id, anchor pid, start time) which can be revalidated?
7. **Raising a dialog again.** Phase 1 cannot re-raise a dialog that timed
   out or was dismissed by accident; the agent requests again. Should
   `cn approve` re-raise it, and from which callers?
