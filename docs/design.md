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
 │          │    └─ ./x.py (env: DB=…)   │        │  - approver dispatch         │
 │          └─ make | cn hide            │        └──────┬────────────┬──────────┘
 │                                       │               │ D-Bus      │ hidraw
 │ human: ! cn approve K7M-Q2X ──────────┼── FIDO2 ──┐   │ (system)   │ (optional)
 └───────────────────────────────────────┘           │   ▼            ▼
                                                      │  polkitd     YubiKey
 graphical session                                    │   │
 ┌───────────────────────────────────────┐           │   ▼
 │ polkit agent (gnome-shell) – dialog   ◄───────────┼── polkitd asks the
 │   optionally backed by pam_u2f        │           │   session's agent
 └───────────────────────────────────────┘           └► YubiKey (via /dev/hidraw,
                                                          uaccess ACL for the seat user)
```

| Process | uid | Role |
| --- | --- | --- |
| `cn` | developer | Client. Talks to `cnd`; forks the child for `cn run`; scrubs its output locally; performs the FIDO2 assertion for `cn approve`. |
| `cnd` | `countersign` | Owns the store, grants, sessions and audit log. Decides every request. Never runs agent-supplied commands. |
| polkitd + polkit agent | root / developer | Daemon-driven approver. `cnd` calls `CheckAuthorization`; the desktop renders the dialog. |
| YubiKey | n/a | FIDO2 credential used for approval and, optionally, store unlock. |
| `cn session exec` | developer | Launcher that registers itself as a session anchor and then `exec`s the agent, keeping the same pid. |

In Phase 1 polkit is the only approver (decision 14): every approval is the
desktop dialog. The FIDO2 paths in the picture (`! cn approve` with a key
touch, daemon-side hidraw) are Phase 2.

`cnd` is the only process that can read the store file or write the audit log.
`cn` is an ordinary client: nothing it tells `cnd` is trusted except what the
kernel attests (peer credentials, pidfd) and what an approver signs.

## 2. Installation layout

| Path | Owner / mode | Contents |
| --- | --- | --- |
| `/usr/bin/cn` | root 0755 | CLI. Documentation tells humans to approve with `/usr/bin/cn` by absolute path. |
| `/usr/libexec/countersign/cnd` | root 0755 | Daemon. |
| `/usr/lib/systemd/system/countersign.{socket,service}` | root 0644 | Units ([below](#systemd-units)). |
| `/usr/lib/sysusers.d/countersign.conf`, `/usr/lib/tmpfiles.d/countersign.conf` | root 0644 | User, group and directories. |
| `/usr/share/polkit-1/actions/computer.mooselabs.countersign.policy` | root 0644 | The three polkit actions ([approvers.md](approvers.md#actions)). |
| `/etc/countersign/config.toml` | root 0644 (0640 `root:countersign` if it holds adapter credentials) | Policy: approvers, TTL limits, matchers, allowed uids. Not writable by the agent. `cnd --config PATH` overrides the path. |
| `/etc/countersign/u2f_mappings` | root 0644 | Touch factors only: the `pam_u2f` key enrolment, origin `pam://countersign`. Root-owned so the agent cannot add a key. |
| `/etc/pam.d/polkit-1` | root 0644 | Touch factors only: polkit's PAM stack with `pam_u2f`, written by the installer from the distribution's `/usr/lib/pam.d/polkit-1`. Machine-wide. |
| `/etc/systemd/system/polkit-agent-helper@.service.d/countersign-hidraw.conf` | root 0644 | Touch factors only: lets polkit's sandboxed PAM helper open the key. |
| `/etc/credstore.encrypted/countersign-mk` | root 0600 | Master key, 32 random bytes sealed with `systemd-creds` (TPM2 if present, else host key) by the installer. |
| `/var/lib/countersign/` | countersign 0700 | `store.v1`, `store.v1.prev`, `keyslots.json`, `audit/`. `$STATE_DIRECTORY` or `cnd --state-dir PATH` overrides the path. |
| `/run/countersign/` | root 0755 | Holds the socket. Root-owned, so no other process can replace the socket. |
| `/run/countersign/cnd.sock` | countersign:countersign-users 0660 | IPC socket. |
| `/etc/countersign/approvers.d/` | root 0755, records 0644 | Phase 2: enrolled FIDO2 credential records (`NAME.approver.toml`). Approver policy, so root-owned (threat model T13). FIDO2 signature counters go in `/var/lib/countersign/approvers/`. |
| `/usr/lib/udev/rules.d/70-countersign.rules` | root 0644 | Phase 2: optional hidraw access for daemon-side FIDO2. |

[`packaging/install.sh`](../packaging/install.sh) installs all of it; see
[packaging/README.md](../packaging/README.md).

### Fixed user, not DynamicUser

The service runs as a fixed system user `countersign` created by
`sysusers.d`, not `DynamicUser=yes`:

- The store and audit log must keep a stable owner across reboots, package
  upgrades and restores from backup. DynamicUser state lives under
  `/var/lib/private` with a uid that can change, which complicates restores
  and manual inspection by root.
- The udev rule and any off-box tooling refer to the group by name.
- The `countersign-users` group (members: the developer, and later a sandbox
  uid) gates the socket. A dynamic user cannot own a stable group for that.

```text
# /usr/lib/sysusers.d/countersign.conf
u countersign - "countersign secret daemon" /var/lib/countersign
g countersign-users -
```

### systemd units

The units are [`packaging/countersign.socket`](../packaging/countersign.socket)
and [`packaging/countersign.service`](../packaging/countersign.service); the
files are the reference, and each directive carries a comment. In short:

- The socket listens on `/run/countersign/cnd.sock`, `countersign:countersign-users`
  0660, and is the unit that gets enabled. The service has no `[Install]`
  section; it starts on the first connection (`Type=notify`).
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

`cnd` also calls `prctl(PR_SET_DUMPABLE, 0)` and `mlockall(MCL_CURRENT|MCL_FUTURE)`
where the memlock limit allows, and zeroizes value buffers after use. The unit
leaves `LimitMEMLOCK` at systemd's default (8 MiB); with `MCL_FUTURE`, any
allocation beyond the limit fails, so `cnd` must check the limit before
locking everything.

`cnd` holds **no capabilities**. That has a consequence: `/proc/<pid>/exe`,
`/proc/<pid>/cwd` and `/proc/<pid>/environ` of the developer's processes are
not readable by another uid without `CAP_SYS_PTRACE`. `cnd` therefore relies
only on world-readable `/proc/<pid>/stat`, `/proc/<pid>/cmdline` and
`/proc/<pid>/comm`, and treats the cwd that `cn` reports as an untrusted label.
Project scope is organizational, so an untrusted cwd is acceptable. If the host
mounts `/proc` with `hidepid=`, the `countersign` user must be given the
`gid=` exemption group.

### Daemon-side FIDO2 (Phase 2, optional)

When `[unlock] fido2_side = "daemon"` is set, `cnd` talks to the key itself so
the `hmac-secret` output never enters the developer's uid:

```text
# 70-countersign.rules
SUBSYSTEM=="hidraw", ENV{ID_FIDO_TOKEN}=="1", GROUP="countersign", MODE="0660", TAG+="uaccess"
```

The unit then sets `PrivateDevices=no` and `DeviceAllow=char-hidraw rw`.
`TAG+="uaccess"` keeps the seat user's access, so `cn approve` still works.

### Configuration

An excerpt; the full annotated file is [examples/config.toml](../examples/config.toml).

```toml
# /etc/countersign/config.toml
[access]
users = ["patrick"]              # peer uids allowed on the socket; must also be in countersign-users
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
list_requires_approval = false

[approvers.polkit]
type = "polkit"
subject = "process"              # the session anchor; "session" once polkit#699 is fixed

[hide]
max_streams_per_minute = 30

[unlock]
slots = ["systemd-creds", "recovery"]   # Phase 1; "fido2" is Phase 2
```

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
| `value` | bytes | Up to 64 KiB. Never returned by `List`. |
| `description` | string | One line, ≤ 200 chars. |
| `usage` | string | Prose, ≤ 4 KiB. Shown to the agent by `cn list`. |
| `projects` | [glob] | Matched against the anchor's reported cwd. Empty = all projects. |
| `tags` | [string] | Free-form. |
| `high_entropy` | bool | Set by the human; `cn add` suggests a value based on an entropy estimate. Controls the default `hide` pattern set. |
| `created`, `updated`, `rotated` | RFC 3339 | `updated` on any change, `rotated` only on value change. |
| `limits` | object, optional | Reserved for phase 2 hard limits (`exe`, `hosts`). Parsed and ignored in v1, with a warning. |

The default environment variable for a secret is its name in upper snake case:
`.` and `-` become `_`, letters are upper-cased. `clickhouse-prod` maps to
`CLICKHOUSE_PROD`.

### Key hierarchy

```text
MK  master key: 32 random bytes made by the installer, sealed with systemd-creds
    in /etc/credstore.encrypted/countersign-mk; cnd reads it from
    $CREDENTIALS_DIRECTORY/countersign-mk
DK  data key: random, generated by `cnd init`
 ├─ wrapped by key slots (keyslots.json), any one unseals:
 │    systemd-creds   DK wrapped with MK
 │    recovery        DK wrapped with KEK = Argon2id(recovery phrase), the phrase
 │                    generated and printed once by `cnd init`
 │    fido2           Phase 2: DK wrapped with KEK = HKDF(hmac-secret(salt), "countersign/kek/v1")
 ├─ FK  = HKDF-SHA256(DK, info="countersign/v1/file")       seals store.v1
 ├─ VK  = HKDF-SHA256(DK, info="countersign/v1/value")      seals each value
 └─ AK  = HKDF-SHA256(DK, info="countersign/v1/audit-sign") seed of the Ed25519 checkpoint key
```

"Wrapped" means XChaCha20-Poly1305 with a random nonce. In Phase 1 `cnd init`
always creates both slots, so every store has a portable one. It runs once,
as the `countersign` user with the credential (the installer uses
`systemd-run`), refuses if a store exists, and prints the recovery phrase once
on stdout. `cnd recover` reads the phrase from stdin, unwraps the data key
with it, and wraps it again for the `systemd-creds` slot with the current
master key: the path after a lost or replaced machine key. At start `cnd`
unseals with the `systemd-creds` slot without interaction. With a `fido2`
slot only (Phase 2), `cnd` would start sealed and answer `store_sealed` until
`cn unlock` succeeds.

Algorithm: **XChaCha20-Poly1305** (RustCrypto `chacha20poly1305`) with random
192-bit nonces, so no nonce counter has to survive crashes. age was considered
for the store and rejected because key slots, FIDO2 `hmac-secret` and per-value
sealing would all sit outside it; age is used for exports (below).

### On-disk format

`store.v1` is one file, rewritten whole on each mutation. A solo developer has
tens to hundreds of secrets, so whole-file rewrites are cheap.

```text
line 1: {"magic":"countersign-store","format":1,"generation":42,"nonce":"<b64>"}
rest:   XChaCha20-Poly1305(FK, nonce, aad=line 1, plaintext=body)
body:   JSON {"secrets":[{name, description, usage, projects, tags, high_entropy,
                          created, updated, rotated, limits,
                          value: {"nonce":"<b64>","ct":"<b64>"}}]}
value.ct = XChaCha20-Poly1305(VK, nonce, aad="countersign/v1/value\0" || name, value)
```

`cnd` keeps the decrypted body in memory as its index. Values stay sealed in
memory and are opened only for `Run`, `Reveal`, `Hide` pattern building and
export, then zeroized. Binding the name into the value's AAD stops a value
from being moved to another name by editing the file.

### Atomic writes

1. Serialize, encrypt, write `store.v1.tmp` (mode 0600) in the same directory.
2. `fsync` the file, rename `store.v1` to `store.v1.prev`, rename the temp
   file to `store.v1`, `fsync` the directory.
3. Append the audit record for the mutation only after step 2 succeeds.
   A failure at any step leaves the previous store intact and returns
   `internal` to the client; no partial state is visible.

### Backup and export

- The raw `store.v1` is safe to copy anywhere, but on a TPM-sealed machine
  it can only be opened elsewhere with the `recovery` slot (or, in Phase 2,
  a `fido2` slot). Back up `keyslots.json` with it.
- `cn export --recipient age1... > backup.age` writes the decrypted store,
  values included, encrypted to an age recipient the human controls. It
  requires an `export` approval and is audited.
- `cn import --from backup.age` and `cn import --glob '.secret-*'` are store
  mutations (section 9).

## 4. IPC protocol

### Framing

Each frame is:

```text
u32 big-endian length (of kind + payload) | u8 kind | payload
kind 0x01 = JSON message (UTF-8), max 1 MiB
kind 0x02 = stream data (raw bytes), max 64 KiB, only inside a Hide stream
```

### Handshake and versioning

The first frame from the client must be `Hello`; anything else closes the
connection. The server answers with the highest protocol version both sides
support, or `unsupported_version`.

```json
{"type":"hello","id":1,"protocols":[1],"client":"cn/0.1.0",
 "labels":{"CLAUDE_CODE_SESSION_ID":"9f3c…"},"cwd":"/home/patrick/projects/x"}
{"type":"hello_ok","id":1,"protocol":1,"server":"cnd/0.1.0",
 "session":{"id":"s_7k2mq9d4x1ha","anchor":{"pid":41210,"comm":"claude"}}}
```

`cnd` resolves the session (section 5) during the handshake, from the
connection's peer credentials. The session is fixed for the connection. Each
request carries an `id`; the response echoes it. One request is in flight per
connection, except that a `Run` connection stays open until `RunFinish` and a
`Hide` connection carries stream frames.

Protocol rules: unknown fields are ignored; unknown `type` values return
`unknown_request`; a breaking change increments the protocol number, and
`cnd` supports the previous version for one minor release.

### Messages

| Request | Key fields | Response |
| --- | --- | --- |
| `hello` | `protocols`, `client`, `labels`, `cwd` | `hello_ok` with session view |
| `session` | — | anchor chain, session id, labels, liveness, grant count |
| `list` | `all_projects` (bool) | secrets: name, description, usage, projects, tags, grant state |
| `request` | `names[]`, `mode` (`use`/`reveal`), `ttl`, `reason` | `request_id`, `code`, `digest_short`, `expires_at`, `approvers[]` |
| `get_request` | `code` | full request for display + canonical digest input |
| `approve` | `code`, `approver`, `assertion` (FIDO2) | `approved` with grant ids, or `pending` (chained approvers) |
| `deny` | `code` | `denied` |
| `grants` | — | active grants for this session |
| `revoke` | `grant_id` (omitted: every grant in the session) | `revoked` |
| `run` | `uses[]: {name, env}`, `argv0`, `argc` | `run_id`, `values[]: {env, value_b64}`, `patterns_extra` |
| `run_finish` | `run_id`, `exit`, `signal`, `duration_ms`, `hits{name:n}` | `ok` |
| `hide` | — | `hide_ok`, then stream frames both ways; client sends `hide_end` |
| `reveal` | `name` | `value_b64` |
| `add` | `meta` (name and metadata), `value_b64` | `request_id`, `code` (mutation needs approval) |
| `set` | `name`, `value_b64` | `request_id`, `code` |
| `edit` | `meta` (the full new metadata; `meta.name` selects the secret) | `request_id`, `code` |
| `rm` | `name` | `request_id`, `code` |
| `audit_query` | `session`, `secret`, `event`, `since`, `until`, `limit` | records (JSON) |
| `audit_segments` | `from_seq` | raw segment bytes for `cn audit verify` |
| `session_register` | `label` | `registered` (anchor = the caller's pid and start time) |
| `unlock` | `hmac_output` (client-side) or empty (daemon-side FIDO2) | `unsealed` |

### Errors

```json
{"type":"error","id":7,"code":"grant_required","message":"no active grant for 'clickhouse-prod' in session s_7k2mq9d4x1ha","detail":{"names":["clickhouse-prod"]}}
```

| Code | Meaning |
| --- | --- |
| `unsupported_version` | No common protocol version. |
| `forbidden_peer` | Peer uid not allowed on the socket. |
| `no_session` | No anchor found for the caller (section 5). |
| `session_dead` | Anchor exited during the request. |
| `unknown_secret` | Name not in store. |
| `grant_required` | No active grant covering name and mode. |
| `request_expired`, `request_not_found` | Bad or stale approval code. |
| `approval_invalid` | Assertion failed verification. |
| `store_sealed` | Store not unlocked. |
| `rate_limited` | Hide or request rate exceeded. |
| `limit_exceeded` | TTL above `max_ttl`, too many names, frame too large. |
| `unknown_request` | The request `type` is not known. |
| `internal` | Server fault; details only in the daemon log. |

## 5. Sessions

### Anchor discovery

Run once per connection, during `Hello`:

1. **Peer.** Get `SO_PEERPIDFD`, which gives a pidfd for the connecting
   process without a pid-reuse race, and `SO_PEERCRED` for its uid. Linux 6.5
   or later is required; `cnd` refuses to start without `SO_PEERPIDFD`
   (decision 16). Reject the peer if its uid is not in `[access]`, or is 0 and
   `allow_root_clients` is false.
2. **Read stat.** Parse `/proc/<pid>/stat` from the *last* `)` (the `comm`
   field may contain spaces and parentheses). Take field 4 (`ppid`) and field
   22 (`starttime`, clock ticks since boot).
3. **Check anchors.** If `(pid, starttime)` is in the launcher-registered
   anchor table, stop: this is the anchor. Otherwise evaluate the configured
   matchers against `/proc/<pid>/comm` and `/proc/<pid>/cmdline`. The first
   match is the anchor. The nearest anchor wins. The process sets its own
   `comm` and `cmdline`, so a matcher identifies a session; it does not
   authenticate one. Only the launcher gives a session boundary the human
   chose.
4. **Step to parent.** Open a pidfd for `ppid`, read its stat, and require
   `parent.starttime <= child.starttime`; a violation means the pid was
   reused, and discovery fails closed. Confirm the child pidfd is still not
   readable (child alive) after reading the parent, so the chain was valid at
   one instant.
5. **Stop conditions.** Stop with `no_session` at pid 1, at a process whose
   uid differs from the peer's (sshd, sudo, a system service), or after 64
   steps.
6. **Record.** Session id = `"s_" + base32(SHA-256(boot_id || anchor_pid ||
   anchor_starttime))[0..12]`, with `boot_id` from
   `/proc/sys/kernel/random/boot_id`. `cnd` keeps the anchor's pidfd.

Labels from `label_env` and the cwd are stored with the session and shown in
approval displays and audit records, always marked untrusted.

### Liveness

`cnd` adds each anchor pidfd to its epoll set. When the pidfd becomes
readable, the anchor has exited: `cnd` marks the session dead, expires its
grants and pending requests, and writes `session.end`. Grants live only in
memory; restarting `cnd` drops every grant. That is deliberate: a restart
fails closed.

### `cn session exec`

```sh
/usr/bin/cn session exec --label "liskov drift" -- claude
```

`cn` connects, sends `session_register` with the label, and `cnd` records the
peer's `(pid, starttime)` from the kernel as an anchor. `cn` then `execve`s the
agent. `execve` keeps the pid and the start time, so the agent process *is*
the registered anchor; there is no extra process to keep alive and nothing an
intermediate shell can break. Registration expires if the pid exits.

`cn session` prints what `cnd` resolved:

```text
session   s_7k2mq9d4x1ha  (registered by cn session exec, label "liskov drift")
anchor    pid 41210  comm claude  started 2026-11-08T09:14:03Z
chain     41377 cn ← 41376 bash ← 41210 claude
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
| Agent creates a long-lived anchor (`systemd-run --user cn session exec -- sleep inf`) | Possible. Its grants still need approval, and the display shows the anchor chain and that it was launcher-registered. Bounded by `max_ttl`. |
| PID namespaces, containers | Out of scope v1; pids from a namespace do not match host `/proc`. |

## 6. Grants

### Lifecycle

```text
                 approve (all required approvers)
  ┌─────────┐ ─────────────────────────────────► ┌──────────┐  ttl elapsed     ┌─────────┐
  │ pending │                                    │  active  │ ────────────────►│ expired │
  └─────────┘ ─── deny ──► denied                └──────────┘                  └─────────┘
      │       ─── pending_expiry ──► expired          │  cn revoke / anchor exit
      │       ─── anchor exit ──► expired              └──────────────────────► revoked/expired
```

`pending` → `approved` is immediate when the last required approver succeeds;
the grant becomes `active` at that moment, and its TTL is counted from
approval, not from the request. Denied, expired and revoked are terminal. A
reveal grant is also consumed after `max_reveal_uses` reveals (default 1).

| Limit | Default | Config |
| --- | --- | --- |
| Use grant TTL | 1h | `default_ttl`; at most `max_ttl` (8h), above which a request is refused |
| Reveal grant TTL | 10m, 1 use | `max_reveal_ttl`, `max_reveal_uses` |
| Pending request lifetime | 5m | `pending_expiry` |
| Names per request | 16 | `[limits] max_names_per_request`; v1 allows lowering it, not raising it |

### Request codes

A code is 6 characters of Crockford base32 shown as `K7M-Q2X` (30 bits),
random, unique among pending requests. Input is case-insensitive, the dash is
optional, and per Crockford `O` reads as `0` and `I`/`L` as `1`. The code is
a handle for humans, not a credential: knowing it lets anyone *attempt* an
approval, which still needs a key touch or a polkit dialog.

### Request digest

The approver signs, and the human compares, a digest over a canonical request:

```json
{
  "domain": "countersign/approve/v1",
  "request_id": "<128-bit random, base32>",
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

Canonical encoding is RFC 8785 (JCS): sorted keys, no whitespace, UTF-8.
`secrets` is sorted. `digest = SHA-256(JCS(request))`. For FIDO2 the digest is
the CTAP2 `clientDataHash`; `cnd` verifies the ES256/EdDSA signature over
`authenticatorData || clientDataHash` with the registered public key, requires
the UP flag, and requires `signCount` to increase when the authenticator
reports one. The short form shown to humans is the first 8 Crockford base32
characters of the digest, e.g. `digest 3QF8-ZK2M`. It appears in `cn request`
and `cn approve` output and in every daemon-rendered display (the polkit
message; the `command` adapter's input), so a shadowed `cn` that shows a
different request also shows a different short digest from the one the
trusted surface shows. Approver details are in the approvers
document.

## 7. `cn run`

```sh
cn run --use clickhouse-prod --use github-token=GH_TOKEN -- ./scripts/drift.py --env prod
```

1. `cn` connects and sends `run` with `uses`, `argv0` and `argc`. Full argv
   is not sent; it can contain anything.
2. `cnd` checks that each name has an active `use` grant in the caller's
   session, writes `use.start` with a `run_id`, and returns the values. The
   connection stays open.
3. `cn` builds the child's environment: its own environment minus any
   `COUNTERSIGN_*` variables, plus each `ENV=value`. It refuses with exit 125
   if two uses map to one variable or a mapped variable name is not a valid
   identifier.
4. `cn` builds a redaction engine (`countersign-hide`) from the returned
   values and their encodings.
5. `cn` creates two pipes and `fork`s; the child `execvpe`s the command with
   the built environment, stdin inherited. The child stays in `cn`'s process
   group so a terminal `^C` reaches it directly. The parent zeroizes the
   value buffers it no longer needs (the engine keeps its own patterns).
6. The parent copies child stdout and stderr through the engine to its own
   stdout and stderr, each stream with its own carry-over buffer (section 8).
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
the remainder, writes a `hide` audit record with byte counts and per-secret
hit counts, and returns `hide_summary`. Values never enter the developer's uid
for hiding.

### Pattern set

By default: every secret with an active grant in the caller's session, plus
every secret marked `high_entropy`. A low-entropy secret that is not granted is
never in the set, so `hide` cannot be used as a guessing oracle for it. Values
shorter than 8 bytes are never patterns (false positives, and they are
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
total byte budget (default 256 MiB/min). Excess returns `rate_limited`. Every
stream is audited with hit counts, so repeated probing is visible.

## 9. Store mutations

| Command | Approval kind | Display shows |
| --- | --- | --- |
| `cn add NAME` | `mutate` | name, description, usage, projects, high_entropy, value length class |
| `cn set NAME` | `mutate` | name, "value changes", old and new `rotated` |
| `cn edit NAME` | `mutate` | metadata diff |
| `cn rm NAME` | `mutate` | name, description |
| `cn import` | `mutate` | list of names to add |
| `cn export` | `export` | recipient, count |

The value travels with the `add`/`set` request and is held by `cnd` with the
pending request, so an approval applies to the exact value submitted; nothing
can be swapped in after the human approves. Value sources, in order of
preference:

```sh
/usr/bin/cn set clickhouse-prod                 # no-echo prompt, needs a real TTY
/usr/bin/cn set clickhouse-prod --from-clipboard
/usr/bin/cn set clickhouse-prod --from-file ./key.txt   # file shredded after success
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
| `countersign-proto` | Frame codec, message enums (serde), protocol version constants, error codes, the canonical request type and its JCS digest (shared so `cn` and `cnd` compute the same bytes). |
| `countersign-core` | Store format and crypto, key slots, atomic writes, data-model validation; session discovery and liveness; grant state machine and TTL policy; config parsing; audit writer, chain, checkpoints and verifier. Used by `cnd`; the verifier also by `cn`. |
| `countersign-approve` | `Approver` trait (`present(request) -> Outcome`), combinators (`all_of`, `any_of`), adapter `polkit` (D-Bus `CheckAuthorization`), and `insecure-auto` behind the debug-only `insecure-test` feature (decision 17). Phase 2: `fido2` (registration, assertion verify), `command` (exit-code protocol). |
| `countersign-hide` | Pattern generation from values and encodings, Aho-Corasick engine, chunk-boundary carry-over, newline flush. Used by `cnd` for `hide` and by `cn` for `run`. |
| `countersign-daemon` | `cnd`: socket accept loop (tokio), peer credentials, epoll on pidfds, request dispatch, sd_notify, startup unseal. |
| `countersign-cli` | `cn`: argument parsing, `run` fork/exec and scrubbing, `hide` streaming, `audit verify`, `session exec`, `import`. Phase 2: FIDO2 client side for `approve`/`unlock` (libfido2 or `ctap-hid-fido2`). |

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
