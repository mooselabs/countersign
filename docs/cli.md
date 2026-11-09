# `cn` command reference

`cn` is the countersign client. It talks to `cnd` over
`/run/countersign/cnd.sock` and runs commands with secrets injected. It never
holds state of its own: secrets, grants, sessions and the audit log all live
in `cnd`.

**Phase 1** (decision 14): polkit is the only approver. Every approval is the
desktop dialog `cnd` raises; `cn approve` only shows the pending request so
the human can cross-check it, and waits for the dialog's answer.
`cn export`, `cn import --from`, `cn unlock`, `cn approver`, `cn sudo`,
`cn audit checkpoints`, `cn audit pubkey` and `cn audit verify --approvals`
are Phase 2: they exit 2 with `not_in_this_version`.

This document covers every command, the global options, the exit codes, the
`--json` output convention that agents parse, and a worked session. The
mechanisms behind the commands are in [design.md](design.md); approvers are in
[approvers.md](approvers.md); the audit record format is in
[audit.md](audit.md).

## Conventions

- **Names.** Secret names match `^[a-z0-9][a-z0-9._-]{0,63}$`. The default
  environment variable for a secret is its name in upper snake case (`.` and
  `-` become `_`): `typesafe-api-key` maps to `TYPESAFE_API_KEY`.
- **Durations** are written `90s`, `30m`, `1h`, `1h30m`, `8h`.
- **Request codes** are six Crockford base32 characters shown as `K7M-Q2X`.
  Input is case-insensitive, the dash is optional, and `O` reads as `0` and
  `I`/`L` as `1`. A code is a handle, not a credential.
- **Short digest** is the first 8 Crockford base32 characters of the request
  digest, shown as `3QF8-ZK2M`. It appears in `cn request`, `cn approve` and
  the polkit dialog, so the human can compare them.
- **Session.** Every call is attributed by `cnd` to a session, resolved from
  the kernel's view of the caller's process ancestry (see `cn session`). The
  session is not something the caller can name or choose. Outside any agent
  session (a terminal the human opened), `cnd` uses a pseudo-session for the
  calling shell: it may change the store and read, never hold grants.
- **Who runs it.** "Agent" means the command is meant to be run from the
  agent's Bash tool. "Human" means the developer runs it, either in a separate
  terminal or as a Claude Code `!` command. A `!` command runs as the same uid,
  with the agent's environment and no TTY, so the agent can run anything the
  human can type there. Nothing in this table is a security boundary; the
  approvers are.
- **Absolute path for humans.** Documentation tells humans to type
  `/usr/bin/cn` for `approve`, `add`, `set`, `edit`, `rm` and `import`. This
  defeats a `cn` planted earlier on `PATH`. It does not defeat a shell
  function named `/usr/bin/cn` or a tampered harness; see
  [approvers.md](approvers.md#the-trusted-display-problem).

## Summary

| Command | Typically run by | Approval | Audit event(s) |
| --- | --- | --- | --- |
| `cn list` | agent | no | `list` (coalesced) |
| `cn show NAME` | agent | no | `list` (coalesced) |
| `cn request` | agent | creates one | `request.create`, then the decision |
| `cn approve CODE` | human | no: it shows the request; the dialog is the approval | none |
| `cn deny CODE` | human or agent | no | `request.deny` |
| `cn grants` | agent or human | no | none |
| `cn revoke` | human or agent | no | `grant.revoke` |
| `cn run` | agent | needs an active `use` grant | `use.start`, `use.end` |
| `cn hide` | agent | no | `hide` (byte and hit counts) |
| `cn reveal NAME` | human, or agent when asked | needs an active `reveal` grant | `reveal` |
| `cn add NAME` | human | `mutate` | `request.create`, `request.approve`, `store.add` |
| `cn set NAME` | human | `mutate` | `request.create`, `request.approve`, `store.set` |
| `cn edit NAME` | human | `mutate` | `request.create`, `request.approve`, `store.edit` |
| `cn rm NAME...` | human | `mutate` (one for all) | `request.create`, `request.approve`, `store.rm` per secret |
| `cn import` | human | `mutate` (one for the batch) | `request.create`, `request.approve`, `store.add` per secret, `import` |
| `cn session` | agent or human | no | none |
| `cn session exec` | human | no | `session.start` |
| `cn audit` | agent or human | no | none |
| `cn audit verify` | human | no | none |
| `cn doctor` | human or agent | no | none |
| `cn export`, `cn unlock`, `cn approver`, `cn sudo` | Phase 2 | | |

## Global options

| Option | Meaning |
| --- | --- |
| `--json` | Machine-readable output; see [JSON output](#json-output). |
| `--socket PATH` | Debug builds only, for tests: socket path, also `COUNTERSIGN_SOCKET`. A release build always uses `/run/countersign/cnd.sock`. |
| `--no-color` | Accepted; `cn` prints no colour. |
| `-q`, `--quiet` | Suppress informational lines on stderr. |
| `-h`, `--help` | Help for the command. |
| `--version` | Print `cn` version and the protocol it speaks. |

Before sending anything, `cn` checks the server end of the socket with
`SO_PEERCRED` and refuses (`bad_peer`) to talk to a peer that is not running
as the `countersign` system user. A release build only ever connects to
`/run/countersign/cnd.sock`, so a fake daemon on another path cannot feed it
a request to display. A debug build with a socket override also accepts a
daemon running as the caller's own uid.

`cn` sets itself non-dumpable before it touches a value, and strips every
`COUNTERSIGN_*` variable from the environment of any child it starts.

---

## `cn list`

```text
cn list [--all] [--long] [--json]
```

Lists secrets visible to the current session: name, grant state and
one-line description; with `--long`, the usage prose under each. Never
values, never value lengths.

By default only secrets whose `projects` globs match the session's reported
cwd (or one of its parents) are shown, plus secrets with no `projects`
(available everywhere). `[list] default_scope = "all"` changes the default.
Project scope is organizational, not a security boundary.

| Flag | Meaning |
| --- | --- |
| `--all` | Include secrets scoped to other projects. They are marked `(other project)`; requesting one is allowed (with `[grants] cross_project = "flag"`, the default) and marked in the dialog. |
| `--long`, `-l` | Print the full usage prose under each secret. |

```console
$ cn list
NAME                      GRANT        DESCRIPTION
clickhouse-password       -            ClickHouse analytics, read-only user `reporter`
typesafe-api-key          use 41m left Typesafe API, production account
acurast-rpc-bearer-token  -            Bearer token for the Acurast RPC endpoint (mainnet)
```

- **Run by:** agent, at the start of any task that may need a credential.
- **Approval:** none. (`[approval] list_requires_approval` is not in this
  version; `cnd` warns and ignores it.)
- **JSON:** every secret's full metadata, usage included, its default
  variable, whether it is in this project, this session's grant and its last
  use.
- **Audit:** `list`, coalesced per session (the first call written at once,
  then one record per 10-minute window with a call count) so polling does not
  flood the log.
- **Limits:** 60 calls per minute per session and 240 per uid
  (`[limits] list_calls_per_minute`, `list_calls_per_minute_per_uid`).

## `cn show NAME`

```text
cn show NAME [--json]
```

Prints one secret's metadata: description, projects, tags, `high_entropy`,
default variable, created / updated / rotated times, the time of its last use
and by which session, the full usage prose, and this session's grant for it.
Never the value or its length. The last use is kept in `cnd`'s memory, so it
reads `never` after a restart.

```console
$ cn show clickhouse-password
name          clickhouse-password
description   ClickHouse analytics, read-only user `reporter`
projects      ~/projects/moose/*
high_entropy  no   (not redacted by `cn hide` unless granted)
env           CLICKHOUSE_PASSWORD
created       2026-10-02T11:40:00Z
updated       2026-10-02T11:40:00Z
rotated       2026-10-02T11:40:00Z
last use      2026-11-08T09:31:12Z  session s_7k2mq9d4x1ha  argv0 python3
usage
  Read-only queries from scripts/clickhouse_*.py. Never write it into
  committed config or a URL. Production data: prefer the sandbox service
  unless the task names production.
grant         none in this session
```

- **Run by:** agent, before requesting, to read the usage prose.
- **Approval:** none (same policy as `list`).
- **Audit:** coalesced into the session's `list` record.

## `cn request`

```text
cn request NAME... --reason TEXT [--ttl DUR] [--mode use|reveal] [--wait[=DUR]] [--json]
```

Creates a pending request for one or more secrets and prints its code and
short digest. The request is bound to the caller's session: when approved, the
grant applies only to processes descending from that session's anchor. It
needs an agent session; from a plain terminal it fails with `no_session`.

| Flag | Meaning |
| --- | --- |
| `--reason TEXT` | Required. What will be run and why; at most 2048 bytes. Any value of a secret in the session's hide set is replaced with `[countersign:NAME]` before anything else sees it. The dialog shows it labelled as the agent's, escaped and cut to 300 characters. |
| `--ttl DUR` | Grant lifetime, counted from approval. Default `[grants] default_ttl` (1h) for `use`, and the smaller of that and `max_reveal_ttl` (10m) for `reveal`. Above `max_ttl` (8h) or `max_reveal_ttl` is refused with `limit_exceeded`, not silently capped. |
| `--mode use` | Default. Values may be injected by `cn run`. |
| `--mode reveal` | Values may be printed by `cn reveal`. Single use by default. Uses the `reveal` chain and its own polkit action. |
| `--wait[=DUR]` | Block until the request is approved, denied or expires, up to `DUR` (default: until the request lapses). Without `--wait`, return as soon as the request is created. |

`cnd` raises the dialog as soon as the request is created; the human answers
it on the desktop:

```console
$ cn request clickhouse-password --ttl 30m --reason "row counts for the weekly cost report via scripts/clickhouse_rows.py"
request K7M-Q2X pending  use clickhouse-password for 30m
digest  3QF8-ZK2M
approve a desktop dialog is open
expires 2026-11-08T09:25:11Z (5m)
```

The dialog stays open until the request lapses at `expires` (or sooner, if
the polkit approver's `timeout` is set). There is no way to raise the dialog
again; request again.

At most two dialogs are open at once for a uid (`[limits]
max_prompts_per_uid`). A further request waits its turn, and `approve` then
reads `queued: its dialog opens when an earlier one is answered`. Its expiry
still counts from when it was made.

A request for secrets that an active grant of the same mode in this session
already covers returns that grant and creates nothing:

```console
$ cn request clickhouse-password --reason "..."
granted already  g_4hx2 use clickhouse-password, 27m left
```

How a request ends, as `--wait` reports it:

| Outcome | Exit | Meaning |
| --- | --- | --- |
| approved | 0 | `approved by polkit  grant g_4hx2 active until 09:51:40` |
| denied | 5 | `request K7M-Q2X was denied by polkit`: the human pressed Cancel or failed to authenticate. |
| approver unavailable | 14 | `request K7M-Q2X could not be shown to the human: ...`: no dialog could be shown, because there is no graphical session, it is not Wayland under `require_wayland`, polkitd is not running, or no authentication agent answers. Tell the human; do not retry blindly. |
| denied by `cnd` | 5 | A fault or an invalid answer from the approver. The message carries the reason. Tell the human; do not retry blindly. |
| expired | 7 | Nobody answered before the request lapsed. |
| pending | 6 | `--wait` ran out first; the request is still open. |

- **Run by:** agent.
- **Approval:** this command creates the thing to be approved.
- **Audit:** `request.create` (secrets, mode, ttl, reason, cwd, session,
  digest and the canonical request). Then `request.approve`,
  `request.deny` or `request.expire` when it resolves.
- **Limits:** at most 16 names per request; at most 3 pending requests and 30
  requests an hour per session, and 10 pending and 120 an hour per uid over
  all its sessions (`[limits]`). A denied request starts a 2-minute cooldown
  for the same names for the uid, in every session, also after the session
  ends. Each is `rate_limited` (exit 10), except too many names
  (`limit_exceeded`, exit 9).

## `cn approve CODE`

```text
/usr/bin/cn approve CODE [--timeout DUR] [--json]
```

Fetches the request from `cnd`, recomputes its digest from the canonical
request and refuses if it differs, prints it, and waits up to `--timeout`
(default 60s) for the decision. It approves nothing: the approval is the
polkit dialog, and the printout lets the human cross-check what the dialog
shows. It does not raise a dialog that was dismissed or timed out.

```console
! /usr/bin/cn approve K7M-Q2X
countersign request K7M-Q2X
  session   s_7k2mq9d4x1ha  anchor claude pid 41210 (registered by cn session exec)
  cwd       "/home/patrick/projects/moose/liskov-agent-orchestrator"   (reported, untrusted)
  secrets   clickhouse-password
  mode      use
  ttl       30m
  reason    (agent-supplied) row counts for the weekly cost report via scripts/clickhouse_rows.py
  digest    3QF8-ZK2M
  state     pending
Approve it in the desktop dialog. Check that the dialog shows request K7M-Q2X and digest 3QF8-ZK2M.
To refuse, cancel the dialog or run: cn deny K7M-Q2X
approved by polkit  grant g_4hx2 active until 09:51:40
```

`--approver NAME` exists for Phase 2: with a daemon-driven approver it is a
usage error, and a FIDO2 approver is `not_in_this_version`.

`cn approve` refuses to run when its `TracerPid` is non-zero. That does not
protect against a replaced binary or shell function; that is the trusted
display problem, covered in [approvers.md](approvers.md).

- **Run by:** human. An agent can run it too; it only prints and waits. The
  Claude Code hook examples in [agent-integration.md](agent-integration.md)
  stop confused agents from trying.
- **Approval:** none; the dialog is the approval.
- **Audit:** none.

In Phase 2, with a `fido2` approver in the chain, `cn approve` also asks the
security key for an assertion over the digest and sends it to `cnd`, which
verifies it against the enrolled public key; that is then the approval, and
is audited as `request.approve` (or `request.approve_fail`).

## `cn deny CODE`

```text
cn deny CODE [--reason TEXT] [--json]
```

Denies a pending request and closes its dialog. Anyone allowed on the socket
can deny any pending request: denial only removes privilege. The agent can use
it to withdraw its own request. A request already decided is
`request_not_found`, one that lapsed `request_expired` (both exit 7).

```console
$ cn deny K7M-Q2X --reason "wrong secret, wanted the sandbox key"
denied K7M-Q2X
```

- **Run by:** human (to refuse) or agent (to withdraw).
- **Approval:** none.
- **Audit:** `request.deny` with approver `client`, the reason (cut to 2048
  bytes, with the request session's values redacted), and who denied: the
  peer's uid, pid and `comm`, and whether it came from the request's own
  session, another session, a terminal or no session.

## `cn grants`

```text
cn grants [--all-sessions] [--json]
```

Lists active grants for the current session: grant id, secrets, mode, time
left, which approver approved it, and how many values were issued under it
(and reveals left, for a reveal grant).

```console
$ cn grants
GRANT   SECRETS               MODE  LEFT  APPROVED BY  USES
g_4hx2  clickhouse-password   use   27m   polkit       2
```

| Flag | Meaning |
| --- | --- |
| `--all-sessions` | Show active grants in every live session of the caller's uid, with each grant's session. For the human's overview. |

- **Run by:** agent (to check what it already has) or human.
- **Approval:** none.
- **Audit:** none.

## `cn revoke`

```text
cn revoke GRANT_ID...
cn revoke --secret NAME
cn revoke --all
```

Each form takes `--all-sessions` to act on every live session of the caller's
uid. Ends grants before their TTL. A running `cn run` child keeps the values
it was started with; no new values are issued under a revoked grant. Grant
ids that match nothing in scope are `grant_required` (exit 4).

```console
$ cn revoke --all
revoked g_4hx2 (clickhouse-password)
```

- **Run by:** human or agent. Agents are told to revoke when a task is done.
- **Approval:** none; revoking only removes privilege.
- **Audit:** `grant.revoke` per grant.

## `cn run`

```text
cn run --use NAME[=ENVVAR]... [--json] -- COMMAND [ARG...]
```

Fetches values for the named secrets from `cnd`, starts `COMMAND` with each
value in its environment, and copies the child's stdout and stderr through a
redaction engine that replaces each value, and its base64, URL-encoded,
JSON-escaped and hex forms, with `[countersign:NAME]`. The engine also covers
the session's other `use`-granted secrets. Stdin is passed through. The exit
status is the child's.

| Flag | Meaning |
| --- | --- |
| `--use NAME` | Inject `NAME` as its default variable (`clickhouse-password` -> `CLICKHOUSE_PASSWORD`). Repeatable. |
| `--use NAME=ENVVAR` | Inject `NAME` as `ENVVAR`. A `COUNTERSIGN_*` variable is refused. |

```console
$ cn run --use clickhouse-password -- python3 scripts/clickhouse_rows.py --since 7d
table            rows
events      1834221
sessions      91022
```

What it does not do:

- It does not scrub files, sockets or `/dev/tty` the child writes to. A log
  file written by the child may hold the value; read such files through
  `| cn hide`.
- It does not keep the value from the child, or from a same-uid process that
  reads `/proc/<child>/environ` while the child runs. See
  [threat-model.md](threat-model.md) T6.
- It does not stop the child when the grant expires. TTL governs when values
  are issued.
- The child sees pipes, not a terminal, on stdout and stderr. Some programs
  turn off colour or change buffering.
- Values in `cn`'s own copy of the child environment and in the redaction
  patterns are not zeroized.

Do not pass a value as an argument (`--password "$CLICKHOUSE_PASSWORD"`
expanded by an outer shell): argv is world-readable in `/proc/<pid>/cmdline`
and appears in the transcript. Let the child read the variable, or use
`sh -c '... "$VAR" ...'` so the expansion happens inside the child.

- **Run by:** agent.
- **Approval:** needs an active `use` grant for every named secret in this
  session. Without one, `cn run` exits 125 with `grant_required` before
  starting anything.
- **Audit:** `use.start` written by `cnd` when values are issued (secrets,
  variables, argv0, argument count, reported cwd, pid, session); `use.end`
  reported by `cn` (exit code or signal, duration, per-secret hit counts in
  the scrubbed output). If `cn` dies, `cnd` writes `use.end` with
  `status: "client_lost"`.

Exit codes for `run` follow `env(1)`, not the general table:

| Exit | Meaning |
| --- | --- |
| child's code | Child exited normally. |
| 128 + N | Child killed by signal N. |
| 125 | `cn` failed before or while starting the child (bad arguments, no grant, daemon unreachable, bad `--use`). The error code is on stderr, as JSON with `--json`. |
| 126 | Command found but not executable. |
| 127 | Command not found. |

## `cn hide`

```text
COMMAND | cn hide [--secret NAME]... [--stats] [--json]
```

A filter. Streams stdin to `cnd`, which replaces secret values (and their
encodings) with `[countersign:NAME]` and streams the result back to stdout.
Values never enter the caller's uid for this. Output is line-buffered: a
complete line passes through immediately; a partial last line may be held
back by up to one byte less than the longest pattern until more input or EOF.
The hold-back depends only on input length and newlines, never on whether a
match is pending.

The default pattern set is every secret granted to the current session plus
every secret marked `high_entropy`. A low-entropy secret that is not granted is
never matched, so `cn hide` cannot confirm guesses of a short password. From
a terminal outside any agent session, nothing is granted, so only
high-entropy secrets are matched.

| Flag | Meaning |
| --- | --- |
| `--secret NAME` | Also match `NAME`. Allowed only for secrets with an active grant in this session (otherwise it would be a guessing oracle); refused with `grant_required`. |
| `--stats` | At EOF print byte counts and per-secret hit counts to stderr: `cn hide: 14336 bytes in, 14310 out, hits: clickhouse-password=1`. |

```console
$ tail -n 50 logs/clickhouse_rows.log | cn hide
2026-11-08 09:33:01 connecting to https://reporter:[countersign:clickhouse-password]@ch.example.net:8443
2026-11-08 09:33:02 ok
```

- **Run by:** agent, as the last stage of any pipeline whose output might
  contain a secret: logs, `env`, config dumps, HTTP debug output, files a
  `cn run` child wrote.
- **Approval:** none.
- **Audit:** `hide` per stream, also one the client abandons: bytes in, hit
  counts per secret, number of patterns. Never the matched text, and not the
  bytes out (with bytes in and the hits, it would give away the matched
  values' lengths).
- **Limits:** 30 new streams per minute per session and 256 MiB per minute;
  120 streams and 1 GiB per minute per uid over all its sessions (`[hide]`).
  Excess returns `rate_limited`.

## `cn reveal NAME`

```text
cn reveal NAME [--clipboard] [--json]
```

Prints the raw value. This puts the value wherever stdout goes: in a `!`
command or an agent's Bash tool, that is the transcript and the model
provider, permanently. With `--json`, the value is in `data.value` (and
`data.value_b64`).

The value is written as its exact bytes, with no trailing newline, so
`cn reveal NAME > file` or `$(cn reveal NAME)` gets the value and nothing
else. Only when stdout is a terminal and the value does not already end in a
newline does `cn` add one after it, so the shell prompt starts on a new line.

| Flag | Meaning |
| --- | --- |
| `--clipboard` | Copy the value to the Wayland clipboard (`wl-copy`, cleared after 30s) instead of printing it. For a human in a terminal. The clipboard is readable by every process of the uid while the value is on it. |

```console
$ cn reveal typesafe-api-key --clipboard
copied typesafe-api-key to the clipboard; clears in 30s
```

- **Run by:** human, or an agent only when the human has asked for the raw
  value in the conversation. It needs an agent session, because grants
  belong to one.
- **Approval:** needs an active `reveal` grant (`cn request NAME --mode
  reveal`), approved through the `reveal` chain. A reveal grant is consumed
  after one reveal by default (`[grants] max_reveal_uses`).
- **Audit:** `reveal` (secret, session, grant, reveals left), and
  `grant.expire` with `by: "uses"` when the last reveal is used.

## `cn add NAME`

```text
/usr/bin/cn add NAME --description TEXT [--usage TEXT | --usage-file PATH]
                [--project GLOB]... [--tag TAG]... [--high-entropy | --low-entropy]
                [--from-clipboard | --from-file PATH | --from-stdin]
                [--wait[=DUR]] [--json]
```

Adds a secret. The value and metadata travel to `cnd` with the request and are
held there until approved, so the approved value is exactly the one submitted.

Value sources, in order of preference:

| Source | Notes |
| --- | --- |
| (none) | No-echo prompt. Needs a real terminal; refused with `no_tty` in a `!` command. |
| `--from-clipboard` | Reads the Wayland clipboard (`wl-paste`) and clears it after reading. Works in a `!` command. |
| `--from-file PATH` | Reads the file; one trailing newline is stripped. With `--wait`, once the change is approved, `cn` overwrites and unlinks it; without, it keeps the file and says so. Overwriting does not erase data on copy-on-write filesystems (btrfs) or SSDs. |
| `--from-stdin` | Reads stdin to EOF. One trailing newline is stripped. |

The value must be 1 byte to 64 KiB.

| Flag | Meaning |
| --- | --- |
| `--description TEXT` | Required. One line, at most 200 characters. |
| `--usage TEXT`, `--usage-file PATH` | How agents should use this secret in this project. At most 4 KiB. |
| `--project GLOB` | Repeatable. Matched against the session's reported cwd and its parents; `~` is your home. Empty means everywhere. |
| `--tag TAG` | Repeatable. Free-form. |
| `--high-entropy`, `--low-entropy` | Whether `cn hide` matches this secret even when it is not granted. Without either, `cn add` estimates the value's entropy: 80 bits or more is high, under 50 is low, and in between it refuses and asks you to choose. Values shorter than 8 bytes are never matched and `cn add` warns. |

```console
$ /usr/bin/cn add acurast-rpc-bearer-token --from-clipboard \
    --description "Bearer token for the Acurast RPC endpoint (mainnet)" \
    --usage "Only for scripts/acurast_*.py read calls. Never log request headers." \
    --project '~/projects/moose/*' --high-entropy --wait
request P2D-8TW pending  mutate: add acurast-rpc-bearer-token
digest  7KMA-W41C
approve a desktop dialog is open
expires 2026-11-08T09:40:02Z (5m)
added acurast-rpc-bearer-token
```

The dialog reads `countersign request P2D-8TW, digest 7KMA-W41C: ADD secret
acurast-rpc-bearer-token (value 16 to 63 bytes, from the clipboard, high
entropy): description "Bearer token for the Acurast RPC endpoint (mainnet)";
usage "Only for scripts/acurast_*.py read calls. Never log request
headers."; projects ["~/projects/moose/*"]. terminal, no agent session (shell
bash, pid 40102); client-reported: cwd "~/projects/moose".` What `cnd` knows
comes first, then the metadata the client sent, quoted with `"` and `\`
escaped; the description is cut at 60 characters, the usage at 120, and a
cut says how long the text was. No projects reads `any (all projects)`. The
value's size is only a class (`under 16
bytes`, `16 to 63 bytes`, `64 to 1023 bytes`, `1 KiB or more`) and is never
audited.

- **Run by:** human, from a terminal outside any agent session where
  possible: the dialog then names that terminal's shell, not the agent.
- **Approval:** `mutate` chain.
- **Audit:** `request.create` (operation `add NAME`, no reason),
  `request.approve`, then `store.add` (metadata only).
- **Errors:** `secret_exists` (exit 2) for a name already in the store;
  `bad_request` (exit 2) for invalid metadata or value.

## `cn set NAME`

```text
/usr/bin/cn set NAME [--from-clipboard | --from-file PATH | --from-stdin] [--wait[=DUR]] [--json]
```

Replaces a secret's value (rotation). Value sources as for `cn add`. Every
grant for `NAME` is revoked when the new value is committed.

```console
$ /usr/bin/cn set typesafe-api-key --from-clipboard --wait
request R9C-2HF pending  mutate: set typesafe-api-key
digest  M2QX-7Z0D
approve a desktop dialog is open
expires 2026-11-08T09:45:10Z (5m)
set typesafe-api-key; 1 grant revoked
```

The dialog reads `... SET a new value for typesafe-api-key (16 to 63 bytes,
from the clipboard); grants for it are revoked. ...`

- **Run by:** human.
- **Approval:** `mutate`. An agent swapping a DSN to point at its own host is
  an exfiltration path. The dialog names the session the change came from:
  deny any `set` you did not start.
- **Audit:** `request.create`, `request.approve`, `store.set` (no value, no
  hash or length of value), `grant.revoke` with `by: "store_change"` per
  revoked grant.

## `cn edit NAME`

```text
/usr/bin/cn edit NAME [--description TEXT] [--usage TEXT | --usage-file PATH]
                 [--add-project GLOB]... [--rm-project GLOB]...
                 [--tag TAG]... [--untag TAG]... [--high-entropy | --low-entropy]
                 [--wait[=DUR]] [--json]
```

Changes metadata, not the value. With no flags and a real terminal, opens
`$EDITOR` on a TOML rendering of the metadata; without a terminal it refuses
with `no_tty`. Grants are kept.

Usage prose steers every later agent session, so a change to it is a change
to agent behaviour. An agent may draft new prose and show it to the human; the
human applies it.

```console
$ /usr/bin/cn edit clickhouse-password --usage-file /tmp/ch-usage.txt --wait
request T4N-6KB pending  mutate: edit clickhouse-password
...
edited clickhouse-password
```

- **Run by:** human.
- **Approval:** `mutate`. The dialog shows each changed field, old -> new,
  with what `cnd` acts on first: the high entropy flag, then projects
  (`EDIT clickhouse-password: projects ["~/work/prod"] -> any (all
  projects); usage "read only" -> "read and write"`). A description or usage
  longer than 40 characters shows as its new text only (`usage becomes
  "..."`).
- **Audit:** `store.edit` with the list of changed fields and the new
  metadata (metadata is not secret).

## `cn rm NAME...`

```text
/usr/bin/cn rm NAME... [--wait[=DUR]] [--json]
```

Removes secrets, with one approval for all of them. Every grant for them is
revoked on commit.

- **Run by:** human.
- **Approval:** `mutate`; the dialog lists the names (`REMOVE 2 secrets: a,
  b`, eight names then "and N more").
- **Audit:** `store.rm` per secret.

## `cn import`

```text
/usr/bin/cn import --glob GLOB [--dir DIR] [--metadata FILE] [--strip-prefix PREFIX]
                   [--shred | --keep] [--dry-run] [--wait[=DUR]] [--json]
```

Moves existing plaintext secret files into the store. Each matching file
becomes one secret; the name is the file name with `--strip-prefix` removed
(default `.secret-`), so `.secret-typesafe-api-key` becomes
`typesafe-api-key`. One trailing newline is stripped from each value. The
whole batch is one `mutate` request of at most 20 secrets (`[limits]
max_names_per_import`); a larger set is refused with `limit_exceeded` (exit
9), so import it in parts. Restoring a
backup with `--from BACKUP.age` is Phase 2.

Metadata comes from, in order: `--metadata FILE` (TOML, below); an
interactive prompt per file in a real terminal; or, with neither, a
placeholder description `imported from <path>` and empty usage. Without an
entropy class in the metadata, `cn` uses its estimate, and low entropy when
the estimate is unsure.

```toml
# countersign-import.toml  (no values in this file)
[typesafe-api-key]
description = "Typesafe API, production account"
usage = """
Used by scripts/typesafe_*.py through TYPESAFE_API_KEY. Production: prefer the
sandbox key unless the task says production.
"""
projects = ["~/projects/moose/*"]
high_entropy = true

[clickhouse-password]
description = "ClickHouse analytics, read-only user `reporter`"
usage = "Read-only queries from scripts/clickhouse_*.py. Never in committed config."
high_entropy = false
```

| Flag | Meaning |
| --- | --- |
| `--glob GLOB` | Files to import, relative to `--dir` (default: cwd). |
| `--metadata FILE` | Description, usage, projects, tags and entropy class per secret name. Lets a `!` command import without prompts. An agent may draft this file. |
| `--shred` | Once the import is approved, overwrite and unlink each source file. Without `--shred` or `--keep`, `cn` asks in a real terminal and keeps the files without one. Needs `--wait` to see the approval. |
| `--keep` | Leave the source files. |
| `--dry-run` | Print what would be imported (names, sizes, git-tracked status), touch nothing, create no request. |

`cn import` warns about each source file that is tracked by git, appears in
git history (`git log --all -- PATH`), or is world-readable. Values that were
ever in a readable file should be rotated after import; see
[the migration guide](../integrations/migrating-from-secret-files.md#7-rotate).

- **Run by:** human. `cn` reads the files as the developer's uid, so it also
  works in a `!` command with `--metadata`.
- **Approval:** one `mutate` approval; the dialog lists the names
  (`IMPORT 3 secrets: ...`, eight names then "and N more").
- **Audit:** `request.create`, `request.approve`, `store.add` per secret, and
  one `import` record for the batch. Shredding happens in `cn` and is not
  audited.

## `cn session`

```text
cn session [--json]
cn session exec [--label TEXT] -- COMMAND [ARG...]
```

`cn session` prints what `cnd` believes the caller's session is: session id,
anchor pid, comm, start time, how the anchor was found (registered by the
launcher, or a matcher), the process chain from the caller to the anchor,
the reported cwd, untrusted labels, and the number of active grants. Outside
an agent session it fails with `no_session` (exit 11).

```console
$ cn session
session   s_7k2mq9d4x1ha  (registered by cn session exec, label "orchestrator")
anchor    pid 41210  comm claude  started 2026-11-08T09:14:03Z
chain     41377 cn <- 41376 bash <- 41210 claude
cwd       "/home/patrick/projects/moose/liskov-agent-orchestrator"  (reported, untrusted)
labels    CLAUDE_CODE_SESSION_ID=9f3c... (untrusted)
grants    1 active
```

`cn session exec` registers the calling process as a session anchor and then
`exec`s `COMMAND`, which keeps the pid and start time, so the agent process
is the anchor. This is the recommended way to start an agent: it works for any
agent and does not depend on matching process names. The label is shown in
the dialog.

```console
$ cn session exec --label orchestrator -- claude
```

Grants die when the anchor exits. A nested `cn session exec` creates a new
session with no grants.

- **Run by:** `cn session`: agent or human, to debug `no_session`.
  `cn session exec`: human, when starting the agent (or a shell alias).
- **Approval:** none.
- **Audit:** `session.start` when `cnd` first sees a session; `session.end`
  when the anchor exits. `cn session` itself is not audited.

## `cn audit`

```text
cn audit [--current | --session ID] [--secret NAME] [--event KIND]...
         [--since TIME|DUR] [--until TIME|DUR] [--limit N] [--follow] [--json]
cn audit verify [--from SEQ] [--pubkey FILE] [--checkpoints FILE] [--dir DIR] [--json]
```

`cn audit` reads the log through `cnd` (the agent cannot open the file). It
prints the newest `--limit` matching records (default 50, at most 1000), in
order. Times accept RFC 3339 or a duration back from now (`--since 2h`).
`--follow` keeps printing new records. Without `--current` or `--session`, a
SESSION column is added. With `--json`, output is JSON Lines, one record per
line, in the format defined in [audit.md](audit.md); this is the one command
whose `--json` output is not a single envelope object.

```console
$ cn audit --current --since 1h
SEQ    TIME      EVENT            DETAIL
18331  09:20:11  request.create   K7M-Q2X use clickhouse-password 30m "row counts for the weekly cost report..."
18332  09:21:40  request.approve  r_9w1k... polkit -> g_4hx2
18333  09:22:03  use.start        u_8d1e... clickhouse-password argv0=python3 pid=41502
18334  09:22:09  use.end          u_8d1e... exited exit=0 signal=null 6100ms hits={}
18335  09:23:30  hide             14336 B in, hits={clickhouse-password:1}
```

`cn audit verify` fetches the raw segments and recomputes the hash chain and
checkpoint signatures locally, so the result does not depend on trusting
`cnd`'s answer. It reports the record count, the checkpoints, the head hash
and the last checkpoint, and exits 13 on any break. Without `--from`, the log
must start at seq 1: a log whose first segments were deleted fails (exit
13). `--from SEQ` starts the check at a record, and the log must then start
exactly there; `--pubkey`, `--checkpoints` and `--dir` (root, reading the
files directly) are described in
[audit.md](audit.md#verifying-cn-audit-verify).

```console
$ cn audit verify
chain ok: 18335 records (1..18335), 19 checkpoints (19 signatures verified), head 9c1e4f02a..., last checkpoint 2026-11-08T09:00:00.000412Z
```

Verification proves the log was not altered by anyone without the checkpoint
key. It does not detect a rewrite by root or `cnd` itself unless checkpoints
were also exported (`cn audit --event checkpoint --json`) and are compared.

- **Run by:** human or agent (read-only).
- **Approval:** none.
- **Audit:** none.

## `cn doctor`

```text
/usr/bin/cn doctor [--json]
```

Checks the installation and the current environment and prints one line per
check: `ok`, `warn` or `fail`, with a fix for each non-`ok` result. Exit 0 when
there are no failures, 1 otherwise (`doctor_failed`).

| Check | `fail` / `warn` when |
| --- | --- |
| `binary` | `/usr/bin/cn` is missing, not root-owned, or group- or world-writable; or the running binary is not `/usr/bin/cn`. |
| `kernel` | Linux older than 6.5. |
| `group` | The `countersign-users` group is missing, you are not in it, or this login session predates joining it. |
| `daemon` | Socket missing or unreachable; peer not running as `countersign`; protocol mismatch; uid not allowed. |
| `session` | No session anchor above this shell (a warning in a plain terminal); notes when the anchor was found by a matcher rather than `cn session exec`. |
| `polkit` | No polkit authentication agent (such as gnome-shell) among your processes. |
| `x11` | An X11 session: any client can synthesize input to the dialog. |
| `ptrace` | `kernel.yama.ptrace_scope` is 0. |
| `leftovers` | `.secret-*` files in the current directory. |

Phase 1 does not check `PATH` shadowing, file permissions under `/etc`, the
polkit policy and PAM stack, GNOME Shell extensions, the store, the audit
chain, or the paths from your uid to root; it says so in its last line.

A shadowed `cn doctor` can report anything. Run it as `/usr/bin/cn doctor` from
a terminal you opened yourself, not only from inside an agent session.

- **Run by:** human after install and after changes; agent when `cn` behaves
  unexpectedly.
- **Approval:** none.
- **Audit:** none.

---

## Exit codes

All commands except `cn run` use this table. `cn run` uses the
[`env(1)`-style table](#cn-run) so the child's code passes through.

| Exit | `error.code` | Meaning | Usual next step |
| --- | --- | --- | --- |
| 0 | — | Success. For `cn request` without `--wait`: request created and pending. | |
| 1 | `internal`, `doctor_failed` | Unexpected failure; details in the daemon log. Or `cn doctor` found a failure. | Report it. |
| 2 | `usage`, `no_tty`, `bad_request`, `secret_exists`, `not_in_this_version` | Bad arguments, a secret that already exists, a prompt was needed with no terminal, or a Phase 2 command. | Fix the command; use `--from-*` value sources. |
| 3 | `daemon_unreachable`, `unsupported_version`, `unknown_request`, `forbidden_peer`, `bad_peer` | Cannot talk to a genuine `cnd` with a common protocol. | `cn doctor`. |
| 4 | `grant_required` | No active grant for that secret and mode in this session. | `cn request`. |
| 5 | `denied` | The request was denied: by the human (Cancel), or by `cnd` after a fault or an invalid answer (the message says why). | Do not retry without asking the human. |
| 6 | `pending` | `--wait` timed out; the request is still pending. | Ask the human to approve, then `cn grants`. |
| 7 | `request_expired`, `request_not_found` | The code is unknown, already decided, or the request lapsed unanswered. | `cn request` again. |
| 8 | `unknown_secret` | No secret by that name. | `cn list --all`. |
| 9 | `limit_exceeded` | Refused by policy: TTL above max, too many names in a request or an import, reason too long, reveal disabled, another project under `cross_project = "deny"`. | Ask for less. |
| 10 | `rate_limited` | A per-session or per-uid limit: pending requests, requests per hour, deny cooldown, `list` calls, hide streams or bytes, open connections, live sessions. | Wait. |
| 11 | `no_session`, `session_dead` | The caller is not under a session anchor, or the anchor exited. | `cn session`; start the agent with `cn session exec`. |
| 12 | `store_sealed` | Phase 2 (FIDO2 unlock). | |
| 13 | `audit_broken` | `cn audit verify` found a break. | Investigate; do not ignore. |
| 14 | `approval_invalid`, `approver_unavailable` | `cn` found the digest `cnd` reported does not match the request it sent; or no approver could show the request to the human (no graphical session, not Wayland, polkitd not running). | `cn doctor`; tell the human. |

## JSON output

Every command accepts `--json`. Agents should always pass it when they parse
output. The rules:

1. **One object on stdout**, then a newline, for every command except
   `cn run`, `cn hide` and `cn audit` (below). Human-oriented text goes to
   stderr or is suppressed.
2. **Envelope.** Success:

   ```json
   {"cn":1,"ok":true,"data":{...}}
   ```

   Failure (exit code non-zero, as in the table above):

   ```json
   {"cn":1,"ok":false,"error":{"code":"grant_required","exit":4,
     "message":"no active use grant for clickhouse-password",
     "hint":"cn request clickhouse-password --reason \"...\"",
     "detail":{"names":["clickhouse-password"]}}}
   ```

   `cn` is the JSON schema version. Within one version, fields are only added;
   consumers must ignore unknown fields. `error.code` values are stable and
   match the daemon's error codes where one exists. For a decided request
   (`denied`, `request_expired`, `pending`), `error.detail` is the request,
   with its `decision`.
3. **Names and units.** `snake_case` keys; times are RFC 3339 UTC strings;
   durations are integer seconds in keys ending `_seconds`; grant ids start
   `g_`, session ids `s_` (`h_` for a terminal outside any agent session),
   request ids `r_`, run ids `u_`.
4. **`cn run --json`.** The child's stdout and stderr pass through unchanged
   apart from scrubbing. If `cn` itself fails (exit 125), it writes the error
   envelope as one line on stderr. On success `cn` writes nothing of its own.
5. **`cn hide --json`.** Stdout is the scrubbed stream. With `--stats`, the
   summary is one JSON object on stderr at EOF:
   `{"cn":1,"ok":true,"data":{"bytes_in":14336,"bytes_out":14310,"hits":{"clickhouse-password":1}}}`.
6. **`cn audit --json`** is JSON Lines, one audit record per line, no envelope.
   `cn audit verify --json` uses the envelope.

Examples (comments are not part of the output; long values shortened):

```text
// cn list --json
{"cn":1,"ok":true,"data":{"session":"s_7k2mq9d4x1ha","secrets":[
  {"name":"clickhouse-password","description":"ClickHouse analytics, read-only user `reporter`",
   "usage":"Read-only queries from scripts/clickhouse_*.py. ...","projects":["~/projects/moose/*"],
   "tags":[],"high_entropy":false,"in_project":true,"default_env":"CLICKHOUSE_PASSWORD",
   "grant":null,"created":"2026-10-02T11:40:00Z","updated":"2026-10-02T11:40:00Z",
   "rotated":"2026-10-02T11:40:00Z","last_use":null}]}}

// cn request --json: the canonical request, then the state
{"cn":1,"ok":true,"data":{"domain":"countersign/approve/v1","request_id":"r_9w1k...",
  "code":"K7M-Q2X","host":"...","boot_id":"...","session":"s_7k2mq9d4x1ha",
  "anchor":{"pid":41210,"starttime":8812345,"comm":"claude","registered":true},
  "cwd":"/home/patrick/projects/x","secrets":["clickhouse-password"],"mode":"use",
  "ttl_seconds":1800,"reason":"row counts ...","created_at":"2026-11-08T09:20:11Z",
  "expires_at":"2026-11-08T09:25:11Z","nonce":"...",
  "state":"pending","digest":"6f2a91c0...","digest_short":"3QF8-ZK2M",
  "approvers":[{"name":"polkit","adapter":"polkit","driven":"daemon","prompted":true}],
  "decision":null,"approve_command":"! /usr/bin/cn approve K7M-Q2X"}}

// cn request --wait --json, approved: the same, with the decision and the grant
{"cn":1,"ok":true,"data":{..., "state":"approved",
  "decision":{"at":"2026-11-08T09:21:40Z","by":["polkit"],"reason":null,"grant":{...},"grants_revoked":0},
  "grant":{"id":"g_4hx2","secrets":["clickhouse-password"],"mode":"use",
           "expires_at":"2026-11-08T09:51:40Z","approved_by":["polkit"],"uses":0,
           "reveals_left":null,"session":"s_7k2mq9d4x1ha"}}}
```

---

## Worked session

A Claude Code session started with `cn session exec`. Lines marked
`[agent]` are the agent's Bash tool; lines marked `[human]` are typed by the
developer, either in the Claude Code prompt as `!` commands or on the desktop.
Output is abbreviated.

**Start the agent under a session anchor** (human, in a terminal):

```console
$ cn session exec --label orchestrator -- claude
```

**The agent looks for a credential.**

```console
[agent] $ cn list
NAME                      GRANT  DESCRIPTION
clickhouse-password       -      ClickHouse analytics, read-only user `reporter`
typesafe-api-key          -      Typesafe API, production account
acurast-rpc-bearer-token  -      Bearer token for the Acurast RPC endpoint (mainnet)

[agent] $ cn show clickhouse-password
...
usage
  Read-only queries from scripts/clickhouse_*.py. Never write it into
  committed config or a URL. Production data: prefer the sandbox service
  unless the task names production.
```

**It requests a 30-minute use grant and waits.**

```console
[agent] $ cn request clickhouse-password --ttl 30m --wait 100s \
            --reason "row counts for the weekly cost report via scripts/clickhouse_rows.py"
request K7M-Q2X pending  use clickhouse-password for 30m
digest  3QF8-ZK2M
approve a desktop dialog is open
expires 2026-11-08T09:25:11Z (5m)
waiting up to 1m40s...
```

The agent tells the human: "I requested `clickhouse-password` for 30 minutes
(code K7M-Q2X, digest 3QF8-ZK2M). Please approve the desktop dialog."

**The polkit dialog.** GNOME Shell shows its authentication dialog, rendered
from details `cnd` supplied. With the touch factor:

```text
Authentication Required
  countersign request K7M-Q2X, digest 3QF8-ZK2M: USE clickhouse-password for 30m.
  agent claude (pid 41210, registered by cn session exec); agent-reported: label "orchestrator",
  cwd "~/projects/moose/liskov-agent-orchestrator".
  Agent's reason: row counts for the weekly cost report via scripts/clickhouse_rows.py
  touch the device
```

```text
[human] compares K7M-Q2X / 3QF8-ZK2M with the agent's message, touches the YubiKey.
```

```console
[agent] approved by polkit  grant g_4hx2 active until 09:51:40
```

**The agent runs the script with the secret injected.** The script echoes its
connection URL in verbose mode; `cn run` scrubs it.

```console
[agent] $ cn run --use clickhouse-password -- python3 scripts/clickhouse_rows.py --since 7d -v
connecting to https://reporter:[countersign:clickhouse-password]@ch.example.net:8443
table            rows
events      1834221
sessions      91022
```

**Output that did not come through `cn run` goes through `cn hide`.** The
script also wrote a log file, which `cn run` does not scrub:

```console
[agent] $ tail -n 5 logs/clickhouse_rows.log | cn hide
2026-11-08 09:33:01 connecting to https://reporter:[countersign:clickhouse-password]@ch.example.net:8443
2026-11-08 09:33:02 ok
```

**The grant expires.** Forty minutes later the agent tries again:

```console
[agent] $ cn run --use clickhouse-password -- python3 scripts/clickhouse_rows.py --since 1d
cn: error[grant_required]: no active use grant for clickhouse-password
hint: cn request clickhouse-password --reason "..."
[exit 125]
```

The agent requests again with a new reason, or stops and asks the human.

**The human reviews what happened:**

```console
[human] ! cn audit --session s_7k2mq9d4x1ha --since 1h
SEQ    TIME      EVENT            DETAIL
18331  09:20:11  request.create   K7M-Q2X use clickhouse-password 30m "row counts for the weekly cost report..."
18332  09:21:40  request.approve  r_9w1k... polkit -> g_4hx2
18333  09:22:03  use.start        u_8d1e... clickhouse-password argv0=python3 pid=41502
18334  09:22:09  use.end          u_8d1e... exited exit=0 signal=null 6100ms hits={clickhouse-password:1}
18335  09:23:30  hide             1024 B in, hits={clickhouse-password:1}
18336  09:51:40  grant.expire     g_4hx2 clickhouse-password by=ttl
```

## Open questions

1. **`--wait` and agent tool timeouts.** Claude Code's Bash tool has a default
   timeout of about two minutes. A `--wait` longer than that is killed by the
   harness while the request stays pending. The snippet says `--wait 100s`;
   the dialog stays open for the request's 5 minutes, so an approval after
   that is seen with `cn grants`. Should `cn request` pick the wait itself
   when it detects an agent?
2. **Rejected `run` attempts in the audit.** [audit.md](audit.md) has no
   event for a `cn run` refused with `grant_required`. Is that worth a record
   (useful to see probing) or noise (coalesce per session)?
3. **Raising a dialog again.** `cn approve` does not re-raise a dialog that
   was dismissed by accident or timed out. Should it? If so, should the agent
   be allowed to trigger that (prompt spam), or only a caller outside any
   agent session?
4. **Exit code granularity.** Exit 5 covers a human's explicit deny, a
   dismissed dialog and a fault in `cnd`; `cnd` finding no way to ask is
   exit 14. Agents should treat all the same and tell the human; the
   decision's `by` and `reason` say which.
5. **`--clipboard` on `reveal` and `add`.** The clipboard is readable by every
   process of the uid. It keeps the value out of the transcript, which is the
   main risk, but it is not private. Keep it, or require a real terminal for
   `reveal` by humans?
6. **Value length on `show`.** Omitted on purpose (a length narrows guesses).
   The mutation display shows only a length class. Is a class leaking
   anything that matters?
7. **`cn import` default for shredding** in a `!` command (no prompt): this
   document keeps files unless `--shred` is given. The other choice is to shred
   by default and require `--keep`.
