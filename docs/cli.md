# `cn` command reference

`cn` is the countersign client. It talks to `cnd` over
`/run/countersign/cnd.sock`, runs commands with secrets injected, and performs
the client side of FIDO2 approvals. It never holds state of its own: secrets,
grants, sessions and the audit log all live in `cnd`.

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
- **Short digest** is the first 8 Crockford base32 characters of the request digest,
  shown as `3QF8-ZK2M`. It appears in `cn request`, `cn approve` and every
  daemon-rendered display, so the human can compare them.
- **Session.** Every call is attributed by `cnd` to a session, resolved from
  the kernel's view of the caller's process ancestry (see `cn session`). The
  session is not something the caller can name or choose.
- **Who runs it.** "Agent" means the command is meant to be run from the
  agent's Bash tool. "Human" means the developer runs it, either in a separate
  terminal or as a Claude Code `!` command. A `!` command runs as the same uid,
  with the agent's environment and no TTY, so the agent can run anything the
  human can type there. Nothing in this table is a security boundary; the
  approvers are.
- **Absolute path for humans.** Documentation tells humans to type
  `/usr/bin/cn` for `approve`, `unlock`, `add`, `set`, `edit`, `rm`, `import`,
  `export` and `approver enroll`. This defeats a `cn` planted earlier on `PATH`. It does
  not defeat a shell function named `/usr/bin/cn` or a tampered harness; see
  [approvers.md](approvers.md#the-trusted-display-problem).

## Summary

| Command | Typically run by | Approval | Audit event(s) |
| --- | --- | --- | --- |
| `cn list` | agent | no (configurable) | `list` (coalesced) |
| `cn show NAME` | agent | no (follows `list`) | `list` (coalesced) |
| `cn request` | agent | creates one | `request.create` |
| `cn approve CODE` | human | is one | `request.approve` or `request.approve_fail` |
| `cn deny CODE` | human or agent | no | `request.deny` |
| `cn grants` | agent or human | no | none |
| `cn revoke` | human or agent | no | `grant.revoke` |
| `cn run` | agent | needs an active `use` grant | `use.start`, `use.end` |
| `cn hide` | agent | no | `hide` (byte and hit counts) |
| `cn reveal NAME` | human, or agent when asked | needs an active `reveal` grant | `reveal` |
| `cn add NAME` | human | `mutate` | `request.create`, `request.approve`, `store.add` |
| `cn set NAME` | human | `mutate` | `request.create`, `request.approve`, `store.set` |
| `cn edit NAME` | human | `mutate` | `request.create`, `request.approve`, `store.edit` |
| `cn rm NAME` | human | `mutate` | `request.create`, `request.approve`, `store.rm` |
| `cn import` | human | `mutate` (one for the batch) | `request.create`, `request.approve`, `store.add` per secret, `import` |
| `cn export` | human | `export` | `request.create`, `request.approve`, `export` |
| `cn session` | agent or human | no | none |
| `cn session exec` | human | no | `session.start` |
| `cn audit` | agent or human | no | none |
| `cn audit verify` | human | no | none |
| `cn unlock` | human | FIDO2 touch | `unlock` |
| `cn approver enroll` | human | root installs the result | `config.load` when `cnd` loads it |
| `cn doctor` | human or agent | no | none |

## Global options

| Option | Meaning |
| --- | --- |
| `--json` | Machine-readable output; see [JSON output](#json-output). |
| `--socket PATH` | Socket path. Default `/run/countersign/cnd.sock`. Also `COUNTERSIGN_SOCKET`. Ignored by `approve`, `unlock` and `approver enroll` (see below). |
| `--no-color` | No ANSI colour. Colour is also off when stdout is not a terminal. |
| `-q`, `--quiet` | Suppress informational lines on stderr. |
| `-h`, `--help` | Help for the command. |
| `--version` | Print `cn` version and the protocol versions it speaks. |

Before sending anything, `cn` checks the server end of the socket with
`SO_PEERCRED` and refuses to talk to a peer that is not running as the
`countersign` system user. `approve`, `unlock` and `approver enroll` always use
the default socket path and ignore `--socket` and `COUNTERSIGN_SOCKET`, so a
fake daemon on another path cannot feed them a request to display.

`cn` strips every `COUNTERSIGN_*` variable from the environment of any child
it starts.

---

## `cn list`

```text
cn list [--all] [--long] [--json]
```

Lists secrets visible to the current session: name, one-line description,
usage prose, project scope and the session's grant state for each. Never
values, never value lengths.

By default only secrets whose `projects` globs match the session's reported
cwd are shown, plus secrets with no `projects` (available everywhere). Project
scope is organizational, not a security boundary.

| Flag | Meaning |
| --- | --- |
| `--all` | Include secrets scoped to other projects. They are marked `other project`; requesting one is allowed but flagged in the approval display. |
| `--long`, `-l` | Print the full usage prose for each secret (default prints the first line). |

```console
$ cn list
NAME                      GRANT        DESCRIPTION
clickhouse-password       -            ClickHouse analytics, read-only user `reporter`
typesafe-api-key          use 41m left Typesafe API, production account
acurast-rpc-bearer-token  -            Bearer token for the Acurast RPC endpoint (mainnet)
```

- **Run by:** agent, at the start of any task that may need a credential.
- **Approval:** none by default. `[approval] list_requires_approval = true`
  makes `list` and `show` need a `use`-level approval once per session.
- **Audit:** `list`, coalesced per session (one record per 10 minutes with a
  call count) so polling does not flood the log.

## `cn show NAME`

```text
cn show NAME [--json]
```

Prints one secret's metadata: description, full usage prose, projects, tags,
`high_entropy`, created / updated / rotated times, the time of its last use
and by which session, and this session's grants for it. Never the value or
its length.

```console
$ cn show clickhouse-password
name          clickhouse-password
description   ClickHouse analytics, read-only user `reporter`
projects      ~/projects/moose/*
high_entropy  no   (not redacted by `cn hide` unless granted)
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
grant applies only to processes descending from that session's anchor.

| Flag | Meaning |
| --- | --- |
| `--reason TEXT` | Required. What will be run and why. Shown to the human labelled as agent-supplied, escaped and truncated to 300 characters. Passed through the redaction engine before it is stored or displayed. |
| `--ttl DUR` | Grant lifetime, counted from approval. Default `[grants] default_ttl` (1h) for `use`, `max_reveal_ttl` (10m) for `reveal`. Above `max_ttl` (8h) or `max_reveal_ttl` (10m) is refused with `limit_exceeded`, not silently capped. |
| `--mode use` | Default. Values may be injected by `cn run`. |
| `--mode reveal` | Values may be printed by `cn reveal`. Single use by default. Needs the `reveal` approval chain, which is usually stricter. |
| `--wait[=DUR]` | Block until the request is approved, denied or expires, up to `DUR` (default: the request's pending lifetime, 5m). Without `--wait`, return as soon as the request is created. |

When the configured chain includes a daemon-driven approver (polkit), `cnd`
raises the dialog as soon as the request is created; the human answers it on
the desktop. When it includes a client-driven approver (FIDO2), the human must
run `/usr/bin/cn approve CODE`. The output says which. With the default chains
([approvers.md](approvers.md#recommended-default-for-the-owner)) a `use`
request raises the polkit dialog only:

```console
$ cn request clickhouse-password --ttl 30m --reason "row counts for the weekly cost report via scripts/clickhouse_rows.py"
request K7M-Q2X pending  use clickhouse-password for 30m
digest  3QF8-ZK2M
approve a desktop dialog is open
expires 2026-11-08T09:25:11Z (5m)
```

When the chain has a client-driven member, the `approve` line names the
command instead: `approve the human runs:  ! /usr/bin/cn approve K7M-Q2X`.

A request for a secret that already has an active grant of the same or wider
mode in this session returns the existing grant and creates nothing.

- **Run by:** agent.
- **Approval:** this command creates the thing to be approved.
- **Audit:** `request.create` (secrets, mode, ttl, reason, session, anchor,
  digest). Further: `request.approve`/`request.deny`/`request.expire` when it
  resolves.
- **Limits:** at most 16 names per request; at most 3 pending requests per
  session; per-session request rate (`[limits]`). A denied request starts a
  cooldown for the same names in that session.

## `cn approve CODE`

```text
/usr/bin/cn approve CODE [--approver NAME] [--timeout DUR] [--json]
```

Fetches the pending request from `cnd`, prints it, and runs the client side of
the approval chain:

- For a **client-driven** approver (FIDO2): computes the canonical digest from
  the request `cnd` returned, checks it equals the digest `cnd` reports, asks
  the security key for an assertion with that digest as `clientDataHash` and
  user presence required, and sends the assertion to `cnd`, which verifies it
  against the enrolled public key.
- For a **daemon-driven** approver (polkit): asks `cnd` to raise (or re-raise)
  the dialog, then waits for the result. Useful after a dialog was dismissed by
  accident.

There is no "press y to confirm" step. A `!` command has no TTY, and the touch
or the dialog is the confirmation. To refuse, do not touch the key (the
approval times out) or run `cn deny CODE`.

| Flag | Meaning |
| --- | --- |
| `--approver NAME` | Use this approver instance from the chain (e.g. `desk-key` in `all_of = ["polkit", "desk-key"]`). Default: the first client-driven approver in the chain, else trigger the daemon-driven one. |
| `--timeout DUR` | How long to wait for the touch. Default 60s. |

With a chain whose client-driven member is the `desk-key` FIDO2 approver:

```console
! /usr/bin/cn approve K7M-Q2X
countersign request K7M-Q2X
  session   s_7k2mq9d4x1ha  anchor claude pid 41210 (registered by cn session exec)
  cwd       /home/patrick/projects/moose/liskov-agent-orchestrator   (reported, untrusted)
  secrets   clickhouse-password   (this project)
  mode      use
  ttl       30m  (max 8h)
  reason    (agent-supplied) row counts for the weekly cost report via scripts/clickhouse_rows.py
  digest    3QF8-ZK2M
Touch the security key "desk-key" to approve, or wait 60s to let it lapse.
approved by fido2:desk-key  grant g_4hx2 active until 09:51:40
```

`cn approve` sets `PR_SET_DUMPABLE=0`, refuses to run when its `TracerPid` is
non-zero, and is statically linked so `LD_PRELOAD` has no effect. None of this
protects against a replaced binary or shell function; that is the trusted
display problem, covered in [approvers.md](approvers.md).

- **Run by:** human. An agent can run it too; it then reaches the key prompt
  and stops, because it cannot touch the key. The Claude Code hook examples in
  [agent-integration.md](agent-integration.md) stop confused agents from
  trying.
- **Approval:** this is the approval.
- **Audit:** `request.approve` with the approver's evidence (for FIDO2:
  credential id, flags, signature counter, the signature and authenticator
  data, so the approval can be re-verified later). A failed verification
  writes `request.approve_fail` and counts toward the per-session
  approval-attempt limit.

## `cn deny CODE`

```text
cn deny CODE [--reason TEXT] [--json]
```

Denies a pending request. Anyone allowed on the socket can deny any pending
request: denial only removes privilege. The agent can use it to withdraw its
own request.

```console
$ cn deny K7M-Q2X --reason "wrong secret, wanted the sandbox key"
denied K7M-Q2X
```

- **Run by:** human (to refuse) or agent (to withdraw).
- **Approval:** none.
- **Audit:** `request.deny` with who denied (session or "outside any
  session") and the reason.

## `cn grants`

```text
cn grants [--all-sessions] [--json]
```

Lists active grants for the current session: grant id, secrets, mode, time
left, which approver approved it, and use count.

```console
$ cn grants
GRANT   SECRETS               MODE  LEFT  APPROVED BY       USES
g_4hx2  clickhouse-password   use   27m   polkit            2
```

| Flag | Meaning |
| --- | --- |
| `--all-sessions` | Show active grants in every live session of the caller's uid, with each session's anchor. For the human's overview. |

- **Run by:** agent (to check what it already has) or human.
- **Approval:** none.
- **Audit:** none.

## `cn revoke`

```text
cn revoke GRANT_ID...
cn revoke --secret NAME
cn revoke --all [--all-sessions]
```

Ends grants before their TTL. A running `cn run` child keeps the values it was
started with; no new values are issued under a revoked grant.

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
JSON-escaped and hex forms, with `[countersign:NAME]`. Stdin is passed through.
The exit status is the child's.

| Flag | Meaning |
| --- | --- |
| `--use NAME` | Inject `NAME` as its default variable (`clickhouse-password` -> `CLICKHOUSE_PASSWORD`). Repeatable. |
| `--use NAME=ENVVAR` | Inject `NAME` as `ENVVAR`. |

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

Do not pass a value as an argument (`--password "$CLICKHOUSE_PASSWORD"`
expanded by an outer shell): argv is world-readable in `/proc/<pid>/cmdline`
and appears in the transcript. Let the child read the variable, or use
`sh -c '... "$VAR" ...'` so the expansion happens inside the child.

- **Run by:** agent.
- **Approval:** needs an active `use` grant for every named secret in this
  session. Without one, `cn run` exits 125 with `grant_required` before
  starting anything.
- **Audit:** `use.start` written by `cnd` when values are issued (secrets,
  argv0, argument count, reported cwd, pid, session); `use.end` reported by
  `cn` (exit code or signal, duration, per-secret hit counts in the scrubbed
  output). `use.end` is client-reported and marked so; if `cn` dies, `cnd`
  writes `use.end` with `status: "client_lost"`.

Exit codes for `run` follow `env(1)`, not the general table:

| Exit | Meaning |
| --- | --- |
| child's code | Child exited normally. |
| 128 + N | Child killed by signal N. |
| 125 | `cn` failed before or while starting the child (no grant, daemon unreachable, bad `--use`). The error code is on stderr, as JSON with `--json`. |
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
never matched, so `cn hide` cannot confirm guesses of a short password.

| Flag | Meaning |
| --- | --- |
| `--secret NAME` | Also match `NAME`. Allowed only for secrets with an active grant in this session (otherwise it would be a guessing oracle); refused with `grant_required`. |
| `--stats` | At EOF print per-secret hit counts to stderr. |

```console
$ tail -n 50 logs/clickhouse_rows.log | cn hide
2026-11-08 09:33:01 connecting to https://reporter:[countersign:clickhouse-password]@ch.example.net:8443
2026-11-08 09:33:02 ok
```

- **Run by:** agent, as the last stage of any pipeline whose output might
  contain a secret: logs, `env`, config dumps, HTTP debug output, files a
  `cn run` child wrote.
- **Approval:** none.
- **Audit:** `hide` per stream: bytes in, bytes out, hit counts per secret.
  Never the matched text.
- **Limits:** 30 new streams per minute per session and a byte budget
  (default 256 MiB/min). Excess returns `rate_limited`.

## `cn reveal NAME`

```text
cn reveal NAME [--clipboard] [--json]
```

Prints the raw value. This puts the value wherever stdout goes: in a `!`
command or an agent's Bash tool, that is the transcript and the model
provider, permanently.

| Flag | Meaning |
| --- | --- |
| `--clipboard` | Copy the value to the Wayland clipboard (`wl-copy`, cleared after 30s) instead of printing it. For a human in a terminal. The clipboard is readable by every process of the uid while the value is on it. |

```console
$ cn reveal typesafe-api-key --clipboard
copied typesafe-api-key to the clipboard; clears in 30s
```

- **Run by:** human, or an agent only when the human has asked for the raw
  value in the conversation.
- **Approval:** needs an active `reveal` grant (`cn request NAME --mode
  reveal`), approved through the `reveal` chain. A reveal grant is consumed
  after one reveal by default.
- **Audit:** `reveal` (secret, session, grant, reveals left). Shown
  highlighted in `cn audit`.

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
| `--from-file PATH` | Reads the file; after the store commit, overwrites and unlinks it. Overwriting does not erase data on copy-on-write filesystems (btrfs) or SSDs. |
| `--from-stdin` | Reads stdin to EOF. One trailing newline is stripped. |

| Flag | Meaning |
| --- | --- |
| `--description TEXT` | Required. One line, at most 200 characters. |
| `--usage TEXT`, `--usage-file PATH` | How agents should use this secret in this project. At most 4 KiB. |
| `--project GLOB` | Repeatable. Matched against the session's reported cwd. Empty means everywhere. |
| `--high-entropy`, `--low-entropy` | Whether `cn hide` matches this secret even when it is not granted. `cn add` estimates entropy and suggests one; you must choose if the estimate is ambiguous. Values shorter than 8 bytes are never matched and `cn add` warns. |

```console
$ /usr/bin/cn add acurast-rpc-bearer-token --from-clipboard \
    --description "Bearer token for the Acurast RPC endpoint (mainnet)" \
    --usage "Only for scripts/acurast_*.py read calls. Never log request headers." \
    --project '~/projects/moose/*' --high-entropy --wait
request P2D-8TW pending  mutate: add acurast-rpc-bearer-token
digest  7KMA-W41C
approve a desktop dialog is open
added acurast-rpc-bearer-token
```

- **Run by:** human. Run it from a terminal outside any agent session where
  possible, so the approval display does not say "initiated in agent session".
- **Approval:** `mutate` chain. The display shows the name, description,
  usage, projects, `high_entropy`, the value's length class, the value source,
  and the initiating session.
- **Audit:** `request.create`, `request.approve`, then `store.add` (metadata only).

## `cn set NAME`

```text
/usr/bin/cn set NAME [--from-clipboard | --from-file PATH | --from-stdin] [--wait[=DUR]] [--json]
```

Replaces a secret's value (rotation). Value sources as for `cn add`. Existing
grants for `NAME` are revoked when the new value is committed.

```console
$ /usr/bin/cn set typesafe-api-key --from-clipboard --wait
request R9C-2HF pending  mutate: set typesafe-api-key (value changes)
digest  M2QX-7Z0D
approve a desktop dialog is open
set typesafe-api-key; 1 grant revoked
```

- **Run by:** human.
- **Approval:** `mutate`. An agent swapping a DSN to point at its own host is
  an exfiltration path, so the display says plainly when the change was
  initiated inside an agent session. Deny any `set` you did not start.
- **Audit:** `request.create`, `request.approve`, `store.set` (no value, no hash of value).

## `cn edit NAME`

```text
/usr/bin/cn edit NAME [--description TEXT] [--usage TEXT | --usage-file PATH]
                 [--add-project GLOB]... [--rm-project GLOB]...
                 [--tag TAG]... [--untag TAG]... [--high-entropy | --low-entropy]
                 [--wait[=DUR]] [--json]
```

Changes metadata, not the value. With no flags and a real terminal, opens
`$EDITOR` on a TOML rendering of the metadata; without a terminal it refuses
with `no_tty`.

Usage prose steers every later agent session, so a change to it is a change
to agent behaviour. An agent may draft new prose and show it to the human; the
human applies it.

```console
$ /usr/bin/cn edit clickhouse-password --usage-file /tmp/ch-usage.txt --wait
request T4N-6KB pending  mutate: edit clickhouse-password (usage: 3 lines changed)
...
edited clickhouse-password
```

- **Run by:** human.
- **Approval:** `mutate`. The display shows a diff of every changed field.
- **Audit:** `store.edit` with the list of changed fields and the new
  metadata (metadata is not secret).

## `cn rm NAME`

```text
/usr/bin/cn rm NAME... [--wait[=DUR]] [--json]
```

Removes secrets. Active grants for them are revoked on commit.

- **Run by:** human.
- **Approval:** `mutate`; the display lists names and descriptions.
- **Audit:** `store.rm` per secret.

## `cn import`

```text
/usr/bin/cn import --glob GLOB [--dir DIR] [--metadata FILE] [--strip-prefix PREFIX]
                   [--shred | --keep] [--dry-run] [--wait[=DUR]] [--json]
/usr/bin/cn import --from BACKUP.age [--wait[=DUR]]
```

Moves existing plaintext secret files into the store. Each matching file
becomes one secret; the name is the file name with `--strip-prefix` removed
(default `.secret-`), so `.secret-typesafe-api-key` becomes
`typesafe-api-key`. The whole batch is one `mutate` request.

Metadata comes from, in order: `--metadata FILE` (TOML, below); an
interactive prompt per file in a real terminal; or, with neither, a
placeholder description `imported from <path>` and empty usage, which
`cn doctor` then reports until edited.

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
| `--metadata FILE` | Descriptions, usage, projects and entropy class per secret name. Lets a `!` command import without prompts. An agent may draft this file. |
| `--shred` | After a successful commit, overwrite and unlink each source file. Default asks in a real terminal and keeps without one. |
| `--keep` | Leave the source files. |
| `--dry-run` | Print what would be imported (names, sizes, git-tracked status), touch nothing, create no request. |

`cn import` warns about each source file that is tracked by git, appears in
git history (`git log --all -- PATH`), or is world-readable. Values that were
ever in a readable file should be rotated after import; see
[agent-integration.md](agent-integration.md#migrating-from-secret-files).

- **Run by:** human. `cn` reads the files as the developer's uid, so it also
  works in a `!` command with `--metadata`.
- **Approval:** one `mutate` approval listing every name to be added.
- **Audit:** `request.create`, `request.approve`, `store.add` per secret, and
  one `import` record for the batch. Shredding happens in `cn` and is not
  audited.

## `cn export`

```text
/usr/bin/cn export --recipient AGE_RECIPIENT [--wait[=DUR]] > backup.age
```

Writes the whole store, values included, encrypted to an age recipient the
human controls ([design.md](design.md#backup-and-export)). Restore with
`cn import --from backup.age`.

- **Run by:** human.
- **Approval:** `export` chain. The display shows the recipient and the number
  of secrets.
- **Audit:** `request.create`, `request.approve`, `export` (count, recipient).

## `cn session`

```text
cn session [--json]
cn session exec [--label TEXT] -- COMMAND [ARG...]
```

`cn session` prints what `cnd` believes the caller's session is: session id,
anchor pid, comm, start time, how the anchor was found (registered by the
launcher, or a matcher), the process chain from the caller to the anchor,
untrusted labels, and the number of active grants.

```console
$ cn session
session   s_7k2mq9d4x1ha  (registered by cn session exec, label "orchestrator")
anchor    pid 41210  comm claude  started 2026-11-08T09:14:03Z
chain     41377 cn <- 41376 bash <- 41210 claude
cwd       /home/patrick/projects/moose/liskov-agent-orchestrator  (reported, untrusted)
labels    CLAUDE_CODE_SESSION_ID=9f3c... (untrusted)
grants    1 active
```

`cn session exec` registers the calling process as a session anchor and then
`exec`s `COMMAND`, which keeps the pid and start time, so the agent process
is the anchor. This is the recommended way to start an agent: it works for any
agent and does not depend on matching process names.

```console
$ cn session exec --label orchestrator -- claude
```

Grants die when the anchor exits. A nested `cn session exec` creates a new
session with no grants.

- **Run by:** `cn session`: agent or human, to debug `no_session`.
  `cn session exec`: human, when starting the agent (or a shell alias).
- **Approval:** none.
- **Audit:** `session.start` for `exec`; `session.end` when the anchor
  exits. `cn session` itself is not audited.

## `cn audit`

```text
cn audit [--current | --session ID] [--secret NAME] [--event KIND]...
         [--since TIME|DUR] [--until TIME] [--limit N] [--follow] [--json]
cn audit verify [--from SEQ] [--approvals] [--pubkey FILE] [--checkpoints FILE]
                [--dir DIR] [--json]
cn audit checkpoints [--since TIME|DUR]
cn audit pubkey
```

`cn audit` reads the log through `cnd` (the agent cannot open the file). Times
accept RFC 3339 or a duration back from now (`--since 2h`). `--follow` streams
new records. With `--json`, output is JSON Lines, one record per line, in the
format defined in [audit.md](audit.md); this is the one command whose `--json`
output is not a single envelope object.

```console
$ cn audit --current --since 1h
SEQ    TIME      EVENT       DETAIL
18331  09:20:11  request.create   K7M-Q2X use clickhouse-password 30m "row counts for the weekly..."
18332  09:21:40  request.approve  K7M-Q2X polkit -> g_4hx2
18333  09:22:03  use.start        g_4hx2 clickhouse-password argv0=python3 pid=41502
18334  09:22:09  use.end          exit=0 6.1s hits={}
18335  09:23:30  hide             14 KiB in, hits={clickhouse-password:1}
```

`cn audit verify` fetches the raw segments and recomputes the hash chain and
checkpoint signatures locally, so the result does not depend on trusting
`cnd`'s answer. It reports the record count, the head hash and the last
checkpoint, and exits 13 on any break. `--approvals` also re-verifies each
FIDO2 approval's signature over its recorded canonical request, using the
public keys in `/etc/countersign/approvers.d/`. `--pubkey`, `--checkpoints`
and `--dir` (root, reading the files directly) are described in
[audit.md](audit.md#verifying-cn-audit-verify). `cn audit checkpoints` prints
checkpoint records for off-box export; `cn audit pubkey` prints the checkpoint
public key.

```console
$ cn audit verify
chain ok: 18335 records, 19 checkpoints, head 9c1e4f..., last checkpoint 2026-11-08T09:00:00Z
```

Verification proves the log was not altered by anyone without the checkpoint
key. It does not detect a rewrite by root or `cnd` itself unless checkpoints
were also exported (journald or a remote sink) and are compared.

- **Run by:** human or agent (read-only).
- **Approval:** none.
- **Audit:** none.

## `cn unlock`

```text
/usr/bin/cn unlock [--timeout DUR] [--json]
/usr/bin/cn unlock --enroll [--wait[=DUR]]
```

Unseals the store when `cnd` is configured with a `fido2` key slot and started
sealed (every other command returns `store_sealed` until then). `cn` gets the
slot's credential id and salt from `cnd`, asks the key for its `hmac-secret`
output (touch required), and sends the output to `cnd`, which derives the
key-encryption key and unwraps the master key. When `[unlock] fido2_side =
"daemon"` is set, `cnd` talks to the key itself and `cn unlock` only triggers
it, so the `hmac-secret` output never enters the developer's uid.

`--enroll` adds a `fido2` key slot for the inserted key. It requires an
unsealed store and a `mutate` approval.

- **Run by:** human, after boot when the store uses a FIDO2 slot.
- **Approval:** the touch. `--enroll` needs `mutate`.
- **Audit:** `unlock` (slot, result) and `store.unseal` on success; `--enroll`
  writes `keyslot.add`.

## `cn approver enroll`

```text
/usr/bin/cn approver enroll --name NAME [--uv required|preferred|discouraged] [--out FILE]
cn approver list [--json]
```

Registers a FIDO2 credential (a YubiKey) as an approver. Enrollment has two
steps, because approver policy is root-owned and the agent must not be able to
add a key of its own:

1. `cn approver enroll` creates a non-discoverable credential on the key
   (touch, and PIN when `--uv required`) with relying party id `countersign`,
   and writes a record with the credential id, COSE public key, AAGUID and the
   attestation statement to `FILE` (default `./NAME.approver.toml`).
2. Root installs the record and reloads the daemon:

```console
$ /usr/bin/cn approver enroll --name desk-key
Touch the security key to create the countersign credential...
wrote desk-key.approver.toml  (YubiKey 5 Series, AAGUID cb69481e-8ff7-4039-93ec-0a2729a154a8)
install with:
  sudo install -o root -g root -m 0644 desk-key.approver.toml /etc/countersign/approvers.d/
  sudo systemctl reload countersign

$ sudo install -o root -g root -m 0644 desk-key.approver.toml /etc/countersign/approvers.d/
$ sudo systemctl reload countersign
```

On load, `cnd` verifies the attestation statement against the trusted roots in
config (default: the Yubico FIDO root). A record produced by a software
authenticator, for example by a shadowed `cn`, fails this check and is not
loaded. `attestation = "none"` in config turns the check off for keys without
usable attestation, at the cost of that protection.

Run enrollment from a real terminal: `sudo` needs one for its password prompt.

- **Run by:** human.
- **Approval:** writing to `/etc/countersign/approvers.d/` needs root; that is
  the approval.
- **Audit:** `config.load`, whose approver summary lists each record (name,
  credential id, AAGUID, attestation result) as loaded or rejected.

## `cn doctor`

```text
/usr/bin/cn doctor [--json]
```

Checks the installation and the current environment and prints one line per
check: `ok`, `warn` or `fail`, with a fix for each non-`ok` result. Exit 0 when
there are no failures, 1 otherwise.

| Check | `fail` / `warn` when |
| --- | --- |
| Binary | `/usr/bin/cn` is not root-owned 0755, or the running binary is not `/usr/bin/cn`. |
| PATH shadowing | `command -v cn` in a login shell resolves to anything other than `/usr/bin/cn`; any `cn` in a `PATH` directory writable by the user; any `alias cn`, `cn()` or `/usr/bin/cn()` definition in `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.config/fish/` or Claude Code's shell snapshot files. |
| Daemon | Socket missing or unreachable; peer not running as `countersign`; protocol version mismatch; caller's uid not allowed; caller not in `countersign-users`. |
| Permissions | `/etc/countersign/` or `config.toml` writable by non-root; `approvers.d/` records not root-owned; `command` adapter executables or their parent directories writable by non-root; `/var/lib/countersign` not `countersign` 0700 (checked through `cnd`). |
| Store | Sealed; no portable key slot; secrets with placeholder descriptions; values shorter than 8 bytes. |
| Approvers | Chain names an approver that is not configured; polkit action not installed or set to `yes` or `*_keep`; no polkit agent registered for the graphical session; `pam_u2f` not in the `polkit-1` PAM stack when the config says it should be; `pam_u2f` `authfile` writable by the user; no FIDO2 credential loaded when the chain needs one; enrolled key not present. |
| Session | `cn session` resolves to `no_session` from the current shell; the anchor was found by a matcher rather than `cn session exec` (info). |
| Environment | X11 session (polkit dialog input can be synthesized); `kernel.yama.ptrace_scope` is 0; `/proc` not mounted `hidepid`. Informational. |
| Leftovers | `.secret-*` or similarly named files in the cwd or the git repository, tracked files matching them, or matches in git history. |
| Audit | Chain head not verified in the last 24h (runs a verify). |

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
| 1 | `internal` | Unexpected failure; details in the daemon log. | Report it. |
| 2 | `usage`, `no_tty` | Bad arguments, or a prompt was needed with no terminal. | Fix the command; use `--from-*` value sources. |
| 3 | `daemon_unreachable`, `unsupported_version`, `unknown_request`, `forbidden_peer`, `bad_peer` | Cannot talk to a genuine `cnd` with a common protocol. | `cn doctor`. |
| 4 | `grant_required` | No active grant for that secret and mode in this session. | `cn request`. |
| 5 | `denied` | The request was denied (by a human, an approver, or a dismissed dialog). | Do not retry without asking the human. |
| 6 | `pending` | `--wait` timed out; the request is still pending. | Ask the human to approve, then `cn grants`. |
| 7 | `request_expired`, `request_not_found` | The code is unknown or the request lapsed. | `cn request` again. |
| 8 | `unknown_secret` | No secret by that name. | `cn list --all`. |
| 9 | `limit_exceeded` | Refused by policy: TTL above max, too many names, mode disabled. | Ask for less. |
| 10 | `rate_limited` | A per-session rate limit was hit. | Wait. |
| 11 | `no_session`, `session_dead` | The caller is not under a session anchor, or the anchor exited. | `cn session`; start the agent with `cn session exec`. |
| 12 | `store_sealed` | The store is not unlocked. | Human runs `cn unlock`. |
| 13 | `audit_broken` | `cn audit verify` found a break. | Investigate; do not ignore. |
| 14 | `approval_invalid`, `approver_unavailable` | An assertion failed verification, or no approver in the chain could run. | `cn doctor`. |

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
     "message":"no active grant for 'clickhouse-password' in session s_7k2mq9d4x1ha",
     "hint":"cn request clickhouse-password --reason \"...\"",
     "detail":{"names":["clickhouse-password"]}}}
   ```

   `cn` is the JSON schema version. Within one version, fields are only added;
   consumers must ignore unknown fields. `error.code` values are stable and
   match the daemon's error codes where one exists.
3. **Names and units.** `snake_case` keys; times are RFC 3339 UTC strings;
   durations are integer seconds in keys ending `_seconds`; grant ids start
   `g_`, session ids `s_`, request ids `r_`.
4. **`cn run --json`.** The child's stdout and stderr pass through unchanged
   apart from scrubbing. If `cn` itself fails (exit 125), it writes the error
   envelope as one line on stderr. On success `cn` writes nothing of its own.
5. **`cn hide --json`.** Stdout is the scrubbed stream. With `--stats`, the
   summary is one JSON object on stderr at EOF:
   `{"cn":1,"ok":true,"data":{"bytes_in":14336,"bytes_out":14310,"hits":{"clickhouse-password":1}}}`.
6. **`cn audit --json`** is JSON Lines, one audit record per line, no envelope.
   `cn audit verify --json` uses the envelope.

Examples (comments are not part of the output):

```text
// cn list --json
{"cn":1,"ok":true,"data":{"session":"s_7k2mq9d4x1ha","secrets":[
  {"name":"clickhouse-password","description":"ClickHouse analytics, read-only user `reporter`",
   "usage":"Read-only queries from scripts/clickhouse_*.py. ...","projects":["~/projects/moose/*"],
   "in_project":true,"high_entropy":false,"default_env":"CLICKHOUSE_PASSWORD",
   "grant":null}]}}

// cn request --json
{"cn":1,"ok":true,"data":{"request_id":"r_9w1k...","code":"K7M-Q2X","state":"pending",
  "secrets":["clickhouse-password"],"mode":"use","ttl_seconds":1800,
  "digest_short":"3QF8-ZK2M","expires_at":"2026-11-08T09:25:11Z",
  "approvers":[{"name":"polkit","driven":"daemon","prompted":true}],
  "approve_command":"! /usr/bin/cn approve K7M-Q2X"}}

// cn request --wait --json, approved
{"cn":1,"ok":true,"data":{"code":"K7M-Q2X","state":"approved",
  "grant":{"id":"g_4hx2","secrets":["clickhouse-password"],"mode":"use",
           "expires_at":"2026-11-08T09:51:40Z","approved_by":["polkit"]}}}
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
[agent] $ cn request clickhouse-password --ttl 30m --wait 3m \
            --reason "row counts for the weekly cost report via scripts/clickhouse_rows.py"
request K7M-Q2X pending  use clickhouse-password for 30m
digest  3QF8-ZK2M
approve a desktop dialog is open
waiting up to 3m...
```

The agent tells the human: "I requested `clickhouse-password` for 30 minutes
(code K7M-Q2X, digest 3QF8-ZK2M). Please approve the desktop dialog."

**Path A: polkit dialog, backed by `pam_u2f` (the default chain).** GNOME Shell shows its
authentication dialog, rendered from details `cnd` supplied:

```text
Authentication Required
  Agent session "orchestrator" (claude, pid 41210) asks to USE
  clickhouse-password for 30m in ~/projects/moose/liskov-agent-orchestrator.
  Agent's reason: row counts for the weekly cost report via
  scripts/clickhouse_rows.py
  Request K7M-Q2X  digest 3QF8-ZK2M
  Please touch the device.
```

```text
[human] compares K7M-Q2X / 3QF8-ZK2M with the agent's message, touches the YubiKey.
```

```console
[agent] approved by polkit  grant g_4hx2 active until 09:51:40
```

**Path B: FIDO2 from the Claude Code prompt.** Only with a non-default chain
that lets a `fido2` approver decide alone (`use = "desk-key"`, or an `any_of`
for a machine with no graphical session). The terminal is then the only
display, which a planning agent can alter
([approvers.md](approvers.md#strength-of-a-chain)):

```console
[human] ! /usr/bin/cn approve K7M-Q2X
countersign request K7M-Q2X
  session   s_7k2mq9d4x1ha  anchor claude pid 41210 (registered by cn session exec)
  cwd       /home/patrick/projects/moose/liskov-agent-orchestrator   (reported, untrusted)
  secrets   clickhouse-password   (this project)
  mode      use
  ttl       30m  (max 8h)
  reason    (agent-supplied) row counts for the weekly cost report via scripts/clickhouse_rows.py
  digest    3QF8-ZK2M
Touch the security key "desk-key" to approve, or wait 60s to let it lapse.
approved by fido2:desk-key  grant g_4hx2 active until 09:51:40
```

The agent's waiting `cn request` returns with the same `approved` line.

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
cn: error[grant_required]: no active grant for 'clickhouse-password' in session s_7k2mq9d4x1ha
    (grant g_4hx2 expired at 09:51:40)
hint: cn request clickhouse-password --reason "..."
[exit 125]
```

The agent requests again with a new reason, or stops and asks the human.

**The human reviews what happened** (this session took path A):

```console
[human] ! cn audit --current --since 1h
SEQ    TIME      EVENT          DETAIL
18331  09:20:11  request.create   K7M-Q2X use clickhouse-password 30m "row counts for the weekly..."
18332  09:21:40  request.approve  K7M-Q2X polkit -> g_4hx2
18333  09:22:03  use.start        g_4hx2 clickhouse-password argv0=python3 pid=41502
18334  09:22:09  use.end          exit=0 6.1s hits={clickhouse-password:1}
18335  09:23:30  hide             1 KiB in, hits={clickhouse-password:1}
18336  09:51:40  grant.expire     g_4hx2
```

## Open questions

1. **`--wait` and agent tool timeouts.** Claude Code's Bash tool has a default
   timeout of about two minutes. A `--wait` longer than that is killed by the
   harness while the request stays pending. Should `cn request` default to
   `--wait 100s` when it detects it is under an agent, or should the snippet
   always say `--wait 2m` and then `cn grants`?
2. **Rejected `run` attempts in the audit.** [audit.md](audit.md) has no
   event for a `cn run` refused with `grant_required`. Is that worth a record
   (useful to see probing) or noise (coalesce per session)?
3. **`cn approve` in a polkit-only chain.** It re-raises the dialog. Should the
   agent be allowed to trigger that (prompt spam), or should `approve` for
   daemon-driven approvers only work from outside any agent session?
4. **Exit code granularity.** Exit 5 covers a human's explicit deny and a
   dismissed dialog. Agents should treat both the same; if a reason is needed
   it is in `error.detail.by`.
5. **`--clipboard` on `reveal` and `add`.** The clipboard is readable by every
   process of the uid. It keeps the value out of the transcript, which is the
   main risk, but it is not private. Keep it, or require a real terminal for
   `reveal` by humans?
6. **Value length on `show`.** Omitted on purpose (a length narrows guesses).
   The mutation display shows only a length class. Is a class (`<16`, `16-64`,
   `>64` bytes) leaking anything that matters?
7. **`cn import` default for shredding** in a `!` command (no prompt): this
   document keeps files unless `--shred` is given. The other choice is to shred
   by default and require `--keep`.
