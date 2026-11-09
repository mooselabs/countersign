# Migrating a project from `.secret-*` files

Starting point: files such as `.secret-clickhouse-password`,
`.secret-typesafe-api-key` and `.secret-acurast-rpc-bearer-token` in a project
root, read by scripts as a fallback when an environment variable such as
`TYPESAFE_API_KEY` is not set.

End point: no plaintext files; scripts read only the environment variable;
the agent runs them through `cn run`.

This guide is for countersign Phase 1: every approval is a polkit dialog on
your desktop ([packaging/README.md](../packaging/README.md#approval-factors)).
Install countersign first and run the smoke test there. Phase 1 has not been
reviewed: do not move real secrets into it until it has.

## 1. Inventory

The agent can do this; none of it reads a value.

```console
$ ls -la .secret-*
$ git ls-files -- '.secret-*'                         # tracked: values are in git
$ git log --all --format='%h %ad %s' -- '.secret-*'   # ever committed
$ grep -rn --exclude-dir=.git -e '\.secret-' .        # which scripts read which file
```

Record, per file: which scripts read it, which environment variable they try
first, whether it was ever tracked, and its mode (0644 means every local user
could read it).

## 2. Draft the metadata

The agent drafts `countersign-import.toml` from what the scripts do. No
values go in this file.

```toml
[clickhouse-password]
description = "ClickHouse analytics, read-only user `reporter`"
usage = """
Read-only queries from scripts/clickhouse_*.py via CLICKHOUSE_PASSWORD.
Never write it into committed config or a URL. Production data: prefer the
sandbox service unless the task names production.
"""
projects = ["~/projects/moose/*"]
high_entropy = false

[typesafe-api-key]
description = "Typesafe API, production account"
usage = "Used by scripts/typesafe_*.py via TYPESAFE_API_KEY. Read-only calls unless the task says otherwise."
projects = ["~/projects/moose/*"]
high_entropy = true

[acurast-rpc-bearer-token]
description = "Bearer token for the Acurast RPC endpoint (mainnet)"
usage = "Only for scripts/acurast_*.py read calls via ACURAST_RPC_BEARER_TOKEN. Never log request headers."
projects = ["~/projects/moose/*"]
high_entropy = true
```

Review it yourself: usage prose steers every later agent session.

## 3. Import

You run the import. With `--metadata` it needs no prompt, so it also works as
a Claude Code `!` command; the approval is the countersign dialog, which lists
the names being added.

First look at what it would do; this creates no request:

```console
! /usr/bin/cn import --glob '.secret-*' --metadata countersign-import.toml --dry-run
NAME                      BYTES  WARNINGS        SOURCE
acurast-rpc-bearer-token  41     world-readable  /home/patrick/projects/moose/liskov-agent-orchestrator/.secret-acurast-rpc-bearer-token
clickhouse-password       24     world-readable  /home/patrick/projects/moose/liskov-agent-orchestrator/.secret-clickhouse-password
typesafe-api-key          40     world-readable  /home/patrick/projects/moose/liskov-agent-orchestrator/.secret-typesafe-api-key
```

Then import:

```console
! /usr/bin/cn import --glob '.secret-*' --metadata countersign-import.toml --shred --wait
cn: warning: /home/patrick/projects/moose/liskov-agent-orchestrator/.secret-clickhouse-password is world-readable; rotate clickhouse-password after importing
cn: warning: /home/patrick/projects/moose/liskov-agent-orchestrator/.secret-typesafe-api-key is world-readable; rotate typesafe-api-key after importing
cn: warning: /home/patrick/projects/moose/liskov-agent-orchestrator/.secret-acurast-rpc-bearer-token is world-readable; rotate acurast-rpc-bearer-token after importing
request W3J-9QA pending  mutate: import acurast-rpc-bearer-token clickhouse-password typesafe-api-key
digest  A71C-HH2P
approve a desktop dialog is open
expires 2026-11-08T09:40:02Z (5m)
imported 3 secrets; removed 3 source file(s)
```

Check that the dialog shows the same request code and digest, and
`IMPORT 3 secrets: ...` with the names you expect, before you approve. The
dialog closes after two minutes; if it does, run the import again. Delete
`countersign-import.toml` afterwards or keep it out of git; it holds no
values, but it is not useful once imported.

## 4. Change the scripts

Keep the environment variable the script already reads. Remove the file
fallback, and fail with a message that names the `cn run` command.

Python, before:

```python
def typesafe_api_key() -> str:
    value = os.environ.get("TYPESAFE_API_KEY")
    if value:
        return value
    path = Path(".secret-typesafe-api-key")
    if path.exists():
        return path.read_text().strip()
    sys.exit("set TYPESAFE_API_KEY or create .secret-typesafe-api-key")
```

After:

```python
def typesafe_api_key() -> str:
    value = os.environ.get("TYPESAFE_API_KEY")
    if value is None or value == "":
        sys.exit(
            "TYPESAFE_API_KEY is not set. Run this script under countersign:\n"
            "  cn run --use typesafe-api-key=TYPESAFE_API_KEY -- python3 "
            + " ".join(sys.argv)
        )
    return value
```

Shell:

```sh
: "${TYPESAFE_API_KEY:?run under: cn run --use typesafe-api-key=TYPESAFE_API_KEY -- $0}"
```

Invocation:

```console
$ cn run --use typesafe-api-key=TYPESAFE_API_KEY -- python3 scripts/typesafe_sync.py
$ cn run --use clickhouse-password=CLICKHOUSE_PASSWORD \
         --use acurast-rpc-bearer-token=ACURAST_RPC_BEARER_TOKEN \
         -- python3 scripts/acurast_usage_report.py
```

`--use typesafe-api-key` alone maps to `TYPESAFE_API_KEY` by the default
upper-snake rule; spell the variable out when the script reads a different
name.

A script can wrap itself so callers do not have to remember the flags:

```sh
#!/bin/sh
# scripts/typesafe-sync: re-exec under countersign when the key is missing.
if [ -z "${TYPESAFE_API_KEY:-}" ]; then
  exec cn run --use typesafe-api-key=TYPESAFE_API_KEY -- "$0" "$@"
fi
exec python3 "$(dirname "$0")/typesafe_sync.py" "$@"
```

Make or just targets do the same:

```make
typesafe-sync:
	cn run --use typesafe-api-key=TYPESAFE_API_KEY -- python3 scripts/typesafe_sync.py
```

Things to check in each script:

- It must not print the value, put it in a URL that gets logged, or write it
  to a file. `cn run` scrubs stdout and stderr, not files.
- It must not pass the value as an argument to another program; the child can
  read the variable itself.
- Test runners and CI that set the variable directly keep working: the script
  only reads the environment.

## 5. Tell the agents

- Paste [AGENTS.snippet.md](AGENTS.snippet.md) into the project's `AGENTS.md`
  (or `CLAUDE.md` if there is no `AGENTS.md`).
- For Claude Code, install the skill: copy
  [claude-code/skills/countersign/](claude-code/skills/countersign/) to
  `.claude/skills/countersign/` in the project, or to
  `~/.claude/skills/countersign/` for every project.
- Start agents under a session so the dialog names them:
  `cn session exec -- claude`.

## 6. Leave a tripwire

- Keep `.secret-*` in `.gitignore`.
- Optionally install the Claude Code guard hook from
  [docs/agent-integration.md](../docs/agent-integration.md#claude-code-hooks-defence-in-depth),
  which blocks any command that mentions `.secret-`.
- `cn doctor` reports leftover `.secret-*` files in the directory you run it
  from.

## 7. Rotate

Importing does not un-disclose anything. Rotate every value that was:

- ever in a file with mode 0644 on a multi-user machine;
- ever committed (`git log --all` above);
- ever read into an agent transcript. Claude Code keeps transcripts under
  `~/.claude/projects/`; other agents keep their own logs. To check whether a
  value appears in them without displaying it, run, in a terminal:

  ```console
  $ cat ~/.claude/projects/*/*.jsonl | cn hide --stats > /dev/null
  cn hide: 48213021 bytes in, 48212998 out, hits: typesafe-api-key=4
  ```

  From a terminal outside any agent session this matches only secrets
  marked high-entropy. To check a low-entropy one such as
  `clickhouse-password`, run it inside a session that holds a use grant for
  it.

`--from-file` on `cn add` and `cn set` (with `--wait`), and
`cn import --shred`, overwrite and unlink, which does not erase data on btrfs (copy-on-write, and snapshots), on
SSDs, or in backups. Check whether snapper or a backup tool captures the
project directory. Treat the old values as disclosed and rotate, approving
each change in the dialog:

```console
$ /usr/bin/cn set typesafe-api-key --from-clipboard --wait
```
