# Agent integration

How coding agents (Claude Code, Codex, Grok and others) use countersign, what
to put in a project's agent instructions, optional Claude Code hooks, and how
to move a project off plaintext `.secret-*` files.

The commands are specified in [cli.md](cli.md). What these measures do and do
not protect against is in [threat-model.md](threat-model.md); the short
version is at the end of this document.

## The flow

```text
agent                                   human                       cnd
-----                                   -----                       ---
cn list / cn show NAME          ─────────────────────────────────►  names, prose, grants
cn request NAME --reason ... --wait ──────────────────────────────►  pending K7M-Q2X
  tells the human the code      ──► polkit dialog: touch key   ──►  approved, grant g_…
                                    or: ! /usr/bin/cn approve K7M-Q2X
cn run --use NAME -- cmd        ─────────────────────────────────►  values issued, use.start
  output scrubbed by cn run
other output | cn hide          ─────────────────────────────────►  scrubbed in cnd
cn revoke --all (when done)     ─────────────────────────────────►  revoked
```

In this flow the agent never reads a value. It sees names, descriptions and usage prose,
asks for a grant with a reason, and runs commands that receive the value in
their environment.

## Start the agent under a session

Grants belong to a session, identified by `cnd` from the process tree. Start
the agent with the launcher so the session is explicit and named:

```console
$ cn session exec --label orchestrator -- claude
```

A shell alias makes it the default:

```sh
alias claude='cn session exec -- claude'
```

Without the launcher, `cnd` finds the anchor by matching configured process
names (`claude`, `codex`, `grok`). That works, but the launcher works for any
agent, names the session in the approval dialog, and is the only anchor the
human explicitly chose.

## Snippet for AGENTS.md / CLAUDE.md

Paste this into the project's agent instructions. It is short on purpose:
agents follow short imperative rules better than explanations.

````markdown
## Secrets (countersign)

Credentials for this project are held by countersign (`cn`). Use them only
through `cn`.

- Never read, print, copy, grep or source `.secret-*` files, `.env` files with
  credentials, or anything under `/var/lib/countersign`. If you find a
  plaintext secret file, tell the human and do not open it.
- Run `cn list` first, and `cn show NAME` to read a secret's usage notes.
  Follow those notes.
- To use a secret, request it with a specific reason and the shortest TTL that
  does the job:
  `cn request NAME --reason "<what you will run and why>" --ttl 30m --wait 100s`
- Then tell the human the request code and digest and ask them to approve the
  desktop dialog, or to type exactly: `! /usr/bin/cn approve <CODE>`.
  Never run `cn approve` yourself.
- Run commands with the secret injected:
  `cn run --use NAME[=ENVVAR] -- <command>`. Never put a value in a command
  argument, a file, `export`, or a commit.
- Pipe any output that might contain a secret through `| cn hide`: logs,
  `env`, config dumps, verbose HTTP output, and files a `cn run` command wrote.
- Never run `cn reveal` unless the human has asked for the raw value in this
  conversation.
- Never run `cn add`, `set`, `edit`, `rm`, `import`, `export`, `unlock` or
  `approver`. Ask the human. You may draft descriptions and usage text for
  them.
- Exit 4 (no grant) or 7 (expired): request again. Exit 5 (denied): stop and
  ask the human; do not look for another way to get the value.
- Use `--json` when you parse `cn` output. Run `cn revoke --all` when the task
  is done.
````

The snippet works for any agent that reads `AGENTS.md` or `CLAUDE.md`. In a
repository whose `CLAUDE.md` imports `AGENTS.md`, put it in `AGENTS.md` only.

## Claude Code skill (sketch)

A skill carries the longer procedure, so the always-loaded snippet can stay
short. Install as `.claude/skills/countersign/SKILL.md` in the project, or
under `~/.claude/skills/` for every project.

````markdown
---
name: countersign
description: Use when a task needs an API key, password, token, DSN or other
  credential, when a command fails for lack of one, or when you are about to
  read a .secret-* or .env file. Covers listing secrets, requesting a grant,
  getting human approval, running commands with secrets injected, and
  scrubbing output.
---

# Using secrets through countersign

## Steps

1. `cn list --json`. Pick the secret whose description and usage fit the
   task. If none fits, stop and tell the human what credential is missing;
   suggest a name, description and usage text they could add with `cn add`.
2. `cn show NAME`. Read the usage prose and follow it. If it says to prefer a
   sandbox secret, use that one unless the task names production.
3. Check for an existing grant: `cn grants --json`. If one covers the secret,
   go to step 6.
4. `cn request NAME --reason "<command you will run> to <purpose>" --ttl 30m --wait 100s --json`.
   - Request only the secrets the next commands need. Ask for `--mode reveal`
     only when the human asked to see the value.
   - The reason is shown to the human as yours. Be specific: name the script
     and what it does with the secret.
5. If the result is `pending` (exit 6) or `approvers` lists a client-driven
   approver, tell the human, in one line:
   "Please approve countersign request K7M-Q2X (digest 3QF8-ZK2M): touch the
   key in the desktop dialog, or run `! /usr/bin/cn approve K7M-Q2X`."
   Then wait for the human to reply, and confirm with `cn grants --json`.
6. Run: `cn run --use NAME[=ENVVAR] -- <command>`. Use the variable name the
   program already reads. Several secrets: repeat `--use`.
7. If you read anything else that might contain the value (log files the
   command wrote, `docker compose config`, `env`), pipe it through `| cn hide`.
8. When finished: `cn revoke --all`.

## Exit codes

| Exit | Do |
| --- | --- |
| 4 `grant_required` | Go to step 4. |
| 5 `denied` | Stop. Ask the human what they want instead. |
| 6 `pending` | Ask the human to approve (step 5). |
| 7 `request_expired` | Request again. |
| 8 `unknown_secret` | `cn list --all`; the name may be scoped to another project. |
| 11 `no_session` | Tell the human; they should start you with `cn session exec`. |
| 12 `store_sealed` | Ask the human to run `/usr/bin/cn unlock`. |
| 125 from `cn run` | `cn` failed before running the command; read the error code on stderr. |

## Never

- Read `.secret-*` files or `/proc/*/environ`.
- Run `cn approve`, `cn add/set/edit/rm/import/export`, `cn unlock`.
- Put a value on a command line, in a file, or in a commit.
- Work around a denial.
````

## Claude Code hooks (defence in depth)

The rules above are instructions, and an agent that has been prompt-injected
may not follow them. Claude Code can enforce some of them mechanically with
permission rules and hooks.

**These are not a security boundary.** The agent runs as your uid and can edit
`.claude/settings.json`, `~/.claude/settings.json` and the hook scripts, or
reach the same file or command through an indirection a pattern does not
catch (`sh -c`, a script it writes, `python3 -c "open('.secret-x')"`). The
boundary is `cnd` and the approvers. Hooks catch the careless and the
confused, which is most of the risk in practice, and they make a deliberate
violation visible in the transcript.

### Permission rules

The simplest layer. In `.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(**/.secret-*)",
      "Edit(**/.secret-*)",
      "Bash(cn approve:*)",
      "Bash(/usr/bin/cn approve:*)",
      "Bash(cn add:*)",
      "Bash(cn set:*)",
      "Bash(cn edit:*)",
      "Bash(cn rm:*)",
      "Bash(cn import:*)",
      "Bash(cn export:*)",
      "Bash(cn unlock:*)",
      "Bash(cn approver:*)"
    ],
    "ask": [
      "Bash(cn reveal:*)"
    ]
  }
}
```

Bash rules match command prefixes, so `cat .secret-foo` or
`cd x && cn approve ...` slips past them. The hook below inspects the whole
command.

### PreToolUse guard

`.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Grep|Glob|Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/countersign-guard.sh"
          }
        ]
      }
    ]
  }
}
```

`.claude/hooks/countersign-guard.sh` (executable):

```bash
#!/usr/bin/env bash
# countersign guard: blocks the obvious ways an agent leaks or self-approves.
# Defence in depth only; see docs/agent-integration.md.
set -euo pipefail

input=$(cat)
tool=$(jq -r '.tool_name // ""' <<<"$input")

deny() {
  # Exit 2 blocks the tool call; stderr is shown to the agent.
  printf 'countersign guard: %s\n' "$1" >&2
  exit 2
}

case "$tool" in
  Bash)
    cmd=$(jq -r '.tool_input.command // ""' <<<"$input")

    # Plaintext secret files, in any position in the command.
    if grep -Eq '(^|[^[:alnum:]_.-])\.secret-[[:alnum:]_.-]+' <<<"$cmd"; then
      deny "do not touch .secret-* files. Use 'cn list', then 'cn run --use NAME -- <command>'."
    fi

    # Approvals and store changes are for the human.
    if grep -Eq '(^|[[:space:];&|(/])cn[[:space:]]+(approve|add|set|edit|rm|import|export|unlock|approver)([[:space:]]|$)' <<<"$cmd"; then
      deny "approvals and store changes are for the human. Ask them to run: ! /usr/bin/cn approve <CODE>"
    fi

    # Reading other processes' environments or the daemon's state.
    if grep -Eq '/proc/[^[:space:]]*/environ|/var/lib/countersign' <<<"$cmd"; then
      deny "do not read process environments or countersign state."
    fi

    # Commands that commonly print credentials: require a final '| cn hide'.
    if grep -Eq '(^|[[:space:];&|])(env|printenv|docker[[:space:]]+(inspect|compose[[:space:]]+config)|kubectl[[:space:]]+get[[:space:]]+secret|curl[[:space:]].*(-v|--verbose))([[:space:]]|$)' <<<"$cmd" \
       && ! grep -Eq '\|[[:space:]]*cn[[:space:]]+hide[[:space:]]*$' <<<"$cmd"; then
      deny "this command may print secrets. Re-run it with '| cn hide' at the end."
    fi
    ;;

  Read|Grep|Glob|Edit|Write)
    path=$(jq -r '.tool_input.file_path // .tool_input.path // .tool_input.pattern // ""' <<<"$input")
    case "$path" in
      *.secret-*|*/var/lib/countersign*)
        deny "do not open secret files. Use 'cn list' and 'cn run'." ;;
    esac
    ;;
esac

exit 0
```

Notes:

- The guard blocks the agent's tool calls only. A `!` command typed by the
  human is not a tool call, so `! /usr/bin/cn approve K7M-Q2X` still works.
- The `| cn hide` rule is a reminder implemented as a block: the agent sees
  the message and re-runs the command with the pipe. Extend the pattern list
  with the project's own noisy commands.
- Keep the patterns simple. Every pattern can be evaded; the aim is to stop
  accidents, not to win an arms race.

### Other agents

Codex and Grok read `AGENTS.md`, so the snippet applies unchanged. Their hook
and permission mechanisms differ; the same rules (block `.secret-*`, block
`cn approve` and store changes, require `| cn hide` on noisy commands) carry
over where the tool supports pre-execution checks.

## Migrating from `.secret-*` files

Starting point: files such as `.secret-clickhouse-password`,
`.secret-typesafe-api-key` and `.secret-acurast-rpc-bearer-token` in a project
root, read by scripts as a fallback when an environment variable such as
`TYPESAFE_API_KEY` is not set.

End point: no plaintext files; scripts read only the environment variable;
the agent runs them through `cn run`.

### 1. Inventory

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

### 2. Draft the metadata

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

The human reviews it: usage prose steers every later agent session.

### 3. Import

The human runs the import. It needs no prompt, so it works as a `!` command:

```console
! /usr/bin/cn import --glob '.secret-*' --metadata countersign-import.toml --shred --wait
importing 3 secrets from /home/patrick/projects/moose/liskov-agent-orchestrator
  clickhouse-password        from .secret-clickhouse-password        (0644, never tracked)
  typesafe-api-key           from .secret-typesafe-api-key           (0644, never tracked)
  acurast-rpc-bearer-token   from .secret-acurast-rpc-bearer-token   (0644, never tracked)
request W3J-9QA pending  mutate: add 3 secrets
digest  A71C-HH2P
approve a desktop dialog is open
added 3 secrets; shredded 3 files
```

The approval dialog lists the names being added. Delete
`countersign-import.toml` afterwards or keep it out of git; it holds no values
but it is not useful once imported.

### 4. Change the scripts

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

### 5. Leave a tripwire

- Keep `.secret-*` in `.gitignore`.
- Add the snippet above to the project's `AGENTS.md`.
- Optionally install the hook, which blocks any command mentioning
  `.secret-`.
- `cn doctor` reports leftover `.secret-*` files and placeholder descriptions.

### 6. Rotate

Importing does not un-disclose anything. Rotate every value that was:

- ever in a file with mode 0644 on a multi-user machine;
- ever committed (`git log --all` above);
- ever read into an agent transcript. Claude Code keeps transcripts under
  `~/.claude/projects/`; other agents keep their own logs. To check whether a
  value appears in them without displaying it, the human can run, in a
  terminal:

  ```console
  $ cat ~/.claude/projects/*/*.jsonl | cn hide --stats > /dev/null
  hits: typesafe-api-key 4
  ```

  This only matches high-entropy secrets and secrets granted to the current
  session (to check `clickhouse-password`, request a use grant for it first).

`--from-file` on `cn add` and `cn set`, and `cn import --shred`, overwrite and unlink, which does
not erase data on btrfs (copy-on-write, and snapshots), on SSDs, or in
backups. Check whether snapper or a backup tool captures the project
directory. Treat the old values as disclosed and rotate:

```console
$ /usr/bin/cn set typesafe-api-key --from-clipboard --wait
```

## What this does and does not protect

With the snippet, the hooks and the migration done, countersign stops the
common failures: an agent running `cat` on a secret file, a verbose command
printing a key into the transcript, a value committed to git, a secret used
without the human knowing, and a plaintext file readable by any local user.

It does not stop an agent that sets out to steal a secret while it holds a
grant: a process running as your uid can read the environment of the
`cn run` child, or ask `cnd` for the value directly (threat model T6, T7). Containing that needs the agent in a sandbox or under a
separate uid, with only the `cnd` socket exposed (tier 2 in the threat
model), and later the egress proxy, where the value never enters your uid.

## Open questions

1. **Does `!` bypass PreToolUse hooks?** This document assumes a `!` command
   is not a tool call and so is not blocked by the guard. That matches current
   Claude Code behaviour as understood, but should be checked against the
   current release; if hooks do apply, the guard must allow
   `/usr/bin/cn approve`.
2. **`--wait` length.** The snippet uses `--wait 100s` to stay under Claude
   Code's default Bash tool timeout (about two minutes). A human who takes
   longer leaves the agent with exit 6 and a follow-up `cn grants` call. Is
   that acceptable, or should `cn request` learn a "wait for approval, then
   print the grant" mode tuned for agent harnesses?
3. **Hook distribution.** Ship the hook script and settings fragment with the
   package (e.g. `/usr/share/countersign/claude/`) and have `cn doctor`
   offer to install them, or leave it to documentation?
4. **Skill location.** A user-level skill (`~/.claude/skills/countersign`)
   covers every project; a project-level one can carry project-specific
   usage. Recommend one, or both?
5. **Transcript scanning.** The rotation step uses `cn hide --stats` as a
   scanner. That is the same oracle `cn hide` already is, limited to
   high-entropy and granted secrets. A dedicated `cn scan PATH...` command
   with clearer output may be worth adding.
6. **Codex and Grok specifics.** Their hook and permission mechanisms, and
   their process names for anchor matching, need checking and examples.
