# Agent integration

How coding agents (Claude Code, Codex, Grok and others) use countersign, what
to put in a project's agent instructions, optional Claude Code hooks, and how
to move a project off plaintext `.secret-*` files. The files to install live
in [`integrations/`](../integrations/); this document explains them.

The commands are specified in [cli.md](cli.md). What these measures do and do
not protect against is in [threat-model.md](threat-model.md); the short
version is at the end of this document.

## The flow

```text
agent                                   human                       cnd
-----                                   -----                       ---
cn list / cn show NAME          ─────────────────────────────────►  names, prose, grants
cn request NAME --reason ... --wait ──────────────────────────────►  pending K7M-Q2X
  tells the human the code      ──► polkit dialog: checks code ──►  approved, grant g_…
                                    and digest, touches the key
                                    or types the password
cn run --use NAME -- cmd        ─────────────────────────────────►  values issued, use.start
  output scrubbed by cn run
other output | cn hide          ─────────────────────────────────►  scrubbed in cnd
cn revoke --all (when done)     ─────────────────────────────────►  revoked
```

In this flow the agent never reads a value. It sees names, descriptions and usage prose,
asks for a grant with a reason, and runs commands that receive the value in
their environment.

In Phase 1 the only approver is polkit (decision 14), so every approval
happens in the desktop dialog that `cnd` raises. `cn approve CODE` only shows
the pending request, so the human can cross-check it against the dialog, and
waits for the answer. The client-driven path (`! /usr/bin/cn approve CODE`
with a FIDO2 touch) comes with the `fido2` approver in Phase 2.

The dialog stays open until the request lapses (`[grants] pending_expiry`,
5 minutes). A request nobody answers then expires (exit 7), and there is no
way to raise its dialog again: the agent requests again. At most two dialogs
are open at once for a uid; a further request waits its turn, and its expiry
still counts from when it was made. When `cnd` cannot show a dialog at all
(no graphical session, not Wayland, polkitd not running), the request ends
at once with `approver_unavailable` (exit 14) and the reason in the message,
and the agent should tell the human.

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

[`integrations/AGENTS.snippet.md`](../integrations/AGENTS.snippet.md) is the
text to paste into a project's agent instructions. It is short on purpose:
agents follow short imperative rules better than explanations. It tells the
agent to list and read usage notes first, to request with a specific reason
and a short TTL, to have the human approve the dialog after comparing the
code and digest, to run commands through `cn run` and pipe other output
through `cn hide`, never to open `.secret-*` files, never to ask the human to
paste a value into the chat, and what to do on each exit code.

The snippet works for any agent that reads `AGENTS.md` or `CLAUDE.md`. In a
repository whose `CLAUDE.md` imports `AGENTS.md`, put it in `AGENTS.md` only.

## Claude Code skill

A skill carries the longer procedure, so the always-loaded snippet can stay
short: [`integrations/claude-code/skills/countersign/SKILL.md`](../integrations/claude-code/skills/countersign/SKILL.md).
Its description makes Claude Code load it when a task mentions secrets,
credentials, API keys, tokens or `.secret-*` files. It walks through `cn list`,
`cn show`, `cn request --wait`, the message to the human, `cn run`, `cn hide`
and `cn revoke`, shows what the approval dialog looks like to the human, and
lists what never to do.

Install it in the project as `.claude/skills/countersign/SKILL.md`, or under
`~/.claude/skills/countersign/` for every project:

```console
$ mkdir -p ~/.claude/skills/countersign
$ cp integrations/claude-code/skills/countersign/SKILL.md ~/.claude/skills/countersign/
```

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
      deny "approvals and store changes are for the human. Ask them to approve the countersign dialog."
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
  human is not a tool call, so `! /usr/bin/cn import ...` still works.
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

The step-by-step guide is
[`integrations/migrating-from-secret-files.md`](../integrations/migrating-from-secret-files.md):
inventory the files and the scripts that read them, draft a metadata file
(no values), import with one approved `cn import`, change the scripts to read
only the environment variable and run them through `cn run`, add the snippet
and the skill, leave a tripwire, and rotate every value that was ever
readable.

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
   current release; if hooks do apply, the guard must allow the human's
   `/usr/bin/cn import` and other store commands (and, in Phase 2,
   `/usr/bin/cn approve`).
2. **`--wait` length.** The snippet uses `--wait 100s` to stay under Claude
   Code's default Bash tool timeout (about two minutes). The dialog stays
   open for the request's 5 minutes, so a human who takes longer than 100
   seconds leaves the agent with exit 6 and a follow-up `cn grants` call.
   Is that acceptable, or
   should `cn request` learn a "wait for approval, then print the grant" mode
   tuned for agent harnesses?
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
