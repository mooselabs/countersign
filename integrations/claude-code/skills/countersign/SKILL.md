---
name: countersign
description: Use whenever a task needs a secret, credential, password, API key, token, DSN or private key; when a command fails for a missing or invalid credential; and before you read a .secret-* file, a .env file, or anything else that may hold a credential. Covers finding the right secret with cn list and cn show, requesting a grant, how the human approves it, running commands with the secret injected (cn run), and scrubbing output (cn hide).
---

# Using secrets through countersign

countersign (`cn`, daemon `cnd`) holds this machine's credentials. You never
see a value: you ask for a grant, the human approves it in a desktop dialog,
and `cn run` puts the value into the environment of the command you run.

## Steps

1. **Find the secret.** `cn list --json`. Pick the one whose description and
   usage fit the task. If none fits, stop and tell the human which credential
   is missing. Suggest a name, a one-line description and usage text they
   could add with `/usr/bin/cn add`. Do not ask them to paste the value into
   the chat.
2. **Read its usage notes.** `cn show NAME`. Follow them. If they say to
   prefer a sandbox secret, use that one unless the task names production.
3. **Check for a grant.** `cn grants --json`. If one covers the secret, go to
   step 6.
4. **Request it.**

   ```sh
   cn request NAME --reason "<command you will run> to <purpose>" --ttl 30m --wait 100s --json
   ```

   - Request only the secrets the next commands need, with the shortest TTL
     that does the job.
   - The reason is shown to the human, labelled as yours. Name the script and
     what it does with the secret.
   - Ask for `--mode reveal` only when the human asked to see the value.
   - `--wait 100s` stays under the Bash tool's two-minute timeout.
5. **Ask the human, in one line**, with the code and digest from the output:
   "Please approve countersign request K7M-Q2X (digest 3QF8-ZK2M) in the
   desktop dialog." If the request is still pending (exit 6), wait for their
   reply, then check `cn grants --json`.
6. **Run the command with the secret injected.**

   ```sh
   cn run --use NAME -- <command>                 # as NAME in upper snake case
   cn run --use NAME=ENVVAR -- <command>          # as the variable the program reads
   ```

   Repeat `--use` for several secrets. `cn run` scrubs the command's stdout
   and stderr. It does not scrub files the command writes.
7. **Scrub everything else.** Pipe any other output that might contain a
   value through `| cn hide`: log files the command wrote, `env`, `docker
   compose config`, verbose HTTP output.
8. **When done:** `cn revoke --all`.

## How approval looks to the human

`cnd` raises the dialog itself as soon as you request; the human does not
type anything in the chat to approve. GNOME shows, for example:

```text
Authentication Required
countersign request K7M-Q2X, digest 3QF8-ZK2M: USE clickhouse-password for 30m.
agent claude (pid 41210) in ~/projects/x. Agent's reason: row counts for the cost report
```

They compare the code and digest with your message, then touch their
security key or type their password, depending on how countersign was
installed. Cancel denies the request (exit 5). If they do nothing, the
dialog closes after two minutes and the request expires (exit 7 when you
were waiting); it cannot be raised again, so request again if still needed.

If `cnd` cannot show a dialog at all (no graphical session, not Wayland,
polkit not running), the request ends at once, denied by `cnd`, with the
reason in the message (exit 5). Tell the human the reason.

`cn approve CODE` only shows the request for cross-checking and waits for
the dialog's answer; approving happens in the dialog. Do not run it
yourself.

## Exit codes

| Exit | Meaning | Do |
| --- | --- | --- |
| 4 | `grant_required` | Go to step 4. |
| 5 | `denied` | Stop. Tell the human, with the message (a denial by `cnd` says why no dialog could be shown). Do not look for another way to get the value. |
| 6 | `pending` | Ask the human to approve (step 5). |
| 7 | `request_expired` | Request again if still needed. |
| 8 | `unknown_secret` | `cn list --all`; it may be scoped to another project. |
| 10 | `rate_limited` | Too many pending or recent requests, or the same secrets were denied a moment ago. Wait, and ask the human. |
| 11 | `no_session` | Tell the human; they should start you with `cn session exec -- claude`. |
| 125 from `cn run` | `cn` failed before running the command | Read the error code on stderr. |

## Never

- Read, cat, grep, source or copy `.secret-*` files, credential `.env` files,
  `/var/lib/countersign`, or `/proc/*/environ`.
- Ask the human to paste a secret value into the chat, or paste one yourself.
- Run `cn approve`, or `cn add`, `set`, `edit`, `rm`, `import`, `export`.
  Those are for the human; you may draft descriptions and usage text.
- Put a value in a file, in `export`, in a commit, or in a command line you
  type. If a program takes the value only as an argument, let the child
  expand it, so it stays out of the transcript:
  `cn run --use X -- sh -c 'tool --password "$X"'`.
- Work around a denial.
