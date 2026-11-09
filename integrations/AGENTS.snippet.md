## Secrets (countersign)

Credentials for this project are held by countersign (`cn`). Use them only
through `cn`.

- Never read, print, copy, grep or source `.secret-*` files, `.env` files with
  credentials, or anything under `/var/lib/countersign`. If you find a
  plaintext secret file, tell the human and do not open it.
- Never ask the human to paste a secret value into the chat. If a credential
  is missing, say which one and ask them to add it with `/usr/bin/cn add`.
- Run `cn list` first, and `cn show NAME` to read a secret's usage notes.
  Follow those notes.
- To use a secret, request it with a specific reason and the shortest TTL that
  does the job:
  `cn request NAME --reason "<what you will run and why>" --ttl 30m --wait 100s`
- Then tell the human the request code and digest, and ask them to approve
  the countersign dialog on their desktop after checking it shows the same
  code and digest. Never run `cn approve` yourself.
- Run commands with the secret injected:
  `cn run --use NAME[=ENVVAR] -- <command>`. Never put a value in a command
  argument, a file, `export`, or a commit.
- Pipe any output that might contain a secret through `| cn hide`: logs,
  `env`, config dumps, verbose HTTP output, and files a `cn run` command wrote.
- Never run `cn reveal` unless the human has asked for the raw value in this
  conversation.
- Never run `cn add`, `set`, `edit`, `rm`, `import` or `export`. Ask the
  human. You may draft descriptions and usage text for them.
- Exit 4 (no grant) or 7 (expired): request again. Exit 6 (still pending):
  ask the human to approve, then check `cn grants`. Exit 5 (denied): stop and
  ask the human; do not look for another way to get the value.
- Use `--json` when you parse `cn` output. Run `cn revoke --all` when the task
  is done.
