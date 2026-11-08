# countersign

A local secret manager built for coding agents. The agent can see which secrets
exist and what they are for, ask to use them, and run commands with them. You
approve each request with a YubiKey touch on a desktop prompt. Values are kept
out of the agent's context and transcript (against careless and confused
agents, not a deliberately malicious one; see below), and every use lands in
an audit log the agent cannot change.

CLI `cn`, daemon `cnd`. Rust, Linux first. Apache-2.0.

> **Status: design phase.** The documents under [`docs/`](docs/) are the spec.
> The streaming redaction engine (`crates/countersign-hide`) is implemented and
> tested; nothing else works yet. Do not store real secrets in it.

## The problem

Agents need credentials: a database password, an API key, a bearer token. The
common answer is a plaintext file in the project root (`.secret-db-password`)
or a `.env`. Those files are readable by the agent's user, often by every
user, and nothing records who read them. When an agent runs `cat` on one, or a
command echoes a key in an error message, the value is in the model transcript
for good.

## How it works

```console
$ cn list
NAME                 GRANT  DESCRIPTION
clickhouse-password  -      ClickHouse Cloud admin password (production)
typesafe-api-key     -      Typesafe shaping API, sandbox account

$ cn show clickhouse-password
name          clickhouse-password
...
usage
  Read-only queries from scripts/clickhouse_*.py. Never write it into
  committed config. Prefer the sandbox service unless the task names prod.

$ cn request clickhouse-password --ttl 30m --reason "row counts for the cost report"
request K7M-Q2X pending  use clickhouse-password for 30m
digest  3QF8-ZK2M
approve a desktop dialog is open
expires 2026-11-08T09:25:11Z (5m)

# the human checks K7M-Q2X / 3QF8-ZK2M in the GNOME dialog and touches the YubiKey

$ cn run --use clickhouse-password=CLICKHOUSE_PASSWORD -- python3 scripts/clickhouse_rows.py
...output, with any echoed value replaced by [countersign:clickhouse-password]...

$ some-verbose-command | cn hide
```

- **Use, don't read.** `cn run` puts values into the child process's
  environment and scrubs them from its output. Reading a raw value
  (`cn reveal`) is a separate grant mode and loudly audited.
- **Approval the agent cannot fake.** An agent can type `cn approve` as easily
  as you can. It cannot touch your YubiKey or answer a polkit dialog drawn by
  your desktop on Wayland. Approvers are adapters chosen in config.
- **Grants belong to one agent session** and expire. The daemon identifies
  the session from the kernel's view of the calling process's ancestry, not
  from environment variables or anything else the agent reports.
- **Secrets carry prose.** Each has a description and usage notes telling the
  agent how it is meant to be used in this project.
- **The daemon runs as its own user**, so the agent cannot read the store or
  edit the audit log.

## What it does not protect against

Read [docs/threat-model.md](docs/threat-model.md) before relying on it. In
short: countersign stops accidental leakage, unconsented use, plaintext at rest
and silent use. A deliberately malicious agent running as your user can still
obtain a value it holds a live grant for: from the environment of a process it
started, or by asking `cnd` for it directly.
Containing that needs the agent in a sandbox or under a separate user.

## Documents

| Doc | What it covers |
| --- | --- |
| [threat-model.md](docs/threat-model.md) | What is defended, what is not, and why |
| [design.md](docs/design.md) | Daemon, store, sessions, grants, IPC, `run`, `hide` |
| [approvers.md](docs/approvers.md) | Approver adapters: FIDO2/YubiKey, polkit, command |
| [audit.md](docs/audit.md) | Audit log format, hash chain, verification |
| [cli.md](docs/cli.md) | `cn` command reference |
| [agent-integration.md](docs/agent-integration.md) | Instructions for agents, hooks, migrating from `.secret-*` files |
| [prior-art.md](docs/prior-art.md) | Related tools and how countersign differs |
| [decisions.md](docs/decisions.md) | Decisions agreed so far |
| [roadmap.md](docs/roadmap.md) | What gets built in which order |

## Building

```sh
cargo test --all-targets
```

## License

Apache-2.0. Contributions need a DCO sign-off (`git commit -s`); see
[CONTRIBUTING.md](CONTRIBUTING.md).
