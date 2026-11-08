# Decisions

Decisions the owner has agreed, newest last. A decision changes only by adding
a new entry that says which one it replaces.

| # | Date | Decision | Why |
| --- | --- | --- | --- |
| 1 | 2026-11-08 | Build a local, agent-first secret manager to replace plaintext `./.secret-*` files in project roots. | The files are plaintext, often world-readable, owned by the agent's uid, and unaudited; one `cat` puts a key into a model transcript permanently. |
| 2 | 2026-11-08 | Agents **use** secrets (`cn run` injects them into a child process) rather than read them. Revealing a value is a separate, rarer grant mode. | A value that enters model context cannot be recalled by any TTL. |
| 3 | 2026-11-08 | Ship `cn hide` as a final pipe that scrubs secret values from any output. | Commands echo credentials (verbose clients, error messages, env dumps); scrubbing at the end of the pipe catches what injection cannot. |
| 4 | 2026-11-08 | Approval requires a channel the agent cannot drive. Approvers are pluggable adapters chosen in config. First adapters: YubiKey (FIDO2) and a polkit desktop prompt. | `!` commands in Claude Code run as the agent's uid with its environment and no TTY, so the agent can type them too. Physical presence or a trusted display is the boundary. |
| 5 | 2026-11-08 | A small daemon (`cnd`) running as its own system user, plus a CLI (`cn`). | Only a different uid keeps the store and the audit log out of the agent's reach. |
| 6 | 2026-11-08 | Each secret carries a one-line description and a usage prose block. Hard limits (allowed executables, hosts) are optional and later. | Prose guidance gets most of the value for a solo developer; enforcement can follow. |
| 7 | 2026-11-08 | Audit log is append-only, hash-chained, owned by the daemon user; the agent may read it but not alter it. | Consent is only meaningful if its use can be checked afterwards. |
| 8 | 2026-11-08 | Local and solo-developer friendly first. Proxying third-party vaults and a credential-injecting egress proxy are a possible commercial direction later, not v1. | Prove the local tool before building a service. |
| 9 | 2026-11-08 | Name **countersign**; CLI `cn`, daemon `cnd`. | A human countersigns each grant. `sk` collides with skim and `cs` with Coursier and csound; no common package ships `cn` or `cnd`. |
| 10 | 2026-11-08 | License Apache-2.0 with DCO sign-off, no CLA. | Enterprise-friendly (the eventual commercial audience often bans AGPL), carries a patent grant, and still allows a separate closed commercial layer. |
| 11 | 2026-11-08 | Rust; Linux first (systemd, polkit, SO_PEERCRED, /proc); macOS later. | The owner's machines are Linux; the session-binding mechanisms are platform-specific. |
| 12 | 2026-11-08 | Repository `github.com/mooselabs/countersign`. | Owner's choice. |

## Proposed, awaiting the owner

Defaults the design documents now assume. They become decisions when the owner
agrees, or change if not.

| # | Proposal | Why |
| --- | --- | --- |
| P1 | Default approver chain: `use` = polkit backed by `pam_u2f` (GNOME dialog + YubiKey touch); `reveal`, store mutations and export = all of polkit and FIDO2. No `any_of` in defaults. | `cnd` cannot reach the user's session bus, so it cannot draw its own notification; FIDO2 alone leaves the agent-alterable terminal as the only display. `any_of` is only as strong as its weakest member. See [approvers.md](approvers.md). |
| P2 | Enrolled FIDO2 credentials live in root-owned `/etc/countersign/approvers.d/`; only signature counters under `/var/lib/countersign/`. | An agent must not be able to enrol its own approver. |
| P3 | `cnd` checks polkit against the user's logind session (`unix-session`), never the requesting process. | With a process subject the agent can register its own authentication agent and draw the prompt. |
| P4 | `pam_u2f` as `sufficient` (password fallback when the key is absent) or as required. Open. | Required is stronger but changes every polkit prompt on the machine. |
