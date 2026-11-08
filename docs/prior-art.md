# Prior art

Survey date: 2026-11-08. Covers tools that keep secrets away from AI coding
agents, and the general developer secret tools countersign would otherwise be
compared with. Every claim below comes from the project's own README or docs
(linked under Sources) unless it is marked **unverified**. Star counts and
last-push dates come from the GitHub API on the survey date. A last push is
not the same as a release; read "activity" as "is anyone still committing".

The question this document answers: does something already do what
countersign proposes? The proposal is: per-agent-session grants with a TTL,
bound by process ancestry; approval through a channel the agent cannot drive
(FIDO2 touch, polkit dialog) through pluggable adapters; "use, don't read"
injection (`cn run`) plus an output scrubber (`cn hide`); description and
usage prose per secret, written for the agent; and an audit log owned by a
separate daemon uid.

Short answer: each of those pieces exists somewhere. No project surveyed
combines them, and two of them (process-ancestry session binding, and a local
audit log the agent's uid cannot alter) do not appear in any local tool
surveyed. The closest projects are fnox, mrz1836/hush, and the 1Password CLI.
The strongest competing *approach* is not a secret manager at all: HTTP proxy
injection in an agent sandbox (Claude Code's sandbox `mask` mode, Docker
Sandboxes, Infisical Agent Vault, nono), where the secret never enters the
agent's uid.

## Comparison

Column notes:

- **Agent-aware**: built for, or has features specifically for, AI agents.
- **Approval channel**: how a human consents to a use, and whether the agent
  could drive that channel itself.
- **Session TTL grants**: a time-limited grant tied to one agent session.
- **Injection vs reveal**: `inject` = value goes into a child process env or
  file; `proxy` = value is added to outbound HTTP by a separate process and
  never reaches the agent's process; `reveal` = value can be printed.
- **Scrub**: removes secret values from command output.
- **Tamper-resistant audit**: an audit log the agent cannot quietly edit.

### Agent-specific tools (2025-2026)

| Project | What it is | Agent-aware | Approval channel | Session TTL grants | Injection vs reveal | Scrub | Tamper-resistant audit | License | Activity (Nov 2026) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [fnox](https://github.com/jdx/fnox) (jdx) | Multi-provider secret manager (age, FIDO2/YubiKey, cloud SMs, password managers) with an MCP server, credential proxy and leases | Yes (MCP server, proxy, `--sandbox`) | None per use; YubiKey/FIDO2 touch when a lease's bootstrap credential is decrypted; secret entry via a localhost page | Values held for the MCP session, gone on disconnect; leases are short-lived backend credentials (STS etc.) | inject (`exec`), proxy (`fnox proxy run`), reveal (`get_secret` unless proxy mode) | Yes, `[REDACTED]`, literal values only | No: JSONL, 0600, owned by the user; docs say any same-user process can edit it | MIT | Very active; 2.4k stars; pushed 2026-11-08 |
| [mrz1836/hush](https://github.com/mrz1836/hush) | Go broker on a separate trusted host; agents request scoped sessions over Tailscale | Yes | Discord DM with buttons; `Approver` interface is pluggable, Discord is the only implementation | Yes: JWT sessions with `--ttl`, `--max-uses`, revoke by `jti`; a supervisor keeps the token across child restarts | inject (env of child; zeroed on exit) | No | Yes: ECDSA-signed, hash-chained, kept on the vault host (not the agent's machine) | MIT | Alpha, unaudited; 1 star; pushed 2026-11-03 |
| [allen-hsu/hush](https://github.com/allen-hsu/hush) | macOS per-branch/per-worktree secrets; age store keyed from Keychain | Yes (detects `CLAUDECODE`, `CODEX_SANDBOX`, missing TTY) | None; `get` and `edit` refused without a TTY | No | inject (`hush run`); reveal only on a TTY, can be disabled | No | No audit log | MIT | 12 stars; pushed 2026-06-22 |
| [secret-agent](https://github.com/paperMoose/secret-agent) (crate) | Rust CLI vault, "keeps secrets out of AI agent traces" | Yes | None described | No | inject (`{{NAME}}` templating, `exec --env`, `inject --file`); reveal behind `--unsafe-display` | Yes, `[REDACTED:NAME]` on `exec` output | None described | MIT (crates.io) | 9 stars; v0.4.4; pushed 2026-08-18 |
| [secretctl](https://github.com/forest6511/secretctl) | Go local vault + MCP server + desktop app | Yes (MCP tools) | None; MCP command allowlist (`default_action: deny`) | No (secret expiry dates only) | inject (`secret_run`); masked partial reveal | Yes, exact string match only (docs say base64/hex not caught) | HMAC-chained log, same-user | Apache-2.0 | 11 stars; pushed 2026-01-22 |
| [Zaida-3dO/secret-broker](https://github.com/Zaida-3dO/secret-broker) | Claude Code hook rewrites `{{secret:NAME}}` to run through `secretrun`; backed by self-hosted Infisical | Yes | None described (unverified beyond description) | No (unverified) | inject | Yes (per description; not verified in code) | Not described | MIT | 0 stars; pushed 2026-10-17 |
| [nopeek](https://github.com/spences10/nopeek) | CLI that loads selected keys from a file into one child | Yes | None | No | inject | No; README says it "is not an output redactor" | No (its `audit` is a repo scanner) | MIT | 20 stars; pushed 2026-11-07 |
| [aivault](https://github.com/moldable-ai/aivault) | Local Rust vault + daemon (`aivaultd`, Unix socket); agents call named capabilities, daemon injects auth on the wire | Yes | None described | No | proxy-like (capability invoke; decryption in daemon, not CLI) | Upstream response headers stripped | Append-only JSONL; no separate uid described | Apache-2.0 | 20 stars; pushed 2026-09-11 |
| [Sesame](https://docs.getsesame.dev) | Credential broker; `sesame request` proxies HTTP and attaches auth by hostname | Yes | Sesame app, dashboard, or Telegram on first access to each new hostname | Revocable grants; TTL not documented | proxy | n/a | "Immutable logs" (vendor claim, mechanism not documented) | Not stated; skills repo has no license | Hosted/self-host status not documented |
| [Infisical Agent Vault](https://infisical.com/docs/documentation/platform/agent-vault/overview) | HTTP(S) MITM forward proxy that attaches real credentials; now part of the Infisical platform; [standalone repo](https://github.com/Infisical/agent-vault) no longer recommended | Yes | Access control page not reviewed (unverified) | Yes: "time-bound grants" (sessions) with access bundles | proxy (agent holds dummy values) | n/a | Encrypted session/request logs on the server | MIT core, proprietary `ee/` | Repo 2.5k stars; pushed 2026-11-07 |
| [authsome](https://github.com/agentrhq/authsome) | Python credential gateway; `authsome run --` routes through an auth proxy | Yes | None per use (OAuth login once) | No (token refresh only) | proxy | n/a | Not described | MIT | 104 stars; pushed 2026-07-24 |
| [OneCLI](https://github.com/onecli/onecli) | Team agent harness; Rust gateway MITMs egress and injects credentials | Yes | In-chat human-in-the-loop for high-risk actions | Not described | proxy | n/a | Not described | Apache-2.0 + `ee/` | 3.6k stars; pushed 2026-11-05 |
| [StrongDM Leash](https://github.com/strongdm/leash) | Container sandbox for agents; Cedar policy over syscalls, network, MCP calls | Yes | Prompt for mounting agent config dirs; policy otherwise | No | Forwards API keys into the container as env; proxy header injection is a [prototype/TODO](https://github.com/strongdm/leash/blob/main/docs/todo/SECRETS-INJECTION.md) | n/a | Full filesystem/network telemetry; not described as tamper-evident | Apache-2.0 | 598 stars; last push 2026-04-06 |
| [nono](https://github.com/nolabs-ai/nono) | Unprivileged agent sandbox (Landlock/seccomp, Seatbelt) with a supervisor process | Yes | Supervisor prompts for out-of-sandbox access (Linux; per secondary sources, unverified) | Not described | proxy with "phantom tokens" | n/a | "Tamper-evident" with optional signing (mechanism not documented) | Apache-2.0 | 4.9k stars; pushed 2026-11-06 |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/configuration/credentials.md) (`sbx`) | MicroVM sandbox for agents; host proxy overwrites auth headers | Yes | First-run approval of third-party kits' credential bindings | Dynamic secrets cached 55 min; no session grant | proxy (agent sees `proxy-managed` sentinel) | n/a | Not described | Proprietary (Docker product) | Shipping product |
| [Claude Code sandbox credentials](https://code.claude.com/docs/en/sandboxing) | Built-in: `sandbox.credentials` deny or `mask` per file/env var; `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` | Yes (it is the agent) | None; settings only honored from user/managed scope, not repo settings | Per-session sentinel | proxy (`mask` + `tlsTerminate`, `injectHosts`); deny | n/a | n/a | Proprietary (Claude Code); runtime is [Apache-2.0](https://github.com/anthropic-experimental/sandbox-runtime) | Shipping |
| [1Password for Claude / Environments MCP](https://www.1password.dev/environments/mcp-server) | Browser autofill for Claude with per-credential approval; MCP server that returns names only and mounts `.env` files on demand | Yes | 1Password app prompt (desktop app is the trust boundary) | Approval lasts until 1Password locks | inject (mounted `.env`, `op run`); names only to agent | `op run` masks (see below) | 1Password business audit (not reviewed) | Proprietary | Launched July-Aug 2026; MCP on Mac and Linux |

### General developer tools

| Project | What it is | Agent-aware | Approval channel | Session TTL grants | Injection vs reveal | Scrub | Tamper-resistant audit | License | Activity (Nov 2026) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [1Password CLI](https://www.1password.dev/cli/app-integration-security/) (`op`) | CLI for a commercial password manager | Partly (see above) | Desktop app: Touch ID on macOS, **polkit** on Linux, Windows Hello | Yes, per terminal: bound to the tty on macOS/Linux (incl. sub-shells), to the PID on Windows; 10 min idle, 12 h hard | inject (`op run`), reveal (`op read`) | Yes: `op run` conceals values on stdout/stderr by default; `--no-masking` | Business-tier activity logs (server-side; not reviewed) | Proprietary | Active |
| [Bitwarden Secrets Manager CLI](https://bitwarden.com/help/secrets-manager-cli/) (`bws`) | Machine-account secrets service | No | None (access token) | No; docs warn a revoked token may keep working until the cached session expires | inject (`bws run`), reveal | Not documented | Server-side event logs (not reviewed) | Bitwarden SDK License (not OSI) | sdk-sm pushed 2026-11-05 |
| [Doppler CLI](https://docs.doppler.com/docs/cli) | Hosted secrets service | No (has MCP guidance on the blog) | None | Ephemeral service tokens via `--max-age` | inject (`doppler run`), reveal | Not documented | Server-side activity logs | Apache-2.0 (CLI) | Pushed 2026-10-22 |
| [Infisical CLI](https://github.com/Infisical/infisical) | Open-core secrets platform | Yes (Agent Vault, above) | Platform access requests (not reviewed) | Platform-side | inject (`infisical run`), reveal | Not reviewed | Server-side audit logs | MIT + proprietary `ee/` | 30k stars; pushed 2026-11-08 |
| [HashiCorp Vault](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/process-supervisor) (agent, leases) | Server secrets manager; Vault Agent renders templates and supervises a child | No | [Control groups](https://developer.hashicorp.com/vault/docs/enterprise/control-groups) (Enterprise): authorizers approve before a wrapped response can be unwrapped | Yes: leases with TTL, renew, revoke; dynamic secrets | inject (process supervisor env, templates), reveal | No | Audit devices on the server (HMAC'd values), outside client control | BUSL-1.1 ([OpenBao](https://github.com/openbao/openbao) fork: MPL-2.0) | 36k stars; pushed 2026-11-07 |
| [aws-vault](https://github.com/99designs/aws-vault) | Stores IAM keys in OS keystore, hands out STS session credentials | No | Keystore unlock; MFA via STS | Yes: STS sessions (`--duration`), `--server` metadata mode | inject (`exec`) | No | No (CloudTrail on the AWS side) | MIT | Original abandoned per README; [ByteNess fork](https://github.com/ByteNess/aws-vault) active (pushed 2026-11-05) |
| [envchain](https://github.com/sorah/envchain) | Env vars from macOS Keychain / gnome-keyring | No | Keychain/keyring unlock | No | inject | No | No | MIT | Last push 2024-04 |
| [sops](https://github.com/getsops/sops) | Encrypted structured files (age, PGP, KMS) | No | Key access (KMS IAM, age key) | No | inject (`exec-env`, `exec-file`), decrypt | No | No (KMS-side logs) | MPL-2.0 | 23.7k stars; pushed 2026-11-03 |
| [pass](https://www.passwordstore.org/) / [gopass](https://github.com/gopasspw/gopass) | GPG-encrypted files in git | No | gpg-agent pinentry; YubiKey if the GPG key lives on one | gpg-agent cache TTL (per key, not per session) | reveal | No | git history only | GPL-2.0+ / MIT | pass mirror pushed 2026-10-27; gopass pushed 2026-11-05 |
| [systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html) | Encrypt credentials to TPM2 and/or host key; delivered to units | No | None (root/TPM) | No | inject into a service's credential dir | No | journald only | LGPL-2.1+ (systemd) | Active |
| [git-crypt](https://github.com/AGWA/git-crypt) | Transparent file encryption in git | No | GPG/symmetric key | No | decrypt in working tree | No | No | GPL-3.0 | Pushed 2025-09-24 |
| [teller](https://github.com/tellerops/teller) | Rust multi-provider env loader | No | None | No | inject (`teller run`) | Yes: `teller redact` pipes any output and redacts | No | Apache-2.0 | 3.2k stars; pushed 2026-01-27 |
| [varlock](https://github.com/dmno-dev/varlock) | `.env.schema` with JSDoc-style descriptions; plugins for 1Password, Vault, etc. | Yes ("agents read your schema, never your secrets") | None | No | inject (`varlock run`) | "Log redaction and leak prevention" in framework integrations (mechanism not reviewed) | No | MIT | 4.9k stars; pushed 2026-11-05 |

### Output redaction and detection

| Project | What it does | Relevance |
| --- | --- | --- |
| GitHub Actions [masking](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands) | Repository secrets and values registered with `::add-mask::` are replaced by `***` in job logs | The reference model for `cn hide`. GitHub states redaction "is not guaranteed" because values can be transformed, and only covers secrets used in the current job. |
| `op run` | Conceals values in the child's stdout/stderr by default | Same idea as `cn run` scrubbing, shipped by a large vendor. |
| fnox, secret-agent, secretctl | `[REDACTED]` / `[REDACTED:NAME]` on exec output | All three document literal matching only; fnox and secretctl state that base64 or other encodings are missed. |
| teller `redact` | Pipe filter | Closest to `cn hide` as a standalone pipe. |
| [gitleaks](https://github.com/gitleaks/gitleaks) (MIT, 30.8k stars), [trufflehog](https://github.com/trufflesecurity/trufflehog) (AGPL-3.0, 29k stars) | Pattern/entropy detectors for repos and files; trufflehog also verifies live credentials | Detect *unknown* secrets by pattern. `cn hide` matches *known* values; a detector pass is a possible complement for secrets countersign does not hold. |

## Closest competitors

### fnox

The broadest overlap. fnox is a Rust secret manager from the author of mise,
under heavy development (2.4k stars, commits on the survey date). It already
ships most of the "use, don't read" surface: an MCP server that exposes only
allowed secrets, `exec` with literal redaction, a credential proxy that swaps
per-session placeholders into HTTPS headers, a `--sandbox` mode (bubblewrap on
Linux, seatbelt on macOS) that makes the proxy the only way out, short-lived
leases from AWS STS, GCP, GitHub Apps, Vault and others, and FIDO2/YubiKey as
a storage provider (touch once when a lease is created). Its docs are honest in
the same way countersign's threat model tries to be: MCP mode is "**not**
isolation", redaction is literal-only, and the audit log is owned by the user
so any same-user process can edit it.

What fnox does not do: approval per grant through a channel the agent cannot
drive (a touch happens to decrypt a provider, not to consent to a named
request), binding of grants to an agent's process tree, a daemon under a
separate uid, a tamper-resistant audit log, or per-secret usage prose. It is
project-file centric (`fnox.toml` per repo), which suits teams but means a
cloned repo's config is partly attacker-controlled; fnox already handles this
by recommending audit config live in the global file.

Learn or borrow: the proxy-plus-sandbox design is the roadmap countersign
describes as "egress proxy", already built; its strict egress default and
DNS-rebinding check on resolved addresses; leases as a first-class concept;
the localhost save page for entering a missing secret without it passing
through the agent. Consider whether countersign should be a fnox *provider*
(fnox resolves from `cnd`, countersign supplies approval and audit) rather
than a parallel tool. That is an open question, not a recommendation.

### mrz1836/hush

The closest match on the approval and audit model, and the only surveyed tool
with both an out-of-band approval channel and an audit log the agent cannot
reach. A single Go binary runs as vault server on a separate trusted host,
reachable only over Tailscale. Agents sign a claim with a per-machine key and
request a session with a TTL and a use count; the operator approves each
session with Discord buttons; secrets come back encrypted to the session's
ephemeral key and go into a child's environment. The `Approver` interface is
pluggable (Discord is the only implementation), sessions can be revoked by
`jti`, and every event is ECDSA-signed and hash-chained.

What it does not do: output scrubbing, process-ancestry binding (the session
is a token held by a supervisor, not tied to an agent process), per-secret
usage prose beyond a description in `hush secret list`, or a local same-host
mode. It is alpha, unaudited, has one star, and the README says so.

Learn or borrow: the max-uses limit alongside TTL; encrypting the response to
a per-session ephemeral key; the supervisor that keeps a session across child
restarts (relevant to countersign's "a process that daemonizes loses its
grants" rule); a pluggable approver with a real non-terminal channel. Discord
as a channel shows that phone-based approval is acceptable to users; countersign's
`command` adapter (ntfy/phone push) covers the same need.

### 1Password CLI, Environments and the MCP server

The closest match on approval UX and on Linux mechanics, from a large vendor.
On Linux the 1Password CLI asks for approval through **polkit** (fingerprint or
OS password), shows the requesting process, binds the authorization to the
terminal's tty including sub-shells, and expires it after 10 minutes idle and
12 hours absolute. `op run` injects into a child and conceals values on
stdout/stderr by default. The Environments MCP server returns only names to the
agent, prompts in the 1Password app per Environment, and can mount a `.env`
file "available on demand without writing them to disk". 1Password for Claude
(July 2026) does per-credential approval for browser logins.

What it does not do, for this use case: it requires a 1Password account and
the desktop app; the authorization unit is a terminal or the app's unlock
state, not an agent session (whether Claude Code's TTY-less Bash tool gets a
prompt per call or inherits the app's state was **not verified**); there is no
FIDO2-touch-per-grant approver; the CLI audit trail is a business-tier
server-side feature that was not reviewed; and it is proprietary. The polkit
prompt is rendered by the desktop's polkit agent, which is the same trusted
display countersign relies on.

Learn or borrow: tty/PID-scoped authorization with idle and hard timeouts is
direct prior art for countersign's session binding and shows users accept it;
masking on by default in `run`; names-only listing for agents; the honest
docs note that same-user processes can read each other's environment.

### The proxy-injection family

Claude Code's own sandbox (`sandbox.credentials` with `mode: "mask"`,
`tlsTerminate`, `injectHosts`), Docker Sandboxes (`sbx secret set`), Infisical
Agent Vault, nono's phantom tokens, OneCLI's gateway, Sesame and authsome all
take the same approach: the agent's process sees a sentinel, and a process
outside its reach adds the real value to outbound HTTPS. This is stronger than
anything `cn run` can offer against a malicious same-uid agent, because the
value never exists in the agent's uid. Its limits are also consistent across
them: HTTP(S) only, header or query substitution only (no bodies), TLS
interception or a client that honours proxy variables, and no help for a
database DSN, an SSH key, or a CLI that speaks a non-HTTP protocol. Claude
Code also only honours `mask` from user or managed settings, not from a repo's
`.claude/settings.json`, which is a precedent for countersign keeping approver
policy in root-owned `/etc`.

For a solo developer whose secrets are mostly HTTP API keys and who already
runs Claude Code with the sandbox on, `mask` mode covers much of what `cn run`
offers, with no extra daemon. countersign's case rests on non-HTTP secrets,
approval, audit, prose, and agent-agnosticism.

### Smaller "use, don't read" CLIs

secret-agent, secretctl, Zaida-3dO/secret-broker, allen-hsu/hush and nopeek
each implement inject-and-redact (or inject-only) for the agent's own uid,
with no out-of-band approval. allen-hsu/hush is worth reading for its agent
detection (`CLAUDECODE`, `CODEX_SANDBOX`, no TTY) and its `agent_profile =
"sandbox"` that hands detected agents throwaway credentials; its README calls
these "guardrails against honest/careless agents, not walls", which is the
right framing. secretctl's HMAC-chained audit log and MCP command allowlist,
and secret-agent's `{{NAME}}` argument templating, are small ideas worth
noting. None of them is a reason not to build countersign.

## Where countersign is different

Honest summary: most individual features are already shipped somewhere, and
the strongest isolation (proxy injection) is already built into Claude Code and
Docker Sandboxes. countersign's distinct contribution is the combination, plus
two pieces nothing surveyed does locally.

1. **Grants bound to process ancestry.** No surveyed tool binds a grant to an
   agent's process tree via SO_PEERCRED/pidfd and a session anchor. The
   closest is 1Password CLI's tty binding (Linux/macOS) and PID binding
   (Windows). This is the most novel part, and also the part with the least
   field evidence; it needs careful testing against how agents actually spawn
   tools (Claude Code's Bash tool, MCP stdio servers, hooks, background jobs).
2. **Audit under a separate uid on the same host.** fnox and secretctl keep
   append-only or chained logs as the user, which the user's agent can edit.
   mrz1836/hush gets tamper resistance by putting the vault on another
   machine. Vault and hosted services keep audit server-side. A same-host
   daemon user that owns the store and the log is not novel as Unix practice,
   but no surveyed agent tool does it.
3. **Per-grant approval the agent cannot drive, with FIDO2 touch as a
   first-class adapter.** mrz1836/hush (Discord), Sesame (app/Telegram),
   1Password (polkit/biometric) and Vault control groups (Enterprise) each
   have an out-of-band approver. None offers a FIDO2 assertion over a hash of
   the specific request, and only mrz1836/hush exposes a pluggable approver
   interface.
4. **Usage prose written for the agent.** varlock's schema comments, Infisical
   Agent Vault's per-bundle "skills", secretctl's notes and mrz1836/hush's
   descriptions are adjacent. None pairs a description with "how to use this
   in this project" prose surfaced by `list` before a request. This is cheap
   to copy, so it is not a moat.
5. **`cn hide` as a daemon-side filter that does not hand values to the
   caller.** teller `redact` and the exec-redaction tools run in the user's
   process with the values. Having `cnd` do the matching, and treating the
   filter as a guess oracle (rate limits, audited hit counts), is not
   something surveyed tools discuss. Matching common encodings goes beyond
   fnox and secretctl, which document literal matching only.

What countersign does **not** do better:

- Against a deliberately malicious same-uid agent during a live grant, `cn run`
  is weaker than proxy injection, as the threat model already says. Claude Code's
  `mask` mode and fnox's `proxy run --sandbox` exist today.
- fnox covers more backends, short-lived cloud credentials, and has an active
  maintainer and user base. A solo developer could get most of "use, don't
  read" by combining fnox with Claude Code's sandbox today.
- 1Password users already have polkit approval, tty-scoped sessions and
  default masking in `op run`.

So countersign is not redundant, but its justification is narrower than "no
tool keeps secrets out of agent transcripts". It is: consent per grant through
hardware or a trusted dialog, scoped to one agent session, with an audit the
agent cannot rewrite, for any secret type, locally, without an account.

## Ideas worth borrowing

| Idea | From | Where it fits |
| --- | --- | --- |
| Use count limit (`--max-uses`) alongside TTL | mrz1836/hush | `cn request --max-uses N` |
| Encrypt the response to a per-session ephemeral key | mrz1836/hush | Defence in depth for IPC; low priority on a local socket |
| Placeholder + HTTPS proxy + sandbox where the proxy is the only egress; strict egress default; check resolved IPs to stop DNS rebinding | fnox, Claude Code sandbox, Docker Sandboxes | The roadmap egress proxy; consider shipping the sandbox launcher with `cn session exec` |
| Short-lived derived credentials (STS, GitHub App tokens) instead of the stored long-lived key | fnox leases, aws-vault, Vault | A later "lease" grant mode |
| Localhost page to enter a missing secret, so the value never transits the agent | fnox `request_secret` | `cn add` from inside an agent session (`!` has no TTY) |
| Policy honoured only from user/managed scope, never from repo files | Claude Code sandbox | Already in the design (`/etc/countersign`); keep project-level config organisational only |
| tty/PID-scoped authorization with idle and absolute timeouts | 1Password CLI | Idle timeout in addition to TTL |
| Masking on by default in `run`, opt-out flag | `op run` | `cn run` default; `--no-scrub` audited |
| Names-only MCP tools (`list_secrets`, never values) | 1Password Environments MCP, secretctl | An optional `cn mcp` server exposing list/request/run |
| Agent detection markers (`CLAUDECODE`, `CODEX_SANDBOX`) and a sandbox profile with throwaway credentials | allen-hsu/hush | Labels for audit; a "sandbox key" fallback mentioned in usage prose |
| Tiered approval: automatic, async notify with default-deny timeout, synchronous FIDO2 | IETF [CB4A draft](https://www.ietf.org/archive/id/draft-hartman-credential-broker-4-agents-00.html) | Approver chain config; the draft also requires fail-closed when audit is unavailable |
| Approval response as a limited-duration wrapped token | Vault control groups | Pending-request model for `cn request` |
| Explicit "this is not isolation" sections | fnox, allen-hsu/hush, nopeek | The threat model's same-uid limits; publish them prominently |
| Detector pass for unknown secrets | gitleaks, trufflehog | Optional `cn hide --detect`, clearly labelled as heuristic |
| Document the limits of masking as GitHub does ("not guaranteed") | GitHub Actions | `cn hide` docs |

## Open questions raised by this survey

- Should countersign interoperate with fnox (as a provider, or by consuming
  fnox providers) instead of growing its own backend list? The roadmap's
  commercial angle (proxying third-party vaults) overlaps directly with what
  fnox already does.
- With Claude Code's `mask` mode shipped, is the egress proxy still a
  countersign roadmap item, or should countersign supply approved values to
  existing sandbox proxies?
- How does process-ancestry binding behave for Claude Code MCP stdio servers
  and hooks, which Claude Code docs say run outside its sandbox? Not tested.

## Sources

Agent-specific:

- fnox: <https://github.com/jdx/fnox>, MCP <https://fnox.jdx.dev/guide/mcp.html>, proxy <https://fnox.jdx.dev/guide/proxy.html>, leases <https://fnox.jdx.dev/guide/leases.html>, audit <https://fnox.jdx.dev/guide/audit.html>
- mrz1836/hush: <https://github.com/mrz1836/hush>
- allen-hsu/hush: <https://github.com/allen-hsu/hush>
- secret-agent: <https://github.com/paperMoose/secret-agent>, <https://docs.rs/crate/secret-agent/0.4.4/source/README.md>, <https://crates.io/crates/secret-agent>
- secretctl: <https://github.com/forest6511/secretctl>
- secret-broker: <https://github.com/Zaida-3dO/secret-broker>
- nopeek: <https://github.com/spences10/nopeek>
- aivault: <https://github.com/moldable-ai/aivault>
- Sesame: <https://docs.getsesame.dev>, <https://docs.getsesame.dev/security/approval-flow.md>, <https://docs.getsesame.dev/security/audit-logs.md>, <https://github.com/getsesame/skills>
- Infisical Agent Vault: <https://infisical.com/docs/documentation/platform/agent-vault/overview>, <https://github.com/Infisical/agent-vault>
- authsome: <https://github.com/agentrhq/authsome>
- OneCLI: <https://github.com/onecli/onecli>
- StrongDM Leash: <https://github.com/strongdm/leash>, <https://github.com/strongdm/leash/blob/main/docs/todo/SECRETS-INJECTION.md>
- nono: <https://github.com/nolabs-ai/nono>, <https://www.helpnetsecurity.com/2026/07/27/nono-open-source-ai-agent-sandboxing/> (secondary)
- Docker Sandboxes: <https://docs.docker.com/ai/sandboxes/configuration/credentials.md>, <https://docs.docker.com/ai/sandboxes/architecture>
- Claude Code sandboxing: <https://code.claude.com/docs/en/sandboxing>, <https://github.com/anthropic-experimental/sandbox-runtime>
- 1Password: CLI app integration <https://www.1password.dev/cli/app-integration-security/>, `op run` <https://www.1password.dev/cli/reference/commands/run/>, secrets in env <https://www.1password.dev/cli/secrets-environment-variables/>, Environments MCP <https://www.1password.dev/environments/mcp-server>, 1Password for Claude <https://www.1password.community/announcements-52/give-claude-access-without-giving-up-your-credentials-25090>, August 2026 update <https://www.1password.community/announcements-52/august-2026-at-1password-smarter-sign-ins-secure-ai-agents-and-safer-developer-secrets-25431>
- op-cache (1Password read cache, no agent features): <https://github.com/SamSaffron/op-cache>
- IETF CB4A draft: <https://www.ietf.org/archive/id/draft-hartman-credential-broker-4-agents-00.html>
- Other agent-secret crates found but not reviewed: secretsh <https://crates.io/crates/secretsh>, svault-ai <https://crates.io/crates/svault-ai>, agent-vault <https://crates.io/crates/agent-vault>; MCP proxies found but not reviewed: janee <https://github.com/rsdouglas/janee>, KeyProxy, key-guard <https://github.com/domjeff/key-guard>

General developer tools:

- Bitwarden `bws`: <https://bitwarden.com/help/secrets-manager-cli/>, <https://github.com/bitwarden/sdk-sm>
- Doppler: <https://docs.doppler.com/docs/cli>, <https://github.com/DopplerHQ/cli>
- Infisical: <https://github.com/Infisical/infisical>
- Vault: <https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/process-supervisor>, <https://developer.hashicorp.com/vault/docs/enterprise/control-groups>, <https://github.com/hashicorp/vault>; OpenBao <https://github.com/openbao/openbao>
- aws-vault: <https://github.com/99designs/aws-vault>, <https://github.com/ByteNess/aws-vault>
- envchain: <https://github.com/sorah/envchain>
- sops: <https://github.com/getsops/sops>
- pass: <https://www.passwordstore.org/>; gopass: <https://github.com/gopasspw/gopass>
- systemd-creds: <https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html>
- git-crypt: <https://github.com/AGWA/git-crypt>
- teller: <https://github.com/tellerops/teller>
- varlock: <https://github.com/dmno-dev/varlock>

Redaction and detection:

- GitHub Actions workflow commands: <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands>; secrets: <https://docs.github.com/en/actions/concepts/security/secrets>
- gitleaks: <https://github.com/gitleaks/gitleaks>
- trufflehog: <https://github.com/trufflesecurity/trufflehog>
