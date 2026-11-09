# Roadmap

Ordered by what makes countersign useful to one developer soonest. Each phase
ends with something the owner uses daily, not a demo.

## Phase 0: design (done)

- Spec documents under `docs/`: threat model, design, approvers, audit, CLI,
  agent integration, prior art.
- `countersign-hide`: the streaming redaction engine, implemented and tested,
  because its correctness (chunk boundaries, encodings, no timing oracle) is
  the easiest part to get subtly wrong.
- `countersign-proto`: frame codec, request messages, error codes, request
  codes.
- Resolve the blocking open questions below before Phase 1 code.

## Phase 1: replaces `.secret-*` files on one machine (in progress)

Done when the owner has deleted every `.secret-*` file from the liskov
workspace and its scripts use `cn run`. Decisions 14 to 19 set its scope.

1. `cnd` skeleton: socket activation, peer credentials through
   `SO_PEERPIDFD` (Linux 6.5+), handshake, sessions (launcher registration
   first, then matchers), in-memory grants.
2. Store: data model, XChaCha20-Poly1305 file, `systemd-creds` key slot,
   recovery phrase slot, atomic writes; `cnd init` and `cnd recover`.
3. Audit writer: hash-chained JSONL, `cn audit`, `cn audit verify`.
4. Approver: `polkit` only, for every kind, with the session anchor as a
   `unix-process` subject and request expiry enforced by `cnd`. An
   `insecure-auto` approver behind the debug-only `insecure-test` feature for
   end-to-end tests.
5. `cn`: `list`, `show`, `request`, `approve` (prints the request for
   cross-checking; the approval itself is the dialog), `deny`, `grants`,
   `revoke`, `run`, `hide`, `add`, `set`, `edit`, `rm`, `import`, `session`,
   `session exec`, `doctor`, with `--json`.
6. Packaging: an install script for openSUSE (sysusers, tmpfiles, units,
   polkit policy, master key, approval factor with `pam_u2f`), then an RPM
   spec. See [packaging/README.md](../packaging/README.md).
7. Agent integration: the AGENTS.md snippet, a Claude Code skill and the
   migration guide, in [`integrations/`](../integrations/).

## Phase 2: unattended and stricter

- **Privilege audit in `cn doctor`.** countersign's guarantees assume the
  agent cannot become root. On the owner's machine (2026-11-08) it can:
  `(ALL : ALL) NOPASSWD: ALL` in sudoers and membership of `docker` (root
  equivalent). `cn doctor` reports every path from the agent's uid to root:
  NOPASSWD rules, a sudo timestamp not bound to the terminal, the `docker`,
  `libvirt` and `disk` groups, polkit rules or actions that return `yes`,
  writable files that root executes. Each finding says what to change.
- **`cn sudo`: approved root commands.** The replacement for `NOPASSWD: ALL`.
  The agent asks to run one exact command as root
  (`cn sudo -- systemctl restart caddy`); the human sees the exact argv in the
  countersign dialog and touches the key; a small root helper, reachable only
  from `cnd`, runs it with a clean environment and streams the output back;
  the audit log records it against the agent session. Standing rules let
  named harmless commands through without a touch (the owner's existing
  `NOPASSWD: /usr/bin/tailscale switch *` is one). Design questions: the
  root helper's interface (argv only, no shell), output scrubbing with
  `cn hide`, and whether a grant may cover a command pattern or only an
  exact argv.

- **The `fido2` approver** (deferred from Phase 1 by decision 14):
  client-driven approval with `/usr/bin/cn approve CODE` and a signature over
  the request digest, `cn approver enroll`, root-owned credential records
  (P2), and the all-of-polkit-and-FIDO2 chain for `reveal`, `mutate` and
  `export` (P1). Needs the library choice (blocker 3 below).
- **FIDO2 store unlock**: a `fido2` key slot, `cn unlock`, and the udev rule
  for daemon-side FIDO2.
- **A phone push approver.** A phone app that shows the request and signs
  its answer over the digest: a display outside the desktop, and an approval
  that works without a graphical session. Considered, not designed
  (decision 19).
- **Session subject for polkit** once polkit-org/polkit#699 is fixed:
  `subject = "session"` closes the process-subject hijack (decision 15).
- Standing grants for unattended hosts (an agent factory), anchored to a
  systemd unit, approved once.
- Optional hard limits per secret: allowed executables, allowed hosts.
- `reveal` with a stricter chain than `use` (polkit and FIDO2, P1). In
  Phase 1 a reveal is approved through the polkit `reveal` action.
- Masked previews for value swaps (scheme and host of a URL-shaped value).
- macOS port (LOCAL_PEERPID, Touch ID approver).

## Phase 3: stronger isolation and other vaults

- Tier 2: run the agent under a separate uid or sandbox with only the socket
  exposed, so a malicious agent cannot read a live child's environment.
- Backends that proxy third-party vaults (1Password, Bitwarden, Doppler,
  Vault, AWS). Decide first whether to build these or to sit on top of an
  existing multi-backend tool (see [prior-art.md](prior-art.md)).
- Tier 3: a credential-injecting egress proxy, so HTTP API keys never enter
  the developer's uid. Check first how much of this agent sandboxes already
  provide.

## Open questions that blocked Phase 1

Collected from the other documents. Questions settled elsewhere (X11,
grant persistence, expiry of running children, the key slot model) are no
longer listed.

1. ~~**polkit subject until polkit-org/polkit#699 is fixed.**~~ Settled by
   decision 15: Phase 1 ships on the `unix-process` subject (the session
   anchor), with the hijack limit documented; `subject = "session"` is
   available for when #699 is fixed. The spike's T4 was confirmed (the human
   had authenticated; a real Cancel returns `polkit.dismissed`).
   ([spike](../spikes/polkit-dialog/README.md))
2. ~~**Kernel floor.**~~ Settled by decision 16: Linux 6.5 or later,
   `SO_PEERPIDFD` only, no `pidfd_open` fallback.
3. **FIDO2 library.** Deferred to Phase 2 with the `fido2` approver
   (decision 14). `libfido2` conflicts with a statically linked `cn`;
   the pure-Rust options have smaller user bases, and `ctap-hid-fido2` cannot
   link statically on musl ([fnox evaluation](fnox-evaluation.md),
   [approvers](approvers.md#library-choice-open)).
4. ~~**Overlap with fnox.**~~ Settled: countersign keeps its own store; fnox
   trusts the agent's uid by design and cannot host a separate-uid broker. In
   Phase 3 `cnd` may call `fnox env --json` as its own user to reach
   third-party vaults. ([fnox evaluation](fnox-evaluation.md))
