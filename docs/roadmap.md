# Roadmap

Ordered by what makes countersign useful to one developer soonest. Each phase
ends with something the owner uses daily, not a demo.

## Phase 0: design (now)

- Spec documents under `docs/`: threat model, design, approvers, audit, CLI,
  agent integration, prior art.
- `countersign-hide`: the streaming redaction engine, implemented and tested,
  because its correctness (chunk boundaries, encodings, no timing oracle) is
  the easiest part to get subtly wrong.
- `countersign-proto`: frame codec, request messages, error codes, request
  codes.
- Resolve the blocking open questions below before Phase 1 code.

## Phase 1: replaces `.secret-*` files on one machine

Done when the owner has deleted every `.secret-*` file from the liskov
workspace and its scripts use `cn run`.

1. `cnd` skeleton: socket activation, peer credentials, handshake, sessions
   (launcher registration first, then matchers), in-memory grants.
2. Store: data model, XChaCha20-Poly1305 file, `systemd-creds` key slot,
   recovery key slot, atomic writes.
3. Audit writer: hash-chained JSONL, `cn audit`, `cn audit verify`.
4. Approvers: `fido2` (client-driven, YubiKey touch), then `polkit`.
5. `cn`: `list`, `show`, `request`, `approve`, `deny`, `grants`, `revoke`,
   `run`, `hide`, `add`, `set`, `edit`, `rm`, `import`, `session`,
   `session exec`, `approver enroll`, `doctor`, with `--json`.
6. Packaging: an install script for openSUSE (sysusers, tmpfiles, units,
   polkit policy, udev rule), then an RPM spec.
7. Agent integration: the AGENTS.md snippet and a Claude Code skill.

## Phase 2: unattended and stricter

- Standing grants for unattended hosts (an agent factory), anchored to a
  systemd unit, approved once.
- Optional hard limits per secret: allowed executables, allowed hosts.
- `reveal` mode with its own approver chain.
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

## Open questions that block Phase 1

Collected from the other documents. Each needs an owner decision or a test
result before the code it names is written. Questions settled elsewhere (X11,
grant persistence, expiry of running children, the key
slot model) are no longer listed.

1. **polkit subject until polkit-org/polkit#699 is fixed.** The spike
   ([spikes/polkit-dialog](../spikes/polkit-dialog/README.md)) showed GNOME
   renders the request code, digest and summary that `cnd` passes as the
   action owner, that an agent cannot pass dialog text, and that `auth_self`
   does not cache. But a `unix-session` subject aborts polkitd 127/128, and a
   `unix-process` subject can be taken over by a same-uid agent registering
   its own authentication agent. Decide: ship Phase 1 on the process subject
   (trusted display against careless agents only, documented), and/or
   upstream a fix for #699 and switch to the session subject by polkit
   version. Also confirm the spike's T4 (authorized after the human was told
   to cancel) before polkit counts as an approver.
2. **Kernel floor.** Require Linux 6.5+ for `SO_PEERPIDFD`, or keep the
   `pidfd_open` fallback and its narrow pid-reuse window? Blocks the `cnd`
   peer-credential code. ([design](design.md#12-open-questions) 2,
   [threat model](threat-model.md) T8)
3. **FIDO2 library.** `libfido2` conflicts with a statically linked `cn`;
   the pure-Rust options have smaller user bases, and `ctap-hid-fido2` cannot
   link statically on musl ([fnox evaluation](fnox-evaluation.md)). Blocks the `fido2` client
   side of `cn approve`. ([approvers](approvers.md#library-choice-open))
4. ~~**Overlap with fnox.**~~ Settled: countersign keeps its own store; fnox
   trusts the agent's uid by design and cannot host a separate-uid broker. In
   Phase 3 `cnd` may call `fnox env --json` as its own user to reach
   third-party vaults. ([fnox evaluation](fnox-evaluation.md))
