# Changelog

All notable changes to countersign. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-10

The first release: Phase 1 of the
[roadmap](https://github.com/mooselabs/countersign/blob/main/docs/roadmap.md), which
replaces plaintext `.secret-*` files on one machine.

### Added

- `cnd`, the daemon: runs as its own user, socket-activated, identifies
  callers through `SO_PEERPIDFD`, binds grants to an agent session, and
  reloads its config on `systemctl reload`.
- The store: XChaCha20-Poly1305, unlocked by a master key sealed with
  `systemd-creds`, with a recovery phrase slot (`cnd init`, `cnd recover`).
- An audit log the agent cannot change: hash-chained JSONL with signed
  checkpoints (`cn audit`, `cn audit verify`).
- Approval through a polkit desktop dialog that starts with the request code
  and digest, with the factor chosen at install: `password`, `touch` (a
  security key, through `pam_u2f`) or `touch+password`.
- `cn`, the CLI: `list`, `show`, `request`, `approve`, `deny`, `grants`,
  `revoke`, `run`, `hide`, `reveal`, `add`, `set`, `edit`, `rm`, `import`,
  `session`, `session exec`, `audit`, `doctor`, with `--json`.
- Packaging: `install.sh` and `uninstall.sh` (sysusers, tmpfiles, units,
  polkit policy, master key, approval factor); `trusted-build.sh`, which
  builds a named commit as root with the distribution's toolchain; and a
  one-line installer that installs a release's prebuilt binaries after
  checking their SHA-256 sums and build provenance.
- Agent integration: an AGENTS.md snippet, a Claude Code skill and a
  migration guide, in `integrations/`.

### Known limits

- Linux 6.5 or later, systemd 253 or later, polkit 0.114 or later, and a
  graphical session with a polkit agent (tested on GNOME Shell, Wayland).
  Release binaries are for x86_64 only; other machines build from source.
- A deliberately malicious agent running as your user can still obtain a
  value it holds a live grant for. It can also register its own polkit agent
  for its process and draw the dialog, though it still needs your factor
  to approve. See
  [docs/threat-model.md](https://github.com/mooselabs/countersign/blob/main/docs/threat-model.md).
- Root, the kernel and polkit are trusted. While your user can run `sudo`
  without a password, an agent running as you can become root, and
  countersign protects nothing against it.
- Not in this release: the FIDO2 approver and FIDO2 store unlock, `cn
  export` and `cn import --from`, audit sinks and retention, raising a
  dialog again after it timed out, a lock that stops `cnd recover` while the
  daemon runs, and an RPM package. See
  [docs/roadmap.md](https://github.com/mooselabs/countersign/blob/main/docs/roadmap.md).

[Unreleased]: https://github.com/mooselabs/countersign/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mooselabs/countersign/releases/tag/v0.1.0
