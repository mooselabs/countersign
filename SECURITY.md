# Security policy

## Supported versions

countersign is pre-1.0. Only the latest `main` is supported. Fixes are not
backported to earlier commits or tags.

## Reporting a vulnerability

Report privately through GitHub private vulnerability reporting:
<https://github.com/mooselabs/countersign/security/advisories/new>.

Do not open a public issue, pull request or discussion for a suspected
vulnerability. Include the version or commit, your configuration (approver
adapters, store sealing mode, desktop session type), steps to reproduce, and what
you expected to happen.

## What to expect

- Acknowledgement within 7 days.
- An initial assessment, including whether we consider it in scope, within 14
  days.
- A fix or a documented mitigation as soon as practical, coordinated with you
  before public disclosure. We credit reporters unless asked not to.

## What counts as a vulnerability

[`docs/threat-model.md`](docs/threat-model.md) defines the boundary. In short:

- **Is a vulnerability:** anything that lets a process without an approved grant
  obtain a value; approval without a human presence or trusted-UI action;
  approval of a request other than the one displayed in a surface the threat
  model claims is trusted; a same-uid process modifying the audit log, store or
  approver config; recovering values from the store at rest without the sealing
  key; a value appearing in `cnd` logs or audit records; a redaction bypass for
  the encodings `cn hide` claims to cover; another local user reaching the socket.
- **Is a documented limit, not a vulnerability:** a deliberately malicious
  same-uid agent reading `/proc/<pid>/environ` or ptracing a `cn run` child during
  a live grant; a same-uid agent obtaining a value it holds a live `use` grant
  for; spoofed terminal approval displays against an agent that controls the
  user's shell or harness; anything requiring root; anything after a value has
  been revealed.

If you are unsure, report it. A report that shows the threat model is wrong is
welcome too.
