# Contributing

countersign is pre-1.0 and design-first: the documents under `docs/` are the
spec, and code follows them. A change to behaviour starts as a change to the
relevant doc (or an issue that proposes one).

## Developer Certificate of Origin

Contributions are accepted under the Apache License 2.0 with a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off.
There is no CLA. Sign every commit:

```sh
git commit -s
```

This adds `Signed-off-by: Your Name <you@example.com>`, certifying you wrote the
change or have the right to submit it under the project license. CI rejects
pull requests with unsigned commits.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

## Security

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md),
and read [docs/threat-model.md](docs/threat-model.md) for what countersign does
and does not claim to protect against.
