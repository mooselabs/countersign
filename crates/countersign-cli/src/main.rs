//! `cn`: the countersign command-line client. Not implemented yet; see `docs/cli.md`.

fn main() {
    eprintln!(
        "cn {}: not implemented yet; see docs/cli.md",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(69); // EX_UNAVAILABLE
}
