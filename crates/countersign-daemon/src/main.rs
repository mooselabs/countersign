//! `cnd`: the countersign daemon. Not implemented yet; see `docs/design.md`.

fn main() {
    eprintln!(
        "cnd {}: not implemented yet; see docs/design.md",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(69); // EX_UNAVAILABLE
}
