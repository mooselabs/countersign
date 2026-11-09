//! Store, sessions, grants, policy and audit for `cnd`.
//!
//! A synchronous library; the daemon wraps it in its event loop.
//!
//! - [`config`] parses `/etc/countersign/config.toml`.
//! - [`store`] is the encrypted store, its key slots and the recovery phrase.
//! - [`audit`] is the hash-chained audit log, its verifier and queries.
//! - [`sessions`] finds the session anchor of a connecting process.
//! - [`grants`] holds pending requests and grants.
//! - [`time`] has the injected clock, durations and RFC 3339.
//!
//! The specification is `docs/design.md` and `docs/audit.md`.

pub mod audit;
pub mod config;
mod encoding;
pub mod grants;
pub mod sessions;
pub mod store;
pub mod time;

pub use encoding::random_id;
