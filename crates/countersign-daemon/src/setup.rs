//! Loading what `cnd` runs on: the config and the approvers it names, the
//! master key, the host identity. Also `cnd init` and `cnd recover`.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use countersign_approve::Registry;
use countersign_approve::polkit::{Bus, PolkitApprover};
use countersign_core::audit::{self, AuditLog, Event};
use countersign_core::config::{ApproverConfig, Config, check_file_owner};
use countersign_core::store::{MasterKey, RecoveryPhrase, STORE_FILE, Store};
use countersign_core::time::{Clock, SystemClock};
use zeroize::Zeroizing;

use crate::Paths;
use crate::log::warning;

/// Where user names in `[access] users` are looked up.
const PASSWD: &str = "/etc/passwd";

/// Everything `cnd` derives from one config file. Replaced whole on reload;
/// requests already running keep the one they started with.
pub struct Runtime {
    /// The parsed config.
    pub config: Config,
    /// Path it was read from.
    pub path: PathBuf,
    /// Hex SHA-256 of the file (`config.load`).
    pub sha256: String,
    /// Peer uids allowed on the socket.
    pub uids: BTreeSet<u32>,
    /// The approver instances.
    pub registry: Registry,
    /// The polkit approvers, for the startup version check.
    pub polkit: Vec<Arc<PolkitApprover>>,
}

impl Runtime {
    /// Whether a peer uid may connect.
    pub fn allows(&self, uid: u32) -> bool {
        if uid == 0 {
            return self.config.access.allow_root_clients;
        }
        self.uids.contains(&uid)
    }

    /// The `approvers` summary for `config.load`.
    pub fn approvers_summary(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for a in self.registry.iter() {
            let info = a.info();
            map.insert(
                info.name.clone(),
                serde_json::json!({
                    "adapter": info.adapter,
                    "trusted_display": info.trusted_display,
                }),
            );
        }
        serde_json::Value::Object(map)
    }
}

/// Reads and checks the config: root-owned (outside test mode), valid, its
/// users known, its approvers built.
pub fn load_runtime(paths: &Paths) -> Result<Runtime, String> {
    if !paths.insecure {
        check_file_owner(&paths.config).map_err(|e| e.to_string())?;
    }
    let loaded = Config::load(&paths.config)
        .map_err(|e| format!("config {}: {e}", paths.config.display()))?;
    let config = loaded.config;
    for w in &config.warnings {
        warning!("config: {w}");
    }
    for w in unsupported(&config) {
        warning!("config: {w}");
    }
    let uids = config
        .access
        .allowed_uids(Path::new(PASSWD))
        .map_err(|e| format!("config {}: {e}", paths.config.display()))?;
    let bus = match &paths.polkit_bus {
        Some(addr) => Bus::Address(addr.clone()),
        None => Bus::System,
    };
    let mut registry = Registry::new();
    let mut polkit = Vec::new();
    for (name, a) in &config.approvers {
        match a {
            ApproverConfig::Polkit(pc) => {
                let p = Arc::new(PolkitApprover::new(name, pc.clone(), bus.clone()));
                polkit.push(p.clone());
                registry.insert(p);
            }
            #[cfg(feature = "insecure-test")]
            ApproverConfig::InsecureAuto(c) => {
                registry.insert(Arc::new(
                    countersign_approve::insecure::InsecureAutoApprover::new(name, c.clone()),
                ));
            }
        }
    }
    Ok(Runtime {
        config,
        path: paths.config.clone(),
        sha256: loaded.sha256,
        uids,
        registry,
        polkit,
    })
}

/// Settings this version parses but does not act on.
fn unsupported(c: &Config) -> Vec<String> {
    let mut w = Vec::new();
    if c.approval.list_requires_approval {
        w.push(
            "[approval] list_requires_approval is not in this version; list needs no approval"
                .into(),
        );
    }
    if !c.audit.sink.is_empty() {
        w.push("[[audit.sink]] is not in this version; only the audit files are written".into());
    }
    w
}

/// The config for `init` and `recover`: the file if it exists (or was named
/// with `--config`), else the built-in defaults.
fn optional_config(paths: &Paths) -> Result<Config, String> {
    if !paths.config_given && !paths.config.exists() {
        return Ok(Config::default());
    }
    Config::load(&paths.config)
        .map(|l| l.config)
        .map_err(|e| format!("config {}: {e}", paths.config.display()))
}

/// The audit directory: `[audit] dir`, else `audit/` in the state directory.
pub fn audit_dir(config: &Config, state_dir: &Path) -> PathBuf {
    config
        .audit
        .dir
        .clone()
        .unwrap_or_else(|| state_dir.join("audit"))
}

/// Opens the audit log with the config's checkpoint settings.
pub fn open_audit(
    config: &Config,
    state_dir: &Path,
    host: &str,
    boot_id: &str,
    clock: Arc<dyn Clock>,
) -> Result<AuditLog, String> {
    let dir = audit_dir(config, state_dir);
    let mut opts = audit::Options::new(host, boot_id);
    opts.checkpoint_every_records = config.audit.checkpoint_every_records;
    opts.checkpoint_interval = config.audit.checkpoint_interval;
    AuditLog::open(&dir, opts, clock).map_err(|e| format!("audit log {}: {e}", dir.display()))
}

/// The master key from the credential (or, in test builds, a plain file).
pub fn master_key(paths: &Paths) -> Result<MasterKey, String> {
    let Some(path) = &paths.master_key else {
        return Err(format!(
            "no master key: $CREDENTIALS_DIRECTORY is not set; run cnd from countersign.service \
             (LoadCredentialEncrypted={})",
            crate::MK_CREDENTIAL
        ));
    };
    MasterKey::read(path).map_err(|e| format!("master key: {e}"))
}

/// `/etc/machine-id`.
pub fn machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".into())
}

/// `/proc/sys/kernel/random/boot_id`.
pub fn boot_id() -> Result<String, String> {
    countersign_core::sessions::ProcFs::default()
        .boot_id()
        .map_err(|e| e.to_string())
}

/// Refuses to run as root, or (outside test mode) as a uid the config lets
/// connect: the store must not belong to the agent's uid.
pub fn check_own_uid(paths: &Paths, uids: Option<&BTreeSet<u32>>) -> Result<(), String> {
    let me = rustix::process::geteuid().as_raw();
    if paths.insecure {
        return Ok(());
    }
    if me == 0 {
        return Err("cnd does not run as root; it runs as the countersign user".into());
    }
    if uids.is_some_and(|u| u.contains(&me)) {
        return Err(format!(
            "cnd runs as uid {me}, which [access] users lets connect; it must run as its own \
             user (countersign) so clients cannot read the store"
        ));
    }
    Ok(())
}

/// `cnd init`.
pub fn init(paths: &Paths) -> Result<(), String> {
    check_own_uid(paths, None)?;
    let config = optional_config(paths)?;
    let state = &paths.state_dir;
    if state.join(STORE_FILE).exists() {
        return Err(format!(
            "a store already exists in {}; cnd init only creates a new one",
            state.display()
        ));
    }
    let adir = audit_dir(&config, state);
    if adir.join(audit::PUBKEY_FILE).exists() {
        return Err(format!(
            "{} holds the audit log of another store; move it away first",
            adir.display()
        ));
    }
    let mk = master_key(paths)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut log = open_audit(&config, state, &machine_id(), &boot_id()?, clock)?;
    let (store, phrase) = Store::init(state, &mk).map_err(|e| e.to_string())?;
    let pubkey = log
        .set_signer(&store.checkpoint_seed())
        .map_err(|e| e.to_string())?;
    log.append(
        None,
        &Event::StoreInit {
            slots: vec!["systemd-creds".into(), "recovery".into()],
        },
    )
    .map_err(|e| e.to_string())?;
    log.checkpoint().map_err(|e| e.to_string())?;

    let text = Zeroizing::new(format!(
        "countersign store created in {}.\n\n\
         Recovery phrase. Write it on paper now and keep it away from this machine;\n\
         it is shown only this once, and you need it if this machine's key is lost:\n\n\
         \x20   {phrase}\n\n\
         Audit checkpoint public key: {pubkey}\n",
        state.display()
    ));
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| format!("writing the recovery phrase: {e}"))
}

/// `cnd recover`.
pub fn recover(paths: &Paths) -> Result<(), String> {
    check_own_uid(paths, None)?;
    let config = optional_config(paths)?;
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(1024)
        .read_to_end(&mut input)
        .map_err(|e| format!("reading the recovery phrase from stdin: {e}"))?;
    let text = std::str::from_utf8(&input).map_err(|_| "the recovery phrase is not text")?;
    let phrase: RecoveryPhrase = text
        .trim()
        .parse()
        .map_err(|e| format!("recovery phrase: {e}"))?;
    let mk = master_key(paths)?;
    let store = Store::recover(&paths.state_dir, &phrase, &mk).map_err(|e| e.to_string())?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut log = open_audit(&config, &paths.state_dir, &machine_id(), &boot_id()?, clock)?;
    log.set_signer(&store.checkpoint_seed())
        .map_err(|e| e.to_string())?;
    log.append(
        None,
        &Event::KeyslotAdd {
            slot: "systemd-creds".into(),
            credential_id: None,
            request_id: None,
        },
    )
    .map_err(|e| e.to_string())?;
    log.checkpoint().map_err(|e| e.to_string())?;
    writeln!(
        std::io::stdout().lock(),
        "recovered: the store in {} now opens with this machine's master key",
        paths.state_dir.display()
    )
    .map_err(|e| e.to_string())
}
