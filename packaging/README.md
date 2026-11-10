# Installing countersign

`install.sh` installs countersign on one Linux machine: the binaries, the
daemon's user and units, the polkit actions, the config, the master key, the
store, and the approval factor you choose. `uninstall.sh` takes it out again.
Both print every action, and `--dry-run` prints the plan without changing
anything.

countersign is new software. Phase 1 has had one internal security and
correctness review; see [docs/roadmap.md](../docs/roadmap.md).

## Requirements

- Linux 6.5 or later (`cnd` uses `SO_PEERPIDFD` and refuses to start without it).
- systemd 253 or later, running as init (`Type=notify-reload`, `systemd-creds`, `LoadCredentialEncrypted=`).
- polkit 0.114 or later (action owners). The touch factors need polkit 125 or
  later, which runs its PAM helper as `polkit-agent-helper@.service`.
- A graphical session with a polkit agent (GNOME Shell on Wayland is what has
  been tested). The approval dialog is drawn there.
- For the touch factors: a FIDO security key (a YubiKey) and `pam_u2f`. On
  openSUSE the script installs `pam_u2f` with zypper; elsewhere install it first.
- For a release: x86_64, `curl`, `tar`, `gzip`, `sha256sum` and `sudo`, and
  `gh`, logged in, to check the build provenance. For a build from source:
  `git` and the distribution's Rust toolchain.

## Install

`install.sh` runs as root. Whoever can change the files it installs or runs
(the script, the units, the policy, the binaries) can run code as root
through it. In your own checkout that is anything running as you, agents
included, and also your `~/.cargo` toolchain and any `rustc` wrapper. So
`install.sh` refuses a source tree or binaries that a user other than root
can change. There are two ways to give it a root-owned tree:

- **From a release**, with the one-line installer: it downloads the
  binaries GitHub Actions built for a release tag, checks them, and runs
  the release's `install.sh`. Quick, and it needs no Rust toolchain.
- **From source**, with `trusted-build.sh`: as root, it clones a commit you
  name and builds it with the distribution's Rust toolchain. Slower, and it
  trusts less (below).

Either way, run it from a terminal you opened yourself, not a Claude Code
`!` command: those have no terminal, and the recovery phrase would land in
the transcript. Both are safe to run again, to upgrade or to change the
factor.

### From a release

As yourself, not as root (it uses `sudo` for the root steps):

```console
$ curl -fsSL https://github.com/mooselabs/countersign/releases/latest/download/install.sh | bash -s -- --dry-run
$ curl -fsSL https://github.com/mooselabs/countersign/releases/latest/download/install.sh | bash -s -- --factor touch
```

The first line downloads and checks the release as you, without `sudo`, and
prints `install.sh`'s plan. The second installs. Leave out `--factor touch`
for the default factor, `password`.

The installer (`packaging/get.sh` in the repository, published with each
release as `install.sh`) is one function called on its last line, so a
download cut short runs nothing. It:

1. Checks Linux on x86_64, kernel 6.5 or later, systemd as init, `curl`,
   `tar`, `gzip`, `sha256sum` and `sudo`, that it is not running as root,
   and, for a real run, that there is a terminal (`/dev/tty`).
2. Finds the release: `--version vX.Y.Z`, or the latest, from where
   `https://github.com/mooselabs/countersign/releases/latest` redirects (no
   GitHub API).
3. Downloads `SHA256SUMS` and `countersign-<version>-x86_64-linux.tar.gz`
   with `sudo curl` into a directory `sudo mktemp -d` made (root, 0700), so
   nothing running as you can change them once they are down.
4. Checks the tarball's SHA-256, as root, against its one line in
   `SHA256SUMS`.
5. Checks the build provenance, if `gh` is installed and logged in:
   `gh attestation verify` with `--repo mooselabs/countersign`,
   `--signer-workflow mooselabs/countersign/.github/workflows/release.yml`,
   `--source-ref refs/tags/<tag>` and `--deny-self-hosted-runners`, on a
   copy you can read. A failure stops the install. Without `gh` it says in
   one line that provenance was not checked and how to check it by hand;
   `--require-attestation` makes that an error.
6. Checks that the tarball holds only files and directories under
   `countersign-<version>/`, extracts it as root with `--no-same-owner`,
   and refuses a file that is setuid, setgid or writable by group or
   others.
7. Moves the tree to `/usr/local/src/countersign/v<version>` (root-owned,
   replacing an older copy of the same version) and runs its
   `packaging/install.sh` with `sudo`, `--user` you, `--bin-dir` the tree's
   `bin/`, and stdin from your terminal. That tree is the one to uninstall
   from.

If countersign is already installed, this is an upgrade: without
`--factor` it keeps the factor installed now (read from
`/etc/pam.d/polkit-1`), and `install.sh` keeps the store, the master key and
a config you changed. It never runs `cnd init` over a store.

| Option | Meaning |
| --- | --- |
| `--version vX.Y.Z` | The release to install. Default: the latest. |
| `--factor password\|touch\|touch+password` | Passed to `install.sh`. Default: the factor already installed, else `password`. |
| `--force` | Passed to `install.sh` (see its options below). |
| `--dry-run` | Download and check as you, without `sudo`, into a directory of yours, then run `install.sh --dry-run` (with `--allow-user-tree`, since you extracted it). Installs nothing. |
| `--require-attestation` | Fail when the provenance cannot be checked. |
| `--base-url URL` | For tests only: take the release files from `URL` (`file://`, `https://`, or `http://` to localhost), a directory laid out like one release's downloads. Needs `--version`. |

**What it trusts.** The one-liner trusts GitHub (it serves the script, the
release files and the attestations, and runs the build), the release
workflow (`.github/workflows/release.yml`, the actions it pins, the
`stable` Rust toolchain it downloads, and the crates `Cargo.lock` pins),
TLS (curl's certificate store), and the shell you paste it into: whatever
`curl`, `bash` and `sudo` resolve to there runs, and an agent that can
change your shell's startup files or `PATH` can change that. The
attestation shows that the tarball was built by the release workflow of
`mooselabs/countersign` from the tag's commit; it does not show that the
workflow or the code is sound. Without `gh`, `SHA256SUMS` comes from the
same place as the tarball, so it catches a broken download, not a changed
one.

`trusted-build.sh` trusts less: a commit hash you check yourself on
github.com, and the distribution's Rust toolchain. GitHub, TLS and the
release workflow cannot change what it builds; git checks every object
against the hash, and cargo checks every crate against `Cargo.lock`. It still
runs through `sudo` in your shell, like the one-liner.

To check a release by hand, as yourself:

```console
$ v=0.1.0
$ curl -fsSLO https://github.com/mooselabs/countersign/releases/download/v$v/countersign-$v-x86_64-linux.tar.gz
$ curl -fsSLO https://github.com/mooselabs/countersign/releases/download/v$v/SHA256SUMS
$ sha256sum --check --ignore-missing SHA256SUMS
$ gh attestation verify countersign-$v-x86_64-linux.tar.gz --repo mooselabs/countersign \
    --signer-workflow mooselabs/countersign/.github/workflows/release.yml --source-ref refs/tags/v$v
```

The tarball has `bin/cn`, `bin/cnd`, `packaging/` (`install.sh`,
`uninstall.sh` and the files they install), `examples/config.toml`,
`CHANGELOG.md`, `LICENSE`, `NOTICE` and `README.md`, under one top
directory. Its `install.sh` finds the binaries in `bin/` by itself. The
release workflow builds on Ubuntu 22.04 (glibc 2.35), checks that `cn` and
`cnd` link only glibc, and makes the tarball with
`packaging/make-release-tarball.sh`, which gives the same bytes for the
same inputs.

### From source: trusted-build.sh

As root, `trusted-build.sh` clones a commit you name into
`/usr/local/src/countersign/<commit>` (root-owned), builds it there with the
distribution's Rust toolchain (`/usr/bin/cargo`, an empty environment, no
user config, `--locked`), and runs that tree's `install.sh`.

#### Where the source comes from

By default root clones `https://github.com/mooselabs/countersign`
anonymously. What makes the build safe is **the commit hash**: git checks
every object it reads against its hash, so the tree root builds is exactly
the commit you named, whoever served it. So take the hash from somewhere an
agent cannot change: the commit's page on github.com in your browser
(`https://github.com/mooselabs/countersign/commit/<hash>`), or `git log` in a
clone on a machine no agent can reach.

With `--bundle FILE`, root clones from a **git bundle** you made as
yourself instead, for example for a commit root cannot fetch from GitHub. A
bundle is plain data: the commits and files, with no repository config and
no hooks, so reading it runs nothing of yours. `trusted-build.sh` copies it
to a root-owned file first (and refuses a symbolic link), then clones that
copy with git's object checks on, checks out the commit, and checks that
`HEAD` is that commit and that `git fsck` passes. Your checkout and the
bundle can be changed by an agent running as you; the commit hash still
decides what is built.

Root needs the network for one step: `cargo fetch --locked` downloads the
locked dependencies from crates.io, and cargo checks each one against its
checksum in `Cargo.lock`. The build after it runs with `--offline`.

#### First install

`trusted-build.sh` refuses to run from a place another user can change, your
checkout included, so the first run needs a root-owned copy of the script
itself. These steps make one in `/root/countersign-bootstrap` (`/root` is
root's, mode 0700). The shell lines are bash; in fish, write `set c <hash>`
for `c=<hash>`.

```console
$ sudo zypper install rust cargo git     # the distribution's toolchain (rust 1.99), once
$ c=<the full hash from the commit's page on github.com>
$ sudo env -i PATH=/usr/bin:/bin git -c transfer.fsckObjects=true -c fetch.fsckObjects=true \
    clone -q --no-checkout https://github.com/mooselabs/countersign /root/countersign-bootstrap
$ sudo env -i PATH=/usr/bin:/bin git -C /root/countersign-bootstrap checkout -q --detach $c
$ sudo env -i PATH=/usr/bin:/bin git -C /root/countersign-bootstrap rev-parse HEAD    # must print $c
$ sudo env -i PATH=/usr/bin:/bin git -C /root/countersign-bootstrap fsck --full --strict --no-dangling
$ sudo /root/countersign-bootstrap/packaging/trusted-build.sh --commit $c --factor touch --dry-run
$ sudo /root/countersign-bootstrap/packaging/trusted-build.sh --commit $c --factor touch
$ sudo rm -rf /root/countersign-bootstrap
```

From a bundle, make it first and use it in both places:

```console
$ git -C ~/projects/moose/countersign bundle create /tmp/countersign.bundle main
$ sudo env -i PATH=/usr/bin:/bin git -c transfer.fsckObjects=true -c fetch.fsckObjects=true \
    clone -q --no-checkout /tmp/countersign.bundle /root/countersign-bootstrap
$ ...
$ sudo /root/countersign-bootstrap/packaging/trusted-build.sh --commit $c \
    --bundle /tmp/countersign.bundle --factor touch
```

The bundle must contain the commit: make it from a branch or tag that does
(`git bundle create` refuses a bare commit hash).

The bootstrap copy only runs `trusted-build.sh`. That script clones again
into `/usr/local/src/countersign/$c`, builds there and installs from there;
that tree is the one to use from now on, for upgrades and for uninstall.
The bootstrap copy can go once the install is done.

#### Upgrade

Run the `trusted-build.sh` of the installed tree with the new commit (and
`--bundle` if you use one). It clones the new commit fresh:

```console
$ sudo /usr/local/src/countersign/<old>/packaging/trusted-build.sh --commit <new> --factor touch
```

You can switch between the two ways at any time; each install replaces the
binaries and keeps the store. Uninstall from the tree of the last install.

### Options

`trusted-build.sh` takes `--commit` (required), `--bundle FILE`,
`--dry-run`, and passes `--factor`, `--user` and `--force` on to
`install.sh`. If `/usr/local/src/countersign/<commit>` already exists it does
not clone again: it checks that tree (root-owned throughout, no changes,
`HEAD` at the commit, `git fsck` passes) and builds in it. Old trees under
`/usr/local/src/countersign` can be removed with `sudo rm -rf`, except the
one you installed from, which `uninstall.sh` runs from.

| `install.sh` option | Meaning |
| --- | --- |
| `--factor password\|touch\|touch+password` | What the polkit dialog asks for. Default `password`. See below. |
| `--user NAME` | The developer who uses countersign. Default: the user who ran `sudo`. |
| `--bin-dir DIR` | Where `cn` and `cnd` are. Default: `bin/` in a release tarball, else `target/release`. The one-liner and `trusted-build.sh` set it. |
| `--dry-run` | Print every action and change nothing. Needs no root. |
| `--force` | Replace an existing `/etc/countersign/config.toml` (kept as `config.toml.bak`), a `/etc/pam.d/polkit-1` that countersign did not write (kept as `polkit-1.countersign-bak`), and an existing key enrolment. |
| `--allow-user-tree` | Install from a tree or binaries another user can change, for example your checkout after `cargo build --release --locked`. It prints why that is unsafe. While your user can run `sudo` without a password, an agent running as you can become root anyway, and this check protects nothing until that is removed. |

Every step is safe to repeat: run it again to upgrade the binaries or to
change the factor.

### What it does

1. Checks the kernel, systemd, polkit, the built binaries and the user, and
   for a touch factor the polkit helper unit, `pam_u2f` and a terminal for
   enrolment. Checks that root alone can change the script, the files next
   to it and the binaries: each file and every directory above it is owned
   by root and writable by no group and no other user (`--allow-user-tree`
   skips this with a warning). It changes nothing until every check passes.
2. Installs `/usr/bin/cn` and `/usr/libexec/countersign/cnd` (root, 0755) and
   prints their SHA-256.
3. Installs `sysusers.d/countersign.conf` and `tmpfiles.d/countersign.conf`
   under `/usr/lib/` and applies them: system user `countersign`, group
   `countersign-users`, `/etc/countersign` (root 0755), `/var/lib/countersign`
   (countersign 0700), `/run/countersign` (root 0755). Adds you to
   `countersign-users`, which gates the socket.
4. Installs `countersign.socket` and `countersign.service` under
   `/usr/lib/systemd/system/` and the polkit actions as
   `/usr/share/polkit-1/actions/computer.mooselabs.countersign.policy`.
5. Copies `examples/config.toml` to `/etc/countersign/config.toml` (root 0644).
   An existing config is kept unless `--force`. It warns if `[access] users`
   does not list you. The service can write only to `/var/lib/countersign`
   (`ProtectSystem=strict`). If you set `[audit] dir` outside it, create the
   directory (owned by `countersign`, mode 0700) and let the service write
   there with a drop-in, `sudo systemctl edit countersign.service`:

   ```ini
   [Service]
   ReadWritePaths=/path/to/audit
   ```
6. Sets up the approval factor (below).
7. Enables `countersign.socket`. `cnd` starts on the first connection.
8. Creates the master key credential if it is missing: 32 random bytes sealed
   with `systemd-creds` (TPM2 when there is one, else the host key) to
   `/etc/credstore.encrypted/countersign-mk`. The service gets it through
   `LoadCredentialEncrypted=countersign-mk`.
9. If there is no store yet, runs `cnd init` as the `countersign` user with
   that credential. It creates the store and the audit log and prints a
   **recovery phrase once**. Write it on paper and keep it away from the
   machine. It is not saved anywhere. It also prints the audit log's
   checkpoint public key; keep a copy off the machine too
   ([docs/audit.md](../docs/audit.md#off-box-export)). This is the last step,
   so both stay on screen.

Then log out and back in (for the group), and run the smoke test below.

### Changing the config

Edit `/etc/countersign/config.toml` as root, then:

```console
$ sudo systemctl reload countersign.service
```

`cnd` re-reads the file and records it in the audit log (`config.load`). A
config that does not load leaves the previous one in force; the reason is in
`journalctl -u countersign.service`. `cnd` refuses a config that is not
root-owned or is writable by group or others. Grants already given keep their
TTL; new limits apply to new requests.

## Approval factors

When an agent asks for a secret, `cnd` asks polkit, and your desktop shows a
dialog that starts with `countersign request K7M-Q2X, digest 3QF8-ZK2M:`. The
factor decides what the dialog wants before it says yes.

| Factor | The dialog asks for | PAM change |
| --- | --- | --- |
| `password` (default) | Your login password. | None. |
| `touch` | A touch of your security key, nothing else. No key, no approval. | `/etc/pam.d/polkit-1`: for you, `auth [success=done default=die] pam_u2f.so ...`, which ends the stack. |
| `touch+password` | A key touch, then your password. | `/etc/pam.d/polkit-1`: for you, `auth [success=ok default=die] pam_u2f.so ...`, then the distribution's auth lines. |

For a touch factor, the two lines go before the distribution's auth lines,
which stay as they are:

```text
auth  [success=1 default=ignore]  pam_succeed_if.so quiet user notin <you>
auth  [success=done default=die]  pam_u2f.so ...    # touch+password: [success=ok default=die]
auth  include                     common-auth
```

The first line skips the key for every user except you, so anyone else,
root included, authenticates exactly as before. Any error in it leads to
the key, never past it. `pam_u2f`'s `nouserok` is not used.

There is no click-only factor. polkit has no confirm-only mode
([polkit#463](https://github.com/polkit-org/polkit/issues/463)), and a prompt
that needs no credential could be answered by an agent that has registered
its own polkit agent (decision 15 in [docs/decisions.md](../docs/decisions.md)).

For a touch factor the script also:

- installs `pam_u2f` with zypper if it is missing (it stays installed after
  uninstall; it does nothing unless a PAM stack uses it);
- enrols your key with `pamu2fcfg` run as you, with origin and appid
  `pam://countersign`, into `/etc/countersign/u2f_mappings` (root 0644, so an
  agent cannot add its own key). Enter the key's PIN if it asks, then touch
  the key when it blinks. This needs a real terminal;
- writes `/etc/systemd/system/polkit-agent-helper@.service.d/countersign-hidraw.conf`,
  which lets polkit's sandboxed PAM helper open the key (`DevicePolicy=auto`,
  `DeviceAllow=char-hidraw rw`, `PrivateDevices=no`);
- writes `/etc/pam.d/polkit-1` from the distribution's `/usr/lib/pam.d/polkit-1`.
  An existing `/etc/pam.d/polkit-1` that countersign did not write is refused
  unless `--force`, which keeps it as `/etc/pam.d/polkit-1.countersign-bak`.

**The factor applies to you, for every polkit action.** polkit has one PAM
service for every action, so after a touch install every polkit prompt that
authenticates as you asks for your factor, countersign's and any other
action that asks for your own credentials. Prompts that authenticate as
another user, root included, keep the distribution's stack. On openSUSE the
administrator identity is root, so `pkexec`, GNOME's administrator dialogs
and package tools still ask for root's password. (If you are an
administrator identity yourself, as members of `wheel` are on some
distributions, those prompts ask for your factor.) Run `install.sh --factor
password` to go back to your password. `sudo` uses its own PAM stack and is
not affected, so a lost key does not lock you out of that way back.

## Memory and swap

`cnd` locks all of its memory (`LimitMEMLOCK=infinity` in the unit), so the
store's values never reach swap from it; its journal says if
locking failed. `cn run`, the commands it starts and your shell are not
locked. If this machine has swap, it should be encrypted: swap inside the
LUKS volume, a swap device with a random key in `/etc/crypttab`, or zram
only. Hibernation writes all memory to swap, so the same applies there.
`swapon --show` and `lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS` show what you
have.

With a touch factor, touch the key only while the countersign dialog is on
screen: a touch approves whatever request is pending. If you do not touch it,
GNOME retries every 30 seconds or so and the key keeps blinking; `cnd` closes
the dialog itself when the request lapses (`[grants] pending_expiry`, 5
minutes by default, or sooner with `[approvers.polkit] timeout`).

## Recovery

The recovery phrase opens the store when the machine's key is gone: a new TPM
or motherboard, a reinstall, or a store restored onto another machine.

1. Restore `/var/lib/countersign` from your backup, owned by `countersign`,
   mode 0700.
2. Install as above, from a release or with `trusted-build.sh`.
   `install.sh` sees a store without a master key credential, creates a new
   credential and prints the recovery command.
3. Stop the daemon: `cnd recover` takes no lock against a running `cnd`.

   ```console
   $ sudo systemctl stop countersign.socket countersign.service
   ```

4. From a terminal you opened yourself, run the recovery command and type the
   phrase:

   ```console
   $ sudo systemd-run --wait --pipe --collect -p User=countersign -p Group=countersign \
       -p StateDirectory=countersign \
       -p LoadCredentialEncrypted=countersign-mk:/etc/credstore.encrypted/countersign-mk \
       /usr/libexec/countersign/cnd recover
   ```

   `cnd recover` reads the phrase from stdin (case, dashes and spaces do not
   matter), opens the store with it, and wraps the store's key again with the
   new master key. The store, the audit log and its checkpoint key stay the
   same.
5. `sudo systemctl start countersign.socket`, then `/usr/bin/cn doctor`.

Without the phrase, a store whose master key is lost cannot be opened.

## Uninstall

Run the copy in the root-owned tree you last installed from,
`/usr/local/src/countersign/v<version>` for a release or
`/usr/local/src/countersign/<commit>` for `trusted-build.sh`, not one in
your checkout: it runs as root too. (The bootstrap copy in `/root` is not
needed for this.) Like
`install.sh`, it refuses to run when it, the files next to it
or the example config it compares against could be changed by a user other
than root; `--allow-user-tree` accepts that, with a warning.

```console
$ sudo /usr/local/src/countersign/<tree>/packaging/uninstall.sh --dry-run
$ sudo /usr/local/src/countersign/<tree>/packaging/uninstall.sh            # keeps the store and the master key
$ sudo /usr/local/src/countersign/<tree>/packaging/uninstall.sh --purge    # deletes them too
```

It stops and removes the units, the binaries, the polkit policy, the
countersign PAM stack (restoring `/etc/pam.d/polkit-1.countersign-bak` if
there is one), the helper drop-in, the key enrolment and the
`countersign-users` group. It removes the config only if it is still the
shipped example. Without `--purge` it keeps `/var/lib/countersign` (store and
audit log), `/etc/credstore.encrypted/countersign-mk` and the `countersign`
user that owns them, so a reinstall finds the store again. `--purge` deletes
those as well; without an export the secrets are gone.

## Smoke test

Run this after installing and logging in again, from a terminal you opened
yourself. It uses a dummy value; nothing here touches a real secret. Each
dialog must start with `countersign request` and show the same code and
digest that the terminal printed.

1. Health check. Every line should be `ok`, except `session`, which warns
   outside an agent session:

   ```console
   $ /usr/bin/cn doctor
   ```

2. Add a dummy secret. A dialog opens: check that its code and digest match
   the terminal and that it reads `ADD secret smoke-test (value 16 to 63
   bytes, from stdin, high entropy): description "install smoke test";
   projects any (all projects)`, then approve it with your factor.

   ```console
   $ printf %s 'smoke-0123456789abcdef' | /usr/bin/cn add smoke-test \
       --description "install smoke test" --high-entropy --from-stdin --wait
   ```

3. Start a stand-in agent under a session (a shell here; `claude` works the
   same), and check the session:

   ```console
   $ cn session exec --label smoke -- bash
   $ cn session
   ```

4. Inside that shell, request a grant and approve the dialog. It must read
   `... agent bash (pid N, registered by cn session exec); agent-reported:
   label "smoke", cwd "<this directory>". Agent's reason: smoke test`, with
   the cwd in quotes:

   ```console
   $ cn request smoke-test --reason "smoke test" --ttl 5m --wait 2m
   $ cn grants
   ```

5. Use it. Both commands must print `[countersign:smoke-test]`, never the value:

   ```console
   $ cn run --use smoke-test -- sh -c 'echo "value: $SMOKE_TEST"'
   $ printf 'value: smoke-0123456789abcdef\n' | cn hide
   ```

6. Revoke, then let a request expire. Do nothing when the dialog opens. After
   5 minutes (`[grants] pending_expiry`) the dialog closes by itself and the
   command reports the request expired (exit 7):

   ```console
   $ cn revoke --all
   $ cn request smoke-test --reason "expiry test" --wait 6m; echo "exit $?"
   ```

7. Cancel a dialog. Press Cancel; the command exits 5 (denied):

   ```console
   $ cn request smoke-test --reason "cancel test" --wait 2m; echo "exit $?"
   ```

8. Leave the stand-in shell (`exit`), then check the audit log and remove the
   dummy secret (approve the dialog):

   ```console
   $ cn audit --since 1h
   $ /usr/bin/cn audit verify
   $ /usr/bin/cn rm smoke-test --wait
   ```

9. With a touch factor, confirm that only your prompts changed: `pkexec true`
   still asks for root's password, not a key touch.

If something fails: `systemctl status countersign.socket countersign.service`
and `journalctl -u countersign.service -b`.

## Not done yet

- An RPM spec. Until then the release installer and `trusted-build.sh` are
  the install paths.
- Release binaries for other architectures than x86_64.
