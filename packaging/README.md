# Installing countersign

`install.sh` installs countersign on one Linux machine: the binaries, the
daemon's user and units, the polkit actions, the config, the master key, the
store, and the approval factor you choose. `uninstall.sh` takes it out again.
Both print every action, and `--dry-run` prints the plan without changing
anything.

countersign is in Phase 1 and has not been reviewed. Do not store real
secrets in it yet.

## Requirements

- Linux 6.5 or later (`cnd` uses `SO_PEERPIDFD` and refuses to start without it).
- systemd 253 or later, running as init (`Type=notify-reload`, `systemd-creds`, `LoadCredentialEncrypted=`).
- polkit 0.114 or later (action owners). The touch factors need polkit 125 or
  later, which runs its PAM helper as `polkit-agent-helper@.service`.
- A graphical session with a polkit agent (GNOME Shell on Wayland is what has
  been tested). The approval dialog is drawn there.
- For the touch factors: a FIDO security key (a YubiKey) and `pam_u2f`. On
  openSUSE the script installs `pam_u2f` with zypper; elsewhere install it first.

## Install

Build as yourself, never as root:

```console
$ cargo build --release --locked
```

Then, from a terminal you opened yourself (not a Claude Code `!` command:
those have no terminal, and the recovery phrase would land in the transcript):

```console
$ sudo packaging/install.sh --dry-run --factor touch    # read the plan
$ sudo packaging/install.sh --factor touch
```

| Option | Meaning |
| --- | --- |
| `--factor password\|touch\|touch+password` | What the polkit dialog asks for. Default `password`. See below. |
| `--user NAME` | The developer who uses countersign. Default: the user who ran `sudo`. |
| `--bin-dir DIR` | Where `cn` and `cnd` were built. Default `target/release`. |
| `--dry-run` | Print every action and change nothing. Needs no root. |
| `--force` | Replace an existing `/etc/countersign/config.toml` (kept as `config.toml.bak`), a `/etc/pam.d/polkit-1` that countersign did not write (kept as `polkit-1.countersign-bak`), and an existing key enrolment. |

Every step is safe to repeat: run the script again to upgrade the binaries
or to change the factor.

### What it does

1. Checks the kernel, systemd, polkit, the built binaries and the user, and
   for a touch factor the polkit helper unit, `pam_u2f` and a terminal for
   enrolment. It changes nothing until every check passes.
2. Installs `/usr/bin/cn` and `/usr/libexec/countersign/cnd` (root, 0755) and
   prints their SHA-256. The build directory belongs to your uid, so anything
   running as you could have changed the files; compare the sums with your
   build.
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
   does not list you.
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
| `touch` | A touch of your security key, nothing else. No key, no approval. | `/etc/pam.d/polkit-1`: `auth [success=done default=die] pam_u2f.so ...` replaces the auth lines. |
| `touch+password` | A key touch, then your password. | `/etc/pam.d/polkit-1`: `auth requisite pam_u2f.so ...` before the distribution's auth lines. |

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

**The polkit PAM stack is machine-wide.** polkit has one PAM service for every
action, so after a touch install every polkit prompt on the machine (`pkexec`,
GNOME's administrator dialogs, package tools) asks for the same factor. Run
`install.sh --factor password` to go back to your password. `sudo` uses its
own PAM stack and is not affected, so a lost key does not lock you out of
that way back.

With a touch factor, touch the key only while the countersign dialog is on
screen: a touch approves whatever request is pending. If you do not touch it,
GNOME retries every 30 seconds or so and the key keeps blinking; `cnd` closes
the dialog itself after two minutes (`[approvers.polkit] timeout`), and the
request expires.

## Recovery

The recovery phrase opens the store when the machine's key is gone: a new TPM
or motherboard, a reinstall, or a store restored onto another machine.

1. Restore `/var/lib/countersign` from your backup, owned by `countersign`,
   mode 0700.
2. Run `sudo packaging/install.sh`. It sees a store without a master key
   credential, creates a new credential and prints the recovery command.
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

```console
$ sudo packaging/uninstall.sh --dry-run
$ sudo packaging/uninstall.sh            # keeps the store and the master key
$ sudo packaging/uninstall.sh --purge    # deletes them too
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
   the terminal and that it reads `ADD secret smoke-test: install smoke test
   (value 16 to 63 bytes, from stdin, high entropy)`, then approve it with
   your factor.

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

4. Inside that shell, request a grant and approve the dialog:

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
   2 minutes the dialog closes by itself and the command reports the request
   expired (exit 7):

   ```console
   $ cn revoke --all
   $ cn request smoke-test --reason "expiry test" --wait 3m; echo "exit $?"
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

9. With a touch factor, confirm the machine-wide effect: `pkexec true` now
   asks for a key touch too.

If something fails: `systemctl status countersign.socket countersign.service`
and `journalctl -u countersign.service -b`.

## Not done yet

- An RPM spec. Until then this script is the only install path.
