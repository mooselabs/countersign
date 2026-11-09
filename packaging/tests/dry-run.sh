#!/bin/bash
# Checks the plans that install.sh and uninstall.sh print with --dry-run,
# against a fake root and stub system tools. Needs no root and changes
# nothing outside a temporary directory. Run: bash packaging/tests/dry-run.sh
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pkg=$(dirname "$here")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fails=0
pass() { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }

# --- fixtures ---------------------------------------------------------------

stubs=$tmp/stubs
bins=$tmp/bins
calls=$tmp/calls.log
mkdir -p "$stubs" "$bins"
: >"$calls"

# Version queries answer; every other call of a system tool is a bug in a
# dry run, so it is logged and fails.
cat >"$stubs/uname" <<'EOF'
#!/bin/sh
echo "${FAKE_KERNEL:-6.8.0-test}"
EOF
cat >"$stubs/systemctl" <<'EOF'
#!/bin/sh
[ "$1" = --version ] && { echo "systemd 256 (256.1)"; echo "+PAM"; exit 0; }
echo "systemctl $*" >>"$CALLS"; exit 99
EOF
cat >"$stubs/pkaction" <<'EOF'
#!/bin/sh
[ "$1" = --version ] && { echo "pkaction version ${FAKE_POLKIT:-126}"; exit 0; }
echo "pkaction $*" >>"$CALLS"; exit 99
EOF
for tool in systemd-creds systemd-run systemd-sysusers systemd-tmpfiles zypper pamu2fcfg \
    usermod runuser groupdel userdel install chmod chown mv cp rm rmdir; do
    # shellcheck disable=SC2016 # $* and $CALLS belong to the stub, not to this script
    printf '#!/bin/sh\necho "%s $*" >>"$CALLS"; exit 99\n' "$tool" >"$stubs/$tool"
done
chmod +x "$stubs"/*
printf '#!/bin/sh\n' >"$bins/cn"
printf '#!/bin/sh\n' >"$bins/cnd"
chmod +x "$bins/cn" "$bins/cnd"

# new_root: a fresh fake root with a systemd system and polkit 126 files.
new_root() {
    root=$tmp/root.$RANDOM$RANDOM
    mkdir -p "$root/run/systemd/system" "$root/usr/lib/pam.d" "$root/usr/lib/systemd/system" "$root/etc/pam.d"
    cat >"$root/usr/lib/pam.d/polkit-1" <<'EOF'
#%PAM-1.0

auth       include      common-auth
account    include      common-account
password   include      common-password
session    include      common-session
session    optional     pam_keyinit.so revoke [force]
EOF
    printf '[Service]\nPrivateDevices=yes\n' >"$root/usr/lib/systemd/system/polkit-agent-helper@.service"
}

snapshot() { (cd "$root" && find . -printf '%p %s %m\n' | sort); }

# plan SCRIPT ARGS...: run a dry run, output in $out, status in $status.
plan() {
    local script=$1
    shift
    status=0
    out=$(CALLS=$calls COUNTERSIGN_INSTALL_ROOT=$root PATH="$stubs:$PATH" \
        bash "$pkg/$script" --dry-run "$@" </dev/null 2>&1) || status=$?
}

has() { grep -qF -- "$1" <<<"$out"; }

expect() { # expect NAME CONDITION...
    local name=$1
    shift
    if "$@"; then pass "$name"; else
        fail "$name"
        printf '%s\n' "$out" | sed 's/^/      | /'
    fi
}

ok() { [ "$status" = 0 ]; }
u2f_then_password() { grep -E -A1 'requisite +pam_u2f' <<<"$out" | grep -Eq 'auth +include +common-auth'; }
not() { ! "$@"; }

install_args=(--user nobody --bin-dir "$bins")
u2f_touch='[success=done default=die] pam_u2f.so authfile=/etc/countersign/u2f_mappings origin=pam://countersign appid=pam://countersign cue'
u2f_req='requisite                  pam_u2f.so authfile=/etc/countersign/u2f_mappings origin=pam://countersign appid=pam://countersign cue'

# --- install: each factor ---------------------------------------------------

for factor in password touch touch+password; do
    new_root
    before=$(snapshot)
    plan install.sh --factor "$factor" "${install_args[@]}"
    expect "install $factor: exit 0" ok
    expect "install $factor: binaries" has "would install $bins/cn -> /usr/bin/cn (root, 0755)"
    expect "install $factor: daemon" has "would install $bins/cnd -> /usr/libexec/countersign/cnd (root, 0755)"
    expect "install $factor: sysusers" has "would run: systemd-sysusers /usr/lib/sysusers.d/countersign.conf"
    expect "install $factor: tmpfiles" has "would run: systemd-tmpfiles --create /usr/lib/tmpfiles.d/countersign.conf"
    expect "install $factor: group" has "would run: usermod -a -G countersign-users nobody"
    expect "install $factor: units" has "-> /usr/lib/systemd/system/countersign.service (root, 0644)"
    expect "install $factor: policy" has "-> /usr/share/polkit-1/actions/computer.mooselabs.countersign.policy (root, 0644)"
    expect "install $factor: config" has "examples/config.toml -> /etc/countersign/config.toml (root, 0644)"
    expect "install $factor: master key" has "head -c 32 /dev/urandom | systemd-creds encrypt --name=countersign-mk - /etc/credstore.encrypted/countersign-mk"
    expect "install $factor: init" has "LoadCredentialEncrypted=countersign-mk:/etc/credstore.encrypted/countersign-mk /usr/libexec/countersign/cnd init"
    expect "install $factor: socket" has "would run: systemctl enable --now countersign.socket"
    expect "install $factor: changed nothing" test "$before" = "$(snapshot)"
    expect "install $factor: ran no system tool" test ! -s "$calls"
    case $factor in
    password)
        expect "install password: no PAM change" not has "pam_u2f.so"
        expect "install password: no drop-in" not has "countersign-hidraw.conf"
        ;;
    touch)
        expect "install touch: touch-only auth line" has "$u2f_touch"
        expect "install touch: vendor auth dropped" not grep -Eq '\| auth +include +common-auth' <<<"$out"
        expect "install touch: keeps account" has "account    include      common-account"
        expect "install touch: enrols" has "pamu2fcfg -u nobody -o pam://countersign -i pam://countersign"
        expect "install touch: drop-in" has "DeviceAllow=char-hidraw rw"
        expect "install touch: machine-wide note" has "EVERY"
        ;;
    touch+password)
        expect "install touch+password: requisite line" has "$u2f_req"
        expect "install touch+password: then the password stack" u2f_then_password
        expect "install touch+password: drop-in" has "PrivateDevices=no"
        ;;
    esac
done

# --- install: existing state ------------------------------------------------

new_root
printf '#%%PAM-1.0\nauth required pam_unix.so\n' >"$root/etc/pam.d/polkit-1"
plan install.sh --factor touch "${install_args[@]}"
expect "foreign polkit-1: refused" not ok
expect "foreign polkit-1: says why" has "was not written by countersign"
plan install.sh --factor touch --force "${install_args[@]}"
expect "foreign polkit-1 with --force: exit 0" ok
expect "foreign polkit-1 with --force: backup" has "would run: cp -p /etc/pam.d/polkit-1 /etc/pam.d/polkit-1.countersign-bak"
expect "foreign polkit-1 with --force: built from it" has "from /etc/pam.d/polkit-1."

new_root
printf '#%%PAM-1.0\n# countersign-managed: test\nauth x\n' >"$root/etc/pam.d/polkit-1"
plan install.sh --factor password "${install_args[@]}"
expect "password after touch: removes our stack" has "would run: rm -f /etc/pam.d/polkit-1"
printf 'x\n' >"$root/etc/pam.d/polkit-1.countersign-bak"
plan install.sh --factor password "${install_args[@]}"
expect "password after touch: restores the backup" has "would run: mv -f /etc/pam.d/polkit-1.countersign-bak /etc/pam.d/polkit-1"

new_root
mkdir -p "$root/etc/countersign" "$root/var/lib/countersign" "$root/etc/credstore.encrypted"
echo 'nobody:abc,def' >"$root/etc/countersign/u2f_mappings"
: >"$root/var/lib/countersign/store.v1"
: >"$root/etc/credstore.encrypted/countersign-mk"
echo '# changed' >"$root/etc/countersign/config.toml"
plan install.sh --factor touch "${install_args[@]}"
expect "reinstall: exit 0" ok
expect "reinstall: keeps enrolment" has "nobody already has a key"
expect "reinstall: keeps the store" has "store exists; not initialising"
expect "reinstall: no init" not has "cnd init"
expect "reinstall: keeps the master key" not has "systemd-creds encrypt"
expect "reinstall: keeps a changed config" has "keeping /etc/countersign/config.toml"
plan install.sh --factor touch --force "${install_args[@]}"
expect "reinstall --force: config backup" has "would run: cp -p /etc/countersign/config.toml /etc/countersign/config.toml.bak"
expect "reinstall --force: enrols again" has "pamu2fcfg -u nobody"

rm "$root/etc/credstore.encrypted/countersign-mk"
plan install.sh "${install_args[@]}"
expect "lost master key: new key" has "systemd-creds encrypt"
expect "lost master key: points to recover" has "cnd recover"

# --- install: refusals ------------------------------------------------------

new_root
plan install.sh --factor click "${install_args[@]}"
expect "bad factor: refused" not ok
plan install.sh --user nobody --bin-dir "$tmp/nowhere"
expect "missing binaries: refused" not ok
expect "missing binaries: says build first" has "cargo build --release --locked"
FAKE_KERNEL=6.4.12 plan install.sh "${install_args[@]}"
expect "kernel 6.4: refused" not ok
expect "kernel 6.4: says why" has "needs 6.5 or later"
FAKE_POLKIT=0.113 plan install.sh "${install_args[@]}"
expect "polkit 0.113: refused" not ok
rm "$root/usr/lib/systemd/system/polkit-agent-helper@.service"
plan install.sh --factor touch "${install_args[@]}"
expect "touch without helper unit: refused" not ok
plan install.sh --factor password "${install_args[@]}"
expect "password without helper unit: fine" ok

status=0
out=$(COUNTERSIGN_INSTALL_ROOT=$root PATH="$stubs:$PATH" bash "$pkg/install.sh" "${install_args[@]}" </dev/null 2>&1) || status=$?
expect "test root without --dry-run: refused" not ok

# --- uninstall --------------------------------------------------------------

new_root
mkdir -p "$root/usr/lib/systemd/system" "$root/var/lib/countersign" "$root/etc/countersign" \
    "$root/etc/credstore.encrypted" "$root/etc/systemd/system/polkit-agent-helper@.service.d"
: >"$root/usr/lib/systemd/system/countersign.socket"
: >"$root/etc/systemd/system/polkit-agent-helper@.service.d/countersign-hidraw.conf"
printf '#%%PAM-1.0\n# countersign-managed: test\n' >"$root/etc/pam.d/polkit-1"
printf 'theirs\n' >"$root/etc/pam.d/polkit-1.countersign-bak"
cp "$pkg/../examples/config.toml" "$root/etc/countersign/config.toml"
: >"$root/etc/credstore.encrypted/countersign-mk"
before=$(snapshot)
plan uninstall.sh
expect "uninstall: exit 0" ok
expect "uninstall: stops the socket" has "would run: systemctl disable --now countersign.socket"
expect "uninstall: restores PAM" has "would run: mv -f /etc/pam.d/polkit-1.countersign-bak /etc/pam.d/polkit-1"
expect "uninstall: drop-in" has "would run: rm -f /etc/systemd/system/polkit-agent-helper@.service.d/countersign-hidraw.conf"
expect "uninstall: unchanged config removed" has "would run: rm -f /etc/countersign/config.toml"
expect "uninstall: keeps the store" not has "rm -rf /var/lib/countersign"
expect "uninstall: keeps the key" not has "rm -f /etc/credstore.encrypted/countersign-mk"
expect "uninstall: changed nothing" test "$before" = "$(snapshot)"
plan uninstall.sh --purge
expect "uninstall --purge: deletes the store" has "would run: rm -rf /var/lib/countersign"
expect "uninstall --purge: deletes the key" has "would run: rm -f /etc/credstore.encrypted/countersign-mk"
expect "uninstall: ran no system tool" test ! -s "$calls"

printf '\n'
if [ "$fails" = 0 ]; then
    echo "all dry-run checks passed"
else
    echo "$fails dry-run check(s) failed"
    exit 1
fi
