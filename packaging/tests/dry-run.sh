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
# stat: install.sh and trusted-build.sh refuse files a non-root user can
# change. This test's files are the tester's, so stat says root owns, mode
# 0755, every path at, below or above an entry of FAKE_ROOT_OWNED (a ':' list),
# and 0775 for FAKE_GROUP_WRITABLE. Other paths get the real answer.
real_stat=$(command -v stat)
cat >"$stubs/stat" <<EOF
#!/bin/bash
if [ "\$1" = -c ] && [ "\$#" = 4 ]; then
    p=\$4
    if [ -n "\${FAKE_GROUP_WRITABLE:-}" ] && [ "\$p" = "\$FAKE_GROUP_WRITABLE" ]; then
        echo "0 0 775"; exit 0
    fi
    IFS=: read -r -a roots <<<"\${FAKE_ROOT_OWNED:-}"
    for r in "\${roots[@]}"; do
        case \$p/ in "\$r"/*) echo "0 0 755"; exit 0 ;; esac
        case \$r/ in "\${p%/}"/*) echo "0 0 755"; exit 0 ;; esac
    done
fi
exec $real_stat "\$@"
EOF
chmod +x "$stubs"/*
# By default the checkout and the test files count as root-owned.
FAKE_ROOT_OWNED="$(realpath "$pkg/..")":"$(realpath "$tmp")"
export FAKE_ROOT_OWNED
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
not() { ! "$@"; }

# pam_stack: the PAM lines (no comments, no blank lines) of the polkit-1
# stack a dry run would write.
pam_stack() {
    awk '/would write \/etc\/pam\.d\/polkit-1 /{ on = 1; next }
        on && /^    \| / { sub(/^    \| /, ""); if ($0 != "" && $0 !~ /^#/) print; next }
        on { exit }' <<<"$out"
}
# stack_is EXPECTED: the rendered stack is exactly EXPECTED, line by line.
stack_is() {
    if [ "$(pam_stack)" = "$1" ]; then return 0; fi
    diff <(printf '%s\n' "$1") <(pam_stack) | sed 's/^/      /'
    return 1
}

install_args=(--user nobody --bin-dir "$bins")
u2f_opts='pam_u2f.so authfile=/etc/countersign/u2f_mappings origin=pam://countersign appid=pam://countersign cue'
skip='auth       [success=1 default=ignore] pam_succeed_if.so quiet user notin nobody'
vendor_rest='account    include      common-account
password   include      common-password
session    include      common-session
session    optional     pam_keyinit.so revoke [force]'

# The stacks each touch factor writes, from the test's vendor stack. For the
# developer (nobody here): the skip line does not match, so pam_u2f runs;
#   touch: [success=done default=die], the key alone decides;
#   touch+password: [success=ok default=die], then common-auth must pass too.
# For anyone else, root above all: the skip line jumps over pam_u2f, and
# common-auth decides as it did before countersign.
stack_touch="$skip
auth       [success=done default=die] $u2f_opts
auth       include      common-auth
$vendor_rest"
stack_touch_password="$skip
auth       [success=ok default=die]   $u2f_opts
auth       include      common-auth
$vendor_rest"

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
        expect "install touch: the stack, line by line" stack_is "$stack_touch"
        expect "install touch: marked as ours" has "| # countersign-managed: written by countersign packaging/install.sh --factor touch"
        expect "install touch: enrols" has "pamu2fcfg -u nobody -o pam://countersign -i pam://countersign"
        expect "install touch: drop-in" has "DeviceAllow=char-hidraw rw"
        expect "install touch: says root is unchanged" has "administrator prompts still ask for"
        expect "install touch: no claim about every prompt" not has "EVERY"
        ;;
    touch+password)
        expect "install touch+password: the stack, line by line" stack_is "$stack_touch_password"
        expect "install touch+password: never requisite" not has "requisite"
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
expect "foreign polkit-1 with --force: its auth line kept after ours" stack_is "$skip
auth       [success=done default=die] $u2f_opts
auth required pam_unix.so"

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
plan install.sh --factor touch --user 'no:body' --bin-dir "$bins"
expect "user name with ':': refused" not ok

# A tree a non-root user can change.
FAKE_ROOT_OWNED='' plan install.sh "${install_args[@]}"
expect "user-owned tree: refused" not ok
expect "user-owned tree: says why" has "is owned by uid $(id -u), not root"
expect "user-owned tree: points to trusted-build.sh" has "packaging/trusted-build.sh"
FAKE_ROOT_OWNED='' plan install.sh --allow-user-tree "${install_args[@]}"
expect "user-owned tree with --allow-user-tree: exit 0" ok
expect "user-owned tree with --allow-user-tree: warns" has "WARNING: --allow-user-tree"
expect "user-owned tree with --allow-user-tree: sudo note" has "can run sudo without a password"
FAKE_GROUP_WRITABLE=$(realpath "$bins") plan install.sh "${install_args[@]}"
expect "group-writable bin dir: refused" not ok
expect "group-writable bin dir: says why" has "is writable by group"
FAKE_GROUP_WRITABLE=$(realpath "$pkg/..") plan install.sh "${install_args[@]}"
expect "group-writable checkout: refused" not ok
plan install.sh "${install_args[@]}"
expect "root-owned tree: no warning" not has "WARNING: --allow-user-tree"
expect "root-owned tree: says so" has "source and binaries can be changed by root only"
ln -s "$bins" "$tmp/binlink"
plan install.sh --user nobody --bin-dir "$tmp/binlink"
expect "symlinked bin dir: installs from the resolved path" has "would install $(realpath "$bins")/cn -> /usr/bin/cn"
rm "$root/usr/lib/systemd/system/polkit-agent-helper@.service"
plan install.sh --factor touch "${install_args[@]}"
expect "touch without helper unit: refused" not ok
plan install.sh --factor password "${install_args[@]}"
expect "password without helper unit: fine" ok

status=0
out=$(COUNTERSIGN_INSTALL_ROOT=$root PATH="$stubs:$PATH" bash "$pkg/install.sh" "${install_args[@]}" </dev/null 2>&1) || status=$?
expect "test root without --dry-run: refused" not ok

# --- trusted-build ----------------------------------------------------------

commit=0123456789abcdef0123456789abcdef01234567
tree=/usr/local/src/countersign/$commit
clean_env='env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/usr/local/src/countersign/.home CARGO_HOME=/usr/local/src/countersign/.home/cargo LANG=C.UTF-8 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0'

# tb_root [RUSTC_VERSION]: a fake root with git, cargo and rustc.
tb_root() {
    new_root
    mkdir -p "$root/usr/bin" "$root/usr/local/src"
    for tool in git cargo; do
        # shellcheck disable=SC2016 # $* and $CALLS belong to the stub
        printf '#!/bin/sh\necho "%s $*" >>"$CALLS"; exit 99\n' "$tool" >"$root/usr/bin/$tool"
    done
    # trusted-build.sh runs rustc under env -i, so the version is in the file.
    printf '#!/bin/sh\necho "rustc %s (0000000 2026-10-01)"\n' "${1:-1.99.0}" >"$root/usr/bin/rustc"
    chmod +x "$root/usr/bin/git" "$root/usr/bin/cargo" "$root/usr/bin/rustc"
}

tb_root
before=$(snapshot)
plan trusted-build.sh --commit "$commit" --factor touch --user nobody
expect "trusted-build: exit 0" ok
expect "trusted-build: checks itself" has "this script can be changed by root only"
expect "trusted-build: root-owned dirs" has "would run: install -d -o root -g root -m 0755 /usr/local/src/countersign /usr/local/src/countersign/.home"
expect "trusted-build: fresh clone" has "would clone https://github.com/mooselabs/countersign into $tree, check out $commit"
expect "trusted-build: toolchain version" has "rustc 1.99.0 (/usr/bin/rustc)"
expect "trusted-build: rust-version" has "rust-version 1.85: ok"
expect "trusted-build: clean locked build" has "would run: $clean_env /usr/bin/cargo build --locked --release"
expect "trusted-build: installs from its tree" has "would run: $tree/packaging/install.sh --factor touch --user nobody --bin-dir $tree/target/release"
expect "trusted-build: changed nothing" test "$before" = "$(snapshot)"
expect "trusted-build: ran no system tool" test ! -s "$calls"

mkdir -p "$root$tree"
plan trusted-build.sh --commit "$commit"
expect "trusted-build, tree exists: checks it" has "would check $tree: root-owned throughout, HEAD at $commit, no changes"
expect "trusted-build, tree exists: no clone" not has "would clone"

FAKE_ROOT_OWNED='' plan trusted-build.sh --commit "$commit"
expect "trusted-build from a user-owned tree: refused" not ok
expect "trusted-build from a user-owned tree: says why" has "refusing to run from a place a user other than root can change"

tb_root
FAKE_GROUP_WRITABLE=$root/usr/local/src plan trusted-build.sh --commit "$commit"
expect "trusted-build, writable /usr/local/src: refused" not ok
expect "trusted-build, writable /usr/local/src: says why" has "cannot build under /usr/local/src/countersign"

plan trusted-build.sh --commit "${commit:0:12}"
expect "trusted-build, short commit: refused" not ok
expect "trusted-build, short commit: says why" has "full 40-character commit hash"
plan trusted-build.sh --commit "$commit" --bin-dir /tmp
expect "trusted-build --bin-dir: refused" test "$status" = 2
plan trusted-build.sh --commit "$commit" --allow-user-tree
expect "trusted-build --allow-user-tree: refused" test "$status" = 2

rm "$root/usr/bin/cargo"
plan trusted-build.sh --commit "$commit"
expect "trusted-build, no cargo: refused" not ok
expect "trusted-build, no cargo: says how to get it" has "sudo zypper install rust cargo"

tb_root
printf '#!/bin/sh\n' >"$root/usr/bin/rustup"
chmod +x "$root/usr/bin/rustup"
ln -sf rustup "$root/usr/bin/cargo"
plan trusted-build.sh --commit "$commit"
expect "trusted-build, rustup cargo: refused" not ok
expect "trusted-build, rustup cargo: says why" has "rustup's proxy"

tb_root 1.80.2
plan trusted-build.sh --commit "$commit"
expect "trusted-build, old rustc: refused" not ok
expect "trusted-build, old rustc: says how to update" has "older than 1.85, the rust-version this commit needs. Update the distribution's toolchain: sudo zypper install rust cargo"
expect "trusted-build: ran no system tool" test ! -s "$calls"

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
expect "uninstall: checks itself" has "this script can be changed by root only"
plan uninstall.sh --purge
expect "uninstall --purge: deletes the store" has "would run: rm -rf /var/lib/countersign"
expect "uninstall --purge: deletes the key" has "would run: rm -f /etc/credstore.encrypted/countersign-mk"

# Run from a tree a non-root user can change.
FAKE_ROOT_OWNED='' plan uninstall.sh
expect "uninstall from a user-owned tree: refused" not ok
expect "uninstall from a user-owned tree: says why" has "is owned by uid $(id -u), not root"
expect "uninstall from a user-owned tree: points to the trusted tree" has "packaging/trusted-build.sh"
expect "uninstall from a user-owned tree: before any step" not has "== stop and remove the units"
FAKE_ROOT_OWNED='' plan uninstall.sh --allow-user-tree
expect "uninstall from a user-owned tree with --allow-user-tree: exit 0" ok
expect "uninstall from a user-owned tree with --allow-user-tree: warns" has "WARNING: --allow-user-tree"
FAKE_GROUP_WRITABLE=$(realpath "$pkg/..") plan uninstall.sh
expect "uninstall from a group-writable checkout: refused" not ok
expect "uninstall from a group-writable checkout: says why" has "is writable by group"
FAKE_GROUP_WRITABLE=$(realpath "$pkg/../examples/config.toml") plan uninstall.sh
expect "uninstall with a group-writable example config: refused" not ok
expect "uninstall: changed nothing, refusals included" test "$before" = "$(snapshot)"
expect "uninstall: ran no system tool" test ! -s "$calls"

printf '\n'
if [ "$fails" = 0 ]; then
    echo "all dry-run checks passed"
else
    echo "$fails dry-run check(s) failed"
    exit 1
fi
