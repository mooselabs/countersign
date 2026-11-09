#!/bin/bash
# Install countersign on this machine. See packaging/README.md.
#
# Usually run by packaging/trusted-build.sh, which builds a commit in a
# root-owned tree and runs that tree's install.sh. Run directly, from a
# terminal you opened yourself:
#   sudo packaging/install.sh [--factor password|touch|touch+password]
#                             [--user NAME] [--bin-dir DIR] [--dry-run] [--force]
#                             [--allow-user-tree]
#
#   --factor    what the polkit dialog asks for (default password):
#                 password        your login password; PAM is not changed
#                 touch           a security key touch only (pam_u2f)
#                 touch+password  a key touch, then your password
#               The touch factors change polkit's PAM stack for the
#               developer only; every other user, root included, keeps the
#               distribution's stack.
#   --user      the developer who uses countersign (default: $SUDO_USER)
#   --bin-dir   where cn and cnd were built (default: target/release)
#   --dry-run   print every action and change nothing; needs no root
#   --force     replace an existing /etc/countersign/config.toml (kept as
#               config.toml.bak), a /etc/pam.d/polkit-1 countersign did not
#               write (kept as polkit-1.countersign-bak), and an existing key
#               enrolment
#   --allow-user-tree
#               install even though this script, the files next to it or the
#               binaries could be changed by a user other than root (a
#               developer's checkout). Without it, install.sh refuses: it
#               runs as root, so whoever can change those files can run code
#               as root.
#
# Every step is safe to repeat. Run it again to upgrade the binaries or to
# change the factor.
set -euo pipefail

here=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(dirname "$here")
# shellcheck source-path=SCRIPTDIR source=lib/trusted-path.sh
. "$here/lib/trusted-path.sh"

# For tests only: with --dry-run, every system path is read below this prefix.
R=${COUNTERSIGN_INSTALL_ROOT:-}

factor=password
user=${SUDO_USER:-}
bin_dir=$repo/target/release
dry=0
force=0
allow_user_tree=0

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}"
}

while [ $# -gt 0 ]; do
    case $1 in
    --factor) factor=${2:?--factor needs a value}; shift 2 ;;
    --factor=*) factor=${1#*=}; shift ;;
    --user) user=${2:?--user needs a value}; shift 2 ;;
    --user=*) user=${1#*=}; shift ;;
    --bin-dir) bin_dir=${2:?--bin-dir needs a value}; shift 2 ;;
    --bin-dir=*) bin_dir=${1#*=}; shift ;;
    --dry-run) dry=1; shift ;;
    --force) force=1; shift ;;
    --allow-user-tree) allow_user_tree=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'install.sh: unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

# --- paths ------------------------------------------------------------------

cn_dest=/usr/bin/cn
cnd_dest=/usr/libexec/countersign/cnd
unit_dir=/usr/lib/systemd/system
sysusers_conf=/usr/lib/sysusers.d/countersign.conf
tmpfiles_conf=/usr/lib/tmpfiles.d/countersign.conf
policy_dest=/usr/share/polkit-1/actions/computer.mooselabs.countersign.policy
config_dest=/etc/countersign/config.toml
config_src=$repo/examples/config.toml
mk=/etc/credstore.encrypted/countersign-mk
state_dir=/var/lib/countersign
u2f_map=/etc/countersign/u2f_mappings
u2f_origin=pam://countersign
pam_etc=/etc/pam.d/polkit-1
pam_backup=/etc/pam.d/polkit-1.countersign-bak
pam_marker='# countersign-managed'
dropin_dir=/etc/systemd/system/polkit-agent-helper@.service.d
dropin=$dropin_dir/countersign-hidraw.conf

# --- output and actions -----------------------------------------------------

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

current_step=preflight
trap 'printf "\ninstall.sh: stopped during \"%s\". Fix the cause and run it again; every step is safe to repeat.\n" "$current_step" >&2' ERR

# run CMD...: print it, then run it (or only print it in a dry run).
run() {
    if [ "$dry" = 1 ]; then
        printf '  would run:'
    else
        printf '  +'
    fi
    printf ' %q' "$@"
    printf '\n'
    [ "$dry" = 1 ] || "$@"
}

# install_file SRC DEST MODE: copy as root, replacing DEST atomically.
install_file() {
    local src=$1 dest=$2 mode=$3
    if [ "$dry" = 1 ]; then
        note "would install $src -> $dest (root, $mode)"
        return
    fi
    install -d -m 0755 "$(dirname "$dest")"
    install -o root -g root -m "$mode" "$src" "$dest.new"
    mv -f "$dest.new" "$dest"
    note "installed $dest"
}

# write_file DEST MODE < CONTENT: write generated content as root.
write_file() {
    local dest=$1 mode=$2 content tmp
    content=$(cat)
    if [ "$dry" = 1 ]; then
        note "would write $dest (root, $mode):"
        printf '%s\n' "$content" | sed 's/^/    | /'
        return
    fi
    install -d -m 0755 "$(dirname "$dest")"
    tmp=$(mktemp "$dest.XXXXXX")
    printf '%s\n' "$content" >"$tmp"
    chown root:root "$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$dest"
    note "wrote $dest"
}

# exists PATH: true if PATH exists; false if it does not or cannot be seen.
exists() { [ -e "$R$1" ]; }

# visible DIR: false when DIR exists but this user cannot look inside (dry run
# without root), so the plan cannot say whether a file in it exists.
visible() { [ ! -e "$R$1" ] || [ -x "$R$1" ]; }

ours() { [ -f "$R$1" ] && grep -q "^$pam_marker" "$R$1"; }

version_ge() { # version_ge A B: A >= B for integers
    [ "$1" -ge "$2" ]
}

# --- preflight: check everything before changing anything -------------------

case $factor in
password | touch | touch+password) ;;
*) die "--factor must be password, touch or touch+password (got '$factor')" ;;
esac

if [ "$dry" = 0 ]; then
    [ -z "$R" ] || die "COUNTERSIGN_INSTALL_ROOT is for tests and works only with --dry-run"
    [ "$(id -u)" = 0 ] || die "run with sudo (or add --dry-run to see the plan without root)"
fi

step "checks"

rel=$(uname -r)
kmajor=${rel%%.*}
kminor=${rel#*.}
kminor=${kminor%%[!0-9]*}
[[ $kmajor =~ ^[0-9]+$ && $kminor =~ ^[0-9]+$ ]] || die "cannot read the kernel version from '$rel'"
if ! version_ge "$kmajor" 6 || { [ "$kmajor" = 6 ] && ! version_ge "$kminor" 5; }; then
    die "Linux $rel is too old: countersign needs 6.5 or later (cnd uses SO_PEERPIDFD)"
fi
note "kernel $rel"

[ -d "$R/run/systemd/system" ] || die "systemd is not the running init system"
sd_version=$(systemctl --version | awk 'NR == 1 { print $2 }')
[[ $sd_version =~ ^[0-9]+$ ]] || die "cannot read the systemd version"
version_ge "$sd_version" 253 || die "systemd $sd_version is too old: countersign needs 253 or later (Type=notify-reload, systemd-creds)"
for tool in systemd-creds systemd-run systemd-sysusers systemd-tmpfiles; do
    command -v "$tool" >/dev/null || die "$tool not found"
done
note "systemd $sd_version"

command -v pkaction >/dev/null || die "polkit is not installed (pkaction not found)"
pk_version=$(pkaction --version | awk '{ print $NF }')
case $pk_version in
0.*)
    pk_minor=${pk_version#0.}
    pk_minor=${pk_minor%%[!0-9]*}
    if ! [[ $pk_minor =~ ^[0-9]+$ ]] || ! version_ge "$pk_minor" 114; then
        die "polkit $pk_version is too old: countersign needs 0.114 or later (action owners)"
    fi
    ;;
[1-9]*) ;;
*) die "cannot read the polkit version from '$pk_version'" ;;
esac
note "polkit $pk_version"

for bin in cn cnd; do
    [ -x "$bin_dir/$bin" ] ||
        die "$bin_dir/$bin not found. Build with packaging/trusted-build.sh, or as yourself (not as root) with cargo build --release --locked and then --allow-user-tree"
done
# From here on, the resolved directory: nothing can swap a symlink under it.
bin_dir=$(realpath -e -- "$bin_dir")
note "binaries in $bin_dir"
[ -f "$config_src" ] || die "$config_src not found"

# Everything this script installs or runs as root must be changeable by root
# only. In a developer's checkout, anything running as the developer (an
# agent included) could change a binary, a unit or this script, and so run
# code as root at the next install.
untrusted=
for f in "${BASH_SOURCE[0]}" "$here/lib/trusted-path.sh" \
    "$here/sysusers.d/countersign.conf" "$here/tmpfiles.d/countersign.conf" \
    "$here/countersign.socket" "$here/countersign.service" \
    "$here/computer.mooselabs.countersign.policy" "$config_src" \
    "$bin_dir/cn" "$bin_dir/cnd"; do
    untrusted=$(untrusted_reason "$f")
    [ -z "$untrusted" ] || break
done
if [ -z "$untrusted" ]; then
    note "source and binaries can be changed by root only"
elif [ "$allow_user_tree" = 0 ]; then
    die "refusing to install from files a user other than root can change: $untrusted. Anything running as that user, an agent included, could have changed what this script installs or runs as root. Build and install with packaging/trusted-build.sh (packaging/README.md, \"Install\"), or pass --allow-user-tree to accept that"
else
    say ""
    say "  WARNING: --allow-user-tree: $untrusted."
    say "  Anything running as that user, an agent included, could have changed this"
    say "  script, the units, the policy or the binaries, and so runs code as root"
    say "  through this install. packaging/trusted-build.sh avoids that. (While that"
    say "  user can run sudo without a password, an agent running as them can become"
    say "  root anyway, and this check protects nothing until that is removed.)"
    say ""
fi

[ -n "$user" ] || die "no user: run through sudo, or pass --user NAME"
id -u "$user" >/dev/null 2>&1 || die "no such user: $user"
[ "$(id -u "$user")" != 0 ] || die "the developer must not be root; pass --user NAME"
# The name goes into a PAM line and a pam_succeed_if value list (':' separated).
[[ $user =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] || die "user name '$user' has characters this script does not put into a PAM stack"
note "user $user"

# Store and master key. Without root a dry run cannot look inside
# /var/lib/countersign or /etc/credstore.encrypted.
if ! visible "$state_dir"; then
    store=unknown
elif exists "$state_dir/store.v1"; then
    store=present
else
    store=absent
fi
if ! visible "$(dirname "$mk")"; then
    mk_state=unknown
elif exists "$mk"; then
    mk_state=present
else
    mk_state=absent
fi

if [ "$store" = absent ] && [ "$dry" = 0 ] && [ ! -t 1 ]; then
    die "cnd init prints the recovery phrase once, so run install.sh with its output on a terminal, not redirected and not as a Claude Code ! command (those have no terminal and the phrase would enter the transcript)"
fi

touch_factor=0
[ "$factor" = password ] || touch_factor=1

enrol=0
pam_base=
if [ "$touch_factor" = 1 ]; then
    helper=
    for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        if [ -e "$R$d/polkit-agent-helper@.service" ]; then helper=$d; break; fi
    done
    [ -n "$helper" ] || die "polkit-agent-helper@.service not found. The touch factors need polkit 125 or later, which runs its PAM helper as a socket-activated service"
    note "polkit-agent-helper@.service in $helper"

    if command -v pamu2fcfg >/dev/null; then
        note "pam_u2f present"
    elif command -v zypper >/dev/null; then
        note "pam_u2f missing; will install it with zypper"
    else
        die "pam_u2f is not installed and zypper was not found. Install pam_u2f (pam_u2f.so and pamu2fcfg) with your package manager, then run again"
    fi

    if [ "$force" = 1 ] || ! grep -q "^$user:" "$R$u2f_map" 2>/dev/null; then
        enrol=1
        if [ "$dry" = 0 ] && [ ! -t 0 ]; then
            die "enrolling the security key needs a terminal (the key may ask for its PIN). Run install.sh from a terminal, not as a Claude Code ! command"
        fi
    fi

    # Choose the stack the countersign file is built from.
    if exists "$pam_etc" && ! ours "$pam_etc"; then
        [ "$force" = 1 ] ||
            die "$pam_etc exists and was not written by countersign. Check it, then run again with --force to back it up to $pam_backup and replace it"
        pam_base=$pam_etc
    elif exists "$pam_backup"; then
        pam_base=$pam_backup
    else
        for f in /usr/lib/pam.d/polkit-1 /usr/share/pam.d/polkit-1; do
            if exists "$f"; then pam_base=$f; break; fi
        done
    fi
    [ -n "$pam_base" ] || die "no polkit-1 PAM stack found to start from (/usr/lib/pam.d/polkit-1)"
    grep -Eq '^[[:space:]]*-?auth[[:space:]]' "$R$pam_base" || die "$pam_base has no auth lines"
    note "PAM stack based on $pam_base"
fi

if [ "$dry" = 1 ]; then
    say ""
    say "Dry run: nothing below is done."
    [ "$store" != absent ] || [ -t 1 ] || note "a real run needs a terminal on stdout (cnd init prints the recovery phrase)"
    [ "$enrol" = 0 ] || [ -t 0 ] || note "a real run needs a terminal on stdin (key enrolment)"
fi

# --- binaries ---------------------------------------------------------------

current_step=binaries
step "binaries"
install_file "$bin_dir/cn" "$cn_dest" 0755
install_file "$bin_dir/cnd" "$cnd_dest" 0755
if [ "$dry" = 1 ]; then
    note "sha256 of the files that would be installed:"
    sha256sum "$bin_dir/cn" "$bin_dir/cnd" | sed 's/^/    /'
else
    note "sha256 of the installed files:"
    sha256sum "$cn_dest" "$cnd_dest" | sed 's/^/    /'
fi

# --- user, group, directories -----------------------------------------------

current_step="user, group and directories"
step "user, group and directories"
install_file "$here/sysusers.d/countersign.conf" "$sysusers_conf" 0644
run systemd-sysusers "$sysusers_conf"
install_file "$here/tmpfiles.d/countersign.conf" "$tmpfiles_conf" 0644
run systemd-tmpfiles --create "$tmpfiles_conf"
relogin=0
if id -nG "$user" | tr ' ' '\n' | grep -qx countersign-users; then
    note "$user is already in countersign-users"
else
    run usermod -a -G countersign-users "$user"
    relogin=1
fi

# --- units and polkit policy ------------------------------------------------

current_step="units and polkit policy"
step "systemd units and polkit policy"
install_file "$here/countersign.socket" "$unit_dir/countersign.socket" 0644
install_file "$here/countersign.service" "$unit_dir/countersign.service" 0644
install_file "$here/computer.mooselabs.countersign.policy" "$policy_dest" 0644
run systemctl daemon-reload

# --- config -----------------------------------------------------------------

current_step=config
step "config"
config_now=$config_src
if ! exists "$config_dest"; then
    install_file "$config_src" "$config_dest" 0644
elif cmp -s "$config_src" "$R$config_dest"; then
    note "$config_dest is already the shipped example"
elif [ "$force" = 1 ]; then
    run cp -p "$config_dest" "$config_dest.bak"
    install_file "$config_src" "$config_dest" 0644
else
    note "keeping $config_dest: it differs from examples/config.toml (--force replaces it and keeps $config_dest.bak)"
    config_now=$R$config_dest
fi
if ! grep -Eq "^[[:space:]]*users[[:space:]]*=.*\"$user\"" "$config_now"; then
    note "WARNING: [access] users in $config_dest does not list \"$user\"; cnd will refuse $user until you add it"
fi

# --- approval factor --------------------------------------------------------

current_step="approval factor"
step "approval factor: $factor"

u2f_line() {
    local control=$1
    printf 'auth       %-26s pam_u2f.so authfile=%s origin=%s appid=%s cue\n' \
        "$control" "$u2f_map" "$u2f_origin" "$u2f_origin"
}

# render_pam BASE: the countersign polkit-1 stack. It is BASE unchanged, with
# two lines put before BASE's first auth line, so that only $user needs the
# key and every other user authenticates exactly as BASE says. That matters
# most for root: polkit's administrator prompts (pkexec, desktop settings,
# package tools) authenticate as root on openSUSE, and root has no key.
#
#   auth [success=1 default=ignore] pam_succeed_if.so quiet user notin $user
#     success: the user being authenticated is not $user. Jump over the one
#       pam_u2f line to BASE's auth lines. A jump does not set the result of
#       the auth stack, so BASE's lines alone decide, as without countersign.
#     default=ignore: every other return (PAM_AUTH_ERR when the user is
#       $user, and also any error) leaves the result unset and goes on to
#       pam_u2f. An error can therefore only put a user in front of the key;
#       it can never let $user skip it. ("user in $user" with a jump on
#       failure would do the opposite.) quiet: no log line per prompt.
#   touch: auth [success=done default=die] pam_u2f.so ...
#     done: a key touch is enough; the stack returns success at once and
#       BASE's lines do not run for $user.
#     die: any other return, PAM_IGNORE included, fails the stack at once,
#       so $user can never fall back to the password.
#   touch+password: auth [success=ok default=die] pam_u2f.so ...
#     ok: record the touch and go on to BASE's lines, which must pass too
#       (their required pam_unix asks for the password).
#     die: as above. Not "requisite", which is ignore=ignore: a PAM_IGNORE
#       from pam_u2f would leave the password alone to decide.
# pam_u2f's nouserok is not used: the first line, not the mapping file,
# decides who needs a key.
render_pam() {
    local base=$1 control
    if [ "$factor" = touch ]; then
        control='[success=done default=die]'
    else
        control='[success=ok default=die]'
    fi
    printf '#%%PAM-1.0\n'
    printf '%s: written by countersign packaging/install.sh --factor %s\n' "$pam_marker" "$factor"
    printf '# from %s. polkit uses this stack for every prompt on this\n' "$base"
    printf '# machine. Prompts that authenticate as %s need the security key;\n' "$user"
    printf '# every other user (root, for administrator prompts) authenticates\n'
    printf '# with the lines from %s as before.\n' "$base"
    printf '# Undo with packaging/uninstall.sh or install.sh --factor password.\n'
    awk -v skip="$(printf 'auth       %-26s pam_succeed_if.so quiet user notin %s' '[success=1 default=ignore]' "$user")" \
        -v key="$(u2f_line "$control")" '
        NR == 1 && /^#%PAM-1.0/ { next }
        /^[[:space:]]*-?auth[[:space:]]/ && !done { print skip; print key; done = 1 }
        { print }
    ' "$R$base"
}

remove_touch_factor() {
    if ours "$pam_etc"; then
        if exists "$pam_backup"; then
            run mv -f "$pam_backup" "$pam_etc"
            note "restored your earlier $pam_etc"
        else
            run rm -f "$pam_etc"
            note "polkit uses the distribution's stack again"
        fi
    fi
    if exists "$dropin"; then
        run rm -f "$dropin"
        run rmdir --ignore-fail-on-non-empty "$dropin_dir"
        run systemctl daemon-reload
    fi
}

if [ "$touch_factor" = 0 ]; then
    remove_touch_factor
    note "the countersign dialog asks for $user's login password (polkit's PAM stack is unchanged)"
else
    say ""
    say "  NOTE: polkit has one PAM stack for the whole machine. After this step every"
    say "  polkit prompt that authenticates as $user (countersign's, and any other"
    say "  action that asks for $user's own credentials) asks for: $factor."
    say "  Prompts for other users are unchanged: administrator prompts still ask for"
    say "  root's password."
    say ""

    if ! command -v pamu2fcfg >/dev/null; then
        run zypper --non-interactive install pam_u2f
    fi

    if [ "$enrol" = 1 ]; then
        if [ "$dry" = 1 ]; then
            note "would enrol the key as $user (needs a terminal):"
            note "  runuser -u $user -- pamu2fcfg -u $user -o $u2f_origin -i $u2f_origin"
            note "would write $u2f_map (root, 0644) with that line, keeping other users' lines"
        else
            say ""
            say ">>> Enrol your security key for $user: enter the key's PIN if asked,"
            say ">>> then touch the key when it blinks."
            install -d -m 0755 "$(dirname "$u2f_map")"
            new=$(mktemp "$u2f_map.XXXXXX")
            if ! runuser -u "$user" -- pamu2fcfg -u "$user" -o "$u2f_origin" -i "$u2f_origin" >"$new.line"; then
                rm -f "$new" "$new.line"
                die "enrolment failed (see the message above). Nothing in PAM was changed. Run again to retry"
            fi
            { grep -v "^$user:" "$u2f_map" 2>/dev/null || true; cat "$new.line"; } >"$new"
            rm -f "$new.line"
            chown root:root "$new"
            chmod 0644 "$new"
            mv -f "$new" "$u2f_map"
            note "enrolled one key for $user in $u2f_map"
        fi
    else
        note "$user already has a key in $u2f_map (--force enrols again)"
    fi

    write_file "$dropin" 0644 <<'EOF'
# countersign: let polkit's PAM helper open FIDO security keys for pam_u2f.
# polkit-agent-helper(8) asks PAM modules that need hardware to ship this.
# Written by countersign packaging/install.sh; removed by uninstall.sh.
[Service]
DevicePolicy=auto
DeviceAllow=char-hidraw rw
PrivateDevices=no
EOF
    run systemctl daemon-reload

    if exists "$pam_etc" && ! ours "$pam_etc"; then
        run cp -p "$pam_etc" "$pam_backup"
        pam_base=$pam_backup
        [ "$dry" = 0 ] || pam_base=$pam_etc
    fi
    render_pam "$pam_base" | write_file "$pam_etc" 0644
fi

# --- enable -----------------------------------------------------------------

current_step="enable the socket"
step "enable the socket"
run systemctl enable --now countersign.socket
# An upgrade: a running cnd picks up the new binary.
run systemctl try-restart countersign.service

# --- master key and store (last, so the phrase stays on screen) -------------

current_step="master key and store"
step "master key and store"
new_mk=0
case $mk_state in
present) note "keeping the existing master key credential $mk" ;;
*)
    if [ "$mk_state" = unknown ]; then
        note "cannot see $(dirname "$mk") without root; a real run creates $mk if it is missing"
    fi
    run install -d -m 0700 "$(dirname "$mk")"
    if [ "$dry" = 1 ]; then
        note "would run: head -c 32 /dev/urandom | systemd-creds encrypt --name=countersign-mk - $mk"
    else
        note "+ head -c 32 /dev/urandom | systemd-creds encrypt --name=countersign-mk - $mk"
        head -c 32 /dev/urandom | systemd-creds encrypt --name=countersign-mk - "$mk"
    fi
    run chmod 0600 "$mk"
    new_mk=1
    ;;
esac

init_cmd=(systemd-run --wait --pipe --collect --quiet
    -p User=countersign -p Group=countersign
    -p StateDirectory=countersign -p StateDirectoryMode=0700
    -p "LoadCredentialEncrypted=countersign-mk:$mk"
    "$cnd_dest" init)

case $store in
present)
    if [ "$new_mk" = 1 ]; then
        say ""
        say "  The store exists but its master key credential was missing, so a new one was"
        say "  made. cnd cannot open the store with it until you recover it with your"
        say "  recovery phrase (packaging/README.md, \"Recovery\"):"
        say "    sudo systemd-run --wait --pipe --collect -p User=countersign -p Group=countersign \\"
        say "      -p StateDirectory=countersign -p LoadCredentialEncrypted=countersign-mk:$mk \\"
        say "      $cnd_dest recover"
    else
        note "store exists; not initialising"
    fi
    ;;
*)
    if [ "$store" = unknown ]; then
        note "cannot see $state_dir without root; a real run initialises the store if there is none"
    fi
    say ""
    say "  cnd init creates the store and prints a RECOVERY PHRASE once. Write it on"
    say "  paper and keep it away from this machine. It is not saved anywhere. You need"
    say "  it if this machine's key is lost (a new TPM, a reinstall, a restore elsewhere)."
    say ""
    run "${init_cmd[@]}"
    ;;
esac

# --- next steps -------------------------------------------------------------

current_step="next steps"
step "done"
[ "$dry" = 0 ] || say "(dry run: nothing was changed)"
[ "$touch_factor" = 0 ] ||
    say "Every polkit prompt that authenticates as $user now asks for: $factor."
say "Next:"
n=1
if [ "$relogin" = 1 ]; then
    say "  $n. Log out and back in, so $user's sessions get the countersign-users group."
    n=$((n + 1))
fi
say "  $n. From a terminal you opened yourself: /usr/bin/cn doctor"
say "  $((n + 1)). Add a test secret; the countersign dialog opens and you approve it there:"
say "       printf %s dummy-value-123 | /usr/bin/cn add smoke-test --description 'install smoke test' --from-stdin --wait"
say "  $((n + 2)). Start agents under a session: cn session exec -- claude"
say "  The full smoke test is in packaging/README.md."
