#!/bin/bash
# Remove countersign from this machine. See packaging/README.md.
#
#   sudo /usr/local/src/countersign/<tree>/packaging/uninstall.sh \
#       [--purge] [--user NAME] [--dry-run] [--allow-user-tree]
#
# Removes the binaries, units, polkit policy, the touch-factor PAM stack (your
# earlier /etc/pam.d/polkit-1 comes back if install.sh had backed it up), the
# polkit helper drop-in, the key enrolment, the countersign-users group, and
# the config if it is still the shipped example.
#
# Kept unless --purge: the store and audit log (/var/lib/countersign), the
# sealed master key (/etc/credstore.encrypted/countersign-mk), the
# countersign user that owns them, and a config you changed. Reinstalling
# then finds the store again.
#
#   --purge    also delete the store, the audit log, the master key, the
#              config and the countersign user. The secrets are gone for good
#              unless you have an export.
#   --user     only for the closing message (default: $SUDO_USER)
#   --dry-run  print every action and change nothing; needs no root
#   --allow-user-tree
#              run even though this script or the files next to it could be
#              changed by a user other than root (a developer's checkout).
#              Without it, uninstall.sh refuses: it runs as root, so whoever
#              can change those files can run code as root. Run the copy in
#              the root-owned tree you installed from instead (a release's
#              /usr/local/src/countersign/v<version>, or the one
#              trusted-build.sh made).
#
# pam_u2f stays installed; it does nothing unless a PAM stack uses it.
set -euo pipefail

here=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(dirname "$here")
# shellcheck source-path=SCRIPTDIR source=lib/trusted-path.sh
. "$here/lib/trusted-path.sh"

# For tests only: with --dry-run, every system path is read below this prefix.
R=${COUNTERSIGN_INSTALL_ROOT:-}

purge=0
dry=0
allow_user_tree=0
user=${SUDO_USER:-}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}"
}

while [ $# -gt 0 ]; do
    case $1 in
    --purge) purge=1; shift ;;
    --dry-run) dry=1; shift ;;
    --allow-user-tree) allow_user_tree=1; shift ;;
    --user) user=${2:?--user needs a value}; shift 2 ;;
    --user=*) user=${1#*=}; shift ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'uninstall.sh: unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

# Same paths as install.sh.
cn_dest=/usr/bin/cn
cnd_dir=/usr/libexec/countersign
unit_dir=/usr/lib/systemd/system
sysusers_conf=/usr/lib/sysusers.d/countersign.conf
tmpfiles_conf=/usr/lib/tmpfiles.d/countersign.conf
policy_dest=/usr/share/polkit-1/actions/computer.mooselabs.countersign.policy
config_dir=/etc/countersign
config_dest=$config_dir/config.toml
config_src=$repo/examples/config.toml
mk=/etc/credstore.encrypted/countersign-mk
state_dir=/var/lib/countersign
u2f_map=$config_dir/u2f_mappings
pam_etc=/etc/pam.d/polkit-1
pam_backup=/etc/pam.d/polkit-1.countersign-bak
pam_marker='# countersign-managed'
dropin_dir=/etc/systemd/system/polkit-agent-helper@.service.d
dropin=$dropin_dir/countersign-hidraw.conf

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() { printf 'uninstall.sh: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

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

exists() { [ -e "$R$1" ] || [ -L "$R$1" ]; }
ours() { [ -f "$R$1" ] && grep -q "^$pam_marker" "$R$1"; }
remove() { if exists "$1"; then run rm -f "$1"; fi; }

if [ "$dry" = 0 ]; then
    [ -z "$R" ] || die "COUNTERSIGN_INSTALL_ROOT is for tests and works only with --dry-run"
    [ "$(id -u)" = 0 ] || die "run with sudo (or add --dry-run to see the plan without root)"
fi
[ "$dry" = 0 ] || say "Dry run: nothing below is done."

# This script runs as root, so it and what it reads to decide must be
# changeable by root only. In a developer's checkout, anything running as
# the developer (an agent included) could change it and run code as root.
# The example config decides whether the installed one is removed.
untrusted=
for f in "${BASH_SOURCE[0]}" "$here/lib/trusted-path.sh" "$config_src"; do
    [ "$f" != "$config_src" ] || [ -e "$f" ] || continue
    untrusted=$(untrusted_reason "$f")
    [ -z "$untrusted" ] || break
done
if [ -z "$untrusted" ]; then
    note "this script can be changed by root only"
elif [ "$allow_user_tree" = 0 ]; then
    die "refusing to run from files a user other than root can change: $untrusted. Anything running as that user, an agent included, could have changed what this script runs as root. Run the uninstall.sh in the root-owned tree you installed from: a release's /usr/local/src/countersign/v<version>, or the one packaging/trusted-build.sh made (packaging/README.md, \"Uninstall\"), or pass --allow-user-tree to accept that"
else
    say ""
    say "  WARNING: --allow-user-tree: $untrusted."
    say "  Anything running as that user, an agent included, could have changed this"
    say "  script, and so runs code as root through it."
    say ""
fi

step "stop and remove the units"
if exists "$unit_dir/countersign.socket" || exists "$unit_dir/countersign.service"; then
    run systemctl disable --now countersign.socket
    run systemctl stop countersign.service
fi
remove "$unit_dir/countersign.socket"
remove "$unit_dir/countersign.service"
run systemctl daemon-reload

step "polkit policy and approval factor"
remove "$policy_dest"
if ours "$pam_etc"; then
    if exists "$pam_backup"; then
        run mv -f "$pam_backup" "$pam_etc"
        note "restored your earlier $pam_etc"
    else
        run rm -f "$pam_etc"
        note "polkit uses the distribution's stack (/usr/lib/pam.d/polkit-1) again"
    fi
elif exists "$pam_etc"; then
    note "leaving $pam_etc: countersign did not write it"
fi
if exists "$dropin"; then
    run rm -f "$dropin"
    run rmdir --ignore-fail-on-non-empty "$dropin_dir"
    run systemctl daemon-reload
fi
remove "$u2f_map"

step "binaries"
remove "$cn_dest"
remove "$cnd_dir/cnd"
if exists "$cnd_dir"; then run rmdir --ignore-fail-on-non-empty "$cnd_dir"; fi

step "config"
if exists "$config_dest"; then
    if [ "$purge" = 1 ]; then
        run rm -f "$config_dest" "$config_dest.bak"
    elif [ -f "$config_src" ] && cmp -s "$config_src" "$R$config_dest"; then
        run rm -f "$config_dest"
    else
        note "keeping $config_dest: you changed it (--purge removes it)"
    fi
fi
if exists "$config_dir"; then run rmdir --ignore-fail-on-non-empty "$config_dir"; fi

step "group, users and directories"
remove "$tmpfiles_conf"
remove "$sysusers_conf"
if getent group countersign-users >/dev/null; then
    run groupdel countersign-users
fi

if [ "$purge" = 1 ]; then
    step "purge: store, audit log, master key, countersign user"
    say "  The store and its audit log are deleted. Without an export the secrets are gone."
    if exists "$state_dir"; then run rm -rf "$state_dir"; fi
    remove "$mk"
    if getent passwd countersign >/dev/null; then run userdel countersign; fi
    if getent group countersign >/dev/null; then run groupdel countersign; fi
else
    step "kept"
    note "$state_dir (store and audit log), $mk (sealed master key) and the countersign"
    note "user that owns them. Reinstall to use them again, or run with --purge to delete them."
fi

step "done"
[ "$dry" = 0 ] || say "(dry run: nothing was changed)"
say "pam_u2f is still installed; it does nothing unless a PAM stack uses it."
[ -z "$user" ] || say "$user's open sessions keep the countersign-users group until they log out."
