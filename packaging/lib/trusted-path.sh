# shellcheck shell=bash
# Sourced by install.sh, uninstall.sh and trusted-build.sh, which run as
# root. Not run on its own.

# untrusted_reason PATH: prints why a user other than root could change PATH,
# or nothing when only root can. PATH is resolved first (symlinks followed),
# and it and every directory above it, up to /, must be owned by root and
# writable by no group and no other user. The one exception is a sticky,
# world-writable directory above PATH (/tmp): there no other user can rename
# or remove the root-owned entry below it.
#
# Group-writable is refused even for group root: an ACL's mask shows as the
# group bits, so a writable group could hide a named user with write access.
untrusted_reason() {
    local p uid gid mode leaf=1
    if ! p=$(realpath -e -- "$1" 2>/dev/null); then
        printf '%s does not exist' "$1"
        return
    fi
    while :; do
        read -r uid gid mode <<<"$(stat -c '%u %g %a' -- "$p")"
        mode=$((8#$mode))
        if [ "$uid" != 0 ]; then
            printf '%s is owned by uid %s, not root' "$p" "$uid"
            return
        fi
        if ((mode & 8#020)); then
            printf '%s is writable by group %s' "$p" "$gid"
            return
        fi
        if ((mode & 8#002)) && { [ "$leaf" = 1 ] || ! ((mode & 8#1000)); }; then
            printf '%s is writable by every user' "$p"
            return
        fi
        [ "$p" != / ] || return 0
        p=$(dirname -- "$p")
        leaf=0
    done
}
