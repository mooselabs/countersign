#!/bin/bash
# polkit dialog spike for countersign. Run as root through pkexec, from the
# graphical session you want the dialogs in:
#
#   pkexec /bin/bash "$PWD/spikes/polkit-dialog/spike.sh" [session|process]
#
# "session" (default) checks the developer's logind session, the subject the
# design wants. polkit 127/128 abort on it (polkit-org/polkit#699). "process"
# checks a throwaway process owned by the developer instead, which works on
# those versions but lets a same-uid agent register its own prompt for it.
#
# It installs a throwaway polkit action, runs six checks, prints what each
# returned, writes the same to results-<timestamp>.txt beside this script, and
# removes the action again. Two checks open a GNOME dialog: the script says
# which button to press before each one.
set -u

here=$(cd "$(dirname "$0")" && pwd)
action=computer.mooselabs.countersign.spike.approve
policy=/usr/share/polkit-1/actions/$action.policy
user_uid=${PKEXEC_UID:?run this through pkexec}
session=$(loginctl show-user "$user_uid" -p Display --value)
mode=${1:-session}
out="$here/results-$mode-$(date -u +%Y%m%dT%H%M%SZ).txt"

[ "$(id -u)" = 0 ] || { echo "must run as root (through pkexec)"; exit 1; }
[ -n "$session" ] || { echo "no graphical session for uid $user_uid"; exit 1; }

log() { echo "$*" | tee -a "$out"; }

case $mode in
session) subject="('unix-session', {'session-id': <'$session'>})" ;;
process)
    # The shell that ran pkexec: a process owned by the developer. An earlier
    # version used a throwaway process started by this root script, and every
    # check returned (false, false); see README.
    subject_pid=$PPID
    [ "$(stat -c %u /proc/$subject_pid)" = "$user_uid" ] || { echo "parent $subject_pid is not uid $user_uid"; exit 1; }
    subject="('unix-process', {'pid': <uint32 $subject_pid>, 'start-time': <uint64 0>})"
    ;;
*) echo "usage: spike.sh [session|process]"; exit 2 ;;
esac

details="{'request': 'K7M-Q2X', 'digest': '3QF8-ZK2M', 'summary': 'use clickhouse-password for 30m (spike)'}"

# check <label> <run-as uid> <details> <flags: 0 none, 1 allow interaction>
check() {
    local label=$1 as=$2 det=$3 flags=$4 before after result
    before=$(systemctl show polkit -p MainPID --value)
    result=$(setpriv --reuid="$as" --regid="$as" --clear-groups \
        gdbus call --system --timeout 120 \
        --dest org.freedesktop.PolicyKit1 \
        --object-path /org/freedesktop/PolicyKit1/Authority \
        --method org.freedesktop.PolicyKit1.Authority.CheckAuthorization \
        "$subject" \
        "$action" "$det" "uint32 $flags" "''" 2>&1)
    sleep 1
    after=$(systemctl show polkit -p MainPID --value)
    log "$label"
    log "  caller uid $as, subject $mode, flags $flags"
    log "  result: $result"
    [ "$before" = "$after" ] || log "  NOTE: polkitd pid changed $before -> $after (it restarted or crashed)"
    log ""
}

log "countersign polkit spike ($mode subject), $(date -u +%FT%TZ)"
log "polkit $(rpm -q --qf '%{VERSION}' polkit 2>/dev/null), gnome-shell $(rpm -q --qf '%{VERSION}' gnome-shell 2>/dev/null), session $session ($(loginctl show-session "$session" -p Type --value))"
log ""

install -m 0644 "$here/$action.policy" "$policy" || { log "could not install $policy"; exit 1; }
trap 'rm -f "$policy"; chown "$user_uid" "$out"' EXIT
sleep 2 # polkitd reloads actions on file change
pkaction --action-id "$action" >/dev/null 2>&1 || { log "polkitd does not see $action after install"; exit 1; }

check "T0 baseline: the developer's uid, no details, no interaction (expect: (false, true, auth_self))" \
    "$user_uid" "@a{ss} {}" 0

check "T1 owner passes details, no interaction (expect: (false, true, ...) = challenge, no dialog)" \
    65534 "$details" 0

echo ">>> T2: a GNOME dialog will open. Read its text, note it exactly, then AUTHENTICATE."
check "T2 owner passes details, interaction (expect: dialog with K7M-Q2X / 3QF8-ZK2M; result true)" \
    65534 "$details" 1

check "T3 owner checks again straight after success, no interaction (expect: challenge again, no caching)" \
    65534 "$details" 0

echo ">>> T4: a second dialog will open. Press CANCEL this time."
check "T4 owner passes details, interaction, human cancels (expect: false)" \
    65534 "$details" 1

check "T5 the developer's uid (stands in for the agent) passes details (expect: NotAuthorized, only trusted callers)" \
    "$user_uid" "$details" 0

check "T6 owner, no details, no interaction (the shape that crashed polkitd from an unprivileged caller)" \
    65534 "@a{ss} {}" 0

log "Done. In chat, report: the exact dialog text from T2, and anything else the dialog showed (icon, user, details expander)."
