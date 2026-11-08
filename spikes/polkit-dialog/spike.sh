#!/bin/bash
# polkit dialog spike for countersign. Run as root through pkexec, from the
# graphical session you want the dialogs in:
#
#   pkexec /bin/bash "$PWD/spikes/polkit-dialog/spike.sh" [MODE] [CHECK...]
#   sudo bash spikes/polkit-dialog/spike.sh [MODE] [CHECK...]   # from a terminal tab
#
# MODE
#   session  check the developer's logind session, the subject the design
#            wants. polkit 127/128 abort on it (polkit-org/polkit#699).
#   process  check the shell that ran pkexec instead. Works on 127/128, but a
#            same-uid agent can register its own prompt for that process.
#   u2f      process subject, with polkit's PAM stack temporarily replaced by
#            a YubiKey touch (pam_u2f) and nothing else. See README.
#
# CHECK  run only these checks, e.g. "T4". Default: all checks for the mode.
#
# It installs a throwaway polkit action, runs the checks, prints what each
# returned, writes the same to results-<mode>-<timestamp>.txt beside this
# script, and undoes every change on exit. Checks that open a dialog say which
# button to press first.
set -u

here=$(cd "$(dirname "$0")" && pwd)
action=computer.mooselabs.countersign.spike.approve
policy=/usr/share/polkit-1/actions/$action.policy
user_uid=${PKEXEC_UID:-${SUDO_UID:?run this through pkexec or sudo}}
user_name=$(id -nu "$user_uid")
session=$(loginctl show-user "$user_uid" -p Display --value)
mode=${1:-session}
shift || true
only=" $* "
out="$here/results-$mode-$(date -u +%Y%m%dT%H%M%SZ).txt"
started=$(date '+%F %T')

# Files the u2f mode adds; all removed on exit.
pam_override=/etc/pam.d/polkit-1
u2f_dir=/etc/countersign-spike
dropin_dir=/etc/systemd/system/polkit-agent-helper@.service.d
dropin=$dropin_dir/countersign-spike-hidraw.conf

[ "$(id -u)" = 0 ] || { echo "must run as root (through pkexec)"; exit 1; }
[ -n "$session" ] || { echo "no graphical session for uid $user_uid"; exit 1; }

log() { echo "$*" | tee -a "$out"; }
want() { [ "$only" = "  " ] || [[ $only == *" $1 "* ]]; }

# Cleanup removes only what this run created.
made_policy= made_pam= made_dropin= made_u2f_dir=
cleanup() {
    [ -n "$made_policy" ] && rm -f "$policy"
    [ -n "$made_pam" ] && rm -f "$pam_override" && echo "restored: polkit uses /usr/lib/pam.d/polkit-1 again"
    if [ -n "$made_dropin" ]; then
        rm -f "$dropin"
        rmdir "$dropin_dir" 2>/dev/null
        systemctl daemon-reload
    fi
    [ -n "$made_u2f_dir" ] && rm -rf "$u2f_dir"
    chown "$user_uid" "$out"
}

case $mode in
session) subject="('unix-session', {'session-id': <'$session'>})" ;;
process | u2f)
    # The nearest ancestor owned by the developer: the shell that ran pkexec or
    # sudo. A throwaway process started by this root script instead made every
    # check return (false, false); see README.
    subject_pid=$PPID
    while [ "$subject_pid" -gt 1 ] && [ "$(stat -c %u /proc/$subject_pid)" != "$user_uid" ]; do
        subject_pid=$(awk '{print $4}' /proc/$subject_pid/stat)
    done
    [ "$subject_pid" -gt 1 ] || { echo "no ancestor owned by uid $user_uid"; exit 1; }
    subject="('unix-process', {'pid': <uint32 $subject_pid>, 'start-time': <uint64 0>})"
    ;;
*) echo "usage: spike.sh [session|process|u2f] [CHECK...]"; exit 2 ;;
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

log "countersign polkit spike ($mode subject${*:+, checks: $*}), $(date -u +%FT%TZ)"
log "polkit $(rpm -q --qf '%{VERSION}' polkit 2>/dev/null), gnome-shell $(rpm -q --qf '%{VERSION}' gnome-shell 2>/dev/null), session $session ($(loginctl show-session "$session" -p Type --value))"
log ""

trap cleanup EXIT

if [ "$mode" = u2f ]; then
    for f in "$pam_override" "$dropin" "$u2f_dir"; do
        [ -e "$f" ] && { log "$f already exists; refusing to replace it"; exit 1; }
    done
    if ! rpm -q pam_u2f >/dev/null; then
        log "installing pam_u2f (left installed afterwards; it does nothing unless configured)"
        zypper --non-interactive install pam_u2f >/dev/null || { log "zypper install pam_u2f failed"; exit 1; }
    fi
    log "pam_u2f $(rpm -q --qf '%{VERSION}' pam_u2f)"

    # Enrol the key for this spike only, in a root-owned file the agent cannot
    # edit, with an origin no other service uses.
    install -d -m 0755 "$u2f_dir" && made_u2f_dir=1
    echo ">>> ENROL: enter your YubiKey PIN if asked, then touch the key when it blinks."
    pamu2fcfg -u "$user_name" -o pam://countersign-spike -i pam://countersign-spike \
        >"$u2f_dir/u2f_mappings" 2>"$u2f_dir/enrol.err" || { log "enrolment failed: $(cat "$u2f_dir/enrol.err")"; exit 1; }
    chmod 0644 "$u2f_dir/u2f_mappings"
    log "enrolled one credential for $user_name"

    # polkit 128 runs its PAM helper with PrivateDevices=yes, which hides the
    # key. Let it see hidraw devices only (polkit-agent-helper(8), SANDBOXING).
    install -d -m 0755 "$dropin_dir"
    made_dropin=1
    printf '[Service]\nDevicePolicy=auto\nDeviceAllow=char-hidraw rw\nPrivateDevices=no\n' >"$dropin"
    systemctl daemon-reload

    # A touch and nothing else: success ends the stack, anything else denies.
    # No password fallback, so a missing key means no approval.
    made_pam=1
    cat >"$pam_override" <<EOF
#%PAM-1.0
# countersign spike: temporary, removed by spike.sh on exit.
auth       [success=done default=die] pam_u2f.so authfile=$u2f_dir/u2f_mappings origin=pam://countersign-spike appid=pam://countersign-spike cue
account    include      common-account
password   include      common-password
session    include      common-session
session    optional     pam_keyinit.so revoke [force]
EOF
    log "polkit PAM stack replaced by a YubiKey touch for this run"
    log ""
fi

[ -e "$policy" ] && { log "$policy already exists; refusing to replace it"; exit 1; }
made_policy=1
install -m 0644 "$here/$action.policy" "$policy" || { log "could not install $policy"; exit 1; }
sleep 2 # polkitd reloads actions on file change
pkaction --action-id "$action" >/dev/null 2>&1 || { log "polkitd does not see $action after install"; exit 1; }

if [ "$mode" = u2f ]; then
    if want U1; then
        echo ">>> U1: a dialog will open and ask you to touch the key. Note what it shows (password field? touch prompt?), then TOUCH the key."
        check "U1 owner passes details, human touches the key (expect: true)" 65534 "$details" 1
    fi
    if want U2; then
        echo ">>> U2: a second dialog will open. Press CANCEL. Do not touch the key."
        check "U2 owner passes details, human cancels without touching (expect: false, dismissed)" 65534 "$details" 1
    fi
    if want U3; then
        echo ">>> U3: a third dialog will open. Do NOT touch the key and do NOT press anything; wait for it to time out (up to 2 minutes)."
        check "U3 owner passes details, human does nothing (expect: false after pam_u2f or the call times out)" 65534 "$details" 1
    fi
    log "agent helper log since $started:"
    journalctl --no-pager -o cat -u 'polkit-agent-helper@*' --since "$started" 2>&1 | tail -20 | sed 's/^/  /' | tee -a "$out"
    log ""
    log "Done. In chat, report what each dialog showed and what you pressed or touched."
    exit 0
fi

want T0 && check "T0 baseline: the developer's uid, no details, no interaction (expect: (false, true, auth_self))" \
    "$user_uid" "@a{ss} {}" 0

want T1 && check "T1 owner passes details, no interaction (expect: (false, true, ...) = challenge, no dialog)" \
    65534 "$details" 0

if want T2; then
    echo ">>> T2: a GNOME dialog will open. Read its text, note it exactly, then AUTHENTICATE."
    check "T2 owner passes details, interaction (expect: dialog with K7M-Q2X / 3QF8-ZK2M; result true)" \
        65534 "$details" 1
fi

want T3 && check "T3 owner checks again straight after success, no interaction (expect: challenge again, no caching)" \
    65534 "$details" 0

if want T4; then
    echo ">>> T4: a dialog will open. Press CANCEL. Do not type your password."
    check "T4 owner passes details, interaction, human cancels (expect: false, polkit.dismissed)" \
        65534 "$details" 1
fi

want T5 && check "T5 the developer's uid (stands in for the agent) passes details (expect: NotAuthorized, only trusted callers)" \
    "$user_uid" "$details" 0

want T6 && check "T6 owner, no details, no interaction (the shape that crashed polkitd from an unprivileged caller)" \
    65534 "@a{ss} {}" 0

log "Done. In chat, report the exact dialog text from T2 and anything else the dialog showed."
