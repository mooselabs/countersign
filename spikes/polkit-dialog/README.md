# Spike: is the GNOME polkit dialog a trusted display?

Answers roadmap blocker 1 ([roadmap](../../docs/roadmap.md)): can `cnd`, running
as its own user, ask polkit about the developer's login session, pass request
details, and have GNOME Shell show them? If not, the dialog proves presence
but not what is being approved, and the default approver chain changes.

## Run

From a terminal inside the GNOME session (a Claude Code `!` command works too,
because `pkexec` asks through the desktop rather than the terminal):

```sh
pkexec /bin/bash "$PWD/spikes/polkit-dialog/spike.sh"
```

It installs a throwaway action owned by `nobody` (standing in for the
`countersign` user), runs six checks, writes `results-*.txt` here, and removes
the action. Two checks open a dialog; the script says which button to press.

## Found before the spike (2026-11-08, polkit 128, GNOME 51, Wayland)

Run as the developer's uid, no root:

1. **An ordinary process cannot put text in a polkit dialog.** Passing any
   details, including `polkit.message`, fails with `NotAuthorized: Only trusted
   callers (e.g. uid 0 or an action owner) can use CheckAuthorization() and
   pass details`. So an agent cannot spoof countersign's dialog text, and `cnd`
   can only pass details if its action names the `countersign` user in
   `org.freedesktop.policykit.owner`.
2. **polkitd 128 aborts on one call shape.** `CheckAuthorization` from an
   unprivileged caller with a `unix-session` subject (its own session) and
   empty details kills polkitd with SIGABRT (`ExecMainCode=3`,
   `ExecMainStatus=6`). D-Bus activation restarts it on the next request, so
   the effect is a short outage during which pending prompts fail. The same
   call with a `unix-process` subject works. Reproduce:

   ```sh
   gdbus call --system --dest org.freedesktop.PolicyKit1 \
     --object-path /org/freedesktop/PolicyKit1/Authority \
     --method org.freedesktop.PolicyKit1.Authority.CheckAuthorization \
     "('unix-session', {'session-id': <'3'>})" org.freedesktop.policykit.exec \
     "@a{ss} {}" "uint32 0" "''"
   ```

   Not yet reported upstream. `cnd` always passes details as the action owner,
   which check T6 tests separately.

## Results (2026-11-08, polkit 128, GNOME Shell 51.1, Wayland)

Raw output: `results-session-*.txt` and `results-process-*.txt`. The first
process run (`results-process-20261108T185059Z.txt`) used a
throwaway process started by the root script as the subject; every check then
returned `(false, false)` and no dialog appeared. A process started by the
developer (the shell that ran `pkexec`) works, so the final script uses that.

| Check | Session subject | Process subject |
| --- | --- | --- |
| T0 developer uid, no details | not run | `auth_self` challenge |
| T1 owner (`nobody`) passes details | polkitd aborts | challenge, details echoed |
| T2 owner, interaction, human authenticates | polkitd aborts | dialog shown, authorized |
| T3 owner checks again straight after | polkitd aborts | challenge again: no caching |
| T4 owner, interaction, human told to cancel | polkitd aborts | authorized (see below) |
| T5 developer uid passes details | refused: only trusted callers | refused: only trusted callers |
| T6 owner, no details | polkitd aborts | challenge |

The T2 dialog ([screenshot](t2-dialog.png)):

> **Authentication Required**
> countersign: approve request K7M-Q2X, digest 3QF8-ZK2M: use
> clickhouse-password for 30m (spike)
> *(user avatar)* **Patrick McEvoy** · Password · Cancel / Authenticate

### What this settles

1. **GNOME shows the request.** polkitd substitutes `$(key)` from the details
   an action owner passes, and GNOME Shell renders the whole message. The
   dialog names the developer (`auth_self`), not "Administrator".
2. **The owner annotation works across uids.** A caller listed in
   `org.freedesktop.policykit.owner` (here `nobody`, standing in for
   `countersign`) may check another user's process and pass details.
3. **An agent cannot write the dialog text.** The developer's uid gets
   `Only trusted callers (e.g. uid 0 or an action owner) can use
   CheckAuthorization() and pass details`.
4. **`auth_self` does not cache.** A check straight after a successful one
   challenges again.
5. **Session subjects are unusable on polkit 127/128.** Every check that gets
   past the caller test aborts polkitd: upstream
   [polkit-org/polkit#699](https://github.com/polkit-org/polkit/issues/699)
   (`push_subject()` in the duktape backend handles only process and bus-name
   subjects). No fix PR as of 2026-11-08.
6. **A process subject can be hijacked by a same-uid agent.** Any process of
   the developer's uid can register its own authentication agent for any of
   that uid's processes (`pkttyagent --process <pid>` registered under a
   pseudo-terminal), and polkit prefers it over the GNOME agent. A malicious
   agent can then draw its own prompt and collect the password or touch. So
   until #699 is fixed, the polkit dialog is a trusted display against careless
   and confused agents only.
7. **Put the code and digest first.** `pkexec`'s own dialog shortened a long
   command line by cutting its middle (`projects/moose ... spikes`). The
   message should start with the request code and digest so they survive.

### Open

- T4 returned authorized although the script asked the human to press
  Cancel. Waiting on the owner to confirm which button was pressed; if it was
  Cancel, that is a serious finding to chase before polkit counts as an
  approver.
- The `pam_u2f` (YubiKey touch) path is not tested: `pam_u2f` is not
  installed on this machine.
