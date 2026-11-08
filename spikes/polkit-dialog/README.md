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
| T4 owner, interaction, human told to cancel | polkitd aborts | authorized: the human authenticated (see below) |
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

- ~~T4 returned authorized although the script asked the human to press
  Cancel.~~ Settled: the owner had authenticated. A Cancel on a GNOME polkit
  dialog for an `auth_self` action (Bitwarden's `com.bitwarden.Bitwarden.unlock`,
  same defaults as the spike action, checked from the developer's uid) returns
  `(false, false, {'polkit.result': 'auth_self', 'polkit.dismissed': 'true'})`.
  `cnd` must treat `polkit.dismissed` as a deny.
- Lesson for the approval UX: `pkexec`'s prompt and the spike's prompt look
  alike, and the human cancelled the wrong one twice. countersign's dialog
  must lead with "countersign" and the request code so it cannot be mistaken
  for another prompt.

## YubiKey touch through polkit (`u2f` mode, 2026-11-08)

`spike.sh u2f` installed `pam_u2f` 1.4.0, enrolled the owner's YubiKey 5C
Nano into a root-owned mapping file with its own origin
(`pam://countersign-spike`), added a drop-in letting
`polkit-agent-helper@.service` open hidraw devices, and replaced the
`polkit-1` PAM stack with `auth [success=done default=die] pam_u2f.so ... cue`
(touch only, no password fallback). Everything except the package was removed
on exit. Raw output: `results-u2f-20261108T190302Z.txt`.

| Check | Human | Result |
| --- | --- | --- |
| Enrolment (`pamu2fcfg`, as root in a terminal) | PIN, then touch | enrolled; the key has a FIDO2 PIN, so enrolment needs a TTY. The PIN prompt came first, after the package install, so the script's "touch now" cue was premature (fixed) |
| U1 dialog, touch the key | touched | `(true, false, ...)`: authorized. The dialog showed the request text and pam_u2f's cue "touch the device", with no password field |
| U2 dialog, press Cancel | cancelled | `(false, false, {'polkit.dismissed': 'true'})` |
| U3 dialog, do nothing | waited | **no dialog appeared; the key blinked**; ended `dismissed` after the key's presence timeout (`pam_authenticate failed: Authentication failure` in the helper log) |

### What this settles

1. **A polkit dialog backed by a YubiKey touch works on polkit 128**, once
   the helper's sandbox lets it see hidraw devices. polkit-agent-helper(8)
   says a PAM module needing hardware should ship such a drop-in;
   openSUSE's `pam_u2f` 1.4.0 does not, so countersign's installer must.
2. **Touch-only is possible.** `[success=done default=die]` gives approval by
   touch with no password, and denies when the key is absent.
3. **Cancel works** with the key path too.
4. **Enrolment needs a terminal.** With a FIDO2 PIN set, `pamu2fcfg` asks for
   it, so `cn approver enroll` cannot run as a Claude Code `!` command.

### What it exposes

- **The key can ask for a touch with nothing on screen (U3).** The touch
  approves whatever request is pending, seen or not. A blinking key is not a
  display. Approval UX must teach "touch only while the countersign dialog is
  showing", and countersign should consider requiring the dialog to be
  answered as well (for example a `required` touch plus a click, rather than
  touch alone). Not yet known: whether the dialog failed to render in U3 or
  rendered late; rerun `spike.sh u2f U3` to see if it repeats.
- **This replaces the PAM stack for every polkit prompt on the machine**
  (`pkexec`, GNOME settings, Bitwarden unlock). polkit has no per-action PAM
  service. A touch-only stack for countersign means touch-only for all
  polkit prompts, which the owner has to choose deliberately.

## Found alongside: the agent's uid is already root

After the owner ran `sudo` in another terminal, `sudo -n true` from the
agent's shell succeeded. That first looked like a shared sudo timestamp, but
`sudo -n -l` shows the cause: `(ALL : ALL) NOPASSWD: ALL` for the owner's
user, plus membership of the `docker` group (root equivalent through the
Docker socket). Any agent running as that user can become root at any time,
with or without a recent `sudo`.

Every countersign guarantee assumes the agent cannot become root (the threat
model puts root out of scope). On a machine like this one, the daemon's
separate uid, the store's permissions and the audit log protect nothing
against a malicious agent. Roadmap Phase 2 adds a privilege audit to
`cn doctor` and `cn sudo` as the replacement for `NOPASSWD: ALL`
([roadmap](../../docs/roadmap.md)). A sudo timestamp bound to the terminal
(`Defaults timestamp_type=tty`) matters only once NOPASSWD is gone.
