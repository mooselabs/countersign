#!/bin/bash
# The one-line installer, published with each GitHub release as install.sh:
#
#   curl -fsSL https://github.com/mooselabs/countersign/releases/latest/download/install.sh | bash
#   curl -fsSL https://github.com/mooselabs/countersign/releases/latest/download/install.sh | bash -s -- --factor touch
#
# It downloads the release tarball as root into a root-owned directory,
# checks it against the release's SHA256SUMS and, with gh, its build
# provenance, and runs the tarball's packaging/install.sh with sudo. Options
# and what it trusts: packaging/README.md, "Install from a release", or
# --help.
#
# Everything below is in functions, and only the last line runs anything, so
# a download cut short runs nothing, and bash has read the whole script before
# any command can read stdin.

cs_usage() {
    cat <<'EOF'
Install countersign from a GitHub release.

  curl -fsSL https://github.com/mooselabs/countersign/releases/latest/download/install.sh | bash -s -- [options]

Run it as yourself, from a terminal you opened yourself: not as root (it
uses sudo for the root steps) and not as a Claude Code ! command (install.sh
shows the recovery phrase once and may ask for your security key's PIN and a
touch, so it needs a terminal).

  --version vX.Y.Z  the release to install (default: the latest)
  --factor F        password, touch or touch+password, passed to install.sh.
                    Default: the factor already installed, else password
  --force           passed to install.sh (replace a changed config, a
                    polkit-1 PAM file countersign did not write, a key
                    enrolment; each is backed up)
  --dry-run         download and check as you, without sudo, then print the
                    plan with install.sh --dry-run. Installs nothing
  --require-attestation
                    fail when the build provenance cannot be checked
                    (gh missing or not logged in)
  --base-url URL    for tests: take the release files from URL, a directory
                    laid out like one release's downloads (file://,
                    https://, or http:// to localhost). Needs --version
  -h, --help        this text

The release tree is kept as root in /usr/local/src/countersign/<version>;
its packaging/uninstall.sh removes countersign again.
EOF
}

cs_say() { printf '%s\n' "$*"; }
cs_note() { printf '  %s\n' "$*"; }
cs_step() { printf '\n== %s\n' "$*"; }
cs_die() { printf 'countersign install: %s\n' "$*" >&2; exit 1; }

# cs_check_platform R: Linux, x86_64, kernel 6.5 or later, systemd as init,
# not root. R is the test root (empty for a real run).
cs_check_platform() {
    local r=$1 os arch rel kmajor kminor
    os=$(uname -s)
    [ "$os" = Linux ] || cs_die "countersign runs on Linux only (this is $os)"
    arch=$(uname -m)
    [ "$arch" = x86_64 ] || cs_die "releases are built for x86_64 only (this is $arch); build from source with packaging/trusted-build.sh"
    rel=$(uname -r)
    kmajor=${rel%%.*}
    kminor=${rel#*.}
    kminor=${kminor%%[!0-9]*}
    [[ $kmajor =~ ^[0-9]+$ && $kminor =~ ^[0-9]+$ ]] || cs_die "cannot read the kernel version from '$rel'"
    if ((kmajor < 6 || (kmajor == 6 && kminor < 5))); then
        cs_die "Linux $rel is too old: countersign needs 6.5 or later (cnd uses SO_PEERPIDFD)"
    fi
    [ -d "$r/run/systemd/system" ] || cs_die "systemd is not the running init system"
    [ "$(id -u)" != 0 ] ||
        cs_die "run this as yourself, not as root: it installs countersign for the user who runs it and uses sudo for the root steps"
}

# cs_check_tools DRY: the commands this script needs.
cs_check_tools() {
    local tool
    for tool in curl tar gzip sha256sum mktemp; do
        command -v "$tool" >/dev/null || cs_die "$tool not found; install it and run again"
    done
    if [ "$1" = 0 ]; then
        command -v sudo >/dev/null || cs_die "sudo not found: the root steps run through sudo"
    fi
}

# cs_check_version TAG: prints TAG if it is vX.Y.Z or vX.Y.Z-suffix.
cs_check_version() {
    [[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || cs_die "not a release version: '$1' (want vX.Y.Z)"
    printf '%s\n' "$1"
}

# cs_latest URL: the tag the releases/latest redirect points to, without the
# GitHub API.
cs_latest() {
    local url
    url=$(curl -q -fsSLI --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' "$1/releases/latest") ||
        cs_die "cannot read $1/releases/latest: no network, or no published release yet"
    case $url in
    */releases/tag/*) cs_check_version "${url##*/releases/tag/}" ;;
    *) cs_die "$1 has no published release yet ($1/releases/latest went to $url)" ;;
    esac
}

# cs_protocols URL: the curl --proto list for a --base-url.
cs_protocols() {
    case $1 in
    file://*) printf '=file\n' ;;
    https://*) printf '=https\n' ;;
    http://localhost[:/]* | http://127.0.0.1[:/]* | http://\[::1\][:/]*) printf '=http\n' ;;
    *) cs_die "--base-url must be file://, https:// or http:// to localhost, got '$1'" ;;
    esac
}

# cs_expected_sum SUMS NAME: the one SHA-256 that SUMS lists for NAME.
cs_expected_sum() {
    local lines
    lines=$(awk -v f="$2" '$2 == f || $2 == "*" f { print $1 }' <<<"$1")
    [ -n "$lines" ] || cs_die "SHA256SUMS has no line for $2"
    [ "$(wc -l <<<"$lines")" = 1 ] || cs_die "SHA256SUMS has more than one line for $2"
    [[ $lines =~ ^[0-9a-f]{64}$ ]] || cs_die "SHA256SUMS has a malformed sum for $2"
    printf '%s\n' "$lines"
}

# cs_check_listing TOP VERBOSE NAMES: every member of the tarball is a plain
# file or a directory (VERBOSE is tar -tv's listing), and TOP or below it with
# no '..' (NAMES is tar -t's).
cs_check_listing() {
    local top=$1 line name
    while IFS= read -r line; do
        case $line in
        -* | d*) ;;
        *) cs_die "the tarball holds something other than files and directories: $line" ;;
        esac
    done <<<"$2"
    while IFS= read -r name; do
        case /$name/ in
        */../*) cs_die "the tarball has a path with '..': $name" ;;
        esac
        case $name in
        "$top" | "$top"/*) ;;
        *) cs_die "the tarball has a path outside $top/: $name" ;;
        esac
    done <<<"$3"
}

# cs_installed_factor R: the factor of an existing install, from the marker
# install.sh writes into /etc/pam.d/polkit-1 (readable by everyone).
cs_installed_factor() {
    local f
    f=$(sed -n 's/^# countersign-managed: written by countersign packaging\/install\.sh --factor \([a-z+]*\)$/\1/p' \
        "$1/etc/pam.d/polkit-1" 2>/dev/null | head -n 1) || true
    case $f in
    touch | touch+password) printf '%s\n' "$f" ;;
    *) printf 'password\n' ;;
    esac
}

# cs_cleanup: remove the download directories, as root when root owns them.
cs_cleanup() {
    if [ -n "${cs_utmp:-}" ]; then rm -rf -- "$cs_utmp"; fi
    if [ -n "${cs_tmp:-}" ]; then
        if [ "${cs_tmp_root:-0}" = 1 ]; then
            sudo rm -rf -- "$cs_tmp" || printf 'countersign install: could not remove %s; remove it with sudo rm -rf\n' "$cs_tmp" >&2
        else
            rm -rf -- "$cs_tmp"
        fi
    fi
}

countersign_get() {
    set -euo pipefail
    # Nothing below reads the piped script: commands get /dev/null, and
    # install.sh gets the terminal.
    exec </dev/null

    local repo=mooselabs/countersign
    local github=https://github.com/$repo
    local tag='' factor='' force=0 dry=0 require_att=0 base_url=''
    # For tests only: with --dry-run, the system paths below are read under
    # this prefix, and install.sh does the same.
    local r=${COUNTERSIGN_INSTALL_ROOT:-}

    while [ $# -gt 0 ]; do
        case $1 in
        --version) tag=${2:?--version needs a value}; shift 2 ;;
        --version=*) tag=${1#*=}; shift ;;
        --factor) factor=${2:?--factor needs a value}; shift 2 ;;
        --factor=*) factor=${1#*=}; shift ;;
        --force) force=1; shift ;;
        --dry-run) dry=1; shift ;;
        --require-attestation) require_att=1; shift ;;
        --base-url) base_url=${2:?--base-url needs a value}; shift 2 ;;
        --base-url=*) base_url=${1#*=}; shift ;;
        -h | --help) cs_usage; return 0 ;;
        *) printf 'countersign install: unknown argument: %s\n\n' "$1" >&2; cs_usage >&2; return 2 ;;
        esac
    done
    case $factor in
    '' | password | touch | touch+password) ;;
    *) cs_die "--factor must be password, touch or touch+password (got '$factor')" ;;
    esac
    if [ "$dry" = 0 ] && [ -n "$r" ]; then
        cs_die "COUNTERSIGN_INSTALL_ROOT is for tests and works only with --dry-run"
    fi

    cs_step "checks"
    cs_check_platform "$r"
    cs_check_tools "$dry"
    local user
    user=$(id -un)
    [[ $user =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] || cs_die "user name '$user' has characters install.sh does not accept"
    cs_note "Linux $(uname -r), x86_64, systemd; installing for $user"
    if [ "$dry" = 0 ]; then
        # install.sh shows the recovery phrase and may ask for the key's PIN
        # and a touch; a Claude Code ! command has no terminal for that.
        { : </dev/tty; } 2>/dev/null ||
            cs_die "no terminal (/dev/tty). Run this from a terminal you opened yourself, not as a Claude Code ! command: install.sh shows the recovery phrase once and may ask for your key's PIN and a touch"
    fi

    # --- which release ---
    local proto='=https' base
    if [ -n "$base_url" ]; then
        [ -n "$tag" ] || cs_die "--base-url needs --version"
        proto=$(cs_protocols "$base_url")
        base=${base_url%/}
    fi
    if [ -n "$tag" ]; then
        case $tag in v*) ;; *) tag=v$tag ;; esac
        tag=$(cs_check_version "$tag")
    else
        tag=$(cs_latest "$github")
    fi
    [ -n "$base_url" ] || base=$github/releases/download/$tag
    local version=${tag#v}
    local name=countersign-$version
    local tarball=$name-x86_64-linux.tar.gz
    cs_note "release $tag from $base"

    # --- an existing install ---
    local current=
    if [ -e "$r/usr/bin/cn" ] || [ -e "$r/usr/libexec/countersign/cnd" ]; then
        current=$(cs_installed_factor "$r")
        local was
        was=$("$r/usr/bin/cn" --version 2>/dev/null | head -n 1) || was=
        cs_note "countersign is installed${was:+ ($was)}, with factor $current: this upgrades it."
        cs_note "install.sh keeps the store, the master key and a changed config; it never runs cnd init over a store"
        if [ -z "$factor" ]; then
            factor=$current
        elif [ "$factor" != "$current" ]; then
            cs_note "the factor changes from $current to $factor"
        fi
    fi
    [ -n "$factor" ] || factor=password
    cs_note "factor $factor"

    # --- download ---
    # A real run downloads as root into a directory only root can read or
    # write, so nothing running as you can change what is checked and
    # installed. A dry run downloads as you.
    local as=()
    cs_step "download"
    trap cs_cleanup EXIT
    trap 'exit 130' INT TERM HUP
    if [ "$dry" = 0 ]; then
        as=(sudo)
        cs_note "sudo asks for your password for the root steps"
        sudo -v || cs_die "sudo failed"
        cs_tmp=$(sudo mktemp -d) || cs_die "sudo mktemp -d failed"
        cs_tmp_root=1
    else
        cs_tmp=$(mktemp -d)
        cs_tmp_root=0
    fi
    local f
    for f in SHA256SUMS "$tarball"; do
        "${as[@]}" curl -q -fsSL --proto "$proto" --proto-redir "$proto" --retry 3 \
            -o "$cs_tmp/$f" -- "$base/$f" || cs_die "cannot download $base/$f"
        cs_note "downloaded $f"
    done

    # --- checksum ---
    cs_step "verify"
    local sums want
    sums=$("${as[@]}" cat -- "$cs_tmp/SHA256SUMS")
    want=$(cs_expected_sum "$sums" "$tarball")
    printf '%s  %s\n' "$want" "$cs_tmp/$tarball" | "${as[@]}" sha256sum --check --strict --quiet - >/dev/null 2>&1 ||
        cs_die "$tarball does not match its line in SHA256SUMS. Nothing was installed"
    cs_note "sha256 $want matches SHA256SUMS"

    # --- provenance ---
    local verify=(gh attestation verify --repo "$repo"
        --signer-workflow "$repo/.github/workflows/release.yml"
        --source-ref "refs/tags/$tag" --deny-self-hosted-runners)
    local why=
    if ! command -v gh >/dev/null; then
        why="gh is not installed"
    elif ! gh auth status >/dev/null 2>&1; then
        why="gh is not logged in"
    elif ! gh attestation verify --help 2>&1 | grep -q -- --source-ref; then
        why="this gh has no attestation verify --source-ref (update gh)"
    fi
    if [ -n "$why" ]; then
        local by_hand="to check it by hand: download $base/$tarball and run ${verify[*]} $tarball"
        [ "$require_att" = 0 ] || cs_die "provenance cannot be checked: $why. Without --require-attestation this is a warning; $by_hand"
        cs_note "provenance not checked: $why; $by_hand"
    else
        local copy=$cs_tmp/$tarball
        if [ "$dry" = 0 ]; then
            # gh runs as you; give it a copy, and check the copy is the file
            # root checked.
            cs_utmp=$(mktemp -d)
            copy=$cs_utmp/$tarball
            # shellcheck disable=SC2024 # root reads, the copy is written as you
            sudo cat -- "$cs_tmp/$tarball" >"$copy"
        fi
        local out
        if ! out=$("${verify[@]}" "$copy" 2>&1); then
            printf '%s\n' "$out" | sed 's/^/    gh: /' >&2
            cs_die "gh attestation verify refused $tarball (gh's output above): no attestation that $repo's release workflow built it for $tag. Nothing was installed"
        fi
        [ "$(sha256sum <"$copy" | awk '{ print $1 }')" = "$want" ] || cs_die "the copy of $tarball changed while gh checked it"
        cs_note "provenance verified: built by $repo/.github/workflows/release.yml for $tag"
    fi

    # --- extract ---
    cs_step "extract"
    local listing names
    listing=$("${as[@]}" tar -tvzf "$cs_tmp/$tarball") || cs_die "cannot read $tarball"
    names=$("${as[@]}" tar -tzf "$cs_tmp/$tarball")
    cs_check_listing "$name" "$listing" "$names"
    "${as[@]}" mkdir -m 0700 -- "$cs_tmp/x"
    "${as[@]}" tar -xzf "$cs_tmp/$tarball" -C "$cs_tmp/x" --no-same-owner ||
        cs_die "cannot extract $tarball"
    local odd
    odd=$("${as[@]}" find "$cs_tmp/x/$name" \( \( ! -type f ! -type d \) -o -perm /7022 \) -print -quit)
    [ -z "$odd" ] || cs_die "the tarball has a file with odd permissions: ${odd#"$cs_tmp/x/"}"
    local tree=$cs_tmp/x/$name
    cs_note "extracted $name"

    # --- install ---
    local args=(--user "$user" --factor "$factor")
    [ "$force" = 0 ] || args+=(--force)
    if [ "$dry" = 1 ]; then
        cs_step "plan"
        cs_note "a real run keeps the tree as root in /usr/local/src/countersign/$tag and runs, with stdin from your terminal:"
        cs_note "  sudo /usr/local/src/countersign/$tag/packaging/install.sh ${args[*]} --bin-dir /usr/local/src/countersign/$tag/bin"
        cs_note "install.sh's plan follows. This dry run extracted the tree as you, so it passes"
        cs_note "--allow-user-tree; a real run extracts as root and needs no such flag."
        bash "$tree/packaging/install.sh" --dry-run --allow-user-tree "${args[@]}" --bin-dir "$tree/bin" ||
            cs_die "install.sh --dry-run failed (above); a real run would fail the same way"
        cs_say ""
        cs_say "(dry run: nothing was installed)"
        return 0
    fi

    # The tree stays, root's, for uninstall.sh and as a record of what was
    # installed, next to the trees trusted-build.sh makes.
    cs_step "install"
    local dest=/usr/local/src/countersign/$tag
    sudo install -d -o root -g root -m 0755 /usr/local/src/countersign
    sudo rm -rf -- "$dest"
    sudo mv -T -- "$tree" "$dest"
    cs_note "release tree in $dest"
    local cmd=(sudo "$dest/packaging/install.sh" "${args[@]}" --bin-dir "$dest/bin")
    printf '  +'
    printf ' %q' "${cmd[@]}"
    printf '\n'
    "${cmd[@]}" </dev/tty || cs_die "install.sh failed (above). Run this again once the cause is fixed; every step is safe to repeat"
    cs_say ""
    cs_say "Uninstall with: sudo $dest/packaging/uninstall.sh"
}

countersign_get "$@"
