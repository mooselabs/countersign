#!/bin/bash
# Build countersign as root from a commit on GitHub, with the distribution's
# Rust toolchain, in a root-owned tree, then install it with that tree's
# packaging/install.sh. Nothing a non-root user can write takes part: not a
# developer's checkout, not ~/.cargo, not a rustc wrapper, not user config.
# See packaging/README.md, "Install".
#
#   sudo /usr/local/src/countersign/<commit>/packaging/trusted-build.sh \
#       --commit <40-hex commit> [--factor F] [--user NAME] [--force] [--dry-run]
#
#   --commit    the full commit hash to build. Push it to GitHub first.
#   --dry-run   print the plan; clones, builds and installs nothing, needs no
#               root
#   --factor, --user, --force
#               passed to install.sh (see install.sh --help)
#
# The tree is /usr/local/src/countersign/<commit>: cloned fresh from
# https://github.com/mooselabs/countersign if it is missing, else checked
# (root-owned throughout, HEAD at the commit, no changes) and built again.
# This script refuses to run from a place a user other than root can change,
# so run it from such a tree (the README shows how to make the first one).
#
# Build scripts and proc macros of the locked dependencies run as root during
# the build, as they would in any root build of a package.
set -euo pipefail

here=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=lib/trusted-path.sh
. "$here/lib/trusted-path.sh"

# For tests only: with --dry-run, every system path is read below this prefix.
R=${COUNTERSIGN_INSTALL_ROOT:-}

url=https://github.com/mooselabs/countersign
base=/usr/local/src/countersign
commit=
dry=0
pass=()

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}"
}

while [ $# -gt 0 ]; do
    case $1 in
    --commit) commit=${2:?--commit needs a value}; shift 2 ;;
    --commit=*) commit=${1#*=}; shift ;;
    --factor | --user) pass+=("$1" "${2:?$1 needs a value}"); shift 2 ;;
    --factor=* | --user=*) pass+=("$1"); shift ;;
    --force) pass+=("$1"); shift ;;
    --dry-run) dry=1; shift ;;
    --bin-dir | --bin-dir=* | --allow-user-tree)
        printf 'trusted-build.sh: %s is not passed on: install.sh gets the tree this script built\n' "$1" >&2
        exit 2
        ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'trusted-build.sh: unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() { printf 'trusted-build.sh: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

# run CMD...: print it, then run it (or only print it in a dry run).
run() {
    if [ "$dry" = 1 ]; then printf '  would run:'; else printf '  +'; fi
    printf ' %q' "$@"
    printf '\n'
    [ "$dry" = 1 ] || "$@"
}

# The environment for git and cargo: nothing from the caller's. HOME and
# CARGO_HOME are root-owned; cargo reads config only from them and from the
# tree and its parents, which are root-owned too.
home=$base/.home
clean_env=(env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$home" CARGO_HOME="$home/cargo"
    LANG=C.UTF-8 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0)
git=/usr/bin/git
cargo=/usr/bin/cargo
rustc=/usr/bin/rustc
get_toolchain="sudo zypper install rust cargo"

# --- checks -----------------------------------------------------------------

[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "--commit needs the full 40-character commit hash (git rev-parse HEAD after pushing), got '$commit'"
if [ "$dry" = 0 ]; then
    [ -z "$R" ] || die "COUNTERSIGN_INSTALL_ROOT is for tests and works only with --dry-run"
    [ "$(id -u)" = 0 ] || die "run as root (or add --dry-run to see the plan)"
fi
umask 022
tree=$base/$commit

step "checks"

why=
for f in "${BASH_SOURCE[0]}" "$here/lib/trusted-path.sh"; do
    why=$(untrusted_reason "$f")
    [ -z "$why" ] || break
done
[ -z "$why" ] ||
    die "refusing to run from a place a user other than root can change: $why. Run the copy in a root-owned tree; packaging/README.md, \"Install\", shows how to make the first one"
note "this script can be changed by root only"

# The nearest existing directory at or above $base must be root's alone.
d=$base
while [ ! -e "$R$d" ]; do d=$(dirname "$d"); done
why=$(untrusted_reason "$R$d")
[ -z "$why" ] || die "cannot build under $base: $why"

[ -x "$R$git" ] || die "$git not found. Install it: sudo zypper install git"
why=$(untrusted_reason "$R$git")
[ -z "$why" ] || die "$git cannot be trusted: $why"
for tool in "$cargo" "$rustc"; do
    [ -x "$R$tool" ] || die "$tool not found. Install the distribution's Rust toolchain: $get_toolchain"
    real=$(realpath -e -- "$R$tool")
    case ${real##*/} in
    rustup*) die "$tool is rustup's proxy, which runs a toolchain from a user's home. Install the distribution's Rust toolchain instead: $get_toolchain" ;;
    esac
    why=$(untrusted_reason "$real")
    [ -z "$why" ] || die "$tool cannot be trusted: $why"
done
rustc_version=$("${clean_env[@]}" "$R$rustc" --version | awk '{ print $2 }')
[[ $rustc_version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || die "cannot read the version of $rustc from '$rustc_version'"
note "rustc $rustc_version ($rustc)"

# version_lt A B: A is older than B; both are MAJOR.MINOR[.PATCH].
version_lt() {
    local a b i
    IFS=. read -r -a a <<<"$1"
    IFS=. read -r -a b <<<"$2"
    for i in 0 1 2; do
        if ((${a[i]:-0} != ${b[i]:-0})); then
            ((${a[i]:-0} < ${b[i]:-0}))
            return
        fi
    done
    return 1
}

# check_rust_version MANIFEST: the toolchain is new enough for it.
check_rust_version() {
    local want
    want=$(sed -n 's/^rust-version[[:space:]]*=[[:space:]]*"\([0-9.]*\)".*/\1/p' "$1" | head -n 1)
    [ -n "$want" ] || die "no rust-version in $1"
    ! version_lt "${rustc_version%%[!0-9.]*}" "$want" ||
        die "rustc $rustc_version is older than $want, the rust-version this commit needs. Update the distribution's toolchain: $get_toolchain"
    note "rust-version $want: ok"
}

# --- source -----------------------------------------------------------------

step "source: $url at $commit"
run install -d -o root -g root -m 0755 "$base" "$home"
if [ ! -e "$R$tree" ]; then
    if [ "$dry" = 1 ]; then
        note "would clone $url into $tree, check out $commit and check that HEAD is $commit"
    else
        tmp=$(mktemp -d "$base/.clone.XXXXXX")
        trap 'rm -rf "$tmp"' EXIT
        chmod 0755 "$tmp"
        run "${clean_env[@]}" "$git" clone --quiet --no-checkout "$url" "$tmp/src"
        run "${clean_env[@]}" "$git" -C "$tmp/src" -c advice.detachedHead=false checkout --quiet --detach "$commit"
        mv "$tmp/src" "$tree"
        rm -rf "$tmp"
        trap - EXIT
    fi
elif [ "$dry" = 1 ]; then
    note "would check $tree: root-owned throughout, HEAD at $commit, no changes"
else
    # Only root can have written here; check anyway that nothing else did.
    why=$(untrusted_reason "$tree")
    [ -z "$why" ] || die "cannot use $tree: $why"
    odd=$(find "$tree" \( ! -user 0 -o \( ! -type l -perm /022 \) \) -print -quit)
    [ -z "$odd" ] || die "$tree is not root's alone ($odd). Remove $tree and run again"
    changes=$("${clean_env[@]}" "$git" -C "$tree" status --porcelain --untracked-files=all)
    [ -z "$changes" ] || die "$tree has changes ($git -C $tree status). Remove $tree and run again"
    note "$tree is root's alone and unchanged"
fi
if [ "$dry" = 0 ]; then
    head=$("${clean_env[@]}" "$git" -C "$tree" rev-parse HEAD)
    [ "$head" = "$commit" ] || die "$tree is at $head, not $commit. Remove $tree and run again"
    note "HEAD is $commit"
    check_rust_version "$tree/Cargo.toml"
else
    note "(dry run: rust-version read from this script's tree; a real run reads the commit's)"
    check_rust_version "$here/../Cargo.toml"
fi

# --- build ------------------------------------------------------------------

step "build"
bin_dir=$tree/target/release
if [ "$dry" = 1 ]; then
    note "would run, in $tree:"
fi
(
    [ "$dry" = 1 ] || cd "$tree"
    run "${clean_env[@]}" "$cargo" build --locked --release
)
if [ "$dry" = 0 ]; then
    for bin in cn cnd; do
        [ -x "$bin_dir/$bin" ] || die "the build did not produce $bin_dir/$bin"
    done
    note "sha256 of the built files:"
    sha256sum "$bin_dir/cn" "$bin_dir/cnd" | sed 's/^/    /'
fi

# --- install ----------------------------------------------------------------

step "install"
install_cmd=("$tree/packaging/install.sh" "${pass[@]}" --bin-dir "$bin_dir")
if [ "$dry" = 1 ]; then
    run "${install_cmd[@]}"
    say ""
    say "(dry run: nothing was changed)"
else
    printf '  + exec'
    printf ' %q' "${install_cmd[@]}"
    printf '\n'
    exec "${install_cmd[@]}"
fi
