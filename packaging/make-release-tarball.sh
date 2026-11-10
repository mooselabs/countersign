#!/bin/bash
# Make the files of a GitHub release: the tarball, the installer and their
# SHA-256 sums. The release workflow runs it; packaging/tests/get.sh runs it
# on stub binaries.
#
#   packaging/make-release-tarball.sh --version 0.1.0 --bin-dir target/release \
#       --out-dir dist [--mtime EPOCH]
#
#   --version  the release version, without the leading v
#   --bin-dir  where cn and cnd were built
#   --out-dir  where the files go; must be missing or empty
#   --mtime    the time stamped on every file in the tarball, in seconds
#              since 1970 (default: $SOURCE_DATE_EPOCH, else the time of the
#              checkout's HEAD commit)
#
# It writes, in --out-dir:
#   countersign-<version>-x86_64-linux.tar.gz
#       one top directory, countersign-<version>/, with bin/cn, bin/cnd,
#       packaging/ (install.sh, uninstall.sh and the files they install),
#       examples/config.toml, CHANGELOG.md, LICENSE, NOTICE and README.md
#   install.sh   a copy of packaging/get.sh, the one-line installer
#   SHA256SUMS   the sums of both
#
# The tarball is the same bytes for the same inputs: files in name order,
# owner and group 0, modes 0755 or 0644, one mtime, gzip without a name or
# time stamp.
set -euo pipefail

here=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(dirname "$here")

version=
bin_dir=
out_dir=
mtime=${SOURCE_DATE_EPOCH:-}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}"
}
die() { printf 'make-release-tarball.sh: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case $1 in
    --version) version=${2:?--version needs a value}; shift 2 ;;
    --version=*) version=${1#*=}; shift ;;
    --bin-dir) bin_dir=${2:?--bin-dir needs a value}; shift 2 ;;
    --bin-dir=*) bin_dir=${1#*=}; shift ;;
    --out-dir) out_dir=${2:?--out-dir needs a value}; shift 2 ;;
    --out-dir=*) out_dir=${1#*=}; shift ;;
    --mtime) mtime=${2:?--mtime needs a value}; shift 2 ;;
    --mtime=*) mtime=${1#*=}; shift ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'make-release-tarball.sh: unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "--version must look like 0.1.0 or 0.2.0-rc.1, got '$version'"
[ -n "$bin_dir" ] || die "--bin-dir is required"
[ -n "$out_dir" ] || die "--out-dir is required"
for bin in cn cnd; do
    [ -f "$bin_dir/$bin" ] && [ -x "$bin_dir/$bin" ] || die "$bin_dir/$bin is not an executable file"
done
if [ -z "$mtime" ]; then
    mtime=$(git -C "$repo" log -1 --format=%ct) || die "no --mtime and no git commit to take it from"
fi
[[ $mtime =~ ^[0-9]+$ ]] || die "--mtime must be seconds since 1970, got '$mtime'"
if [ -e "$out_dir" ]; then
    [ -d "$out_dir" ] && [ -z "$(ls -A -- "$out_dir")" ] || die "$out_dir exists and is not an empty directory"
fi

export LC_ALL=C TZ=UTC
umask 022
name=countersign-$version
tarball=$name-x86_64-linux.tar.gz

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
top=$stage/$name

# put MODE SRC DEST: copy SRC to $top/DEST with MODE.
put() { install -D -m "$1" -- "$2" "$top/$3"; }

put 0755 "$bin_dir/cn" bin/cn
put 0755 "$bin_dir/cnd" bin/cnd
put 0755 "$here/install.sh" packaging/install.sh
put 0755 "$here/uninstall.sh" packaging/uninstall.sh
for f in README.md lib/trusted-path.sh sysusers.d/countersign.conf tmpfiles.d/countersign.conf \
    countersign.socket countersign.service computer.mooselabs.countersign.policy; do
    put 0644 "$here/$f" "packaging/$f"
done
put 0644 "$repo/examples/config.toml" examples/config.toml
for f in CHANGELOG.md LICENSE NOTICE README.md; do
    put 0644 "$repo/$f" "$f"
done
chmod 0755 "$top"
find "$top" -type d -exec chmod 0755 {} +

mkdir -p -- "$out_dir"
tar --create --directory="$stage" --format=gnu --sort=name \
    --owner=0 --group=0 --numeric-owner --mtime="@$mtime" -- "$name" |
    gzip -9 -n >"$out_dir/$tarball"
install -m 0644 -- "$here/get.sh" "$out_dir/install.sh"
(cd -- "$out_dir" && sha256sum -- "$tarball" install.sh >SHA256SUMS)

printf '%s\n' "$out_dir/$tarball" "$out_dir/install.sh" "$out_dir/SHA256SUMS"
