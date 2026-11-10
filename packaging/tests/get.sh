#!/bin/bash
# Checks the release packaging and the one-line installer (packaging/get.sh):
# makes a release with make-release-tarball.sh from stub binaries, serves it
# from file:// and from a local HTTP server, and runs get.sh against it with
# --dry-run and stub system tools. Needs no root and changes nothing outside a
# temporary directory. Run: bash packaging/tests/get.sh
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pkg=$(dirname "$here")
tmp=$(mktemp -d)
server=
cleanup() {
    [ -z "$server" ] || kill "$server" 2>/dev/null || true
    rm -rf "$tmp"
}
trap cleanup EXIT

fails=0
pass() { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }

version=0.1.0
tag=v$version
tarball=countersign-$version-x86_64-linux.tar.gz

# --- a release from stub binaries -------------------------------------------

bins=$tmp/bins
mkdir -p "$bins"
printf '#!/bin/sh\necho stub\n' >"$bins/cn"
printf '#!/bin/sh\necho stub\n' >"$bins/cnd"
chmod +x "$bins/cn" "$bins/cnd"

release() { # release DIR: the release files in DIR
    bash "$pkg/make-release-tarball.sh" --version "$version" --bin-dir "$bins" \
        --out-dir "$1" --mtime 1700000000 >/dev/null
}
good=$tmp/good/$tag
release "$good"
release "$tmp/again"

out=
expect() { # expect NAME CONDITION...
    local name=$1
    shift
    if "$@"; then pass "$name"; else
        fail "$name"
        printf '%s\n' "$out" | sed 's/^/      | /'
    fi
}
has() { grep -qF -- "$1" <<<"$out"; }
not() { ! "$@"; }
ok() { [ "$status" = 0 ]; }

expect "release: the same bytes twice" cmp -s "$good/SHA256SUMS" "$tmp/again/SHA256SUMS"
sums_check() { (cd "$1" && sha256sum --check --strict --quiet SHA256SUMS); }
expect "release: SHA256SUMS checks" sums_check "$good"
expect "release: installer is get.sh" cmp -s "$good/install.sh" "$pkg/get.sh"
out=$(tar -tvzf "$good/$tarball")
names=$(tar -tzf "$good/$tarball")
expect "tarball: one top directory" test -z "$(grep -v "^countersign-$version/" <<<"$names")"
for f in bin/cn bin/cnd packaging/install.sh packaging/uninstall.sh packaging/lib/trusted-path.sh \
    packaging/countersign.service examples/config.toml CHANGELOG.md LICENSE README.md; do
    expect "tarball: has $f" grep -qx "countersign-$version/$f" <<<"$names"
done
expect "tarball: no tests or get.sh" not grep -Eq 'tests/|get\.sh' <<<"$names"
expect "tarball: owner 0/0" test -z "$(awk '$2 != "0/0"' <<<"$out")"
expect "tarball: no group or other write" test -z "$(awk 'substr($1, 6, 1) != "-" || substr($1, 9, 1) != "-"' <<<"$out")"
expect "tarball: install.sh executable" grep -q "^-rwxr-xr-x .* countersign-$version/packaging/install.sh$" <<<"$out"

# --- stub system tools ------------------------------------------------------

stubs=$tmp/stubs
calls=$tmp/calls.log
mkdir -p "$stubs"
: >"$calls"
cat >"$stubs/uname" <<'EOF'
#!/bin/sh
case $1 in
-s) echo "${FAKE_OS:-Linux}" ;;
-m) echo "${FAKE_ARCH:-x86_64}" ;;
-r) echo "${FAKE_KERNEL:-6.8.0-test}" ;;
*) exec /usr/bin/uname "$@" ;;
esac
EOF
real_id=$(command -v id)
cat >"$stubs/id" <<EOF
#!/bin/sh
if [ "\$#" = 1 ] && [ "\$1" = -u ] && [ -n "\${FAKE_UID:-}" ]; then echo "\$FAKE_UID"; exit 0; fi
exec $real_id "\$@"
EOF
# gh: FAKE_GH=out (not logged in, the default), ok, or refuse.
cat >"$stubs/gh" <<'EOF'
#!/bin/sh
echo "gh $*" >>"$CALLS"
case "$1 $2" in
"auth status") [ "${FAKE_GH:-out}" != out ] ;;
"attestation verify")
    case " $* " in *" --help "*) echo "      --source-ref string"; exit 0 ;; esac
    [ "${FAKE_GH:-out}" = ok ] || { echo "no matching attestations found"; exit 1; }
    ;;
*) exit 99 ;;
esac
EOF
# A dry run must not use sudo.
cat >"$stubs/sudo" <<'EOF'
#!/bin/sh
echo "sudo $*" >>"$CALLS"; exit 99
EOF
# For install.sh --dry-run.
cat >"$stubs/systemctl" <<'EOF'
#!/bin/sh
[ "$1" = --version ] && { echo "systemd 256 (256.1)"; exit 0; }
echo "systemctl $*" >>"$CALLS"; exit 99
EOF
cat >"$stubs/pkaction" <<'EOF'
#!/bin/sh
[ "$1" = --version ] && { echo "pkaction version 126"; exit 0; }
echo "pkaction $*" >>"$CALLS"; exit 99
EOF
for tool in systemd-creds systemd-run systemd-sysusers systemd-tmpfiles zypper pamu2fcfg; do
    # shellcheck disable=SC2016 # $* and $CALLS belong to the stub, not to this script
    printf '#!/bin/sh\necho "%s $*" >>"$CALLS"; exit 99\n' "$tool" >"$stubs/$tool"
done
chmod +x "$stubs"/*

# new_root: a fresh fake root with a systemd system and a polkit 126 PAM stack.
new_root() {
    root=$tmp/root.$RANDOM$RANDOM
    mkdir -p "$root/run/systemd/system" "$root/usr/lib/pam.d" "$root/usr/lib/systemd/system" "$root/etc/pam.d"
    printf '#%%PAM-1.0\nauth       include      common-auth\n' >"$root/usr/lib/pam.d/polkit-1"
    printf '[Service]\nPrivateDevices=yes\n' >"$root/usr/lib/systemd/system/polkit-agent-helper@.service"
}

# get [ARGS...]: run get.sh piped into bash as the one-liner does, with
# --dry-run and the release in $base. Output in $out, status in $status.
base=file://$good
get() {
    status=0
    : >"$calls"
    out=$(CALLS=$calls COUNTERSIGN_INSTALL_ROOT=$root PATH="$stubs:$PATH" \
        bash -s -- --dry-run --version "$tag" --base-url "$base" "$@" <"$pkg/get.sh" 2>&1) || status=$?
}
no_sudo() { ! grep -q '^sudo' "$calls"; }

# The tarball's own install.sh finds the binaries in bin/ without --bin-dir.
new_root
mkdir -p "$tmp/x"
tar -xzf "$good/$tarball" -C "$tmp/x"
status=0
out=$(CALLS=$calls COUNTERSIGN_INSTALL_ROOT=$root PATH="$stubs:$PATH" \
    bash "$tmp/x/countersign-$version/packaging/install.sh" --dry-run --allow-user-tree --user nobody \
    </dev/null 2>&1) || status=$?
expect "tarball install.sh: exit 0" ok
expect "tarball install.sh: finds bin/" has "would install $tmp/x/countersign-$version/bin/cn -> /usr/bin/cn (root, 0755)"

# --- dry runs that pass -----------------------------------------------------

new_root
get
expect "dry run: exit 0" ok
expect "dry run: checksum" has "matches SHA256SUMS"
expect "dry run: no provenance without gh login" has "provenance not checked: gh is not logged in"
expect "dry run: says how to check by hand" has "gh attestation verify --repo mooselabs/countersign"
expect "dry run: install.sh plan" has "would install "
expect "dry run: install.sh gets the user" has "--user $(id -un) --factor password"
expect "dry run: install.sh gets bin/" has "/countersign-$version/bin/cn -> /usr/bin/cn (root, 0755)"
expect "dry run: names the kept tree" has "/usr/local/src/countersign/$tag/packaging/install.sh"
expect "dry run: fresh install inits" has "cnd init"
expect "dry run: no sudo" no_sudo
expect "dry run: nothing installed" has "(dry run: nothing was installed)"

get --factor touch --force
expect "dry run --factor touch --force: passed on" has "--factor touch --force"

FAKE_GH=ok get --require-attestation
expect "gh ok: exit 0" ok
expect "gh ok: verified" has "provenance verified"
expect "gh ok: pinned to the workflow and tag" grep -q -- "--signer-workflow mooselabs/countersign/.github/workflows/release.yml --source-ref refs/tags/$tag" "$calls"

# An existing touch install: the upgrade keeps the factor.
mkdir -p "$root/usr/bin"
printf '#!/bin/sh\necho "cn 0.0.9 (protocol 1)"\n' >"$root/usr/bin/cn"
chmod +x "$root/usr/bin/cn"
printf '#%%PAM-1.0\n# countersign-managed: written by countersign packaging/install.sh --factor touch\nauth x\n' \
    >"$root/etc/pam.d/polkit-1"
get
expect "upgrade: exit 0" ok
expect "upgrade: seen" has "countersign is installed (cn 0.0.9 (protocol 1)), with factor touch: this upgrades it"
expect "upgrade: keeps the factor" has "--factor touch"
get --factor password
expect "upgrade to password: says so" has "the factor changes from touch to password"

# Served over HTTP, as GitHub serves it.
if command -v python3 >/dev/null; then
    port=$((20000 + RANDOM % 20000))
    python3 -m http.server --bind 127.0.0.1 --directory "$tmp/good" "$port" >/dev/null 2>&1 &
    server=$!
    for _ in $(seq 50); do
        curl -fsS -o /dev/null "http://127.0.0.1:$port/$tag/SHA256SUMS" 2>/dev/null && break
        sleep 0.1
    done
    new_root
    base=http://127.0.0.1:$port/$tag
    get
    expect "http: exit 0" ok
    expect "http: checksum" has "matches SHA256SUMS"
    kill "$server" 2>/dev/null || true
    server=
    base=file://$good
else
    printf 'skip  http: no python3\n'
fi

# --- refusals ---------------------------------------------------------------

# variant NAME: a copy of the good release in $tmp/NAME/$tag, served from $base.
variant() {
    rm -rf "${tmp:?}/$1"
    mkdir -p "$tmp/$1"
    cp -r "$good" "$tmp/$1/$tag"
    v=$tmp/$1/$tag
    base=file://$v
}

new_root
variant corrupt
printf 'x' >>"$v/$tarball"
get
expect "corrupt tarball: refused" not ok
expect "corrupt tarball: says why" has "does not match its line in SHA256SUMS"
expect "corrupt tarball: no install.sh run" not has "would install"

variant wrongsum
sed -i "s/^[0-9a-f]\{8\}/00000000/" "$v/SHA256SUMS"
get
expect "wrong SUMS line: refused" not ok
expect "wrong SUMS line: says why" has "does not match"

variant nosum
grep -v "$tarball" "$good/SHA256SUMS" >"$v/SHA256SUMS"
get
expect "no SUMS line: refused" not ok
expect "no SUMS line: says why" has "SHA256SUMS has no line for $tarball"

variant twosums
grep "$tarball" "$good/SHA256SUMS" >>"$v/SHA256SUMS"
get
expect "two SUMS lines: refused" not ok
expect "two SUMS lines: says why" has "more than one line"

variant missing
rm "$v/$tarball"
get
expect "missing tarball: refused" not ok
expect "missing tarball: says why" has "cannot download"

# A tarball with a path outside its top directory, with a matching sum.
variant escape
mkdir -p "$tmp/escape-src/countersign-$version"
: >"$tmp/escape-src/evil"
tar -czf "$v/$tarball" -C "$tmp/escape-src" "countersign-$version" evil
(cd "$v" && sha256sum "$tarball" install.sh >SHA256SUMS)
get
expect "path outside the top directory: refused" not ok
expect "path outside the top directory: says why" has "outside countersign-$version/"

# A symbolic link in the tarball.
variant link
mkdir -p "$tmp/link-src/countersign-$version"
ln -s /etc/passwd "$tmp/link-src/countersign-$version/bin"
tar -czf "$v/$tarball" -C "$tmp/link-src" "countersign-$version"
(cd "$v" && sha256sum "$tarball" install.sh >SHA256SUMS)
get
expect "symbolic link: refused" not ok
expect "symbolic link: says why" has "other than files and directories"

base=file://$good
FAKE_GH=refuse get
expect "attestation refused: refused" not ok
expect "attestation refused: shows gh's reason" has "gh: no matching attestations found"
get --require-attestation
expect "--require-attestation without gh login: refused" not ok
expect "--require-attestation without gh login: says why" has "provenance cannot be checked: gh is not logged in"

FAKE_KERNEL=6.4.12 get
expect "kernel 6.4: refused" not ok
expect "kernel 6.4: says why" has "needs 6.5 or later"
FAKE_ARCH=aarch64 get
expect "aarch64: refused" not ok
expect "aarch64: says why" has "x86_64 only"
FAKE_OS=Darwin get
expect "not Linux: refused" not ok
expect "not Linux: says why" has "Linux only"
FAKE_UID=0 get
expect "root: refused" not ok
expect "root: says why" has "not as root"
rm -r "$root/run/systemd/system"
get
expect "no systemd: refused" not ok
expect "no systemd: says why" has "systemd is not the running init system"
new_root

get --factor click
expect "bad factor: refused" not ok
expect "bad factor: says why" has "--factor must be"
status=0
out=$(PATH="$stubs:$PATH" bash -s -- --dry-run --base-url "$base" <"$pkg/get.sh" 2>&1) || status=$?
expect "--base-url without --version: refused" not ok
expect "--base-url without --version: says why" has "--base-url needs --version"
base=http://example.com/$tag
get
expect "http to another host: refused" not ok
expect "http to another host: says why" has "http:// to localhost"
base=file://$good

# A real run (no --dry-run) needs a terminal; without one it stops before
# sudo. setsid leaves it without a controlling terminal.
if command -v setsid >/dev/null; then
    status=0
    : >"$calls"
    out=$(CALLS=$calls PATH="$stubs:$PATH" setsid -w bash -s -- --version "$tag" --base-url "$base" \
        <"$pkg/get.sh" 2>&1) || status=$?
    expect "no terminal: refused" not ok
    expect "no terminal: says why" has "no terminal (/dev/tty)"
    expect "no terminal: no sudo" no_sudo
    status=0
    out=$(CALLS=$calls COUNTERSIGN_INSTALL_ROOT=$root PATH="$stubs:$PATH" bash -s -- --version "$tag" \
        --base-url "$base" <"$pkg/get.sh" 2>&1) || status=$?
    expect "test root without --dry-run: refused" has "works only with --dry-run"
else
    printf 'skip  no terminal: no setsid\n'
fi

# A script cut off mid-way runs nothing.
status=0
out=$(head -c 4000 "$pkg/get.sh" | PATH="$stubs:$PATH" bash -s -- --dry-run 2>&1) || status=$?
expect "cut-off script: prints nothing" test -z "$(grep -v 'syntax error\|unexpected end of file' <<<"$out")"

printf '\n'
if [ "$fails" = 0 ]; then
    printf 'all get.sh checks passed\n'
else
    printf '%s get.sh checks failed\n' "$fails"
    exit 1
fi
