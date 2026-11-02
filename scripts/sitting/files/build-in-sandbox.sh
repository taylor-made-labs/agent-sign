# The build, run inside a throwaway account that systemd makes for each run
# (agent-sign-sitting.sh runs it twice with `systemd-run --wait --pipe -p
# DynamicUser=yes ...`, once per phase). It is NOT run as Taylor or as root: it
# builds third-party code (the dependencies' build scripts), which must never run
# while sudo is cached.
#
# Usage (the sitting's one-line bootstrap does this): bash ./build-in-sandbox.sh fetch|compile
#
# Why two phases (review finding A-4): one systemd-run call cannot give the fetch
# a network and the compile none. Build scripts and proc-macros run in the
# compile, so that is where the network must be closed.
#
#   fetch:   Input: a tar on standard input, unpacked by the bootstrap into
#            /tmp/agent-sign-build, holding this script and source.tar (the `git
#            archive` of the pinned commit, made from a verified bundle).
#            Needs the network, with private address ranges and this machine's
#            own global addresses denied by the sitting (IPAddressDeny; the DNS
#            servers alone allowed).
#            Downloads the Rust toolchain, checks it against the pinned hash,
#            installs it, runs `cargo fetch --locked`, and writes to standard
#            output a tar of toolchain.tar.xz, cargo/registry/cache (the .crate
#            files) and cargo/registry/index. No crate code runs here: cargo
#            fetch only downloads and checks hashes. The extracted sources
#            (registry/src) are left out on purpose.
#   compile: Input: this script, source.tar and fetched.tar (the fetch's output).
#            No network at all (PrivateNetwork=yes), and no /run. It trusts
#            nothing the fetch phase made: it checks toolchain.tar.xz against the
#            pinned hash again and every .crate file against the checksum in
#            Cargo.lock, takes ONLY the toolchain archive, the .crate files and
#            the registry index from fetched.tar (never registry/src, which cargo
#            would trust as the crates' source, and never a cargo config), so
#            cargo extracts every crate from a checked .crate itself; then builds
#            with --frozen and writes a tar of the five programs to standard
#            output.
#
# Needs TOOLCHAIN_URL (fetch only), TOOLCHAIN_SHA256 and RUST_VERSION in the
# environment. Every message goes to standard error, so standard output stays clean.
# Nothing else is kept: the account has no capabilities, no home and no state
# that outlives the run, sees none of the machine's other accounts' files, and
# its only output is the tar, which the sitting refuses if it holds a test build
# and hashes before root installs anything.
set -euo pipefail
umask 077

phase=${1:?usage: build-in-sandbox.sh fetch|compile}
: "${TOOLCHAIN_SHA256:?}" "${RUST_VERSION:?}"

work=/tmp/agent-sign-build
export HOME=$work/home CARGO_HOME=$work/cargo CARGO_TARGET_DIR=$work/target
mkdir -p "$HOME" "$CARGO_HOME" "$work/src" "$work/toolchain"
cd "$work"

check_toolchain() {
  # The hash is the pinned one (scripts/sitting/pins.env): anything else is refused.
  echo "$TOOLCHAIN_SHA256  toolchain.tar.xz" | sha256sum --check --quiet - >&2
}

install_toolchain() {
  echo "build: installing the toolchain into the sandbox" >&2
  tar -x -J -f toolchain.tar.xz -C toolchain --strip-components=1
  toolchain/install.sh --prefix="$work/rust" --disable-ldconfig --without=rust-docs >&2
  export PATH=$work/rust/bin:/usr/bin:/bin
}

# A missing or empty archive is named in plain words, not left to tar's "This
# does not look like a tar archive".
[ -s source.tar ] || { echo "build: source.tar is missing or empty in what this sandbox was handed" >&2; exit 1; }
echo "build: unpacking the source" >&2
tar -x -f source.tar -C src

case $phase in
  fetch)
    : "${TOOLCHAIN_URL:?}"
    echo "build: downloading rust $RUST_VERSION" >&2
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
      --output toolchain.tar.xz "$TOOLCHAIN_URL"
    check_toolchain
    install_toolchain
    cd src
    echo "build: fetching the dependencies the lockfile names" >&2
    cargo fetch --locked >&2
    cd "$work"
    echo "build: fetch done" >&2
    tar -c -f - toolchain.tar.xz cargo/registry/cache cargo/registry/index
    ;;

  compile)
    [ -s fetched.tar ] || { echo "build: fetched.tar (the fetch phase's output) is missing or empty in what this sandbox was handed" >&2; exit 1; }
    echo "build: unpacking what the fetch phase handed over (the toolchain archive, the .crate files and the index only)" >&2
    tar -x -f fetched.tar toolchain.tar.xz cargo/registry/cache cargo/registry/index
    check_toolchain
    # Every crate file must be the one Cargo.lock names, whatever the fetch phase
    # made of it (cargo itself only checks a crate's hash when it downloads it).
    echo "build: checking every crate against Cargo.lock" >&2
    count=0
    while read -r sum file; do
      found=$(ls -1 cargo/registry/cache/*/"$file" 2>/dev/null | head -n 1 || true)
      [ -n "$found" ] || { echo "build: the crate $file is missing from what the fetch phase handed over" >&2; exit 1; }
      echo "$sum  $found" | sha256sum --check --quiet - >&2 || { echo "build: the crate $file does not match Cargo.lock" >&2; exit 1; }
      count=$((count + 1))
    done < <(awk '
      /^\[\[package\]\]/ { name = ""; ver = ""; sum = "" }
      /^name = / { name = $3; gsub(/"/, "", name) }
      /^version = / { ver = $3; gsub(/"/, "", ver) }
      /^checksum = / { sum = $3; gsub(/"/, "", sum); print sum, name "-" ver ".crate" }
    ' src/Cargo.lock)
    [ "$count" -gt 0 ] || { echo "build: Cargo.lock names no crates to check" >&2; exit 1; }
    install_toolchain
    cd src
    echo "build: compiling (release, offline, $count crates checked)" >&2
    cargo build --release --frozen --offline \
      --bin agent-sign --bin agent-signd --bin agent-launchd --bin agent-git --bin agent-ssh-sign >&2
    echo "build: done" >&2
    tar -c -f - -C "$CARGO_TARGET_DIR/release" \
      agent-sign agent-signd agent-launchd agent-git agent-ssh-sign
    ;;

  *)
    echo "build: unknown phase $phase" >&2
    exit 2
    ;;
esac
