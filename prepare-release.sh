#!/bin/sh

set -e
set -x

# The machine (or emulated platform) this runs on decides the tarball: x86_64 or aarch64.
# KLLDAP 0.8.0 is 64-bit only.
ARCH=$(uname -m)

# Build the binary server. On x86_64 for the x86-64-v2 instruction set, so it runs
# on x86-64-v2 processors and newer. The flag goes in only through
# CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS, which merges with .cargo/config.toml's
# p384 cfg; RUSTFLAGS would replace it. On aarch64 this variable does not apply: no CPU flag.
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64-v2" cargo build --release -p lldap

# Build the frontend, unless this run reuses the web files another run built in this tree
# (they are architecture-free): SKIP_FRONTEND=1, which refuses if they are missing.
if [ "${SKIP_FRONTEND:-}" = 1 ]; then
    [ -f app/pkg/lldap_app_bg.wasm ] || { echo "SKIP_FRONTEND=1 but app/pkg has no web build" >&2; exit 1; }
else
    ./app/build.sh
fi

VERSION=$(git describe --tags)

# Package the release for this architecture.
mkdir -p /tmp/release/$ARCH
cp target/release/lldap /tmp/release/$ARCH
cp -R app/index.html app/static app/pkg lldap_config.docker_template.toml README.md LICENSE /tmp/release/$ARCH
tar -czvf lldap-$ARCH-glibc-${VERSION}.tar.gz -C /tmp/release $ARCH

echo "Release archive created:"
ls -l lldap-$ARCH-glibc-${VERSION}.tar.gz
