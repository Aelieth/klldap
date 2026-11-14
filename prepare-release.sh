#!/bin/sh

set -e
set -x

# Build the binary server for x86_64 with broad CPU compatibility.
# Explicitly target the baseline x86-64 instruction set (equivalent to the original
# amd64 baseline). This prevents accidental use of x86-64-v3 (AVX2 etc.) features
# that would make the binary incompatible with older x86_64 processors.
# The previous release apparently picked up v3 instructions (likely via native build
# on a modern CPU or implicit optimization).
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64" cargo build --release -p lldap

# Build the frontend (unchanged).
./app/build.sh

VERSION=$(git describe --tags)

# Package the x86_64 (glibc) release. KLLDAP 0.8.0 is 64-bit only: there is no armv7 tarball.
mkdir -p /tmp/release/x86_64
cp target/release/lldap /tmp/release/x86_64
cp -R app/index.html app/static app/pkg lldap_config.docker_template.toml README.md LICENSE /tmp/release/x86_64
tar -czvf lldap-x86_64-glibc-${VERSION}.tar.gz -C /tmp/release x86_64

echo "Release archive created:"
ls -l *.tar.gz
