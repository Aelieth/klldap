#!/bin/sh

set -e
set -x

# Build the binary server for x86_64 with broad CPU compatibility.
# Explicitly target the baseline x86-64 instruction set (equivalent to the original
# amd64 baseline). This prevents accidental use of x86-64-v3 (AVX2 etc.) features
# that would make the binary incompatible with older x86_64 processors.
# The previous release apparently picked up v3 instructions (likely via native build
# on a modern CPU or implicit optimization).
RUSTFLAGS="-C target-cpu=x86-64" cargo build --release -p lldap

cargo install cross

# Build for 32-bit ARMv7 (hard-float) using glibc instead of musl.
# MIT Kerberos (via the kerberos crate + pkg-config/bindgen) requires glibc.
# The cross target is now gnueabihf. Ensure your Cross.toml / Docker setup
# provides the necessary cross-compiler and libkrb5-dev for armhf if the
# kerberos build step runs during cross-compilation.
cross build --target=armv7-unknown-linux-gnueabihf -p lldap --release

# Build the frontend (unchanged).
./app/build.sh

VERSION=$(git describe --tags)

# Package x86_64 (glibc) release
mkdir -p /tmp/release/x86_64
cp target/release/lldap /tmp/release/x86_64
cp -R app/index.html app/static app/pkg lldap_config.docker_template.toml README.md LICENSE /tmp/release/x86_64
tar -czvf lldap-x86_64-glibc-${VERSION}.tar.gz -C /tmp/release x86_64

# Package armv7 (glibc) release
mkdir -p /tmp/release/armv7
cp target/armv7-unknown-linux-gnueabihf/release/lldap /tmp/release/armv7
cp -R app/index.html app/static app/pkg lldap_config.docker_template.toml README.md LICENSE /tmp/release/armv7
tar -czvf lldap-armv7-glibc-${VERSION}.tar.gz -C /tmp/release armv7

echo "Release archives created:"
ls -l *.tar.gz
