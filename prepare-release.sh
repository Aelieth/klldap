#!/bin/sh

set -e
set -x

# The machine (or emulated platform) this runs on decides the tarball: x86_64 or aarch64.
# KLLDAP 0.8.0 is 64-bit only.
ARCH=$(uname -m)

# Build the binary server. On x86_64 for the x86-64-v2 instruction set, so it runs
# on x86-64-v2 processors and newer: rustc through
# CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS, which merges with .cargo/config.toml's
# p384 cfg (RUSTFLAGS would replace it), and gcc, for the C code crates bundle (SQLite,
# ring), through CFLAGS_x86_64_unknown_linux_gnu, which the cc crate reads. On aarch64
# neither variable applies: no CPU flag.
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64-v2" \
    CFLAGS_x86_64_unknown_linux_gnu="-march=x86-64-v2" cargo build --release -p lldap

# Prove the x86_64 build: C functions without run-time CPU dispatch must hold no
# instruction outside x86-64-v2 (VEX/EVEX v..., BMI1/BMI2, MOVBE, LZCNT/TZCNT).
check_v2() {
    fn=$(nm target/release/lldap | awk -v p="$1" '$3 ~ p {print $3; exit}')
    [ -n "$fn" ] || { echo "no function matching $1 in target/release/lldap" >&2; exit 1; }
    mkdir -p /tmp/release
    objdump -d --no-show-raw-insn --disassemble="$fn" target/release/lldap >/tmp/release/check_v2.dis
    total=$(grep -cE '^ +[0-9a-f]+:' /tmp/release/check_v2.dis || true)
    bad=$(grep -cE '^ +[0-9a-f]+:\s+(v[a-z0-9]+|andn|bextr|blsi|blsmsk|blsr|bzhi|mulx|pdep|pext|rorx|sarx|shlx|shrx|movbe|lzcnt|tzcnt)(\s|$)' /tmp/release/check_v2.dis || true)
    [ "$total" -gt 100 ] && [ "$bad" = 0 ] || { echo "$fn: $bad of $total instructions are outside x86-64-v2" >&2; exit 1; }
    echo "$fn: $total instructions, none outside x86-64-v2"
}
if [ "$ARCH" = x86_64 ]; then
    check_v2 '^sqlite3VdbeExec$'
    check_v2 '^ring_core_.*__x25519_ge_scalarmult_base$'
fi

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
