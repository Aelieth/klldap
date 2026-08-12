#! /bin/sh
set -e

cd "$(dirname "$0")"
if ! command -v wasm-pack > /dev/null 2>&1
then
  >&2 echo '`wasm-pack` not found. Try running `cargo install wasm-pack`'
  exit 1
fi
if ! command -v gzip > /dev/null 2>&1
then
  >&2 echo '`gzip` not found.'
  exit 1
fi

wasm-pack build --target web --release

gzip -9 -k -f pkg/lldap_app_bg.wasm
