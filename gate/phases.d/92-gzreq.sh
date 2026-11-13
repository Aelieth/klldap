# shellcheck shell=bash
# Phase: a compressed GraphQL body is not decoded. actix-web is built without
# compress-brotli, compress-gzip and compress-zstd. The plain post still answers,
# and the precompressed wasm asset is still served with its own gzip header.

# shellcheck disable=SC2154
D="$(phase_dir)"
BODY='{"query":"{ logs(limit: 1) { kind } }","variables":{}}'

# brotli of BODY. The host has no brotli tool; gzip and zstd are made beside it.
BR_B64='ixqAeyJxdWVyeSI6InsgbG9ncyhsaW1pdDogMSkgeyBraW5kIH0gfSIsInZhcmlhYmxlcyI6e319Aw=='

printf '%s' "$BODY" >"$D/plain.json"
printf '%s' "$BODY" | python3 -c 'import gzip,sys; sys.stdout.buffer.write(gzip.compress(sys.stdin.buffer.read()))' >"$D/body.gz"
printf '%s' "$BODY" | zstd -q -c >"$D/body.zst"
printf '%s' "$BR_B64" | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' >"$D/body.br"

if ! graphql '{ logs(limit: 1) { kind } }' >"$D/plain.json.out" 2>"$D/plain.json.err"; then
    p_bad "plain GraphQL post failed (see plain.json.err)"
else
    p_ok "a plain GraphQL post still answers"
fi

post_encoded() {
    local enc="$1" file="$2" out="$3"
    ENC="$enc" BODY_FILE="$file" URL="http://127.0.0.1:${HTTP_PORT}/api/graphql" \
        OUT="$out" TOKEN="$TOKEN" t python3 - <<'PY'
import os, urllib.error, urllib.request
data = open(os.environ["BODY_FILE"], "rb").read()
req = urllib.request.Request(
    os.environ["URL"], data=data, method="POST",
    headers={
        "Content-Type": "application/json",
        "Content-Encoding": os.environ["ENC"],
        "Authorization": "Bearer " + os.environ["TOKEN"],
    },
)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        open(os.environ["OUT"], "w").write(str(resp.status))
except urllib.error.HTTPError as err:
    open(os.environ["OUT"], "w").write(str(err.code))
PY
}

for spec in "gzip:$D/body.gz" "br:$D/body.br" "zstd:$D/body.zst"; do
    enc="${spec%%:*}"
    file="${spec#*:}"
    post_encoded "$enc" "$file" "$D/${enc}.status"
    code="$(tr -d '[:space:]' <"$D/${enc}.status")"
    if [ "$code" = "400" ]; then
        p_ok "a $enc GraphQL body is not decoded (400)"
    else
        p_bad "a $enc GraphQL body answered $code, expected 400"
    fi
done

if docker exec "$CONTAINER" /app/lldap healthcheck \
    --config-file /data/lldap_config.toml >"$D/health.out" 2>"$D/health.err"; then
    p_ok "the server is healthy after the compressed posts"
else
    p_bad "healthcheck failed after the compressed posts (see health.err)"
fi

curl -sD "$D/wasm.headers" -o "$D/wasm.body" \
    "http://127.0.0.1:${HTTP_PORT}/pkg/lldap_app_bg.wasm.gz" || true
if grep -qi '^HTTP/.* 200' "$D/wasm.headers" \
    && grep -qi '^content-encoding: gzip' "$D/wasm.headers"; then
    p_ok "the wasm asset is served with Content-Encoding: gzip"
else
    p_bad "wasm.gz was not served as gzip (see wasm.headers)"
fi
