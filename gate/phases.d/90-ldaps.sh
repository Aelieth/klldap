# shellcheck shell=bash
# Phase: LDAPS on its own container. The certificate is made by the image's openssl
# on a Docker volume, and the volume is removed even when a row fails.
# The runner (gate/run-gate.sh) sets the variables this phase reads.

# shellcheck disable=SC2154
D="$(phase_dir)"
LDAPS_C="$CONTAINER-ldaps"
LDAPS_VOL="klldap-gate-ldaps-$RUNID"
EXTRA_CONTAINERS+=("$LDAPS_C")

ldaps_stop() {
    docker rm -f "$LDAPS_C" >/dev/null 2>&1 || true
    docker volume rm "$LDAPS_VOL" >/dev/null 2>&1 || true
}

if ! docker volume create "$LDAPS_VOL" >/dev/null; then
    p_bad "could not create the certificate volume"
    ldaps_stop
    return 0
fi

# Two certificates, both from the image's openssl. other.pem is the trust anchor
# the untrusted-client row points at, so the client does not fall back to the
# image's system trust.
if ! docker run --rm --entrypoint sh -v "$LDAPS_VOL:/data" "$GATE_IMAGE" -c \
    'mkdir -p /data/cert &&
     openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=ldaps-gate" \
       -addext "subjectAltName=DNS:ldaps-gate,DNS:localhost" \
       -keyout /data/cert/key.pem -out /data/cert/cert.pem &&
     openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=other" \
       -addext "subjectAltName=DNS:other" \
       -keyout /data/cert/other-key.pem -out /data/cert/other.pem &&
     chown 1000:1000 /data/cert/key.pem /data/cert/cert.pem \
       /data/cert/other-key.pem /data/cert/other.pem &&
     chmod 600 /data/cert/key.pem /data/cert/other-key.pem &&
     chmod 644 /data/cert/cert.pem /data/cert/other.pem' \
    >"$D/openssl.log" 2>&1; then
    p_bad "the image openssl could not write the certificates (see openssl.log)"
    ldaps_stop
    return 0
fi

docker run -d --name "$LDAPS_C" --hostname ldaps-gate --network "$NET" \
    -v "$LDAPS_VOL:/data" \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_KEY_SEED="$KEY_SEED" \
    -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
    -e LLDAP_VERBOSE=true -e LLDAP_ENABLE_MFA=true \
    -e LLDAP_LDAPS_OPTIONS__ENABLED=true \
    -e LLDAP_LDAPS_OPTIONS__CERT_FILE=/data/cert/cert.pem \
    -e LLDAP_LDAPS_OPTIONS__KEY_FILE=/data/cert/key.pem \
    "$GATE_IMAGE" >/dev/null || p_bad "could not start the LDAPS container"

healthy=""
for _ in $(seq 1 90); do
    if docker exec "$LDAPS_C" /app/lldap healthcheck \
        --config-file /data/lldap_config.toml >/dev/null 2>&1; then
        healthy=1
        break
    fi
    [ -z "$(docker ps -q -f "name=^$LDAPS_C$")" ] && break
    sleep 1
done
docker logs "$LDAPS_C" >"$D/docker.log" 2>&1 || true

if [ -z "$healthy" ]; then
    p_bad "LDAPS container did not become healthy (see docker.log)"
    ldaps_stop
    return 0
fi

if grep -q "Starting the LDAPS server on port 6360" "$D/docker.log"; then
    p_ok "the server logs that LDAPS listens on 6360"
else
    p_bad "no 'Starting the LDAPS server on port 6360' (see docker.log)"
fi

if t docker exec -e LDAPTLS_CACERT=/data/cert/cert.pem "$LDAPS_C" \
    ldapsearch -x -H ldaps://ldaps-gate:6360 -D "$(admin_dn)" -w "$ADMIN_PASS" \
    -b "$BASE_DN" '(uid=admin)' uid >"$D/search.out" 2>"$D/search.err" \
    && grep -q '^uid: admin' "$D/search.out" \
    && grep -q 'result: 0 Success' "$D/search.out"; then
    p_ok "admin bind and search over ldaps://ldaps-gate:6360 with the certificate checked"
else
    p_bad "admin LDAPS search failed (see search.out, search.err)"
fi

wrong_rc=0
t docker exec -e LDAPTLS_CACERT=/data/cert/cert.pem "$LDAPS_C" \
    ldapsearch -x -H ldaps://ldaps-gate:6360 -D "$(admin_dn)" -w wrong \
    -b "$BASE_DN" '(uid=admin)' uid >"$D/wrong.out" 2>"$D/wrong.err" || wrong_rc=$?
if [ "$wrong_rc" -eq 49 ]; then
    p_ok "a wrong password over LDAPS exits 49"
else
    p_bad "wrong password exited $wrong_rc, expected 49 (see wrong.err)"
fi

untrusted_rc=0
t docker exec -e LDAPTLS_CACERT=/data/cert/other.pem "$LDAPS_C" \
    ldapsearch -x -H ldaps://ldaps-gate:6360 -D "$(admin_dn)" -w "$ADMIN_PASS" \
    -b "$BASE_DN" '(uid=admin)' uid >"$D/untrusted.out" 2>"$D/untrusted.err" || untrusted_rc=$?
if [ "$untrusted_rc" -eq 255 ] && ! grep -q 'result: 0' "$D/untrusted.out"; then
    p_ok "a client trusting a different certificate is refused (exit 255)"
else
    p_bad "untrusted client exited $untrusted_rc (see untrusted.out, untrusted.err)"
fi

t docker exec "$LDAPS_C" \
    sh -c 'openssl s_client -connect ldaps-gate:6360 -CAfile /data/cert/cert.pem </dev/null' \
    >"$D/sclient.out" 2>"$D/sclient.err" || true
if grep -qE 'Protocol *: *TLSv1\.(2|3)' "$D/sclient.out"; then
    p_ok "the negotiated protocol is TLS 1.2 or 1.3"
else
    p_bad "openssl s_client did not report TLS 1.2 or 1.3 (see sclient.out)"
fi

if docker exec "$LDAPS_C" /app/lldap healthcheck \
    --config-file /data/lldap_config.toml >"$D/health.out" 2>"$D/health.err"; then
    p_ok "the healthcheck stays healthy with LDAPS on"
else
    p_bad "healthcheck failed with LDAPS on (see health.err)"
fi

ldaps_stop
