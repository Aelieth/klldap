# shellcheck shell=bash
# Phase: env validation — the server itself refuses to start without a JWT secret, fast and with
# its own sentence; without a base DN it starts on dc=example,dc=com, as upstream LLDAP does.
# Uses throwaway containers with no network.

D="$(phase_dir)"
ENV_CONTAINER="$CONTAINER-env"

out="$(timeout 25 docker run --rm --network none -e LLDAP_LDAP_BASE_DN="$BASE_DN" "$GATE_IMAGE" 2>&1)"
rc=$?
printf '%s\n' "$out" >"$D/missing-jwt-secret.log"
if [ "$rc" -ne 0 ] && grep -qF "The JWT secret must be initialized" <<<"$out"; then
    p_ok "missing-jwt-secret: fast nonzero exit with the server's sentence"
else
    p_bad "missing-jwt-secret: rc=$rc or the sentence is missing (see missing-jwt-secret.log)"
fi

docker rm -f -v "$ENV_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$ENV_CONTAINER" --network none -e LLDAP_VERBOSE=true \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
    "$GATE_IMAGE" >"$D/missing-base-dn.run" 2>&1
healthy=""
for _ in $(seq 1 60); do
    if docker exec "$ENV_CONTAINER" /app/lldap healthcheck \
        --config-file /data/lldap_config.toml >/dev/null 2>&1; then
        healthy=1
        break
    fi
    [ -z "$(docker ps -q -f "name=^$ENV_CONTAINER$")" ] && break
    sleep 1
done
docker logs "$ENV_CONTAINER" >"$D/missing-base-dn.log" 2>&1
if [ -n "$healthy" ] && grep -qF 'ldap_base_dn: "dc=example,dc=com"' "$D/missing-base-dn.log"; then
    p_ok "missing-base-dn: healthy, serving dc=example,dc=com"
else
    p_bad "missing-base-dn: not healthy on dc=example,dc=com (see missing-base-dn.log)"
fi
docker rm -f -v "$ENV_CONTAINER" >/dev/null 2>&1 || true

# A 0.7.2 config names none of the five realm and Keycloak paths: the image's ENV keeps them
# where 0.7.2 had them, not relative to the working directory.
OLD_DATA="$CONTAINER-oldcfg-data"
OLD_KDC="$CONTAINER-oldcfg-kdc"
docker volume rm -f "$OLD_DATA" "$OLD_KDC" >/dev/null 2>&1 || true
docker run --rm --entrypoint sh -v "$OLD_DATA:/data" "$GATE_IMAGE" -c ': >/data/lldap_config.toml' \
    >"$D/oldcfg-prepare.log" 2>&1
docker run -d --name "$ENV_CONTAINER" --network none \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
    -v "$OLD_DATA:/data" -v "$OLD_KDC:/var/kerberos/krb5kdc" "$GATE_IMAGE" >"$D/oldcfg.run" 2>&1
healthy=""
for _ in $(seq 1 90); do
    if docker exec "$ENV_CONTAINER" /app/lldap healthcheck \
        --config-file /data/lldap_config.toml >/dev/null 2>&1; then
        healthy=1
        break
    fi
    [ -z "$(docker ps -q -f "name=^$ENV_CONTAINER$")" ] && break
    sleep 1
done
docker logs "$ENV_CONTAINER" >"$D/oldcfg.log" 2>&1
if [ -n "$healthy" ] && docker exec "$ENV_CONTAINER" sh -c \
    '[ -s /var/kerberos/krb5kdc/principal ] && [ -s /data/kadm5.keytab ] && [ ! -e /app/krb5kdc ]'; then
    p_ok "a config naming none of the paths: the realm is in /var/kerberos/krb5kdc, the keytab in /data"
else
    p_bad "a config naming none of the paths did not keep them (see oldcfg.log)"
fi
docker rm -f -v "$ENV_CONTAINER" >/dev/null 2>&1 || true
docker volume rm -f "$OLD_DATA" "$OLD_KDC" >/dev/null 2>&1 || true
