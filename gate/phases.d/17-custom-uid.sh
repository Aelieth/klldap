# shellcheck shell=bash
# Phase: custom LLDAP_UID/LLDAP_GID — a throwaway container running as 1500:1500 must own
# the admin keytab and the KDB, so the server can read the keytab on first boot and run
# kadmin.local (keytab export) without a restart.

D="$(phase_dir)"
UID_CONTAINER="$CONTAINER-uid"
CUSTOM_ID=1500

docker rm -f -v "$UID_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$UID_CONTAINER" --network "$NET" \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" \
    -e LLDAP_KEY_SEED="$KEY_SEED" \
    -e LLDAP_LDAP_BASE_DN="$BASE_DN" \
    -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
    -e LLDAP_DATABASE_URL="sqlite:////data/users.db?mode=rwc" \
    -e LLDAP_UID="$CUSTOM_ID" -e LLDAP_GID="$CUSTOM_ID" \
    "$GATE_IMAGE" >"$D/run.log" 2>&1 || p_bad "could not start the custom-uid container"

uid_healthy=""
for _ in $(seq 1 120); do
    if docker exec "$UID_CONTAINER" /app/lldap healthcheck \
        --config-file /data/lldap_config.toml --kerberos >/dev/null 2>&1; then
        uid_healthy=1
        break
    fi
    if [ -z "$(docker ps -q -f "name=^$UID_CONTAINER$")" ]; then
        break
    fi
    sleep 1
done
docker logs "$UID_CONTAINER" >"$D/docker.log" 2>&1

if [ -n "$uid_healthy" ]; then
    p_ok "custom-uid container is healthy with the KDC"
    server_uid="$(docker exec "$UID_CONTAINER" sh -c 'stat -c %u /proc/$(pgrep -x lldap | head -1)' 2>/dev/null)"
    if [ "$server_uid" = "$CUSTOM_ID" ]; then
        p_ok "lldap server runs as uid $CUSTOM_ID"
    else
        p_bad "lldap server runs as uid '${server_uid:-unknown}' (expected $CUSTOM_ID)"
    fi
    keytab="$(docker exec "$UID_CONTAINER" stat -c '%u:%g %a' /data/kadm5.keytab 2>/dev/null)"
    if [ "$keytab" = "$CUSTOM_ID:$CUSTOM_ID 640" ]; then
        p_ok "admin keytab is owned by $CUSTOM_ID:$CUSTOM_ID, mode 640"
    else
        p_bad "admin keytab is '${keytab:-missing}' (expected '$CUSTOM_ID:$CUSTOM_ID 640')"
    fi
    # -p as the server passes it: uid 1500 has no passwd entry to derive a name from.
    if docker exec -u "$CUSTOM_ID:$CUSTOM_ID" "$UID_CONTAINER" \
        /usr/sbin/kadmin.local -p "admin/admin@$REALM" -q listprincs >"$D/listprincs.txt" 2>&1 \
        && grep -q "admin/admin@$REALM" "$D/listprincs.txt"; then
        p_ok "kadmin.local works as uid $CUSTOM_ID (KDB owned by the server user)"
    else
        p_bad "kadmin.local as uid $CUSTOM_ID failed (see listprincs.txt)"
    fi
    if docker exec -u "$CUSTOM_ID:$CUSTOM_ID" -e KRB5CCNAME=/tmp/gate_uid_cc "$UID_CONTAINER" \
        kinit -kt /data/kadm5.keytab "admin/admin@$REALM" >"$D/kinit.log" 2>&1; then
        p_ok "keytab kinit works as uid $CUSTOM_ID"
    else
        p_bad "keytab kinit as uid $CUSTOM_ID failed (see kinit.log)"
    fi
else
    p_bad "custom-uid container did not become healthy (see docker.log)"
fi

docker rm -f -v "$UID_CONTAINER" >/dev/null 2>&1 || true
