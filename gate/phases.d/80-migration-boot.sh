# shellcheck shell=bash
# Phase: a 0.7.2 realm on first boot, on copies. A: the committed fixture's dump (LIVEBOB.TEST)
# migrates. B: a local 0.7.2 install without its dump is refused: degraded, nothing moved. B runs
# when GATE_FIXTURE_DATA, GATE_FIXTURE_KDC and GATE_FIXTURE_BASE_DN are set;
# GATE_FIXTURE_ADMIN_PASS adds the admin's bind while degraded.

D="$(phase_dir)"
KDC=/var/kerberos/krb5kdc

# The containers wrote into the bind-mounted copies; hand them back to the invoking user.
mig_stop() {
    docker exec "$1" chown -R "$(id -u):$(id -g)" /data "$KDC" >/dev/null 2>&1
    docker rm -f "$1" >/dev/null 2>&1
}

MIG_A="klldap-gate-mig-a-$RUNID"
EXTRA_CONTAINERS+=("$MIG_A")
A="$D/branch-a"
mkdir -p "$A/data" "$A/krb5kdc"
cp server/tests/fixtures/krb5kdc/principal.dump server/tests/fixtures/krb5kdc/.k5.LIVEBOB.TEST "$A/krb5kdc/"
docker run -d --name "$MIG_A" --network "$NET" \
    -v "$A/data:/data" -v "$A/krb5kdc:$KDC" \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_KEY_SEED="$KEY_SEED" \
    -e LLDAP_LDAP_BASE_DN="dc=livebob,dc=test" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
    "$GATE_IMAGE" >/dev/null || p_bad "could not start branch A's container"
a_healthy=""
for _ in $(seq 1 120); do
    if docker exec "$MIG_A" /app/lldap healthcheck --config-file /data/lldap_config.toml >/dev/null 2>&1; then
        a_healthy=1
        break
    fi
    [ -z "$(docker ps -q -f "name=^$MIG_A$")" ] && break
    sleep 1
done
docker logs "$MIG_A" >"$D/branch-a-docker.log" 2>&1
if [ -n "$a_healthy" ] && grep -q "Kerberos realm LIVEBOB.TEST serving" "$D/branch-a-docker.log"; then
    p_ok "the dump boots to healthy, realm LIVEBOB.TEST serving"
    if CONTAINER="$MIG_A" kinit_pw "livebob@LIVEBOB.TEST" "LivebobPass2026!" >"$D/branch-a-kinit.log" 2>&1; then
        p_ok "kinit livebob works with the fixture password"
    else
        p_bad "kinit livebob failed (see branch-a-kinit.log)"
    fi
    if CONTAINER="$MIG_A" REALM="LIVEBOB.TEST" kadmin_q "getprinc livebob" >"$D/branch-a-getprinc.txt" 2>&1 \
        && grep -qE "^Attributes:.*REQUIRES_PRE_AUTH" "$D/branch-a-getprinc.txt" \
        && grep -q "^Maximum renewable life: 7 days 00:00:00" "$D/branch-a-getprinc.txt"; then
        p_ok "getprinc livebob shows REQUIRES_PRE_AUTH and a 7-day renewable life"
    else
        p_bad "getprinc livebob over kadmin failed or differs (see branch-a-getprinc.txt)"
    fi
    if [ "$(docker exec "$MIG_A" stat -c %a "$KDC/mit-db2.bak" 2>/dev/null)" = 700 ] \
        && docker exec "$MIG_A" test -f "$KDC/mit-db2.bak/principal.dump"; then
        p_ok "mit-db2.bak/ holds the dump, mode 0700"
    else
        p_bad "mit-db2.bak/ is missing, not 0700, or without the dump"
    fi
else
    p_bad "the dump did not boot to a serving realm (see branch-a-docker.log)"
fi
mig_stop "$MIG_A"

if [ -z "${GATE_FIXTURE_DATA:-}" ] || [ -z "${GATE_FIXTURE_KDC:-}" ] || [ -z "${GATE_FIXTURE_BASE_DN:-}" ]; then
    p_skip "branch B: GATE_FIXTURE_DATA/GATE_FIXTURE_KDC/GATE_FIXTURE_BASE_DN not set"
    return 0
fi
MIG_B="klldap-gate-mig-b-$RUNID"
EXTRA_CONTAINERS+=("$MIG_B" "$MIG_B-prep")
B="$D/branch-b"
mkdir -p "$B"
cp -a "$GATE_FIXTURE_DATA" "$B/data"
cp -a "$GATE_FIXTURE_KDC" "$B/krb5kdc"
rm -f "$B/krb5kdc/principal.dump" "$B/krb5kdc/principal.dump.dump_ok"

# The 0.7.2 LLDAP database is adopted under a fresh key: one run with the force flags (the
# server exits after applying them, before the realm), then the boot under test.
force_env=(-e LLDAP_FORCE_UPDATE_PRIVATE_KEY=true -e LLDAP_FORCE_LDAP_USER_PASS_RESET=true)
if [ -n "${GATE_FIXTURE_ADMIN_PASS:-}" ]; then
    force_env+=(-e LLDAP_LDAP_USER_PASS="$GATE_FIXTURE_ADMIN_PASS")
fi
timeout 120 docker run --rm --name "$MIG_B-prep" \
    -v "$B/data:/data" -v "$B/krb5kdc:$KDC" \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_LDAP_BASE_DN="$GATE_FIXTURE_BASE_DN" \
    "${force_env[@]}" "$GATE_IMAGE" >"$D/branch-b-force-reset.log" 2>&1
grep -q "Restart the server without" "$D/branch-b-force-reset.log" \
    || p_bad "branch B's force-reset run did not apply the flags (see branch-b-force-reset.log)"

docker run -d --name "$MIG_B" --network "$NET" \
    -v "$B/data:/data" -v "$B/krb5kdc:$KDC" \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_LDAP_BASE_DN="$GATE_FIXTURE_BASE_DN" \
    "$GATE_IMAGE" >/dev/null || p_bad "could not start branch B's container"
degraded=""
for _ in $(seq 1 90); do
    docker logs "$MIG_B" >"$D/branch-b-docker.log" 2>&1
    grep -q "Only admins may sign in" "$D/branch-b-docker.log" && degraded=1 && break
    [ -z "$(docker ps -q -f "name=^$MIG_B$")" ] && break
    sleep 1
done
docker exec "$MIG_B" /app/lldap healthcheck --config-file /data/lldap_config.toml >"$D/branch-b-health.log" 2>&1
if [ -n "$degraded" ] && grep -q "503 Service Unavailable" "$D/branch-b-health.log"; then
    p_ok "without the dump the realm does not open: degraded, /health answers 503"
else
    p_bad "branch B did not come up degraded (see branch-b-docker.log, branch-b-health.log)"
fi
if cat "$D/branch-b-health.log" "$D/branch-b-docker.log" | grep -q "$KDC/principal.dump" \
    && cat "$D/branch-b-health.log" "$D/branch-b-docker.log" | grep -q "Upgrading from 0.7.2"; then
    p_ok "the cause names the dump file and the upgrade section"
else
    p_bad "the cause does not name the dump file and the upgrade section"
fi
if docker exec "$MIG_B" sh -c "[ ! -e $KDC/mit-db2.bak ] && [ -f $KDC/principal ] && [ -f $KDC/principal.kadm5 ]"; then
    p_ok "nothing moved: no mit-db2.bak/, the db2 files where they were"
else
    p_bad "branch B moved files in the KDC volume"
fi
if [ -n "${GATE_FIXTURE_ADMIN_PASS:-}" ]; then
    if gexec_in "$MIG_B" ldapwhoami -x -H ldap://127.0.0.1:3890 \
        -D "uid=admin,ou=people,$GATE_FIXTURE_BASE_DN" -w "$GATE_FIXTURE_ADMIN_PASS" \
        >"$D/branch-b-whoami.log" 2>&1; then
        p_ok "admin binds while degraded"
    else
        p_bad "the admin's bind failed while degraded (see branch-b-whoami.log)"
    fi
else
    p_skip "GATE_FIXTURE_ADMIN_PASS not set: the admin's bind is skipped"
fi
mig_stop "$MIG_B"
