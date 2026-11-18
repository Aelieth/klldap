# shellcheck shell=bash
# Phase: a 0.7.2 realm on first boot, on copies. A: the committed fixture's dump (LIVEBOB.TEST)
# migrates for livebob with kerberosSync on. A2: the same dump for livebob WITHOUT sync: the first
# start disables the principal, keeps it, and logs one row. B: a local 0.7.2 install without its
# dump is refused: degraded, nothing moved. B runs
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
# As on an upgrade, the directory has livebob before the realm comes over: a first start without
# Kerberos creates the user, and the second start imports the dump.
# mig_run <container> <dir> [docker args]: one start of the image on that copy.
mig_run() {
    local name="$1" dir="$2"
    shift 2
    docker run -d --name "$name" --network "$NET" -p 127.0.0.1::17170 \
        -v "$dir/data:/data" -v "$dir/krb5kdc:$KDC" \
        -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_KEY_SEED="$KEY_SEED" \
        -e LLDAP_LDAP_BASE_DN="dc=livebob,dc=test" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        "$@" "$GATE_IMAGE" >/dev/null || p_bad "could not start $name"
}
# mig_user <container> <tag> <user json>: the first start without Kerberos, and the user.
mig_user() {
    local name="$1" tag="$2" user="$3" port token
    for _ in $(seq 1 60); do
        docker exec "$name" /app/lldap healthcheck --config-file /data/lldap_config.toml >/dev/null 2>&1 && break
        sleep 1
    done
    port="$(docker port "$name" 17170/tcp | head -1 | sed 's/.*://')"
    token="$(HTTP_PORT="$port" gate_login)" && HTTP_PORT="$port" TOKEN="$token" graphql \
        'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": '"$user"'}' >"$D/$tag-user.json" 2>&1
}
# mig_rows <container> <tag> <target or empty> <detail>: how many kerberos_sync rows say exactly that.
mig_rows() {
    local name="$1" tag="$2" target="$3" detail="$4" port token
    port="$(docker port "$name" 17170/tcp | head -1 | sed 's/.*://')"
    token="$(HTTP_PORT="$port" gate_login)" || { echo -1; return; }
    HTTP_PORT="$port" TOKEN="$token" graphql \
        '{ logs(filter: {kinds: [KERBEROS_SYNC]}, limit: 200) { target detail } }' '{}' \
        >"$D/$tag-rows.json" 2>&1 || { echo -1; return; }
    TARGET="$target" DETAIL="$detail" python3 - "$D/$tag-rows.json" <<'PY'
import json, os, sys
rows = json.load(open(sys.argv[1], encoding="utf-8")).get("logs") or []
target = os.environ["TARGET"] or None
print(sum(1 for r in rows if r.get("target") == target and r.get("detail") == os.environ["DETAIL"]))
PY
}
# mig_healthy <container> <tag>: waits for the import; 0 when healthy and serving.
mig_healthy() {
    local name="$1" tag="$2" healthy=""
    for _ in $(seq 1 120); do
        if docker exec "$name" /app/lldap healthcheck --config-file /data/lldap_config.toml >/dev/null 2>&1; then
            healthy=1
            break
        fi
        [ -z "$(docker ps -q -f "name=^$name$")" ] && break
        sleep 1
    done
    docker logs "$name" >"$D/$tag-docker.log" 2>&1
    [ -n "$healthy" ] && grep -q "Kerberos realm LIVEBOB.TEST serving" "$D/$tag-docker.log"
}
mig_run "$MIG_A" "$A" -e LLDAP_KERBEROS_OPTIONS__ENABLED=false
if mig_user "$MIG_A" branch-a '{"id": "livebob", "email": "livebob@livebob.test",
        "attributes": [{"name": "kerberossync", "value": ["1"]}]}'; then
    p_ok "livebob is created in the directory, with kerberosSync on, before the import"
else
    p_bad "could not create livebob before the import (see branch-a-user.json)"
fi
docker rm -f "$MIG_A" >/dev/null 2>&1
mig_run "$MIG_A" "$A"
if mig_healthy "$MIG_A" branch-a; then
    p_ok "the dump boots to healthy, realm LIVEBOB.TEST serving"
    if CONTAINER="$MIG_A" kinit_pw "livebob@LIVEBOB.TEST" "LivebobPass2026!" >"$D/branch-a-kinit.log" 2>&1; then
        p_ok "kinit livebob (kerberosSync on) works with the fixture password"
    else
        p_bad "kinit livebob (kerberosSync on) failed (see branch-a-kinit.log)"
    fi
    marked="$(mig_rows "$MIG_A" branch-a "" "marked at start: 1 principals")"
    if [ "$marked" = 1 ]; then
        p_ok "the first start marks livebob: one 'marked at start: 1 principals' row"
    else
        p_bad "expected one 'marked at start: 1 principals' row, found $marked (see branch-a-rows.json)"
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
    if docker exec "$MIG_A" sh -c "[ ! -e $KDC/principal ] && [ ! -e $KDC/principal.dump ] && [ -e $KDC/lockout ]"; then
        p_ok "the realm went to the database: the realm directory keeps the stash and the lockout file"
    else
        p_bad "the realm directory still has a principal file or the dump, or no lockout file"
    fi
else
    p_bad "the dump did not boot to a serving realm (see branch-a-docker.log)"
fi
mig_stop "$MIG_A"

# A2: livebob without sync. A 0.7.x operator could give such a user a principal with kadmin.
MIG_A2="klldap-gate-mig-a2-$RUNID"
EXTRA_CONTAINERS+=("$MIG_A2")
A2="$D/branch-a2"
mkdir -p "$A2/data" "$A2/krb5kdc"
cp server/tests/fixtures/krb5kdc/principal.dump server/tests/fixtures/krb5kdc/.k5.LIVEBOB.TEST "$A2/krb5kdc/"
mig_run "$MIG_A2" "$A2" -e LLDAP_KERBEROS_OPTIONS__ENABLED=false
if mig_user "$MIG_A2" branch-a2 '{"id": "livebob", "email": "livebob@livebob.test"}'; then
    p_ok "A2: livebob is created in the directory, without kerberosSync, before the import"
else
    p_bad "A2: could not create livebob before the import (see branch-a2-user.json)"
fi
docker rm -f "$MIG_A2" >/dev/null 2>&1
mig_run "$MIG_A2" "$A2"
if mig_healthy "$MIG_A2" branch-a2; then
    p_ok "A2: the dump boots to healthy, realm LIVEBOB.TEST serving"
    if CONTAINER="$MIG_A2" kinit_pw "livebob@LIVEBOB.TEST" "LivebobPass2026!" >"$D/branch-a2-kinit.log" 2>&1; then
        p_bad "A2: kinit livebob without sync succeeded"
    elif grep -q "credentials have been revoked" "$D/branch-a2-kinit.log"; then
        p_ok "A2: kinit livebob without sync is revoked"
    else
        p_bad "A2: kinit livebob failed without 'credentials have been revoked' (see branch-a2-kinit.log)"
    fi
    if CONTAINER="$MIG_A2" REALM="LIVEBOB.TEST" kadmin_q "getprinc livebob" >"$D/branch-a2-getprinc.txt" 2>&1 \
        && grep -q "^Principal: livebob@LIVEBOB.TEST" "$D/branch-a2-getprinc.txt" \
        && grep -qE "^Attributes:.*DISALLOW_ALL_TIX" "$D/branch-a2-getprinc.txt"; then
        p_ok "A2: the principal is still there, with DISALLOW_ALL_TIX"
    else
        p_bad "A2: getprinc livebob is missing or not DISALLOW_ALL_TIX (see branch-a2-getprinc.txt)"
    fi
    disabled="$(mig_rows "$MIG_A2" branch-a2 livebob \
        "disabled at start: a directory user without Kerberos sync has a principal")"
    if [ "$disabled" = 1 ]; then
        p_ok "A2: one kerberos_sync row names the disabled principal"
    else
        p_bad "A2: expected one 'disabled at start' row for livebob, found $disabled (see branch-a2-rows.json)"
    fi
else
    p_bad "A2: the dump did not boot to a serving realm (see branch-a2-docker.log)"
fi
mig_stop "$MIG_A2"

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

# B4 binds as admin with a known password: one run sets it (the server exits after applying
# the flag). The realm cannot open here, so the admin, who has no sync, is reset with Kerberos
# disabled. A 0.7.2 install's data keeps its own key.
if [ -n "${GATE_FIXTURE_ADMIN_PASS:-}" ]; then
    timeout 120 docker run --rm --name "$MIG_B-prep" \
        -v "$B/data:/data" -v "$B/krb5kdc:$KDC" \
        -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_LDAP_BASE_DN="$GATE_FIXTURE_BASE_DN" \
        -e LLDAP_FORCE_LDAP_USER_PASS_RESET=true -e LLDAP_LDAP_USER_PASS="$GATE_FIXTURE_ADMIN_PASS" \
        -e LLDAP_KERBEROS_OPTIONS__ENABLED=false \
        "$GATE_IMAGE" >"$D/branch-b-pass-reset.log" 2>&1
    grep -q "Restart the server without" "$D/branch-b-pass-reset.log" \
        || p_bad "branch B's admin password reset did not apply (see branch-b-pass-reset.log)"
fi

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
