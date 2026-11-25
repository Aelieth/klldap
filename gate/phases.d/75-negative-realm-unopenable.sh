# shellcheck shell=bash
# Phase: negative — a realm that cannot open (its stash moved away) brings the server up
# degraded: unhealthy with the cause, LDAP and HTTP on the container's loopback only, admins
# only, writes refused. Moving the stash back and restarting restores it.

D="$(phase_dir)"
DEG_USER="gatedeg"
DEG_PASS="GateDegPass2026!"
STASH="/var/kerberos/krb5kdc/.k5.$REALM"
cip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER")"
in_ldap() { gexec "$1" -x -H ldap://127.0.0.1:3890 "${@:2}"; }

graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$DEG_USER"'", "email": "'"$DEG_USER"'@gate.test"}}' \
    >"$D/create.json" 2>&1 || p_bad "createUser $DEG_USER failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$DEG_USER"'", "pw": "'"$DEG_PASS"'"}' >"$D/setpw.json" 2>&1 \
    || p_bad "setUserPassword $DEG_USER failed"

if t bash -c "</dev/tcp/$cip/$KDC_INNER_PORT" 2>/dev/null; then
    p_ok "the KDC answers on the container's address ($cip:$KDC_INNER_PORT)"
else
    p_bad "the KDC does not answer on $cip:$KDC_INNER_PORT"
fi
if t bash -c "</dev/tcp/$cip/$KADMIN_INNER_PORT" 2>/dev/null; then
    p_bad "kadmin answers on the container's address ($cip:$KADMIN_INNER_PORT)"
else
    p_ok "kadmin is not reachable on the container's address"
fi
if kadmin_q listprincs >"$D/listprincs.txt" 2>/dev/null && grep -q "admin/admin@$REALM" "$D/listprincs.txt"; then
    p_ok "kadmin works inside the container"
else
    p_bad "kadmin_q listprincs failed inside the container"
fi

gexec mv "$STASH" "$STASH.gate-moved" || p_bad "could not move the stash"
restart_stamp="$(date +%s)"
t docker restart "$CONTAINER" >/dev/null 2>&1 || p_bad "docker restart failed"
degraded=""
for _ in $(seq 1 60); do
    docker logs --since "$restart_stamp" "$CONTAINER" >"$D/degraded-docker.log" 2>&1
    grep -q "Only admins may sign in" "$D/degraded-docker.log" && degraded=1 && break
    sleep 1
done
if [ -n "$degraded" ] && grep -q "the Kerberos realm $REALM did not open" "$D/degraded-docker.log"; then
    p_ok "the server came up degraded and logged the cause"
else
    p_bad "no degraded start with the cause in the log (see degraded-docker.log)"
fi

if gexec /app/lldap healthcheck --config-file /data/lldap_config.toml >"$D/health-degraded.log" 2>&1; then
    p_bad "healthcheck passes with the realm unopenable"
elif grep -q "did not open" "$D/health-degraded.log"; then
    p_ok "healthcheck fails and prints the cause"
else
    p_bad "healthcheck fails without the cause (see health-degraded.log)"
fi
discover_ports || p_bad "port discovery failed after the degraded restart"
http_code="$(t curl -s -m 5 -o /dev/null -w '%{http_code}' "$(http_url)/health" 2>/dev/null)"
if [ "${http_code:-000}" = "000" ]; then
    p_ok "the published HTTP port does not answer while degraded"
else
    p_bad "the published HTTP port answered $http_code while degraded"
fi
if t ldapsearch -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" -b "$BASE_DN" \
    "(uid=admin)" uid >/dev/null 2>&1; then
    p_bad "the published LDAP port answers while degraded"
else
    p_ok "the published LDAP port does not answer while degraded"
fi
if gexec bash -c "</dev/tcp/127.0.0.1/$KDC_INNER_PORT" 2>/dev/null; then
    p_bad "the KDC port answers while degraded"
else
    p_ok "the KDC port refuses while degraded"
fi

# Saved before the grep: under pipefail, grep -q closing the pipe early fails the exec.
in_ldap ldapsearch -D "$(admin_dn)" -w "$ADMIN_PASS" -b "$BASE_DN" "(uid=admin)" uid \
    >"$D/admin-search.out" 2>"$D/admin-search.err"
if grep -q "^uid: admin" "$D/admin-search.out"; then
    p_ok "an admin binds and searches on the container's loopback"
else
    p_bad "admin bind or search on loopback failed (see admin-search.err)"
fi
in_ldap ldapwhoami -D "uid=$DEG_USER,ou=people,$BASE_DN" -w "$DEG_PASS" >"$D/user-bind.log" 2>&1
user_bind=$?
if [ "$user_bind" = "52" ]; then
    p_ok "a regular user's bind gets 52 (unavailable)"
else
    p_bad "a regular user's bind returned $user_bind (expected 52)"
fi
gexec sh -c 'printf "dn: uid=gatenew,ou=people,%s\nobjectClass: inetOrgPerson\nuid: gatenew\ncn: gatenew\nsn: gatenew\nmail: gatenew@gate.test\n" "$0" |
    ldapadd -x -H ldap://127.0.0.1:3890 -D "$1" -w "$2"' "$BASE_DN" "$(admin_dn)" "$ADMIN_PASS" \
    >"$D/write.log" 2>&1
if [ $? -ne 0 ] && grep -q "did not open" "$D/write.log"; then
    p_ok "an admin's write is refused with the cause"
else
    p_bad "an admin's write was not refused with the cause (see write.log)"
fi

gexec mv "$STASH.gate-moved" "$STASH" || p_bad "could not restore the stash"
if t docker restart "$CONTAINER" >/dev/null 2>&1 && wait_healthy 90; then
    p_ok "healthy again once the stash is back"
else
    p_bad "not healthy after restoring the stash"
fi
discover_ports || p_bad "port discovery failed after the restore"
TOKEN="$(gate_login)" || p_bad "admin login failed after the restore"
if gexec sh -c "KRB5CCNAME=/tmp/gate_restore_cc kinit -kt /data/kadm5.keytab admin/admin@$REALM" \
    >"$D/kinit-restored.log" 2>&1; then
    p_ok "the restored realm issues tickets"
else
    p_bad "kinit -kt failed after the restore"
fi

# A second server on the gate's database while the gate's server holds the realm (W1): it watches
# the realm for thirty-five seconds with no listener up, then exits naming the holder. With
# force_ldap_user_pass_reset it first resets the admin's directory password without the realm.
RW_PLAIN="${CONTAINER}-rwplain" RW_RESET="${CONTAINER}-rwreset"
RW_SAID="another server holds the Kerberos realm in this database; this one wrote nothing and stops"
RW_RAN="password ran without the Kerberos realm, because the Kerberos realm $REALM did not open: the directory password is the configured one"
RW_ROW="admin password reset from the configuration"
RW_SILENT="nothing listens on 17170 or 3890"
RW_QUIET="" RW_CODE="" RW_SECS=0
EXTRA_CONTAINERS+=("$RW_PLAIN" "$RW_RESET")
EXTRA_VOLUMES+=("$RW_PLAIN-data" "$RW_PLAIN-kdc" "$RW_RESET-data" "$RW_RESET-kdc")

# rw_up <name> [-e NAME=value ...]: a server with Kerberos on, on the gate's database, its volumes its own.
rw_up() {
    local name="$1"
    shift
    rw_down "$name"
    LLDAP_JWT_SECRET="$JWT_SECRET" LLDAP_KEY_SEED="$KEY_SEED" LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        LLDAP_DATABASE_URL="$GATE_DATABASE_URL" t docker run -d --name "$name" --network "$NET" \
        -v "$name-data:/data" -v "$name-kdc:/var/kerberos/krb5kdc" \
        -e LLDAP_JWT_SECRET -e LLDAP_KEY_SEED -e LLDAP_LDAP_USER_PASS -e LLDAP_DATABASE_URL \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_ENABLE_MFA=true -e LLDAP_VERBOSE=true "$@" \
        "$GATE_IMAGE" >/dev/null 2>>"$D/second.err"
}
rw_down() {
    docker rm -fv "$1" >/dev/null 2>&1
    docker volume rm "$1-data" "$1-kdc" >/dev/null 2>&1
}

# rw_quiet <name>: while it runs, which of its HTTP and LDAP ports take a connection inside it.
rw_quiet() {
    local port open=""
    if ! gexec_in "$1" bash -c : 2>/dev/null; then
        echo "not running"
        return
    fi
    for port in 17170 3890; do
        gexec_in "$1" bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null && open="$open $port"
    done
    if [ -n "$open" ]; then
        echo "listening on$open"
    else
        echo "$RW_SILENT"
    fi
}

# rw_second <name> [-e NAME=value ...]: started beside the holder and waited for. RW_QUIET is what
# it answered fifteen seconds in; RW_CODE and RW_SECS are its exit; its log is <name>.log.
rw_second() {
    local name="$1" from
    RW_QUIET="not started" RW_CODE="" RW_SECS=0
    from="$(date +%s)"
    rw_up "$@" || return 1
    sleep 15
    RW_QUIET="$(rw_quiet "$name")"
    RW_CODE="$(timeout 120 docker wait "$name" 2>/dev/null)"
    RW_SECS=$(($(date +%s) - from))
    docker logs "$name" >"$D/$name.log" 2>&1
}

# rw_first: the gate's server still serves with its realm: healthy, the admin logs in, the keytab
# kinits. Its two ports take rw_quiet's connection, which is that probe's control.
rw_first() {
    gexec /app/lldap healthcheck --config-file /data/lldap_config.toml >"$D/first-health.log" 2>&1 &&
        gexec bash -c "</dev/tcp/127.0.0.1/17170 && </dev/tcp/127.0.0.1/3890" 2>>"$D/first-health.log" &&
        TOKEN="$(gate_login 2>>"$D/first-health.log")" &&
        gexec sh -c "KRB5CCNAME=/tmp/gate_rw_cc kinit -kt /data/kadm5.keytab admin/admin@$REALM" \
            >"$D/first-kinit.log" 2>&1
}

# rw_watched <name>: nothing listened, it exited non-zero no sooner than the watch, and named the holder.
rw_watched() {
    [ "$RW_QUIET" = "$RW_SILENT" ] && [ -n "$RW_CODE" ] && [ "$RW_CODE" != 0 ] && [ "$RW_SECS" -ge 35 ] &&
        grep -qF "$RW_SAID" "$D/$1.log"
}

rw_admin_sync() {
    graphql '{ user(userId: "admin") { attributes { name value } } }' '{}' 2>/dev/null | python3 -c '
import json, sys
attrs = json.load(sys.stdin)["user"]["attributes"]
vals = [",".join(a["value"]) for a in attrs if a["name"] == "kerberossync"]
print(vals[0] if vals else "absent")' 2>/dev/null
}

# rw_reset_rows <mark>: the admin_bootstrap rows of a reset from the configuration after the marker.
rw_reset_rows() {
    graphql 'query($id: ID!) { logs(filter: {kinds: [ADMIN_BOOTSTRAP]}, afterId: $id, limit: 20) { detail } }' \
        '{"id": "'"$1"'"}' 2>/dev/null | WANT="$RW_ROW" python3 -c '
import json, os, sys
print(sum(1 for row in json.load(sys.stdin)["logs"] if row.get("detail") == os.environ["WANT"]))' 2>/dev/null
}

rw_watch_row() {
    local row="W1.second-watch" got
    if ! rw_second "$RW_PLAIN"; then
        p_bad "[$row] the second server did not start (see second.err)"
        return
    fi
    got="at 15 s: $RW_QUIET; exit ${RW_CODE:-none} after ${RW_SECS}s"
    if rw_watched "$RW_PLAIN" && rw_first; then
        p_ok "[$row] a second server on the gate's database beside the holder: $got, its log says '$RW_SAID'; the gate's server stays healthy, logs the admin in and kinits"
    else
        p_bad "[$row] $got; want '$RW_SILENT', a non-zero exit after 35 s or more, '$RW_SAID' in $RW_PLAIN.log, and the gate's server healthy with its realm (see first-health.log, first-kinit.log)"
    fi
}

rw_reset_row() {
    local row="W1.second-reset" got mark sync rows
    sync="$(rw_admin_sync)"
    case "$sync" in
    absent | 0) ;;
    1)
        p_skip "[$row] the gate's admin has Kerberos sync on, and the reset would turn it off for the phases after; not run"
        return
        ;;
    *)
        p_bad "[$row] the admin's kerberossync could not be read; not run"
        return
        ;;
    esac
    mark="$(log_mark)"
    if ! rw_second "$RW_RESET" -e LLDAP_FORCE_LDAP_USER_PASS_RESET=always; then
        p_bad "[$row] the second server did not start (see second.err)"
        return
    fi
    got="at 15 s: $RW_QUIET; exit ${RW_CODE:-none} after ${RW_SECS}s"
    if rw_watched "$RW_RESET" && grep -qF "$RW_RAN" "$D/$RW_RESET.log" && rw_first &&
        rows="$(rw_reset_rows "$mark")" && [ "$rows" = 1 ]; then
        p_ok "[$row] the same start with force_ldap_user_pass_reset=always: $got; its log says the reset ran without the realm, and '$RW_SAID'; one admin_bootstrap row '$RW_ROW'; the gate's server stays healthy, logs the admin in with the configured password and kinits"
    else
        p_bad "[$row] $got; admin_bootstrap rows '$RW_ROW' after the marker: ${rows:-unread}; want '$RW_SILENT', a non-zero exit after 35 s or more, '$RW_RAN' and '$RW_SAID' in $RW_RESET.log, one row, and the gate's server healthy with its realm"
    fi
}

if [ "$GATE_DB" != postgres ]; then
    p_skip "[W1.second-watch] two servers need one shared database; on $GATE_DB this row is not run"
    p_skip "[W1.second-reset] two servers need one shared database; on $GATE_DB this row is not run"
elif ! rw_first; then
    p_bad "[W1.second-setup] the gate's server is not healthy with its realm before the rows (see first-health.log, first-kinit.log); not run"
else
    : >"$D/second.err"
    rw_watch_row
    rw_down "$RW_PLAIN"
    rw_reset_row
    rw_down "$RW_RESET"
fi
