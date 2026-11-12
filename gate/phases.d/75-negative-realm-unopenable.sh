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
