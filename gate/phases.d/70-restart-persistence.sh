# shellcheck shell=bash
# Phase: restart persistence — KDC database, keytab, key versions, passwords and LDAP
# data all survive a container restart; the manager takes its existing-database path
# and does not re-create principals.

D="$(phase_dir)"
KEEP_USER="gatekeep"
KEEP_PASS="GateKeepPass2026!"

graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$KEEP_USER"'", "email": "'"$KEEP_USER"'@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create.json" 2>&1 || p_bad "createUser $KEEP_USER failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$KEEP_USER"'", "pw": "'"$KEEP_PASS"'"}' >"$D/setpw.json" 2>&1 \
    || p_bad "setUserPassword $KEEP_USER failed"

keytab_before="$(file_digest /data/kadm5.keytab)"
kvno_before="$(kadmin_q "getprinc admin/admin@$REALM" | grep -m1 "vno" | awk '{print $3}' | tr -d ',')"
restart_stamp="$(date +%s)"

if t docker restart "$CONTAINER" >/dev/null 2>&1; then
    p_ok "container restarted"
else
    p_bad "docker restart failed"
fi
if wait_healthy 90; then
    p_ok "healthy again after restart"
else
    p_bad "container did not become healthy after restart"
fi
discover_ports || p_bad "port discovery failed after restart"
TOKEN="$(gate_login)" || p_bad "admin login failed after restart"
if wait_kerberos_healthy 90; then
    p_ok "Kerberos stack healthy again after restart"
else
    p_bad "Kerberos stack did not recover within 90s of the restart"
fi

docker logs --since "$restart_stamp" "$CONTAINER" >"$D/restart-docker.log" 2>&1
if grep -q "Existing KDC database detected" "$D/restart-docker.log"; then
    p_ok "manager took the existing-database path"
else
    p_bad "no 'Existing KDC database detected' after restart"
fi
if grep -q "addprinc" "$D/restart-docker.log"; then
    p_bad "manager re-created principals on restart (addprinc in logs)"
else
    p_ok "no principal re-creation on restart"
fi

keytab_after="$(file_digest /data/kadm5.keytab)"
if [ -n "$keytab_before" ] && [ "$keytab_before" = "$keytab_after" ]; then
    p_ok "admin keytab is byte-identical across restart"
else
    p_bad "admin keytab changed across restart ($keytab_before → $keytab_after)"
fi
kvno_after="$(kadmin_q "getprinc admin/admin@$REALM" | grep -m1 "vno" | awk '{print $3}' | tr -d ',')"
if [ -n "$kvno_before" ] && [ "$kvno_before" = "$kvno_after" ]; then
    p_ok "admin/admin key vno unchanged ($kvno_after)"
else
    p_bad "admin/admin key vno changed ($kvno_before → $kvno_after)"
fi

if kinit_pw "$KEEP_USER@$REALM" "$KEEP_PASS" >"$D/kinit.log" 2>&1; then
    p_ok "pre-restart password still kinits"
else
    p_bad "pre-restart password no longer kinits"
fi
if lsearch -b "$BASE_DN" -s sub "(uid=$KEEP_USER)" uid 2>"$D/ldap.err" | grep -q "^uid: $KEEP_USER"; then
    p_ok "LDAP data intact after restart"
else
    p_bad "LDAP search for $KEEP_USER failed after restart"
fi
