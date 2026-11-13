# shellcheck shell=bash
# Phase: restart persistence — the realm, key versions, passwords, tickets and LDAP data all
# survive a container restart, and the restart creates no principals.

D="$(phase_dir)"
KEEP_USER="gatekeep"
KEEP_PASS="GateKeepPass2026!"
KEEP_CC="/tmp/gate_keep_cc"

graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$KEEP_USER"'", "email": "'"$KEEP_USER"'@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create.json" 2>&1 || p_bad "createUser $KEEP_USER failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$KEEP_USER"'", "pw": "'"$KEEP_PASS"'"}' >"$D/setpw.json" 2>&1 \
    || p_bad "setUserPassword $KEEP_USER failed"

# A renewable ticket taken now must still renew after the restart: that needs the same krbtgt key.
if gexec sh -c "printf '%s\n' \"\$1\" | KRB5CCNAME=$KEEP_CC kinit -r 1d \"\$0\"" \
    "$KEEP_USER@$REALM" "$KEEP_PASS" >"$D/kinit-before.log" 2>&1; then
    p_ok "renewable ticket for $KEEP_USER before the restart"
else
    p_bad "kinit -r for $KEEP_USER failed before the restart"
fi
kadmin_q listprincs 2>/dev/null | grep '@' | sort >"$D/listprincs-before.txt"
kvno_before="$(admin_kvno)"
logs_before="$(log_rows "1 = 1")"
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

docker logs --since "$restart_stamp" "$CONTAINER" >"$D/restart-docker.log" 2>&1
if grep -q "Kerberos realm $REALM serving" "$D/restart-docker.log"; then
    p_ok "the realm reopened"
else
    p_bad "no 'Kerberos realm $REALM serving' after restart"
fi
kadmin_q listprincs 2>/dev/null | grep '@' | sort >"$D/listprincs-after.txt"
if [ -s "$D/listprincs-before.txt" ] && cmp -s "$D/listprincs-before.txt" "$D/listprincs-after.txt"; then
    p_ok "no principal created or lost on restart"
else
    p_bad "principals differ across the restart (see listprincs-before/after.txt)"
fi
kvno_after="$(admin_kvno)"
if [ -n "$kvno_before" ] && [ "$kvno_before" = "$kvno_after" ]; then
    p_ok "admin/admin key vno unchanged ($kvno_after)"
else
    p_bad "admin/admin key vno changed ($kvno_before → $kvno_after)"
fi
if gexec sh -c "KRB5CCNAME=/tmp/gate_keep_kt kinit -kt /data/kadm5.keytab admin/admin@$REALM" \
    >"$D/kinit-keytab.log" 2>&1; then
    p_ok "the admin keytab still kinits after restart"
else
    p_bad "kinit -kt with the admin keytab failed after restart"
fi

if gexec env KRB5CCNAME="$KEEP_CC" kinit -R >"$D/renew-after.log" 2>&1; then
    p_ok "the pre-restart ticket renews after the restart"
else
    p_bad "the pre-restart ticket does not renew (see renew-after.log)"
fi
if kinit_pw "$KEEP_USER@$REALM" "$KEEP_PASS" >"$D/kinit.log" 2>&1; then
    p_ok "pre-restart password still kinits"
else
    p_bad "pre-restart password no longer kinits"
fi
if lsearch -b "$BASE_DN" -s sub "(uid=$KEEP_USER)" uid >"$D/ldap.txt" 2>"$D/ldap.err" \
    && grep -q "^uid: $KEEP_USER" "$D/ldap.txt"; then
    p_ok "LDAP data intact after restart"
else
    p_bad "LDAP search for $KEEP_USER failed after restart"
fi

logs_after="$(log_rows "1 = 1")"
if [ "$logs_before" -gt 0 ] && [ "$logs_after" -ge "$logs_before" ]; then
    p_ok "logs rows survive the restart ($logs_before → $logs_after)"
else
    p_bad "logs rows lost across the restart ($logs_before → $logs_after)"
fi
if [ "$(log_rows "kind = 'user_create' AND target = '$KEEP_USER' AND actor = 'admin' AND protocol = 'graphql'")" = "1" ]; then
    p_ok "createUser $KEEP_USER is in the logs table with actor and protocol"
else
    p_bad "createUser $KEEP_USER missing from the logs table"
fi
if [ "$(log_rows "kind = 'server_start'")" -ge 2 ]; then
    p_ok "server_start recorded for both boots"
else
    p_bad "server_start rows missing after restart"
fi

# The server is process 1 now; SIGTERM must end it well inside Docker's 10 s grace period.
stop_started="$(date +%s)"
if t docker stop "$CONTAINER" >/dev/null 2>&1; then
    stop_secs=$(($(date +%s) - stop_started))
    stop_code="$(docker inspect -f '{{.State.ExitCode}}' "$CONTAINER")"
    if [ "$stop_code" != "137" ] && [ "$stop_secs" -lt 5 ]; then
        p_ok "docker stop ends the server cleanly (exit $stop_code in ${stop_secs}s)"
    elif [ "$stop_secs" -ge 5 ]; then
        finished_at="$(docker inspect -f '{{.State.FinishedAt}}' "$CONTAINER")"
        last_log="$(docker logs --timestamps "$CONTAINER" 2>&1 | tail -n 1)"
        p_bad "docker stop: exit $stop_code after ${stop_secs}s (SIGTERM not handled); FinishedAt ${finished_at}; last log: ${last_log}"
    else
        p_bad "docker stop: exit $stop_code after ${stop_secs}s (SIGTERM not handled)"
    fi
else
    p_bad "docker stop failed"
fi
if t docker start "$CONTAINER" >/dev/null 2>&1 && wait_healthy 90; then
    p_ok "healthy again after docker start"
else
    p_bad "container did not become healthy after docker start"
fi
discover_ports || p_bad "port discovery failed after docker start"
TOKEN="$(gate_login)" || p_bad "admin login failed after docker start"
