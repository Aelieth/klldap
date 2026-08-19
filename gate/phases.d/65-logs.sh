# shellcheck shell=bash
# Phase: event log queries — a failed bind and a createUser show up with actor, protocol
# and peer; the summary counts it, the activity reports it, the tail cursor pages forward;
# the queries are admin-only and the refusal itself is logged.

D="$(phase_dir)"
LOG_USER="gatelog"
LOG_PASS="GateLogPass2026!"

# The writer lingers before it inserts a batch: poll a query until its first row exists.
log_query_has_row() {
    for _ in $(seq 1 20); do
        if graphql "$1" >"$D/$2.json" 2>"$D/$2.err" \
            && [ -n "$(json_get logs.0.kind <"$D/$2.json" 2>/dev/null)" ]; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$LOG_USER"'", "email": "'"$LOG_USER"'@gate.test"}}' >"$D/create.json" 2>&1 \
    || p_bad "createUser $LOG_USER failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$LOG_USER"'", "pw": "'"$LOG_PASS"'"}' >"$D/setpw.json" 2>&1 \
    || p_bad "setUserPassword $LOG_USER failed"

if t ldapwhoami -x -H "$(ldap_url)" -D "uid=$LOG_USER-nobody,ou=people,$BASE_DN" -w wrong >"$D/whoami.out" 2>&1; then
    p_bad "bind as $LOG_USER-nobody with a wrong password succeeded"
else
    p_ok "wrong-password bind refused"
fi

if log_query_has_row '{ logs(filter: {kinds: [BIND], success: false, actor: "'"$LOG_USER-nobody"'"}) { kind peer protocol detail } }' bind; then
    peer="$(json_get logs.0.peer <"$D/bind.json")"
    proto="$(json_get logs.0.protocol <"$D/bind.json")"
    if [ -n "$peer" ] && [ "$peer" != "None" ] && [ "$proto" = "LDAP" ]; then
        p_ok "failed bind is in the log with peer $peer over LDAP"
    else
        p_bad "failed bind row without peer/protocol: $(cat "$D/bind.json")"
    fi
else
    p_bad "failed bind never showed up in the log (see bind.err)"
fi

if log_query_has_row '{ logs(filter: {kinds: [USER_CREATE], target: "'"$LOG_USER"'"}) { kind actor protocol } }' create-row \
    && [ "$(json_get logs.0.actor <"$D/create-row.json")" = "admin" ] \
    && [ "$(json_get logs.0.protocol <"$D/create-row.json")" = "GRAPHQL" ]; then
    p_ok "createUser $LOG_USER is in the log with actor admin over GraphQL"
else
    p_bad "createUser row missing or wrong: $(cat "$D/create-row.json" 2>/dev/null)"
fi

if graphql '{ logs(limit: 1) { id timestamp kind } }' >"$D/newest.json" 2>"$D/newest.err" \
    && [ -n "$(json_get logs.0.id <"$D/newest.json")" ]; then
    p_ok "logs(limit: 1) returns the newest row"
else
    p_bad "logs(limit: 1) failed (see newest.err)"
fi

if graphql '{ logs(afterId: "0", limit: 2) { id } }' >"$D/tail.json" 2>"$D/tail.err" \
    && [ "$(json_get logs.0.id <"$D/tail.json")" -lt "$(json_get logs.1.id <"$D/tail.json")" ]; then
    p_ok "logs(afterId: \"0\") pages forward, oldest first"
else
    p_bad "logs(afterId) failed: $(cat "$D/tail.json" "$D/tail.err" 2>/dev/null)"
fi

if graphql '{ logSummary(filter: {kinds: [BIND], success: false, actor: "'"$LOG_USER-nobody"'"}, groupBy: [ACTOR, PEER]) { actor peer count first last } }' \
    >"$D/summary.json" 2>"$D/summary.err" \
    && [ "$(json_get logSummary.0.actor <"$D/summary.json")" = "$LOG_USER-nobody" ] \
    && [ "$(json_get logSummary.0.count <"$D/summary.json")" -ge 1 ]; then
    p_ok "logSummary counts the failed bind per actor and peer $(json_get logSummary.0.peer <"$D/summary.json")"
else
    p_bad "logSummary failed: $(cat "$D/summary.json" "$D/summary.err" 2>/dev/null)"
fi

if graphql '{ logActivity(actor: "'"$LOG_USER-nobody"'") { lastSuccess { id } lastFailure { detail } failuresSinceLastSuccess } }' \
    >"$D/activity.json" 2>"$D/activity.err" \
    && [ "$(json_get logActivity.lastSuccess <"$D/activity.json")" = "None" ] \
    && [ "$(json_get logActivity.failuresSinceLastSuccess <"$D/activity.json")" -ge 1 ]; then
    p_ok "logActivity reports the failure streak: $(json_get logActivity.lastFailure.detail <"$D/activity.json")"
else
    p_bad "logActivity failed: $(cat "$D/activity.json" "$D/activity.err" 2>/dev/null)"
fi

saved_token="$TOKEN"
if TOKEN="$(gate_login "$LOG_USER" "$LOG_PASS")"; then
    if graphql '{ logs(limit: 1) { id } }' >"$D/denied.json" 2>"$D/denied.err"; then
        p_bad "regular user $LOG_USER could read the log"
    else
        p_ok "regular user is refused the log"
    fi
    if graphql '{ logSummary(groupBy: [ACTOR]) { count } }' >"$D/denied-summary.json" 2>"$D/denied-summary.err"; then
        p_bad "regular user $LOG_USER could read the log summary"
    else
        p_ok "regular user is refused the log summary"
    fi
else
    p_bad "login as $LOG_USER failed"
fi
TOKEN="$saved_token"

if log_query_has_row '{ logs(filter: {kinds: [ACCESS_DENIED], actor: "'"$LOG_USER"'"}) { kind detail } }' denied-row \
    && grep -q "Unauthorized to read the logs" "$D/denied-row.json"; then
    p_ok "the refusal itself is logged for $LOG_USER"
else
    p_bad "access_denied row for $LOG_USER missing"
fi

if gexec /app/lldap run --help 2>/dev/null | grep -q -- "--log-retention-days"; then
    p_ok "--log-retention-days is on the command line"
else
    p_bad "--log-retention-days missing from lldap run --help"
fi

graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' '{"id": "'"$LOG_USER"'"}' \
    >"$D/delete.json" 2>&1 || p_bad "deleteUser $LOG_USER failed"
