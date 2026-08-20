# shellcheck shell=bash
# Phase: TOTP second factor — the exempt group exists, enrollment over GraphQL, the
# password:code format at the LDAP and simple-login doors, replay refusal, the
# administrative reset, and the log rows.

D="$(phase_dir)"
MFA_USER="gatemfa"
MFA_PASS="GateMfaPass2026!"
MFA_DN="uid=$MFA_USER,ou=people,$BASE_DN"

# totp_code <base32 secret> <step offset>: RFC 6238 (SHA-1, six digits, 30 s), stdlib only.
totp_code() {
    TOTP_SECRET="$1" TOTP_OFFSET="$2" python3 - <<'PY'
import base64, hashlib, hmac, os, struct, time
secret = os.environ["TOTP_SECRET"]
key = base64.b32decode(secret + "=" * (-len(secret) % 8))
step = int(time.time()) // 30 + int(os.environ["TOTP_OFFSET"])
digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
offset = digest[19] & 0x0F
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
print(f"{code:06d}")
PY
}

# totp_wait_step: sleep past the next 30 s boundary, so an unused code exists again.
totp_wait_step() {
    sleep $((30 - $(date +%s) % 30 + 1))
}

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

mfa_gid="$(graphql '{ groups { id displayName } }' '{}' | GROUP=lldap_mfa_disabled python3 -c '
import json, os, sys
groups = json.load(sys.stdin)["groups"]
match = [g["id"] for g in groups if g["displayName"] == os.environ["GROUP"]]
print(match[0] if match else "")')"
if [ -n "$mfa_gid" ]; then
    p_ok "lldap_mfa_disabled exists at boot (id $mfa_gid)"
else
    p_bad "lldap_mfa_disabled group not found"
fi

graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$MFA_USER"'", "email": "'"$MFA_USER"'@gate.test"}}' >"$D/create.json" 2>&1 \
    || p_bad "createUser $MFA_USER failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$MFA_USER"'", "pw": "'"$MFA_PASS"'"}' >"$D/setpw.json" 2>&1 \
    || p_bad "setUserPassword $MFA_USER failed"

USER_TOKEN="$(gate_login "$MFA_USER" "$MFA_PASS" 2>"$D/login-plain-before.err")" || USER_TOKEN=""
if [ -n "$USER_TOKEN" ]; then
    p_ok "plain simple login works before enrollment"
else
    p_bad "plain simple login failed before enrollment"
fi

TOKEN="$USER_TOKEN" graphql 'mutation { startMfaEnrollment { secretBase32 state } }' '{}' \
    >"$D/start.json" 2>"$D/start.err" || p_bad "startMfaEnrollment failed (see start.err)"
SECRET="$(json_get startMfaEnrollment.secretBase32 <"$D/start.json" 2>/dev/null)"
STATE="$(json_get startMfaEnrollment.state <"$D/start.json" 2>/dev/null)"
CODE="$(totp_code "$SECRET" 0)"
if TOKEN="$USER_TOKEN" graphql \
    'mutation($s: String!, $c: String!) { finishMfaEnrollment(state: $s, code: $c) { ok } }' \
    '{"s": "'"$STATE"'", "c": "'"$CODE"'"}' >"$D/finish.json" 2>"$D/finish.err"; then
    p_ok "enrollment confirmed with the current code"
else
    p_bad "finishMfaEnrollment failed (see finish.err)"
fi

if t ldapwhoami -x -H "$(ldap_url)" -D "$MFA_DN" -w "$MFA_PASS" >"$D/bind-plain.out" 2>&1; then
    p_bad "plain bind succeeded for an enrolled user"
elif grep -q "TOTP code required" "$D/bind-plain.out"; then
    p_ok "plain bind refused with the TOTP diagnostic"
else
    p_bad "plain bind refused without the diagnostic (see bind-plain.out)"
fi
NEXT="$(totp_code "$SECRET" 1)"
if t ldapwhoami -x -H "$(ldap_url)" -D "$MFA_DN" -w "$MFA_PASS:$NEXT" >"$D/bind-code.out" 2>&1; then
    p_ok "password:code bind succeeds"
else
    p_bad "password:code bind failed (see bind-code.out)"
fi
if t ldapwhoami -x -H "$(ldap_url)" -D "$MFA_DN" -w "$MFA_PASS:$NEXT" >"$D/bind-replay.out" 2>&1; then
    p_bad "replayed code accepted"
elif grep -q "already used" "$D/bind-replay.out"; then
    p_ok "replayed code refused"
else
    p_bad "replay refused without the diagnostic (see bind-replay.out)"
fi

totp_wait_step
FRESH="$(totp_code "$SECRET" 1)"
if gate_login "$MFA_USER" "$MFA_PASS:$FRESH" >"$D/login-code.out" 2>&1; then
    p_ok "simple login with password:code yields a token"
else
    p_bad "simple login with password:code failed (see login-code.out)"
fi
if gate_login "$MFA_USER" "$MFA_PASS" >"$D/login-plain.out" 2>&1; then
    p_bad "plain simple login succeeded for an enrolled user"
else
    p_ok "plain simple login refused for an enrolled user"
fi

if graphql 'mutation($u: String!) { resetUserMfa(userId: $u) { ok } }' \
    '{"u": "'"$MFA_USER"'"}' >"$D/reset.json" 2>"$D/reset.err"; then
    p_ok "resetUserMfa by the admin"
else
    p_bad "resetUserMfa failed (see reset.err)"
fi
if t ldapwhoami -x -H "$(ldap_url)" -D "$MFA_DN" -w "$MFA_PASS" >"$D/bind-after.out" 2>&1; then
    p_ok "plain bind works again after the reset"
else
    p_bad "plain bind failed after the reset (see bind-after.out)"
fi

if log_query_has_row '{ logs(filter: {kinds: [MFA_ENROLL], actor: "'"$MFA_USER"'", success: true}) { kind detail } }' enroll; then
    p_ok "mfa_enroll rows are in the log"
else
    p_bad "no mfa_enroll row for $MFA_USER"
fi
if log_query_has_row '{ logs(filter: {kinds: [BIND], actor: "'"$MFA_USER"'", success: false}) { kind detail } }' bindfail; then
    detail="$(json_get logs.0.detail <"$D/bindfail.json")"
    if [ "$detail" = "totp replayed" ]; then
        p_ok "the replay is a bind row with detail 'totp replayed'"
    else
        p_bad "unexpected newest failed-bind detail '$detail'"
    fi
else
    p_bad "no failed bind row for $MFA_USER"
fi
if log_query_has_row '{ logs(filter: {kinds: [MFA_RESET], actor: "admin"}) { kind detail } }' reset; then
    p_ok "mfa_reset row is in the log"
else
    p_bad "no mfa_reset row"
fi
