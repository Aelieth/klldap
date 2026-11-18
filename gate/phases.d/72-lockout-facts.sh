# shellcheck shell=bash
# Phase: lockout facts at LDAP bind, simple login, TOTP and Kerberos pre-auth; rows say today | when enforced.

LK_D="$(phase_dir)"
LK_N=0 LK_P=0 LK_F=0 LK_K=0 LK_X=0 LK_FIND=()
LK_RUN="lk$(date +%H%M%S)"
LK_USER="${LK_RUN}-u" LK_MFA="${LK_RUN}-m" LK_POL="${LK_RUN}pol"
LK_XT=0
case $- in *x*) LK_XT=1 ;; esac
{ set +x; } 2>/dev/null
LK_PASS="$(python3 -c 'import secrets; print("Lk" + secrets.token_hex(10) + "!")')"
[ "$LK_XT" = 1 ] && set -x
LK_ONE="${CONTAINER}-one" LK_ONE_VOL="${CONTAINER}-one-data"
LK_TWO="${CONTAINER}-two" LK_TWO_VOL="${CONTAINER}-two-data"
LK_SECRET="" LK_MADE=0
EXTRA_CONTAINERS+=("$LK_ONE" "$LK_TWO")
EXTRA_VOLUMES+=("$LK_ONE_VOL" "$LK_TWO_VOL")

lk_pass() { LK_N=$((LK_N + 1)) LK_P=$((LK_P + 1)); p_ok "$1"; }
lk_note() { LK_N=$((LK_N + 1)) LK_K=$((LK_K + 1)); note "[NOTE] ${PHASE}: $1"; }
lk_finding() { LK_N=$((LK_N + 1)) LK_F=$((LK_F + 1)) LK_FIND+=("${1%%]*}]"); note "[FINDING] ${PHASE}: $1"; }
lk_fail() { LK_N=$((LK_N + 1)) LK_X=$((LK_X + 1)); p_bad "$1"; }
lk_gql() { graphql "$1" "$2" 2>"$LK_D/last.err"; }
lk_hush() {
    local xt=0 rc
    case $- in *x*) xt=1 ;; esac
    { set +x; } 2>/dev/null
    "$@"
    rc=$?
    [ "$xt" = 1 ] && set -x
    return "$rc"
}
lk__pw_vars() { LKU="$1" LKP="$LK_PASS" python3 -c 'import json,os; print(json.dumps({"id": os.environ["LKU"], "pw": os.environ["LKP"]}))'; }
lk_pw_vars() { lk_hush lk__pw_vars "$@"; }
lk__secret() {
    case "$1" in
    pass) printf '%s' "$LK_PASS" ;;
    pass:code) printf '%s:%s' "$LK_PASS" "$(lk__code)" ;;
    pass:wrongcode) printf '%s:%06d' "$LK_PASS" $(((10#$(lk__code) + 1) % 1000000)) ;;
    *) printf '%s' "$1" ;;
    esac
}

lk__simple_at() {
    LOGIN_URL="http://127.0.0.1:$1/auth/simple/login" LOGIN_USER="$2" LOGIN_PASS="$(lk__secret "$3")" t python3 - <<'PY'
import json, os, urllib.error, urllib.request
req = urllib.request.Request(os.environ["LOGIN_URL"], headers={"Content-Type": "application/json"},
    data=json.dumps({"username": os.environ["LOGIN_USER"], "password": os.environ["LOGIN_PASS"]}).encode())
try:
    print("200", "token" if json.load(urllib.request.urlopen(req)).get("token") else "none")
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode(errors="replace")[:200])
except Exception as e:
    print("000", str(e)[:200])
PY
}
lk_simple_at() { lk_hush lk__simple_at "$@"; }
lk_simple() { lk_simple_at "$HTTP_PORT" "$@"; }
lk_bind() { lk_hush lk__bind "$@"; }
lk__bind() {
    local f="$LK_D/.bindpw" rc
    (umask 077 && lk__secret "$2" >"$f")
    t ldapwhoami -x -H "$(ldap_url)" -D "uid=$1,ou=people,$BASE_DN" -y "$f" >/dev/null 2>&1
    rc=$?
    rm -f "$f"
    return "$rc"
}
lk_kinit() { lk_hush lk__kinit "$@"; }
lk__kinit() {
    kinit_pw "$LK_USER@$REALM" "$(lk__secret "$1")" >"$LK_D/kinit.out" 2>&1 && echo ok && return
    if grep -q "credentials have been revoked" "$LK_D/kinit.out"; then echo revoked; elif grep -q "Password incorrect" "$LK_D/kinit.out"; then echo incorrect; else echo other; fi
}
lk_rows() {
    local n
    for _ in $(seq 1 20); do
        n="$(log_rows "$1")"
        [ "${n:-0}" -ge "$2" ] && break
        sleep 0.5
    done
    printf '%s\n' "${n:-0}"
}
lk__code() {
    TOTP_SECRET="$LK_SECRET" TOTP_OFFSET="${1:-0}" python3 - <<'PY'
import base64, hashlib, hmac, os, struct, time
secret = os.environ["TOTP_SECRET"]
key = base64.b32decode(secret + "=" * (-len(secret) % 8))
step = int(time.time()) // 30 + int(os.environ["TOTP_OFFSET"])
digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
offset = digest[19] & 0x0F
print(f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}")
PY
}
lk_step() { echo $(($(date +%s) / 30)); }
lk_step_start() { sleep $((30 - $(date +%s) % 30 + 1)); }
# Prints "<answered Invalid TOTP code> <answered Too many TOTP attempts>" for five wrong codes.
lk_five_wrong() {
    local i out n=0 many=0
    for i in 1 2 3 4 5; do
        out="$(lk_simple_at "$1" "$LK_MFA" pass:wrongcode)"
        if [ "${out%% *}" = 401 ] && grep -q 'Invalid TOTP code' <<<"$out"; then
            n=$((n + 1))
        elif grep -q 'Too many TOTP attempts' <<<"$out"; then
            many=$((many + 1))
        fi
    done
    printf '%s %s\n' "$n" "$many"
}
# shellcheck disable=SC2034
lk_back_up() { wait_healthy 120 && discover_ports && TOKEN="$(gate_login)"; }

lk_setup() {
    lk_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$LK_USER"'", "email": "'"$LK_USER"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' >/dev/null &&
        lk_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$(lk_pw_vars "$LK_USER")" >/dev/null &&
        lk_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$LK_MFA"'", "email": "'"$LK_MFA"'@gate.test"}}' >/dev/null &&
        lk_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$(lk_pw_vars "$LK_MFA")" >/dev/null || {
        lk_fail "[L1.setup-users] the users could not be made: $(cat "$LK_D/last.err")"
        return 1
    }
    lk_hush lk__enrol || {
        lk_fail "[L1.setup-totp] TOTP enrolment could not be made"
        return 1
    }
}
lk__enrol() {
    local mtok out state
    mtok="$(gate_login "$LK_MFA" "$LK_PASS")" &&
        out="$(TOKEN="$mtok" graphql 'mutation { startMfaEnrollment { secretBase32 state } }' '{}' 2>/dev/null)" || return 1
    LK_SECRET="$(json_get startMfaEnrollment.secretBase32 <<<"$out")"
    state="$(json_get startMfaEnrollment.state <<<"$out")"
    TOKEN="$mtok" graphql 'mutation($s: String!, $c: String!) { finishMfaEnrollment(state: $s, code: $c) { ok } }' \
        '{"s": "'"$state"'", "c": "'"$(lk__code)"'"}' >/dev/null 2>&1
}

lk_fifty() {
    local door="$1" i wrong=0 rows proto out
    for i in $(seq 1 50); do
        case "$door" in
        ldap-bind)
            lk_bind "$LK_USER" "wrong-$i-$LK_RUN"
            [ $? = 49 ] || wrong=$((wrong + 1))
            ;;
        simple-login)
            out="$(lk_simple "$LK_USER" "wrong-$i-$LK_RUN")"
            [ "${out%% *}" = 401 ] || wrong=$((wrong + 1))
            ;;
        esac
    done
    [ "$wrong" = 0 ] || lk_finding "[L1.$door-wrong] $wrong of 50 wrong passwords at $door were not refused as wrong"
    proto="$([ "$door" = ldap-bind ] && echo ldap || echo http)"
    rows="$(lk_rows "kind = 'bind' AND protocol = '$proto' AND actor = '$LK_USER' AND NOT success" 50)"
    if [ "$rows" = 50 ]; then
        lk_pass "[L1.$door-rows] 50 wrong passwords at $door: today 50 failure rows (kind bind, protocol $proto), one per attempt | when enforced: the same rows feed the counter"
    else
        lk_finding "[L1.$door-rows] 50 wrong passwords at $door wrote $rows failure rows (kind bind, protocol $proto), not one per attempt | when enforced: each attempt must count"
    fi
    case "$door" in
    ldap-bind) lk_bind "$LK_USER" pass ;;
    simple-login) [ "$(lk_simple "$LK_USER" pass)" = "200 token" ] ;;
    esac
    if [ $? = 0 ]; then
        lk_pass "[L1.$door-right] the right password after 50 wrong at $door: today allowed, no counter | when enforced: refused while locked"
    else
        lk_finding "[L1.$door-right] the right password after 50 wrong at $door was refused today, with no lockout in the product"
    fi
}

# lk_plain_up <name> <volume>: a server with Kerberos disabled on the gate's database.
lk_plain_up() {
    LLDAP_JWT_SECRET="$JWT_SECRET" LLDAP_KEY_SEED="$KEY_SEED" LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        LLDAP_DATABASE_URL="$GATE_DATABASE_URL" t docker run -d --name "$1" --network "$NET" -p "127.0.0.1::17170" \
        -v "$2:/data" -e LLDAP_JWT_SECRET -e LLDAP_KEY_SEED -e LLDAP_LDAP_USER_PASS -e LLDAP_DATABASE_URL \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_ENABLE_MFA=true -e LLDAP_KERBEROS_OPTIONS__ENABLED=false \
        "$GATE_IMAGE" >/dev/null 2>>"$LK_D/two.err"
}
lk_plain_port() {
    local i
    for i in $(seq 1 60); do
        gexec_in "$1" /app/lldap healthcheck --config-file /data/lldap_config.toml >/dev/null 2>&1 &&
            docker port "$1" 17170/tcp | head -1 | sed 's/.*://' && return 0
        sleep 2
    done
    return 1
}

# Servers that share a database share the Kerberos setting: the gate's own server (Kerberos on)
# stops for this row, and two servers with Kerberos disabled run on its database.
lk_two_server() {
    local one_port="" two_port="" out ctl n many step
    docker rm -fv "$LK_ONE" "$LK_TWO" >/dev/null 2>&1
    : >"$LK_D/two.err"
    if ! t docker stop "$CONTAINER" >/dev/null 2>&1; then
        lk_note "[L1.totp-two-servers] the gate's server could not be stopped for this row; not run"
        return 0
    fi
    if lk_plain_up "$LK_ONE" "$LK_ONE_VOL" && lk_plain_up "$LK_TWO" "$LK_TWO_VOL"; then
        one_port="$(lk_plain_port "$LK_ONE")" && two_port="$(lk_plain_port "$LK_TWO")"
    fi
    if [ -z "$one_port" ] || [ -z "$two_port" ]; then
        lk_note "[L1.totp-two-servers] the two servers with Kerberos disabled did not both become healthy ($(head -c 200 "$LK_D/two.err")); not run"
    else
        lk_step_start
        step="$(lk_step)"
        read -r n many <<<"$(lk_five_wrong "$one_port")"
        out="$(lk_simple_at "$two_port" "$LK_MFA" pass:code)"
        ctl="$(lk_simple_at "$one_port" "$LK_MFA" pass:code)"
        if [ "$n" != 5 ]; then
            lk_note "[L1.totp-two-servers] only $n of 5 wrong codes were answered 'Invalid TOTP code' on server one ($many 'Too many'); this run cannot tell"
        elif [ "$(lk_step)" != "$step" ]; then
            lk_note "[L1.totp-two-servers] the attempts did not fall in one 30 s step; this run cannot tell"
        elif ! grep -q 'Too many TOTP attempts' <<<"$ctl"; then
            lk_fail "[L1.totp-two-servers] control: server one did not refuse the right code for too many attempts in step $step ($ctl), so it was not at its limit"
        elif [ "$out" = "200 token" ]; then
            lk_pass "[L1.totp-two-servers] 5 wrong codes on one server, then the right code on a second server on the same database in the same step ($step): today allowed, nothing shared; control: server one refused the same code for too many attempts | when enforced: refused, the count shared"
        elif grep -q 'Too many TOTP attempts' <<<"$out"; then
            lk_finding "[L1.totp-two-servers] the healthy second server refused the right code for too many attempts: the count is shared after all"
        else
            lk_note "[L1.totp-two-servers] the healthy second server answered '$out'; this run cannot tell"
        fi
    fi
    docker rm -fv "$LK_ONE" "$LK_TWO" >/dev/null 2>&1
    docker volume rm "$LK_ONE_VOL" "$LK_TWO_VOL" >/dev/null 2>&1
    t docker start "$CONTAINER" >/dev/null 2>&1 && lk_back_up ||
        lk_fail "[L1.totp-two-servers-back] the gate's server did not come back after the row"
    return 0
}

lk_totp() {
    local out step n many
    lk_step_start
    step="$(lk_step)"
    read -r n many <<<"$(lk_five_wrong "$HTTP_PORT")"
    out="$(lk_simple "$LK_MFA" pass:code)"
    if [ "$(lk_step)" != "$step" ]; then
        lk_note "[L1.totp-sixth] the six attempts did not fall in one 30 s step; this run cannot tell"
    elif [ "$many" != 0 ]; then
        lk_finding "[L1.totp-sixth] 'Too many TOTP attempts' came after $n wrong codes in step $step, so the limit is below 5"
    elif [ "$n" != 5 ]; then
        lk_note "[L1.totp-sixth] only $n of 5 wrong codes were answered 'Invalid TOTP code'; this run cannot tell"
    elif grep -q 'Too many TOTP attempts' <<<"$out"; then
        lk_pass "[L1.totp-sixth] 5 wrong codes each answered 'Invalid TOTP code', then the right code in the same 30 s step (step $step) is refused: today 'Too many TOTP attempts', 5 per step, kept in memory | when enforced: refused, and the failures also count toward lockout-threshold"
    else
        lk_finding "[L1.totp-sixth] after 5 wrong codes in step $step the right code was not refused for too many attempts ($out)"
    fi
    lk_step_start
    if [ "$(lk_simple "$LK_MFA" pass:code)" = "200 token" ]; then
        lk_pass "[L1.totp-next-step] the next step allows the right code again: today allowed | when enforced: allowed unless the account is locked"
    else
        lk_finding "[L1.totp-next-step] the right code was refused in the next step"
    fi
    lk_step_start
    step="$(lk_step)"
    read -r n many <<<"$(lk_five_wrong "$HTTP_PORT")"
    t docker restart "$CONTAINER" >/dev/null 2>&1 && lk_back_up || {
        lk_fail "[L1.totp-restart-up] the container did not come back after the TOTP restart"
        return 1
    }
    if [ "$n" != 5 ]; then
        lk_note "[L1.totp-restart] only $n of 5 wrong codes were answered 'Invalid TOTP code' before the restart ($many 'Too many'); this run cannot tell"
    elif [ "$(lk_step)" != "$step" ]; then
        lk_note "[L1.totp-restart] the restart took past the 30 s step, so this run cannot tell whether it forgot the count"
    elif [ "$(lk_simple "$LK_MFA" pass:code)" = "200 token" ]; then
        lk_pass "[L1.totp-restart] 5 wrong codes, a restart in the same step, then the right code: today allowed, the count is lost with the process | when enforced: refused, the count kept in the database"
    else
        lk_finding "[L1.totp-restart] after a restart in the same step the right code was refused"
    fi
    if [ "$GATE_DB" = postgres ]; then
        lk_two_server
    else
        lk_note "[L1.totp-two-servers] two servers need one shared database; on $GATE_DB this row is not run | when enforced: the count is shared"
    fi
    return 0
}

# kadmin -q exits 0 when its query fails, so absence needs getpol's own answer.
lk_policy_gone() {
    kadmin_q "delpol -force $LK_POL" >/dev/null 2>&1
    kadmin_q "listpols" >"$LK_D/listpols.txt" 2>&1
    kadmin_q "getpol $LK_POL" >"$LK_D/getpol.txt" 2>&1
    grep -q "Policy does not exist" "$LK_D/getpol.txt" && ! grep -qw "$LK_POL" "$LK_D/listpols.txt"
}

lk_kerberos() {
    local i wrong=0 na="not applicable on this product"
    for i in $(seq 1 20); do [ "$(lk_kinit "wrong-$i-$LK_RUN")" = incorrect ] || wrong=$((wrong + 1)); done
    [ "$wrong" = 0 ] || lk_finding "[L1.kinit-wrong] $wrong of 20 wrong passwords were not refused as 'Password incorrect'"
    if [ "$(lk_kinit pass)" = ok ]; then
        lk_pass "[L1.kinit-no-policy] 20 wrong pre-auths, then the right password, no Kerberos policy bound: today allowed | when enforced: refused, locked by the OU policy at kinit too"
    else
        lk_finding "[L1.kinit-no-policy] the right password was refused after 20 wrong, with no Kerberos policy bound"
    fi
    kadmin_q "addpol -maxfailure 3 -failurecountinterval 0 -lockoutduration 600 $LK_POL" >"$LK_D/addpol.log" 2>&1
    if grep -q " while " "$LK_D/addpol.log"; then
        lk_fail "[L1.kinit-policy-bind] addpol $LK_POL failed: $(grep ' while ' "$LK_D/addpol.log" | head -1 | cut -c1-200)"
    elif kadmin_protected "$LK_USER" "modprinc -policy $LK_POL $LK_USER" "$LK_D/modprinc.log" &&
        lk_bind "$LK_USER" pass && [ "$(lk_kinit pass)" = ok ]; then
        lk_pass "[L1.kinit-policy-bind] modprinc -policy $LK_POL (maxfailure 3) on the directory user $LK_USER: refused with PROTECT_PRINCIPAL ('Cannot change protected principal'), nothing changes, one access_denied row (protocol KADMIN, actor admin/admin@$REALM)"
    else
        lk_fail "[L1.kinit-policy-bind] ${KP_WHY:-bind or kinit lost the password after the refusal} (see modprinc.log)"
    fi
    lk_note "[L1.kinit-policy] $na: K1 binds no Kerberos policy on a directory user, so kinit has no kadmin lockout; the directory's lockout (E1′) replaces it"
    lk_note "[L1.kinit-restart] $na: no Kerberos lockout to keep over a restart; the directory's lockout (E1′) replaces it"
    lk_note "[L1.kinit-kill9] $na: no Kerberos lockout to keep over kill -9; the directory's lockout (E1′) replaces it"
    lk_note "[L1.kinit-unlock] $na: nothing is locked at kinit to release (phase 86 holds kadmin's unlock of a directory user)"
}

lk_cleanup() {
    local u out gone=0 deleted=0
    docker rm -fv "$LK_ONE" "$LK_TWO" >/dev/null 2>&1
    docker volume rm "$LK_ONE_VOL" "$LK_TWO_VOL" >/dev/null 2>&1
    lk_policy_gone && gone=1
    for u in "$LK_USER" "$LK_MFA"; do
        out="$(lk_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}')" &&
            [ "$(json_get deleteUser.ok <<<"$out" 2>/dev/null)" = True ] && deleted=$((deleted + 1))
    done
    LK_SECRET=""
    [ "$LK_MADE" = 1 ] || return 0
    if [ "$gone" = 1 ] && [ "$deleted" = 2 ]; then
        lk_pass "[L1.cleanup] the Kerberos policy $LK_POL is gone (getpol: 'Policy does not exist'; listpols does not name it) and both users are deleted"
    else
        lk_fail "[L1.cleanup] policy gone: $gone (getpol: $(tail -n 1 "$LK_D/getpol.txt" | cut -c1-120)); users deleted: $deleted of 2"
    fi
}

if lk_setup; then
    LK_MADE=1
    lk_fifty ldap-bind
    lk_fifty simple-login
    lk_totp && lk_kerberos
fi
lk_cleanup
note "lockout-facts FINDING ids: ${LK_FIND[*]:-none}"
note "lockout-facts: $LK_N rows, $LK_P pass, $LK_F FINDING, $LK_K NOTE, $LK_X FAIL"
