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
LK_TWO="${CONTAINER}-two" LK_TWO_VOL="${CONTAINER}-two-data"
LK_SECRET=""
EXTRA_CONTAINERS+=("$LK_TWO")
EXTRA_VOLUMES+=("$LK_TWO_VOL")

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
lk_five_wrong() {
    local i out n=0
    for i in 1 2 3 4 5; do
        out="$(lk_simple_at "$1" "$LK_MFA" pass:wrongcode)"
        [ "${out%% *}" = 401 ] && n=$((n + 1))
    done
    printf '%s\n' "$n"
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

lk_two_server() {
    local two_port i healthy=0 out n
    docker rm -fv "$LK_TWO" >/dev/null 2>&1
    LLDAP_JWT_SECRET="$JWT_SECRET" LLDAP_KEY_SEED="$KEY_SEED" LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        LLDAP_DATABASE_URL="$GATE_DATABASE_URL" t docker run -d --name "$LK_TWO" --network "$NET" -p "127.0.0.1::17170" \
        -v "$LK_TWO_VOL:/data" -e LLDAP_JWT_SECRET -e LLDAP_KEY_SEED -e LLDAP_LDAP_USER_PASS -e LLDAP_DATABASE_URL \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_ENABLE_MFA=true -e LLDAP_KERBEROS_OPTIONS__ENABLED=false \
        "$GATE_IMAGE" >/dev/null 2>"$LK_D/two.err" || {
        lk_note "[L1.totp-two-servers] the second server could not start ($(head -c 200 "$LK_D/two.err")); not run"
        return 0
    }
    for i in $(seq 1 60); do
        gexec_in "$LK_TWO" /app/lldap healthcheck --config-file /data/lldap_config.toml >/dev/null 2>&1 && healthy=1 && break
        sleep 2
    done
    two_port="$(docker port "$LK_TWO" 17170/tcp | head -1 | sed 's/.*://')"
    if [ "$healthy" != 1 ] || [ -z "$two_port" ]; then
        lk_note "[L1.totp-two-servers] the second server never became healthy; not run"
    else
        lk_step_start
        n="$(lk_five_wrong "$HTTP_PORT")"
        out="$(lk_simple_at "$two_port" "$LK_MFA" pass:code)"
        if [ "$n" != 5 ]; then
            lk_note "[L1.totp-two-servers] only $n of 5 wrong codes were refused as wrong on server one; this run cannot tell"
        elif [ "$out" = "200 token" ]; then
            lk_pass "[L1.totp-two-servers] 5 wrong codes on one server, then the right code on a second server on the same database in the same step: today allowed, nothing shared | when enforced: refused, the count shared"
        elif grep -q 'Too many TOTP attempts' <<<"$out"; then
            lk_finding "[L1.totp-two-servers] the healthy second server refused the right code for too many attempts: the count is shared after all"
        else
            lk_note "[L1.totp-two-servers] the healthy second server answered '$out'; this run cannot tell"
        fi
    fi
    docker rm -fv "$LK_TWO" >/dev/null 2>&1
    docker volume rm "$LK_TWO_VOL" >/dev/null 2>&1
    return 0
}

lk_totp() {
    local out step n
    lk_step_start
    step="$(lk_step)"
    n="$(lk_five_wrong "$HTTP_PORT")"
    out="$(lk_simple "$LK_MFA" pass:code)"
    if [ "$n" != 5 ]; then
        lk_note "[L1.totp-sixth] only $n of 5 wrong codes were refused as wrong; this run cannot tell"
    elif [ "$(lk_step)" != "$step" ]; then
        lk_note "[L1.totp-sixth] the six attempts did not fall in one 30 s step; this run cannot tell"
    elif grep -q 'Too many TOTP attempts' <<<"$out"; then
        lk_pass "[L1.totp-sixth] after 5 wrong codes, the right code in the same 30 s step (step $step) is refused: today 'Too many TOTP attempts', 5 per step, kept in memory | when enforced: refused, and the failures also count toward lockout-threshold"
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
    n="$(lk_five_wrong "$HTTP_PORT")"
    t docker restart "$CONTAINER" >/dev/null 2>&1 && lk_back_up || {
        lk_fail "[L1.totp-restart-up] the container did not come back after the TOTP restart"
        return 1
    }
    if [ "$n" != 5 ]; then
        lk_note "[L1.totp-restart] only $n of 5 wrong codes were refused as wrong before the restart; this run cannot tell"
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

lk_policy_gone() {
    kadmin_q "modprinc -unlock $LK_USER@$REALM" >/dev/null 2>&1
    kadmin_q "modprinc -clearpolicy $LK_USER@$REALM" >/dev/null 2>&1
    kadmin_q "delpol -force $LK_POL" >/dev/null 2>&1
    local pols
    if pols="$(kadmin_q "listpols" 2>/dev/null)"; then
        ! grep -qw "$LK_POL" <<<"$pols"
    else
        kadmin_q "getpol $LK_POL" 2>&1 | grep -q "Policy does not exist"
    fi
}

lk_kerberos() {
    local i wrong=0 got code
    for i in $(seq 1 20); do [ "$(lk_kinit "wrong-$i-$LK_RUN")" = incorrect ] || wrong=$((wrong + 1)); done
    [ "$wrong" = 0 ] || lk_finding "[L1.kinit-wrong] $wrong of 20 wrong passwords were not refused as 'Password incorrect'"
    if [ "$(lk_kinit pass)" = ok ]; then
        lk_pass "[L1.kinit-no-policy] 20 wrong pre-auths, then the right password, no Kerberos policy bound: today allowed | when enforced: refused, locked by the OU policy at kinit too"
    else
        lk_finding "[L1.kinit-no-policy] the right password was refused after 20 wrong, with no Kerberos policy bound"
    fi
    kadmin_q "addpol -maxfailure 3 -failurecountinterval 0 -lockoutduration 600 $LK_POL" >"$LK_D/addpol.log" 2>&1 &&
        kadmin_q "modprinc -policy $LK_POL $LK_USER@$REALM" >"$LK_D/modprinc.log" 2>&1 || {
        lk_note "[L1.kinit-policy] a Kerberos policy could not be made or bound through kadmin on loopback: $(tail -n 1 -q "$LK_D/addpol.log" "$LK_D/modprinc.log" | tr '\n' ' ' | cut -c1-200)"
        return 0
    }
    for i in 1 2 3; do lk_kinit "wrong-p$i-$LK_RUN" >/dev/null; done
    got="$(lk_kinit pass)"
    if [ "$got" = revoked ]; then
        lk_pass "[L1.kinit-policy] a Kerberos policy with maxfailure 3 (kadmin on loopback), 3 wrong, then the right password: today refused, 'Client's credentials have been revoked' | when enforced: the same, and the OU policy also applies"
    else
        lk_finding "[L1.kinit-policy] with maxfailure 3 bound through kadmin, the right password after 3 failures gave '$got', not the lockout refusal"
    fi
    t docker restart "$CONTAINER" >/dev/null 2>&1 && lk_back_up || {
        lk_fail "[L1.kinit-restart-up] the container did not come back after the Kerberos restart"
        return 1
    }
    got="$(lk_kinit pass)"
    if [ "$got" = revoked ]; then
        lk_pass "[L1.kinit-restart] after a clean restart the principal is still locked ('credentials have been revoked'): today kept in data_dir/lockout | when enforced: the same"
    else
        lk_finding "[L1.kinit-restart] after a clean restart the right password gave '$got': the Kerberos lockout was not kept"
    fi
    t docker kill -s KILL "$CONTAINER" >/dev/null 2>&1
    code="$(docker inspect -f '{{.State.Running}} {{.State.ExitCode}}' "$CONTAINER" 2>&1)"
    if [ "$code" != "false 137" ]; then
        lk_fail "[L1.kinit-kill9-kill] the SIGKILL was not seen (state '$code', want 'false 137')"
        t docker start "$CONTAINER" >/dev/null 2>&1 && lk_back_up
        return 1
    fi
    t docker start "$CONTAINER" >/dev/null 2>&1 && lk_back_up || {
        lk_fail "[L1.kinit-kill9-up] the container did not come back after kill -9"
        return 1
    }
    got="$(lk_kinit pass)"
    if [ "$got" = revoked ]; then
        lk_pass "[L1.kinit-kill9] after kill -9 (exit 137) and a start the principal is still locked: today kept | when enforced: the same"
    else
        lk_finding "[L1.kinit-kill9] after kill -9 (exit 137) the right password gave '$got': the Kerberos lockout was not kept"
    fi
    kadmin_q "modprinc -unlock $LK_USER@$REALM" >"$LK_D/unlock.log" 2>&1
    got="$(lk_kinit pass)"
    if [ "$got" = ok ]; then
        lk_pass "[L1.kinit-unlock] kadmin modprinc -unlock releases the principal: today allowed again"
    else
        lk_finding "[L1.kinit-unlock] after modprinc -unlock the right password gave '$got' ($(tail -n 1 "$LK_D/unlock.log"))"
    fi
}

lk_cleanup() {
    docker rm -fv "$LK_TWO" >/dev/null 2>&1
    docker volume rm "$LK_TWO_VOL" >/dev/null 2>&1
    lk_policy_gone || lk_fail "[L1.cleanup-policy] the Kerberos policy $LK_POL is still there after delpol"
    for u in "$LK_USER" "$LK_MFA"; do lk_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}' >/dev/null; done
    LK_SECRET=""
}

if lk_setup; then
    lk_fifty ldap-bind
    lk_fifty simple-login
    lk_totp && lk_kerberos
fi
lk_cleanup
note "lockout-facts FINDING ids: ${LK_FIND[*]:-none}"
note "lockout-facts: $LK_N rows, $LK_P pass, $LK_F FINDING, $LK_K NOTE, $LK_X FAIL"
