# shellcheck shell=bash
# Phase: lockout at LDAP bind, simple login, TOTP, Kerberos pre-auth and S4U2Self: no threshold counts, an OU threshold locks.
# Also the refusal rows' peer at both login doors, and the answers while ou_policies is held.

LK_D="$(phase_dir)"
LK_N=0 LK_P=0 LK_F=0 LK_K=0 LK_X=0 LK_FIND=()
LK_RUN="lk$(date +%H%M%S)"
LK_USER="${LK_RUN}-u" LK_MFA="${LK_RUN}-m" LK_POL="${LK_RUN}pol"
LK_LOCK="${LK_RUN}-l" LK_OU="${LK_RUN}ou" LK_POLICY="" LK_LOCK_DN=""
LK_SVC="${LK_RUN}s4u/gate.test" LK_KT="/tmp/${LK_RUN}s4u.keytab" LK_SCC="/tmp/${LK_RUN}s4u.cc"
LK_W3="incorrect incorrect incorrect"
LK_XT=0
case $- in *x*) LK_XT=1 ;; esac
{ set +x; } 2>/dev/null
LK_PASS="$(python3 -c 'import secrets; print("Lk" + secrets.token_hex(10) + "!")')"
[ "$LK_XT" = 1 ] && set -x
LK_ONE="${CONTAINER}-one" LK_ONE_VOL="${CONTAINER}-one-data"
LK_TWO="${CONTAINER}-two" LK_TWO_VOL="${CONTAINER}-two-data"
LK_SECRET="" LK_MADE=0
LK_PEER_CTN="klldap-lkpeer-${RUNID}" LK_HELD="${LK_RUN}-h" LK_HELD_TRIED=0
LK_TCC="/tmp/${LK_RUN}tgs.cc" LK_ONE_OU="${LK_RUN}one" LK_ONE_POLICY="" LK_PAGE_USERS=()
EXTRA_CONTAINERS+=("$LK_ONE" "$LK_TWO" "$LK_PEER_CTN")
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
    local f="$LK_D/.bindpw" rc dn="uid=$1,ou=people,$BASE_DN"
    [ "$1" = "$LK_LOCK" ] && dn="$LK_LOCK_DN"
    (umask 077 && lk__secret "$2" >"$f")
    t ldapwhoami -x -H "$(ldap_url)" -D "$dn" -y "$f" >/dev/null 2>&1
    rc=$?
    rm -f "$f"
    return "$rc"
}
lk_kinit() { lk_hush lk__kinit "$LK_USER" "$@"; }
lk_kinit_as() { lk_hush lk__kinit "$@"; }
lk__kinit() {
    kinit_pw "$1@$REALM" "$(lk__secret "$2")" >"$LK_D/kinit.out" 2>&1 && echo ok && return
    if grep -q "credentials have been revoked" "$LK_D/kinit.out"; then echo revoked; elif grep -q "Password incorrect" "$LK_D/kinit.out"; then echo incorrect; else echo other; fi
}
lk_wrong3() {
    local i got=""
    for i in 1 2 3; do got+="$(lk_kinit_as "$LK_LOCK" "wrong-$1$i-$LK_RUN") "; done
    printf '%s\n' "${got% }"
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
lk_mark() {
    sleep 1
    graphql '{ logs(limit: 1) { id } }' '{}' 2>/dev/null | json_get logs.0.id 2>/dev/null
}
lk_one() {
    local n
    [ -n "$2" ] || {
        echo unread
        return
    }
    n="$(lk_rows "$1 AND id > $2" 1)"
    [ "$n" = 1 ] && sleep 1 && n="$(log_rows "$1 AND id > $2")"
    printf '%s\n' "${n:-0}"
}
lk_who() { printf "(actor = '%s' OR target = '%s')" "$1" "$1"; }
lk_lock_row() { printf "kind = 'account_lock' AND success AND actor IS NULL AND target = '%s' AND protocol = '%s' AND detail = 'locked: %s'" "$LK_LOCK" "$1" "$2"; }
lk_unlock_row() { printf "kind = 'account_unlock' AND success AND target IN ('%s', '%s@%s') AND %s AND protocol = '%s' AND detail = '%s'" "$LK_LOCK" "$LK_LOCK" "$REALM" "$1" "$2" "$3"; }
# The gate reads its database on postgres and sqlite; elsewhere a row that needs a read is a NOTE.
LK_READS=0
case "$GATE_DB" in postgres | sqlite) LK_READS=1 ;; esac
lk_is() { [ "$LK_READS" = 0 ] || [ "$1" = "$2" ]; }
lk_pass_read() { if [ "$LK_READS" = 1 ]; then lk_pass "$1"; else lk_note "$1 | counts and rows not read on $GATE_DB"; fi; }
lk_count() {
    local n=""
    case "$GATE_DB" in
    postgres)
        n="$(gexec_in "$PG_CONTAINER" psql -U klldap -d klldap -tAc \
            "SELECT COALESCE(MAX(fail_count), 0) FROM login_lockouts WHERE user_id = '$1'" 2>/dev/null | tr -d '[:space:]')"
        ;;
    sqlite)
        docker cp "$CONTAINER:/data/users.db" "$LK_D/lockouts-copy.db" >/dev/null 2>&1 &&
            n="$(LK_DB="$LK_D/lockouts-copy.db" LK_U="$1" python3 -c '
import os, sqlite3
row = sqlite3.connect(os.environ["LK_DB"]).execute("SELECT fail_count FROM login_lockouts WHERE user_id = ?", (os.environ["LK_U"],)).fetchone()
print(row[0] if row else 0)' 2>/dev/null)"
        ;;
    esac
    printf '%s\n' "$n"
}
lk_count_wait() {
    local n
    [ "$LK_READS" = 1 ] || return 0
    for _ in $(seq 1 10); do
        n="$(lk_count "$1")"
        [ "$n" = "$2" ] && break
        sleep 0.5
    done
    printf '%s\n' "$n"
}
lk_unlock() {
    local out
    out="$(lk_gql 'mutation($u: String!) { unlockUser(userId: $u) { ok } }' '{"u": "'"$1"'"}')" &&
        [ "$(json_get unlockUser.ok <<<"$out" 2>/dev/null)" = True ]
}
lk_s4u() {
    gexec kvno --no-store -c "$LK_SCC" -k "$LK_KT" -I "$LK_LOCK@$REALM" "$LK_SVC@$REALM" >"$LK_D/s4u-$1.log" 2>&1 &&
        grep -q 'keytab entry valid' "$LK_D/s4u-$1.log" && echo ticket && return
    grep -qi 'revoked' "$LK_D/s4u-$1.log" && echo revoked || echo other
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
        lk_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$(lk_pw_vars "$LK_MFA")" >/dev/null &&
        lk_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$LK_LOCK"'", "email": "'"$LK_LOCK"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' >/dev/null &&
        lk_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$(lk_pw_vars "$LK_LOCK")" >/dev/null || {
        lk_fail "[L1.setup-users] the users could not be made: $(cat "$LK_D/last.err")"
        return 1
    }
    lk_hush lk__enrol || {
        lk_fail "[L1.setup-totp] TOTP enrolment could not be made"
        return 1
    }
    lk_setup_ou || {
        lk_fail "[L1.setup-policy] $LK_LOCK in OU $LK_OU under lockout-threshold 3, lockout-duration-seconds 0 could not be made: $(head -c 300 "$LK_D/last.err")"
        return 1
    }
}
lk_setup_ou() {
    local got
    lk_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$LK_OU"'"}' >/dev/null &&
        LK_POLICY="$(lk_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
            '{"n": "'"$LK_RUN"' lockout", "i": [{"key": "lockout-threshold", "value": "3"}, {"key": "lockout-duration-seconds", "value": "0"}]}' |
            json_get createPolicy.id 2>/dev/null)" && [ -n "$LK_POLICY" ] &&
        lk_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' '{"o": "'"$LK_OU"'", "p": '"$LK_POLICY"'}' >/dev/null &&
        lk_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$LK_LOCK"'"], "ou": "'"$LK_OU"'"}' >/dev/null || return 1
    got="$(lk_gql 'query($o: String!, $u: String!) { effectivePolicyItems(ou: $o) { key value } user(userId: $u) { ou } }' \
        '{"o": "'"$LK_OU"'", "u": "'"$LK_LOCK"'"}' | python3 -c '
import json, sys
d = json.load(sys.stdin)
items = {i["key"]: i["value"] for i in d["effectivePolicyItems"]}
print(items.get("lockout-threshold"), items.get("lockout-duration-seconds"), d["user"]["ou"].lower())' 2>/dev/null)"
    [ "$got" = "3 0 ${LK_OU,,}" ] || {
        echo "effective items and OU: '$got', want '3 0 ${LK_OU,,}'" >"$LK_D/last.err"
        return 1
    }
    LK_LOCK_DN="$(lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$LK_LOCK)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1)"
    [ -n "$LK_LOCK_DN" ] && lk_bind "$LK_LOCK" pass || {
        echo "no DN found for $LK_LOCK, or its bind with the right password failed (DN '$LK_LOCK_DN')" >"$LK_D/last.err"
        return 1
    }
    for _ in $(seq 1 15); do
        kadmin_q "getprinc $LK_LOCK" 2>/dev/null | grep -q "^Principal: $LK_LOCK@$REALM" && return 0
        sleep 1
    done
    echo "no principal $LK_LOCK@$REALM" >"$LK_D/last.err"
    return 1
}
lk__enrol() {
    local mtok out state proof
    # shellcheck disable=SC2016
    local q='mutation($p: String) { startMfaEnrollment(enrollmentProof: $p) { secretBase32 state } }'
    mtok="$(gate_login "$LK_MFA" "$LK_PASS")" &&
        proof="$(gate_enrollment_proof "$LK_MFA" "$LK_PASS")" &&
        out="$(TOKEN="$mtok" graphql "$q" '{"p": "'"$proof"'"}' 2>/dev/null)" || return 1
    LK_SECRET="$(json_get startMfaEnrollment.secretBase32 <<<"$out")"
    state="$(json_get startMfaEnrollment.state <<<"$out")"
    TOKEN="$mtok" graphql 'mutation($s: String!, $c: String!) { finishMfaEnrollment(state: $s, code: $c) { ok } }' \
        '{"s": "'"$state"'", "c": "'"$(lk__code)"'"}' >/dev/null 2>&1
}

# lk_flood <protocol> <mark>: "<started> <resolved>", the sign_in_flood rows of 50 wrong binds
# once their window has closed (20 s after the last one, then the writer's tick).
lk_flood() {
    local row resolved
    [ "$LK_READS" = 1 ] || {
        echo unread
        return
    }
    row="kind = 'sign_in_flood' AND NOT success AND protocol = '$1' AND (target = '$LK_USER' OR target IS NULL) AND id > ${2:-0}"
    resolved="$row AND detail LIKE 'bind flood resolved: 42 refusals, 1 names, %'"
    for _ in $(seq 1 45); do
        [ "$(log_rows "$resolved")" = 0 ] || break
        sleep 1
    done
    printf '%s %s\n' "$(log_rows "$row AND detail = 'bind flood started'")" "$(log_rows "$resolved")"
}

lk_fifty() {
    local door="$1" i wrong=0 rows proto out before after mark quiet flood
    proto="$([ "$door" = ldap-bind ] && echo ldap || echo http)"
    quiet="$(flood_quiet BIND "${proto^^}")"
    mark="$(lk_mark)"
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
    before="$(lk_count_wait "$LK_USER" 50)"
    case "$door" in
    ldap-bind) lk_bind "$LK_USER" pass ;;
    simple-login) [ "$(lk_simple "$LK_USER" pass)" = "200 token" ] ;;
    esac
    out=$?
    after="$(lk_count_wait "$LK_USER" 0)"
    if [ "$out" = 0 ] && lk_is "$before" 50 && lk_is "$after" 0; then
        lk_pass_read "[L1.$door-right] no threshold on $LK_USER (another OU sets one, so the lockout is on): the 50 wrong at $door are counted (login_lockouts fail_count 50), the right password is allowed and the count is 0"
    else
        lk_finding "[L1.$door-right] no threshold: fail_count after 50 wrong at $door was $before (want 50); the right password $([ "$out" = 0 ] && echo allowed || echo REFUSED) (want allowed); fail_count after it $after (want 0)"
    fi
    flood="$(lk_flood "$proto" "$mark")"
    rows="$(log_rows "kind = 'bind' AND protocol = '$proto' AND actor = '$LK_USER' AND NOT success AND id > ${mark:-0}")"
    if lk_is "$rows" 8 && lk_is "$flood" "1 1"; then
        lk_pass_read "[L1.$door-rows] 50 wrong passwords at $door after $quiet s of waiting for a closed flood window: the first 8 are failure rows (kind bind, protocol $proto), the other 42 are one sign_in_flood pair, 'bind flood started' and 'bind flood resolved: 42 refusals, 1 names', while fail_count read 50"
    else
        lk_fail "[L1.$door-rows] 50 wrong passwords at $door wrote $rows failure rows (kind bind, protocol $proto; want 8) and sign_in_flood rows 'bind flood started' and 'bind flood resolved: 42 refusals, 1 names': $flood (want 1 1); fail_count read $before"
    fi
}

lk_threshold() {
    local door="$1" i wrong=0 mark out count right want proto label rows locks
    case "$door" in
    ldap-bind) proto=ldap label="ldap bind" want=49 ;;
    simple-login) proto=http label="simple login" want=401 ;;
    esac
    # The four refusals below must be kept one to one: no flood window of this door is open.
    flood_quiet BIND "${proto^^}" >/dev/null
    mark="$(lk_mark)"
    for i in 1 2 3; do
        case "$door" in
        ldap-bind)
            lk_bind "$LK_LOCK" "wrong-t$i-$LK_RUN"
            [ $? = 49 ] || wrong=$((wrong + 1))
            ;;
        simple-login)
            out="$(lk_simple "$LK_LOCK" "wrong-t$i-$LK_RUN")"
            [ "${out%% *}" = 401 ] || wrong=$((wrong + 1))
            ;;
        esac
    done
    count="$(lk_count_wait "$LK_LOCK" 3)"
    case "$door" in
    ldap-bind)
        lk_bind "$LK_LOCK" pass
        right=$?
        ;;
    simple-login)
        out="$(lk_simple "$LK_LOCK" pass)"
        right="${out%% *}"
        ;;
    esac
    rows="$(lk_one "kind = 'bind' AND protocol = '$proto' AND NOT success AND detail = 'locked out' AND $(lk_who "$LK_LOCK")" "$mark")"
    locks="$(lk_one "$(lk_lock_row "$proto" "$label")" "$mark")"
    if [ "$wrong" = 0 ] && lk_is "$count" 3 && [ "$right" = "$want" ] && lk_is "$rows" 1 && lk_is "$locks" 1; then
        lk_pass_read "[L1.$door-locked] OU threshold 3: 3 wrong at $door (fail_count 3), then the right password is refused as a wrong one ($want); one 'locked out' row (kind bind, protocol $proto) and one account_lock 'locked: $label'"
    else
        lk_fail "[L1.$door-locked] OU threshold 3: $wrong of 3 wrong not refused, fail_count $count (want 3), the right password answered $right (want $want); 'locked out' rows: $rows, account_lock rows: $locks (want 1 and 1)"
    fi
    lk_unlock "$LK_LOCK" || lk_finding "[L1.$door-unlock] unlockUser $LK_LOCK failed: $(head -c 200 "$LK_D/last.err")"
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
        lk_note "[L1.totp-used-two-servers] the gate's server could not be stopped for this row; not run"
        return 0
    fi
    if lk_plain_up "$LK_ONE" "$LK_ONE_VOL" && lk_plain_up "$LK_TWO" "$LK_TWO_VOL"; then
        one_port="$(lk_plain_port "$LK_ONE")" && two_port="$(lk_plain_port "$LK_TWO")"
    fi
    if [ -z "$one_port" ] || [ -z "$two_port" ]; then
        lk_note "[L1.totp-two-servers] the two servers with Kerberos disabled did not both become healthy ($(head -c 200 "$LK_D/two.err")); not run"
        lk_note "[L1.totp-used-two-servers] the two servers did not both become healthy; not run"
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
        elif grep -q 'Too many TOTP attempts' <<<"$out"; then
            lk_pass "[L1.totp-two-servers] 5 wrong codes on one server, then the right code on a second server on the same database in the same step ($step): refused for too many attempts, the count shared in the database; control: server one refused it too"
        elif [ "$out" = "200 token" ]; then
            lk_finding "[L1.totp-two-servers] the second server allowed the right code after 5 wrong codes on server one in the same step: the count is not shared"
        else
            lk_note "[L1.totp-two-servers] the healthy second server answered '$out'; this run cannot tell"
        fi
        lk_used_two_servers "$one_port" "$two_port"
    fi
    docker rm -fv "$LK_ONE" "$LK_TWO" >/dev/null 2>&1
    docker volume rm "$LK_ONE_VOL" "$LK_TWO_VOL" >/dev/null 2>&1
    t docker start "$CONTAINER" >/dev/null 2>&1 && lk_back_up ||
        lk_fail "[L1.totp-two-servers-back] the gate's server did not come back after the row"
    return 0
}

# The same right code on both servers in one fresh step: the second must answer 'already used'.
lk_used_two_servers() {
    local one two step
    lk_step_start
    step="$(lk_step)"
    one="$(lk_simple_at "$1" "$LK_MFA" pass:code)"
    two="$(lk_simple_at "$2" "$LK_MFA" pass:code)"
    if [ "$(lk_step)" != "$step" ]; then
        lk_note "[L1.totp-used-two-servers] the two sign-ins did not fall in one 30 s step; this run cannot tell"
    elif [ "$one" != "200 token" ]; then
        lk_note "[L1.totp-used-two-servers] server one did not take the right code in a fresh step ($one); this run cannot tell"
    elif grep -q 'TOTP code already used' <<<"$two"; then
        lk_pass "[L1.totp-used-two-servers] a code taken on server one in step $step is refused on server two as already used: the used mark is shared in the database"
    elif [ "$two" = "200 token" ]; then
        lk_finding "[L1.totp-used-two-servers] the code taken on server one was taken again on server two in step $step"
    else
        lk_note "[L1.totp-used-two-servers] server two answered '$two'; this run cannot tell"
    fi
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
        lk_pass "[L1.totp-sixth] 5 wrong codes each answered 'Invalid TOTP code', then the right code in the same 30 s step (step $step) is refused: 'Too many TOTP attempts', 5 per step, kept in the database"
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
    else
        out="$(lk_simple "$LK_MFA" pass:code)"
        if grep -q 'Too many TOTP attempts' <<<"$out"; then
            lk_pass "[L1.totp-restart] 5 wrong codes, a restart in the same step, then the right code: refused for too many attempts, the count kept in the database"
        elif [ "$out" = "200 token" ]; then
            lk_finding "[L1.totp-restart] after a restart in the same step the right code was allowed: the count was lost with the process"
        else
            lk_note "[L1.totp-restart] after the restart the right code was answered '$out'; this run cannot tell"
        fi
    fi
    if [ "$GATE_DB" = postgres ]; then
        lk_two_server
    else
        lk_note "[L1.totp-two-servers] two servers need one shared database; on $GATE_DB this row is not run"
        lk_note "[L1.totp-used-two-servers] two servers need one shared database; on $GATE_DB this row is not run"
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
    local i wrong=0 before got after
    for i in $(seq 1 20); do [ "$(lk_kinit "wrong-$i-$LK_RUN")" = incorrect ] || wrong=$((wrong + 1)); done
    [ "$wrong" = 0 ] || lk_finding "[L1.kinit-wrong] $wrong of 20 wrong passwords were not refused as 'Password incorrect'"
    before="$(lk_count_wait "$LK_USER" 20)"
    got="$(lk_kinit pass)"
    after="$(lk_count_wait "$LK_USER" 0)"
    if [ "$got" = ok ] && lk_is "$before" 20 && lk_is "$after" 0; then
        lk_pass_read "[L1.kinit-no-policy] no threshold on $LK_USER (another OU sets one, so the lockout is on): 20 wrong pre-auths are counted (login_lockouts fail_count 20), the right password gets a ticket and the count is 0"
    else
        lk_finding "[L1.kinit-no-policy] no threshold: fail_count after 20 wrong was $before (want 20); the right password gave '$got' (want ok); fail_count after it $after (want 0)"
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
    lk_kinit_policy
    lk_kinit_restart && lk_kinit_kill9 || return 1
    lk_kinit_unlock
    lk_s4u_rows
    lk_tgs_locked
    lk_one_counter
    lk_tool_unlock
}

lk_kinit_policy() {
    local mark w count got rows locks
    # The 20 wrong kinits above may have left a flood window open: the 'locked out' row is kept
    # one to one only in a new one.
    flood_quiet LOGIN KERBEROS >/dev/null
    mark="$(lk_mark)"
    w="$(lk_wrong3 p)"
    count="$(lk_count_wait "$LK_LOCK" 3)"
    got="$(lk_kinit_as "$LK_LOCK" pass)"
    rows="$(lk_one "kind = 'login' AND protocol = 'kerberos' AND NOT success AND detail = 'locked out' AND $(lk_who "$LK_LOCK")" "$mark")"
    locks="$(lk_one "$(lk_lock_row kerberos kerberos)" "$mark")"
    if [ "$w" = "$LK_W3" ] && lk_is "$count" 3 && [ "$got" = revoked ] && lk_is "$rows" 1 && lk_is "$locks" 1; then
        lk_pass_read "[L1.kinit-policy] OU threshold 3 on $LK_LOCK: 3 wrong, each 'Password incorrect' (fail_count 3), then the right password is refused before pre-auth ('credentials have been revoked'); one kerberos login row 'locked out' and one account_lock 'locked: kerberos'"
    else
        lk_fail "[L1.kinit-policy] OU threshold 3: the 3 wrong gave '$w', fail_count $count (want 3), the right password '$got' (want revoked); 'locked out' login rows: $rows, account_lock rows: $locks (want 1 and 1)"
    fi
}

lk_kinit_restart() {
    local count got
    t docker restart "$CONTAINER" >/dev/null 2>&1 && lk_back_up || {
        lk_fail "[L1.kinit-restart-up] the container did not come back after the Kerberos restart"
        return 1
    }
    count="$(lk_count "$LK_LOCK")"
    got="$(lk_kinit_as "$LK_LOCK" pass)"
    if lk_is "$count" 3 && [ "$got" = revoked ]; then
        lk_pass_read "[L1.kinit-restart] after a clean restart $LK_LOCK is still locked: fail_count 3 in login_lockouts, the right password 'credentials have been revoked'"
    else
        lk_finding "[L1.kinit-restart] after a clean restart fail_count is $count and the right password gave '$got' (want 3 and revoked): the lock was not kept"
    fi
}

lk_kinit_kill9() {
    local w before code count got
    lk_unlock "$LK_LOCK" || lk_finding "[L1.kinit-kill9-unlock] unlockUser $LK_LOCK failed before the kill: $(head -c 200 "$LK_D/last.err")"
    w="$(lk_wrong3 k)"
    # The row is about a stored count surviving a kill: the kill waits until the table holds it.
    before="$(lk_count_wait "$LK_LOCK" 3)"
    [ "$LK_READS" = 1 ] || sleep 2
    t docker kill -s KILL "$CONTAINER" >/dev/null 2>&1
    for _ in $(seq 1 10); do
        code="$(docker inspect -f '{{.State.Running}} {{.State.ExitCode}}' "$CONTAINER" 2>&1)"
        [ "${code%% *}" = false ] && break
        sleep 0.5
    done
    if [ "$code" != "false 137" ]; then
        lk_fail "[L1.kinit-kill9-kill] the SIGKILL was not seen (state '$code', want 'false 137')"
        t docker start "$CONTAINER" >/dev/null 2>&1 && lk_back_up
        return 1
    fi
    t docker start "$CONTAINER" >/dev/null 2>&1 && lk_back_up || {
        lk_fail "[L1.kinit-kill9-up] the container did not come back after kill -9"
        return 1
    }
    count="$(lk_count "$LK_LOCK")"
    got="$(lk_kinit_as "$LK_LOCK" pass)"
    if [ "$w" = "$LK_W3" ] && lk_is "$before" 3 && lk_is "$count" 3 && [ "$got" = revoked ]; then
        lk_pass_read "[L1.kinit-kill9] unlocked, 3 wrong (each 'Password incorrect'), the table read back at 3, then kill -9 (exit 137) and a start: fail_count 3 and still locked ('credentials have been revoked'); a stored count survives a kill"
    else
        lk_finding "[L1.kinit-kill9] 3 wrong ('$w'), stored $before before the kill (want 3), then kill -9 (exit 137) and a start: fail_count $count, the right password '$got' (want 3 and revoked)"
    fi
}

lk_kinit_unlock() {
    local mark count got rows w locked
    mark="$(lk_mark)"
    if lk_unlock "$LK_LOCK"; then
        count="$(lk_count_wait "$LK_LOCK" 0)"
        got="$(lk_kinit_as "$LK_LOCK" pass)"
        rows="$(lk_one "$(lk_unlock_row "actor = 'admin'" graphql unlockUser)" "$mark")"
        if lk_is "$count" 0 && [ "$got" = ok ] && lk_is "$rows" 1; then
            lk_pass_read "[L1.kinit-unlock] unlockUser on the locked $LK_LOCK: fail_count 0, the right password gets a ticket, one account_unlock 'unlockUser' (protocol graphql, actor admin)"
        else
            lk_finding "[L1.kinit-unlock] after unlockUser: fail_count $count (want 0), the right password '$got' (want ok), account_unlock 'unlockUser' rows: $rows (want 1)"
        fi
    else
        lk_finding "[L1.kinit-unlock] unlockUser $LK_LOCK failed: $(head -c 200 "$LK_D/last.err")"
    fi
    w="$(lk_wrong3 u)"
    locked="$(lk_kinit_as "$LK_LOCK" pass)"
    mark="$(lk_mark)"
    kadmin_q "modprinc -unlock $LK_LOCK" >"$LK_D/kadmin-unlock.log" 2>&1
    count="$(lk_count_wait "$LK_LOCK" 0)"
    got="$(lk_kinit_as "$LK_LOCK" pass)"
    rows="$(lk_one "$(lk_unlock_row "actor = 'admin/admin@$REALM'" kadmin 'kadmin modprinc -unlock')" "$mark")"
    if grep -q " while " "$LK_D/kadmin-unlock.log"; then
        lk_finding "[L1.kinit-unlock-kadmin] modprinc -unlock $LK_LOCK: $(grep ' while ' "$LK_D/kadmin-unlock.log" | head -1 | cut -c1-200)"
    elif [ "$w" = "$LK_W3" ] && [ "$locked" = revoked ] && lk_is "$count" 0 && [ "$got" = ok ] && lk_is "$rows" 1; then
        lk_pass_read "[L1.kinit-unlock-kadmin] locked again (3 wrong, the right password revoked), then kadmin modprinc -unlock: fail_count 0, the right password gets a ticket, one account_unlock 'kadmin modprinc -unlock' (protocol kadmin, actor admin/admin@$REALM)"
    else
        lk_finding "[L1.kinit-unlock-kadmin] 3 wrong '$w' then the right password '$locked' (want revoked); after modprinc -unlock fail_count $count (want 0), the right password '$got' (want ok), account_unlock rows: $rows (want 1)"
    fi
}

lk_s4u_rows() {
    local w before got after mark rows locked
    if ! { kadmin_q "addprinc -randkey $LK_SVC" >"$LK_D/s4u-add.txt" 2>&1 && ! grep -q " while " "$LK_D/s4u-add.txt" &&
        kadmin_q "ktadd -k $LK_KT $LK_SVC" >"$LK_D/s4u-ktadd.txt" 2>&1 && grep -q "added to keytab" "$LK_D/s4u-ktadd.txt" &&
        gexec kinit -k -t "$LK_KT" -c "$LK_SCC" "$LK_SVC@$REALM" >"$LK_D/s4u-kinit.log" 2>&1; }; then
        lk_fail "[L1.s4u-setup] $LK_SVC, its keytab $LK_KT or its ticket could not be made (see s4u-add.txt, s4u-ktadd.txt, s4u-kinit.log)"
        return 0
    fi
    w="$(lk_kinit_as "$LK_LOCK" "wrong-s1-$LK_RUN") $(lk_kinit_as "$LK_LOCK" "wrong-s2-$LK_RUN")"
    before="$(lk_count_wait "$LK_LOCK" 2)"
    got="$(lk_s4u allowed)"
    sleep 2
    after="$(lk_count "$LK_LOCK")"
    if [ "$w" = "incorrect incorrect" ] && lk_is "$before" 2 && [ "$got" = ticket ] && lk_is "$after" 2; then
        lk_pass_read "[L1.s4u-allowed] $LK_SVC asks S4U2Self (kvno -I) for $LK_LOCK at fail_count 2 under threshold 3: a ticket that its keytab decrypts, and fail_count stays 2 (no count, no clear)"
    else
        lk_finding "[L1.s4u-allowed] 2 wrong ('$w', fail_count $before), then S4U2Self for $LK_LOCK: '$got' (want ticket); fail_count after it $after (want 2)"
    fi
    w="$(lk_kinit_as "$LK_LOCK" "wrong-s3-$LK_RUN")"
    locked="$(lk_kinit_as "$LK_LOCK" pass)"
    before="$(lk_count_wait "$LK_LOCK" 3)"
    mark="$(lk_mark)"
    got="$(lk_s4u locked)"
    rows="$(lk_one "kind = 'access_denied' AND protocol = 'kerberos' AND NOT success AND detail = 'locked out (S4U2Self by $LK_SVC@$REALM)' AND $(lk_who "$LK_LOCK")" "$mark")"
    after="$(lk_count "$LK_LOCK")"
    if [ "$w $locked" = "incorrect revoked" ] && lk_is "$before" 3 && [ "$got" = revoked ] && lk_is "$rows" 1 && lk_is "$after" 3; then
        lk_pass_read "[L1.s4u-locked] a third wrong locks $LK_LOCK (kinit revoked); S4U2Self for it is refused, 'credentials have been revoked' (18), one access_denied row 'locked out (S4U2Self by $LK_SVC@$REALM)' (protocol kerberos), fail_count stays 3"
    else
        lk_finding "[L1.s4u-locked] the third wrong '$w', then kinit '$locked' (want incorrect, revoked), fail_count $before; S4U2Self '$got' (want revoked), access_denied rows: $rows (want 1), fail_count after $after (want 3)"
    fi
    if lk_unlock "$LK_LOCK"; then
        got="$(lk_s4u unlocked)"
        if [ "$got" = ticket ]; then
            lk_pass "[L1.s4u-unlocked] after unlockUser, S4U2Self for $LK_LOCK gets a ticket again"
        else
            lk_finding "[L1.s4u-unlocked] after unlockUser, S4U2Self for $LK_LOCK gave '$got' (want ticket)"
        fi
    else
        lk_finding "[L1.s4u-unlocked] unlockUser $LK_LOCK failed: $(head -c 200 "$LK_D/last.err")"
    fi
}

lk_one_counter() {
    local mark w out rows
    mark="$(lk_mark)"
    w="$(lk_wrong3 o)"
    out="$(lk_simple "$LK_LOCK" pass)"
    rows="$(lk_one "kind = 'bind' AND protocol = 'http' AND NOT success AND detail = 'locked out' AND $(lk_who "$LK_LOCK")" "$mark")"
    if [ "$w" = "$LK_W3" ] && [ "${out%% *}" = 401 ] && lk_is "$rows" 1; then
        lk_pass_read "[L1.one-counter] 3 wrong at kinit (each 'Password incorrect'), then the right password at simple login: 401 and one 'locked out' row (kind bind, protocol http); one counter for every door"
    else
        lk_finding "[L1.one-counter] 3 wrong at kinit ('$w'), then the right password at simple login answered ${out%% *} (want 401); 'locked out' rows: $rows (want 1)"
    fi
    lk_unlock "$LK_LOCK" || lk_finding "[L1.one-counter-unlock] unlockUser $LK_LOCK failed: $(head -c 200 "$LK_D/last.err")"
}

# The browser image's own client on the gate's network: the web login and the simple login.
lk__refused_client() {
    docker rm -f -v "$LK_PEER_CTN" >/dev/null 2>&1
    (
        export BROWSER_PASS="$LK_PASS"
        timeout 180 docker run --rm --name "$LK_PEER_CTN" --network "$NET" --init --shm-size=1g \
            --user "$(id -u):$(id -g)" --entrypoint node \
            -v "$GATE_ROOT/lib/browser.mjs:/work/browser.mjs:ro" -v "$LK_D:/out" \
            -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_MODE=refused \
            -e BROWSER_URL="http://${CONTAINER}:17170" -e BROWSER_USER="$LK_LOCK" -e BROWSER_PASS \
            "$WIRE_IMAGE" /work/browser.mjs >"$LK_D/peer.out" 2>"$LK_D/peer.err"
    )
    docker rm -f -v "$LK_PEER_CTN" >/dev/null 2>&1
}

lk_peer_rows() {
    local i w=0 out mark addr simple peer web web_at bind bind_at count
    if ! docker image inspect "$WIRE_IMAGE" >/dev/null 2>&1; then
        lk_note "[L1.peer-web-login] the browser image is absent; not run"
        lk_note "[L1.peer-simple-login] the browser image is absent; not run"
        return 0
    fi
    for i in 1 2 3; do
        out="$(lk_simple "$LK_LOCK" "wrong-p$i-$LK_RUN")"
        [ "${out%% *}" = 401 ] || w=$((w + 1))
    done
    count="$(lk_count_wait "$LK_LOCK" 3)"
    mark="$(lk_mark)"
    docker rm -f "$LK_PEER_CTN" >/dev/null 2>&1
    lk_hush lk__refused_client
    docker rm -f "$LK_PEER_CTN" >/dev/null 2>&1
    addr="$(sed -n 's/^ADDR //p' "$LK_D/peer.out" | head -1)"
    simple="$(sed -n 's/^SIMPLE //p' "$LK_D/peer.out" | head -1)"
    case "$addr" in
    "" | none | *,*)
        lk_note "[L1.peer-web-login] the client printed no single address ('${addr:-nothing}', see peer.out, peer.err); not run"
        lk_note "[L1.peer-simple-login] the client printed no single address; not run"
        lk_unlock "$LK_LOCK" || lk_finding "[L1.peer-unlock] unlockUser $LK_LOCK failed: $(head -c 200 "$LK_D/last.err")"
        return 0
        ;;
    esac
    peer="peer IN ('$addr', '::ffff:$addr')"
    web="kind = 'login' AND protocol = 'http' AND NOT success AND detail = 'locked out' AND $(lk_who "$LK_LOCK")"
    bind="kind = 'bind' AND protocol = 'http' AND NOT success AND detail = 'locked out' AND $(lk_who "$LK_LOCK")"
    web_at="$(lk_one "$web AND $peer" "$mark")"
    web="$(lk_one "$web" "$mark")"
    bind_at="$(lk_one "$bind AND $peer" "$mark")"
    bind="$(lk_one "$bind" "$mark")"
    out="$(lk_count "$LK_LOCK")"
    if [ "$w" = 0 ] && lk_is "$count" 3 && grep -q '^ROW refused-web PASS' "$LK_D/peer.out" && lk_is "$web" 1 && lk_is "$web_at" 1; then
        lk_pass_read "[L1.peer-web-login] $LK_LOCK locked (3 wrong, fail_count 3); the right password at the web login page from a client at $addr on the gate's network: 'Invalid username or password', and its one 'locked out' row (kind login, protocol http) carries peer $addr"
    else
        lk_finding "[L1.peer-web-login] 3 wrong: $w not refused, fail_count $count (want 3); the page: $(grep -m1 '^ROW refused-web' "$LK_D/peer.out" || echo 'no line, see peer.err'); 'locked out' login rows $web, with peer $addr $web_at (want 1 and 1)"
    fi
    if [ "$simple" = 401 ] && lk_is "$bind" 1 && lk_is "$bind_at" 1 && lk_is "$out" 3; then
        lk_pass_read "[L1.peer-simple-login] the same client, the right password at /auth/simple/login: 401, and its one 'locked out' row (kind bind, protocol http) carries peer $addr; fail_count stays 3"
    else
        lk_finding "[L1.peer-simple-login] the right password at /auth/simple/login from $addr answered ${simple:-nothing} (want 401); 'locked out' bind rows $bind, with peer $addr $bind_at (want 1 and 1); fail_count $out (want 3)"
    fi
    lk_unlock "$LK_LOCK" || lk_finding "[L1.peer-unlock] unlockUser $LK_LOCK failed: $(head -c 200 "$LK_D/last.err")"
}

lk_pg() { gexec_in "$PG_CONTAINER" psql -U klldap -d klldap -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
lk_pg_held() { lk_pg "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE c.relname = 'ou_policies' AND l.mode = 'AccessExclusiveLock' AND l.granted"; }
lk_ms() { date +%s%3N; }
lk_set_pw() { lk_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$(lk_pw_vars "$1")" >/dev/null; }
LK_HELD_MS=3000

# Postgres only: while ou_policies is held, a user is made, then a password change is refused
# within the bound; after the release both kinds answer.
lk_held_policy() {
    local hold held=0 mark t0 made=0 made_ms=0 refused=0 set_ms=0 why="" still="" rows after=0 hers=0 login
    local unread="the password policy could not be read; try again"
    if [ "$GATE_DB" != postgres ]; then
        lk_note "[L1.held-policy-answers] the gate holds ou_policies only on postgres (a table lock it can see); on $GATE_DB not run"
        return 0
    fi
    mark="$(lk_mark)"
    timeout 120 docker exec -e PGAPPNAME=lkhold "$PG_CONTAINER" psql -U klldap -d klldap -c \
        "BEGIN; LOCK TABLE ou_policies IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(60); COMMIT;" >"$LK_D/hold.out" 2>&1 &
    hold=$!
    for _ in $(seq 1 20); do
        [ "$(lk_pg_held)" = 1 ] && held=1 && break
        sleep 0.5
    done
    if [ "$held" = 1 ]; then
        LK_HELD_TRIED=1
        t0="$(lk_ms)"
        lk_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$LK_HELD"'", "email": "'"$LK_HELD"'@gate.test"}}' >/dev/null && made=1
        made_ms=$(($(lk_ms) - t0))
        t0="$(lk_ms)"
        if ! lk_set_pw "$LK_USER" && grep -qF "$unread" "$LK_D/last.err"; then
            refused=1
        fi
        set_ms=$(($(lk_ms) - t0))
        why="$(head -c 200 "$LK_D/last.err")"
        still="$(lk_pg_held)"
    fi
    lk_pg "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'lkhold'" >/dev/null
    wait "$hold" 2>/dev/null
    if [ "$held" = 0 ]; then
        lk_note "[L1.held-policy-answers] the gate could not hold ou_policies (see hold.out); not run"
        return 0
    fi
    rows="$(lk_one "kind = 'password_change' AND NOT success AND detail = '$unread' AND $(lk_who "$LK_USER")" "$mark")"
    lk_set_pw "$LK_USER" && after=1
    lk_set_pw "$LK_HELD" && hers=1
    login="$(lk_simple "$LK_HELD" pass)"
    if [ "$made $refused $still" = "1 1 1" ] && [ "$made_ms" -le "$LK_HELD_MS" ] && [ "$set_ms" -le "$LK_HELD_MS" ] &&
        lk_is "$rows" 1 && [ "$after $hers" = "1 1" ] && [ "$login" = "200 token" ]; then
        lk_pass_read "[L1.held-policy-answers] postgres, ou_policies held ACCESS EXCLUSIVE: createUser $LK_HELD answered in $made_ms ms; setUserPassword for $LK_USER was refused '$unread' in $set_ms ms (one password_change row), the table still held; after the release setUserPassword answered for $LK_USER and $LK_HELD, and $LK_HELD signs in at /auth/simple/login"
    else
        lk_finding "[L1.held-policy-answers] during the hold: createUser $LK_HELD made $made in $made_ms ms, setUserPassword for $LK_USER refused as unreadable $refused in $set_ms ms (want 1 and 1, each within $LK_HELD_MS ms; it answered '$why'), still held '$still' (want 1), password_change rows $rows (want 1); after the release setUserPassword $after for $LK_USER and $hers for $LK_HELD (want 1 and 1), the simple login '$login' (want 200 token)"
    fi
}

# A ticket issued before the lock: its renewal and a service ticket on it are refused.
lk__tgt() {
    gexec sh -c 'printf "%s\n" "$1" | KRB5CCNAME="$2" kinit -r 1d "$0"' "$LK_LOCK@$REALM" "$LK_PASS" "$LK_TCC" \
        >"$LK_D/tgs-kinit.log" 2>&1
}
lk_tgs_answer() {
    local label="$1"
    shift
    "$@" >"$LK_D/tgs-$label.log" 2>&1 && echo ok && return
    grep -qi 'revoked' "$LK_D/tgs-$label.log" && echo revoked || echo other
}
lk_tgs_locked() {
    local w svc renew mark rows count
    if ! lk_hush lk__tgt; then
        lk_fail "[L1.tgs-locked] no renewable ticket for $LK_LOCK before the lock (see tgs-kinit.log)"
        return 0
    fi
    w="$(lk_wrong3 g)"
    mark="$(lk_mark)"
    svc="$(lk_tgs_answer service gexec env KRB5CCNAME="$LK_TCC" kvno --no-store "$LK_SVC@$REALM")"
    renew="$(lk_tgs_answer renewal gexec env KRB5CCNAME="$LK_TCC" kinit -R)"
    rows="$(lk_one "kind = 'access_denied' AND protocol = 'kerberos' AND NOT success AND detail = 'locked out' AND $(lk_who "$LK_LOCK")" "$mark")"
    count="$(lk_count "$LK_LOCK")"
    if [ "$w $svc $renew" = "$LK_W3 revoked revoked" ] && { [ "$LK_READS" = 0 ] || [ "${rows:-0}" -ge 1 ]; } && lk_is "$count" 3; then
        lk_pass_read "[L1.tgs-locked] a renewable ticket for $LK_LOCK, then 3 wrong lock it: a service ticket on that ticket (kvno) and its renewal (kinit -R) are each 'credentials have been revoked', with access_denied 'locked out' rows ($rows, one each unless a flood coalesces them); fail_count stays 3"
    else
        lk_finding "[L1.tgs-locked] 3 wrong '$w', then the service ticket '$svc' and the renewal '$renew' on a ticket from before the lock (want revoked, revoked); access_denied 'locked out' rows: $rows; fail_count $count (want 3)"
    fi
    gexec rm -f "$LK_TCC" >/dev/null 2>&1
    lk_unlock "$LK_LOCK" || lk_finding "[L1.tgs-unlock] unlockUser $LK_LOCK failed: $(head -c 200 "$LK_D/last.err")"
}

lk__page() {
    docker rm -f -v "$LK_PEER_CTN" >/dev/null 2>&1
    (
        export BROWSER_PASS="$3" BROWSER_NEW_PASS="${4:-}"
        timeout 180 docker run --rm --name "$LK_PEER_CTN" --network "$NET" --init --shm-size=1g \
            --user "$(id -u):$(id -g)" --entrypoint node \
            -v "$GATE_ROOT/lib/browser.mjs:/work/browser.mjs:ro" -v "$LK_D:/out" \
            -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_MODE="$1" \
            -e BROWSER_URL="http://${CONTAINER}:17170" -e BROWSER_USER="$2" -e BROWSER_PASS -e BROWSER_NEW_PASS \
            "$WIRE_IMAGE" /work/browser.mjs >"$LK_D/page-$1.out" 2>"$LK_D/page-$1.err"
    )
    docker rm -f -v "$LK_PEER_CTN" >/dev/null 2>&1
}

# Past a start's 10 seconds, its fold and the writer's batch: an unfinished start shows by then.
lk_settle() {
    sleep 14
}
# lk_page_user <user> <password> [ou]: in the threshold-1 OU unless another is named.
lk_page_user() {
    LK_PAGE_USERS+=("$1")
    lk_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$1"'", "email": "'"$1"'@gate.test"}}' >/dev/null &&
        lk_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
            "$(LKU="$1" LKP="$2" python3 -c 'import json,os; print(json.dumps({"id": os.environ["LKU"], "pw": os.environ["LKP"]}))')" >/dev/null &&
        lk_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$1"'"], "ou": "'"${3:-$LK_ONE_OU}"'"}' >/dev/null
}

# The pages finish every start they make: at threshold 1 they never lock their own user.
lk_pages_threshold_one() {
    local colon="${LK_RUN}-c" change="${LK_RUN}-p" colon_pass change_pass new_pass rows mark
    if ! docker image inspect "$WIRE_IMAGE" >/dev/null 2>&1; then
        lk_note "[L1.page-login-colon] the browser image is absent; not run"
        lk_note "[L1.page-change] the browser image is absent; not run"
        lk_note "[L1.page-code-retry] the browser image is absent; not run"
        return 0
    fi
    colon_pass="$(python3 -c 'import secrets; print("Lc" + secrets.token_hex(8) + "!:123456")')"
    change_pass="$(python3 -c 'import secrets; print("Lp" + secrets.token_hex(8) + "!:654321")')"
    new_pass="$(python3 -c 'import secrets; print("Ln" + secrets.token_hex(10) + "!")')"
    lk_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$LK_ONE_OU"'"}' >/dev/null &&
        LK_ONE_POLICY="$(lk_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
            '{"n": "'"$LK_RUN"' one", "i": [{"key": "lockout-threshold", "value": "1"}, {"key": "lockout-duration-seconds", "value": "0"}]}' |
            json_get createPolicy.id 2>/dev/null)" && [ -n "$LK_ONE_POLICY" ] &&
        lk_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' '{"o": "'"$LK_ONE_OU"'", "p": '"$LK_ONE_POLICY"'}' >/dev/null &&
        lk_hush lk_page_user "$colon" "$colon_pass" && lk_hush lk_page_user "$change" "$change_pass" || {
        lk_fail "[L1.page-setup] OU $LK_ONE_OU at threshold 1 and its two users could not be made: $(head -c 200 "$LK_D/last.err")"
        return 0
    }
    mark="$(lk_mark)"
    lk_hush lk__page login "$colon" "$colon_pass"
    lk_settle
    rows="$(log_rows "detail LIKE 'locked out%' AND $(lk_who "$colon") AND id > ${mark:-0}")"
    if grep -q '^ROW user-login PASS' "$LK_D/page-login.out" && lk_is "$(lk_count_wait "$colon" 0)" 0 && lk_is "$rows" 0; then
        lk_pass_read "[L1.page-login-colon] threshold 1: the login page signs in $colon, whose password ends in ':' and six digits, with one start it finishes; fail_count 0 and no 'locked out' row"
    else
        lk_finding "[L1.page-login-colon] threshold 1, a password ending in ':' and six digits: the page answered '$(grep -m1 '^ROW' "$LK_D/page-login.out" || echo 'no line, see page-login.err')'; fail_count $(lk_count "$colon"); 'locked out' rows $rows (want signed in, 0, 0)"
    fi
    mark="$(lk_mark)"
    lk_hush lk__page change "$change" "$change_pass" "$new_pass"
    lk_settle
    rows="$(log_rows "detail LIKE 'locked out%' AND $(lk_who "$change") AND id > ${mark:-0}")"
    if grep -q '^ROW user-login PASS' "$LK_D/page-change.out" && lk_wire_whole "$LK_D/page-change.out" change &&
        grep -q '^WIRE change starts=1 finishes=1 ' "$LK_D/page-change.out" &&
        lk_is "$(lk_count "$change")" 0 && lk_is "$rows" 0; then
        lk_pass_read "[L1.page-change] threshold 1: $change, whose password ends in ':' and six digits, signs in and changes it on the change page submitted twice in one tick: one start, finished, read past the fold; fail_count 0, no 'locked out' row"
    else
        lk_finding "[L1.page-change] threshold 1: the change page answered '$(grep '^ROW\|^WIRE change ' "$LK_D/page-change.out" | tr '\n' ' ' || true)'; fail_count $(lk_count "$change"); 'locked out' rows $rows (want both PASS, starts=1 finishes=1, 0, 0)"
    fi
    lk_pages_enrol_reset
    lk_page_code_retry
}

# Threshold 3: a wrong code on the code step counts 1; the next Verify starts again with the
# right code, signs in and clears the count. The page waits while the gate reads the count.
lk_page_code_retry() {
    local user="${LK_RUN}-r" out="$LK_D/page-code-retry.out" mark pid mid count wrong signed
    lk_hush lk_page_user "$user" "$LK_PASS" "$LK_OU" || {
        lk_fail "[L1.page-code-retry] $user could not be made in $LK_OU: $(head -c 200 "$LK_D/last.err")"
        return 0
    }
    rm -f "$LK_D/code-retry.go" "$out"
    mark="$(lk_mark)"
    lk_hush lk__page code-retry "$user" "$LK_PASS" &
    pid=$!
    for _ in $(seq 1 150); do
        grep -q '^ROW retry-wrong \|^ROW [a-z-]* FAIL' "$out" 2>/dev/null && break
        sleep 1
    done
    mid="$(lk_count_wait "$user" 1)"
    touch "$LK_D/code-retry.go"
    wait "$pid"
    count="$(lk_count_wait "$user" 0)"
    wrong="$(lk_one "kind = 'login' AND NOT success AND detail = 'invalid totp' AND $(lk_who "$user")" "$mark")"
    signed="$(lk_one "kind = 'login' AND success AND detail = 'totp' AND $(lk_who "$user")" "$mark")"
    if lk_wire_whole "$out" retry-wrong && lk_wire_whole "$out" retry-right &&
        grep -q '^WIRE retry-right starts=1 finishes=1 sessionless=0 proof-asked=0 codes=1 statuses=200 ' "$out" &&
        lk_is "$mid" 1 && lk_is "$count" 0 && lk_is "$wrong" 1 && lk_is "$signed" 1; then
        lk_pass_read "[L1.page-code-retry] threshold 3: the enrolled $user types a wrong code on the code step (count 1, one 'invalid totp' row), then the right one: the second Verify sends a new start and its finish, signs in (one 'totp' row) and the count is 0"
    else
        lk_finding "[L1.page-code-retry] threshold 3: $(grep '^WIRE retry-\(wrong\|right\) \|^ROW retry-' "$out" | tr '\n' ' ' || true); count after the wrong code $mid (want 1), after the right one $count (want 0); 'invalid totp' rows $wrong, 'totp' rows $signed (want 1, 1)"
    fi
}

# lk_wire_whole <out> <row>: the row passed and finished every login start it made.
lk_wire_whole() {
    local line starts finishes
    grep -q "^ROW $2 PASS" "$1" || return 1
    line="$(grep -m1 "^WIRE $2 " "$1")"
    starts="$(sed -n 's/.* starts=\([0-9]*\).*/\1/p' <<<"$line")"
    finishes="$(sed -n 's/.* finishes=\([0-9]*\).*/\1/p' <<<"$line")"
    [ -n "$starts" ] && [ "$starts" -gt 0 ] && [ "$starts" = "$finishes" ]
}

# The enrolment and reset pages at threshold 1, with the sign-in and change between them.
lk_pages_enrol_reset() {
    local user="${LK_RUN}-e" new_pass out="$LK_D/page-pages-one.out" mark rows count
    new_pass="$(python3 -c 'import secrets; print("Lr" + secrets.token_hex(10) + "!")')"
    lk_hush lk_page_user "$user" "$LK_PASS" || {
        lk_fail "[L1.page-enrol] $user could not be made in $LK_ONE_OU: $(head -c 200 "$LK_D/last.err")"
        return 0
    }
    mark="$(lk_mark)"
    lk_hush lk__page pages-one "$user" "$LK_PASS" "$new_pass"
    lk_settle
    rows="$(log_rows "detail LIKE 'locked out%' AND $(lk_who "$user") AND id > ${mark:-0}")"
    count="$(lk_count "$user")"
    if lk_wire_whole "$out" one-login && lk_wire_whole "$out" one-enrol && lk_is "$rows" 0; then
        lk_pass_read "[L1.page-enrol] threshold 1: $user signs in and enrols a second factor on the enrolment page; every login start the pages made was finished, no 'locked out' row"
    else
        lk_finding "[L1.page-enrol] threshold 1: $(grep '^WIRE one-login \|^WIRE one-enrol \|^ROW one-login\|^ROW one-enrol' "$out" | tr '\n' ' ' || true); 'locked out' rows $rows (want both rows PASS, starts = finishes, 0)"
    fi
    if lk_wire_whole "$out" one-signin && lk_wire_whole "$out" one-change && lk_wire_whole "$out" one-reset &&
        lk_is "$rows" 0 && lk_is "$count" 0; then
        lk_pass_read "[L1.page-reset] threshold 1: the enrolled $user signs in in two steps, changes the password and resets its own second factor on the pages; every start finished, fail_count 0, no 'locked out' row"
    else
        lk_finding "[L1.page-reset] threshold 1: $(grep '^WIRE one-\(signin\|change\|reset\) \|^ROW one-\(signin\|change\|reset\)' "$out" | tr '\n' ' ' || true); fail_count $count; 'locked out' rows $rows (want every row PASS with starts = finishes, 0, 0)"
    fi
}

# As the server's own user, so a SQLite side file the tool makes keeps the server's owner.
lk_tool() {
    local u args=()
    u="$(uid_of_comm lldap)"
    [ -n "$u" ] && args=(-u "$u")
    t docker exec "${args[@]}" "$CONTAINER" /app/lldap unlock --config-file /data/lldap_config.toml "$1"
}

lk_tool_unlock() {
    local w locked mark rc got="" waited=0 rows
    w="$(lk_wrong3 h)"
    locked="$(lk_kinit_as "$LK_LOCK" pass)"
    mark="$(lk_mark)"
    lk_tool "$LK_LOCK" >"$LK_D/tool-unlock.out" 2>&1
    rc=$?
    if [ "$w $locked" != "$LK_W3 revoked" ]; then
        lk_finding "[L1.tool-unlock] $LK_LOCK was not locked before the tool: 3 wrong gave '$w', the right password '$locked'"
    elif [ "$rc" != 0 ] || ! grep -qF "Unlocked $LK_LOCK" "$LK_D/tool-unlock.out"; then
        lk_finding "[L1.tool-unlock] lldap unlock $LK_LOCK exited $rc: '$(head -c 200 "$LK_D/tool-unlock.out")' (want exit 0 and 'Unlocked $LK_LOCK')"
    else
        while [ "$waited" -le 45 ]; do
            got="$(lk_kinit_as "$LK_LOCK" pass)"
            [ "$got" = ok ] && break
            sleep 5
            waited=$((waited + 5))
        done
        rows="$(lk_one "$(lk_unlock_row 'actor IS NULL' system 'lldap unlock')" "$mark")"
        if [ "$got" = ok ] && lk_is "$rows" 1; then
            lk_pass_read "[L1.tool-unlock] $LK_LOCK locked, then lldap unlock in the container (exit 0, 'Unlocked $LK_LOCK'): the right password gets a ticket after ${waited} s (within 45 s), one account_unlock 'lldap unlock' (protocol system, no actor)"
        else
            lk_finding "[L1.tool-unlock] after lldap unlock the right password gave '$got' for ${waited} s (want ok within 45 s); account_unlock 'lldap unlock' rows: $rows (want 1)"
        fi
    fi
    lk_tool "nosuch-$LK_RUN" >"$LK_D/tool-unknown.out" 2>&1
    rc=$?
    if [ "$rc" != 0 ]; then
        lk_pass "[L1.tool-unlock-unknown] lldap unlock of a name that is no user exits $rc"
    else
        lk_finding "[L1.tool-unlock-unknown] lldap unlock of a name that is no user exited 0: '$(head -c 200 "$LK_D/tool-unknown.out")'"
    fi
}

lk_cleanup() {
    local u out gone=0 deleted=0 svc=0 left=""
    docker rm -fv "$LK_ONE" "$LK_TWO" >/dev/null 2>&1
    docker volume rm "$LK_ONE_VOL" "$LK_TWO_VOL" >/dev/null 2>&1
    lk_policy_gone && gone=1
    lk_unlock "$LK_LOCK" >/dev/null 2>&1
    if [ "$LK_HELD_TRIED" = 1 ]; then
        lk_pg "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'lkhold'" >/dev/null
        lk_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$LK_HELD"'"}' >/dev/null
    fi
    for u in "${LK_PAGE_USERS[@]}"; do
        lk_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}' >/dev/null
    done
    if [ -n "$LK_ONE_POLICY" ]; then
        lk_gql 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' '{"o": "'"$LK_ONE_OU"'"}' >/dev/null
        lk_gql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$LK_ONE_POLICY"'}' >/dev/null
    fi
    lk_gql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$LK_ONE_OU"'"}' >/dev/null
    for u in "$LK_USER" "$LK_MFA" "$LK_LOCK"; do
        out="$(lk_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}')" &&
            [ "$(json_get deleteUser.ok <<<"$out" 2>/dev/null)" = True ] && deleted=$((deleted + 1))
    done
    lk_gql 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' '{"o": "'"$LK_OU"'"}' >/dev/null
    [ -n "$LK_POLICY" ] && lk_gql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$LK_POLICY"'}' >/dev/null
    lk_gql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$LK_OU"'"}' >/dev/null
    kadmin_q "delprinc -force $LK_SVC" >/dev/null 2>&1
    kadmin_q "getprinc $LK_SVC" >"$LK_D/getprinc-svc.txt" 2>&1
    grep -q "Principal does not exist" "$LK_D/getprinc-svc.txt" && svc=1
    gexec rm -f "$LK_KT" "$LK_SCC" >/dev/null 2>&1
    out="$(lk_gql '{ policies { name } listOus ouPolicyStates { ou } users { id } }' '{}')" && ! grep -q "$LK_RUN" <<<"$out" && left=none
    LK_SECRET=""
    [ "$LK_MADE" = 1 ] || return 0
    if [ "$gone" = 1 ] && [ "$deleted" = 3 ] && [ "$svc" = 1 ] && [ "$left" = none ]; then
        lk_pass "[L1.cleanup] the Kerberos policy $LK_POL and the service $LK_SVC are gone (getpol, getprinc: does not exist), the three users are deleted, and no policy, OU or user named $LK_RUN is left"
    else
        lk_fail "[L1.cleanup] policy gone: $gone (getpol: $(tail -n 1 "$LK_D/getpol.txt" | cut -c1-120)); users deleted: $deleted of 3; service gone: $svc; leftovers named $LK_RUN: ${left:-some, or unread}"
    fi
}

if lk_setup; then
    LK_MADE=1
    lk_fifty ldap-bind
    lk_fifty simple-login
    lk_threshold ldap-bind
    lk_threshold simple-login
    lk_peer_rows
    lk_pages_threshold_one
    lk_totp && lk_kerberos
    lk_held_policy
fi
lk_cleanup
note "lockout-facts FINDING ids: ${LK_FIND[*]:-none}"
note "lockout-facts: $LK_N rows, $LK_P pass, $LK_F FINDING, $LK_K NOTE, $LK_X FAIL"
note "lockout-facts: a correct product gives 34 rows, 0 FINDING, 0 FAIL: 34 pass on postgres; 31 pass and 3 NOTE ([L1.totp-two-servers], [L1.totp-used-two-servers], [L1.held-policy-answers]) on sqlite"
