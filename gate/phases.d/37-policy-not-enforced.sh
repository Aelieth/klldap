# shellcheck shell=bash
# Phase: each policy item set and shown effective, then simple login, LDAP bind, kinit; lockout-threshold locks, enable-mfa=always is overridden here
# by the server's explicit LLDAP_ENABLE_MFA and refuses the binds on a server without it. login-hours and allowed-networks refuse, on the user's OU
# only; inactivity-days admits a user who is not idle. A refusing policy on the root is undone with lldap policy-unlink.

# Passwords and tokens travel in this phase's variables and helpers: nothing of it is traced. The
# tracing state is put back at the end, for the phases after this one.
NE_XT=0
case $- in *x*) NE_XT=1 ;; esac
{ set +x; } 2>/dev/null
NE_D="$(phase_dir)"
NE_N=0 NE_P=0 NE_F=0 NE_K=0 NE_X=0 NE_FIND=()
NE_RUN="ne$(date +%H%M%S)"
NE_OU="${NE_RUN}ou" NE_USER="${NE_RUN}-u" NE_POLICY=""
NE_ROOT_POLICY="" NE_ROOT_HELD=0 NE_WAITED=0 NE_POLLED_401=0 NE_STUCK=0
NE_HOURS="policy: login-hours (outside login hours)"
NE_PASS="$(python3 -c 'import secrets; print("Ne" + secrets.token_hex(10) + "!")')"
NE_SIDE="$CONTAINER-ou37" NE_SIDE_VOL="klldap-gate-ou37-$RUNID"
EXTRA_CONTAINERS+=("$NE_SIDE")
EXTRA_VOLUMES+=("$NE_SIDE_VOL")

ne_pass() { NE_N=$((NE_N + 1)) NE_P=$((NE_P + 1)); p_ok "$1"; }
ne_bad() { NE_N=$((NE_N + 1)) NE_X=$((NE_X + 1)); p_bad "$1"; }
ne_note() { NE_N=$((NE_N + 1)) NE_K=$((NE_K + 1)); note "[NOTE] ${PHASE}: $1"; }
ne_finding() { NE_N=$((NE_N + 1)) NE_F=$((NE_F + 1)) NE_FIND+=("$1"); note "[FINDING] ${PHASE}: $1"; }
ne_gql() { graphql "$1" "$2" 2>"$NE_D/last.err"; }

ne_simple() {
    LOGIN_URL="$(http_url)/auth/simple/login" LOGIN_USER="$1" LOGIN_PASS="$2" t python3 - <<'PY'
import json, os, urllib.error, urllib.request
req = urllib.request.Request(os.environ["LOGIN_URL"], headers={"Content-Type": "application/json"},
    data=json.dumps({"username": os.environ["LOGIN_USER"], "password": os.environ["LOGIN_PASS"]}).encode())
try:
    print(200 if json.load(urllib.request.urlopen(req)).get("token") else 0)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print(0)
PY
}
ne_bind() {
    t ldapwhoami -x -H "$(ldap_url)" -D "$NE_DN" -w "$1" >"$NE_D/bind.out" 2>&1
    echo $?
}
ne_kinit() {
    kinit_pw "$NE_USER@$REALM" "$1" >"$NE_D/kinit.out" 2>&1 && echo ok && return
    if grep -q "credentials have been revoked" "$NE_D/kinit.out"; then echo revoked; elif grep -q "Password incorrect" "$NE_D/kinit.out"; then echo incorrect; else echo other; fi
}
ne_right() {
    case "$1" in
    simple-login) [ "$(ne_simple "$NE_USER" "$NE_PASS")" = 200 ] ;;
    ldap-bind) [ "$(ne_bind "$NE_PASS")" = 0 ] ;;
    kinit) [ "$(ne_kinit "$NE_PASS")" = ok ] ;;
    esac
}
ne_wrong_refused() {
    case "$1" in
    simple-login) [ "$(ne_simple "$NE_USER" "$2")" = 401 ] ;;
    ldap-bind) [ "$(ne_bind "$2")" = 49 ] ;;
    kinit) [ "$(ne_kinit "$2")" = "${3:-incorrect}" ] ;;
    esac
}
ne_locked() {
    case "$1" in
    simple-login) [ "$(ne_simple "$NE_USER" "$NE_PASS")" = 401 ] ;;
    ldap-bind) [ "$(ne_bind "$NE_PASS")" = 49 ] ;;
    kinit) [ "$(ne_kinit "$NE_PASS")" = revoked ] ;;
    esac
}
ne_unlock() {
    local out
    out="$(ne_gql 'mutation($u: String!) { unlockUser(userId: $u) { ok } }' '{"u": "'"$NE_USER"'"}')" &&
        [ "$(json_get unlockUser.ok <<<"$out" 2>/dev/null)" = True ]
}

# The threshold sits on the test OU alone: the root takes back its own policy meanwhile.
ne_root() {
    local p="${NE_ROOT_BEFORE:-}"
    [ "$1" = ours ] && p="$NE_POLICY"
    if [ -n "$p" ]; then
        ne_gql 'mutation($p: Int!) { setOuPolicy(ou: "", policyId: $p) { ok } }' '{"p": '"$p"'}' >/dev/null
    else
        ne_gql 'mutation { clearOuPolicy(ou: "") { ok } }' '{}' >/dev/null
    fi
}

# ne_answer <door>: the right password's answer: the HTTP status, the bind's exit, or kinit's word.
ne_answer() {
    case "$1" in
    simple-login) ne_simple "$NE_USER" "$NE_PASS" ;;
    ldap-bind) ne_bind "$NE_PASS" ;;
    kinit) ne_kinit "$NE_PASS" ;;
    esac
}
ne_want() {
    case "$1:$2" in
    simple-login:out) echo 401 ;;
    ldap-bind:out) echo 49 ;;
    kinit:out) echo revoked ;;
    simple-login:in) echo 200 ;;
    ldap-bind:in) echo 0 ;;
    kinit:in) echo ok ;;
    esac
}

# The kind and protocol of a refusal's one row at each door.
ne_row_of() {
    case "$1" in
    simple-login) echo "BIND HTTP" ;;
    ldap-bind) echo "BIND LDAP" ;;
    kinit) echo "LOGIN KERBEROS" ;;
    esac
}

# ne_door ID CASE DOOR in|out [DETAIL]: the right password is admitted (in) or refused as a wrong
# one (out); with DETAIL, the refusal's one row must name that reason.
ne_door() {
    local id="$1" case_="$2" door="$3" detail="${5:-}" want got said=refused mark="" kind proto
    want="$(ne_want "$door" "$4")"
    [ "$4" = in ] && said=admitted
    [ -n "$detail" ] && mark="$(log_mark)"
    got="$(ne_answer "$door")"
    if [ "$got" != "$want" ]; then
        ne_bad "[$id] $case_, $door with the right password answered '$got' (want $said, $want)"
    elif [ -z "$detail" ]; then
        ne_pass "[$id] $case_, $door with the right password: $said ($want)"
    else
        read -r kind proto <<<"$(ne_row_of "$door")"
        if fail_once "$kind" "$NE_USER" "$detail" "$mark" "$proto"; then
            ne_pass "[$id] $case_, $door with the right password: $said ($want), one $kind row (protocol $proto) '$detail'"
        else
            ne_bad "[$id] $case_, $door with the right password: $said ($want), but $FAIL_WHY"
        fi
    fi
}

# ne_case ITEM VALUE: the policy holds only ITEM=VALUE; the row fails unless it is effective on the user's OU.
ne_case() {
    local got
    ne_gql 'mutation($p: Int!, $i: [PolicyItemInput!]) { updatePolicy(policyId: $p, items: $i) { ok } }' \
        '{"p": '"$NE_POLICY"', "i": [{"key": "'"$1"'", "value": "'"$2"'"}]}' >/dev/null || {
        ne_finding "[P2.case-$1] $1=$2 could not be set: $(cat "$NE_D/last.err")"
        return 1
    }
    got="$(ne_gql 'query($o: String!) { effectivePolicyItems(ou: $o) { key value sourceOu } }' '{"o": "'"$NE_OU"'"}' |
        NEK="$1" python3 -c '
import json, os, sys
items = json.load(sys.stdin)["effectivePolicyItems"]
hit = [i for i in items if i["key"] == os.environ["NEK"]]
print(hit[0]["value"] + "|" + (hit[0]["sourceOu"] or "") if hit else "<missing>")' 2>/dev/null)"
    if [ "$got" = "$2|${NE_OU,,}" ]; then
        ne_pass "[P2.effective-$1] $1=$2 is effective on the user's OU ${NE_OU,,}"
    else
        ne_finding "[P2.effective-$1] $1=$2 is not shown effective on ${NE_OU,,} (got '$got'); the door rows below prove nothing"
        return 1
    fi
}

ne_setup() {
    local ou
    NE_ROOT_BEFORE="$(ne_gql '{ ouPolicyStates { ou policyId } }' '{}' | python3 -c '
import json, sys
print(next((str(x["policyId"] or "") for x in json.load(sys.stdin)["ouPolicyStates"] if x["ou"] == ""), ""))')" || {
        p_bad "setup: ouPolicyStates could not be read"
        return 1
    }
    ne_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$NE_OU"'"}' >/dev/null &&
        ne_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$NE_USER"'", "email": "'"$NE_USER"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' >/dev/null &&
        NE_VARS="$(NEU="$NE_USER" NEP="$NE_PASS" python3 -c 'import json,os; print(json.dumps({"id": os.environ["NEU"], "pw": os.environ["NEP"]}))')" &&
        ne_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$NE_VARS" >/dev/null &&
        ne_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$NE_USER"'"], "ou": "'"$NE_OU"'"}' >/dev/null || {
        p_bad "setup failed: $(cat "$NE_D/last.err")"
        return 1
    }
    unset NE_VARS
    ou="$(ne_gql 'query($u: String!) { user(userId: $u) { ou } }' '{"u": "'"$NE_USER"'"}' | json_get user.ou 2>/dev/null)"
    [ "${ou,,}" = "${NE_OU,,}" ] || {
        p_bad "setup: $NE_USER is in OU '$ou', not ${NE_OU,,}"
        return 1
    }
    NE_DN="$(lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$NE_USER)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1)"
    [ -n "$NE_DN" ] || {
        p_bad "setup: no DN found for $NE_USER"
        return 1
    }
    NE_POLICY="$(ne_gql 'mutation($n: String!) { createPolicy(name: $n) { id } }' '{"n": "'"$NE_RUN"' pinned"}' | json_get createPolicy.id)"
    [ -n "$NE_POLICY" ] &&
        ne_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' '{"o": "'"$NE_OU"'", "p": '"$NE_POLICY"'}' >/dev/null &&
        ne_gql 'mutation($p: Int!) { setOuPolicy(ou: "", policyId: $p) { ok } }' '{"p": '"$NE_POLICY"'}' >/dev/null || {
        p_bad "setup: the policy could not be attached: $(cat "$NE_D/last.err")"
        return 1
    }
    for door in simple-login ldap-bind kinit; do
        ne_right "$door" || {
            p_bad "setup: $door does not work for $NE_USER even with an empty policy"
            return 1
        }
    done
}

# shellcheck disable=SC2016
ne_side_setup() {
    local id
    ne_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$NE_OU"'"}' >/dev/null &&
        ne_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$NE_USER"'", "email": "'"$NE_USER"'@gate.test"}}' >/dev/null &&
        NE_VARS="$(NEU="$NE_USER" NEP="$NE_PASS" python3 -c 'import json,os; print(json.dumps({"id": os.environ["NEU"], "pw": os.environ["NEP"]}))')" &&
        ne_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$NE_VARS" >/dev/null &&
        ne_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$NE_USER"'"], "ou": "'"$NE_OU"'"}' >/dev/null || return 1
    unset NE_VARS
    NE_DN="$(lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$NE_USER)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1)"
    [ -n "$NE_DN" ] && ne_right simple-login && ne_right ldap-bind || return 1
    id="$(ne_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
        '{"n": "'"$NE_RUN"' side", "i": [{"key": "enable-mfa", "value": "always"}]}' | json_get createPolicy.id)" &&
        [ -n "$id" ] || return 1
    ne_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' \
        '{"o": "'"$NE_OU"'", "p": '"$id"'}' >/dev/null && return 0
    graphql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$id"'}' >/dev/null 2>&1 || true
    return 1
}

# P2.1 turned round on a server that sets no LLDAP_ENABLE_MFA, so the OU's enable-mfa decides.
ne_side() {
    local ports main_dn="$NE_DN" door
    if ! ports="$(side_up "$NE_SIDE" "$NE_SIDE_VOL" 2>"$NE_D/side.err")"; then
        p_bad "[P2.1-side] the server without LLDAP_ENABLE_MFA did not become healthy (see side.err, side.log)"
        side_down "$NE_SIDE" "$NE_SIDE_VOL" "$NE_D/side.log"
        return
    fi
    # shellcheck disable=SC2086
    side_use $ports
    if [ -z "$TOKEN" ] || ! ne_side_setup; then
        p_bad "[P2.1-side] setup on $NE_SIDE failed: $(head -c 200 "$NE_D/last.err")"
    else
        for door in simple-login ldap-bind; do
            if ne_enrol_refused "$door"; then
                ne_pass "[P2.1-$door] enable-mfa=always on the user's OU, no server-wide value: $door with the right password is refused until the user enrols a second factor (HTTP 401, LDAP 49 'MFA enrollment required'); control: allowed before the OU set it"
            else
                ne_bad "[P2.1-$door] enable-mfa=always on the user's OU, no server-wide value: $door was not refused as 'MFA enrollment required' (see simple.out, bind.out)"
            fi
        done
    fi
    side_back
    NE_DN="$main_dn"
    side_down "$NE_SIDE" "$NE_SIDE_VOL" "$NE_D/side.log"
}

ne_enrol_refused() {
    case "$1" in
    simple-login)
        ! gate_login "$NE_USER" "$NE_PASS" >"$NE_D/simple.out" 2>&1 &&
            grep -q "HTTP 401" "$NE_D/simple.out" && grep -q "MFA enrollment required" "$NE_D/simple.out"
        ;;
    ldap-bind) [ "$(ne_bind "$NE_PASS")" = 49 ] && grep -q "MFA enrollment required" "$NE_D/bind.out" ;;
    esac
}

ne_today() {
    local day i bad want
    ne_case enable-mfa always && {
        for door in simple-login ldap-bind; do
            if ne_right "$door"; then
                ne_pass "[P2.1-main-$door] enable-mfa=always on the user's OU, overridden by the main server's explicit LLDAP_ENABLE_MFA=true: $door with the password alone is allowed, as for an unenrolled user under 'enabled'"
            else
                ne_bad "[P2.1-main-$door] enable-mfa=always on the user's OU: $door was refused although the main server's explicit LLDAP_ENABLE_MFA=true overrides the OUs"
            fi
        done
        if ne_right kinit; then
            ne_pass "[P2.1-kinit] enable-mfa=always on the user's OU, overridden by the main server's explicit LLDAP_ENABLE_MFA=true, the user not enrolled: the KDC asks no fresh proof, kinit with the right password is allowed (a user who must give a factor needs one: phase 88)"
        else
            ne_bad "[P2.1-kinit] the user is not enrolled under the main server's explicit LLDAP_ENABLE_MFA=true, so the KDC asks no proof, yet kinit with the right password was refused (see kinit.out)"
        fi
    }
    ne_side
    if ! ne_root before; then
        ne_bad "[P2.root-before] the root could not take back its own policy, so P2.2 to P2.5 are not run: no item of the test policy may reach the admin"
        return
    fi
    ne_case lockout-threshold 3 &&
        for door in simple-login ldap-bind kinit; do
            bad=0
            for i in $(seq 1 10); do
                want=incorrect
                [ "$i" -gt 3 ] && want=revoked
                ne_wrong_refused "$door" "wrong-$i-$NE_RUN" "$want" || bad=$((bad + 1))
            done
            [ "$bad" = 0 ] || ne_finding "[P2.2-$door-wrong] $bad of 10 wrong passwords at $door were not refused as wrong (want HTTP 401, LDAP 49, kinit 'Password incorrect' for the first 3, then 'credentials have been revoked')"
            if ne_locked "$door"; then
                ne_pass "[P2.2-$door] lockout-threshold=3 after ten wrong passwords, $door with the right password: refused as locked (HTTP 401, LDAP 49, kinit revoked), for lockout-duration-seconds (default 900)"
            else
                ne_finding "[P2.2-$door] lockout-threshold=3 after ten wrong passwords, $door with the right password was not refused as locked"
            fi
            if ne_unlock && ne_right "$door"; then
                ne_pass "[P2.2-$door-unlock] unlockUser $NE_USER, then the right password at $door: allowed"
            else
                ne_finding "[P2.2-$door-unlock] unlockUser $NE_USER failed, or the right password at $door was still refused after it: $(head -c 200 "$NE_D/last.err")"
            fi
        done
    day="$(LC_ALL=C date -d '+2 days' +%a | tr 'A-Z' 'a-z')"
    # From here the test policy is on the user's OU only; the root keeps what it had.
    # kinit is refused before any password: P2.2's eleven refusals left its flood window open,
    # and P2.3's row must be the first of a new one.
    flood_quiet LOGIN KERBEROS >/dev/null
    ne_case login-hours "$day 03:00-03:01" &&
        for door in simple-login ldap-bind kinit; do
            ne_door "P2.3-$door" "login-hours='$day 03:00-03:01' on the user's OU (now is outside it)" "$door" out \
                "$NE_HOURS"
        done
    ne_case allowed-networks "192.0.2.0/24" &&
        for door in simple-login ldap-bind kinit; do
            ne_door "P2.4-$door" "allowed-networks=192.0.2.0/24 on the user's OU (TEST-NET-1, RFC 5737; no client of the gate is in it)" \
                "$door" out "policy: allowed-networks (address not allowed)"
        done
    ne_case inactivity-days 1 &&
        for door in simple-login ldap-bind kinit; do
            ne_door "P2.5-$door" "inactivity-days=1 on the user's OU, linked now: the user, made minutes ago, is not idle" "$door" in
        done
    ne_root_unlink "$day 03:00-03:01"
}

# The host tool in the gate's container, as the server's own user: the way back when a root
# policy refuses the admin, whose token is then refused too.
ne_tool_unlink() {
    local u args=()
    u="$(uid_of_comm lldap)"
    [ -n "$u" ] && args=(-u "$u")
    t docker exec "${args[@]}" "$CONTAINER" /app/lldap policy-unlink --config-file /data/lldap_config.toml "(root)"
}

# ne_admin_back: the admin's simple login every 5 s for up to 45 s; NE_WAITED, NE_POLLED_401.
ne_admin_back() {
    local got
    NE_WAITED=0 NE_POLLED_401=0
    while [ "$NE_WAITED" -le 45 ]; do
        got="$(ne_simple admin "$ADMIN_PASS")"
        [ "$got" = 200 ] && return 0
        [ "$got" = 401 ] && NE_POLLED_401=$((NE_POLLED_401 + 1))
        sleep 5
        NE_WAITED=$((NE_WAITED + 5))
    done
    return 1
}

# ne_token_use: one GraphQL request on the admin's session: "<status> <refused|other>".
ne_token_use() {
    GQ_URL="$(http_url)/api/graphql" GQ_TOKEN="$TOKEN" t python3 - <<'PY'
import json, os, urllib.error, urllib.request
req = urllib.request.Request(os.environ["GQ_URL"],
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["GQ_TOKEN"]},
    data=json.dumps({"query": '{ user(userId: "admin") { id } }'}).encode())
try:
    urllib.request.urlopen(req)
    print("200 other")
except urllib.error.HTTPError as e:
    print(e.code, "refused" if e.read().decode(errors="replace").strip() == "Access refused" else "other")
except Exception:
    print("000 none")
PY
}

ne__rows() {
    graphql "query(\$id: ID!, \$t: String!) { logs(filter: {kinds: [$1], target: \$t}, afterId: \$id, limit: 50) { success protocol detail } }" \
        "$(ID="$6" T="$2" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "t": os.environ["T"]}))')" 2>/dev/null |
        WANT="$3" PROTO="$4" OK="$5" python3 -c '
import json, os, sys
rows = json.load(sys.stdin)["logs"]
print(sum(1 for r in rows if r.get("detail") == os.environ["WANT"] and r.get("protocol") == os.environ["PROTO"]
          and r.get("success") is (os.environ["OK"] == "true")))' 2>/dev/null
}
# ne_rows KIND TARGET DETAIL PROTOCOL true|false MARK WANT: the count of such rows after the mark.
ne_rows() {
    local n=""
    for _ in $(seq 1 20); do
        n="$(ne__rows "$@")"
        [ "${n:-0}" -ge "$7" ] && break
        sleep 0.5
    done
    sleep 1
    n="$(ne__rows "$@")"
    printf '%s\n' "${n:-0}"
}

# One row: a policy that refuses the admin on the root, undone from the host. No GraphQL call is
# made between the link and the unlink: the admin's token is refused there.
ne_root_unlink() {
    local value="$1" mark simple token rc said unlinked bind denied
    unlinked="policy cleared: $NE_RUN root (lldap policy-unlink)"
    said="Removed the policy link of (root); a running server sees it within 30 seconds."
    mark="$(log_mark)"
    NE_ROOT_POLICY="$(ne_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
        '{"n": "'"$NE_RUN"' root", "i": [{"key": "login-hours", "value": "'"$value"'"}]}' | json_get createPolicy.id 2>/dev/null)"
    if [ -z "$mark" ] || [ -z "$NE_ROOT_POLICY" ]; then
        ne_bad "[P2.root-unlink] no log marker, or the policy '$NE_RUN root' could not be made: $(head -c 200 "$NE_D/last.err")"
        return
    fi
    NE_ROOT_HELD=1
    if ! ne_gql 'mutation($p: Int!) { setOuPolicy(ou: "", policyId: $p) { ok } }' '{"p": '"$NE_ROOT_POLICY"'}' >/dev/null; then
        NE_ROOT_HELD=0
        ne_bad "[P2.root-unlink] the policy could not be linked to the root: $(head -c 200 "$NE_D/last.err")"
        return
    fi
    simple="$(ne_simple admin "$ADMIN_PASS")"
    token="$(ne_token_use)"
    ne_tool_unlink >"$NE_D/policy-unlink.out" 2>&1
    rc=$?
    if ! ne_admin_back; then
        ne_bad "[P2.root-unlink] after lldap policy-unlink (exit $rc: '$(head -c 200 "$NE_D/policy-unlink.out")') the admin's simple login was still refused for 45 s"
        ne_tool_unlink >"$NE_D/policy-unlink-again.out" 2>&1
        rc=$?
        ne_admin_back || ne_root_stuck "$rc"
        NE_ROOT_HELD=0
        TOKEN="$(gate_login)"
        return
    fi
    NE_ROOT_HELD=0
    TOKEN="$(gate_login)"
    bind="$(ne_rows BIND admin "$NE_HOURS" HTTP false "$mark" $((1 + NE_POLLED_401)))"
    denied="$(ne_rows ACCESS_DENIED admin "$NE_HOURS" GRAPHQL false "$mark" 1)"
    unlinked="$(ne_rows POLICY_CHANGE "(root)" "$unlinked" SYSTEM true "$mark" 1)"
    if [ "$simple $token $rc" = "401 401 refused 0" ] && grep -qF "$said" "$NE_D/policy-unlink.out" &&
        [ "$bind $denied $unlinked" = "$((1 + NE_POLLED_401)) 1 1" ]; then
        ne_pass "[P2.root-unlink] login-hours='$value' linked to the root reaches the admin: the simple login 401 and the session's next request 401 'Access refused' (BIND and ACCESS_DENIED rows '$NE_HOURS'); lldap policy-unlink '(root)' in the container (exit 0, '$said'): the admin signs in again after $NE_WAITED s (within 45 s), one POLICY_CHANGE row on (root) 'policy cleared: $NE_RUN root (lldap policy-unlink)' (protocol SYSTEM)"
    else
        ne_bad "[P2.root-unlink] simple login '$simple', session '$token' (want 401, 401 refused); the tool exited $rc: '$(head -c 160 "$NE_D/policy-unlink.out")'; BIND rows $bind (want $((1 + NE_POLLED_401))), ACCESS_DENIED rows $denied (want 1), POLICY_CHANGE unlink rows $unlinked (want 1)"
    fi
}

# The tool ran twice and the admin is still refused: no later phase could sign in, so the run
# stops here, and the gate's own exit removes its containers.
ne_root_stuck() {
    NE_STUCK=1
    ne_bad "[P2.root-stuck] lldap policy-unlink '(root)' ran twice (the second exit $1: '$(head -c 200 "$NE_D/policy-unlink-again.out")') and the admin was still refused 45 s after each: the run stops here"
    note "policy-not-enforced: $NE_N rows, $NE_P pass, $NE_F FINDING, $NE_K NOTE, $NE_X FAIL"
    gate_summary
    exit 1
}

ne_cleanup() {
    [ "$NE_STUCK" = 1 ] && return 0
    if [ "$NE_ROOT_HELD" = 1 ]; then
        ne_tool_unlink >"$NE_D/policy-unlink-cleanup.out" 2>&1
        ne_admin_back && TOKEN="$(gate_login)"
        NE_ROOT_HELD=0
    fi
    if [ -n "${NE_ROOT_BEFORE:-}" ]; then
        ne_gql 'mutation($p: Int!) { setOuPolicy(ou: "", policyId: $p) { ok } }' '{"p": '"$NE_ROOT_BEFORE"'}' >/dev/null
    else
        ne_gql 'mutation { clearOuPolicy(ou: "") { ok } }' '{}' >/dev/null
    fi
    ne_gql 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' '{"o": "'"$NE_OU"'"}' >/dev/null
    [ -n "$NE_POLICY" ] && ne_gql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$NE_POLICY"'}' >/dev/null
    [ -n "$NE_ROOT_POLICY" ] && ne_gql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$NE_ROOT_POLICY"'}' >/dev/null
    ne_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$NE_USER"'"}' >/dev/null
    ne_gql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$NE_OU"'"}' >/dev/null
    local left
    left="$(ne_gql '{ policies { name } ouPolicyStates { ou policyId } users { id } }' '{}')" || {
        p_bad "cleanup: the leftover check could not read the state"
        return
    }
    if grep -q "$NE_RUN" <<<"$left"; then p_bad "cleanup left $NE_RUN state behind"; fi
    [ "$(NEL="$left" python3 -c '
import json, os
print(next((str(x["policyId"] or "") for x in json.loads(os.environ["NEL"])["ouPolicyStates"] if x["ou"] == ""), ""))')" = "${NE_ROOT_BEFORE:-}" ] ||
        p_bad "the root's policy was not restored to '${NE_ROOT_BEFORE:-none}'"
}

# On any exit the root and the test OU are unlinked first, then the gate's own exit runs.
ne_trap_command() {
    eval "set -- $1"
    printf '%s' "${3:-}"
}
NE_TRAP="$(trap -p EXIT)"
# shellcheck disable=SC2064
trap "ne_cleanup; $(ne_trap_command "$NE_TRAP")" EXIT
if ne_setup; then ne_today; fi
ne_cleanup
if [ -n "$NE_TRAP" ]; then eval "$NE_TRAP"; else trap - EXIT; fi
note "--- policy-not-enforced FINDING rows ---"
for f in "${NE_FIND[@]}"; do note "[FINDING] ${PHASE}: $f"; done
note "policy-not-enforced: $NE_N rows, $NE_P pass, $NE_F FINDING, $NE_K NOTE, $NE_X FAIL"
note "policy-not-enforced: a correct product gives 26 rows, 26 pass, 0 FINDING, 0 NOTE, 0 FAIL"
if [ "$NE_XT" = 1 ]; then set -x; fi
