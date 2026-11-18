# shellcheck shell=bash
# Phase: each policy item set and shown effective, then simple login, LDAP bind, kinit; lockout-threshold locks, the other rows say today | when enforced.

NE_D="$(phase_dir)"
NE_N=0 NE_P=0 NE_F=0 NE_K=0 NE_FIND=()
NE_RUN="ne$(date +%H%M%S)"
NE_OU="${NE_RUN}ou" NE_USER="${NE_RUN}-u" NE_POLICY=""
NE_PASS="$(python3 -c 'import secrets; print("Ne" + secrets.token_hex(10) + "!")')"

ne_pass() { NE_N=$((NE_N + 1)) NE_P=$((NE_P + 1)); p_ok "$1"; }
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

ne_door() {
    local id="$1" case_="$2" door="$3" enforced="$4"
    if ne_right "$door"; then
        ne_pass "[$id] $case_, $door with the right password: today allowed (as pinned) | when enforced: $enforced"
    else
        ne_finding "[$id] $case_, $door with the right password: today REFUSED, but nothing is enforced yet | when enforced: $enforced"
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

ne_today() {
    local day i bad want
    ne_case require-mfa always &&
        for door in simple-login ldap-bind kinit; do
            ne_door "P2.1-$door" "require-mfa=always, user without MFA" "$door" \
                "refused until the user enrols a second factor$([ "$door" = kinit ] && echo '; kinit has no code today, so enforcement needs a Kerberos-side answer')"
        done
    ne_root before && ne_case lockout-threshold 3 &&
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
    # The root takes the test policy again only once its items no longer hold the threshold.
    ne_case login-hours "$day 03:00-03:01" && {
        ne_root ours || ne_finding "[P2.2-root] the test policy could not be set on the root again"
        for door in simple-login ldap-bind kinit; do
            ne_door "P2.3-$door" "login-hours='$day 03:00-03:01' (now is outside it)" "$door" "refused outside the window"
        done
    }
    ne_case allowed-networks "192.0.2.0/24" &&
        for door in simple-login ldap-bind kinit; do
            ne_door "P2.4-$door" "allowed-networks=192.0.2.0/24 (TEST-NET-1, RFC 5737; the client is not in it)" "$door" \
                "refused from outside the listed networks"
        done
    ne_case inactivity-days 1 && {
        ne_note "[P2.5-record] inactivity-days=1: the server keeps no last-login time, so nothing can age a user today | when enforced: a user idle over 1 day is refused, which first needs a last-login record"
        for door in simple-login ldap-bind kinit; do
            ne_door "P2.5-$door" "inactivity-days=1" "$door" "refused only for a user idle over 1 day (this user is not)"
        done
    }
}

ne_cleanup() {
    if [ -n "${NE_ROOT_BEFORE:-}" ]; then
        ne_gql 'mutation($p: Int!) { setOuPolicy(ou: "", policyId: $p) { ok } }' '{"p": '"$NE_ROOT_BEFORE"'}' >/dev/null
    else
        ne_gql 'mutation { clearOuPolicy(ou: "") { ok } }' '{}' >/dev/null
    fi
    ne_gql 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' '{"o": "'"$NE_OU"'"}' >/dev/null
    [ -n "$NE_POLICY" ] && ne_gql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$NE_POLICY"'}' >/dev/null
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
note "policy-not-enforced: $NE_N rows, $NE_P pass, $NE_F FINDING, $NE_K NOTE"
