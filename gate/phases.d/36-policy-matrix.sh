# shellcheck shell=bash
# Phase: the OU-policy catalog and API matrix. Rows that show the product wrong print FINDING and do not fail the gate;
# NOTE rows pin behaviour put to the owner; FAIL is kept for a harness that cannot proceed or leaves state behind.

PM_D="$(phase_dir)"
PM_N=0 PM_P=0 PM_F=0 PM_K=0
PM_FIND_CAPS=() PM_FIND=()
PM_RUN="pm$(date +%H%M%S)$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
PM_A="${PM_RUN}a" PM_B="${PM_RUN}b" PM_C="${PM_RUN}c"
PM_NEST="${PM_A}\\${PM_RUN}n"
PM_RO="${PM_RUN}-ro" PM_USER="${PM_RUN}-user"
PM_PASS="$(python3 -c 'import secrets; print("Pm" + secrets.token_hex(10) + "!")')"
PM_IDS=() PM_ROOT_BEFORE=""

pm_pass() { PM_N=$((PM_N + 1)) PM_P=$((PM_P + 1)); p_ok "$1"; }
pm_note() { PM_N=$((PM_N + 1)) PM_K=$((PM_K + 1)); note "[NOTE] ${PHASE}: $1"; }
pm_finding() {
    PM_N=$((PM_N + 1)) PM_F=$((PM_F + 1))
    note "[FINDING] ${PHASE}: $1"
    case "$1" in *[A-Z][A-Z][A-Z][A-Z]\ ALLOWED*) PM_FIND_CAPS+=("$1") ;; *) PM_FIND+=("$1") ;; esac
}
pm_row() { if [ "$1" = 0 ]; then pm_pass "$2"; else pm_finding "$2${3:+ ($3)}"; fi; }

# pm_q TOKEN QUERY [name=value ...] -> the whole answer as JSON, {"http": code} on a transport refusal. Values: i:3 is
# an int, b:true a bool, j:[...] raw JSON, e:pass the run's password from the environment, anything else a string.
pm_q() {
    PMQ_URL="$(http_url)/api/graphql" PMQ_TOKEN="$1" PMQ_QUERY="$2" PMQ_PASS="$PM_PASS" t python3 - "${@:3}" <<'PY'
import json, os, sys, urllib.error, urllib.request
variables = {}
for arg in sys.argv[1:]:
    name, value = arg.split("=", 1)
    if value.startswith("i:"):
        variables[name] = int(value[2:])
    elif value.startswith("b:"):
        variables[name] = value[2:] == "true"
    elif value.startswith("j:"):
        variables[name] = json.loads(value[2:])
    elif value == "e:pass":
        variables[name] = os.environ["PMQ_PASS"]
    else:
        variables[name] = value
headers = {"Content-Type": "application/json"}
if os.environ["PMQ_TOKEN"]:
    headers["Authorization"] = "Bearer " + os.environ["PMQ_TOKEN"]
req = urllib.request.Request(os.environ["PMQ_URL"], headers=headers,
    data=json.dumps({"query": os.environ["PMQ_QUERY"], "variables": variables}).encode())
try:
    print(json.dumps(json.load(urllib.request.urlopen(req))))
except urllib.error.HTTPError as e:
    print(json.dumps({"http": e.code, "body": e.read().decode(errors="replace")[:300]}))
except Exception as e:
    print(json.dumps({"transport": str(e)[:200]}))
PY
}
pm_ok() { PMA="$1" python3 -c 'import json,os,sys; a=json.loads(os.environ["PMA"]); sys.exit(0 if a.get("data") and not a.get("errors") and "http" not in a else 1)'; }
pm_refused() { PMA="$1" python3 -c 'import json,os,sys; a=json.loads(os.environ["PMA"]); sys.exit(0 if a.get("errors") or a.get("http") in (401, 403) else 1)'; }
pm_unauth() { PMA="$1" PMR="$2" python3 -c '
import json, os, sys
a = json.loads(os.environ["PMA"])
msgs = " ".join(e.get("message", "") for e in a.get("errors") or [])
if os.environ["PMR"] == "no-session":
    sys.exit(0 if "Unauthorized" in msgs or a.get("http") in (401, 403) else 1)
sys.exit(0 if "Unauthorized" in msgs and "http" not in a else 1)'; }
pm_says() { PMA="$1" PMW="$2" python3 -c '
import json, os, sys
a = json.loads(os.environ["PMA"])
sys.exit(0 if any(os.environ["PMW"] in e.get("message", "") for e in a.get("errors") or []) else 1)'; }
pm_err() { PMA="$1" python3 -c 'import json,os; a=json.loads(os.environ["PMA"]); print((json.dumps(a.get("errors") or a.get("http") or a.get("transport") or "no error"))[:200])'; }
pm_get() { PMA="$1" PMP="$2" python3 -c '
import json, os
v = json.loads(os.environ["PMA"])
for p in os.environ["PMP"].split("."):
    v = v[int(p)] if isinstance(v, list) and len(v) > int(p) else v.get(p) if isinstance(v, dict) else None
print(json.dumps(v) if isinstance(v, (dict, list)) else ("" if v is None else v))'; }
pm_track() {
    local id
    id="$(pm_get "$1" data.createPolicy.id)"
    [ -n "$id" ] && PM_IDS+=("$id")
    printf '%s\n' "$id"
}

pm_items() {
    local a
    a="$(pm_q "$TOKEN" 'query($p: Int!) { policy(policyId: $p) { items { key value } } }' "p=i:$1")"
    pm_ok "$a" && pm_get "$a" data.policy.items || echo "<error>"
}
pm_item() {
    local items
    items="$(pm_items "$1")"
    [ "$items" = "<error>" ] && {
        echo "<error>"
        return
    }
    PMI="$items" PMK="$2" python3 -c '
import json, os
items = {i["key"]: i["value"] for i in json.loads(os.environ["PMI"])}
print(items.get(os.environ["PMK"], "<absent>"))'
}
pm_state() {
    local a
    a="$(pm_q "$TOKEN" '{ policies { id name description items { key value } linkedOus } ouPolicyStates { ou policyId blockInheritance } }')"
    pm_ok "$a" || {
        echo "<error>"
        return
    }
    PMA="$a" python3 -c 'import json,os; print(json.dumps(json.loads(os.environ["PMA"])["data"], sort_keys=True))'
}
pm_states_of() {
    local s
    s="$(pm_state)"
    [ "$s" = "<error>" ] && {
        echo "<error>"
        return
    }
    PMS="$s" PMO="$1" python3 -c '
import json, os
st = [x for x in json.loads(os.environ["PMS"])["ouPolicyStates"] if x["ou"] == os.environ["PMO"]]
print(len(st), (st[0]["policyId"] or "none") if st else "", st[0]["blockInheritance"] if st else "")'
}
pm_eff() { PMA="$(pm_q "$TOKEN" 'query($o: String!) { effectivePolicyItems(ou: $o) { key value sourceOu sourcePolicyName } }' "o=$1")" PMK="$2" PMF="$3" python3 -c '
import json, os
a = json.loads(os.environ["PMA"])
for i in (a.get("data") or {}).get("effectivePolicyItems") or []:
    if i["key"] == os.environ["PMK"]:
        v = i.get(os.environ["PMF"])
        print("<none>" if v is None else v)
        break
else:
    print("<error>")'; }
pm_new_policy() { pm_track "$(pm_q "$TOKEN" 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' "n=$1" "i=j:${2:-[]}")"; }
pm_set_items() { pm_q "$TOKEN" 'mutation($p: Int!, $i: [PolicyItemInput!]) { updatePolicy(policyId: $p, items: $i) { ok } }' "p=i:$1" "i=j:$2"; }
pm_ou_of() {
    local a
    a="$(pm_q "$TOKEN" "$1" "$2")"
    pm_ok "$a" && pm_get "$a" "$3" || echo "<error>"
}

pm_setup() {
    local a ro_gid
    PM_ROOT_BEFORE="$(pm_states_of "")"
    [ "$PM_ROOT_BEFORE" != "<error>" ] || {
        p_bad "setup: ouPolicyStates could not be read"
        return 1
    }
    PM_ROOT_POLICY_BEFORE="$(pm_get "$(pm_q "$TOKEN" '{ ouPolicyStates { ou policyId } }')" data.ouPolicyStates | python3 -c '
import json, sys
print(next((str(x["policyId"] or "") for x in json.load(sys.stdin) if x["ou"] == ""), ""))')" || {
        p_bad "setup: the root's policy could not be read"
        return 1
    }
    for ou in "$PM_A" "$PM_B" "$PM_C" "$PM_NEST"; do
        pm_ok "$(pm_q "$TOKEN" 'mutation($n: String!) { createOu(name: $n) { ok } }' "n=$ou")" || {
            p_bad "setup: createOu $ou failed"
            return 1
        }
    done
    for u in "$PM_RO" "$PM_USER"; do
        pm_ok "$(pm_q "$TOKEN" 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' "u=j:{\"id\": \"$u\", \"email\": \"$u@example.com\"}")" &&
            pm_ok "$(pm_q "$TOKEN" 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "id=$u" "pw=e:pass")" || {
            p_bad "setup: user $u could not be made"
            return 1
        }
    done
    a="$(pm_q "$TOKEN" '{ groups { id displayName } }')"
    ro_gid="$(PMA="$a" python3 -c 'import json,os; print(next((g["id"] for g in json.loads(os.environ["PMA"])["data"]["groups"] if g["displayName"] == "lldap_strict_readonly"), ""))')"
    [ -n "$ro_gid" ] && pm_ok "$(pm_q "$TOKEN" 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' "u=$PM_RO" "g=i:$ro_gid")" || {
        p_bad "setup: $PM_RO could not join lldap_strict_readonly"
        return 1
    }
    a="$(pm_q "$TOKEN" 'mutation($n: String!) { createGroup(name: $n) { id } }' "n=${PM_RUN}-grp")"
    PM_GID="$(pm_get "$a" data.createGroup.id)"
    [ -n "$PM_GID" ] || {
        p_bad "setup: createGroup failed: $(pm_err "$a")"
        return 1
    }
    PM_RO_TOKEN="$(gate_login "$PM_RO" "$PM_PASS")" && PM_USER_TOKEN="$(gate_login "$PM_USER" "$PM_PASS")" || {
        p_bad "setup: the read-only admin or the plain user could not log in"
        return 1
    }
}

pm_catalog() {
    local a want got
    a="$(pm_q "$TOKEN" '{ policyItemCatalog { key enforced defaultValue } }')"
    printf '%s\n' "$a" >"$PM_D/catalog.json"
    pm_ok "$a" || {
        pm_finding "the catalog could not be read ($(pm_err "$a"))"
        return
    }
    got="$(PMA="$a" python3 -c '
import json, os
c = json.loads(os.environ["PMA"])["data"]["policyItemCatalog"]
print(len(c), all(i["enforced"] is False for i in c))')"
    pm_row "$([ "$got" = "6 True" ] && echo 0 || echo 1)" "catalog lists six items, none enforced" "got $got"
    for want in "require-mfa=off" "lockout-threshold=0" "lockout-duration-seconds=900" "login-hours=" "allowed-networks=" "inactivity-days=0"; do
        got="$(PMA="$a" PMK="${want%%=*}" python3 -c '
import json, os
c = {i["key"]: i["defaultValue"] for i in json.loads(os.environ["PMA"])["data"]["policyItemCatalog"]}
print(c.get(os.environ["PMK"], "<missing>"))')"
        pm_row "$([ "$got" = "${want#*=}" ] && echo 0 || echo 1)" "catalog default of ${want%%=*} is '${want#*=}'" "got '$got'"
    done
}

pm_items_cycle() {
    local p row key v1 v2 got a
    p="$(pm_new_policy "${PM_RUN} cycle")"
    [ -n "$p" ] || {
        p_bad "createPolicy for the item cycle failed"
        return 1
    }
    for row in "require-mfa|enrolled|always" "lockout-threshold|3|100" "lockout-duration-seconds|60|604800" \
        "login-hours|mon-fri 08:00-18:00|sat 10:00-12:00;sun 10:00-11:00" \
        "allowed-networks|10.0.0.0/8|192.168.1.0/24, 2001:db8::/32" "inactivity-days|1|3650"; do
        IFS='|' read -r key v1 v2 <<<"$row"
        a="$(pm_set_items "$p" "[{\"key\": \"$key\", \"value\": \"$v1\"}]")"
        pm_row "$(pm_ok "$a" && echo 0 || echo 1)" "$key: set to '$v1' accepted" "$(pm_err "$a")"
        got="$(pm_item "$p" "$key")"
        pm_row "$([ "$got" = "$v1" ] && echo 0 || echo 1)" "$key: reads back '$v1'" "read '$got'"
        a="$(pm_set_items "$p" "[{\"key\": \"$key\", \"value\": \"$v2\"}]")"
        got="$(pm_item "$p" "$key")"
        pm_row "$(pm_ok "$a" && [ "$got" = "$v2" ] && echo 0 || echo 1)" "$key: updated to '$v2' and reads back" "read '$got', $(pm_err "$a")"
        a="$(pm_set_items "$p" '[]')"
        got="$(pm_item "$p" "$key")"
        pm_row "$(pm_ok "$a" && [ "$got" = "<absent>" ] && echo 0 || echo 1)" "$key: cleared, absent from the policy" "read '$got', $(pm_err "$a")"
    done
    PM_CYCLE="$p"
}

pm_bad_values() {
    local p row key value before after a names
    p="$PM_CYCLE"
    pm_set_items "$p" '[{"key": "lockout-threshold", "value": "5"}]' >/dev/null
    before="$(pm_items "$p")"
    for row in "require-mfa|sometimes" "require-mfa|" "lockout-threshold|-1" "lockout-threshold|101" "lockout-threshold|3.5" \
        "lockout-duration-seconds|604801" "login-hours|mon 25:00-26:00" "login-hours|funday 09:00-17:00" \
        "login-hours|mon 18:00-08:00" "allowed-networks|10.0.0.1" "allowed-networks|10.0.0.0/33" "allowed-networks|foo/8" \
        "allowed-networks|10.0.0.0/8,," "inactivity-days|3651" "inactivity-days|-1" "max-sessions|3"; do
        IFS='|' read -r key value <<<"$row"
        a="$(pm_set_items "$p" "[{\"key\": \"$key\", \"value\": \"$value\"}]")"
        after="$(pm_items "$p")"
        if pm_refused "$a" && [ "$before" != "<error>" ] && [ "$after" = "$before" ]; then pm_pass "$key='$value' refused, policy unchanged"; else pm_finding "$key='$value' was not refused or changed the policy (answer $(pm_err "$a"); items $after)"; fi
    done
    a="$(pm_set_items "$p" '[{"key": "inactivity-days", "value": "1"}, {"key": "inactivity-days", "value": "2"}]')"
    after="$(pm_items "$p")"
    pm_row "$(pm_refused "$a" && [ "$after" = "$before" ] && echo 0 || echo 1)" "the same item twice in one update is refused, policy unchanged" "$(pm_err "$a")"
    a="$(pm_q "$TOKEN" 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' "n=${PM_RUN} badcreate" 'i=j:[{"key": "lockout-threshold", "value": "999"}]')"
    pm_track "$a" >/dev/null
    names="$(pm_q "$TOKEN" '{ policies { name } }')"
    if pm_refused "$a" && pm_ok "$names" && ! grep -q "${PM_RUN} badcreate" <<<"$names"; then pm_pass "createPolicy with a bad item is refused and creates nothing"; else pm_finding "createPolicy with a bad item: $(pm_err "$a")"; fi
    for row in "0|lockout-threshold" "100|lockout-threshold" "0|lockout-duration-seconds" "0|inactivity-days"; do
        IFS='|' read -r value key <<<"$row"
        a="$(pm_set_items "$p" "[{\"key\": \"$key\", \"value\": \"$value\"}]")"
        after="$(pm_item "$p" "$key")"
        pm_row "$(pm_ok "$a" && [ "$after" = "$value" ] && echo 0 || echo 1)" "$key='$value' at its bound is accepted and reads back" "read '$after', $(pm_err "$a")"
    done
}

pm_names() {
    local a pad65 pad64 ctrl
    pad65="${PM_RUN}$(printf 'n%.0s' $(seq 1 $((65 - ${#PM_RUN}))))"
    pad64="${pad65:0:64}"
    ctrl="${PM_RUN}bad$(printf '\a')name"
    a="$(pm_q "$TOKEN" 'mutation($n: String!) { createPolicy(name: $n) { id } }' 'n=')"
    pm_track "$a" >/dev/null
    pm_row "$(pm_refused "$a" && echo 0 || echo 1)" "an empty policy name is refused" "$(pm_err "$a")"
    a="$(pm_q "$TOKEN" 'mutation($n: String!) { createPolicy(name: $n) { id } }' "n=$pad65")"
    pm_track "$a" >/dev/null
    pm_row "$(pm_refused "$a" && echo 0 || echo 1)" "a 65-character policy name is refused" "$(pm_err "$a")"
    a="$(pm_q "$TOKEN" 'mutation($n: String!) { createPolicy(name: $n) { id } }' "n=$pad64")"
    pm_track "$a" >/dev/null
    pm_row "$(pm_ok "$a" && echo 0 || echo 1)" "a 64-character policy name is accepted" "$(pm_err "$a")"
    a="$(pm_q "$TOKEN" 'mutation($n: String!) { createPolicy(name: $n) { id } }' "n=$ctrl")"
    pm_track "$a" >/dev/null
    pm_row "$(pm_refused "$a" && echo 0 || echo 1)" "a policy name with a control character is refused" "$(pm_err "$a")"
    a="$(pm_q "$TOKEN" 'mutation($n: String!) { createPolicy(name: $n) { id } }' "n=${PM_RUN} CYCLE")"
    pm_track "$a" >/dev/null
    pm_row "$(pm_refused "$a" && echo 0 || echo 1)" "a name that differs from an existing one only in case is refused" "$(pm_err "$a")"
    PM_P2="$(pm_new_policy "${PM_RUN} second" '[{"key": "lockout-threshold", "value": "7"}]')"
    a="$(pm_q "$TOKEN" 'mutation($p: Int!, $n: String) { updatePolicy(policyId: $p, name: $n) { ok } }' "p=i:$PM_P2" "n=${PM_RUN} Cycle")"
    pm_row "$(pm_refused "$a" && echo 0 || echo 1)" "renaming onto another policy's name in another case is refused" "$(pm_err "$a")"
}

pm_attach() {
    local a
    pm_set_items "$PM_CYCLE" '[{"key": "require-mfa", "value": "always"}, {"key": "lockout-threshold", "value": "5"}]' >/dev/null
    pm_q "$TOKEN" 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' "o=$PM_A" "p=i:$PM_P2" >/dev/null
    pm_q "$TOKEN" 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' "o=$PM_A" "p=i:$PM_CYCLE" >/dev/null
    a="$(pm_states_of "${PM_A,,}")"
    pm_row "$([ "$a" = "1 $PM_CYCLE False" ] && echo 0 || echo 1)" "one policy per OU: a second setOuPolicy replaces the first" "state $a"
    pm_q "$TOKEN" 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' "o=$PM_C" "p=i:$PM_CYCLE" >/dev/null
    a="$(pm_q "$TOKEN" 'query($p: Int!) { policy(policyId: $p) { linkedOus } }' "p=i:$PM_CYCLE")"
    a="$(pm_ok "$a" && pm_get "$a" data.policy.linkedOus || echo "<error>")"
    pm_row "$(grep -q "\"${PM_A,,}\"" <<<"$a" && grep -q "\"${PM_C,,}\"" <<<"$a" && echo 0 || echo 1)" "one policy may be linked to two OUs" "linkedOus $a"
}

pm_nesting() {
    local nest_key a p3
    nest_key="${PM_NEST,,}"
    a="$(pm_eff "$PM_NEST" require-mfa value)|$(pm_eff "$PM_NEST" require-mfa sourceOu)"
    pm_row "$([ "$a" = "always|${PM_A,,}" ] && echo 0 || echo 1)" "the nested OU inherits require-mfa=always from its parent" "got $a"
    p3="$(pm_new_policy "${PM_RUN} nested" '[{"key": "lockout-threshold", "value": "9"}]')"
    PM_P3="$p3"
    pm_q "$TOKEN" 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' "o=$PM_NEST" "p=i:$p3" >/dev/null
    a="$(pm_eff "$PM_NEST" lockout-threshold value)|$(pm_eff "$PM_NEST" lockout-threshold sourceOu)|$(pm_eff "$PM_NEST" require-mfa value)"
    pm_row "$([ "$a" = "9|$nest_key|always" ] && echo 0 || echo 1)" "the nested OU's own value wins and the parent's other item still reaches it" "got $a"
    pm_q "$TOKEN" 'mutation($o: String!, $b: Boolean!) { setOuPolicyInheritance(ou: $o, blocked: $b) { ok } }' "o=$PM_NEST" "b=b:true" >/dev/null
    a="$(pm_eff "$PM_NEST" require-mfa value)|$(pm_eff "$PM_NEST" require-mfa sourceOu)|$(pm_eff "$PM_NEST" lockout-threshold value)"
    pm_row "$([ "$a" = "off|<none>|9" ] && echo 0 || echo 1)" "a blocked nested OU loses the parent's items and keeps its own" "got $a"
    a="$(pm_q "$TOKEN" 'mutation { setOuPolicyInheritance(ou: "", blocked: true) { ok } }')"
    pm_row "$(pm_refused "$a" && echo 0 || echo 1)" "the root cannot block inheritance" "$(pm_err "$a")"
    PM_ROOTP="$(pm_new_policy "${PM_RUN} root" '[{"key": "inactivity-days", "value": "30"}]')"
    pm_q "$TOKEN" 'mutation($p: Int!) { setOuPolicy(ou: "", policyId: $p) { ok } }' "p=i:$PM_ROOTP" >/dev/null
    a="$(pm_eff "$PM_B" inactivity-days value)|$(pm_eff "$PM_A" inactivity-days value)|$(pm_eff "$PM_NEST" inactivity-days value)"
    pm_row "$([ "$a" = "30|30|0" ] && echo 0 || echo 1)" "a root policy reaches plain and policy OUs, and not a blocked one" "B|A|nested got $a"
    pm_restore_root
}

pm_restore_root() {
    if [ -n "${PM_ROOT_POLICY_BEFORE:-}" ]; then
        pm_q "$TOKEN" 'mutation($p: Int!) { setOuPolicy(ou: "", policyId: $p) { ok } }' "p=i:$PM_ROOT_POLICY_BEFORE" >/dev/null
    else
        pm_q "$TOKEN" 'mutation { clearOuPolicy(ou: "") { ok } }' >/dev/null
    fi
}

pm_delete_attached() {
    local a
    pm_q "$TOKEN" 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' "p=i:$PM_P3" >/dev/null
    a="$(pm_states_of "${PM_NEST,,}")"
    pm_row "$([ "$a" = "1 none True" ] && echo 0 || echo 1)" "deleting an attached policy leaves the blocked OU with no policy and its block kept" "state $a"
    a="$(pm_eff "$PM_NEST" lockout-threshold value)|$(pm_eff "$PM_NEST" lockout-threshold sourceOu)"
    pm_row "$([ "$a" = "0|<none>" ] && echo 0 || echo 1)" "after the delete the nested OU falls back to the default" "got $a"
}

pm_ou_delete() {
    local a
    pm_q "$TOKEN" 'mutation($n: String!) { deleteOu(name: $n) { ok } }' "n=$PM_C" >/dev/null
    a="$(pm_state)"
    pm_row "$([ "$a" != "<error>" ] && ! grep -q "\"${PM_C,,}\"" <<<"$a" && echo 0 || echo 1)" "deleteOu with a policy attached drops its policy state" "state: $(cut -c1-120 <<<"$a")"
    pm_q "$TOKEN" 'mutation($n: String!) { createOu(name: $n) { ok } }' "n=$PM_C" >/dev/null
    a="$(pm_eff "$PM_C" require-mfa sourceOu)|$(pm_states_of "${PM_C,,}")"
    pm_row "$([ "$a" = "<none>|0  " ] && echo 0 || echo 1)" "recreating the OU brings back no stale policy" "sourceOu|state $a"
}

pm_unregistered() {
    local a nosuch="${PM_RUN}nosuch"
    a="$(pm_q "$TOKEN" 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' "o=$nosuch" "p=i:$PM_CYCLE")"
    pm_row "$(pm_says "$a" "Unknown OU" && echo 0 || echo 1)" "setOuPolicy on an unregistered OU is refused as unknown" "$(pm_err "$a")"
    a="$(pm_q "$TOKEN" 'mutation($o: String!) { setOuPolicyInheritance(ou: $o, blocked: true) { ok } }' "o=$nosuch")"
    pm_row "$(pm_says "$a" "Unknown OU" && echo 0 || echo 1)" "setOuPolicyInheritance on an unregistered OU is refused as unknown" "$(pm_err "$a")"
    a="$(pm_q "$TOKEN" 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' "o=$nosuch")"
    pm_row "$(pm_says "$a" "Unknown OU" && echo 0 || echo 1)" "clearOuPolicy on an unregistered OU is refused as unknown" "no registration check: it answered $(pm_err "$a")"
    a="$(pm_q "$TOKEN" 'query($o: String!) { effectivePolicyItems(ou: $o) { key } }' "o=$nosuch")"
    pm_row "$(pm_says "$a" "Unknown OU" && echo 0 || echo 1)" "effectivePolicyItems on an unregistered OU is refused as unknown" "no registration check: it answered $(pm_ok "$a" && echo 'the root values' || pm_err "$a")"
}

pm_move() {
    local before after placed moved
    pm_q "$TOKEN" 'mutation($u: [String!]!, $o: String!) { changeUserOu(userIds: $u, newOu: $o) { ok } }' "u=j:[\"$PM_USER\"]" "o=$PM_B" >/dev/null
    pm_q "$TOKEN" 'mutation($g: [Int!]!, $o: String!) { changeGroupOu(groupIds: $g, newOu: $o) { ok } }' "g=j:[$PM_GID]" "o=$PM_B" >/dev/null
    placed="$(pm_ou_of 'query($u: String!) { user(userId: $u) { ou } }' "u=$PM_USER" data.user.ou)|$(pm_ou_of 'query($g: Int!) { group(groupId: $g) { ou } }' "g=i:$PM_GID" data.group.ou)"
    before="$(pm_state)|$(pm_q "$TOKEN" 'query($o: String!) { effectivePolicyItems(ou: $o) { key value sourceOu } }' "o=$PM_A")|$(pm_q "$TOKEN" 'query($o: String!) { effectivePolicyItems(ou: $o) { key value sourceOu } }' "o=$PM_B")"
    pm_q "$TOKEN" 'mutation($u: [String!]!, $o: String!) { changeUserOu(userIds: $u, newOu: $o) { ok } }' "u=j:[\"$PM_USER\"]" "o=$PM_A" >/dev/null
    pm_q "$TOKEN" 'mutation($g: [Int!]!, $o: String!) { changeGroupOu(groupIds: $g, newOu: $o) { ok } }' "g=j:[$PM_GID]" "o=$PM_A" >/dev/null
    moved="$(pm_ou_of 'query($u: String!) { user(userId: $u) { ou } }' "u=$PM_USER" data.user.ou)|$(pm_ou_of 'query($g: Int!) { group(groupId: $g) { ou } }' "g=i:$PM_GID" data.group.ou)"
    after="$(pm_state)|$(pm_q "$TOKEN" 'query($o: String!) { effectivePolicyItems(ou: $o) { key value sourceOu } }' "o=$PM_A")|$(pm_q "$TOKEN" 'query($o: String!) { effectivePolicyItems(ou: $o) { key value sourceOu } }' "o=$PM_B")"
    if [ "${placed,,}" != "${PM_B,,}|${PM_B,,}" ] || [ "${moved,,}" != "${PM_A,,}|${PM_A,,}" ]; then
        p_bad "the move rows could not move the user and group (placed $placed, moved $moved)"
        return
    fi
    pm_row "$([ "${before%%|*}" != "<error>" ] && [ "$before" = "$after" ] && echo 0 || echo 1)" "moving a user and a group from a plain OU into a policy OU changes no policy state and no effective value: resolution is per OU and never per user" "something changed"
}

pm_authz() {
    local role="$1" tok="$2" op q vars a before after scratch kind
    scratch="$(pm_new_policy "${PM_RUN} authz-$role")"
    for op in policies policy policyItemCatalog effectivePolicyItems ouPolicyStates createPolicy updatePolicy deletePolicy setOuPolicy clearOuPolicy setOuPolicyInheritance; do
        case "$op" in
        policies) q='{ policies { id } }' vars=() kind=read ;;
        policy) q='query($p: Int!) { policy(policyId: $p) { id } }' vars=("p=i:$scratch") kind=read ;;
        policyItemCatalog) q='{ policyItemCatalog { key } }' vars=() kind=read ;;
        effectivePolicyItems) q='query($o: String!) { effectivePolicyItems(ou: $o) { key } }' vars=("o=$PM_A") kind=read ;;
        ouPolicyStates) q='{ ouPolicyStates { ou } }' vars=() kind=read ;;
        createPolicy) q='mutation($n: String!) { createPolicy(name: $n) { id } }' vars=("n=${PM_RUN} by-$role") kind=write ;;
        updatePolicy) q='mutation($p: Int!) { updatePolicy(policyId: $p, description: "changed") { ok } }' vars=("p=i:$scratch") kind=write ;;
        deletePolicy) q='mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' vars=("p=i:$scratch") kind=write ;;
        setOuPolicy) q='mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' vars=("o=$PM_B" "p=i:$scratch") kind=write ;;
        clearOuPolicy) q='mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' vars=("o=$PM_A") kind=write ;;
        setOuPolicyInheritance) q='mutation($o: String!) { setOuPolicyInheritance(ou: $o, blocked: true) { ok } }' vars=("o=$PM_B") kind=write ;;
        esac
        if [ "$role" = admin ]; then
            [ "$op" = deletePolicy ] && continue
            a="$(pm_q "$tok" "$q" "${vars[@]}")"
            [ "$op" = createPolicy ] && pm_track "$a" >/dev/null
            pm_row "$(pm_ok "$a" && echo 0 || echo 1)" "admin may $op" "$(pm_err "$a")"
            continue
        fi
        before="$(pm_state)"
        a="$(pm_q "$tok" "$q" "${vars[@]}")"
        [ "$op" = createPolicy ] && pm_track "$a" >/dev/null
        after="$(pm_state)"
        if [ "$role" = read-only-admin ] && [ "$kind" = read ]; then
            if pm_ok "$a" && [ "$before" != "<error>" ] && [ "$before" = "$after" ]; then
                pm_pass "read-only-admin may read $op (Q10), and nothing changed"
            else
                pm_finding "read-only-admin is refused $op although Q10 allows it ($(pm_err "$a"))"
            fi
        elif pm_unauth "$a" "$role" && [ "$before" != "<error>" ] && [ "$before" = "$after" ]; then
            pm_pass "$role is refused $op as unauthorized$([ "$kind" = write ] && echo ', and nothing changed')"
        elif pm_ok "$a" || [ "$before" != "$after" ]; then
            case "$role" in
            plain-user) pm_finding "PLAIN USER ALLOWED $op ($(pm_err "$a"))" ;;
            no-session) pm_finding "NO SESSION ALLOWED $op ($(pm_err "$a"))" ;;
            *) pm_finding "READ-ONLY ADMIN ALLOWED $op ($(pm_err "$a"))" ;;
            esac
        else
            pm_finding "$role on $op: refused, but not as unauthorized ($(pm_err "$a"))"
        fi
    done
    if [ "$role" = admin ]; then
        a="$(pm_q "$tok" 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' "p=i:$scratch")"
        pm_row "$(pm_ok "$a" && echo 0 || echo 1)" "admin may deletePolicy" "$(pm_err "$a")"
        pm_q "$TOKEN" 'mutation($o: String!) { setOuPolicyInheritance(ou: $o, blocked: false) { ok } }' "o=$PM_B" >/dev/null
        pm_q "$TOKEN" 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' "o=$PM_B" >/dev/null
        pm_q "$TOKEN" 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' "o=$PM_A" "p=i:$PM_CYCLE" >/dev/null
    fi
}

pm_cleanup() {
    local id a left
    pm_q "$TOKEN" 'mutation($u: [String!]!) { changeUserOu(userIds: $u, newOu: "people") { ok } }' "u=j:[\"$PM_USER\"]" >/dev/null
    pm_restore_root
    a="$(pm_q "$TOKEN" '{ policies { id name } }')"
    for id in "${PM_IDS[@]}" $(PMA="$a" PMR="$PM_RUN" python3 -c '
import json, os
for p in (json.loads(os.environ["PMA"]).get("data") or {}).get("policies") or []:
    if os.environ["PMR"] in p["name"]:
        print(p["id"])'); do
        [ -n "$id" ] && pm_q "$TOKEN" 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' "p=i:$id" >/dev/null
    done
    for u in "$PM_RO" "$PM_USER"; do pm_q "$TOKEN" 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' "u=$u" >/dev/null; done
    [ -n "${PM_GID:-}" ] && pm_q "$TOKEN" 'mutation($g: Int!) { deleteGroup(groupId: $g) { ok } }' "g=i:$PM_GID" >/dev/null
    for ou in "$PM_NEST" "$PM_A" "$PM_B" "$PM_C"; do
        pm_q "$TOKEN" 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' "o=$ou" >/dev/null
        pm_q "$TOKEN" 'mutation($o: String!) { setOuPolicyInheritance(ou: $o, blocked: false) { ok } }' "o=$ou" >/dev/null
        pm_q "$TOKEN" 'mutation($n: String!) { deleteOu(name: $n) { ok } }' "n=$ou" >/dev/null
    done
    left="$(pm_state)"
    if [ "$left" = "<error>" ] || grep -q "$PM_RUN" <<<"$left"; then p_bad "cleanup left $PM_RUN policies or OU states behind (or the state could not be read)"; fi
    [ "$(pm_states_of "")" = "$PM_ROOT_BEFORE" ] || p_bad "the root's policy state was not restored (before: $PM_ROOT_BEFORE)"
}

if pm_setup; then
    pm_catalog
    if pm_items_cycle; then
        pm_bad_values
        pm_names
        pm_attach
        pm_nesting
        pm_delete_attached
        pm_ou_delete
        pm_unregistered
        pm_move
        pm_authz admin "$TOKEN"
        pm_authz read-only-admin "$PM_RO_TOKEN"
        pm_authz plain-user "$PM_USER_TOKEN"
        pm_authz no-session ""
    fi
fi
pm_cleanup
note "--- policy-matrix FINDING rows ---"
for f in "${PM_FIND_CAPS[@]}" "${PM_FIND[@]}"; do note "[FINDING] ${PHASE}: $f"; done
note "policy-matrix: $PM_N rows, $PM_P pass, $PM_F FINDING, $PM_K NOTE"
