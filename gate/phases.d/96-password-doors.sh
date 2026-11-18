# shellcheck shell=bash
# Phase: password length at each door. The directory minimum is 8 to 128.
# Part A tries one character. A door that takes it is FINDING. A PASS names
# the door's sentence, not any refusal. Part B: K1 refuses a Kerberos policy on a
# directory user, 9 characters pass every door, pol-svc keeps its effect. add-pol is a
# counted SKIP until min-length is an OU policy. The two kadmin rows are
# re-scoped, see K1. The e-mail reset page follows after this revision has run.

D="$(phase_dir)"
DOOR="pwdoor"
WEB="pwweb"
ADD1="pwadd1"
DN="uid=${DOOR},ou=people,${BASE_DN}"
WEB_DN="uid=${WEB},ou=people,${BASE_DN}"
POL="pwpol"
ADDPOL="pwadd"
WEBPOL="pwweb"
SVC="pwsvc/gate.test"
SET_PW="mutation(\$id: String!, \$pw: String!) { setUserPassword(userId: \$id, password: \$pw) { ok } }"
OUT="$D/rows.txt"
: >"$OUT"
DOOR_SECRETS=""

w1_gen() {
    python3 -c 'import secrets,sys
n=int(sys.argv[1])
alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
print("".join(secrets.choice(alphabet) for _ in range(n)))' "$1"
}

w1_bind() { t ldapwhoami -x -H "$(ldap_url)" -D "$2" -w "$1" >/dev/null 2>&1; }
w1_kinit() { kinit_pw "$2@$REALM" "$1" >"$3" 2>&1; }

w1_clip() {
    TEXT="$1" python3 -c '
import os
secrets = {}
for secret in os.environ.get("DOOR_SECRETS", "").split("\n"):
    if len(secret) >= 4:
        secrets[secret] = "len=" + str(len(secret))
words = os.environ.get("TEXT", "").split()
print(" ".join(secrets.get(word, word) for word in words)[:300])
'
}

w1_file() {
    python3 -c '
import os, sys
lines = open(sys.argv[1], errors="replace").read().splitlines()
picked = [ln.strip() for ln in lines if ln.startswith("Result:") or ln.startswith("Additional")]
text = " | ".join(picked) if picked else " ".join(ln.strip() for ln in lines if ln.strip())
print(text)
' "$1" 2>/dev/null || true
}

w1_say() {
    local name="$1" kind="$2" answer="$3" tail="${4:-}"
    answer="$(w1_clip "$answer")"
    if [ -n "$tail" ]; then
        printf 'ROW %s %s %s | %s\n' "$name" "$kind" "$answer" "$tail" | tee -a "$OUT"
    else
        printf 'ROW %s %s %s\n' "$name" "$kind" "$answer" | tee -a "$OUT"
    fi
}

# kadmin stays on the old rule: a taken password is FINDING, a refusal that
# leaves the password is PASS. The row is re-scoped; see K1.
w1_short_row() {
    local name="$1" took="$2" answer="$3" stayed="$4"
    if [ "$CLASS" = both ] || [ "$CLASS" = split ] || [ "$CLASS" = kadmin ]; then
        w1_say "$name" FINDING "$answer" "$FOUR"
    elif [ "$took" -eq 0 ] && [ "$CLASS" = "$stayed" ]; then
        w1_say "$name" PASS "$answer" "$FOUR"
    else
        w1_say "$name" FAIL "$answer" "$FOUR"
    fi
}

# PASS requires the refusal sentence in the door's answer. Any other refusal is FAIL.
# A door that takes the password is FINDING.
w1_sentence_row() {
    local name="$1" took="$2" answer="$3" stayed="$4" sentence="$5" file="$6"
    if [ "$CLASS" = both ] || [ "$CLASS" = split ] || [ "$CLASS" = kadmin ]; then
        w1_say "$name" FINDING "$answer" "$FOUR"
    elif [ "$took" -eq 0 ] && [ "$CLASS" = "$stayed" ] && grep -q -F "$sentence" "$file"; then
        w1_say "$name" PASS "$answer" "$FOUR"
    else
        w1_say "$name" FAIL "$answer" "$FOUR"
    fi
}

w1_floor_row() {
    local name="$1" took="$2" answer="$3"
    if [ "$took" -eq 1 ] && [ "$CLASS" = both ]; then
        w1_say "$name" PASS "$answer" "$FOUR | a directory user's password rules are the directory's: the floor of 8 now, OU policy later"
    else
        w1_say "$name" FAIL "$answer" "$FOUR"
    fi
}

w1_refused_bind() {
    local name="$1" pol="$2" user="$3" pw="$4" dn="$5"
    if ! kadmin_q "addpol -minlength 12 -maxfailure 0 $pol" >"$D/addpol-${name}.log" 2>&1 \
        || grep -q " while " "$D/addpol-${name}.log"; then
        w1_say "$name" FAIL "addpol $pol failed (see addpol-${name}.log)"
    elif kadmin_protected "$user" "modprinc -policy $pol $user" "$D/modprinc-${name}.log" \
        && w1_bind "$pw" "$dn" && w1_kinit "$pw" "$user" "$D/kinit-${name}.log"; then
        w1_say "$name" PASS "modprinc -policy $pol $user refused with PROTECT_PRINCIPAL (Cannot change protected principal), nothing changes" "one access_denied, protocol KADMIN, actor admin/admin@$REALM"
    else
        w1_say "$name" FAIL "${KP_WHY:-bind or kinit lost the password} (see modprinc-${name}.log)"
    fi
}

w1_svc() {
    local kv now old=no new=no
    kadmin_q "addprinc -pw $LONG_SVC $SVC" >"$D/svc-add.log" 2>&1
    kadmin_q "modprinc -policy $POL $SVC" >"$D/svc-modprinc.log" 2>&1
    if grep -q " while " "$D/svc-add.log" "$D/svc-modprinc.log" || ! w1_bound "$SVC" "$POL" "$D/svc-getprinc.txt"; then
        w1_say pol-svc FAIL "the control: $POL is not on $SVC (see svc-add.log, svc-modprinc.log, svc-getprinc.txt)"
        return
    fi
    kv="$(kadmin_q "getprinc $SVC" 2>/dev/null | awk '/Key: vno/ {print $3; exit}' | tr -d ',')"
    kadmin_q "cpw -pw $NINE_SVC $SVC" >"$D/pol-svc.log" 2>&1
    now="$(kadmin_q "getprinc $SVC" 2>/dev/null | awk '/Key: vno/ {print $3; exit}' | tr -d ',')"
    if w1_kinit "$LONG_SVC" "$SVC" "$D/kinit-pol-svc-old.log"; then old=yes; fi
    if w1_kinit "$NINE_SVC" "$SVC" "$D/kinit-pol-svc-new.log"; then
        new=yes
    elif grep -q "Password incorrect" "$D/kinit-pol-svc-new.log"; then
        new=incorrect
    fi
    if grep -q "Password is too short" "$D/pol-svc.log" && [ -n "$kv" ] && [ "$now" = "$kv" ] \
        && [ "$old $new" = "yes incorrect" ]; then
        w1_say pol-svc PASS "len=${#NINE_SVC} Password is too short" "kvno=$kv kinit-old=yes kinit-new=incorrect | $POL (min 12) on the unsynced $SVC; a directory user's password rules are the directory's (the floor of 8 now, OU policy later)"
    else
        w1_say pol-svc FAIL "len=${#NINE_SVC} $(w1_file "$D/pol-svc.log")" "kvno=${kv:-none}->${now:-none} kinit-old=$old kinit-new=$new"
    fi
}

# kadmin -q exits 0 when the change is refused. The refusal names the principal.
w1_kadmin_refused() {
    grep -q " while changing password for " "$1"
}

w1_summary() {
    local rows=0 pass=0 finding=0 notes=0 skips=0
    if [ -s "$OUT" ]; then
        rows="$(grep -c '^ROW ' "$OUT" || true)"
        pass="$(grep -c '^ROW [^ ]* PASS' "$OUT" || true)"
        finding="$(grep -c '^ROW [^ ]* FINDING' "$OUT" || true)"
        notes="$(grep -c '^ROW [^ ]* NOTE' "$OUT" || true)"
        skips="$(grep -c '^ROW [^ ]* SKIP' "$OUT" || true)"
    fi
    note "W1 rows=${rows} pass=${pass} FINDING=${finding} NOTE=${notes} SKIP=${skips}"
}

w1_judge() {
    local name="$1" line
    line="$(grep "^ROW ${name} " "$OUT" 2>/dev/null | head -1 || true)"
    case "$line" in
    "ROW ${name} PASS"*) p_ok "${name}: ${line#ROW "${name}" PASS }" ;;
    "ROW ${name} FINDING"*) note "FINDING ${name}: ${line#ROW "${name}" FINDING }" ;;
    "ROW ${name} NOTE"*) note "NOTE ${name}: ${line#ROW "${name}" NOTE }" ;;
    "ROW ${name} SKIP"*) p_skip "${name}: ${line#ROW "${name}" SKIP }" ;;
    "") p_bad "${name}: not reached" ;;
    *) p_bad "${name}: ${line#ROW "${name}" }" ;;
    esac
}

w1_vars() {
    ID="$1" PW="$2" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "pw": os.environ["PW"]}))'
}

w1_graphql() {
    GQ_URL="$(http_url)/api/graphql" GQ_TOKEN="$TOKEN" GQ_QUERY="$1" GQ_VARS="${2:-{\}}" \
        t python3 - <<'PY'
import json, os, sys, urllib.error, urllib.request
req = urllib.request.Request(
    os.environ["GQ_URL"],
    data=json.dumps({"query": os.environ["GQ_QUERY"],
                     "variables": json.loads(os.environ["GQ_VARS"])}).encode(),
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer " + os.environ["GQ_TOKEN"]})
try:
    resp = urllib.request.urlopen(req)
except urllib.error.HTTPError as err:
    body = err.read().decode("utf-8", "replace")
    sys.exit("HTTP %s: %s" % (err.code, body))
body = json.load(resp)
if body.get("errors"):
    sys.exit("GraphQL error: " + json.dumps(body["errors"]))
json.dump(body["data"], sys.stdout)
PY
}

w1_set() {
    w1_graphql "$SET_PW" "$(w1_vars "$1" "$2")" >"$3" 2>"$4"
}

w1_sides() {
    local new="$1" dir_old="$2" krb_old="$3" user="$4" dn="$5" tag="$6"
    local bn=no bo=no kn=other ko=other
    if w1_bind "$new" "$dn"; then bn=yes; fi
    if w1_bind "$dir_old" "$dn"; then bo=yes; fi
    if w1_kinit "$new" "$user" "$D/kinit-${tag}-new.log"; then
        kn=yes
    elif grep -q "Password incorrect" "$D/kinit-${tag}-new.log"; then
        kn=incorrect
    fi
    if w1_kinit "$krb_old" "$user" "$D/kinit-${tag}-old.log"; then
        ko=yes
    elif grep -q "Password incorrect" "$D/kinit-${tag}-old.log"; then
        ko=incorrect
    fi
    FOUR="bind-new=${bn} bind-old=${bo} kinit-new=${kn} kinit-old=${ko}"
    case "$FOUR" in
    "bind-new=yes bind-old=no kinit-new=yes kinit-old=incorrect") CLASS="both" ;;
    "bind-new=no bind-old=yes kinit-new=incorrect kinit-old=yes") CLASS="stay" ;;
    "bind-new=no bind-old=yes kinit-new=yes kinit-old=incorrect") CLASS="kadmin" ;;
    "bind-new=yes bind-old=no kinit-new=incorrect kinit-old=yes") CLASS="split" ;;
    "bind-new=no bind-old=no kinit-new=incorrect kinit-old=yes") CLASS="absent" ;;
    *) CLASS="bad" ;;
    esac
}

w1_track() {
    case "$CLASS" in
    both) dir_pw="$1"; krb_pw="$1" ;;
    kadmin) krb_pw="$1" ;;
    split) dir_pw="$1" ;;
    esac
}

w1_bound() {
    local user="$1" pol="$2" file="$3"
    kadmin_q "getprinc $user" >"$file" 2>&1 \
        && grep -q "^Policy: ${pol}$" "$file"
}

w1_princ_state() {
    local id="$1" file="$2"
    kadmin_q "getprinc $id" >"$file" 2>&1 || true
    if grep -q "^Principal: ${id}@$REALM" "$file"; then
        printf 'present\n'
    elif grep -q "Principal does not exist" "$file"; then
        printf 'absent\n'
    else
        printf 'error\n'
    fi
}

w1_user_absent() {
    local id="$1" file="$2"
    lsearch -b "uid=${id},ou=people,${BASE_DN}" -s base dn >"$file" 2>&1 || true
    if grep -q "^dn:" "$file"; then
        return 1
    fi
    grep -q "No such object" "$file"
}

w1_wait_gone() {
    local id="$1" i state
    for i in $(seq 1 10); do
        state="$(w1_princ_state "$id" "$D/gone-${id}-${i}.txt")"
        if [ "$state" = absent ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

w1_drop_user() {
    local id="$1" state
    if ! w1_user_absent "$id" "$D/exists-${id}.txt"; then
        w1_graphql "mutation(\$id: String!) { deleteUser(userId: \$id) { ok } }" \
            '{"id": "'"$id"'"}' >"$D/delete-${id}.json" 2>&1 || p_bad "deleteUser ${id} failed"
    fi
    if w1_user_absent "$id" "$D/user-gone-${id}.txt"; then
        note "directory user ${id} is gone"
    else
        p_bad "directory user ${id} is still present, or the search did not say No such object"
    fi
    state="$(w1_princ_state "$id" "$D/pregone-${id}.txt")"
    if [ "$state" = present ]; then
        if ! w1_wait_gone "$id"; then
            kadmin_q "delprinc -force $id" >"$D/delprinc-${id}.log" 2>&1 || p_bad "delprinc ${id} failed"
            w1_wait_gone "$id" || p_bad "principal ${id} survived deletion"
        fi
    elif [ "$state" = error ]; then
        p_bad "getprinc ${id} did not say whether the principal exists"
        return
    fi
    state="$(w1_princ_state "$id" "$D/final-${id}.txt")"
    if [ "$state" = absent ]; then
        note "principal ${id} is gone"
    else
        p_bad "principal ${id} is not confirmed gone"
    fi
}

w1_drop_pol() {
    local pol="$1"
    kadmin_q "getpol $pol" >"$D/getpol-before-${pol}.txt" 2>&1 || true
    if grep -q "^Policy: ${pol}$" "$D/getpol-before-${pol}.txt"; then
        kadmin_q "delpol -force $pol" >"$D/delpol-${pol}.log" 2>&1 || p_bad "delpol ${pol} failed"
        kadmin_q "getpol $pol" >"$D/getpol-${pol}.txt" 2>&1 || true
        if grep -q "Policy does not exist" "$D/getpol-${pol}.txt"; then
            note "policy ${pol} is gone"
        else
            p_bad "policy ${pol} still answers getpol"
        fi
    elif grep -q "Policy does not exist" "$D/getpol-before-${pol}.txt"; then
        note "policy ${pol} is gone"
    else
        p_bad "getpol ${pol} did not say whether the policy exists"
    fi
}

w1_create() {
    local id="$1"
    # $u belongs to the GraphQL query.
    # shellcheck disable=SC2016
    w1_graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$id"'", "email": "'"$id"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
        >"$D/create-${id}.json" 2>&1
}

w1_fresh() {
    local n="$1" avoid="$2" drawn="" i
    for i in $(seq 1 20); do
        drawn="$(w1_gen "$n")"
        if [ -n "$drawn" ] && [ "$drawn" != "$avoid" ]; then
            printf '%s\n' "$drawn"
            return 0
        fi
    done
    return 1
}

LONG="$(w1_gen 24)"
ONE_GQL="$(w1_fresh 1 "$LONG" || true)"
ONE_MOD="$(w1_fresh 1 "$ONE_GQL" || true)"
ONE_REPL="$(w1_fresh 1 "$ONE_MOD" || true)"
ONE_TOOL="$(w1_fresh 1 "$ONE_REPL" || true)"
ONE_KADM="$(w1_fresh 1 "$ONE_REPL" || true)"
LONG2="$(w1_gen 24)"
NINE_GQL="$(w1_gen 9)"
NINE_MOD="$(w1_gen 9)"
NINE_REPL="$(w1_gen 9)"
NINE_TOOL="$(w1_gen 9)"
NINE_KADM="$(w1_gen 9)"
ONE_ADD="$(w1_gen 1)"
ADD_GOOD="$(w1_gen 24)"
LONG_WEB="$(w1_gen 24)"
ONE_WEB="$(w1_gen 1)"
NINE_WEB="$(w1_gen 9)"
LONG_SVC="$(w1_gen 24)"
NINE_SVC="$(w1_gen 9)"
DOOR_SECRETS="$(printf '%s\n' "$LONG" "$ONE_GQL" "$ONE_MOD" "$ONE_REPL" "$ONE_TOOL" "$ONE_KADM" \
    "$LONG2" "$NINE_GQL" "$NINE_MOD" "$NINE_REPL" "$NINE_TOOL" "$NINE_KADM" \
    "$ONE_ADD" "$ADD_GOOD" "$LONG_WEB" "$ONE_WEB" "$NINE_WEB" "$LONG_SVC" "$NINE_SVC")"
export DOOR_SECRETS

if [ -z "$LONG" ] || [ -z "$ONE_GQL" ] || [ -z "$ONE_MOD" ] || [ -z "$ONE_REPL" ] \
    || [ -z "$ONE_TOOL" ] || [ -z "$ONE_KADM" ] || [ -z "$NINE_GQL" ] || [ -z "$LONG_WEB" ] \
    || [ -z "$ADD_GOOD" ] || [ "${#ADD_GOOD}" -ne 24 ] || [ "${#LONG_SVC}" -ne 24 ] || [ "${#NINE_SVC}" -ne 9 ] \
    || [ "${#ONE_GQL}" -ne 1 ] || [ "${#NINE_GQL}" -ne 9 ] \
    || [ "$ONE_MOD" = "$ONE_GQL" ] || [ "$ONE_REPL" = "$ONE_MOD" ] \
    || [ "$ONE_TOOL" = "$ONE_REPL" ] || [ "$ONE_KADM" = "$ONE_REPL" ]; then
    p_bad "generated password is empty or the wrong length"
    unset DOOR_SECRETS
    w1_summary
    return 0
fi

dir_pw="$LONG"
krb_pw="$LONG"
TOKEN="$(gate_login)" || p_bad "could not log in again before the password doors"
export TOKEN
w1_create "$DOOR" || p_bad "createUser $DOOR failed"
w1_set "$DOOR" "$LONG" "$D/set-init.json" "$D/set-init.err" || p_bad "initial setUserPassword $DOOR failed"
w1_sides "$LONG" "$ONE_GQL" "$ONE_GQL" "$DOOR" "$DN" init
if [ "$CLASS" != both ]; then
    p_bad "initial password does not bind and kinit ($FOUR)"
fi

gql_code=0
if w1_set "$DOOR" "$ONE_GQL" "$D/one-graphql.json" "$D/one-graphql.err"; then
    gql_code=0
else
    gql_code=$?
fi
gql_answer="exit=${gql_code} len=${#ONE_GQL} $(w1_file "$D/one-graphql.json") $(w1_file "$D/one-graphql.err")"
w1_sides "$ONE_GQL" "$dir_pw" "$krb_pw" "$DOOR" "$DN" one-graphql
took=0
if [ "$gql_code" -eq 0 ]; then took=1; fi
w1_sentence_row one-graphql "$took" "$gql_answer" stay \
    "the password must be at least 8 characters" "$D/one-graphql.err"
w1_track "$ONE_GQL"

ldap_code=0
if t ldappasswd -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" -s "$ONE_MOD" "$DN" \
    >"$D/one-modify.log" 2>&1; then
    ldap_code=0
else
    ldap_code=$?
fi
ldap_answer="exit=${ldap_code} len=${#ONE_MOD} $(w1_file "$D/one-modify.log")"
w1_sides "$ONE_MOD" "$dir_pw" "$krb_pw" "$DOOR" "$DN" one-modify
took=0
if [ "$ldap_code" -eq 0 ]; then took=1; fi
w1_sentence_row one-modify "$took" "$ldap_answer" stay \
    "the password must be at least 8 characters" "$D/one-modify.log"
w1_track "$ONE_MOD"

cat >"$D/one-replace.ldif" <<EOF
dn: $DN
changetype: modify
replace: userPassword
userPassword: $ONE_REPL
EOF
ldap_code=0
if lmodify -f "$D/one-replace.ldif" >"$D/one-replace.log" 2>&1; then
    ldap_code=0
else
    ldap_code=$?
fi
ldap_answer="exit=${ldap_code} len=${#ONE_REPL} $(w1_file "$D/one-replace.log")"
w1_sides "$ONE_REPL" "$dir_pw" "$krb_pw" "$DOOR" "$DN" one-replace
took=0
if [ "$ldap_code" -eq 0 ]; then took=1; fi
w1_sentence_row one-replace "$took" "$ldap_answer" stay \
    "the password must be at least 8 characters" "$D/one-replace.log"
w1_track "$ONE_REPL"

tool_code=0
if gexec /app/lldap_set_password --base-url http://127.0.0.1:17170 --token "$TOKEN" \
    --username "$DOOR" --password "$ONE_TOOL" >"$D/one-tool.log" 2>&1; then
    tool_code=0
else
    tool_code=$?
fi
tool_answer="exit=${tool_code} len=${#ONE_TOOL} $(w1_file "$D/one-tool.log")"
w1_sides "$ONE_TOOL" "$dir_pw" "$krb_pw" "$DOOR" "$DN" one-tool
took=0
if [ "$tool_code" -eq 0 ]; then took=1; fi
w1_sentence_row one-tool "$took" "$tool_answer" stay \
    "New password is too short, expected at least 8 characters" "$D/one-tool.log"
w1_track "$ONE_TOOL"

kadm_code=0
if kadmin_q "cpw -pw $ONE_KADM $DOOR" >"$D/one-kadmin.log" 2>&1; then
    kadm_code=0
else
    kadm_code=$?
fi
kadm_answer="exit=${kadm_code} len=${#ONE_KADM} $(w1_file "$D/one-kadmin.log")"
w1_sides "$ONE_KADM" "$dir_pw" "$krb_pw" "$DOOR" "$DN" one-kadmin
took=0
if [ "$kadm_code" -eq 0 ] && ! w1_kadmin_refused "$D/one-kadmin.log"; then
    took=1
fi
w1_short_row one-kadmin "$took" "${kadm_answer:-cpw}" stay
note "one-kadmin: re-scoped, see K1"
w1_track "$ONE_KADM"

if w1_set "$DOOR" "$LONG2" "$D/align.json" "$D/align.err"; then
    w1_sides "$LONG2" "$dir_pw" "$krb_pw" "$DOOR" "$DN" align
    if [ "$CLASS" = both ]; then
        dir_pw="$LONG2"
        krb_pw="$LONG2"
        note "passwords aligned before the policy"
    else
        p_bad "could not align the directory and Kerberos passwords ($FOUR)"
    fi
else
    p_bad "could not align the directory and Kerberos passwords before the policy"
fi

w1_refused_bind pol-bind "$POL" "$DOOR" "$dir_pw" "$DN"

gql_code=0
if w1_set "$DOOR" "$NINE_GQL" "$D/pol-graphql.json" "$D/pol-graphql.err"; then
    gql_code=0
else
    gql_code=$?
fi
gql_answer="exit=${gql_code} len=${#NINE_GQL} $(w1_file "$D/pol-graphql.err") $(w1_file "$D/pol-graphql.json")"
w1_sides "$NINE_GQL" "$dir_pw" "$krb_pw" "$DOOR" "$DN" pol-graphql
took=0
if [ "$gql_code" -eq 0 ]; then took=1; fi
w1_floor_row pol-graphql "$took" "$gql_answer"
w1_track "$NINE_GQL"

ldap_code=0
if t ldappasswd -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" -s "$NINE_MOD" "$DN" \
    >"$D/pol-modify.log" 2>&1; then
    ldap_code=0
else
    ldap_code=$?
fi
ldap_answer="exit=${ldap_code} len=${#NINE_MOD} $(w1_file "$D/pol-modify.log")"
w1_sides "$NINE_MOD" "$dir_pw" "$krb_pw" "$DOOR" "$DN" pol-modify
took=0
if [ "$ldap_code" -eq 0 ]; then took=1; fi
w1_floor_row pol-modify "$took" "$ldap_answer"
w1_track "$NINE_MOD"

cat >"$D/pol-replace.ldif" <<EOF
dn: $DN
changetype: modify
replace: userPassword
userPassword: $NINE_REPL
EOF
ldap_code=0
if lmodify -f "$D/pol-replace.ldif" >"$D/pol-replace.log" 2>&1; then
    ldap_code=0
else
    ldap_code=$?
fi
ldap_answer="exit=${ldap_code} len=${#NINE_REPL} $(w1_file "$D/pol-replace.log")"
w1_sides "$NINE_REPL" "$dir_pw" "$krb_pw" "$DOOR" "$DN" pol-replace
took=0
if [ "$ldap_code" -eq 0 ]; then took=1; fi
w1_floor_row pol-replace "$took" "$ldap_answer"
w1_track "$NINE_REPL"

tool_code=0
if gexec /app/lldap_set_password --base-url http://127.0.0.1:17170 --token "$TOKEN" \
    --username "$DOOR" --password "$NINE_TOOL" >"$D/pol-tool.log" 2>&1; then
    tool_code=0
else
    tool_code=$?
fi
tool_answer="exit=${tool_code} len=${#NINE_TOOL} $(w1_file "$D/pol-tool.log")"
w1_sides "$NINE_TOOL" "$dir_pw" "$krb_pw" "$DOOR" "$DN" pol-tool
took=0
if [ "$tool_code" -eq 0 ]; then took=1; fi
w1_floor_row pol-tool "$took" "$tool_answer"
w1_track "$NINE_TOOL"

kadm_code=0
if kadmin_q "cpw -pw $NINE_KADM $DOOR" >"$D/pol-kadmin.log" 2>&1; then
    kadm_code=0
else
    kadm_code=$?
fi
kadm_answer="exit=${kadm_code} len=${#NINE_KADM} $(w1_file "$D/pol-kadmin.log")"
w1_sides "$NINE_KADM" "$dir_pw" "$krb_pw" "$DOOR" "$DN" pol-kadmin
took=0
if [ "$kadm_code" -eq 0 ] && ! w1_kadmin_refused "$D/pol-kadmin.log"; then
    took=1
fi
w1_floor_row pol-kadmin "$took" "$kadm_answer"
w1_track "$NINE_KADM"

w1_svc

w1_drop_user "$DOOR"
kadmin_q "delprinc -force $SVC" >"$D/svc-del.log" 2>&1 || true
kadmin_q "getprinc $SVC" >"$D/svc-gone.txt" 2>&1 || true
if grep -q "Principal does not exist" "$D/svc-gone.txt"; then
    note "principal $SVC is gone"
else
    p_bad "principal $SVC is not confirmed gone (see svc-del.log, svc-gone.txt)"
fi
w1_drop_pol "$POL"

w1_add() {
    local user="$1" pw="$2" file="$3"
    cat >"$file" <<EOF
dn: uid=${user},ou=people,${BASE_DN}
changetype: add
objectClass: inetOrgPerson
objectClass: person
uid: ${user}
mail: ${user}@gate.test
cn: ${user}
sn: ${user}
userPassword: ${pw}
kerberossync: 1
EOF
}

w1_add "$ADD1" "$ONE_ADD" "$D/add-one.ldif"
ldap_code=0
if lmodify -f "$D/add-one.ldif" >"$D/add-one.log" 2>&1; then
    ldap_code=0
else
    ldap_code=$?
fi
ldap_answer="exit=${ldap_code} len=${#ONE_ADD} $(w1_file "$D/add-one.log")"
w1_sides "$ONE_ADD" "$LONG" "$LONG" "$ADD1" "uid=${ADD1},ou=people,${BASE_DN}" add-one
took=0
if [ "$ldap_code" -eq 0 ]; then took=1; fi
if [ "$ldap_code" -eq 53 ] \
    && grep -q -F "the password must be at least 8 characters" "$D/add-one.log" \
    && w1_user_absent "$ADD1" "$D/add-one-absent.txt" \
    && grep -q "not found in Kerberos database" "$D/kinit-add-one-new.log" \
    && grep -q "not found in Kerberos database" "$D/kinit-add-one-old.log"; then
    w1_say add-one PASS "$ldap_answer" "$FOUR"
elif [ "$took" -eq 1 ]; then
    w1_say add-one FINDING "$ldap_answer" "$FOUR"
else
    w1_say add-one FAIL "$ldap_answer" "$FOUR"
fi
w1_drop_user "$ADD1"
w1_add "$ADD1" "$ADD_GOOD" "$D/add-good.ldif"
if lmodify -f "$D/add-good.ldif" >"$D/add-good.log" 2>&1 \
    && ! w1_user_absent "$ADD1" "$D/add-good-present.txt" \
    && w1_bind "$ADD_GOOD" "uid=${ADD1},ou=people,${BASE_DN}"; then
    note "add-one control: a ${#ADD_GOOD}-character add binds"
else
    p_bad "add-one control: a good password did not add and bind (see add-good.log)"
fi
rm -f "$D/add-one.ldif" "$D/add-good.ldif"
w1_drop_user "$ADD1"

w1_say add-pol SKIP "min-length is not an OU policy yet"
w1_drop_pol "$ADDPOL"

BROWSER_IMAGE="mcr.microsoft.com/playwright@sha256:766137e2d9caad4744187e53cdc89320ba6f2eb57cff097374020944b44dd0a9"
BROWSER_CTN="klldap-pwpage-${RUNID}"
w1_browser() {
    local mode="$1" pass="$2"
    docker rm -f "$BROWSER_CTN" >/dev/null 2>&1 || true
    (
        export BROWSER_ADMIN_PASS="$ADMIN_PASS"
        export BROWSER_PASS="$pass"
        timeout 180 docker run --rm --name "$BROWSER_CTN" \
            --network "$NET" \
            --init \
            --shm-size=1g \
            --user "$(id -u):$(id -g)" \
            --entrypoint node \
            -v "$GATE_ROOT/lib/change-password.mjs:/work/change-password.mjs:ro" \
            -v "$D:/out" \
            -e HOME=/tmp/home \
            -e BROWSER_OUT=/out \
            -e BROWSER_MODE="$mode" \
            -e BROWSER_URL="http://${CONTAINER}:17170" \
            -e BROWSER_USER="$WEB" \
            -e BROWSER_ADMIN_PASS \
            -e BROWSER_PASS \
            "$BROWSER_IMAGE" /work/change-password.mjs \
            >"$D/${mode}.out" 2>"$D/${mode}.err"
    )
}

if ! docker image inspect "$BROWSER_IMAGE" >/dev/null 2>&1; then
    p_skip "browser image absent; the change-password page was not run"
else
    EXTRA_CONTAINERS+=("$BROWSER_CTN")
    w1_create "$WEB" || p_bad "createUser $WEB failed"
    w1_set "$WEB" "$LONG_WEB" "$D/web-set.json" "$D/web-set.err" || p_bad "initial setUserPassword $WEB failed"
    w1_browser web-one "$ONE_WEB" || true
    page="$(grep '^PAGE web-one ' "$D/web-one.out" 2>/dev/null | head -1 || true)"
    w1_sides "$ONE_WEB" "$LONG_WEB" "$LONG_WEB" "$WEB" "$WEB_DN" web-one
    if [ -z "$page" ]; then
        w1_say web-one FAIL "len=${#ONE_WEB} the browser did not print a PAGE line" "$FOUR"
    elif [ "$CLASS" = stay ] && printf '%s\n' "$page" | grep -q "Invalid password. Min length: 8"; then
        w1_say web-one PASS "len=${#ONE_WEB} ${page#PAGE web-one }" "$FOUR"
    elif [ "$CLASS" = both ] || [ "$CLASS" = split ]; then
        w1_say web-one FINDING "len=${#ONE_WEB} ${page#PAGE web-one }" "$FOUR"
    else
        w1_say web-one FAIL "len=${#ONE_WEB} ${page#PAGE web-one }" "$FOUR"
    fi
    w1_refused_bind web-pol-bind "$WEBPOL" "$WEB" "$LONG_WEB" "$WEB_DN"
    wire_page web-pol change "$WEB" "$NINE_WEB"
    w1_sides "$NINE_WEB" "$LONG_WEB" "$LONG_WEB" "$WEB" "$WEB_DN" web-pol
    if [ "$WIRE_LINE" = "WIRE start-key=yes finish-envelope=yes rewrite=none finish-status=200 graphql-seal=no create-sent=no page=done" ] \
        && [ "$CLASS" = both ]; then
        w1_say web-pol PASS "len=${#NINE_WEB} $WIRE_LINE" "$FOUR | a directory user's password rules are the directory's: the floor of 8 now, OU policy later"
    else
        w1_say web-pol FAIL "len=${#NINE_WEB} $WIRE_LINE ${WIRE_ALERT:+alert: $WIRE_ALERT}" "$FOUR"
    fi
    w1_drop_user "$WEB"
    w1_drop_pol "$WEBPOL"
    docker rm -f "$BROWSER_CTN" >/dev/null 2>&1 || true
fi

w1_judge one-graphql
w1_judge one-modify
w1_judge one-replace
w1_judge one-tool
w1_judge one-kadmin
w1_judge pol-bind
w1_judge pol-graphql
w1_judge pol-modify
w1_judge pol-replace
w1_judge pol-tool
w1_judge pol-kadmin
w1_judge pol-svc
w1_judge add-one
w1_judge add-pol
if docker image inspect "$BROWSER_IMAGE" >/dev/null 2>&1; then
    w1_judge web-one
    w1_judge web-pol-bind
    w1_judge web-pol
fi
unset DOOR_SECRETS
w1_summary
