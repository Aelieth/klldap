# shellcheck shell=bash
# Phase: password length at each door. Part A uses one character.
# Part B binds a Kerberos policy of minimum length 12 and maximum failure 0,
# then tries nine characters. The e-mail reset page follows after this revision has run.

D="$(phase_dir)"
DOOR="pwdoor"
WEB="pwweb"
ADD1="pwadd1"
ADD2="pwadd2"
DN="uid=${DOOR},ou=people,${BASE_DN}"
WEB_DN="uid=${WEB},ou=people,${BASE_DN}"
POL="pwpol"
ADDPOL="pwadd"
WEBPOL="pwweb"
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
    if secret:
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

w1_summary() {
    local rows=0 pass=0 finding=0 notes=0
    if [ -s "$OUT" ]; then
        rows="$(grep -c '^ROW ' "$OUT" || true)"
        pass="$(grep -c '^ROW [^ ]* PASS' "$OUT" || true)"
        finding="$(grep -c '^ROW [^ ]* FINDING' "$OUT" || true)"
        notes="$(grep -c '^ROW [^ ]* NOTE' "$OUT" || true)"
    fi
    note "W1 rows=${rows} pass=${pass} FINDING=${finding} NOTE=${notes}"
}

w1_judge() {
    local name="$1" line
    line="$(grep "^ROW ${name} " "$OUT" 2>/dev/null | head -1 || true)"
    case "$line" in
    "ROW ${name} PASS"*) p_ok "${name}: ${line#ROW "${name}" PASS }" ;;
    "ROW ${name} FINDING"*) note "FINDING ${name}: ${line#ROW "${name}" FINDING }" ;;
    "ROW ${name} NOTE"*) note "NOTE ${name}: ${line#ROW "${name}" NOTE }" ;;
    "") p_bad "${name}: not reached" ;;
    *) p_bad "${name}: ${line#ROW "${name}" }" ;;
    esac
}

w1_vars() {
    ID="$1" PW="$2" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "pw": os.environ["PW"]}))'
}

w1_set() {
    graphql "$SET_PW" "$(w1_vars "$1" "$2")" >"$3" 2>"$4"
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
        graphql "mutation(\$id: String!) { deleteUser(userId: \$id) { ok } }" \
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
    ID="$id" graphql "mutation(\$u: CreateUserInput!) { createUser(user: \$u) { id } }" \
        "$(python3 -c 'import json,os; print(json.dumps({"u": {"id": os.environ["ID"], "email": os.environ["ID"] + "@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}))')" \
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
ADD_OLD="$(w1_gen 24)"
NINE_ADD="$(w1_gen 9)"
LONG_WEB="$(w1_gen 24)"
ONE_WEB="$(w1_gen 1)"
NINE_WEB="$(w1_gen 9)"
DOOR_SECRETS="$(printf '%s\n' "$LONG" "$ONE_GQL" "$ONE_MOD" "$ONE_REPL" "$ONE_TOOL" "$ONE_KADM" \
    "$LONG2" "$NINE_GQL" "$NINE_MOD" "$NINE_REPL" "$NINE_TOOL" "$NINE_KADM" \
    "$ONE_ADD" "$ADD_OLD" "$NINE_ADD" "$LONG_WEB" "$ONE_WEB" "$NINE_WEB")"
export DOOR_SECRETS

if [ -z "$LONG" ] || [ -z "$ONE_GQL" ] || [ -z "$ONE_MOD" ] || [ -z "$ONE_REPL" ] \
    || [ -z "$ONE_TOOL" ] || [ -z "$ONE_KADM" ] || [ -z "$NINE_GQL" ] || [ -z "$LONG_WEB" ] \
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
if [ "$gql_code" -eq 0 ] && [ "$CLASS" = both ]; then
    w1_say one-graphql PASS "$gql_answer" "$FOUR"
else
    w1_say one-graphql FAIL "$gql_answer" "$FOUR"
fi
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
if [ "$ldap_code" -eq 0 ] && [ "$CLASS" = both ]; then
    w1_say one-modify PASS "${ldap_answer}" "$FOUR"
else
    w1_say one-modify FAIL "${ldap_answer}" "$FOUR"
fi
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
if [ "$ldap_code" -eq 0 ] && [ "$CLASS" = both ]; then
    w1_say one-replace PASS "${ldap_answer}" "$FOUR"
else
    w1_say one-replace FAIL "${ldap_answer}" "$FOUR"
fi
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
if [ "$tool_code" -ne 0 ] && grep -q "at least 8" "$D/one-tool.log" && [ "$CLASS" = stay ]; then
    w1_say one-tool PASS "${tool_answer}" "$FOUR"
else
    w1_say one-tool FAIL "${tool_answer}" "$FOUR"
fi
w1_track "$ONE_TOOL"

kadm_code=0
if kadmin_q "cpw -pw $ONE_KADM $DOOR" >"$D/one-kadmin.log" 2>&1; then
    kadm_code=0
else
    kadm_code=$?
fi
kadm_answer="exit=${kadm_code} len=${#ONE_KADM} $(w1_file "$D/one-kadmin.log")"
w1_sides "$ONE_KADM" "$dir_pw" "$krb_pw" "$DOOR" "$DN" one-kadmin
if [ "$kadm_code" -eq 0 ] && [ "$CLASS" = kadmin ]; then
    w1_say one-kadmin PASS "${kadm_answer:-cpw}" "$FOUR"
else
    w1_say one-kadmin FAIL "${kadm_answer:-cpw}" "$FOUR"
fi
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

bound=0
if kadmin_q "addpol -minlength 12 -maxfailure 0 $POL" >"$D/addpol.log" 2>&1 \
    && kadmin_q "modprinc -policy $POL $DOOR" >"$D/modprinc.log" 2>&1 \
    && w1_bound "$DOOR" "$POL" "$D/getprinc-policy.txt" \
    && kadmin_q "getpol $POL" >"$D/getpol-live.txt" 2>&1 \
    && grep -q "^Policy: ${POL}$" "$D/getpol-live.txt"; then
    bound=1
    note "policy $POL min length 12 max failure 0 is on $DOOR"
else
    p_bad "policy $POL is not on $DOOR (see getprinc-policy.txt)"
fi

if [ "$bound" -eq 1 ]; then
    gql_code=0
    if w1_set "$DOOR" "$NINE_GQL" "$D/pol-graphql.json" "$D/pol-graphql.err"; then
        gql_code=0
    else
        gql_code=$?
    fi
    gql_answer="exit=${gql_code} len=${#NINE_GQL} $(w1_file "$D/pol-graphql.err") $(w1_file "$D/pol-graphql.json")"
    w1_sides "$NINE_GQL" "$dir_pw" "$krb_pw" "$DOOR" "$DN" pol-graphql
    if grep -q "min_length 12" "$D/pol-graphql.err" && [ "$CLASS" = split ]; then
        w1_say pol-graphql FINDING "${gql_answer}" "$FOUR"
    elif grep -q "min_length" "$D/pol-graphql.err" && [ "$CLASS" = stay ]; then
        w1_say pol-graphql PASS "${gql_answer}" "$FOUR"
    else
        w1_say pol-graphql FAIL "${gql_answer}" "$FOUR"
    fi
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
    if [ "$ldap_code" -eq 0 ] && [ "$CLASS" = split ]; then
        w1_say pol-modify FINDING "${ldap_answer}" "$FOUR"
    elif [ "$ldap_code" -ne 0 ] && [ "$CLASS" = stay ]; then
        w1_say pol-modify PASS "${ldap_answer}" "$FOUR"
    else
        w1_say pol-modify FAIL "${ldap_answer}" "$FOUR"
    fi
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
    if [ "$ldap_code" -eq 0 ] && [ "$CLASS" = split ]; then
        w1_say pol-replace FINDING "${ldap_answer}" "$FOUR"
    elif [ "$ldap_code" -ne 0 ] && [ "$CLASS" = stay ]; then
        w1_say pol-replace PASS "${ldap_answer}" "$FOUR"
    else
        w1_say pol-replace FAIL "${ldap_answer}" "$FOUR"
    fi
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
    if [ "$tool_code" -eq 0 ] && [ "$CLASS" = split ]; then
        w1_say pol-tool NOTE "${tool_answer}" "$FOUR"
    else
        w1_say pol-tool FAIL "${tool_answer}" "$FOUR"
    fi
    w1_track "$NINE_TOOL"

    kadm_code=0
    if kadmin_q "cpw -pw $NINE_KADM $DOOR" >"$D/pol-kadmin.log" 2>&1; then
        kadm_code=0
    else
        kadm_code=$?
    fi
    kadm_answer="exit=${kadm_code} len=${#NINE_KADM} $(w1_file "$D/pol-kadmin.log")"
    w1_sides "$NINE_KADM" "$dir_pw" "$krb_pw" "$DOOR" "$DN" pol-kadmin
    if [ "$kadm_code" -ne 0 ] && [ "$CLASS" = stay ]; then
        w1_say pol-kadmin PASS "${kadm_answer}" "$FOUR"
    else
        w1_say pol-kadmin FAIL "${kadm_answer}" "$FOUR"
    fi
    w1_track "$NINE_KADM"
else
    w1_say pol-graphql FAIL "policy was not on the principal"
    w1_say pol-modify FAIL "policy was not on the principal"
    w1_say pol-replace FAIL "policy was not on the principal"
    w1_say pol-tool FAIL "policy was not on the principal"
    w1_say pol-kadmin FAIL "policy was not on the principal"
fi

w1_drop_user "$DOOR"
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
if [ "$ldap_code" -eq 0 ] && [ "$CLASS" = both ]; then
    w1_say add-one PASS "${ldap_answer}" "$FOUR"
else
    w1_say add-one FAIL "${ldap_answer}" "$FOUR"
fi
w1_drop_user "$ADD1"

if kadmin_q "addpol -minlength 12 -maxfailure 0 $ADDPOL" >"$D/add-pol-addpol.log" 2>&1 \
    && kadmin_q "addprinc -policy $ADDPOL -pw $ADD_OLD $ADD2" >"$D/addprinc.log" 2>&1 \
    && w1_bound "$ADD2" "$ADDPOL" "$D/getprinc-add.txt"; then
    w1_add "$ADD2" "$NINE_ADD" "$D/add-pol.ldif"
    ldap_code=0
    if lmodify -f "$D/add-pol.ldif" >"$D/add-pol.log" 2>&1; then
        ldap_code=0
    else
        ldap_code=$?
    fi
    ldap_answer="exit=${ldap_code} len=${#NINE_ADD} $(w1_file "$D/add-pol.log")"
    w1_sides "$NINE_ADD" "$ADD_OLD" "$ADD_OLD" "$ADD2" "uid=${ADD2},ou=people,${BASE_DN}" add-pol
    if [ "$ldap_code" -eq 0 ] && [ "$CLASS" = split ]; then
        w1_say add-pol FINDING "${ldap_answer}" "$FOUR"
    elif [ "$ldap_code" -ne 0 ] && [ "$CLASS" = absent ]; then
        w1_say add-pol PASS "${ldap_answer}" "$FOUR"
    else
        w1_say add-pol FAIL "${ldap_answer}" "$FOUR"
    fi
else
    w1_say add-pol FAIL "could not create the principal with policy $ADDPOL"
fi
w1_drop_user "$ADD2"
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
    if [ -n "$page" ] && [ "$CLASS" = stay ]; then
        w1_say web-one PASS "len=${#ONE_WEB} ${page#PAGE web-one }" "$FOUR"
    else
        w1_say web-one FAIL "len=${#ONE_WEB} ${page:-page}" "$FOUR"
    fi
    if kadmin_q "addpol -minlength 12 -maxfailure 0 $WEBPOL" >"$D/web-addpol.log" 2>&1 \
        && kadmin_q "modprinc -policy $WEBPOL $WEB" >"$D/web-modprinc.log" 2>&1 \
        && w1_bound "$WEB" "$WEBPOL" "$D/getprinc-web.txt"; then
        w1_browser web-pol "$NINE_WEB" || true
        page="$(grep '^PAGE web-pol ' "$D/web-pol.out" 2>/dev/null | head -1 || true)"
        w1_sides "$NINE_WEB" "$LONG_WEB" "$LONG_WEB" "$WEB" "$WEB_DN" web-pol
        if [ -n "$page" ] && [ "$CLASS" = split ]; then
            w1_say web-pol FINDING "len=${#NINE_WEB} ${page#PAGE web-pol }" "$FOUR"
        elif [ -n "$page" ] && [ "$CLASS" = stay ]; then
            w1_say web-pol PASS "len=${#NINE_WEB} ${page#PAGE web-pol }" "$FOUR"
        else
            w1_say web-pol FAIL "len=${#NINE_WEB} ${page:-page}" "$FOUR"
        fi
    else
        w1_say web-pol FAIL "policy $WEBPOL is not on $WEB"
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
w1_judge pol-graphql
w1_judge pol-modify
w1_judge pol-replace
w1_judge pol-tool
w1_judge pol-kadmin
w1_judge add-one
w1_judge add-pol
if docker image inspect "$BROWSER_IMAGE" >/dev/null 2>&1; then
    w1_judge web-one
    w1_judge web-pol
fi
unset DOOR_SECRETS
w1_summary
