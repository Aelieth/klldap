# shellcheck shell=bash
# Phase: TOTP second factor — the exempt group exists, enrollment over GraphQL, the
# password:code format at the LDAP and simple-login doors, replay refusal, the
# administrative reset, the log rows, and the two-factor pages driven in a browser.

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

PROOF="$(gate_enrollment_proof "$MFA_USER" "$MFA_PASS" 2>"$D/proof.err")" \
    || p_bad "enrollment proof failed (see proof.err)"
# shellcheck disable=SC2016
TOKEN="$USER_TOKEN" graphql 'mutation($p: String) { startMfaEnrollment(enrollmentProof: $p) { secretBase32 state } }' \
    '{"p": "'"$PROOF"'"}' \
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
    replayed="$(BINDFAIL="$D/bindfail.json" python3 - <<'PY'
import json, os
rows = json.load(open(os.environ["BINDFAIL"], encoding="utf-8")).get("logs") or []
print(sum(1 for row in rows if row.get("detail") == "totp replayed"))
PY
)"
    if [ "$replayed" -eq 1 ] && [ "$detail" = "totp code required" ]; then
        p_ok "one failed bind detail is 'totp replayed', and the newest is 'totp code required'"
    else
        p_bad "failed binds: newest '${detail:-empty}', totp replayed count ${replayed}"
    fi
else
    p_bad "no failed bind row for $MFA_USER"
fi
if log_query_has_row '{ logs(filter: {kinds: [MFA_RESET], actor: "admin"}) { kind detail } }' reset; then
    p_ok "mfa_reset row is in the log"
else
    p_bad "no mfa_reset row"
fi

# The pages, as the user: a first enrollment, the old one-field form, a wrong code, sign-in in
# two steps, a replacement, the change page and the own reset; each page's submit is sent
# twice in one tick, the second past the disabled button, so the page's own guard must stop
# it. Each WIRE line is what that row sent; no request may carry the password in any
# encoding, the page may not keep it, and nothing the page prints may show it.
MFA_BROWSER_IMAGE="mcr.microsoft.com/playwright@sha256:766137e2d9caad4744187e53cdc89320ba6f2eb57cff097374020944b44dd0a9"
MFA_BROWSER_CTN="klldap-mfa-pages-${RUNID}"
MFA_NEW_PASS="$(python3 -c 'import secrets; print("Gm" + secrets.token_hex(8))')"
MFA_TAIL="password-sent=no stored=no console-leak=no"
MFA_ROWS=(
    "mfa-login|two submits of Login in one tick sign in once with the password alone before enrolling|starts=1 finishes=1 sessionless=0 proof-asked=0 codes=0 statuses=200"
    "mfa-enrol|the enrollment page asks the password, has the server check it without a session, and enrolls; two submits in one tick start once, at each step|starts=2 finishes=2 sessionless=2 proof-asked=1 codes=0 statuses=200/200"
    "mfa-old-form|password:code in the password field fails as a wrong password, with the next-step hint, and sends no finish|starts=1 finishes=0 sessionless=0 proof-asked=0 codes=0 statuses=none"
    "mfa-wrong-code|a wrong code stays on the code step|starts=2 finishes=2 sessionless=0 proof-asked=0 codes=1 statuses=200/401"
    "mfa-signin|the code step signs in with a fresh start and the code; two submits of Verify in one tick start once|starts=1 finishes=1 sessionless=0 proof-asked=0 codes=1 statuses=200"
    "mfa-replace|replacing the factor takes the current code and checks the password without a session|starts=1 finishes=1 sessionless=1 proof-asked=0 codes=0 statuses=200"
    "mfa-change|the change page starts once with the whole old password, without a session, when submitted twice in one tick|starts=1 finishes=1 sessionless=1 proof-asked=0 codes=0 statuses=200"
    "mfa-reset|the reset page checks the password without a session, once when submitted twice in one tick|starts=1 finishes=1 sessionless=1 proof-asked=0 codes=0 statuses=200"
)

mfa_pages_run() {
    docker rm -f -v "$MFA_BROWSER_CTN" >/dev/null 2>&1 || true
    # -e NAME, not -e NAME=value, so the passwords are not on the host's command line.
    (
        export BROWSER_PASS="$MFA_PASS" BROWSER_NEW_PASS="$MFA_NEW_PASS"
        timeout 300 docker run --rm --name "$MFA_BROWSER_CTN" --network "$NET" --init --shm-size=1g \
            --user "$(id -u):$(id -g)" --entrypoint node \
            -v "$GATE_ROOT/lib/browser.mjs:/work/browser.mjs:ro" -v "$D:/out" \
            -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_MODE=mfa \
            -e BROWSER_URL="http://${CONTAINER}:17170" -e BROWSER_USER="$MFA_USER" \
            -e BROWSER_PASS -e BROWSER_NEW_PASS \
            "$MFA_BROWSER_IMAGE" /work/browser.mjs >"$D/mfa-pages.out" 2>"$D/mfa-pages.err"
    )
    docker rm -f -v "$MFA_BROWSER_CTN" >/dev/null 2>&1 || true
}

# mfa_rows_with <detail>: the user's login rows with that detail, polled while the writer lingers.
mfa_rows_with() {
    local want="$1" got=-1
    for _ in $(seq 1 20); do
        got="$(log_rows "kind = 'login' AND actor = '$MFA_USER' AND detail = '$want'")"
        [ "$got" = "$2" ] && break
        sleep 0.5
    done
    printf '%s\n' "$got"
}

mfa_pages_rows() {
    local entry name label want row wire reached=yes
    for entry in "${MFA_ROWS[@]}"; do
        IFS='|' read -r name label want <<<"$entry"
        if [ "$reached" = no ]; then
            p_bad "[M1.$name] $label: not reached"
            continue
        fi
        row="$(grep -m1 "^ROW $name " "$D/mfa-pages.out" 2>/dev/null)"
        wire="$(grep -m1 "^WIRE $name " "$D/mfa-pages.out" 2>/dev/null)"
        if [ "$row" = "ROW $name PASS" ] && [ "$wire" = "WIRE $name $want $MFA_TAIL" ]; then
            p_ok "[M1.$name] $label; nothing sent or kept carries the password"
        elif [ "$row" = "ROW $name PASS" ]; then
            p_bad "[M1.$name] $label: ${wire:-no WIRE line}; want WIRE $name $want $MFA_TAIL"
        else
            p_bad "[M1.$name] $label: ${row:-not reached} (see mfa-pages.out, $name.png)"
            reached=no
        fi
    done
}

if ! docker image inspect "$MFA_BROWSER_IMAGE" >/dev/null 2>&1; then
    p_skip "[M1.browser] browser image absent: ${MFA_BROWSER_IMAGE}; the page rows did not run"
elif [ -z "$MFA_NEW_PASS" ]; then
    p_bad "[M1.browser] could not make a per-run password"
else
    EXTRA_CONTAINERS+=("$MFA_BROWSER_CTN")
    mfa_pages_run || true
    grep '^CONTEXT \|^FINDING ' "$D/mfa-pages.out" 2>/dev/null | while IFS= read -r line; do note "$line"; done
    mfa_pages_rows
    if grep -q '^ROW mfa-reset PASS' "$D/mfa-pages.out" 2>/dev/null; then
        if t ldapwhoami -x -H "$(ldap_url)" -D "$MFA_DN" -w "$MFA_NEW_PASS" >"$D/bind-pages.out" 2>&1; then
            p_ok "[M1.pages-bind] after the pages' change and reset, the new password binds alone"
        else
            p_bad "[M1.pages-bind] the new password does not bind after the pages (see bind-pages.out)"
        fi
        nosession="$(mfa_rows_with 'no session' 2)"
        challenged="$(mfa_rows_with 'totp code required; no session' 3)"
        if [ "$nosession $challenged" = "2 3" ]; then
            p_ok "[M1.pages-rows] every row of a password check says 'no session': the enrollment page's two, and 'totp code required; no session' for the replacement, change and reset"
        else
            p_bad "[M1.pages-rows] login rows for $MFA_USER: 'no session' $nosession (want 2), 'totp code required; no session' $challenged (want 3)"
        fi
    fi
    docker rm -f -v "$MFA_BROWSER_CTN" >/dev/null 2>&1 || true
fi

# An OU's enable-mfa. The main server sets LLDAP_ENABLE_MFA=true, which overrides every OU: its
# rows show an OU's always and off change nothing there. The OU rows run on a server that sets
# no value (OU_SIDE), and two rows on one that sets it off (OU_OFF); each is removed by name.
OU_PASS="GateOuPass2026!"
OU_SIDE="$CONTAINER-ou67" OU_SIDE_VOL="klldap-gate-ou67-$RUNID"
OU_OFF="$CONTAINER-mfaoff" OU_OFF_VOL="klldap-gate-mfaoff-$RUNID"
OU_BROWSER_CTN="klldap-mfa-ou-${RUNID}"
OU_MAIN_POLICIES=()
EXTRA_CONTAINERS+=("$OU_SIDE" "$OU_OFF" "$OU_BROWSER_CTN")
EXTRA_VOLUMES+=("$OU_SIDE_VOL" "$OU_OFF_VOL")

# ou_link <ou> <value>: the OU with a policy of its own setting enable-mfa; prints the policy id.
# shellcheck disable=SC2016
ou_link() {
    local id
    graphql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$1"'"}' >/dev/null || return 1
    id="$(graphql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
        '{"n": "gate '"$1"'", "i": [{"key": "enable-mfa", "value": "'"$2"'"}]}' | json_get createPolicy.id)" &&
        [ -n "$id" ] || return 1
    if graphql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' \
        '{"o": "'"$1"'", "p": '"$id"'}' >/dev/null; then
        printf '%s\n' "$id"
        return 0
    fi
    graphql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$id"'}' >/dev/null 2>&1 || true
    return 1
}

# ou_user <user> <ou>
# shellcheck disable=SC2016
ou_user() {
    graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$1"'", "email": "'"$1"'@gate.test"}}' >/dev/null &&
        graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
            '{"id": "'"$1"'", "pw": "'"$OU_PASS"'"}' >/dev/null &&
        graphql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$1"'"], "ou": "'"$2"'"}' >/dev/null
}

# ou_enrol <user>: enrolled with the current step's code; prints the secret.
# shellcheck disable=SC2016
ou_enrol() {
    local token proof state secret
    token="$(gate_login "$1" "$OU_PASS")" &&
        proof="$(gate_enrollment_proof "$1" "$OU_PASS")" &&
        TOKEN="$token" graphql 'mutation($p: String) { startMfaEnrollment(enrollmentProof: $p) { secretBase32 state } }' \
            '{"p": "'"$proof"'"}' >"$D/ou-start-$1.json" || return 1
    secret="$(json_get startMfaEnrollment.secretBase32 <"$D/ou-start-$1.json")"
    state="$(json_get startMfaEnrollment.state <"$D/ou-start-$1.json")"
    TOKEN="$token" graphql 'mutation($s: String!, $c: String!) { finishMfaEnrollment(state: $s, code: $c) { ok } }' \
        '{"s": "'"$state"'", "c": "'"$(totp_code "$secret" 0)"'"}' >/dev/null && printf '%s\n' "$secret"
}

ou_dn() {
    lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$1)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1
}

# ou_try <user> <bind|simple> <out>: the right password alone; status 0 when let in.
ou_try() {
    local dn
    case "$2" in
    bind)
        dn="$(ou_dn "$1")"
        [ -n "$dn" ] || { echo "no DN found for $1" >"$3" && return 2; }
        t ldapwhoami -x -H "$(ldap_url)" -D "$dn" -w "$OU_PASS" >"$3" 2>&1
        ;;
    simple) gate_login "$1" "$OU_PASS" >"$3" 2>&1 ;;
    esac
}

# ou_refused <id> <label> <user> <bind|simple> <want>
ou_refused() {
    local out="$D/ou-$1.out"
    if ou_try "$3" "$4" "$out"; then
        p_bad "[M2.$1] $2: the password alone was let in"
    elif grep -q "$5" "$out" && { [ "$4" = bind ] || grep -q "HTTP 401" "$out"; }; then
        p_ok "[M2.$1] $2: refused with '$5'"
    else
        p_bad "[M2.$1] $2: refused without '$5' (see ou-$1.out)"
    fi
}

# ou_admitted <id> <label> <user> <bind|simple>
ou_admitted() {
    if ou_try "$3" "$4" "$D/ou-$1.out"; then
        p_ok "[M2.$1] $2: the password alone is let in"
    else
        p_bad "[M2.$1] $2: refused (see ou-$1.out)"
    fi
}

# ou_no_enrolment <id> <label> <user>
# shellcheck disable=SC2016
ou_no_enrolment() {
    local token out="$D/ou-$1.out"
    token="$(gate_login "$3" "$OU_PASS" 2>"$out")" &&
        TOKEN="$token" graphql 'mutation { startMfaEnrollment { state } }' '{}' >>"$out" 2>&1
    if grep -q "MFA is disabled for this user" "$out"; then
        p_ok "[M2.$1] $2: refused with 'MFA is disabled for this user'"
    else
        p_bad "[M2.$1] $2: not refused as disabled for this user (see ou-$1.out)"
    fi
}

# ou_pages <mode> <server> <user> <code user> <secret> <out>
ou_pages() {
    docker rm -f -v "$OU_BROWSER_CTN" >/dev/null 2>&1 || true
    # -e NAME, not -e NAME=value, so the password and the secret are not on the host's command line.
    BROWSER_PASS="$OU_PASS" BROWSER_TOTP_SECRET="$5" \
        timeout 300 docker run --rm --name "$OU_BROWSER_CTN" --network "$NET" --init --shm-size=1g \
        --user "$(id -u):$(id -g)" --entrypoint node \
        -v "$GATE_ROOT/lib/browser.mjs:/work/browser.mjs:ro" -v "$D:/out" \
        -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_MODE="$1" \
        -e BROWSER_URL="http://$2:17170" -e BROWSER_USER="$3" -e BROWSER_CODE_USER="$4" \
        -e BROWSER_PASS -e BROWSER_TOTP_SECRET \
        "$MFA_BROWSER_IMAGE" /work/browser.mjs >"$6" 2>"$6.err"
    docker rm -f -v "$OU_BROWSER_CTN" >/dev/null 2>&1 || true
    grep '^CONTEXT \|^FINDING ' "$6" 2>/dev/null | while IFS= read -r line; do note "$line"; done
}

# ou_wire <out> <name|label|want>...: each row passed, with exactly its WIRE line.
ou_wire() {
    local out="$1" entry name label want row wire
    shift
    for entry in "$@"; do
        IFS='|' read -r name label want <<<"$entry"
        row="$(grep -m1 "^ROW $name " "$out" 2>/dev/null)"
        wire="$(grep -m1 "^WIRE $name " "$out" 2>/dev/null)"
        if [ "$row" = "ROW $name PASS" ] && [ "$wire" = "WIRE $name $want $MFA_TAIL" ]; then
            p_ok "[M2.$name] $label; nothing sent or kept carries the password"
        else
            p_bad "[M2.$name] $label: ${row:-not reached}, ${wire:-no WIRE line}; want WIRE $name $want $MFA_TAIL (see ${out##*/})"
        fi
    done
}

ou_browser() {
    docker image inspect "$MFA_BROWSER_IMAGE" >/dev/null 2>&1 && return 0
    p_skip "[M2.$1] browser image absent: ${MFA_BROWSER_IMAGE}; the web rows did not run"
    return 1
}

ou_main() {
    local id secret=""
    if id="$(ou_link gatemfaalways always)" && OU_MAIN_POLICIES+=("$id") &&
        id="$(ou_link gatemfaoff off)" && OU_MAIN_POLICIES+=("$id") &&
        ou_user gateoumainalways gatemfaalways && ou_user gateoumainoff gatemfaoff; then
        secret="$(ou_enrol gateoumainoff)"
    fi
    if [ -z "$secret" ]; then
        p_bad "[M2.main-setup] the OUs, their policies and users on the main server could not be made (see ou-main-setup.err)"
        return
    fi
    ou_admitted main-bind-always "the main server's explicit enabled overrides the OU's always: LDAP bind of an unenrolled user" gateoumainalways bind
    ou_admitted main-simple-always "the main server's explicit enabled overrides the OU's always: simple login of an unenrolled user" gateoumainalways simple
    ou_refused main-bind-off "the main server's explicit enabled overrides the OU's off: LDAP bind of an enrolled user without the code" gateoumainoff bind "TOTP code required"
    ou_refused main-simple-off "the main server's explicit enabled overrides the OU's off: simple login of an enrolled user without the code" gateoumainoff simple "TOTP code required"
    ou_browser main-web || return 0
    ou_pages ou-main "$CONTAINER" gateoumainalways gateoumainoff "$secret" "$D/ou-main.out"
    ou_wire "$D/ou-main.out" \
        "ou-main-always|the main server's explicit enabled overrides the OU's always: an unenrolled user's web login lands on their own page|starts=1 finishes=1 sessionless=0 proof-asked=0 codes=0 statuses=200" \
        "ou-main-off|the main server's explicit enabled overrides the OU's off: an enrolled user's web login asks the code, then signs in with it|starts=2 finishes=2 sessionless=0 proof-asked=0 codes=1 statuses=200/200"
}

# shellcheck disable=SC2016
ou_main_cleanup() {
    local ou id user
    for ou in gatemfaalways gatemfaoff; do
        graphql 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' '{"o": "'"$ou"'"}' >/dev/null 2>&1
    done
    for id in "${OU_MAIN_POLICIES[@]}"; do
        graphql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$id"'}' >/dev/null 2>&1
    done
    for user in gateoumainalways gateoumainoff; do
        graphql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$user"'"}' >/dev/null 2>&1
    done
    for ou in gatemfaalways gatemfaoff; do
        graphql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$ou"'"}' >/dev/null 2>&1 ||
            p_bad "[M2.main-cleanup] OU $ou was not removed from the main server"
    done
}

ou_side() {
    local ports secret=""
    if ! ports="$(side_up "$OU_SIDE" "$OU_SIDE_VOL" 2>"$D/ou-side.err")"; then
        p_bad "[M2.side-setup] the server without LLDAP_ENABLE_MFA did not become healthy (see ou-side.err, ou-side.log)"
        side_down "$OU_SIDE" "$OU_SIDE_VOL" "$D/ou-side.log"
        return
    fi
    # shellcheck disable=SC2086
    side_use $ports
    if [ -n "$TOKEN" ] && ou_link gatemfaalways always >/dev/null && ou_link gatemfaenabled enabled >/dev/null &&
        ou_link gatemfaoff off >/dev/null && ou_user gateoualways gatemfaalways &&
        ou_user gateouenrolled gatemfaenabled && ou_user gateouoff gatemfaoff; then
        secret="$(ou_enrol gateouenrolled)"
    fi
    if [ -z "$secret" ]; then
        p_bad "[M2.side-setup] the OUs, their policies and users on $OU_SIDE could not be made (see ou-side-setup.err)"
    else
        ou_refused bind-always "no server-wide value, the OU's always: LDAP bind of an unenrolled user" gateoualways bind "MFA enrollment required"
        ou_refused simple-always "no server-wide value, the OU's always: simple login of an unenrolled user" gateoualways simple "MFA enrollment required"
        ou_refused bind-enrolled "no server-wide value, the OU's enabled: LDAP bind of an enrolled user without the code" gateouenrolled bind "TOTP code required"
        ou_refused simple-enrolled "no server-wide value, the OU's enabled: simple login of an enrolled user without the code" gateouenrolled simple "TOTP code required"
        ou_no_enrolment enrol-off "no server-wide value, the OU's off: enrolment" gateouoff
        if ou_browser side-web; then
            ou_pages ou-mfa "$OU_SIDE" gateoualways gateouenrolled "$secret" "$D/ou-side.out"
            ou_wire "$D/ou-side.out" \
                "ou-pending|no server-wide value, the OU's always: an unenrolled user's web login lands on enrolment only|starts=1 finishes=1 sessionless=0 proof-asked=0 codes=0 statuses=200" \
                "ou-code|no server-wide value, the OU's enabled: an enrolled user's web login asks the code, then signs in with it|starts=2 finishes=2 sessionless=0 proof-asked=0 codes=1 statuses=200/200"
            if grep -q '^ROW ou-confined PASS' "$D/ou-side.out" 2>/dev/null; then
                p_ok "[M2.ou-confined] the OU's always: another page of the pending session goes back to enrolment"
            else
                p_bad "[M2.ou-confined] the pending session reached another page (see ou-side.out)"
            fi
        fi
    fi
    side_back
    side_down "$OU_SIDE" "$OU_SIDE_VOL" "$D/ou-side.log"
}

ou_off() {
    local ports
    if ! ports="$(side_up "$OU_OFF" "$OU_OFF_VOL" -e LLDAP_ENABLE_MFA=off 2>"$D/ou-off.err")"; then
        p_bad "[M2.off-setup] the server with LLDAP_ENABLE_MFA=off did not become healthy (see ou-off.err, ou-off.log)"
        side_down "$OU_OFF" "$OU_OFF_VOL" "$D/ou-off.log"
        return
    fi
    # shellcheck disable=SC2086
    side_use $ports
    if [ -n "$TOKEN" ] && ou_link gatemfaalways always >/dev/null && ou_user gateoualways gatemfaalways; then
        ou_admitted off-bind-always "the server's explicit off overrides the OU's always: LDAP bind of an unenrolled user" gateoualways bind
        ou_no_enrolment off-enrol "the server's explicit off overrides the OU's always: enrolment" gateoualways
    else
        p_bad "[M2.off-setup] the OU, its policy and user on $OU_OFF could not be made (see ou-off-setup.err)"
    fi
    side_back
    side_down "$OU_OFF" "$OU_OFF_VOL" "$D/ou-off.log"
}

ou_main 2>"$D/ou-main-setup.err"
ou_main_cleanup
ou_side 2>"$D/ou-side-setup.err"
ou_off 2>"$D/ou-off-setup.err"
