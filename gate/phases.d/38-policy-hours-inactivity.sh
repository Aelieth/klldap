# shellcheck shell=bash
# shellcheck disable=SC2016
# Phase: login-hours and inactivity-days on a real server, at the LDAP bind, the simple login, the
# web login and kinit. Hours: a window around now and a one-minute window six hours away, read from
# the server's own clock in its zone, on the main server (UTC) and on a side server in
# America/Chicago; a live session refused at its next request and working again; a TOTP user
# outside the hours gets a wrong password's answer. Inactivity: the user's times set back in the
# database with the server stopped, then reenableUser; again, then lldap reenable.

HI_D="$(phase_dir)"
HI_N=0 HI_P=0 HI_K=0 HI_X=0 HI_FAILS=()
HI_RUN="hi$(date +%H%M%S)"
HI_OU="${HI_RUN}ou" HI_IOU="${HI_RUN}io"
HI_USER="${HI_RUN}-u" HI_TOTP="${HI_RUN}-t" HI_IDLE="${HI_RUN}-i"
HI_POLICY="" HI_IPOLICY="" HI_DN="" HI_TOTP_DN="" HI_IDLE_DN="" HI_SIDE_DN=""
HI_SECRET="" HI_SESSION="" HI_IN="" HI_OUT="" HI_AT=0 HI_MADE=0 HI_SIDE_UP=0 HI_SETBACK_WHY=""
HI_SIDE_POLICY="" HI_IDLE_TRIED=0
HI_SIDE="$CONTAINER-hours38" HI_SIDE_VOL="klldap-gate-hours38-$RUNID"
HI_SIDE_KVOL="klldap-gate-hours38-kdc-$RUNID" HI_SIDE_ZONE="America/Chicago"
HI_PEER_CTN="klldap-hipeer-${RUNID}"
HI_HOURS_DETAIL="policy: login-hours (outside login hours)"
HI_IDLE_DETAIL="policy: inactivity-days (inactive)"
HI_CODE_TEXT="TOTP code required"
HI_CODE_LDAP="TOTP code required: append ':' and the code"
HI_REFUSED_TEXT="Access refused"
HI_DOORS="ldap-bind simple-login web-login kinit"
EXTRA_CONTAINERS+=("$HI_SIDE" "$HI_PEER_CTN")
EXTRA_VOLUMES+=("$HI_SIDE_VOL" "$HI_SIDE_KVOL")
HI_XT=0
case $- in *x*) HI_XT=1 ;; esac
{ set +x; } 2>/dev/null
HI_PASS="$(python3 -c 'import secrets; print("Hi" + secrets.token_hex(10) + "!")')"
[ "$HI_XT" = 1 ] && set -x

hi_pass() { HI_N=$((HI_N + 1)) HI_P=$((HI_P + 1)); p_ok "$1"; }
hi_note() { HI_N=$((HI_N + 1)) HI_K=$((HI_K + 1)); note "[NOTE] ${PHASE}: $1"; }
hi_bad() { HI_N=$((HI_N + 1)) HI_X=$((HI_X + 1)) HI_FAILS+=("${1%%]*}]"); p_bad "$1"; }
hi_gql() { graphql "$1" "$2" 2>"$HI_D/last.err"; }
hi_hush() {
    local xt=0 rc
    case $- in *x*) xt=1 ;; esac
    { set +x; } 2>/dev/null
    "$@"
    rc=$?
    [ "$xt" = 1 ] && set -x
    return "$rc"
}
hi_browser() { docker image inspect "$WIRE_IMAGE" >/dev/null 2>&1; }

# hi__simple <user> <right|wrong>: "<status> <body hash> <code|->", or "200 token -"; no body is kept.
hi__simple() {
    local pass="$HI_PASS"
    [ "$2" = wrong ] && pass="wrong-$HI_RUN"
    LOGIN_URL="$(http_url)/auth/simple/login" LOGIN_USER="$1" LOGIN_PASS="$pass" HI_CODE="$HI_CODE_TEXT" \
        t python3 - <<'PY'
import hashlib, json, os, urllib.error, urllib.request
req = urllib.request.Request(os.environ["LOGIN_URL"], headers={"Content-Type": "application/json"},
    data=json.dumps({"username": os.environ["LOGIN_USER"], "password": os.environ["LOGIN_PASS"]}).encode())
try:
    print("200", "token" if json.load(urllib.request.urlopen(req)).get("token") else "none", "-")
except urllib.error.HTTPError as e:
    body = e.read()
    print(e.code, hashlib.sha256(body).hexdigest()[:16], "code" if os.environ["HI_CODE"].encode() in body else "-")
except Exception:
    print("000 none -")
PY
}

# hi__bind <dn> <right|wrong>: "<exit> <output hash> <code|->"; the password goes in a 0600 file.
hi__bind() {
    local f="$HI_D/.bindpw" rc out="$HI_D/bind.out"
    (
        umask 077
        if [ "$2" = wrong ]; then printf '%s' "wrong-$HI_RUN"; else printf '%s' "$HI_PASS"; fi >"$f"
    )
    t ldapwhoami -x -H "$(ldap_url)" -D "$1" -y "$f" >"$out" 2>&1
    rc=$?
    rm -f "$f"
    printf '%s %s %s\n' "$rc" "$(sha256sum <"$out" | cut -c1-16)" \
        "$(grep -qF "$HI_CODE_LDAP" "$out" && echo code || echo -)"
}

# hi__kinit <container> <user>: ok, revoked, incorrect or other; the password on stdin, its own cache.
hi__kinit() {
    printf '%s\n' "$HI_PASS" | t docker exec -i "$1" sh -c \
        'c="/tmp/hi_cc_$$"; KRB5CCNAME="$c" kinit "$0"; rc=$?; rm -f "$c"; exit "$rc"' \
        "$2@$REALM" >"$HI_D/kinit.out" 2>&1 && echo ok && return
    if grep -q "credentials have been revoked" "$HI_D/kinit.out"; then
        echo revoked
    elif grep -q "Password incorrect" "$HI_D/kinit.out"; then
        echo incorrect
    else
        echo other
    fi
}

# hi__web <refused|login> <user> <tag> <container>: that server's login page, from the gate's network.
hi__web() {
    local out="$HI_D/web-$3.out" line
    docker rm -f -v "$HI_PEER_CTN" >/dev/null 2>&1
    (
        export BROWSER_PASS="$HI_PASS"
        timeout 180 docker run --rm --name "$HI_PEER_CTN" --network "$NET" --init --shm-size=1g \
            --user "$(id -u):$(id -g)" --entrypoint node \
            -v "$GATE_ROOT/lib/browser.mjs:/work/browser.mjs:ro" -v "$HI_D:/out" \
            -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_MODE="$1" \
            -e BROWSER_URL="http://${4}:17170" -e BROWSER_USER="$2" -e BROWSER_PASS \
            "$WIRE_IMAGE" /work/browser.mjs >"$out" 2>"$HI_D/web-$3.err"
    )
    docker rm -f -v "$HI_PEER_CTN" >/dev/null 2>&1
    if grep -q '^ROW refused-web PASS' "$out"; then
        echo refused
    elif grep -q '^ROW user-login PASS' "$out"; then
        echo admitted
    else
        line="$(grep -m1 '^ROW ' "$out" | cut -c1-120)"
        echo "${line:-no line (see web-$3.err)}"
    fi
}

# hi_door <door> <user> <dn> <in|out> <tag> <container>: the right password's answer there.
hi_door() {
    local got mode=login
    [ "$4" = out ] && mode=refused
    case "$1" in
    ldap-bind)
        got="$(hi_hush hi__bind "$3" right)"
        echo "${got%% *}"
        ;;
    simple-login)
        got="$(hi_hush hi__simple "$2" right)"
        echo "${got%% *}"
        ;;
    web-login) hi_hush hi__web "$mode" "$2" "$5" "$6" ;;
    kinit) hi_hush hi__kinit "$6" "$2" ;;
    esac
}

# hi_want <door> <in|out>: "<answer> <row kind> <row protocol>".
hi_want() {
    case "$1:$2" in
    ldap-bind:out) echo "49 BIND LDAP" ;;
    ldap-bind:in) echo "0 BIND LDAP" ;;
    simple-login:out) echo "401 BIND HTTP" ;;
    simple-login:in) echo "200 BIND HTTP" ;;
    web-login:out) echo "refused LOGIN HTTP" ;;
    web-login:in) echo "admitted LOGIN HTTP" ;;
    kinit:out) echo "revoked LOGIN KERBEROS" ;;
    kinit:in) echo "ok LOGIN KERBEROS" ;;
    esac
}

# hi_out <label> <door> <user> <dn> <detail> <container> <case>: refused, with its one row.
hi_out() {
    local label="$1" door="$2" user="$3" dn="$4" detail="$5" ctn="$6" what="$7" want kind proto mark got
    read -r want kind proto <<<"$(hi_want "$door" out)"
    if [ "$door" = web-login ] && ! hi_browser; then
        hi_note "[$label] the browser image is absent; not run"
        return
    fi
    mark="$(log_mark)"
    got="$(hi_door "$door" "$user" "$dn" out "$label" "$ctn")"
    if [ "$got" != "$want" ]; then
        hi_bad "[$label] $what: $door with the right password answered '$got' (want $want)"
    elif ! fail_once "$kind" "$user" "$detail" "$mark" "$proto"; then
        hi_bad "[$label] $what: $door refused ($want), but $FAIL_WHY"
    else
        hi_pass "[$label] $what: $door with the right password is refused ($want), one $kind row (protocol $proto) '$detail'"
    fi
}

# hi_in <label> <door> <user> <dn> <container> <case> [clock container]: admitted; with a clock
# container, a NOTE once the window's twenty minutes may have passed.
hi_in() {
    local label="$1" door="$2" user="$3" dn="$4" ctn="$5" what="$6" want got
    read -r want _ _ <<<"$(hi_want "$door" in)"
    if [ "$door" = web-login ] && ! hi_browser; then
        hi_note "[$label] the browser image is absent; not run"
        return
    fi
    got="$(hi_door "$door" "$user" "$dn" in "$label" "$ctn")"
    if [ -n "${7:-}" ] && ! hi_fresh "$7"; then
        hi_note "[$label] the window around now was read over 19 minutes before this row; this run cannot tell"
    elif [ "$got" = "$want" ]; then
        hi_pass "[$label] $what: $door with the right password is admitted ($want)"
    else
        hi_bad "[$label] $what: $door with the right password answered '$got' (want $want)"
    fi
}

# hi_windows <container> <zone>: HI_IN from ten minutes ago to twenty ahead, HI_OUT one minute six
# hours ahead, from that container's clock in that zone; HI_AT is its clock then.
hi_windows() {
    local clock made
    clock="$(t docker exec "$1" sh -c 'now=$(date +%s); echo "$now"
        for o in -600 1200 21600; do TZ="$0" LC_ALL=C date -d "@$((now + o))" "+%a %H:%M"; done' "$2")" ||
        return 1
    made="$(HI_CLOCK="$clock" python3 - <<'PY'
import os
lines = os.environ["HI_CLOCK"].splitlines()
if len(lines) != 4:
    raise SystemExit(1)
(d0, t0), (d1, t1), (d2, t2) = (line.lower().split() for line in lines[1:])
def later(hhmm):
    h, m = (int(x) for x in hhmm.split(":"))
    return "%02d:%02d" % ((h + 1, 0) if m == 59 else (h, m + 1))
if d0 != d1:
    inside = f"{d0} {t0}-24:00" + ("" if t1 == "00:00" else f";{d1} 00:00-{t1}")
elif t0 < t1:
    inside = f"{d0} {t0}-{t1}"
else:
    inside = f"{d0} 00:00-24:00"
print(f"{inside}|{d2} {t2}-{later(t2)}")
PY
)" || return 1
    HI_AT="$(head -1 <<<"$clock")" HI_IN="${made%%|*}" HI_OUT="${made#*|}"
    [ -n "$HI_AT" ] && [ -n "$HI_IN" ] && [ -n "$HI_OUT" ]
}
hi_fresh() {
    local now
    now="$(t docker exec "$1" date +%s 2>/dev/null)"
    [ -n "$now" ] && [ $((now - HI_AT)) -le 1140 ]
}

hi__user() {
    local attrs=""
    [ "${3:-}" = kerberos ] && attrs=', "attributes": [{"name": "kerberossync", "value": ["1"]}]'
    hi_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$1"'", "email": "'"$1"'@gate.test"'"$attrs"'}}' >/dev/null &&
        hi_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
            "$(HIU="$1" HIP="$HI_PASS" python3 -c 'import json,os; print(json.dumps({"id": os.environ["HIU"], "pw": os.environ["HIP"]}))')" \
            >/dev/null &&
        hi_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$1"'"], "ou": "'"$2"'"}' >/dev/null
}
# hi_user <user> <ou> [kerberos]: the user with the phase's password, in the OU.
hi_user() { hi_hush hi__user "$@"; }
hi_dn() { lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$1)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1; }
# hi_ready <container> <user>: the user's principal is in that realm.
hi_ready() {
    for _ in $(seq 1 15); do
        gexec_in "$1" kadmin -k -t /data/kadm5.keytab -p "admin/admin@$REALM" -q "getprinc $2" \
            >"$HI_D/getprinc.txt" 2>&1 && grep -q "^Principal: $2@$REALM" "$HI_D/getprinc.txt" && return 0
        sleep 1
    done
    return 1
}
# hi_link <ou> <name> <key> <value>: prints the new policy's id; true once it is linked to the OU.
hi_link() {
    local id
    id="$(hi_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
        '{"n": "'"$2"'", "i": [{"key": "'"$3"'", "value": "'"$4"'"}]}' | json_get createPolicy.id 2>/dev/null)"
    [ -n "$id" ] || return 1
    printf '%s\n' "$id"
    hi_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' \
        '{"o": "'"$1"'", "p": '"$id"'}' >/dev/null
}
# hi_hours <policy> <value>: the policy's login-hours; a link on this server applies at once.
hi_hours() {
    hi_gql 'mutation($p: Int!, $i: [PolicyItemInput!]) { updatePolicy(policyId: $p, items: $i) { ok } }' \
        '{"p": '"$1"', "i": [{"key": "login-hours", "value": "'"$2"'"}]}' >/dev/null
}
hi_effective() {
    hi_gql 'query($o: String!) { effectivePolicyItems(ou: $o) { key value } }' '{"o": "'"$1"'"}' |
        HIK="$2" python3 -c '
import json, os, sys
items = {i["key"]: i["value"] for i in json.load(sys.stdin)["effectivePolicyItems"]}
print(items.get(os.environ["HIK"], "<missing>"))' 2>/dev/null
}
hi__code() {
    TOTP_SECRET="$HI_SECRET" python3 - <<'PY'
import base64, hashlib, hmac, os, struct, time
secret = os.environ["TOTP_SECRET"]
key = base64.b32decode(secret + "=" * (-len(secret) % 8))
digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
offset = digest[19] & 0x0F
print(f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}")
PY
}
hi__enrol() {
    local mtok out state proof
    mtok="$(gate_login "$HI_TOTP" "$HI_PASS")" &&
        proof="$(gate_enrollment_proof "$HI_TOTP" "$HI_PASS")" &&
        out="$(TOKEN="$mtok" graphql 'mutation($p: String) { startMfaEnrollment(enrollmentProof: $p) { secretBase32 state } }' \
            '{"p": "'"$proof"'"}' 2>/dev/null)" || return 1
    HI_SECRET="$(json_get startMfaEnrollment.secretBase32 <<<"$out")"
    state="$(json_get startMfaEnrollment.state <<<"$out")"
    TOKEN="$mtok" graphql 'mutation($s: String!, $c: String!) { finishMfaEnrollment(state: $s, code: $c) { ok } }' \
        '{"s": "'"$state"'", "c": "'"$(hi__code)"'"}' >/dev/null 2>&1
}

hi_zone_row() {
    local want="login-hours are judged in $3" log="$HI_D/$1.log"
    docker logs "$2" >"$log" 2>&1
    if grep -qF "$want" "$log"; then
        hi_pass "[$1] the server's start says '$want'"
    else
        hi_bad "[$1] the server's log does not say '$want'"
    fi
}

# The main server: the users and the policy, the hours six hours away.
hi_setup() {
    if ! { hi_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$HI_OU"'"}' >/dev/null &&
        hi_user "$HI_USER" "$HI_OU" kerberos && hi_user "$HI_TOTP" "$HI_OU"; }; then
        hi_bad "[H.setup] the OU $HI_OU and its users could not be made: $(head -c 200 "$HI_D/last.err")"
        return 1
    fi
    if ! hi_hush hi__enrol; then
        hi_bad "[H.setup] the TOTP enrolment of $HI_TOTP could not be made"
        return 1
    fi
    HI_DN="$(hi_dn "$HI_USER")" HI_TOTP_DN="$(hi_dn "$HI_TOTP")"
    if [ -z "$HI_DN" ] || [ -z "$HI_TOTP_DN" ] || ! hi_ready "$CONTAINER" "$HI_USER"; then
        hi_bad "[H.setup] no DN for $HI_USER or $HI_TOTP, or no principal $HI_USER@$REALM"
        return 1
    fi
    if ! { hi_windows "$CONTAINER" UTC && HI_POLICY="$(hi_link "$HI_OU" "$HI_RUN hours" login-hours "$HI_OUT")" &&
        [ "$(hi_effective "$HI_OU" login-hours)" = "$HI_OUT" ]; }; then
        hi_bad "[H.setup] login-hours '$HI_OUT' could not be linked to $HI_OU: $(head -c 200 "$HI_D/last.err")"
        return 1
    fi
}

# Q31: outside the hours, the right password and no code answer as a wrong password does.
hi_totp_out() {
    local mark right wrong why=""
    mark="$(log_mark)"
    right="$(hi_hush hi__simple "$HI_TOTP" right)"
    fail_once BIND "$HI_TOTP" "$HI_HOURS_DETAIL" "$mark" HTTP || why="$FAIL_WHY"
    wrong="$(hi_hush hi__simple "$HI_TOTP" wrong)"
    if [ "${right%% *}" = 401 ] && [ "$right" = "$wrong" ] && [ "${right##* }" = - ] && [ -z "$why" ]; then
        hi_pass "[H.totp-out-simple-login] an enrolled TOTP user outside the hours, the right password and no code at /auth/simple/login: 401 and the same body as a wrong password (no '$HI_CODE_TEXT'), one BIND row (protocol HTTP) '$HI_HOURS_DETAIL'"
    else
        hi_bad "[H.totp-out-simple-login] right password, no code: status ${right%% *}, code text ${right##* }; wrong password: status ${wrong%% *}; same body $([ "${right#* }" = "${wrong#* }" ] && echo yes || echo no) (want 401, -, 401, yes); ${why:-one row}"
    fi
    why=""
    mark="$(log_mark)"
    right="$(hi_hush hi__bind "$HI_TOTP_DN" right)"
    fail_once BIND "$HI_TOTP" "$HI_HOURS_DETAIL" "$mark" LDAP || why="$FAIL_WHY"
    wrong="$(hi_hush hi__bind "$HI_TOTP_DN" wrong)"
    if [ "${right%% *}" = 49 ] && [ "$right" = "$wrong" ] && [ "${right##* }" = - ] && [ -z "$why" ]; then
        hi_pass "[H.totp-out-ldap-bind] the same user at the LDAP bind, the right password and no code: 49 and the same diagnostic as a wrong password (no '$HI_CODE_LDAP'), one BIND row (protocol LDAP) '$HI_HOURS_DETAIL'"
    else
        hi_bad "[H.totp-out-ldap-bind] right password, no code: exit ${right%% *}, code text ${right##* }; wrong password: exit ${wrong%% *}; same output $([ "${right#* }" = "${wrong#* }" ] && echo yes || echo no) (want 49, -, 49, yes); ${why:-one row}"
    fi
    hi_out H.totp-out-web-login web-login "$HI_TOTP" "" "$HI_HOURS_DETAIL" "$CONTAINER" \
        "an enrolled TOTP user outside the hours, no code: the page says 'Invalid username or password', not the code step"
}

# Inside the hours the same user is asked for the code.
hi_totp_in() {
    local got
    got="$(hi_hush hi__simple "$HI_TOTP" right)"
    if ! hi_fresh "$CONTAINER"; then
        hi_note "[H.totp-in-simple-login] the window around now was read over 19 minutes before this row; this run cannot tell"
    elif [ "${got%% *} ${got##* }" = "401 code" ]; then
        hi_pass "[H.totp-in-simple-login] inside the hours, the right password and no code at /auth/simple/login: 401 '$HI_CODE_TEXT'"
    else
        hi_bad "[H.totp-in-simple-login] inside the hours: status ${got%% *}, code text ${got##* } (want 401 and '$HI_CODE_TEXT')"
    fi
    got="$(hi_hush hi__bind "$HI_TOTP_DN" right)"
    if ! hi_fresh "$CONTAINER"; then
        hi_note "[H.totp-in-ldap-bind] the window around now was read over 19 minutes before this row; this run cannot tell"
    elif [ "${got%% *} ${got##* }" = "49 code" ]; then
        hi_pass "[H.totp-in-ldap-bind] inside the hours, the right password and no code at the LDAP bind: 49 '$HI_CODE_LDAP'"
    else
        hi_bad "[H.totp-in-ldap-bind] inside the hours: exit ${got%% *}, code text ${got##* } (want 49 and '$HI_CODE_LDAP')"
    fi
}

# hi__use <token> <user>: one GraphQL request on that session: "<status> <self|refused|other>".
hi__use() {
    GQ_URL="$(http_url)/api/graphql" GQ_TOKEN="$1" GQ_USER="$2" HI_SAID="$HI_REFUSED_TEXT" t python3 - <<'PY'
import json, os, urllib.error, urllib.request
req = urllib.request.Request(os.environ["GQ_URL"],
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["GQ_TOKEN"]},
    data=json.dumps({"query": "query($u: String!) { user(userId: $u) { id } }",
                     "variables": {"u": os.environ["GQ_USER"]}}).encode())
try:
    body = json.load(urllib.request.urlopen(req))
    user = ((body.get("data") or {}).get("user") or {}).get("id")
    print(200, "self" if user == os.environ["GQ_USER"] else "other")
except urllib.error.HTTPError as e:
    print(e.code, "refused" if e.read().decode(errors="replace").strip() == os.environ["HI_SAID"] else "other")
except Exception:
    print("000 none")
PY
}

# Q12: a session is refused at its next request while the rule refuses, and works again after.
hi_session() {
    local before during after mark why=""
    HI_SESSION="$(hi_hush gate_login "$HI_USER" "$HI_PASS")"
    before="$(hi_hush hi__use "$HI_SESSION" "$HI_USER")"
    mark="$(log_mark)"
    hi_hours "$HI_POLICY" "$HI_OUT"
    during="$(hi_hush hi__use "$HI_SESSION" "$HI_USER")"
    fail_once ACCESS_DENIED "$HI_USER" "$HI_HOURS_DETAIL" "$mark" GRAPHQL || why="$FAIL_WHY"
    hi_hours "$HI_POLICY" "$HI_IN"
    after="$(hi_hush hi__use "$HI_SESSION" "$HI_USER")"
    HI_SESSION=""
    if [ "$before $during" = "200 self 401 refused" ] && [ -z "$why" ]; then
        hi_pass "[H.session-refused] a session token from inside the hours answers its GraphQL request; with the OU's login-hours moved to '$HI_OUT' its next request is refused, 401 '$HI_REFUSED_TEXT', one ACCESS_DENIED row (protocol GRAPHQL) '$HI_HOURS_DETAIL'"
    else
        hi_bad "[H.session-refused] the session answered '$before' inside, then '$during' outside (want 200 self, 401 refused); ${why:-one row}"
    fi
    if ! hi_fresh "$CONTAINER"; then
        hi_note "[H.session-back] the window around now was read over 19 minutes before this row; this run cannot tell"
    elif [ "$after" = "200 self" ]; then
        hi_pass "[H.session-back] login-hours back to '$HI_IN': the same token answers again (nothing was revoked)"
    else
        hi_bad "[H.session-back] login-hours back to '$HI_IN': the same token answered '$after' (want 200 self)"
    fi
}

hi_hours_main() {
    local door
    # kinit is refused before any password: its rows must start a flood window of their own.
    flood_quiet LOGIN KERBEROS >/dev/null
    hi_zone_row H.main-zone "$CONTAINER" "UTC (built in)"
    for door in $HI_DOORS; do
        hi_out "H.out-$door" "$door" "$HI_USER" "$HI_DN" "$HI_HOURS_DETAIL" "$CONTAINER" \
            "login-hours '$HI_OUT', six hours ahead on the server's UTC clock"
    done
    hi_totp_out
    if ! hi_windows "$CONTAINER" UTC || ! hi_hours "$HI_POLICY" "$HI_IN"; then
        hi_bad "[H.in-setup] the window around now could not be read or set: $(head -c 200 "$HI_D/last.err")"
        return
    fi
    for door in $HI_DOORS; do
        hi_in "H.in-$door" "$door" "$HI_USER" "$HI_DN" "$CONTAINER" \
            "login-hours '$HI_IN', around now on the server's UTC clock" "$CONTAINER"
    done
    hi_totp_in
    hi_hush hi_session
}

hi_side_setup() {
    local id
    hi_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$HI_OU"'"}' >/dev/null &&
        hi_user "$HI_USER" "$HI_OU" kerberos && hi_ready "$HI_SIDE" "$HI_USER" || return 1
    HI_SIDE_DN="$(hi_dn "$HI_USER")"
    [ -n "$HI_SIDE_DN" ] && hi_windows "$HI_SIDE" "$HI_SIDE_ZONE" &&
        id="$(hi_link "$HI_OU" "$HI_RUN side" login-hours "$HI_OUT")" &&
        [ "$(hi_effective "$HI_OU" login-hours)" = "$HI_OUT" ] && HI_SIDE_POLICY="$id"
}
hi_side_down() {
    side_down "$HI_SIDE" "$HI_SIDE_VOL" "$HI_D/side.log"
    docker volume rm "$HI_SIDE_KVOL" >/dev/null 2>&1 || true
    HI_SIDE_UP=0
}

# The side server judges in America/Chicago; the windows come from its own clock in that zone.
hi_side() {
    local ports http ldap door
    HI_SIDE_UP=1
    if ! ports="$(side_up_kdc "$HI_SIDE" "$HI_SIDE_VOL" "$HI_SIDE_KVOL" \
        -e LLDAP_LOGIN_HOURS_TIMEZONE="$HI_SIDE_ZONE" 2>"$HI_D/side.err")"; then
        hi_bad "[H.side-setup] the side server in $HI_SIDE_ZONE did not become healthy (see side.err, side.log)"
        hi_side_down
        return
    fi
    read -r http ldap _ <<<"$ports"
    side_use "$http" "$ldap"
    if [ -z "$TOKEN" ] || ! hi_side_setup; then
        hi_bad "[H.side-setup] the side server's OU, user, principal or policy could not be made: $(head -c 200 "$HI_D/last.err")"
    else
        hi_zone_row H.side-zone "$HI_SIDE" "$HI_SIDE_ZONE (/usr/share/zoneinfo/$HI_SIDE_ZONE)"
        for door in $HI_DOORS; do
            hi_out "H.side-out-$door" "$door" "$HI_USER" "$HI_SIDE_DN" "$HI_HOURS_DETAIL" "$HI_SIDE" \
                "side server, login-hours '$HI_OUT', six hours ahead on its $HI_SIDE_ZONE clock"
        done
        if hi_windows "$HI_SIDE" "$HI_SIDE_ZONE" && hi_hours "$HI_SIDE_POLICY" "$HI_IN"; then
            for door in $HI_DOORS; do
                hi_in "H.side-in-$door" "$door" "$HI_USER" "$HI_SIDE_DN" "$HI_SIDE" \
                    "side server, login-hours '$HI_IN', around now on its $HI_SIDE_ZONE clock" "$HI_SIDE"
            done
        else
            hi_bad "[H.side-in-setup] the side server's window around now could not be read or set: $(head -c 200 "$HI_D/last.err")"
        fi
    fi
    side_back
    hi_side_down
}

hi_back_up() { wait_healthy 120 && discover_ports && TOKEN="$(gate_login)"; }

# SQLite: the file copied out of the stopped server, three days taken off, copied back; the
# entrypoint gives /data back to the server's user at the start.
hi_setback_sqlite() {
    local copy="$HI_D/setback.db" side
    rm -f "$copy"
    # A journal left beside the stopped database would undo the edit at its next open.
    for side in users.db-journal users.db-wal users.db-shm; do
        if docker cp "$CONTAINER:/data/$side" - >/dev/null 2>&1; then
            echo "$side is beside the stopped database"
            return 1
        fi
    done
    docker cp "$CONTAINER:/data/users.db" "$copy" >/dev/null 2>&1 || {
        echo "users.db could not be copied out"
        return 1
    }
    HI_DB="$copy" HI_U="$HI_IDLE" python3 - <<'PY' || return 1
import os, sqlite3
con = sqlite3.connect(os.environ["HI_DB"])
user = os.environ["HI_U"]
back = "strftime('%Y-%m-%d %H:%M:%f', {0}, '-3 days')"
made = con.execute("UPDATE users SET creation_date = " + back.format("creation_date") + " WHERE user_id = ?", (user,)).rowcount
con.execute("UPDATE user_activity SET last_success = " + back.format("last_success") + ", reenabled_at = "
            + back.format("reenabled_at") + " WHERE user_id = ?", (user,))
since = con.execute("""UPDATE system_config SET "value" = strftime('%Y-%m-%dT%H:%M:%fZ', "value", '-3 days')
    WHERE "key" = 'inactivity_recording_since' AND "value" <> 'off'""").rowcount
con.commit()
idle = con.execute("""SELECT julianday('now') - max(julianday(u.creation_date), coalesce(julianday(a.last_success), 0),
    coalesce(julianday(a.reenabled_at), 0), coalesce(julianday(s."value"), 0)) FROM users u
    LEFT JOIN user_activity a ON a.user_id = u.user_id
    LEFT JOIN system_config s ON s."key" = 'inactivity_recording_since' WHERE u.user_id = ?""", (user,)).fetchone()[0]
con.close()
print(f"users {made}, recording_since {since}, idle {idle if idle is None else round(idle, 2)} days")
raise SystemExit(0 if made == 1 and since == 1 and idle is not None and idle > 2 else 1)
PY
    docker cp "$copy" "$CONTAINER:/data/users.db" >/dev/null 2>&1 || {
        echo "users.db could not be copied back"
        return 1
    }
}

hi_setback_postgres() {
    gexec_in "$PG_CONTAINER" psql -U klldap -d klldap -v ON_ERROR_STOP=1 -q -tA -c "BEGIN;
UPDATE users SET creation_date = creation_date - interval '3 days' WHERE user_id = '$HI_IDLE';
UPDATE user_activity SET last_success = last_success - interval '3 days',
    reenabled_at = reenabled_at - interval '3 days' WHERE user_id = '$HI_IDLE';
UPDATE system_config SET \"value\" = to_char((\"value\"::timestamptz - interval '3 days') AT TIME ZONE 'UTC',
    'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') WHERE \"key\" = 'inactivity_recording_since' AND \"value\" <> 'off';
COMMIT;
SELECT CASE WHEN GREATEST(u.creation_date, a.last_success, a.reenabled_at,
    s.\"value\"::timestamptz AT TIME ZONE 'UTC') < (now() AT TIME ZONE 'UTC') - interval '2 days'
    THEN 'aged' ELSE 'young' END FROM users u LEFT JOIN user_activity a ON a.user_id = u.user_id
    JOIN system_config s ON s.\"key\" = 'inactivity_recording_since' WHERE u.user_id = '$HI_IDLE';"
}

# hi_setback: the idle user's creation, last success and re-enable, and recording_since, each three
# days earlier, written with the gate's server stopped; then it starts and is healthy again.
hi_setback() {
    local said rc=0
    HI_SETBACK_WHY=""
    if ! t docker stop "$CONTAINER" >/dev/null 2>&1; then
        HI_SETBACK_WHY="the gate's server could not be stopped"
        return 1
    fi
    case "$GATE_DB" in
    sqlite) said="$(hi_setback_sqlite 2>&1)" || rc=1 ;;
    postgres)
        said="$(hi_setback_postgres 2>&1)"
        [ "$(tail -n 1 <<<"$said")" = aged ] || rc=1
        ;;
    esac
    rm -f "$HI_D/setback.db"
    printf '%s\n' "$said" >>"$HI_D/setback.out"
    hi_restart
    [ "$rc" = 0 ] || HI_SETBACK_WHY="the times were not set back: $(head -c 200 <<<"$said")"
    [ "$rc" = 0 ]
}

# The gate's server, healthy again before the next row; started a second time if it is not. Down
# after both, every later phase would fail on it, so the run stops here.
hi_restart() {
    { t docker start "$CONTAINER" >/dev/null 2>&1 && hi_back_up; } && return 0
    { t docker start "$CONTAINER" >/dev/null 2>&1 && hi_back_up; } && return 0
    hi_bad "[I.server-down] the gate's server did not come back healthy after the set-back, started twice: the run stops here"
    note "policy-hours-inactivity: $HI_N rows, $HI_P pass, $HI_K NOTE, $HI_X FAIL"
    gate_summary
    exit 1
}

# hi_tool <command> <argument>: the host tool in the gate's container, as the server's own user.
hi_tool() {
    local u args=()
    u="$(uid_of_comm lldap)"
    [ -n "$u" ] && args=(-u "$u")
    t docker exec "${args[@]}" "$CONTAINER" /app/lldap "$1" --config-file /data/lldap_config.toml "$2"
}

hi_idle_setup() {
    local got
    HI_IDLE_TRIED=1
    hi_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$HI_IOU"'"}' >/dev/null &&
        hi_user "$HI_IDLE" "$HI_IOU" kerberos && hi_ready "$CONTAINER" "$HI_IDLE" || return 1
    HI_IDLE_DN="$(hi_dn "$HI_IDLE")"
    [ -n "$HI_IDLE_DN" ] && HI_IPOLICY="$(hi_link "$HI_IOU" "$HI_RUN idle" inactivity-days 1)" &&
        [ "$(hi_effective "$HI_IOU" inactivity-days)" = 1 ] || return 1
    got="$(hi_hush hi__simple "$HI_IDLE" right)"
    [ "${got%% *}" = 200 ] || {
        echo "a user made now was not admitted under inactivity-days 1 (status ${got%% *})" >"$HI_D/last.err"
        return 1
    }
}

hi_idle_rows() {
    local tag="$1" kind="$2" what="$3" door
    for door in $HI_DOORS; do
        if [ "$kind" = out ]; then
            hi_out "I.$tag-$door" "$door" "$HI_IDLE" "$HI_IDLE_DN" "$HI_IDLE_DETAIL" "$CONTAINER" "$what"
        else
            hi_in "I.$tag-$door" "$door" "$HI_IDLE" "$HI_IDLE_DN" "$CONTAINER" "$what"
        fi
    done
}

hi_api_reenable() {
    local mark out
    mark="$(log_mark)"
    out="$(hi_gql 'mutation($u: String!) { reenableUser(userId: $u) { ok } }' '{"u": "'"$HI_IDLE"'"}')"
    if [ "$(json_get reenableUser.ok <<<"$out" 2>/dev/null)" != True ]; then
        hi_bad "[I.api-reenable] reenableUser $HI_IDLE failed: $(head -c 200 "$HI_D/last.err")"
    elif ! log_once true ACCOUNT_REENABLE "$HI_IDLE" reenableUser "$mark" GRAPHQL; then
        hi_bad "[I.api-reenable] reenableUser $HI_IDLE answered ok, but $FAIL_WHY"
    else
        hi_pass "[I.api-reenable] reenableUser $HI_IDLE as admin: ok, one ACCOUNT_REENABLE row 'reenableUser' (protocol GRAPHQL)"
    fi
}

hi_tool_reenable() {
    local mark rc waited=0 got="" said="Re-enabled $HI_IDLE; a running server sees it within 30 seconds."
    mark="$(log_mark)"
    hi_tool reenable "$HI_IDLE" >"$HI_D/tool-reenable.out" 2>&1
    rc=$?
    if [ "$rc" != 0 ] || ! grep -qF "$said" "$HI_D/tool-reenable.out"; then
        hi_bad "[I.tool-reenable] lldap reenable $HI_IDLE exited $rc: '$(head -c 200 "$HI_D/tool-reenable.out")' (want exit 0 and '$said')"
        return
    fi
    while [ "$waited" -le 45 ]; do
        got="$(hi_hush hi__bind "$HI_IDLE_DN" right)"
        got="${got%% *}"
        [ "$got" = 0 ] && break
        sleep 5
        waited=$((waited + 5))
    done
    if [ "$got" != 0 ]; then
        hi_bad "[I.tool-reenable] after lldap reenable the LDAP bind still answered $got for $waited s (want 0 within 45 s)"
    elif ! log_once true ACCOUNT_REENABLE "$HI_IDLE" "lldap reenable" "$mark" SYSTEM; then
        hi_bad "[I.tool-reenable] the bind is admitted after $waited s, but $FAIL_WHY"
    else
        hi_pass "[I.tool-reenable] lldap reenable in the container (exit 0, '$said'): the right password is admitted after $waited s (within 45 s), one ACCOUNT_REENABLE row 'lldap reenable' (protocol SYSTEM)"
    fi
}

hi_idle() {
    local tag door
    if [ "$GATE_DB" != sqlite ] && [ "$GATE_DB" != postgres ]; then
        for tag in out api again tool; do
            [ "$tag" = api ] && hi_note "[I.api-reenable] the gate sets times back only on sqlite and postgres; on $GATE_DB not run"
            [ "$tag" = tool ] && hi_note "[I.tool-reenable] the gate sets times back only on sqlite and postgres; on $GATE_DB not run"
            for door in $HI_DOORS; do
                hi_note "[I.$tag-$door] the gate sets times back only on sqlite and postgres; on $GATE_DB not run"
            done
        done
        return
    fi
    if ! hi_idle_setup; then
        hi_bad "[I.setup] $HI_IDLE in $HI_IOU under inactivity-days 1 could not be made: $(head -c 200 "$HI_D/last.err")"
        return
    fi
    if ! hi_setback; then
        hi_bad "[I.setback] $HI_SETBACK_WHY"
        return
    fi
    hi_idle_rows out out "inactivity-days 1, the user's times three days back"
    hi_api_reenable
    hi_idle_rows api in "after reenableUser"
    if ! hi_setback; then
        hi_bad "[I.setback-again] $HI_SETBACK_WHY"
        return
    fi
    hi_idle_rows again out "the times three days back again, the re-enable included"
    hi_tool_reenable
    hi_idle_rows tool in "after lldap reenable"
}

hi_cleanup() {
    local u out deleted=0 left="" policy ou users=("$HI_USER" "$HI_TOTP")
    [ "$HI_IDLE_TRIED" = 1 ] && users+=("$HI_IDLE")
    docker rm -f -v "$HI_PEER_CTN" >/dev/null 2>&1
    [ "$HI_SIDE_UP" = 1 ] && hi_side_down
    HI_SESSION="" HI_SECRET=""
    for ou in "$HI_OU" "$HI_IOU"; do
        hi_gql 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' '{"o": "'"$ou"'"}' >/dev/null
    done
    for policy in "$HI_POLICY" "$HI_IPOLICY"; do
        [ -n "$policy" ] && hi_gql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$policy"'}' >/dev/null
    done
    for u in "${users[@]}"; do
        out="$(hi_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}')" &&
            [ "$(json_get deleteUser.ok <<<"$out" 2>/dev/null)" = True ] && deleted=$((deleted + 1))
    done
    for ou in "$HI_OU" "$HI_IOU"; do
        hi_gql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$ou"'"}' >/dev/null
    done
    out="$(hi_gql '{ policies { name } listOus ouPolicyStates { ou } users { id } }' '{}')" &&
        ! grep -q "$HI_RUN" <<<"$out" && left=none
    [ "$HI_MADE" = 1 ] || return 0
    if [ "$deleted" = "${#users[@]}" ] && [ "$left" = none ] && [ -z "$(docker ps -aq -f "name=^${HI_SIDE}$")" ]; then
        hi_pass "[S.cleanup] the phase's users are deleted, no policy, OU or user named $HI_RUN is left, and the side server is gone"
    else
        hi_bad "[S.cleanup] users deleted: $deleted of ${#users[@]}; leftovers named $HI_RUN: ${left:-some, or unread}; side server: $(docker ps -aq -f "name=^${HI_SIDE}$" | head -c 20)"
    fi
}

if hi_setup; then
    HI_MADE=1
    hi_hours_main
    hi_side
    hi_idle
fi
hi_cleanup
note "policy-hours-inactivity FAIL ids: ${HI_FAILS[*]:-none}"
note "policy-hours-inactivity: $HI_N rows, $HI_P pass, $HI_K NOTE, $HI_X FAIL"
note "policy-hours-inactivity: a correct product gives 44 rows, 0 FAIL: 44 pass on sqlite and postgres; 35 pass and 9 NOTE (the web-login rows) when the browser image is absent; 26 pass and 18 NOTE (the I. rows) on mysql, 21 pass and 23 NOTE there without the browser"
