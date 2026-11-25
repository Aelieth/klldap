# shellcheck shell=bash
# Phase: allowed-networks on a real server: a client container on the gate's network inside a
# list, the host through the published port outside it (it comes in as the network's gateway),
# for LDAP, HTTP and kinit; X-Forwarded-For with and without trusted_proxies; clientAddress; the
# warning on a policy save; lldap policy-unlink as the way back.

AN_D="$(phase_dir)"
AN_N=0 AN_P=0 AN_F=0 AN_K=0 AN_X=0 AN_FIND=()
AN_RUN="an$(date +%H%M%S)"
AN_USER="${AN_RUN}-u" AN_OU="${AN_RUN}ou" AN_POLICY="" AN_DN="" AN_IP="" AN_GW=""
AN_SIDE_USER="${AN_RUN}-s" AN_SIDE_OU="${AN_RUN}side" AN_SIDE_POLICY=""
AN_CTN="klldap-anclient-${RUNID}"
AN_SIDE="${CONTAINER}-an" AN_SIDE_VOL="${CONTAINER}-an-data"
AN_BAD="${CONTAINER}-anbad" AN_BAD_VOL="${CONTAINER}-anbad-data"
AN_MADE=0 AN_SIDE_UP=0
AN_NOT="policy: allowed-networks (address not allowed)"
AN_XT=0
case $- in *x*) AN_XT=1 ;; esac
{ set +x; } 2>/dev/null
AN_PASS="$(python3 -c 'import secrets; print("An" + secrets.token_hex(10) + "!")')"
[ "$AN_XT" = 1 ] && set -x
EXTRA_CONTAINERS+=("$AN_CTN" "$AN_SIDE" "$AN_BAD")
EXTRA_VOLUMES+=("$AN_SIDE_VOL" "$AN_BAD_VOL")

an_pass() { AN_N=$((AN_N + 1)) AN_P=$((AN_P + 1)); p_ok "$1"; }
an_note() { AN_N=$((AN_N + 1)) AN_K=$((AN_K + 1)); note "[NOTE] ${PHASE}: $1"; }
an_finding() { AN_N=$((AN_N + 1)) AN_F=$((AN_F + 1)) AN_FIND+=("${1%%]*}]"); note "[FINDING] ${PHASE}: $1"; }
an_fail() { AN_N=$((AN_N + 1)) AN_X=$((AN_X + 1)); p_bad "$1"; }
an_gql() { graphql "$1" "$2" 2>"$AN_D/last.err"; }
an_hush() {
    local xt=0 rc
    case $- in *x*) xt=1 ;; esac
    { set +x; } 2>/dev/null
    "$@"
    rc=$?
    [ "$xt" = 1 ] && set -x
    return "$rc"
}
an__pw_vars() { ANU="$1" ANP="$AN_PASS" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ANU"], "pw": os.environ["ANP"]}))'; }
an__login_body() { ANU="$1" ANP="${2:-$AN_PASS}" python3 -c 'import json,os; print(json.dumps({"username": os.environ["ANU"], "password": os.environ["ANP"]}), end="")'; }

# The gate reads its database on postgres and sqlite; elsewhere a row that needs a read is a NOTE.
AN_READS=0
case "$GATE_DB" in postgres | sqlite) AN_READS=1 ;; esac
an_is() { [ "$AN_READS" = 0 ] || [ "$1" = "$2" ]; }
an_pass_read() { if [ "$AN_READS" = 1 ]; then an_pass "$1"; else an_note "$1 | rows not read on $GATE_DB"; fi; }
an_mark() {
    sleep 1
    graphql '{ logs(limit: 1) { id } }' '{}' 2>/dev/null | json_get logs.0.id 2>/dev/null
}
an_one() {
    local n=""
    [ -n "$2" ] || {
        echo unread
        return
    }
    for _ in $(seq 1 20); do
        n="$(log_rows "$1 AND id > $2")"
        [ "${n:-0}" -ge 1 ] && break
        sleep 0.5
    done
    [ "$n" = 1 ] && sleep 1 && n="$(log_rows "$1 AND id > $2")"
    printf '%s\n' "${n:-0}"
}
an_who() { printf "(actor = '%s' OR target = '%s')" "$1" "$1"; }
an_peer() { printf "peer IN ('%s', '::ffff:%s')" "$1" "$1"; }

# The client: the image itself, idle on the gate's network; HTTP through bash's /dev/tcp.
an_client_up() {
    cat >"$AN_D/an-http.sh" <<'SH'
#!/bin/bash
# an-http.sh <host> <port> <path> <forwarded or ->; stdin: a bearer token or - on its first line,
# then the JSON body. Prints "<status> <body>".
read -r bearer
body="$(cat)"
exec 3<>"/dev/tcp/$1/$2" || {
    echo "000 no connection"
    exit 0
}
{
    printf 'POST %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n' "$3" "$1"
    printf 'Content-Type: application/json\r\nContent-Length: %s\r\n' "${#body}"
    [ "$4" = - ] || printf 'X-Forwarded-For: %s\r\n' "$4"
    [ "$bearer" = - ] || printf 'Authorization: Bearer %s\r\n' "$bearer"
    printf '\r\n%s' "$body"
} >&3
reply="$(tr -d '\r' <&3)"
status="$(printf '%s\n' "$reply" | head -n 1 | cut -d ' ' -f 2)"
printf '%s %s\n' "${status:-000}" "${reply#*$'\n\n'}"
SH
    docker rm -f -v "$AN_CTN" >/dev/null 2>&1
    docker run -d --name "$AN_CTN" --network "$NET" --entrypoint sleep "$GATE_IMAGE" 3600 >/dev/null || return 1
    docker cp "$AN_D/an-http.sh" "$AN_CTN:/tmp/an-http.sh" >/dev/null || return 1
    printf '[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n dns_lookup_realm = false\n udp_preference_limit = 1\n rdns = false\n[realms]\n %s = {\n  kdc = %s:%s\n }\n' \
        "$REALM" "$REALM" "$CONTAINER" "$KDC_INNER_PORT" | docker exec -i "$AN_CTN" sh -c 'cat >/tmp/krb5.conf' || return 1
    AN_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$AN_CTN")"
    AN_GW="$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' "$NET" | awk '{print $1}')"
    [ -n "$AN_IP" ] && [ -n "$AN_GW" ]
}
an_http_in() { docker exec -i "$AN_CTN" bash /tmp/an-http.sh "$@"; }
# an__login_in <host> <user> <forwarded or ->: the simple login from the client.
an__login_in() { { printf -- '-\n'; an__login_body "$2"; } | an_http_in "$1" 17170 /auth/simple/login "$3"; }
an_login_in() { an_hush an__login_in "$@"; }
# an_address_in <host> <token> <forwarded or ->: clientAddress as the client asks it.
an_address_in() {
    local out
    out="$({ printf '%s\n' "$2"; printf '%s' '{"query": "{ clientAddress }"}'; } | an_http_in "$1" 17170 /api/graphql "$3")"
    json_get data.clientAddress <<<"${out#* }" 2>/dev/null || echo "unread: ${out:0:200}"
}
an__ldap_in() {
    printf '%s' "$AN_PASS" | docker exec -i "$AN_CTN" sh -c \
        'cat >/tmp/an.pw && ldapwhoami -x -H "ldap://$0:3890" -D "$1" -y /tmp/an.pw >/dev/null 2>&1; rc=$?; rm -f /tmp/an.pw; exit $rc' \
        "$CONTAINER" "$1"
}
an_ldap_in() { an_hush an__ldap_in "$@"; }
an__kinit_in() {
    printf '%s\n' "$AN_PASS" | docker exec -i -e KRB5_CONFIG=/tmp/krb5.conf -e KRB5CCNAME=/tmp/an_cc "$AN_CTN" \
        kinit "$AN_USER@$REALM" >"$AN_D/kinit-in.out" 2>&1 && echo ok && return
    grep -q "revoked" "$AN_D/kinit-in.out" && echo revoked || echo other
}
an_kinit_in() { an_hush an__kinit_in; }
an__kinit_there() {
    kinit_pw "$AN_USER@$REALM" "$AN_PASS" >"$AN_D/kinit-there.out" 2>&1 && echo ok && return
    grep -q "revoked" "$AN_D/kinit-there.out" && echo revoked || echo other
}
an_kinit_there() { an_hush an__kinit_there; }
an__ldap_host() {
    local f="$AN_D/.bindpw" rc
    (umask 077 && printf '%s' "$AN_PASS" >"$f")
    t ldapwhoami -x -H "$(ldap_url)" -D "$1" -y "$f" >/dev/null 2>&1
    rc=$?
    rm -f "$f"
    return "$rc"
}
an_ldap_host() { an_hush an__ldap_host "$@"; }
# an__simple_host <port> <user> <password> <forwarded or ->: the simple login from the host.
an__simple_host() {
    LOGIN_URL="http://127.0.0.1:$1/auth/simple/login" LOGIN_BODY="$(an__login_body "$2" "$3")" LOGIN_XFF="$4" t python3 - <<'PY'
import os, urllib.error, urllib.request
headers = {"Content-Type": "application/json"}
if os.environ["LOGIN_XFF"] != "-":
    headers["X-Forwarded-For"] = os.environ["LOGIN_XFF"]
req = urllib.request.Request(os.environ["LOGIN_URL"], headers=headers, data=os.environ["LOGIN_BODY"].encode())
try:
    urllib.request.urlopen(req).read()
    print("200 token")
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode(errors="replace")[:300])
except Exception as e:
    print("000", str(e)[:200])
PY
}
an_simple_host() { an_hush an__simple_host "$@"; }
# an_forged_rows <mark>: "one" for exactly the forged login's row on the side server, else the rows read.
an_forged_rows() {
    an_gql 'query($id: ID!, $t: String!) { logs(filter: {kinds: [BIND], target: $t}, afterId: $id, limit: 20) { success peer forwardedFor detail } }' \
        '{"id": "'"${1:-0}"'", "t": "'"$AN_SIDE_USER"'"}' | GW="$AN_GW" NOT="$AN_NOT" python3 -c '
import json, os, sys
rows = json.load(sys.stdin)["logs"]
want = {"success": False, "peer": os.environ["GW"], "forwardedFor": "203.0.113.9", "detail": os.environ["NOT"]}
print("one" if rows == [want] else json.dumps(rows)[:300])' 2>/dev/null
}
an_side_uid() {
    docker exec "$AN_SIDE" sh -c 'for p in /proc/[0-9]*; do
        set -- $(tr "\0" " " <"$p/cmdline" 2>/dev/null)
        [ "${2:-}" = run ] || continue
        awk "/^Uid:/ {print \$2; exit}" "$p/status"
        exit 0
    done
    exit 1' 2>/dev/null
}

an_setup() {
    local i
    an_client_up || {
        an_fail "[N1.setup-client] the client container on $NET could not be made, or its address or the network's gateway is unread (address '$AN_IP', gateway '$AN_GW')"
        return 1
    }
    an_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$AN_USER"'", "email": "'"$AN_USER"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' >/dev/null &&
        an_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$(an_hush an__pw_vars "$AN_USER")" >/dev/null &&
        an_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$AN_OU"'"}' >/dev/null &&
        an_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$AN_USER"'"], "ou": "'"$AN_OU"'"}' >/dev/null &&
        AN_POLICY="$(an_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
            '{"n": "'"$AN_RUN"' nets", "i": [{"key": "allowed-networks", "value": "'"$AN_IP"'/32"}]}' | json_get createPolicy.id 2>/dev/null)" &&
        [ -n "$AN_POLICY" ] || {
        an_fail "[N1.setup] $AN_USER in OU $AN_OU and the policy allowed-networks=$AN_IP/32 could not be made: $(head -c 300 "$AN_D/last.err")"
        return 1
    }
    AN_DN="$(lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$AN_USER)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1)"
    for i in $(seq 1 15); do
        kadmin_q "getprinc $AN_USER" 2>/dev/null | grep -q "^Principal: $AN_USER@$REALM" && break
        [ "$i" = 15 ] && {
            an_fail "[N1.setup] no principal $AN_USER@$REALM"
            return 1
        }
        sleep 1
    done
    [ -n "$AN_DN" ] || {
        an_fail "[N1.setup] no DN found for $AN_USER"
        return 1
    }
}

an_main() {
    local out tok addr right wrong mark rows rc got quiet
    out="$(an_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok warnings } }' '{"o": "'"$AN_OU"'", "p": '"$AN_POLICY"'}')"
    if [ "$(json_get setOuPolicy.ok <<<"$out" 2>/dev/null)" = True ] && [ "$(json_get setOuPolicy.warnings <<<"$out" 2>/dev/null)" = "[]" ]; then
        an_pass "[N1.save-no-warning] the admin links allowed-networks=$AN_IP/32 to $AN_OU: ok, warnings [] (the list does not reach the admin)"
    else
        an_finding "[N1.save-no-warning] setOuPolicy answered '${out:0:300}' $(head -c 200 "$AN_D/last.err") (want ok and warnings [])"
    fi

    out="$(an_login_in "$CONTAINER" "$AN_USER" -)"
    tok="$(json_get token <<<"${out#* }" 2>/dev/null)"
    if [ "${out%% *}" = 200 ] && [ -n "$tok" ]; then
        an_pass "[N1.http-inside] $AN_USER's simple login from the client container at $AN_IP (inside the list): 200 and a token"
    else
        an_finding "[N1.http-inside] the simple login from $AN_IP answered '${out:0:200}' (want 200)"
    fi
    addr="$(an_address_in "$CONTAINER" "${tok:--}" -)"
    if [ "$addr" = "$AN_IP" ]; then
        an_pass "[N1.client-address] that session's { clientAddress } from the client: $addr, the client's own address"
    else
        an_finding "[N1.client-address] { clientAddress } from the client gave '$addr' (want $AN_IP)"
    fi

    mark="$(an_mark)"
    right="$(an_simple_host "$HTTP_PORT" "$AN_USER" "$AN_PASS" -)"
    wrong="$(an_simple_host "$HTTP_PORT" "$AN_USER" "wrong-$AN_RUN" -)"
    rows="$(an_one "kind = 'bind' AND protocol = 'http' AND NOT success AND detail = '$AN_NOT' AND $(an_who "$AN_USER") AND $(an_peer "$AN_GW")" "$mark")"
    if [ "${right%% *}" = 401 ] && [ "$right" = "$wrong" ] && an_is "$rows" 1; then
        an_pass_read "[N1.http-outside] the right password at /auth/simple/login from the host through the published port: 401, the body of a wrong password byte for byte, and one bind row '$AN_NOT' with peer $AN_GW"
    else
        an_finding "[N1.http-outside] from the host the right password answered '${right:0:150}', a wrong one '${wrong:0:150}' (want both 401, equal); '$AN_NOT' rows with peer $AN_GW: $rows (want 1)"
    fi
    addr="$(an_gql '{ clientAddress }' '{}' | json_get clientAddress 2>/dev/null)"
    if [ "$addr" = "$AN_GW" ]; then
        an_pass "[N1.published-gateway] the admin's { clientAddress } from the host through the published port is $addr, the gate network's gateway: a client through the published port is judged as the gateway"
    else
        an_finding "[N1.published-gateway] the admin's { clientAddress } from the host gave '$addr' (the network's gateway is $AN_GW)"
    fi

    an_ldap_in "$AN_DN"
    rc=$?
    if [ "$rc" = 0 ]; then
        an_pass "[N1.ldap-inside] ldapwhoami as $AN_USER from the client container to $CONTAINER:3890: bound"
    else
        an_finding "[N1.ldap-inside] ldapwhoami from the client exited $rc (want 0)"
    fi
    mark="$(an_mark)"
    an_ldap_host "$AN_DN"
    rc=$?
    rows="$(an_one "kind = 'bind' AND protocol = 'ldap' AND NOT success AND detail = '$AN_NOT' AND $(an_who "$AN_USER") AND $(an_peer "$AN_GW")" "$mark")"
    if [ "$rc" = 49 ] && an_is "$rows" 1; then
        an_pass_read "[N1.ldap-outside] ldapwhoami with the right password from the host through the published port: 49, and one bind row '$AN_NOT' (protocol ldap) with peer $AN_GW"
    else
        an_finding "[N1.ldap-outside] ldapwhoami from the host exited $rc (want 49); '$AN_NOT' ldap rows: $rows (want 1)"
    fi

    got="$(an_kinit_in)"
    if [ "$got" = ok ]; then
        an_pass "[N1.kinit-inside] kinit $AN_USER from the client container to $CONTAINER:$KDC_INNER_PORT (tcp): a ticket"
    else
        an_finding "[N1.kinit-inside] kinit from the client gave '$got': $(head -c 200 "$AN_D/kinit-in.out")"
    fi
    # kinit is refused before any password: the row must be the first of its flood window.
    quiet="$(flood_quiet LOGIN KERBEROS)"
    mark="$(an_mark)"
    got="$(an_kinit_there)"
    rows="$(an_one "kind = 'login' AND protocol = 'kerberos' AND NOT success AND detail = '$AN_NOT' AND $(an_who "$AN_USER")" "$mark")"
    if [ "$got" = revoked ] && an_is "$rows" 1; then
        an_pass_read "[N1.kinit-outside] kinit $AN_USER inside the server's container (loopback, outside the list): 'credentials have been revoked' (18), and one login row '$AN_NOT' (protocol kerberos), the first of its flood window (waited $quiet s for the last one to close)"
    else
        an_fail "[N1.kinit-outside] kinit inside the server's container gave '$got' (want revoked): $(head -c 200 "$AN_D/kinit-there.out"); rows: $rows (want 1, after $quiet s of waiting for a closed flood window)"
    fi

    out="$(an_login_in "$CONTAINER" "$AN_USER" 192.0.2.1)"
    tok="$(json_get token <<<"${out#* }" 2>/dev/null)"
    addr="$(an_address_in "$CONTAINER" "${tok:--}" 192.0.2.1)"
    if [ "${out%% *}" = 200 ] && [ "$addr" = "$AN_IP" ]; then
        an_pass "[N1.forwarded-unlisted] no trusted_proxies: the client sends X-Forwarded-For 192.0.2.1 (outside the list); its simple login is 200 and its { clientAddress } is still $AN_IP"
    else
        an_finding "[N1.forwarded-unlisted] with X-Forwarded-For 192.0.2.1 and no trusted_proxies: login '${out:0:120}' (want 200), clientAddress '$addr' (want $AN_IP)"
    fi
}

an_bad_proxies() {
    local out
    if side_up "$AN_BAD" "$AN_BAD_VOL" -e LLDAP_TRUSTED_PROXIES=10.0.0.1 >/dev/null 2>&1; then
        an_finding "[N1.bad-proxies] a server with LLDAP_TRUSTED_PROXIES=10.0.0.1 (no prefix) became healthy (want a refused start)"
    else
        out="$(docker logs "$AN_BAD" 2>&1 | grep -m1 'trusted_proxies "10.0.0.1" is refused')"
        if [ -n "$out" ] && [ -z "$(docker ps -q -f "name=^${AN_BAD}$")" ]; then
            an_pass "[N1.bad-proxies] a server with LLDAP_TRUSTED_PROXIES=10.0.0.1 refuses to start, naming the entry: '${out:0:160}'"
        else
            an_finding "[N1.bad-proxies] LLDAP_TRUSTED_PROXIES=10.0.0.1: the container is $(docker ps -q -f "name=^${AN_BAD}$" | grep -q . && echo running || echo stopped), and its log names no refused entry (see bad-proxies.log)"
        fi
    fi
    side_down "$AN_BAD" "$AN_BAD_VOL" "$AN_D/bad-proxies.log"
}

an_side() {
    local ports out tok addr forged mark rows uid back=0 waited=0 xff bad=0 said=
    ports="$(side_up "$AN_SIDE" "$AN_SIDE_VOL" -e "LLDAP_TRUSTED_PROXIES=$AN_IP/32")" || {
        an_fail "[N1.side-up] the side server with LLDAP_TRUSTED_PROXIES=$AN_IP/32 did not become healthy (see side.log)"
        side_down "$AN_SIDE" "$AN_SIDE_VOL" "$AN_D/side.log"
        return 1
    }
    AN_SIDE_UP=1
    if docker logs "$AN_SIDE" 2>&1 | grep -q "X-Forwarded-For is read behind the trusted proxies $AN_IP/32"; then
        an_pass "[N1.side-up] a side server with LLDAP_TRUSTED_PROXIES=$AN_IP/32 starts and its log names the trusted proxies"
    else
        an_finding "[N1.side-up] the side server's log does not name the trusted proxies $AN_IP/32"
    fi
    # shellcheck disable=SC2086
    side_use $ports
    an_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' '{"u": {"id": "'"$AN_SIDE_USER"'", "email": "'"$AN_SIDE_USER"'@gate.test"}}' >/dev/null &&
        an_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$(an_hush an__pw_vars "$AN_SIDE_USER")" >/dev/null &&
        an_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$AN_SIDE_OU"'"}' >/dev/null &&
        an_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$AN_SIDE_USER"'"], "ou": "'"$AN_SIDE_OU"'"}' >/dev/null &&
        AN_SIDE_POLICY="$(an_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
            '{"n": "'"$AN_RUN"' far", "i": [{"key": "allowed-networks", "value": "203.0.113.0/24, '"$AN_IP"'/32"}]}' | json_get createPolicy.id 2>/dev/null)" &&
        [ -n "$AN_SIDE_POLICY" ] &&
        an_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' '{"o": "'"$AN_SIDE_OU"'", "p": '"$AN_SIDE_POLICY"'}' >/dev/null || {
        an_fail "[N1.side-setup] $AN_SIDE_USER in $AN_SIDE_OU under allowed-networks=203.0.113.0/24, $AN_IP/32 could not be made on the side server: $(head -c 300 "$AN_D/last.err")"
        side_back
        return 1
    }

    out="$(an_login_in "$AN_SIDE" "$AN_SIDE_USER" 203.0.113.9)"
    tok="$(json_get token <<<"${out#* }" 2>/dev/null)"
    addr="$(an_address_in "$AN_SIDE" "${tok:--}" 203.0.113.9)"
    if [ "${out%% *}" = 200 ] && [ "$addr" = 203.0.113.9 ]; then
        an_pass "[N1.forwarded-listed] trusted_proxies $AN_IP/32: the client (a listed proxy) sends X-Forwarded-For 203.0.113.9; the simple login is 200 and { clientAddress } is 203.0.113.9"
    else
        an_finding "[N1.forwarded-listed] from the listed proxy with X-Forwarded-For 203.0.113.9: login '${out:0:120}' (want 200), clientAddress '$addr' (want 203.0.113.9)"
    fi
    out="$(an_login_in "$AN_SIDE" "$AN_SIDE_USER" -)"
    tok="$(json_get token <<<"${out#* }" 2>/dev/null)"
    addr="$(an_address_in "$AN_SIDE" "${tok:--}" -)"
    if [ "${out%% *}" = 200 ] && [ "$addr" = "$AN_IP" ]; then
        an_pass "[N1.forwarded-no-header] the listed proxy with no X-Forwarded-For is itself the client: its address $AN_IP is in the list, the simple login is 200 and { clientAddress } is $AN_IP"
    else
        an_finding "[N1.forwarded-no-header] the listed proxy without the header: login '${out:0:120}' (want 200), clientAddress '$addr' (want $AN_IP)"
    fi
    for xff in 203.0.113.9:443 '[2001:db8::9]' unknown '203.0.113.9,,'; do
        out="$(an_login_in "$AN_SIDE" "$AN_SIDE_USER" "$xff")"
        [ "${out%% *}" = 401 ] || bad=$((bad + 1)) said+="'$xff' answered '${out:0:60}'; "
    done
    addr="$(an_hush an_address_in "$AN_SIDE" "$TOKEN" unknown)"
    if [ "$bad" = 0 ] && [ "$addr" = None ]; then
        an_pass "[N1.forwarded-malformed] from the listed proxy, X-Forwarded-For with a port, brackets, the text 'unknown' or an empty element leaves the client unknown: 401 each though the proxy's own address $AN_IP is in the list; the side admin's { clientAddress } (no list reaches the admin), asked from the proxy with 'unknown', is null"
    else
        an_finding "[N1.forwarded-malformed] want 401 for each of a port, brackets, 'unknown', an empty element: ${said:-all 401}; clientAddress with 'unknown': '$addr' (want null)"
    fi
    mark="$(an_mark)"
    forged="$(an_simple_host "$HTTP_PORT" "$AN_SIDE_USER" "$AN_PASS" 203.0.113.9)"
    # The writer stores rows on its tick: ask until a row is there, then once more.
    rows=""
    for _ in $(seq 1 20); do
        rows="$(an_forged_rows "$mark")"
        [ "$rows" = "[]" ] || break
        sleep 0.5
    done
    [ "$rows" = "[]" ] || { sleep 1 && rows="$(an_forged_rows "$mark")"; }
    if [ "${forged%% *}" = 401 ] && [ "$rows" = one ]; then
        an_pass "[N1.forwarded-forged] from the host (the gateway $AN_GW, not a listed proxy) with X-Forwarded-For 203.0.113.9: 401, and its one bind row keeps peer $AN_GW and forwardedFor 203.0.113.9"
    else
        an_finding "[N1.forwarded-forged] from the host with a forged X-Forwarded-For: '${forged:0:100}' (want 401); rows: ${rows:-unread}"
    fi

    out="$(an_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok warnings } }' '{"o": "", "p": '"$AN_SIDE_POLICY"'}')"
    if [ "$(json_get setOuPolicy.ok <<<"$out" 2>/dev/null)" = True ] &&
        [ "$(json_get setOuPolicy.warnings.0 <<<"$out" 2>/dev/null)" = "allowed-networks: the list that now applies to you does not contain the address the server sees you as ($AN_GW). The way back, on the host: lldap policy-unlink --config-file <config> '(root)'" ] &&
        [ "$(json_get setOuPolicy.warnings <<<"$out" | python3 -c 'import ast,sys; print(len(ast.literal_eval(sys.stdin.read())))' 2>/dev/null)" = 1 ]; then
        an_pass "[N1.save-warning] the side admin, at $AN_GW, links allowed-networks=203.0.113.0/24, $AN_IP/32 to the root: ok, with one warning naming $AN_GW and the way back, lldap policy-unlink on '(root)'"
    else
        an_finding "[N1.save-warning] setOuPolicy on the side root answered '${out:0:300}' $(head -c 200 "$AN_D/last.err") (want ok and one warning naming $AN_GW and the way back on '(root)')"
    fi
    if ! an_gql '{ apiVersion }' '{}' >/dev/null && grep -q 'HTTP 401' "$AN_D/last.err"; then
        an_pass "[N1.locked-out] the side admin's next request is refused: 401"
    else
        an_finding "[N1.locked-out] the side admin's next request was not refused with 401: $(head -c 200 "$AN_D/last.err")"
    fi
    uid="$(an_side_uid)"
    if t docker exec -u "${uid:-1000}" "$AN_SIDE" /app/lldap policy-unlink --config-file /data/lldap_config.toml '(root)' >"$AN_D/unlink.out" 2>&1; then
        while [ "$waited" -le 45 ]; do
            an_gql '{ apiVersion }' '{}' >/dev/null && back=1 && break
            sleep 5
            waited=$((waited + 5))
        done
    fi
    if [ "$back" = 1 ] && grep -q 'Removed the policy link of (root)' "$AN_D/unlink.out"; then
        an_pass "[N1.policy-unlink] lldap policy-unlink '(root)' in the side container: 'Removed the policy link of (root)', and the side admin's requests answer again after ${waited} s (within 45 s)"
    else
        an_finding "[N1.policy-unlink] lldap policy-unlink: '$(head -c 200 "$AN_D/unlink.out")'; the side admin back: $back after ${waited} s"
    fi
    side_back
}

an_cleanup() {
    local out deleted=0 left=""
    docker rm -f -v "$AN_CTN" >/dev/null 2>&1
    [ "$AN_SIDE_UP" = 1 ] && side_down "$AN_SIDE" "$AN_SIDE_VOL" "$AN_D/side.log"
    [ "$AN_MADE" = 1 ] || return 0
    an_gql 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' '{"o": "'"$AN_OU"'"}' >/dev/null
    [ -n "$AN_POLICY" ] && an_gql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$AN_POLICY"'}' >/dev/null
    out="$(an_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$AN_USER"'"}')" &&
        [ "$(json_get deleteUser.ok <<<"$out" 2>/dev/null)" = True ] && deleted=1
    an_gql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$AN_OU"'"}' >/dev/null
    out="$(an_gql '{ policies { name } listOus ouPolicyStates { ou } users { id } }' '{}')" && ! grep -q "$AN_RUN" <<<"$out" && left=none
    if [ "$deleted" = 1 ] && [ "$left" = none ] && [ -z "$(docker ps -aq -f "name=^${AN_CTN}$")" ]; then
        an_pass "[N1.cleanup] $AN_USER is deleted, no policy, OU or user named $AN_RUN is left, and the client container is gone"
    else
        an_fail "[N1.cleanup] users deleted: $deleted of 1; leftovers named $AN_RUN: ${left:-some, or unread}; client container left: $(docker ps -aq -f "name=^${AN_CTN}$")"
    fi
}

if an_setup; then
    AN_MADE=1
    an_main
    an_bad_proxies
    an_side
fi
an_cleanup
note "allowed-networks FINDING ids: ${AN_FIND[*]:-none}"
note "allowed-networks: $AN_N rows, $AN_P pass, $AN_F FINDING, $AN_K NOTE, $AN_X FAIL"
note "allowed-networks: a correct product gives 20 rows, 0 FINDING, 0 FAIL: 20 pass on postgres and sqlite; on mysql 17 pass and 3 NOTE ([N1.http-outside], [N1.ldap-outside], [N1.kinit-outside])"
