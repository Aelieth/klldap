# shellcheck shell=bash
# Phase: kinit asks a fresh proof of a user who must give a second factor. Error 12 until a
# sign-in with password and code at a directory door, then a ticket for the window. Three side
# servers with their own realms: two with nothing set server-wide (one with a one-minute window),
# one with LLDAP_ENABLE_MFA=true and a one-minute window; and the main server's explicit true.

D="$(phase_dir)"
MK_RUN="mk$(date +%H%M%S)"
MK_SIDE="$CONTAINER-mfakdc" MK_VOL="klldap-gate-mfakdc-$RUNID" MK_KVOL="klldap-gate-mfakdc-kdc-$RUNID"
MK_SHORT="$CONTAINER-mfakdc1m" MK_SVOL="klldap-gate-mfakdc1m-$RUNID"
MK_SKVOL="klldap-gate-mfakdc1m-kdc-$RUNID"
MK_EXPL="$CONTAINER-mfakdc1me" MK_EVOL="klldap-gate-mfakdc1me-$RUNID"
MK_EKVOL="klldap-gate-mfakdc1me-kdc-$RUNID"
EXTRA_CONTAINERS+=("$MK_SIDE" "$MK_SHORT" "$MK_EXPL")
EXTRA_VOLUMES+=("$MK_VOL" "$MK_KVOL" "$MK_SVOL" "$MK_SKVOL" "$MK_EVOL" "$MK_EKVOL")
MK_PASS="GateKdcPass2026!"
MK_SVC="${MK_RUN}svc/gate.test"
MK_ALWAYS="${MK_RUN}always" MK_ENABLED="${MK_RUN}enabled"
MK_TEXT="second factor needed: sign in to the directory with your code (enrol there first if you have none), then run kinit again"
MK_SAYS="KDC policy rejects request"
MK_DETAIL="policy: enable-mfa (no fresh proof)"
MK_MAIN_PORTS="$HTTP_PORT $LDAP_PORT" MK_MAIN_TOKEN="$TOKEN"
MK_OLD_AT=0 MK_WIN_AT=0 MK_EXPL_AT=0 MK_UP=0 MK_MAIN_MADE=0 MK_SVC_MADE=0

mk_on() { HTTP_PORT="$1" LDAP_PORT="$2" TOKEN="$3"; }
mk_main() {
    # shellcheck disable=SC2086
    mk_on $MK_MAIN_PORTS "$MK_MAIN_TOKEN"
}
mk_gql() { graphql "$1" "$2" 2>"$D/last.err"; }

# mk_hush <cmd...>: runs a command that carries a password or a code without the shell trace.
mk_hush() {
    local xt=0 rc
    case $- in *x*) xt=1 ;; esac
    { set +x; } 2>/dev/null
    "$@"
    rc=$?
    [ "$xt" = 1 ] && set -x
    return "$rc"
}

# mk_totp <base32 secret> <step offset>: RFC 6238 (SHA-1, six digits, 30 s), stdlib only.
mk_totp() {
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

# mk_link <ou> <value>: the OU with a policy of its own setting enable-mfa; a failed link leaves
# no policy behind.
# shellcheck disable=SC2016
mk_link() {
    local id
    mk_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$1"'"}' >/dev/null || return 1
    id="$(mk_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
        '{"n": "'"$1"'", "i": [{"key": "enable-mfa", "value": "'"$2"'"}]}' | json_get createPolicy.id)" &&
        [ -n "$id" ] || return 1
    mk_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' \
        '{"o": "'"$1"'", "p": '"$id"'}' >/dev/null && return 0
    graphql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$id"'}' >/dev/null 2>&1 || true
    return 1
}

# mk_user <user> <ou>: a user with a principal (kerberossync), the phase's password, in the OU.
# shellcheck disable=SC2016
mk_user() {
    local vars
    mk_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$1"'", "email": "'"$1"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
        >/dev/null || return 1
    vars="$(MKU="$1" MKP="$MK_PASS" python3 -c 'import json,os; print(json.dumps({"id": os.environ["MKU"], "pw": os.environ["MKP"]}))')" &&
        mk_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
            "$vars" >/dev/null || return 1
    [ -z "$2" ] && return 0
    mk_move "$1" "$2"
}

# shellcheck disable=SC2016
mk_move() {
    mk_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
        '{"ids": ["'"$1"'"], "ou": "'"$2"'"}' >/dev/null
}

# mk_ready <container> <user>: the user's principal exists in that realm.
mk_ready() {
    local _
    for _ in $(seq 1 15); do
        if gexec_in "$1" kadmin -k -t /data/kadm5.keytab -p "admin/admin@$REALM" -q "getprinc $2" \
            >"$D/getprinc-$2.txt" 2>&1 && grep -q "^Principal: $2@$REALM" "$D/getprinc-$2.txt"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# mk_service <container>: the phase's service principal in that realm.
mk_service() {
    gexec_in "$1" kadmin -k -t /data/kadm5.keytab -p "admin/admin@$REALM" -q "addprinc -randkey $MK_SVC" \
        >"$D/addprinc-$1.txt" 2>&1 && ! grep -q " while " "$D/addprinc-$1.txt"
}

# mk_exempt <user>: a member of lldap_mfa_disabled.
# shellcheck disable=SC2016
mk_exempt() {
    local gid
    gid="$(mk_gql '{ groups { id displayName } }' '{}' | python3 -c '
import json, sys
groups = json.load(sys.stdin)["groups"]
print(next((g["id"] for g in groups if g["displayName"] == "lldap_mfa_disabled"), ""))')"
    [ -n "$gid" ] &&
        mk_gql 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
            '{"u": "'"$1"'", "g": '"$gid"'}' >/dev/null
}

# mk_enrol <user>: a first factor through the simple login's proof, finished with the current
# code; prints the secret. The finish is a proof of its own.
# shellcheck disable=SC2016
mk__enrol() {
    local token proof secret state started
    token="$(gate_login "$1" "$MK_PASS")" &&
        proof="$(gate_enrollment_proof "$1" "$MK_PASS")" || return 1
    TOKEN="$token" mk_gql 'mutation($p: String) { startMfaEnrollment(enrollmentProof: $p) { secretBase32 state } }' \
        '{"p": "'"$proof"'"}' >"$D/start-$1.json"
    started=$?
    secret="$(json_get startMfaEnrollment.secretBase32 <"$D/start-$1.json" 2>/dev/null)"
    state="$(json_get startMfaEnrollment.state <"$D/start-$1.json" 2>/dev/null)"
    rm -f "$D/start-$1.json"
    [ "$started" = 0 ] && [ -n "$secret" ] && [ -n "$state" ] || return 1
    TOKEN="$token" mk_gql 'mutation($s: String!, $c: String!) { finishMfaEnrollment(state: $s, code: $c) { ok } }' \
        '{"s": "'"$state"'", "c": "'"$(mk_totp "$secret" 0)"'"}' >/dev/null && printf '%s\n' "$secret"
}
mk_enrol() { mk_hush mk__enrol "$@"; }

mk_dn() {
    lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$1)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1
}

# mk_bind <user> <secret> <step offset>: an LDAP bind with password:code; status 0 when let in.
mk__bind() {
    local dn
    dn="$(mk_dn "$1")"
    [ -n "$dn" ] || return 2
    t ldapwhoami -x -H "$(ldap_url)" -D "$dn" -w "$MK_PASS:$(mk_totp "$2" "$3")" >"$D/bind-$1.out" 2>&1
}
mk_bind() { mk_hush mk__bind "$@"; }

# mk_kinit <tag> <container> <user> <cache> [armor cache]: ok, policy (error 12) or other; the
# client's output in kinit-<tag>.log and its KRB5_TRACE in kinit-<tag>.trace.
mk__kinit() {
    # shellcheck disable=SC2016
    gexec_in "$1" sh -c 'printf "%s\n" "$1" | KRB5_TRACE="$2.trace" KRB5CCNAME="$2" kinit $3 "$0"' \
        "$2@$REALM" "$MK_PASS" "$3" "${4:+-T $4}"
}
mk_kinit() {
    local tag="$1"
    shift
    if mk_hush mk__kinit "$@" >"$D/kinit-$tag.log" 2>&1; then
        mk_ticket "$1" "$3" && echo ok || echo noticket
        return
    fi
    gexec_in "$1" cat "$3.trace" >"$D/kinit-$tag.trace" 2>&1 || true
    if grep -qF "$MK_SAYS" "$D/kinit-$tag.log"; then echo policy; else echo other; fi
}

# mk_ticket <container> <cache>: the cache holds a ticket that has not expired.
mk_ticket() {
    # shellcheck disable=SC2016
    gexec_in "$1" sh -c 'KRB5CCNAME="$0" klist -s' "$2" >/dev/null 2>&1
}

# mk_refused <id> <got> <LOGIN|ACCESS_DENIED> <user> <log mark> <label> [where to look]: error 12
# and the refusal's one row, on the server the row talks to.
mk_refused() {
    if [ "$2" != policy ]; then
        p_bad "[K.$1] $6: got '$2', want error 12 ${7:-}"
    elif ! log_once false "$3" "$4" "$MK_DETAIL" "$5" KERBEROS; then
        p_bad "[K.$1] $6: error 12, but $FAIL_WHY"
    else
        p_ok "[K.$1] $6, with one $3 row '$MK_DETAIL'"
    fi
}

# mk_kvno <tag> <container> <cache>: a service ticket for the phase's service with that cache's
# ticket: ok, policy or other. The client's KRB5_TRACE goes to kvno-<tag>.trace.
mk_kvno() {
    local said=other
    # shellcheck disable=SC2016
    if gexec_in "$2" sh -c 'rm -f "$2"; KRB5_TRACE="$2" KRB5CCNAME="$1" kvno --no-store "$0"' \
        "$MK_SVC@$REALM" "$3" "$3.kvno.trace" >"$D/kvno-$1.log" 2>&1; then
        said=ok
    elif grep -qF "$MK_SAYS" "$D/kvno-$1.log"; then
        said=policy
    fi
    gexec_in "$2" cat "$3.kvno.trace" >"$D/kvno-$1.trace" 2>&1 || true
    echo "$said"
}

# mk_sent <tag>: the requests kvno-<tag>'s client sent, by its trace.
mk_sent() { grep -c 'Sending request (' "$D/kvno-$1.trace" 2>/dev/null || true; }

# mk_nrows <kind> <target> <detail> <mark> <n>: exactly n rows after the marker, each success
# false, KERBEROS, with the detail; else FAIL_WHY names both numbers.
mk__nrows() {
    graphql "query(\$id: ID!, \$t: String!) { logs(filter: {kinds: [$1], target: \$t}, afterId: \$id, limit: 20) { success protocol detail } }" \
        "$(ID="$4" T="$2" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "t": os.environ["T"]}))')" 2>/dev/null |
        WANT="$3" python3 -c '
import json, os, sys
rows = json.load(sys.stdin)["logs"]
ok = all(r.get("success") is False and r.get("detail") == os.environ["WANT"]
         and r.get("protocol") == "KERBEROS" for r in rows)
print("%d %s" % (len(rows), "ok" if ok else json.dumps(rows)[:300]))' 2>/dev/null
}
mk_nrows() {
    local got=""
    FAIL_WHY=""
    if [ -z "$4" ]; then
        FAIL_WHY="no log marker could be read"
        return 1
    fi
    for _ in $(seq 1 20); do
        got="$(mk__nrows "$@")"
        [ "${got%% *}" -ge "$5" ] 2>/dev/null && break
        sleep 0.5
    done
    sleep 1
    got="$(mk__nrows "$@")"
    [ "$got" = "$5 ok" ] || FAIL_WHY="$1 rows for $2 after the marker: ${got:-unread}; want $5 (one per request the client sent), each success false, protocol KERBEROS, '$3'"
    [ -z "$FAIL_WHY" ]
}

# mk_refused_tgs <id> <got> <user> <log mark> <label> <tag>: error 12, and one ACCESS_DENIED row
# per TGS request the client's trace shows (kvno asks again without referrals after a refusal).
mk_refused_tgs() {
    local sent
    sent="$(mk_sent "$6")"
    if [ "$2" != policy ]; then
        p_bad "[K.$1] $5: got '$2', want error 12 (see kvno-$6.log)"
    elif [ "${sent:-0}" -lt 1 ] 2>/dev/null || [ -z "$sent" ]; then
        p_bad "[K.$1] $5: error 12, but the client's trace shows no request sent (see kvno-$6.trace)"
    elif ! mk_nrows ACCESS_DENIED "$3" "$MK_DETAIL" "$4" "$sent"; then
        p_bad "[K.$1] $5: error 12 after $sent request(s), but $FAIL_WHY"
    else
        p_ok "[K.$1] $5, with $sent ACCESS_DENIED row(s) '$MK_DETAIL', one per TGS request the client sent"
    fi
}

# mk_wire <kdc port> <user>: an AS-REQ without pre-authentication over TCP from the gate host;
# prints the KRB-ERROR's code and text as code|text.
mk_wire() {
    WIRE_PORT="$1" WIRE_USER="$2" WIRE_REALM="$REALM" t python3 - <<'PY'
import os, socket, struct, time

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        size = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        size = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + size + body

def ctx(n, body):
    return tlv(0xA0 + n, body)

def integer(v):
    return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))

def text(s):
    return tlv(0x1B, s.encode())

def name(kind, parts):
    return tlv(0x30, ctx(0, integer(kind)) + ctx(1, tlv(0x30, b"".join(text(p) for p in parts))))

def read(buf, at):
    tag, n = buf[at], buf[at + 1]
    at += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[at:at + k], "big")
        at += k
    return tag, buf[at:at + n], at + n

realm, user = os.environ["WIRE_REALM"], os.environ["WIRE_USER"]
till = time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() + 36000)).encode()
body = tlv(0x30, ctx(0, tlv(0x03, b"\x00\x40\x00\x00\x00")) + ctx(1, name(1, [user]))
           + ctx(2, text(realm)) + ctx(3, name(2, ["krbtgt", realm])) + ctx(5, tlv(0x18, till))
           + ctx(7, integer(int(time.time()) & 0x7FFFFFFF))
           + ctx(8, tlv(0x30, integer(18) + integer(17))))
request = tlv(0x6A, tlv(0x30, ctx(1, integer(5)) + ctx(2, integer(10)) + ctx(4, body)))
with socket.create_connection(("127.0.0.1", int(os.environ["WIRE_PORT"])), timeout=10) as s:
    s.sendall(struct.pack(">I", len(request)) + request)
    size = struct.unpack(">I", s.recv(4, socket.MSG_WAITALL))[0]
    reply = s.recv(size, socket.MSG_WAITALL)
tag, outer, _ = read(reply, 0)
if tag != 0x7E:
    raise SystemExit("not a KRB-ERROR: tag %#x" % tag)
fields, at, seq = {}, 0, read(outer, 0)[1]
while at < len(seq):
    tag, value, at = read(seq, at)
    fields[tag - 0xA0] = read(value, 0)[1]
code = int.from_bytes(fields[6], "big", signed=True)
print("%d|%s" % (code, fields.get(11, b"").decode("ascii", "replace")))
PY
}

# mk_wait <epoch> <seconds>: sleeps until that many seconds after the epoch.
mk_wait() {
    local left=$(($1 + $2 - $(date +%s)))
    [ "$left" -gt 0 ] && sleep "$left"
    return 0
}

# mk_row <id> <got> <want> <label> [where to look]
mk_row() {
    if [ "$2" = "$3" ]; then p_ok "[K.$1] $4"; else p_bad "[K.$1] $4: got '$2', want '$3' ${5:-}"; fi
}

# The side server with an OU at always and one at enabled: its users and its service.
mk_side_setup() {
    local user
    mk_link "$MK_ALWAYS" always && mk_link "$MK_ENABLED" enabled || return 1
    for user in "${MK_RUN}a" "${MK_RUN}x"; do mk_user "$user" "$MK_ALWAYS" || return 1; done
    for user in "${MK_RUN}b" "${MK_RUN}o"; do mk_user "$user" "$MK_ENABLED" || return 1; done
    mk_exempt "${MK_RUN}x" || return 1
    for user in "${MK_RUN}a" "${MK_RUN}x" "${MK_RUN}b" "${MK_RUN}o"; do
        mk_ready "$MK_SIDE" "$user" || return 1
    done
    mk_service "$MK_SIDE" &&
        gexec_in "$MK_SIDE" kinit -k -t /data/kadm5.keytab -c /tmp/mk-armor "admin/admin@$REALM" \
            >"$D/armor.log" 2>&1
}

# The one-minute server: one user in an OU at enabled, enrolled now.
mk_short_setup() {
    mk_link "$MK_ENABLED" enabled && mk_user "${MK_RUN}w" "$MK_ENABLED" &&
        mk_ready "$MK_SHORT" "${MK_RUN}w"
}

# The one-minute server with LLDAP_ENABLE_MFA=true: one user, and the service.
mk_expl_setup() {
    mk_user "${MK_RUN}e" "" && mk_ready "$MK_EXPL" "${MK_RUN}e" && mk_service "$MK_EXPL"
}

# The main server: explicit true, one user (not enrolled yet) and the service.
mk_main_setup() {
    mk_user "${MK_RUN}m" "" || return 1
    MK_MAIN_MADE=1
    mk_ready "$CONTAINER" "${MK_RUN}m" && mk_service "$CONTAINER" && MK_SVC_MADE=1
}

mk_rows() {
    local h1 l1 k1 got mark secret wsecret esecret msecret dn moved=""
    read -r h1 l1 k1 <<<"$MK_SIDE_PORTS"
    read -r MK_S2_HTTP MK_S2_LDAP _ <<<"$MK_SHORT_PORTS"
    read -r MK_S3_HTTP MK_S3_LDAP _ <<<"$MK_EXPL_PORTS"
    mk_on "$h1" "$l1" "$MK_SIDE_TOKEN"
    got="$(mk_kinit old "$MK_SIDE" "${MK_RUN}o" /tmp/mk-old)"
    mk_main
    got="$got $(mk_kinit main-old "$CONTAINER" "${MK_RUN}m" /tmp/mk-main-old)"
    MK_OLD_AT="$(date +%s)"
    mk_row before "$got" "ok ok" "an enabled OU's user and the main server's user, neither enrolled: today's kinit, a ticket each in the cache"
    mk_on "$MK_S2_HTTP" "$MK_S2_LDAP" "$MK_SHORT_TOKEN"
    wsecret="$(mk_enrol "${MK_RUN}w")"
    MK_WIN_AT="$(date +%s)"
    got="$([ -n "$wsecret" ] && mk_kinit window-open "$MK_SHORT" "${MK_RUN}w" /tmp/mk-win)"
    mk_row window-open "$got" ok "one-minute server: enrolled just now, the enrolment's proof opens kinit, a ticket in the cache"
    mk_on "$MK_S3_HTTP" "$MK_S3_LDAP" "$MK_EXPL_TOKEN"
    esecret="$(mk_enrol "${MK_RUN}e")"
    MK_EXPL_AT="$(date +%s)"
    got="$([ -n "$esecret" ] && mk_kinit explicit-open "$MK_EXPL" "${MK_RUN}e" /tmp/mk-expl)"
    mk_row explicit-open "$got" ok "one-minute server with LLDAP_ENABLE_MFA=true: enrolled just now, kinit gets a ticket"
    mk_on "$h1" "$l1" "$MK_SIDE_TOKEN"
    mark="$(log_mark)"
    got="$(mk_kinit always-refused "$MK_SIDE" "${MK_RUN}a" /tmp/mk-always)"
    mk_refused always-refused "$got" LOGIN "${MK_RUN}a" "$mark" "an OU at always, a user not enrolled: kinit says '$MK_SAYS' (error 12)" "(see kinit-always-refused.log)"
    got="$(grep -F 'Received error from KDC' "$D/kinit-always-refused.trace" 2>/dev/null | grep -F "$MK_SAYS" | head -1)"
    mk_row always-trace "${got:+found}" found "KRB5_TRACE: ${got:-no line from the KDC with $MK_SAYS}" "(see kinit-always-refused.trace)"
    mark="$(log_mark)"
    got="$(mk_wire "$k1" "${MK_RUN}a" 2>"$D/wire.err")"
    got="$([ "$got" = "12|$MK_TEXT" ] && echo policy || echo "$got")"
    mk_refused wire-plain "$got" LOGIN "${MK_RUN}a" "$mark" "on the wire, an AS-REQ from the gate host: KRB-ERROR code 12 with the text" "(see wire.err)"
    mark="$(log_mark)"
    got="$(mk_kinit wire-fast "$MK_SIDE" "${MK_RUN}a" /tmp/mk-fast /tmp/mk-armor)"
    mk_refused wire-fast "$got" LOGIN "${MK_RUN}a" "$mark" "kinit -T with the admin keytab's ticket as armor: error 12" "(see kinit-wire-fast.log, armor.log)"
    if grep -qF "into FAST request" "$D/kinit-wire-fast.trace" 2>/dev/null; then
        p_ok "[K.wire-fast-used] the client's trace shows the request sent inside FAST"
    else
        note "[NOTE] ${PHASE}: [K.wire-fast-used] the client's trace shows no FAST line; FAST on the wire is the unit wire row's (crates/kerberos admission.rs)"
    fi
    note "[NOTE] ${PHASE}: [K.wire-fast-text] the image's kinit prints a KDC error's table text, never its e-text: our text inside FAST is proven by the unit wire row in crates/kerberos (admission.rs)"
    got="$(mk_kinit enabled-bare "$MK_SIDE" "${MK_RUN}b" /tmp/mk-bare)"
    mk_row enabled-bare "$got" ok "an OU at enabled, a user not enrolled: today's kinit, a ticket in the cache"
    got="$(mk_kinit exempt "$MK_SIDE" "${MK_RUN}x" /tmp/mk-exempt)"
    mk_row exempt "$got" ok "an OU at always, a member of lldap_mfa_disabled: today's kinit, a ticket in the cache"
    mk_move "${MK_RUN}a" "$MK_ENABLED" && secret="$(mk_enrol "${MK_RUN}a")" &&
        mk_move "${MK_RUN}a" "$MK_ALWAYS" && moved=1
    got="$([ -n "$moved" ] && [ -n "${secret:-}" ] && mk_kinit enrol-opens "$MK_SIDE" "${MK_RUN}a" /tmp/mk-always)"
    mk_row enrol-opens "$got" ok "the same user, enrolled and back in the always OU: the enrolment's proof opens kinit"
    got="$(mk_kvno service "$MK_SIDE" /tmp/mk-always)"
    mk_row service-ticket "$got" ok "and a service ticket for $MK_SVC on that ticket" "(see kvno-service.log)"
    mk_wait "$MK_WIN_AT" 62
    mk_wait "$MK_EXPL_AT" 62
    mk_wait "$MK_OLD_AT" 62
    mk_on "$MK_S2_HTTP" "$MK_S2_LDAP" "$MK_SHORT_TOKEN"
    mark="$(log_mark)"
    got="$(mk_kinit window-ended "$MK_SHORT" "${MK_RUN}w" /tmp/mk-win)"
    mk_refused window-ended "$got" LOGIN "${MK_RUN}w" "$mark" "one-minute server, 62 s after the proof: kinit refused, error 12" "(see kinit-window-ended.log)"
    dn="$(mk_dn "${MK_RUN}w")"
    got="$([ -n "$dn" ] && [ -n "$wsecret" ] && mk_hush mk_docs_bind "$dn" "$wsecret" && echo bound)"
    mk_row docs-bind "$got" bound "the docs' helper, first line: ldapwhoami -x -H <ldap> -D <dn> -W, the password, a colon and the code typed at the prompt" "(see docs-bind.out)"
    got="$(mk_kinit docs-kinit "$MK_SHORT" "${MK_RUN}w" /tmp/mk-docs)"
    mk_row docs-kinit "$got" ok "the docs' helper, second line: kinit gets a ticket"
    mk_on "$MK_S3_HTTP" "$MK_S3_LDAP" "$MK_EXPL_TOKEN"
    mark="$(log_mark)"
    got="$(mk_kinit explicit-ended "$MK_EXPL" "${MK_RUN}e" /tmp/mk-expl)"
    mk_refused explicit-ended "$got" LOGIN "${MK_RUN}e" "$mark" "LLDAP_ENABLE_MFA=true, 62 s after the proof: kinit refused, error 12" "(see kinit-explicit-ended.log)"
    got="$([ -n "$esecret" ] && mk_bind "${MK_RUN}e" "$esecret" 0 && echo bound)"
    mk_row explicit-bind "$got" bound "LLDAP_ENABLE_MFA=true: an LDAP bind with password:code" "(see bind-${MK_RUN}e.out)"
    got="$(mk_kinit explicit-kinit "$MK_EXPL" "${MK_RUN}e" /tmp/mk-expl-new)"
    mk_row explicit-kinit "$got" ok "LLDAP_ENABLE_MFA=true: after the bind, kinit gets a ticket"
    got="$(mk_kvno explicit-service "$MK_EXPL" /tmp/mk-expl-new)"
    mk_row explicit-service "$got" ok "and a service ticket for $MK_SVC on the ticket the bind opened" "(see kvno-explicit-service.log)"
    mk_on "$h1" "$l1" "$MK_SIDE_TOKEN"
    secret="$(mk_enrol "${MK_RUN}o")"
    mark="$(log_mark)"
    got="$([ -n "$secret" ] && mk_kvno old "$MK_SIDE" /tmp/mk-old)"
    mk_refused_tgs old-ticket "$got" "${MK_RUN}o" "$mark" "a ticket from before the user enrolled: refused at its next service ticket, error 12" old
    got="$(mk_kinit old-new "$MK_SIDE" "${MK_RUN}o" /tmp/mk-old-new)"
    mk_row old-then-new "$got" ok "the same user's kinit after enrolling: a ticket in the cache"
    mk_main
    msecret="$(mk_enrol "${MK_RUN}m")"
    mark="$(log_mark)"
    got="$([ -n "$msecret" ] && mk_kvno main-old "$CONTAINER" /tmp/mk-main-old)"
    mk_refused_tgs main-old-ticket "$got" "${MK_RUN}m" "$mark" "the main server's explicit true, at TGS: a ticket from before the enrolment is refused, error 12" main-old
    got="$(mk_bind "${MK_RUN}m" "$msecret" 1 && mk_kinit main-new "$CONTAINER" "${MK_RUN}m" /tmp/mk-main-new)"
    mk_row main-bind-kinit "$got" ok "the main server: a bind with password:code succeeds and kinit gets a ticket (the enrolment had opened the window already; the AS refusal and its lifting are K.explicit-*)" "(see bind-${MK_RUN}m.out)"
}

# The docs' two lines, the first one: the prompt read from stdin, without a terminal.
mk_docs_bind() {
    printf '%s:%s\n' "$MK_PASS" "$(mk_totp "$2" 0)" |
        t setsid -w ldapwhoami -x -H "$(ldap_url)" -D "$1" -W >"$D/docs-bind.out" 2>&1
}

mk_down() {
    side_down "$MK_SIDE" "$MK_VOL" "$D/side.log"
    side_down "$MK_SHORT" "$MK_SVOL" "$D/short.log"
    side_down "$MK_EXPL" "$MK_EVOL" "$D/explicit.log"
    docker volume rm "$MK_KVOL" "$MK_SKVOL" "$MK_EKVOL" >/dev/null 2>&1 || true
    mk_main
    if [ "$MK_MAIN_MADE" = 1 ]; then
        # shellcheck disable=SC2016
        mk_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"${MK_RUN}m"'"}' >/dev/null ||
            p_bad "[K.cleanup] ${MK_RUN}m was not deleted on the main server"
    fi
    [ "$MK_SVC_MADE" = 1 ] || return 0
    kadmin_q "delprinc -force $MK_SVC" >"$D/delprinc.txt" 2>&1 || true
    kadmin_q "getprinc $MK_SVC" >"$D/delprinc-check.txt" 2>&1 || true
    grep -q "Principal does not exist" "$D/delprinc-check.txt" ||
        p_bad "[K.cleanup] $MK_SVC is still on the main server (see delprinc.txt, delprinc-check.txt)"
}

# mk_up_side <name> <ports var> <token var> <setup> <label> [-e ...]: one side server, its admin
# token and its setup; one BAD row when any of it fails.
mk_up_side() {
    local name="$1" ports_var="$2" token_var="$3" setup="$4" label="$5" ports token http ldap
    shift 5
    if ! ports="$(side_up_kdc "$name" "$@" 2>"$D/$name.err")"; then
        p_bad "[K.setup] the $label did not become healthy (see $name.err and the server's log)"
        return 1
    fi
    read -r http ldap _ <<<"$ports"
    mk_on "$http" "$ldap" ""
    token="$(gate_login)" || token=""
    TOKEN="$token"
    printf -v "$ports_var" '%s' "$ports"
    printf -v "$token_var" '%s' "$token"
    if [ -z "$token" ] || ! "$setup"; then
        p_bad "[K.setup] the $label's OUs, users or service could not be made: $(head -c 200 "$D/last.err")"
        return 1
    fi
}

MK_SIDE_PORTS="" MK_SHORT_PORTS="" MK_EXPL_PORTS="" MK_SIDE_TOKEN="" MK_SHORT_TOKEN="" MK_EXPL_TOKEN=""
if mk_up_side "$MK_SIDE" MK_SIDE_PORTS MK_SIDE_TOKEN mk_side_setup "Kerberos side server" \
    "$MK_VOL" "$MK_KVOL" &&
    mk_up_side "$MK_SHORT" MK_SHORT_PORTS MK_SHORT_TOKEN mk_short_setup "one-minute side server" \
        "$MK_SVOL" "$MK_SKVOL" -e LLDAP_KERBEROS_OPTIONS__MFA_PROOF_WINDOW=1m &&
    mk_up_side "$MK_EXPL" MK_EXPL_PORTS MK_EXPL_TOKEN mk_expl_setup "explicit one-minute side server" \
        "$MK_EVOL" "$MK_EKVOL" -e LLDAP_ENABLE_MFA=true -e LLDAP_KERBEROS_OPTIONS__MFA_PROOF_WINDOW=1m; then
    MK_UP=1
fi
if [ "$MK_UP" = 1 ]; then
    mk_main
    if mk_main_setup; then
        mk_rows
    else
        p_bad "[K.setup] the main server's user or service could not be made: $(head -c 200 "$D/last.err")"
    fi
fi
mk_down
