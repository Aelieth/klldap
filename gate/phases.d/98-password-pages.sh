# shellcheck shell=bash
# Phase: U1′'s password pages and the set-password tool. register/start gives a key only to a
# synced user; that user's finish carries the password sealed for that user (OAEP label
# klldap-kerberos-envelope-v1:<user>), and the server commits it to both stores in one transaction.

# Passwords and tokens travel in this phase's variables and helpers: nothing of it is traced. The
# tracing state is put back at the end.
PP_XT=0
case $- in *x*) PP_XT=1 ;; esac
{ set +x; } 2>/dev/null
PP_D="$(phase_dir)"
PP_RUN="pp$(date +%H%M%S)"
PP_PM="${PP_RUN}m" PP_SYNC="${PP_RUN}s" PP_PLAIN="${PP_RUN}p" PP_BIG="${PP_RUN}b" PP_NEW="${PP_RUN}n"
PP_GONE_MUT='mutation($u: String!, $e: String!) { syncKerberosPassword(userId: $u, encryptedPassword: $e) }'
PP_SET='mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }'
PP_UPD='mutation($u: UpdateUserInput!) { updateUser(user: $u) { ok } }'
PP_KEY="" PP_GOT="" PP_WIRE="" PP_ALERT=""
PP_BOTH_NEW="bind-new=yes bind-old=no kinit-new=yes kinit-old=no"
PP_BOTH_OLD="bind-new=no bind-old=yes kinit-new=no kinit-old=yes"
PP_BROWSER_IMAGE="mcr.microsoft.com/playwright@sha256:766137e2d9caad4744187e53cdc89320ba6f2eb57cff097374020944b44dd0a9"
PP_BROWSER_CTN="klldap-pp-wire-${RUNID}"
EXTRA_CONTAINERS+=("$PP_BROWSER_CTN")
PP_OFF_CTN="klldap-pp-krboff-${RUNID}" PP_OFF_DATA="klldap-pp-krboff-data-${RUNID}" PP_OFF_KDC="klldap-pp-krboff-kdc-${RUNID}"
PP_OFF_PORT="" PP_OFF_TOK=""
PP_OFF_DISABLED="Kerberos is disabled on this server (kerberos_options.enabled is false)"
PP_OFF_SAID="$PP_OFF_DISABLED: enable Kerberos, or turn the user's Kerberos sync off first"
PP_OFF_CREATE="Kerberos is disabled; create the user without Kerberos sync"
PP_OFF_SYNC_ON="$PP_OFF_DISABLED: Kerberos sync is turned on only with Kerberos enabled"
PP_OFF_LEFT="Kerberos is disabled: a principal, if there is one, is left for the start pass, which removes it at the next start with Kerberos enabled"
PP_OFF_STATUS="Kerberos is disabled: the status of a principal, if there is one, is left for the start pass, which sets it from lldap_disabled at the next start with Kerberos enabled"
EXTRA_CONTAINERS+=("$PP_OFF_CTN")
EXTRA_VOLUMES+=("$PP_OFF_DATA" "$PP_OFF_KDC")
# shellcheck disable=SC2034
TOKEN="$(gate_login)" || p_bad "[U1.pages-login] the admin could not log in"

pp_gen() { python3 -c 'import secrets; print("Pp" + secrets.token_hex(10) + "!")'; }
pp_vars() { ID="$1" PW="$2" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "pw": os.environ["PW"]}))'; }
pp_dn() { printf 'uid=%s,ou=people,%s' "$1" "$BASE_DN"; }

pp_bind() { pp_bind_at "$(pp_dn "$1")" "$2"; }
pp_bind_at() {
    local f="$PP_D/.bindpw" rc
    (umask 077 && printf '%s' "$2" >"$f")
    t ldapwhoami -x -H "$(ldap_url)" -D "$1" -y "$f" >/dev/null 2>&1
    rc=$?
    rm -f "$f"
    return "$rc"
}
pp_kinit() { kinit_pw "$1@$REALM" "$2" >"$PP_D/kinit.out" 2>&1; }

# pp_sides <user> <new> <old>: PP_GOT, what bind and kinit each take.
pp_sides() {
    local bn=no bo=no kn=no ko=no
    pp_bind "$1" "$2" && bn=yes
    pp_bind "$1" "$3" && bo=yes
    pp_kinit "$1" "$2" && kn=yes
    pp_kinit "$1" "$3" && ko=yes
    PP_GOT="bind-new=$bn bind-old=$bo kinit-new=$kn kinit-old=$ko"
}
pp_binds() {
    local bn=no bo=no
    pp_bind "$1" "$2" && bn=yes
    pp_bind "$1" "$3" && bo=yes
    PP_GOT="bind-new=$bn bind-old=$bo"
}

# pp_seal <password> <label user>: the page's envelope, sealed by the image's OpenSSL.
pp_seal() {
    local hex
    hex="$(printf '%s' "klldap-kerberos-envelope-v1:$2" | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
    printf '%s' "$1" | t docker exec -i -e KEY="$PP_KEY" -e HEX="$hex" "$CONTAINER" sh -c '
        printf %s "$KEY" | base64 -d >/tmp/gate_pp.der &&
            openssl rsa -RSAPublicKey_in -inform DER -in /tmp/gate_pp.der -pubout -out /tmp/gate_pp.pem 2>/dev/null &&
            openssl pkeyutl -encrypt -pubin -inkey /tmp/gate_pp.pem -pkeyopt rsa_padding_mode:oaep \
                -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -pkeyopt "rsa_oaep_label:$HEX" | base64 -w0
        rc=$?; rm -f /tmp/gate_pp.der /tmp/gate_pp.pem; exit $rc' 2>>"$PP_D/seal.err"
}

pp_register() {
    local tok="$1" user="$2" pw="$3"
    shift 3
    gexec /app/lldap_set_password --base-url http://127.0.0.1:17170 --token "$tok" \
        --username "$user" --password "$pw" "$@"
}

pp_gone_post() {
    GQ_URL="$(http_url)/api/graphql" GQ_TOKEN="$1" GQ_QUERY="$PP_GONE_MUT" \
        GQ_VARS='{"u": "'"$2"'", "e": "'"$3"'"}' t python3 - <<'PY'
import json, os, urllib.error, urllib.request
req = urllib.request.Request(
    os.environ["GQ_URL"],
    data=json.dumps({"query": os.environ["GQ_QUERY"],
                     "variables": json.loads(os.environ["GQ_VARS"])}).encode(),
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer " + os.environ["GQ_TOKEN"]})
try:
    body = urllib.request.urlopen(req).read().decode()
except urllib.error.HTTPError as e:
    body = e.read().decode()
try:
    answer = json.loads(body)
    errors = [error.get("message", "") for error in answer.get("errors") or []]
    print(" | ".join(errors) if errors else json.dumps(answer.get("data")))
except (ValueError, TypeError):
    print(body.strip()[:300])
PY
}

pp_made() {
    local out
    out="$(graphql '{ users { id } }' 2>/dev/null)" || {
        echo error
        return
    }
    U="$1" python3 -c '
import json, os, sys
print("yes" if os.environ["U"] in [u["id"] for u in json.load(sys.stdin)["users"]] else "no")' <<<"$out" 2>/dev/null || echo error
}

pp_setup() {
    local pm_gid
    graphql '{ kerberosInfo { publicKeyDerBase64 } }' >"$PP_D/key.json" 2>&1 &&
        PP_KEY="$(json_get kerberosInfo.publicKeyDerBase64 <"$PP_D/key.json")" &&
        gexec sh -c 'command -v openssl' >/dev/null 2>&1 || {
        p_bad "[U1.pages-setup] no transport key or no openssl in the image (see key.json)"
        return 1
    }
    pm_gid="$(graphql '{ groups { id displayName } }' '{}' | GROUP=lldap_password_manager python3 -c '
import json, os, sys
groups = json.load(sys.stdin)["groups"]
match = [g["id"] for g in groups if g["displayName"] == os.environ["GROUP"]]
print(match[0] if match else "")')"
    PP_PM_PASS="$(pp_gen)" PP_SYNC_PASS="$(pp_gen)" PP_PLAIN_PASS="$(pp_gen)"
    graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$PP_PM"'", "email": "'"$PP_PM"'@gate.test"}}' >"$PP_D/create.json" 2>&1 &&
        graphql 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
            '{"u": "'"$PP_PM"'", "g": '"${pm_gid:-0}"'}' >>"$PP_D/create.json" 2>&1 &&
        graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$PP_SYNC"'", "email": "'"$PP_SYNC"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
            >>"$PP_D/create.json" 2>&1 &&
        graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$PP_PLAIN"'", "email": "'"$PP_PLAIN"'@gate.test"}}' >>"$PP_D/create.json" 2>&1 &&
        graphql "$PP_SET" "$(pp_vars "$PP_PM" "$PP_PM_PASS")" >>"$PP_D/create.json" 2>&1 &&
        graphql "$PP_SET" "$(pp_vars "$PP_SYNC" "$PP_SYNC_PASS")" >>"$PP_D/create.json" 2>&1 &&
        graphql "$PP_SET" "$(pp_vars "$PP_PLAIN" "$PP_PLAIN_PASS")" >>"$PP_D/create.json" 2>&1 &&
        pp_bind "$PP_SYNC" "$PP_SYNC_PASS" && pp_kinit "$PP_SYNC" "$PP_SYNC_PASS" || {
        p_bad "[U1.pages-setup] the users could not be made, or the synced one's first password is not on both sides (see create.json, kinit.out; lldap_password_manager id '${pm_gid}')"
        return 1
    }
}

pp_gone() {
    local tok new answer row="U1.g8-sync-gone"
    new="$(pp_gen)"
    tok="$(gate_login "$PP_PLAIN" "$PP_PLAIN_PASS")" || {
        p_bad "[$row] $PP_PLAIN could not log in"
        return
    }
    pp_register "$tok" "$PP_PLAIN" "$new" >"$PP_D/nosync-register.log" 2>&1
    pp_binds "$PP_PLAIN" "$new" "$PP_PLAIN_PASS"
    if [ "$PP_GOT" = "bind-new=yes bind-old=no" ]; then
        PP_PLAIN_PASS="$new"
        p_ok "[$row-bind] the tool changes a user without sync: the new password binds and the old does not"
    else
        p_bad "[$row-bind] the tool for a user without sync: $PP_GOT (see nosync-register.log)"
    fi
    answer="$(pp_gone_post "$tok" "$PP_PLAIN" "c2VhbGVk")"
    if grep -q 'Unknown field "syncKerberosPassword" on type "Mutation"' <<<"$answer"; then
        p_ok "[$row] syncKerberosPassword is gone: $answer"
    else
        p_bad "[$row] syncKerberosPassword answered: $answer"
    fi
}

pp_floor() {
    local short="Short7x" rc row="U1.synced-floor" mark
    mark="$(log_mark)"
    pp_register "$TOKEN" "$PP_SYNC" "$short" --bypass-password-policy >"$PP_D/floor-register.log" 2>&1
    rc=$?
    pp_sides "$PP_SYNC" "$short" "$PP_SYNC_PASS"
    if [ "$rc" != 0 ] && grep -q '400 Bad Request' "$PP_D/floor-register.log" &&
        grep -q 'the password must be at least 8 characters' "$PP_D/floor-register.log" &&
        [ "$PP_GOT" = "$PP_BOTH_OLD" ]; then
        p_ok "[$row] a 7-character password at a synced user's finish: 400 'the password must be at least 8 characters', and bind and kinit keep the old one"
    else
        p_bad "[$row] tool exit $rc ($(tail -1 "$PP_D/floor-register.log" 2>/dev/null)); $PP_GOT, want $PP_BOTH_OLD"
    fi
    fail_row "$row-row" PASSWORD_CHANGE "$PP_SYNC" "the password must be at least 8 characters" "$mark" HTTP
}

pp_manager() {
    local tok new row="U1.pm-synced-user"
    new="$(pp_gen)"
    tok="$(gate_login "$PP_PM" "$PP_PM_PASS")" || {
        p_bad "[$row] the password manager could not log in"
        return
    }
    pp_register "$tok" "$PP_SYNC" "$new" >"$PP_D/pm-register.log" 2>&1
    pp_sides "$PP_SYNC" "$new" "$PP_SYNC_PASS"
    if [ "$PP_GOT" = "$PP_BOTH_NEW" ]; then
        PP_SYNC_PASS="$new"
        p_ok "[$row] a password manager's change of a synced user through the tool's envelope: bind and kinit both take the new password"
    else
        pp_bind "$PP_SYNC" "$new" && PP_SYNC_PASS="$new"
        p_bad "[$row] $PP_GOT, want $PP_BOTH_NEW (see pm-register.log)"
    fi
}

# pp_wire <tag> <change|create> <user> <typed> [<add|swap> <envelope>] [<mail>]: PP_WIRE, PP_ALERT.
pp_wire() {
    local tag="$1" kind="$2" user="$3" typed="$4" mode="${5:-}" envelope="${6:-}" mail="${7:-}"
    docker rm -f "$PP_BROWSER_CTN" >/dev/null 2>&1 || true
    (
        export BROWSER_ADMIN_PASS="$ADMIN_PASS" BROWSER_PASS="$typed" BROWSER_FINISH_ENVELOPE="$envelope"
        timeout 180 docker run --rm --name "$PP_BROWSER_CTN" --network "$NET" --init --shm-size=1g \
            --user "$(id -u):$(id -g)" --entrypoint node \
            -v "$GATE_ROOT/lib/password-wire.mjs:/work/password-wire.mjs:ro" -v "$PP_D:/out" \
            -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_URL="http://${CONTAINER}:17170" \
            -e BROWSER_PAGE="$kind" -e BROWSER_USER="$user" -e BROWSER_TAG="$tag" -e BROWSER_MAIL="$mail" \
            -e BROWSER_FINISH_MODE="$mode" -e BROWSER_ADMIN_PASS -e BROWSER_PASS -e BROWSER_FINISH_ENVELOPE \
            "$PP_BROWSER_IMAGE" /work/password-wire.mjs >"$PP_D/wire-$tag.out" 2>"$PP_D/wire-$tag.err"
    )
    PP_WIRE="$(grep -m1 '^WIRE \|^ROW wire FAIL' "$PP_D/wire-$tag.out" 2>/dev/null || echo "no line (see wire-$tag.err)")"
    PP_ALERT="$(grep -m1 '^ALERT ' "$PP_D/wire-$tag.out" 2>/dev/null | sed 's/^ALERT //')"
}

pp_wire_rows() {
    local row="U1.g8-nosync-envelope" ctl="U1.page-synced-finish" plain_new sync_new
    local want_sync="WIRE start-key=yes finish-envelope=yes rewrite=none finish-status=200 graphql-seal=no create-sent=no page=done"
    local want_plain="WIRE start-key=no finish-envelope=no rewrite=none finish-status=200 graphql-seal=no create-sent=no page=done"
    plain_new="$(pp_gen)" sync_new="$(pp_gen)"
    pp_wire sync change "$PP_SYNC" "$sync_new"
    pp_sides "$PP_SYNC" "$sync_new" "$PP_SYNC_PASS"
    if [ "$PP_WIRE" = "$want_sync" ] && [ "$PP_GOT" = "$PP_BOTH_NEW" ]; then
        PP_SYNC_PASS="$sync_new"
        p_ok "[$ctl] the change page for a synced user: register/start gives the key, finish carries the envelope, and bind and kinit both take the new password"
    else
        pp_bind "$PP_SYNC" "$sync_new" && PP_SYNC_PASS="$sync_new"
        p_bad "[$ctl] $PP_WIRE ${PP_ALERT:+(alert: $PP_ALERT) }; $PP_GOT; want $want_sync and $PP_BOTH_NEW"
        p_bad "[$row] the synced control did not show its seal, so the capture is not trusted"
        return
    fi
    pp_wire plain change "$PP_PLAIN" "$plain_new"
    pp_binds "$PP_PLAIN" "$plain_new" "$PP_PLAIN_PASS"
    if [ "$PP_WIRE" = "$want_plain" ] && [ "$PP_GOT" = "bind-new=yes bind-old=no" ]; then
        PP_PLAIN_PASS="$plain_new"
        p_ok "[$row] the change page for a user without sync: register/start gives no key, nothing is sealed, and the new password binds"
    else
        pp_bind "$PP_PLAIN" "$plain_new" && PP_PLAIN_PASS="$plain_new"
        p_bad "[$row] $PP_WIRE ${PP_ALERT:+(alert: $PP_ALERT) }; $PP_GOT; want $want_plain and bind-new=yes bind-old=no"
    fi
}

pp_inject_nosync() {
    local row="U1.envelope-nosync-refused" new sealed mark
    local want="WIRE start-key=no finish-envelope=no rewrite=added finish-status=400 graphql-seal=no create-sent=no page=stayed"
    new="$(pp_gen)"
    sealed="$(pp_seal "$new" "$PP_PLAIN")"
    [ -n "$sealed" ] || {
        p_bad "[$row] OpenSSL did not seal (see seal.err)"
        return
    }
    mark="$(log_mark)"
    pp_wire plain-add change "$PP_PLAIN" "$new" add "$sealed"
    pp_binds "$PP_PLAIN" "$new" "$PP_PLAIN_PASS"
    if [ "$PP_WIRE" = "$want" ] && [ "$PP_GOT" = "bind-new=no bind-old=yes" ] &&
        grep -q 'a Kerberos password envelope is taken only for a user with Kerberos sync' <<<"$PP_ALERT"; then
        p_ok "[$row] an envelope in a finish for a user without sync: 400 '$PP_ALERT', and the old password still binds"
    else
        p_bad "[$row] $PP_WIRE (alert: ${PP_ALERT:-none}); $PP_GOT; want $want, the sync sentence, bind-new=no bind-old=yes"
    fi
    fail_row "$row-row" PASSWORD_CHANGE "$PP_PLAIN" \
        "a Kerberos password envelope is taken only for a user with Kerberos sync" "$mark" HTTP
}

# The server commits the envelope's password, sealed by OpenSSL with the user's label, not the typed one.
pp_swap_label() {
    local row="U1.envelope-label" typed sealed p2 t_bind=no t_kinit=no
    local want="WIRE start-key=yes finish-envelope=yes rewrite=swapped finish-status=200 graphql-seal=no create-sent=no page=done"
    typed="$(pp_gen)" p2="$(pp_gen)"
    sealed="$(pp_seal "$p2" "$PP_SYNC")"
    [ -n "$sealed" ] || {
        p_bad "[$row] OpenSSL did not seal (see seal.err)"
        return
    }
    pp_wire sync-label change "$PP_SYNC" "$typed" swap "$sealed"
    pp_sides "$PP_SYNC" "$p2" "$PP_SYNC_PASS"
    pp_bind "$PP_SYNC" "$typed" && t_bind=yes
    pp_kinit "$PP_SYNC" "$typed" && t_kinit=yes
    if [ "$PP_WIRE" = "$want" ] && [ "$PP_GOT" = "$PP_BOTH_NEW" ] && [ "$t_bind $t_kinit" = "no no" ]; then
        PP_SYNC_PASS="$p2"
        p_ok "[$row] an envelope sealed with 'klldap-kerberos-envelope-v1:$PP_SYNC' opens: bind and kinit take its password, not the typed one"
    else
        pp_bind "$PP_SYNC" "$p2" && PP_SYNC_PASS="$p2"
        p_bad "[$row] $PP_WIRE ${PP_ALERT:+(alert: $PP_ALERT) }; envelope's password $PP_GOT; typed bind=$t_bind kinit=$t_kinit; want $want, $PP_BOTH_NEW, typed no no"
    fi
}

pp_swap_other() {
    local row="U1.envelope-other-label" typed sealed mark
    local want="WIRE start-key=yes finish-envelope=yes rewrite=swapped finish-status=400 graphql-seal=no create-sent=no page=stayed"
    typed="$(pp_gen)"
    sealed="$(pp_seal "$typed" "$PP_PLAIN")"
    [ -n "$sealed" ] || {
        p_bad "[$row] OpenSSL did not seal (see seal.err)"
        return
    }
    mark="$(log_mark)"
    pp_wire sync-other change "$PP_SYNC" "$typed" swap "$sealed"
    pp_sides "$PP_SYNC" "$typed" "$PP_SYNC_PASS"
    if [ "$PP_WIRE" = "$want" ] && [ "$PP_GOT" = "$PP_BOTH_OLD" ] &&
        grep -q 'the Kerberos password envelope did not open' <<<"$PP_ALERT"; then
        p_ok "[$row] $PP_SYNC's finish with an envelope sealed for $PP_PLAIN: 400 '$PP_ALERT', and bind and kinit keep the old password"
    else
        p_bad "[$row] $PP_WIRE (alert: ${PP_ALERT:-none}); $PP_GOT; want $want, 'did not open', $PP_BOTH_OLD"
    fi
    fail_row "$row-row" PASSWORD_CHANGE "$PP_SYNC" \
        "the Kerberos password envelope did not open: Decryption failed" "$mark" HTTP
}

pp_create_big() {
    local row="U1.create-page-318" big made
    local want="WIRE start-key=none finish-envelope=none rewrite=none finish-status=none graphql-seal=no create-sent=no page=stayed"
    big="$(python3 -c 'print("Pp-" + "x" * 316)')"
    pp_wire create-318 create "$PP_BIG" "$big" "" "" "$PP_BIG@gate.test"
    made="$(pp_made "$PP_BIG")"
    if [ "$PP_WIRE" = "$want" ] && [ "$made" = no ] &&
        grep -q 'A password with Kerberos sync can be at most 318 bytes long' <<<"$PP_ALERT"; then
        p_ok "[$row] the create page with Kerberos sync and a ${#big}-byte password: '$PP_ALERT' before createUser; no user was made"
    else
        p_bad "[$row] $PP_WIRE (alert: ${PP_ALERT:-none}); user made=$made; want $want, the 318-byte sentence, no user"
    fi
}

pp_create_synced() {
    local row="U1.create-page-synced" pw b=no k=no
    local want="WIRE start-key=yes finish-envelope=yes rewrite=none finish-status=200 graphql-seal=no create-sent=yes page=done"
    pw="$(pp_gen)"
    pp_wire create-new create "$PP_NEW" "$pw" "" "" "$PP_NEW@gate.test"
    pp_bind "$PP_NEW" "$pw" && b=yes
    pp_kinit "$PP_NEW" "$pw" && k=yes
    if [ "$PP_WIRE" = "$want" ] && [ "$b $k" = "yes yes" ]; then
        p_ok "[$row] the create page with Kerberos sync: createUser, then the sealed finish; bind and kinit take the password"
    else
        p_bad "[$row] $PP_WIRE ${PP_ALERT:+(alert: $PP_ALERT) }; bind=$b kinit=$k; want $want, yes yes"
    fi
}

# A user without sync in an OU at password-min-length 12: the change page refuses 11 characters
# with the start's number, before the finish.
pp_min_page() {
    local row="U1.page-min-nosync" ou="${PP_RUN}ou" user="${PP_RUN}u" old new pol="" made="" dn="" got=""
    local ready="" bn=no bo=no
    local want="WIRE start-key=no finish-envelope=none rewrite=none finish-status=none graphql-seal=no create-sent=no page=stayed"
    old="$(pp_gen)" new="$(python3 -c 'import secrets; print("Pp" + secrets.token_hex(4) + "!")')"
    if graphql "mutation(\$n: String!) { createOu(name: \$n) { ok } }" '{"n": "'"$ou"'"}' >"$PP_D/min-ou.json" 2>&1; then
        made=yes
    fi
    [ -n "$made" ] &&
        graphql "mutation(\$u: CreateUserInput!) { createUser(user: \$u) { id } }" \
            '{"u": {"id": "'"$user"'", "email": "'"$user"'@gate.test"}}' >"$PP_D/min-user.json" 2>&1 &&
        graphql "$PP_SET" "$(pp_vars "$user" "$old")" >>"$PP_D/min-user.json" 2>&1 &&
        graphql "mutation(\$ids: [String!]!, \$ou: String!) { changeUserOu(userIds: \$ids, newOu: \$ou) { ok } }" \
            '{"ids": ["'"$user"'"], "ou": "'"$ou"'"}' >>"$PP_D/min-user.json" 2>&1 &&
        pol="$(graphql "mutation(\$n: String!, \$i: [PolicyItemInput!]) { createPolicy(name: \$n, items: \$i) { id } }" \
            '{"n": "'"$ou"' min 12", "i": [{"key": "password-min-length", "value": "12"}]}' 2>"$PP_D/min-policy.err" |
            json_get createPolicy.id 2>>"$PP_D/min-policy.err")" && [ -n "$pol" ] &&
        graphql "mutation(\$o: String!, \$p: Int!) { setOuPolicy(ou: \$o, policyId: \$p) { ok } }" \
            '{"o": "'"$ou"'", "p": '"$pol"'}' >"$PP_D/min-link.json" 2>&1 &&
        got="$(graphql "query(\$o: String!) { effectivePolicyItems(ou: \$o) { key value } }" '{"o": "'"$ou"'"}' 2>/dev/null |
            python3 -c '
import json, sys
print({i["key"]: i["value"] for i in json.load(sys.stdin)["effectivePolicyItems"]}.get("password-min-length"))' 2>/dev/null)" &&
        [ "$got" = 12 ] &&
        dn="$(lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$user)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1)" &&
        [ -n "$dn" ] && pp_bind_at "$dn" "$old" && ready=yes
    if [ -z "$ready" ] || [ "${#new}" -ne 11 ]; then
        p_bad "[$row] $user in $ou at password-min-length 12 could not be set up, or its first password does not bind (see min-*.json, min-policy.err; minimum '${got:-unread}', DN '$dn')"
    else
        pp_wire min-nosync change "$user" "$new"
        pp_bind_at "$dn" "$new" && bn=yes
        pp_bind_at "$dn" "$old" && bo=yes
        if [ "$PP_WIRE" = "$want" ] && [ "$bn $bo" = "no yes" ] &&
            grep -qF "Invalid password. Min length: 12" <<<"$PP_ALERT"; then
            p_ok "[$row] the change page for a user without sync in an OU at 12: an 11-character password is refused with '$PP_ALERT' before the finish, and the old password still binds"
        else
            p_bad "[$row] $PP_WIRE (alert: ${PP_ALERT:-none}); bind-new=$bn bind-old=$bo; want $want, 'Invalid password. Min length: 12', bind-new=no bind-old=yes"
        fi
    fi
    graphql "mutation(\$u: String!) { deleteUser(userId: \$u) { ok } }" '{"u": "'"$user"'"}' >/dev/null 2>&1
    if [ -n "$pol" ]; then
        graphql "mutation(\$o: String!) { clearOuPolicy(ou: \$o) { ok } }" '{"o": "'"$ou"'"}' >/dev/null 2>&1 ||
            p_bad "[$row-cleanup] clearOuPolicy $ou failed"
        graphql "mutation(\$p: Int!) { deletePolicy(policyId: \$p) { ok } }" '{"p": '"$pol"'}' >/dev/null 2>&1 ||
            p_bad "[$row-cleanup] deletePolicy $pol failed"
    fi
    if [ -n "$made" ]; then
        graphql "mutation(\$n: String!) { deleteOu(name: \$n) { ok } }" '{"n": "'"$ou"'"}' >/dev/null 2>&1 ||
            p_bad "[$row-cleanup] deleteOu $ou failed"
    fi
}

pp_no_progress() {
    local hits
    hits="$(grep -il 'in progress' "$PP_D"/*-register.log "$PP_D"/wire-*.out 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')"
    if [ -z "$hits" ]; then
        p_ok "[U1.no-in-progress] no page and no tool answer of this phase says a change is in progress"
    else
        p_bad "[U1.no-in-progress] 'in progress' in: $hits"
    fi
}

pp_off_up() {
    PP_OFF_PORT="" PP_OFF_TOK=""
    docker rm -fv "$PP_OFF_CTN" >/dev/null 2>&1
    docker run -d --name "$PP_OFF_CTN" --network "$NET" -p "127.0.0.1::17170" \
        -v "$PP_OFF_DATA:/data" -v "$PP_OFF_KDC:/var/kerberos/krb5kdc" \
        -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_KEY_SEED="$KEY_SEED" \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        "$@" "$GATE_IMAGE" >/dev/null 2>>"$PP_D/krb-off.err" || return 1
    for _ in $(seq 1 120); do
        docker exec "$PP_OFF_CTN" /app/lldap healthcheck --config-file /data/lldap_config.toml >/dev/null 2>&1 && break
        [ -z "$(docker ps -q -f "name=^$PP_OFF_CTN$")" ] && break
        sleep 1
    done
    PP_OFF_PORT="$(docker port "$PP_OFF_CTN" 17170/tcp 2>/dev/null | head -1 | sed 's/.*://')"
    [ -n "$PP_OFF_PORT" ] && PP_OFF_TOK="$(HTTP_PORT="$PP_OFF_PORT" gate_login 2>>"$PP_D/krb-off.err")"
}

# The blinded element is ristretto255's base point, a valid one; a start registers nothing.
pp_off_start() {
    START_URL="http://127.0.0.1:$PP_OFF_PORT/auth/opaque/register/start" START_TOKEN="$PP_OFF_TOK" START_USER="$1" \
        t python3 - <<'PY'
import json, os, urllib.error, urllib.request
point = list(bytes.fromhex("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"))
body = {"username": os.environ["START_USER"], "registration_start_request": {"blinded_element": point}}
req = urllib.request.Request(os.environ["START_URL"], data=json.dumps(body).encode(),
                             headers={"Content-Type": "application/json",
                                      "Authorization": "Bearer " + os.environ["START_TOKEN"]})
try:
    resp = urllib.request.urlopen(req)
    code, text = resp.status, resp.read().decode(errors="replace")
except urllib.error.HTTPError as e:
    code, text = e.code, e.read().decode(errors="replace")
try:
    answer = json.loads(text)
except ValueError:
    answer = None
if isinstance(answer, dict) and "kerberos_envelope_key" in answer:
    shape = "key"
elif isinstance(answer, dict) and {"server_data", "registration_response"} <= set(answer):
    shape = "start"
else:
    shape = "text"
print(code, shape, " ".join(text.split())[:300])
PY
}

pp_off_gql() { HTTP_PORT="$PP_OFF_PORT" TOKEN="$PP_OFF_TOK" graphql "$@"; }
pp_off_mark() { HTTP_PORT="$PP_OFF_PORT" TOKEN="$PP_OFF_TOK" log_mark; }
pp_off_once() { HTTP_PORT="$PP_OFF_PORT" TOKEN="$PP_OFF_TOK" log_once "$@"; }
pp_off_made() { HTTP_PORT="$PP_OFF_PORT" TOKEN="$PP_OFF_TOK" pp_made "$1"; }
pp_off_login() { HTTP_PORT="$PP_OFF_PORT" gate_login "$1" "$2" >/dev/null 2>&1; }
pp_off_make() {
    local attrs=""
    [ "${2:-}" = sync ] && attrs=', "attributes": [{"name": "kerberossync", "value": ["1"]}]'
    pp_off_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$1"'", "email": "'"$1"'@gate.test"'"$attrs"'}}'
}
pp_off_sync() {
    local out
    out="$(pp_off_gql 'query($u: String!) { user(userId: $u) { attributes { name value } } }' '{"u": "'"$1"'"}' 2>&1)" || {
        echo nouser
        return
    }
    python3 -c '
import json, sys
attrs = json.load(sys.stdin)["user"]["attributes"]
vals = [",".join(a["value"]) for a in attrs if a["name"] == "kerberossync"]
print(vals[0] if vals else "absent")' <<<"$out" 2>/dev/null || echo error
}

pp_off_create_page() {
    local row="U1.krb-off-create-page" user="${PP_RUN}w" pw sent attr login=no shown ctl
    local want="WIRE start-key=no finish-envelope=no rewrite=none finish-status=200 graphql-seal=no create-sent=yes page=done"
    if ! docker image inspect "$PP_BROWSER_IMAGE" >/dev/null 2>&1; then
        p_skip "[$row] browser image absent: ${PP_BROWSER_IMAGE}; the create page did not run"
        return
    fi
    pw="$(pp_gen)"
    CONTAINER="$PP_OFF_CTN" pp_wire off-create create "$user" "$pw" "" "" "$user@gate.test"
    sent="$(grep -m1 '^CREATE ' "$PP_D/wire-off-create.out" 2>/dev/null)"
    attr="$(pp_off_sync "$user")"
    pp_off_login "$user" "$pw" && login=yes
    if [ "$PP_WIRE" = "$want" ] && [ "$sent" = "CREATE kerberossync=no" ] && [ "$attr $login" = "absent yes" ]; then
        p_ok "[$row] Kerberos disabled: the create page's createUser carries no kerberossync, the user has none, and its password logs in"
    else
        p_bad "[$row] $PP_WIRE ${PP_ALERT:+(alert: $PP_ALERT) }; ${sent:-no CREATE line}; kerberossync=$attr login=$login; want $want, CREATE kerberossync=no, absent, yes"
    fi
    row="U1.krb-off-create-switch"
    shown="$(grep -m1 '^SWITCH ' "$PP_D/wire-off-create.out" 2>/dev/null)"
    ctl="$(grep -m1 '^SWITCH ' "$PP_D/wire-create-new.out" 2>/dev/null)"
    if [ "$ctl" != "SWITCH kerberos=shown" ]; then
        p_bad "[$row] control: the create page of the gate's server, Kerberos on, did not show the switch (${ctl:-no SWITCH line in wire-create-new.out}), so its absence is not trusted"
    elif [ "$shown" = "SWITCH kerberos=absent" ]; then
        p_ok "[$row] Kerberos disabled: the create page has no Kerberos switch (no label for kerberossync_toggle); control: the create page of the gate's server, Kerberos on, has it"
    else
        p_bad "[$row] ${shown:-no SWITCH line (see wire-off-create.err)}; want SWITCH kerberos=absent"
    fi
}

# The users are made with Kerberos on; the same volumes then start with Kerberos disabled.
pp_krb_off() {
    local sync="${PP_RUN}o" plain="${PP_RUN}q" off="${PP_RUN}f" gone="${PP_RUN}d" made="${PP_RUN}c"
    local got mark pw new row="U1.krb-off-start-synced" ctl="U1.krb-off-start-plain"
    pw="$(pp_gen)" new="$(pp_gen)"
    if ! pp_off_up || ! pp_off_make "$sync" sync >"$PP_D/krb-off-users.json" 2>&1 ||
        ! pp_off_make "$plain" >>"$PP_D/krb-off-users.json" 2>&1 ||
        ! pp_off_make "$off" sync >>"$PP_D/krb-off-users.json" 2>&1 ||
        ! pp_off_make "$gone" sync >>"$PP_D/krb-off-users.json" 2>&1 ||
        ! pp_off_gql "$PP_SET" "$(pp_vars "$sync" "$pw")" >>"$PP_D/krb-off-users.json" 2>&1; then
        docker logs "$PP_OFF_CTN" >"$PP_D/krb-off-on-docker.log" 2>&1
        p_bad "[U1.krb-off-setup] the second server with Kerberos on did not start, or did not make its users (see krb-off.err, krb-off-users.json, krb-off-on-docker.log)"
        return
    fi
    docker logs "$PP_OFF_CTN" >"$PP_D/krb-off-on-docker.log" 2>&1
    if ! pp_off_up -e LLDAP_KERBEROS_OPTIONS__ENABLED=false ||
        [ "$(pp_off_gql '{ kerberosInfo { enabled } }' 2>/dev/null | json_get kerberosInfo.enabled 2>/dev/null)" != False ]; then
        docker logs "$PP_OFF_CTN" >"$PP_D/krb-off-docker.log" 2>&1
        p_bad "[U1.krb-off-setup] the same volumes did not start with Kerberos disabled, or kerberosInfo.enabled is not false (see krb-off.err, krb-off-docker.log)"
        return
    fi
    mark="$(pp_off_mark)"
    got="$(pp_off_start "$sync" 2>&1)"
    case "$got" in
    "400 text "*"$PP_OFF_SAID"*)
        if pp_off_once false PASSWORD_CHANGE "$sync" "$PP_OFF_SAID" "$mark" HTTP; then
            p_ok "[$row] Kerberos disabled: register/start for the synced $sync answers 400 '$PP_OFF_SAID', no key, and one password_change failure row (protocol HTTP)"
        else
            p_bad "[$row] the 400 and the sentence came, but: $FAIL_WHY"
        fi
        ;;
    *) p_bad "[$row] register/start for the synced $sync answered '$got'; want 400, no key, '$PP_OFF_SAID'" ;;
    esac
    got="$(pp_off_start "$plain" 2>&1)"
    case "$got" in
    "200 start "*) p_ok "[$ctl] Kerberos disabled: register/start for $plain, without sync, answers 200 (server_data, registration_response) and no kerberos_envelope_key: the answer carries no key, only the minimum" ;;
    *) p_bad "[$ctl] register/start for $plain answered '$got'; want 200, server_data and registration_response, and no key" ;;
    esac

    row="U1.krb-off-create-sync" FAIL_WHY=""
    mark="$(pp_off_mark)"
    if pp_off_make "$made" sync >"$PP_D/krb-off-create.json" 2>"$PP_D/krb-off-create.err"; then
        p_bad "[$row] createUser with kerberossync=1 answered ok with Kerberos disabled"
    elif grep -qF "$PP_OFF_CREATE" "$PP_D/krb-off-create.err" && [ "$(pp_off_made "$made")" = no ] &&
        pp_off_once false USER_CREATE "$made" "$PP_OFF_CREATE" "$mark" GRAPHQL; then
        p_ok "[$row] Kerberos disabled: createUser with kerberossync=1 is refused with '$PP_OFF_CREATE', no user is made, one user_create failure row"
    else
        p_bad "[$row] $(head -c 300 "$PP_D/krb-off-create.err"); made=$(pp_off_made "$made"); ${FAIL_WHY:-want '$PP_OFF_CREATE' and no user}"
    fi

    pp_off_create_page

    row="U1.krb-off-sync-off" FAIL_WHY=""
    got="$(pp_off_sync "$off")"
    mark="$(pp_off_mark)"
    if [ "$got" = 1 ] &&
        pp_off_gql "$PP_UPD" '{"u": {"id": "'"$off"'", "removeAttributes": ["kerberossync"]}}' >"$PP_D/krb-off-syncoff.json" 2>&1 &&
        [ "$(pp_off_sync "$off")" = absent ] && pp_off_once true KERBEROS_SYNC "$off" "$PP_OFF_LEFT" "$mark" GRAPHQL; then
        p_ok "[$row] Kerberos disabled: sync off for the synced $off is allowed, directory-only: kerberossync goes from 1 to absent, and one kerberos_sync row says '$PP_OFF_LEFT'"
    else
        p_bad "[$row] kerberossync before=$got after=$(pp_off_sync "$off"); $(head -c 300 "$PP_D/krb-off-syncoff.json" 2>/dev/null); ${FAIL_WHY:-want 1, ok, then absent}"
    fi

    row="U1.krb-off-delete" FAIL_WHY=""
    mark="$(pp_off_mark)"
    if pp_off_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$gone"'"}' >"$PP_D/krb-off-delete.json" 2>&1 &&
        [ "$(pp_off_made "$gone")" = no ] && pp_off_once true KERBEROS_SYNC "$gone" "$PP_OFF_LEFT" "$mark" GRAPHQL; then
        p_ok "[$row] Kerberos disabled: deleting the synced $gone is allowed, directory-only, and one kerberos_sync row says '$PP_OFF_LEFT'"
    else
        p_bad "[$row] $(head -c 300 "$PP_D/krb-off-delete.json"); still there=$(pp_off_made "$gone"); ${FAIL_WHY:-want ok and no user}"
    fi

    row="U1.krb-off-sync-on" FAIL_WHY=""
    mark="$(pp_off_mark)"
    if pp_off_gql "$PP_UPD" '{"u": {"id": "'"$plain"'", "insertAttributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
        >"$PP_D/krb-off-syncon.json" 2>"$PP_D/krb-off-syncon.err"; then
        p_bad "[$row] turning kerberossync on answered ok with Kerberos disabled"
    elif grep -qF "$PP_OFF_SYNC_ON" "$PP_D/krb-off-syncon.err" && [ "$(pp_off_sync "$plain")" = absent ] &&
        pp_off_once false USER_UPDATE "$plain" "$PP_OFF_SYNC_ON" "$mark" GRAPHQL; then
        p_ok "[$row] Kerberos disabled: sync on for $plain is refused with '$PP_OFF_SYNC_ON', kerberossync stays absent, one user_update failure row"
    else
        p_bad "[$row] $(head -c 300 "$PP_D/krb-off-syncon.err"); kerberossync=$(pp_off_sync "$plain"); ${FAIL_WHY:-want the sentence and no kerberossync}"
    fi

    row="U1.krb-off-setpw-synced" FAIL_WHY=""
    mark="$(pp_off_mark)"
    if pp_off_gql "$PP_SET" "$(pp_vars "$sync" "$new")" >"$PP_D/krb-off-setpw.json" 2>"$PP_D/krb-off-setpw.err"; then
        p_bad "[$row] setUserPassword for the synced $sync answered ok with Kerberos disabled"
    elif grep -qF "$PP_OFF_SAID" "$PP_D/krb-off-setpw.err" && pp_off_login "$sync" "$pw" && ! pp_off_login "$sync" "$new" &&
        pp_off_once false PASSWORD_CHANGE "$sync" "$PP_OFF_SAID" "$mark" GRAPHQL; then
        p_ok "[$row] Kerberos disabled: setUserPassword for the synced $sync is a GraphQL error '$PP_OFF_SAID'; the old password still logs in, one password_change failure row"
    else
        p_bad "[$row] $(head -c 300 "$PP_D/krb-off-setpw.err"); ${FAIL_WHY:-want the sentence, the old password kept}"
    fi

    row="U1.krb-off-ldappasswd-synced" FAIL_WHY=""
    mark="$(pp_off_mark)"
    gexec_in "$PP_OFF_CTN" ldappasswd -x -H ldap://127.0.0.1:3890 -D "$(admin_dn)" -w "$ADMIN_PASS" -s "$new" "$(pp_dn "$sync")" \
        >"$PP_D/krb-off-ldappasswd.log" 2>&1
    if grep -qF "Server is unwilling to perform (53)" "$PP_D/krb-off-ldappasswd.log" && grep -qF "$PP_OFF_SAID" "$PP_D/krb-off-ldappasswd.log" &&
        pp_off_login "$sync" "$pw" && ! pp_off_login "$sync" "$new" &&
        pp_off_once false PASSWORD_CHANGE "$sync" "$PP_OFF_SAID" "$mark" LDAP; then
        p_ok "[$row] Kerberos disabled: ldappasswd for the synced $sync answers 53 '$PP_OFF_SAID'; the old password still logs in, one password_change failure row"
    else
        p_bad "[$row] $(tr '\n' ' ' <"$PP_D/krb-off-ldappasswd.log" | head -c 300); ${FAIL_WHY:-want 53, the sentence, the old password kept}"
    fi

    row="U1.krb-off-disable" FAIL_WHY=""
    local gid
    mark="$(pp_off_mark)"
    gid="$(pp_off_gql '{ groups { id displayName } }' '{}' 2>/dev/null | python3 -c '
import json, sys
print(next(g["id"] for g in json.load(sys.stdin)["groups"] if g["displayName"] == "lldap_disabled"))' 2>/dev/null)"
    if [ -n "$gid" ] &&
        pp_off_gql 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
            '{"u": "'"$sync"'", "g": '"$gid"'}' >"$PP_D/krb-off-disable.json" 2>&1 &&
        pp_off_once true KERBEROS_SYNC "$sync" "$PP_OFF_STATUS" "$mark" GRAPHQL; then
        p_ok "[$row] Kerberos disabled: adding the synced $sync to lldap_disabled is allowed, and one kerberos_sync row says '$PP_OFF_STATUS'"
    else
        p_bad "[$row] lldap_disabled=${gid:-not found}; $(head -c 300 "$PP_D/krb-off-disable.json" 2>/dev/null); ${FAIL_WHY:-want ok and one kerberos_sync row}"
    fi
    docker logs "$PP_OFF_CTN" >"$PP_D/krb-off-docker.log" 2>&1
}

# The user page's sign-in state (E7, E7-b), on a phase OU with lockout-threshold 3 for ever and
# inactivity-days 1: a locked user, an inactive one (its times set back with the gate's server
# stopped, as phase 38 does, so this runs last), and a fresh one. Each button shows only with its state.
PP_ACT_OU="${PP_RUN}a" PP_LOCK="${PP_RUN}l" PP_IDLE="${PP_RUN}i" PP_FRESH="${PP_RUN}f"
PP_ACT_POLICY="" PP_ACT_PASS="" PP_ACT_SINCE="" PP_ACT_AGED=0
PP_ACT_CTN="klldap-pp-act-${RUNID}"
EXTRA_CONTAINERS+=("$PP_ACT_CTN")

# pp_act_page <mode> <tag> [user]: the page driver; its ROW lines in actions-<tag>.out.
pp_act_page() {
    docker rm -f "$PP_ACT_CTN" >/dev/null 2>&1 || true
    (
        BROWSER_ADMIN_PASS="$ADMIN_PASS" BROWSER_PASS="$PP_ACT_PASS" \
            timeout 240 docker run --rm --name "$PP_ACT_CTN" --network "$NET" --init --shm-size=1g \
            --user "$(id -u):$(id -g)" --entrypoint node \
            -v "$GATE_ROOT/lib/sign-in-actions.mjs:/work/sign-in-actions.mjs:ro" -v "$PP_D:/out" \
            -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_URL="http://${CONTAINER}:17170" \
            -e BROWSER_MODE="$1" -e BROWSER_USER="${3:-}" -e BROWSER_LOCKED="$PP_LOCK" -e BROWSER_FRESH="$PP_FRESH" \
            -e BROWSER_IDLE="$([ "$PP_ACT_AGED" = 1 ] && echo "$PP_IDLE")" -e BROWSER_INACTIVE="$PP_ACT_SINCE" \
            -e BROWSER_ADMIN_PASS -e BROWSER_PASS \
            "$PP_BROWSER_IMAGE" /work/sign-in-actions.mjs >"$PP_D/actions-$2.out" 2>"$PP_D/actions-$2.err"
    )
    docker rm -f "$PP_ACT_CTN" >/dev/null 2>&1 || true
}
pp_act_row() { grep -m1 "^ROW $2 " "$PP_D/actions-$1.out" 2>/dev/null || echo "ROW $2 none (see actions-$1.err)"; }
# A user in an OU has its DN from the directory, as 37 and 72 read it.
pp_act_dn() { lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$1)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1; }
pp_act_bind() { pp_bind_at "$(pp_act_dn "$1")" "$2" && echo 0 || echo refused; }

# pp_act_none <kind> <user> <mark>: how many such rows after the mark, two seconds on.
pp_act_none() {
    sleep 2
    graphql "query(\$id: ID!, \$t: String!) { logs(filter: {kinds: [$1], target: \$t}, afterId: \$id, limit: 20) { id } }" \
        '{"id": "'"$3"'", "t": "'"$2"'"}' 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["logs"]))' 2>/dev/null
}

pp_act_setup() {
    PP_ACT_PASS="$(pp_gen)"
    graphql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$PP_ACT_OU"'"}' >/dev/null 2>&1 &&
        PP_ACT_POLICY="$(graphql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
            '{"n": "'"$PP_RUN"' actions", "i": [{"key": "lockout-threshold", "value": "3"}, {"key": "lockout-duration-seconds", "value": "0"}, {"key": "inactivity-days", "value": "1"}]}' \
            2>/dev/null | json_get createPolicy.id 2>/dev/null)" && [ -n "$PP_ACT_POLICY" ] &&
        graphql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' \
            '{"o": "'"$PP_ACT_OU"'", "p": '"$PP_ACT_POLICY"'}' >/dev/null 2>&1 || return 1
    for u in "$PP_LOCK" "$PP_IDLE" "$PP_FRESH"; do
        graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$u"'", "email": "'"$u"'@gate.test"}}' >/dev/null 2>&1 &&
            graphql "$PP_SET" "$(pp_vars "$u" "$PP_ACT_PASS")" >/dev/null 2>&1 &&
            graphql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
                '{"ids": ["'"$u"'"], "ou": "'"$PP_ACT_OU"'"}' >/dev/null 2>&1 || return 1
    done
    [ "$(pp_act_bind "$PP_IDLE" "$PP_ACT_PASS")" = 0 ]
}

# pp_act_setback: the idle user's creation, last success and re-enable, and recording_since, each
# three days earlier, with the gate's server stopped; then it is healthy again (phase 38's way).
# PP_ACT_SINCE is the badge the page then owes: the latest of the four, plus the one day, as a UTC date.
pp_act_setback() {
    local copy="$PP_D/setback.db" said="" rc=0 since side
    t docker stop "$CONTAINER" >/dev/null 2>&1 || return 1
    case "$GATE_DB" in
    sqlite)
        rm -f "$copy"
        # A journal left beside the stopped database would undo the edit at its next open.
        for side in users.db-journal users.db-wal users.db-shm; do
            docker cp "$CONTAINER:/data/$side" - >/dev/null 2>&1 && said="$side is beside the stopped database" && rc=1
        done
        [ "$rc" = 0 ] && docker cp "$CONTAINER:/data/users.db" "$copy" >/dev/null 2>&1 &&
            said="$(PP_DB="$copy" PP_U="$PP_IDLE" python3 - 2>&1 <<'PY'
import os, sqlite3
con = sqlite3.connect(os.environ["PP_DB"])
user = os.environ["PP_U"]
back = "strftime('%Y-%m-%d %H:%M:%f', {0}, '-3 days')"
made = con.execute("UPDATE users SET creation_date = " + back.format("creation_date") + " WHERE user_id = ?", (user,)).rowcount
con.execute("UPDATE user_activity SET last_success = " + back.format("last_success") + ", reenabled_at = "
            + back.format("reenabled_at") + " WHERE user_id = ?", (user,))
since = con.execute("""UPDATE system_config SET "value" = strftime('%Y-%m-%dT%H:%M:%fZ', "value", '-3 days')
    WHERE "key" = 'inactivity_recording_since' AND "value" <> 'off'""").rowcount
con.commit()
end = con.execute("""SELECT date(max(julianday(u.creation_date), coalesce(julianday(a.last_success), 0),
    coalesce(julianday(a.reenabled_at), 0), coalesce(julianday(s."value"), 0)) + 1) FROM users u
    LEFT JOIN user_activity a ON a.user_id = u.user_id
    LEFT JOIN system_config s ON s."key" = 'inactivity_recording_since' WHERE u.user_id = ?""", (user,)).fetchone()[0]
print(f"users {made}, recording_since {since}")
print(end)
raise SystemExit(0 if made == 1 and since == 1 and end else 1)
PY
)" && docker cp "$copy" "$CONTAINER:/data/users.db" >/dev/null 2>&1 || rc=1
        rm -f "$copy"
        ;;
    postgres)
        said="$(gexec_in "$PG_CONTAINER" psql -U klldap -d klldap -v ON_ERROR_STOP=1 -q -tA -c "BEGIN;
UPDATE users SET creation_date = creation_date - interval '3 days' WHERE user_id = '$PP_IDLE';
UPDATE user_activity SET last_success = last_success - interval '3 days',
    reenabled_at = reenabled_at - interval '3 days' WHERE user_id = '$PP_IDLE';
UPDATE system_config SET \"value\" = to_char((\"value\"::timestamptz - interval '3 days') AT TIME ZONE 'UTC',
    'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') WHERE \"key\" = 'inactivity_recording_since' AND \"value\" <> 'off';
COMMIT;
SELECT to_char(GREATEST(u.creation_date, a.last_success, a.reenabled_at,
    s.\"value\"::timestamptz AT TIME ZONE 'UTC') + interval '1 day', 'YYYY-MM-DD') FROM users u
    LEFT JOIN user_activity a ON a.user_id = u.user_id
    JOIN system_config s ON s.\"key\" = 'inactivity_recording_since' WHERE u.user_id = '$PP_IDLE'
    AND GREATEST(u.creation_date, a.last_success, a.reenabled_at, s.\"value\"::timestamptz AT TIME ZONE 'UTC')
        < (now() AT TIME ZONE 'UTC') - interval '2 days';" 2>&1)"
        ;;
    *) rc=1 ;;
    esac
    printf '%s\n' "$said" >>"$PP_D/setback.out"
    since="$(tail -n 1 <<<"$said")"
    case "$since" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) PP_ACT_SINCE="Inactive since $since" ;; *) rc=1 ;; esac
    pp_act_restart
    return "$rc"
}

# The gate's server, healthy again before the next row; started a second time if it is not. Down
# after both, the rows after it would fail on it, so the run stops here.
pp_act_up() { t docker start "$CONTAINER" >/dev/null 2>&1 && wait_healthy 120 && discover_ports && TOKEN="$(gate_login)"; }
pp_act_restart() {
    pp_act_up && return 0
    pp_act_up && return 0
    p_bad "[U1.actions-server-down] the gate's server did not come back healthy after the set-back, started twice: the run stops here"
    gate_summary
    exit 1
}

# The three inactive rows' SKIP: what kept them from running.
pp_act_unaged() {
    case "$GATE_DB" in
    sqlite | postgres) printf '%s\n' "not run: the set-back failed (see [U1.actions-setback] and setback.out)" ;;
    *) printf '%s\n' "the gate sets times back only on sqlite and postgres; on $GATE_DB not run" ;;
    esac
}

# pp_act_said <tag> <row> <label> <what the page must show> <case>: the row, judged here.
pp_act_said() {
    local got
    got="$(pp_act_row "$1" "$2")"
    if [ "$got" = "ROW $2 SEEN $4" ]; then
        p_ok "[$3] $5: $4"
    else
        p_bad "[$3] $5: ${got#ROW "$2" } (want $4)"
    fi
}

pp_actions() {
    local row mark i got before after idle_before
    if ! pp_act_setup; then
        p_bad "[U1.actions-setup] $PP_ACT_OU, its policy (lockout-threshold 3, duration 0, inactivity-days 1) or its users could not be made"
        return
    fi
    for i in 1 2 3; do pp_act_bind "$PP_LOCK" "wrong-$i-$PP_RUN" >/dev/null; done
    before="$(pp_act_bind "$PP_LOCK" "$PP_ACT_PASS")"
    case "$GATE_DB" in
    sqlite | postgres)
        if pp_act_setback; then
            PP_ACT_AGED=1
        else
            p_bad "[U1.actions-setback] $PP_IDLE's times could not be set back, or were not read back three days old (see setback.out)"
        fi
        ;;
    esac
    idle_before="$(pp_act_bind "$PP_IDLE" "$PP_ACT_PASS")"
    mark="$(log_mark)"
    pp_act_page admin admin
    pp_act_said admin state-locked U1.actions-state-locked \
        "locked='Locked until an admin unlocks' inactive=none unlock='Unlock' reenable=none" \
        "an admin on $PP_LOCK's page, locked until an admin unlocks (duration 0)"
    pp_act_said admin state-fresh U1.actions-state-fresh "locked=none inactive=none unlock=none reenable=none" \
        "an admin on $PP_FRESH's page, neither locked nor inactive, once its state has answered"
    if [ "$PP_ACT_AGED" = 1 ]; then
        pp_act_said admin state-inactive U1.actions-state-inactive \
            "locked=none inactive='$PP_ACT_SINCE' unlock=none reenable='Re-enable after inactivity'" \
            "an admin on $PP_IDLE's page, idle past inactivity-days 1 (the latest start plus one day)"
    else
        p_skip "[U1.actions-state-inactive] $(pp_act_unaged)"
    fi
    row="U1.actions-unlock" FAIL_WHY=""
    got="$(pp_act_row admin unlock-page)"
    after="$(pp_act_bind "$PP_LOCK" "$PP_ACT_PASS")"
    if [ "$before" = refused ] && [ "$got" = "ROW unlock-page SEEN Unlocked $PP_LOCK | the badge and the button are gone" ] &&
        [ "$after" = 0 ] && log_once true ACCOUNT_UNLOCK "$PP_LOCK" unlockUser "$mark" GRAPHQL; then
        p_ok "[$row] $PP_LOCK locked (3 wrong, the right password refused); Unlock on its page: 'Unlocked $PP_LOCK', the badge and the button go, one ACCOUNT_UNLOCK row 'unlockUser' (protocol GRAPHQL), the right password binds"
    else
        p_bad "[$row] before: $before (want refused); page: $got; after: $after (want 0); ${FAIL_WHY:-want one ACCOUNT_UNLOCK row}"
    fi
    if [ "$PP_ACT_AGED" = 1 ]; then
        row="U1.actions-reenable-cancel"
        got="$(pp_act_row admin reenable-modal)"
        i="$(pp_act_none ACCOUNT_REENABLE "$PP_IDLE" "$mark")"
        if [ "$got" = "ROW reenable-modal SEEN Re-enable $PP_IDLE? | Re-enable sign-in for this user (resets the inactivity count) | Cancel | no result line" ] &&
            [ "$i" = 0 ]; then
            p_ok "[$row] Re-enable on $PP_IDLE's page opens 'Re-enable $PP_IDLE?' with 'Re-enable sign-in for this user (resets the inactivity count)'; Cancel leaves no result line and writes no ACCOUNT_REENABLE row"
        else
            p_bad "[$row] $got; ACCOUNT_REENABLE rows after Cancel: ${i:-unread} (want 0)"
        fi
        row="U1.actions-reenable-early-cancel"
        got="$(pp_act_row admin reenable-early-cancel)"
        if [ "$got" = "ROW reenable-early-cancel SEEN Cancel before shown.bs.modal | closed | no result line" ] &&
            [ "$i" = 0 ]; then
            p_ok "[$row] Re-enable on $PP_IDLE's page, then one Cancel while the dialog is still opening (before shown.bs.modal): it closes when the opening ends (hidden.bs.modal, no backdrop left), with no result line and no ACCOUNT_REENABLE row"
        else
            p_bad "[$row] $got; ACCOUNT_REENABLE rows after Cancel: ${i:-unread} (want 0)"
        fi
    else
        p_skip "[U1.actions-reenable-cancel] $(pp_act_unaged)"
        p_skip "[U1.actions-reenable-early-cancel] $(pp_act_unaged)"
    fi
    pp_act_page own own "$PP_FRESH"
    pp_act_said own buttons-own U1.actions-own-page "locked=none inactive=none unlock=none reenable=none" \
        "$PP_FRESH on its own page"
    row="U1.actions-reenable" FAIL_WHY=""
    if [ "$PP_ACT_AGED" != 1 ]; then
        p_skip "[$row] $(pp_act_unaged)"
        return
    fi
    mark="$(log_mark)"
    pp_act_page reenable reenable
    got="$(pp_act_row reenable reenable-page)"
    after="$(pp_act_bind "$PP_IDLE" "$PP_ACT_PASS")"
    if [ "$idle_before" = refused ] && [ "$got" = "ROW reenable-page SEEN Re-enabled $PP_IDLE | the badge and the button are gone" ] &&
        [ "$after" = 0 ] && log_once true ACCOUNT_REENABLE "$PP_IDLE" reenableUser "$mark" GRAPHQL; then
        p_ok "[$row] $PP_IDLE idle past inactivity-days 1 (refused); Yes, re-enable on its page: 'Re-enabled $PP_IDLE', the badge and the button go, one ACCOUNT_REENABLE row 'reenableUser' (protocol GRAPHQL), the right password binds"
    else
        p_bad "[$row] before: $idle_before (want refused); page: $got; after: $after (want 0); ${FAIL_WHY:-want one ACCOUNT_REENABLE row}"
    fi
}

pp_act_cleanup() {
    local u
    docker rm -f "$PP_ACT_CTN" >/dev/null 2>&1 || true
    for u in "$PP_LOCK" "$PP_IDLE" "$PP_FRESH"; do
        graphql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}' >/dev/null 2>&1
    done
    graphql 'mutation($o: String!) { clearOuPolicy(ou: $o) { ok } }' '{"o": "'"$PP_ACT_OU"'"}' >/dev/null 2>&1
    [ -n "$PP_ACT_POLICY" ] && graphql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$PP_ACT_POLICY"'}' >/dev/null 2>&1
    graphql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$PP_ACT_OU"'"}' >/dev/null 2>&1
}

if pp_setup; then
    pp_gone
    pp_floor
    pp_manager
    if docker image inspect "$PP_BROWSER_IMAGE" >/dev/null 2>&1; then
        pp_wire_rows
        pp_inject_nosync
        pp_swap_label
        pp_swap_other
        pp_create_big
        pp_create_synced
        pp_min_page
    else
        p_skip "[U1.pages-browser] browser image absent: ${PP_BROWSER_IMAGE}; the page rows did not run"
    fi
    pp_no_progress
    if docker image inspect "$PP_BROWSER_IMAGE" >/dev/null 2>&1; then
        pp_actions
    fi
fi
docker rm -f "$PP_BROWSER_CTN" >/dev/null 2>&1 || true
for u in "$PP_PM" "$PP_SYNC" "$PP_PLAIN" "$PP_BIG" "$PP_NEW"; do
    graphql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}' >/dev/null 2>&1
done
pp_act_cleanup
pp_krb_off
docker rm -fv "$PP_OFF_CTN" >/dev/null 2>&1
docker volume rm "$PP_OFF_DATA" "$PP_OFF_KDC" >/dev/null 2>&1
if [ "$PP_XT" = 1 ]; then set -x; fi
