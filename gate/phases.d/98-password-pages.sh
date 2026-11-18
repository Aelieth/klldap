# shellcheck shell=bash
# Phase: U1′'s password pages and the set-password tool. register/start gives a key only to a
# synced user; that user's finish carries the password sealed for that user (OAEP label
# klldap-kerberos-envelope-v1:<user>), and the server commits it to both stores in one transaction.

PP_D="$(phase_dir)"
PP_RUN="pp$(date +%H%M%S)"
PP_PM="${PP_RUN}m" PP_SYNC="${PP_RUN}s" PP_PLAIN="${PP_RUN}p" PP_BIG="${PP_RUN}b" PP_NEW="${PP_RUN}n"
PP_GONE_MUT='mutation($u: String!, $e: String!) { syncKerberosPassword(userId: $u, encryptedPassword: $e) }'
PP_SET='mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }'
PP_KEY="" PP_GOT="" PP_WIRE="" PP_ALERT=""
PP_BOTH_NEW="bind-new=yes bind-old=no kinit-new=yes kinit-old=no"
PP_BOTH_OLD="bind-new=no bind-old=yes kinit-new=no kinit-old=yes"
PP_BROWSER_IMAGE="mcr.microsoft.com/playwright@sha256:766137e2d9caad4744187e53cdc89320ba6f2eb57cff097374020944b44dd0a9"
PP_BROWSER_CTN="klldap-pp-wire-${RUNID}"
EXTRA_CONTAINERS+=("$PP_BROWSER_CTN")
# shellcheck disable=SC2034
TOKEN="$(gate_login)" || p_bad "[U1.pages-login] the admin could not log in"

pp_gen() { python3 -c 'import secrets; print("Pp" + secrets.token_hex(10) + "!")'; }
pp_vars() { ID="$1" PW="$2" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "pw": os.environ["PW"]}))'; }
pp_dn() { printf 'uid=%s,ou=people,%s' "$1" "$BASE_DN"; }

pp_bind() {
    local f="$PP_D/.bindpw" rc
    (umask 077 && printf '%s' "$2" >"$f")
    t ldapwhoami -x -H "$(ldap_url)" -D "$(pp_dn "$1")" -y "$f" >/dev/null 2>&1
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
    local short="Short7x" rc row="U1.synced-floor"
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
    local row="U1.envelope-nosync-refused" new sealed
    local want="WIRE start-key=no finish-envelope=no rewrite=added finish-status=400 graphql-seal=no create-sent=no page=stayed"
    new="$(pp_gen)"
    sealed="$(pp_seal "$new" "$PP_PLAIN")"
    [ -n "$sealed" ] || {
        p_bad "[$row] OpenSSL did not seal (see seal.err)"
        return
    }
    pp_wire plain-add change "$PP_PLAIN" "$new" add "$sealed"
    pp_binds "$PP_PLAIN" "$new" "$PP_PLAIN_PASS"
    if [ "$PP_WIRE" = "$want" ] && [ "$PP_GOT" = "bind-new=no bind-old=yes" ] &&
        grep -q 'a Kerberos password envelope is taken only for a user with Kerberos sync' <<<"$PP_ALERT"; then
        p_ok "[$row] an envelope in a finish for a user without sync: 400 '$PP_ALERT', and the old password still binds"
    else
        p_bad "[$row] $PP_WIRE (alert: ${PP_ALERT:-none}); $PP_GOT; want $want, the sync sentence, bind-new=no bind-old=yes"
    fi
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
    local row="U1.envelope-other-label" typed sealed
    local want="WIRE start-key=yes finish-envelope=yes rewrite=swapped finish-status=400 graphql-seal=no create-sent=no page=stayed"
    typed="$(pp_gen)"
    sealed="$(pp_seal "$typed" "$PP_PLAIN")"
    [ -n "$sealed" ] || {
        p_bad "[$row] OpenSSL did not seal (see seal.err)"
        return
    }
    pp_wire sync-other change "$PP_SYNC" "$typed" swap "$sealed"
    pp_sides "$PP_SYNC" "$typed" "$PP_SYNC_PASS"
    if [ "$PP_WIRE" = "$want" ] && [ "$PP_GOT" = "$PP_BOTH_OLD" ] &&
        grep -q 'the Kerberos password envelope did not open' <<<"$PP_ALERT"; then
        p_ok "[$row] $PP_SYNC's finish with an envelope sealed for $PP_PLAIN: 400 '$PP_ALERT', and bind and kinit keep the old password"
    else
        p_bad "[$row] $PP_WIRE (alert: ${PP_ALERT:-none}); $PP_GOT; want $want, 'did not open', $PP_BOTH_OLD"
    fi
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

pp_no_progress() {
    local hits
    hits="$(grep -il 'in progress' "$PP_D"/*-register.log "$PP_D"/wire-*.out 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')"
    if [ -z "$hits" ]; then
        p_ok "[U1.no-in-progress] no page and no tool answer of this phase says a change is in progress"
    else
        p_bad "[U1.no-in-progress] 'in progress' in: $hits"
    fi
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
    else
        p_skip "[U1.pages-browser] browser image absent: ${PP_BROWSER_IMAGE}; the page rows did not run"
    fi
    pp_no_progress
fi
docker rm -f "$PP_BROWSER_CTN" >/dev/null 2>&1 || true
for u in "$PP_PM" "$PP_SYNC" "$PP_PLAIN" "$PP_BIG" "$PP_NEW"; do
    graphql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}' >/dev/null 2>&1
done
