# shellcheck shell=bash
# Phase: kadmin and directory users. Every wrong answer is FAIL.
# kadmin -q exits 0 on a refused query, so a refusal is judged on its text
# and on the record being unchanged. add_alias is not in this image's kadmin.
# The corrections against rows.md are logs/PROPER/K1/note-phases-6.md and PH/note-phases-7.md.
# The OTHER.TEST rows are logs/PROPER/R5L/note.md.

D="$(phase_dir)"
SYNC=k1sync
NOSYNC=k1nosync
LATE=k1late
FLOOD=k1flood
ORPHAN=k1orphan
SVC=k1svc/gate.test
CTL=k1ctl/gate.test
PASS=K1syncPass2026!
NEW=K1syncNewPass2026!
SELF=K1selfPass2026!
AFTER=K1afterPass2026!
E128=aes128-cts-hmac-sha1-96:normal
E256=aes256-cts-hmac-sha1-96:normal
ADMIN="admin/admin@$REALM"
CUR="$PASS"

kvno_of() {
    kadmin_q "getprinc $1" 2>/dev/null | awk '/Key: vno/ {print $3; exit}' | tr -d ','
}
bind_ok() {
    t ldapwhoami -x -H "$(ldap_url)" -D "uid=$1,ou=people,$BASE_DN" -w "$2" >/dev/null 2>&1
}
kadmin_user() {
    # shellcheck disable=SC2016
    gexec sh -c 'printf "%s\n" "$1" | kadmin -p "$0" -q "$2"' \
        "$1@$REALM" "$2" "$3"
}
no_principal() {
    local name="$1" tag="$2"
    kadmin_q "getprinc $name" >"$D/$tag-absent.txt" 2>&1 || true
    if grep -q 'Principal does not exist' "$D/$tag-absent.txt"; then
        p_ok "$tag: $name has no principal"
    else
        p_bad "$tag: expected 'Principal does not exist' for $name (see $tag-absent.txt)"
    fi
}
kinit_missing() {
    local name="$1" pass="$2" tag="$3"
    if kinit_pw "$name@$REALM" "$pass" >"$D/kinit-$tag.log" 2>&1; then
        p_bad "$tag: kinit of $name succeeded"
    elif grep -q 'not found in Kerberos database' "$D/kinit-$tag.log"; then
        p_ok "$tag: kinit of $name finds no principal"
    else
        p_bad "$tag: kinit of $name failed without 'not found in Kerberos database' (see kinit-$tag.log)"
    fi
}
log_mark() {
    graphql '{ logs(limit: 1) { id } }' '{}' >"$D/mark.json" 2>"$D/mark.err" || return 1
    json_get logs.0.id <"$D/mark.json"
}
# Exactly one row after the marker with this target and detail; protocol kadmin, actor the client.
log_one() {
    local kind="$1" target="$2" detail="$3" success="$4" tag="$5" mark="$6" actor="$7"
    local _
    for _ in $(seq 1 20); do
        if graphql "query(\$id: ID!, \$t: String!) { logs(filter: {kinds: [$kind], target: \$t}, afterId: \$id, limit: 20) { success protocol actor detail } }" \
            '{"id": "'"$mark"'", "t": "'"$target"'"}' >"$D/$tag-log.json" 2>"$D/$tag-log.err" \
            && DETAIL="$detail" WANT="$success" ACTOR="$actor" python3 - "$D/$tag-log.json" <<'PY'
import json, os, sys
try:
    rows = json.load(open(sys.argv[1], encoding="utf-8")).get("logs") or []
except Exception:
    sys.exit(1)
same = [r for r in rows if r.get("detail") == os.environ["DETAIL"]]
ok = len(same) == 1 and (
    same[0].get("success") is (os.environ["WANT"] == "true")
    and same[0].get("protocol") == "KADMIN"
    and same[0].get("actor") == os.environ["ACTOR"]
)
sys.exit(0 if ok else 1)
PY
        then
            return 0
        fi
        sleep 0.5
    done
    return 1
}
# No access_denied row after the marker names the principal; a later refusal's row shows the writer passed it.
log_none() {
    local name="$1" later="$2" tag="$3" mark="$4"
    # shellcheck disable=SC2016
    graphql 'query($id: ID!) { logs(filter: {kinds: [ACCESS_DENIED]}, afterId: $id, limit: 100) { target detail } }' \
        '{"id": "'"$mark"'"}' >"$D/$tag-log.json" 2>"$D/$tag-log.err" || return 1
    NAME="$name" LATER="$later" python3 - "$D/$tag-log.json" >"$D/$tag-log.out" 2>&1 <<'PY'
import json, os, sys
rows = json.load(open(sys.argv[1], encoding="utf-8")).get("logs") or []
name, later = os.environ["NAME"], os.environ["LATER"]
named = [r for r in rows if r.get("target") == name or name in (r.get("detail") or "")]
bad = []
if named:
    bad.append(f"access_denied rows name {name}: {json.dumps(named)}")
if not any(r.get("detail") == later for r in rows):
    bad.append(f"the later row '{later}' is not in the log, so nothing shows the writer passed the cpw")
print("; ".join(bad))
sys.exit(1 if bad else 0)
PY
}
princ_view() {
    awk '/^(Policy:|Attributes:|Expiration date:|Password expiration date:|Number of keys:|Key:)/ { print }'
}
take_snap() {
    kadmin_q "getprinc $SYNC" >"$D/snap-princ.txt" 2>&1 || true
    kadmin_q "getstrs $SYNC" >"$D/snap-strs.txt" 2>&1 || true
    KV="$(kvno_of "$SYNC")"
}
same_record() {
    local tag="$1"
    local now view
    kadmin_q "getprinc $SYNC" >"$D/now-princ.txt" 2>&1 || true
    kadmin_q "getstrs $SYNC" >"$D/now-strs.txt" 2>&1 || true
    now="$(kvno_of "$SYNC")"
    view="$(princ_view <"$D/now-princ.txt")"
    if [ -z "$KV" ] || [ "$now" != "$KV" ]; then
        p_bad "$tag: key version changed (${KV:-empty} -> ${now:-empty})"
    elif [ "$view" != "$(princ_view <"$D/snap-princ.txt")" ]; then
        p_bad "$tag: policy, attributes, expiry, or keys changed"
    elif ! cmp -s "$D/snap-strs.txt" "$D/now-strs.txt"; then
        p_bad "$tag: string attributes changed"
    elif bind_ok "$SYNC" "$CUR" && kinit_pw "$SYNC@$REALM" "$CUR" >"$D/kinit-$tag.log" 2>&1; then
        p_ok "$tag: the record, the bind, and kinit are unchanged"
    else
        p_bad "$tag: the doors moved (see kinit-$tag.log)"
    fi
}

# A refusal. The exit code is not the verdict.
refused() {
    local tag="$1" query="$2" text="$3" verb="$4" code="$5" actor="$6"
    local as_user="${7:-}" principal="${8:-$SYNC}"
    local mark detail
    mark="$(log_mark)" || { p_bad "$tag: could not read a log marker"; return; }
    take_snap
    if [ -n "$as_user" ]; then
        kadmin_user "$as_user" "$CUR" "$query" >"$D/$tag.txt" 2>&1 || true
    else
        kadmin_q "$query" >"$D/$tag.txt" 2>&1 || true
    fi
    if grep -qF "$text" "$D/$tag.txt"; then
        p_ok "$tag: $text"
    else
        p_bad "$tag: expected '$text' (see $tag.txt)"
    fi
    detail="kadmin $verb on ${principal}@${REALM} by ${actor}: ${code}"
    if log_one ACCESS_DENIED "${principal}@${REALM}" "$detail" false "$tag" "$mark" "$actor"; then
        p_ok "$tag: one access_denied names $code, protocol KADMIN, actor $actor"
    else
        p_bad "$tag: access_denied '$detail' with protocol KADMIN and actor $actor is not exactly one (see $tag-log.json)"
    fi
    same_record "$tag"
}

# The flood rows after the marker: 8 access_denied, one started; at "end", one resolved too.
flood_check() {
    local stage="$1" mark="$2"
    # shellcheck disable=SC2016
    graphql 'query($id: ID!) { logs(filter: {kinds: [ACCESS_DENIED, ACCESS_DENIED_FLOOD]}, afterId: $id, limit: 500) { kind success protocol actor target detail } }' \
        '{"id": "'"$mark"'"}' >"$D/flood-$stage.json" 2>"$D/flood-$stage.err" || return 1
    STAGE="$stage" WHO="$FLOOD@$REALM" DETAIL="$FLOOD_DETAIL" \
        python3 - "$D/flood-$stage.json" >"$D/flood-$stage.out" 2>&1 <<'PY'
import json, os, re, sys
rows = json.load(open(sys.argv[1], encoding="utf-8")).get("logs") or []
who = os.environ["WHO"]
def mine(r):
    return r.get("success") is False and r.get("protocol") == "KADMIN" and r.get("actor") == who
denied = [r for r in rows if r.get("kind") == "ACCESS_DENIED" and r.get("target") == who]
floods = [r for r in rows if r.get("kind") == "ACCESS_DENIED_FLOOD" and r.get("protocol") == "KADMIN"]
started = [r for r in floods if r.get("detail") == "access-denied flood started"]
resolved = [r for r in floods if (r.get("detail") or "").startswith("access-denied flood resolved")]
bad = []
if len(denied) != 8 or not all(mine(r) and r.get("detail") == os.environ["DETAIL"] for r in denied):
    bad.append(f"{len(denied)} access_denied rows for {who}, want 8: {json.dumps(denied)}")
if any(r.get("actor") != who for r in floods):
    bad.append("a kadmin flood row names another actor: " + json.dumps(floods))
if len(started) != 1 or not mine(started[0]) or started[0].get("target") is not None:
    bad.append("started rows: " + json.dumps(started))
want = r"access-denied flood resolved: 2 denials, 1 actors, [0-9]+s"
if os.environ["STAGE"] == "end" and (
    len(resolved) != 1 or not mine(resolved[0])
    or not re.fullmatch(want, resolved[0].get("detail") or "")
):
    bad.append("resolved rows: " + json.dumps(resolved))
print("; ".join(bad))
sys.exit(1 if bad else 0)
PY
}

# shellcheck disable=SC2016
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$SYNC"'", "email": "'"$SYNC"'@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create-sync.json" 2>&1 || p_bad "createUser $SYNC failed"
# shellcheck disable=SC2016
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$NOSYNC"'", "email": "'"$NOSYNC"'@gate.test"}}' \
    >"$D/create-nosync.json" 2>&1 || p_bad "createUser $NOSYNC failed"
# shellcheck disable=SC2016
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$LATE"'", "email": "'"$LATE"'@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create-late.json" 2>&1 || p_bad "createUser $LATE failed"
# shellcheck disable=SC2016
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$SYNC"'", "pw": "'"$PASS"'"}' >"$D/setpw-sync.json" 2>&1 \
    || p_bad "setUserPassword $SYNC failed"
# shellcheck disable=SC2016
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$NOSYNC"'", "pw": "'"$PASS"'"}' >"$D/setpw-nosync.json" 2>&1 \
    || p_bad "setUserPassword $NOSYNC failed"

ready=""
for _ in $(seq 1 15); do
    if kadmin_q "getprinc $SYNC" >"$D/wait-sync.txt" 2>&1 \
        && grep -q "^Principal: $SYNC@$REALM" "$D/wait-sync.txt"; then
        ready=1
        break
    fi
    sleep 1
done
if [ -n "$ready" ]; then
    p_ok "$SYNC has a principal"
else
    p_bad "$SYNC has no principal"
fi
no_principal "$NOSYNC" nosync-before
late_appeared=""
for _ in $(seq 1 8); do
    if kadmin_q "getprinc $LATE" >"$D/wait-late.txt" 2>&1 \
        && grep -q "^Principal: $LATE@$REALM" "$D/wait-late.txt"; then
        late_appeared=1
        break
    fi
    sleep 1
done
if [ -n "$late_appeared" ]; then
    p_bad "$LATE gained a principal before any password was set"
else
    p_ok "$LATE still has no principal"
fi

for ctl in "svc $SVC K1svcPass2026!" "ctl $CTL K1ctlPass2026!"; do
    read -r ctl_tag ctl_name ctl_pw <<<"$ctl"
    kadmin_q "addprinc -pw $ctl_pw $ctl_name" >"$D/add-$ctl_tag.txt" 2>&1 || true
    if ! grep -q " while " "$D/add-$ctl_tag.txt" \
        && kadmin_q "getprinc $ctl_name" >"$D/get-$ctl_tag.txt" 2>&1 \
        && grep -q "^Principal: $ctl_name@$REALM" "$D/get-$ctl_tag.txt"; then
        p_ok "setup: service principal $ctl_name exists"
    else
        p_bad "setup: service principal $ctl_name was not created (see add-$ctl_tag.txt, get-$ctl_tag.txt)"
    fi
done

kadmin_q "addprinc -pw K1orphanPass2026! $ORPHAN" >"$D/orphan.txt" 2>&1 || true
if grep -qF "Kerberos database constraints violated" "$D/orphan.txt"; then
    p_ok "orphan: addprinc of $ORPHAN, one part and no directory user, says Kerberos database constraints violated"
else
    p_bad "orphan: expected 'Kerberos database constraints violated' for $ORPHAN (see orphan.txt)"
fi
no_principal "$ORPHAN" orphan

# shellcheck disable=SC2016
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$FLOOD"'", "email": "'"$FLOOD"'@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create-flood.json" 2>&1 || p_bad "createUser $FLOOD failed"
# shellcheck disable=SC2016
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$FLOOD"'", "pw": "'"$PASS"'"}' >"$D/setpw-flood.json" 2>&1 \
    || p_bad "setUserPassword $FLOOD failed"
flood_ready=""
for _ in $(seq 1 15); do
    if kadmin_q "getprinc $FLOOD" >"$D/wait-flood.txt" 2>&1 \
        && grep -q "^Principal: $FLOOD@$REALM" "$D/wait-flood.txt"; then
        flood_ready=1
        break
    fi
    sleep 1
done
if [ -n "$flood_ready" ]; then
    p_ok "setup: $FLOOD has a principal"
else
    p_bad "setup: $FLOOD has no principal (see wait-flood.txt)"
fi
FLOOD_DETAIL="kadmin purge_keys on $FLOOD@$REALM by $FLOOD@$REALM: PROTECT_PRINCIPAL"
FLOOD_MARK="$(log_mark)" || FLOOD_MARK=""
flood_refused=0
for i in $(seq 1 10); do
    kadmin_user "$FLOOD" "$PASS" "purgekeys $FLOOD" >"$D/flood-$i.txt" 2>&1 || true
    if grep -qF "Cannot change protected principal" "$D/flood-$i.txt"; then
        flood_refused=$((flood_refused + 1))
    fi
done
FLOOD_END="$(date +%s)"
if [ "$flood_refused" = 10 ]; then
    p_ok "flood: kadmin refused all 10 of $FLOOD's own purgekeys"
else
    p_bad "flood: $flood_refused of 10 of $FLOOD's own purgekeys said Cannot change protected principal (see flood-N.txt)"
fi
flood_started=""
for _ in $(seq 1 20); do
    if [ -n "$FLOOD_MARK" ] && flood_check start "$FLOOD_MARK"; then
        flood_started=1
        break
    fi
    sleep 0.5
done
if [ -n "$flood_started" ]; then
    p_ok "flood: 8 access_denied rows, then one 'access-denied flood started' for $FLOOD@$REALM"
else
    p_bad "flood: $(cat "$D/flood-start.out" 2>/dev/null || echo 'no rows read (see mark.err, flood-start.err)')"
fi

KV="$(kvno_of "$SYNC")"
MARK="$(log_mark)" || MARK=""
if kadmin_q "cpw -pw $NEW $SYNC" >"$D/cpw.txt" 2>&1 && ! grep -q " while " "$D/cpw.txt"; then
    p_ok "cpw of $SYNC produced no error text"
else
    p_bad "cpw of $SYNC failed (see cpw.txt)"
fi
now="$(kvno_of "$SYNC")"
if [ -n "$KV" ] && [ "$now" = "$((KV + 1))" ] \
    && bind_ok "$SYNC" "$NEW" && ! bind_ok "$SYNC" "$PASS" \
    && kinit_pw "$SYNC@$REALM" "$NEW" >"$D/kinit-new.log" 2>&1 \
    && ! kinit_pw "$SYNC@$REALM" "$PASS" >"$D/kinit-old.log" 2>&1; then
    p_ok "cpw: bind and kinit take the new password and the key version increased by one"
else
    p_bad "cpw: the doors did not follow the new password (kvno '${now:-empty}')"
fi
CPW_DETAIL="kadmin change_password by $ADMIN"
if [ -n "$MARK" ] && log_one PASSWORD_CHANGE "$SYNC@$REALM" "$CPW_DETAIL" true cpw "$MARK" "$ADMIN"; then
    p_ok "cpw: exactly one password_change names the kadmin caller, protocol KADMIN, actor $ADMIN"
else
    p_bad "cpw: password_change '$CPW_DETAIL' with protocol KADMIN and actor $ADMIN is not exactly one"
fi
CUR="$NEW"
KV="$now"

refused cpw-short "cpw -pw short7x $SYNC" "Password is too short" "change_password" PASS_Q_TOOSHORT "$ADMIN"
refused cpw-keepold "cpw -keepold -pw K1keepoldPass2026! $SYNC" \
    "Cannot change protected principal" "change_password" PROTECT_PRINCIPAL "$ADMIN"
refused cpw-randkey "cpw -randkey $SYNC" \
    "Cannot change protected principal" "randkey" PROTECT_PRINCIPAL "$ADMIN"
refused cpw-randkey-e "cpw -randkey -e $E256 $SYNC" \
    "Cannot change protected principal" "randkey" PROTECT_PRINCIPAL "$ADMIN"
E_MARK="$(log_mark)" || E_MARK=""
ctl_kv="$(kvno_of "$CTL")"
if kadmin_q "cpw -e $E256 -pw K1ctlEPass2026! $CTL" >"$D/cpw-e-ctl.txt" 2>&1 \
    && ! grep -q " while " "$D/cpw-e-ctl.txt" \
    && kinit_pw "$CTL@$REALM" "K1ctlEPass2026!" >"$D/kinit-cpw-e-ctl.log" 2>&1 \
    && [ -n "$ctl_kv" ] && [ "$(kvno_of "$CTL")" = "$((ctl_kv + 1))" ]; then
    p_ok "cpw-e-ctl: cpw -e $E256 on $CTL, no directory user's principal, is carried out: kinit takes the new password and the key version increased by one"
else
    p_bad "cpw-e-ctl: cpw -e $E256 on $CTL failed (kvno '${ctl_kv:-empty}' before; see cpw-e-ctl.txt, kinit-cpw-e-ctl.log)"
fi
for e in "aes128 $E128 K1e128Pass2026!" "aes256 $E256 K1e256Pass2026!"; do
    read -r e_tag e_ks e_pw <<<"$e"
    refused "cpw-e-$e_tag" "cpw -e $e_ks -pw $e_pw $SYNC" \
        "Invalid key/salt tuples" "change_password" BAD_KEYSALTS "$ADMIN"
    if kinit_pw "$SYNC@$REALM" "$e_pw" >"$D/kinit-cpw-e-$e_tag-new.log" 2>&1; then
        p_bad "cpw-e-$e_tag: kinit of $SYNC takes the password the refused cpw carried"
    elif grep -q 'Password incorrect' "$D/kinit-cpw-e-$e_tag-new.log"; then
        p_ok "cpw-e-$e_tag: kinit of $SYNC with the password the refused cpw carried says Password incorrect"
    else
        p_bad "cpw-e-$e_tag: kinit of $SYNC with the password the refused cpw carried failed without 'Password incorrect' (see kinit-cpw-e-$e_tag-new.log)"
    fi
done
E_LATER="kadmin change_password on $SYNC@$REALM by $ADMIN: BAD_KEYSALTS"
if [ -n "$E_MARK" ] && log_none "$CTL@$REALM" "$E_LATER" cpw-e-ctl "$E_MARK"; then
    p_ok "cpw-e-ctl: no access_denied names $CTL, in a log read past the later refusals"
else
    p_bad "cpw-e-ctl: $(cat "$D/cpw-e-ctl-log.out" 2>/dev/null || echo 'no rows read (see mark.err, cpw-e-ctl-log.err)')"
fi
KV="$(kvno_of "$SYNC")"
MARK="$(log_mark)" || MARK=""
if kadmin_q "cpw -pw $AFTER $SYNC" >"$D/cpw-after.txt" 2>&1 && ! grep -q " while " "$D/cpw-after.txt"; then
    p_ok "cpw-after: a plain cpw of $SYNC after the refused key/salt lists produced no error text"
else
    p_bad "cpw-after: a plain cpw of $SYNC after the refused key/salt lists failed (see cpw-after.txt)"
fi
now="$(kvno_of "$SYNC")"
if [ -n "$KV" ] && [ "$now" = "$((KV + 1))" ] \
    && bind_ok "$SYNC" "$AFTER" && ! bind_ok "$SYNC" "$CUR" \
    && kinit_pw "$SYNC@$REALM" "$AFTER" >"$D/kinit-after-new.log" 2>&1 \
    && ! kinit_pw "$SYNC@$REALM" "$CUR" >"$D/kinit-after-old.log" 2>&1; then
    p_ok "cpw-after: bind and kinit take the new password and the key version increased by one"
else
    p_bad "cpw-after: the doors did not follow the new password (kvno '${KV:-empty}' -> '${now:-empty}'; see kinit-after-new.log, kinit-after-old.log)"
fi
if [ -n "$MARK" ] && log_one PASSWORD_CHANGE "$SYNC@$REALM" "$CPW_DETAIL" true cpw-after "$MARK" "$ADMIN"; then
    p_ok "cpw-after: exactly one password_change names the kadmin caller, protocol KADMIN, actor $ADMIN"
else
    p_bad "cpw-after: password_change '$CPW_DETAIL' with protocol KADMIN and actor $ADMIN is not exactly one (see cpw-after-log.json)"
fi
bind_ok "$SYNC" "$AFTER" && CUR="$AFTER"
KV="$now"
refused ktadd "ktadd -k /tmp/k1.kt $SYNC" \
    "Cannot change protected principal" "randkey" PROTECT_PRINCIPAL "$ADMIN"
if gexec sh -c 'test ! -e /tmp/k1.kt'; then
    p_ok "ktadd left no keytab"
else
    p_bad "ktadd left /tmp/k1.kt"
    gexec rm -f /tmp/k1.kt >/dev/null 2>&1 || true
fi
refused purgekeys "purgekeys $SYNC" \
    "Cannot change protected principal" "purge_keys" PROTECT_PRINCIPAL "$ADMIN"
refused purgekeys-all "purgekeys -all $SYNC" \
    "Cannot change protected principal" "purge_keys" PROTECT_PRINCIPAL "$ADMIN"
refused modprinc-kvno "modprinc -kvno 9 $SYNC" \
    "Cannot change protected principal" "modify" PROTECT_PRINCIPAL "$ADMIN"
if kadmin_q "addpol k1pol" >"$D/addpol.txt" 2>&1 && ! grep -q " while " "$D/addpol.txt"; then
    p_ok "policy k1pol created"
else
    p_bad "addpol k1pol failed (see addpol.txt)"
fi
refused modprinc-policy "modprinc -policy k1pol $SYNC" \
    "Cannot change protected principal" "modify" PROTECT_PRINCIPAL "$ADMIN"
refused modprinc-clearpolicy "modprinc -clearpolicy $SYNC" \
    "Cannot change protected principal" "modify" PROTECT_PRINCIPAL "$ADMIN"
refused modprinc-flag "modprinc +needchange $SYNC" \
    "Cannot change protected principal" "modify" PROTECT_PRINCIPAL "$ADMIN"
refused modprinc-expire "modprinc -expire \"1/1/2030 00:00:00\" $SYNC" \
    "Cannot change protected principal" "modify" PROTECT_PRINCIPAL "$ADMIN"
refused setstr "setstr $SYNC session_enctypes aes256-cts" \
    "Cannot change protected principal" "set_string" PROTECT_PRINCIPAL "$ADMIN"
refused delstr "delstr $SYNC session_enctypes" \
    "Cannot change protected principal" "set_string" PROTECT_PRINCIPAL "$ADMIN"
refused delprinc "delprinc -force $SYNC" \
    "Cannot change protected principal" "delete" PROTECT_PRINCIPAL "$ADMIN"
if kadmin_q "getprinc $SYNC" >"$D/del-stays.txt" 2>&1 \
    && grep -q "^Principal: $SYNC@$REALM" "$D/del-stays.txt"; then
    p_ok "delprinc left $SYNC in place"
else
    p_bad "delprinc removed $SYNC"
fi
refused renprinc-away "renprinc -force $SYNC k1syncaway" \
    "Cannot change protected principal" "rename" PROTECT_PRINCIPAL "$ADMIN"
no_principal k1syncaway renprinc-away
refused addprinc-absent "addprinc -pw K1absentPass2026! $NOSYNC" \
    "Operation requires \`\`add'' privilege" "create" AUTH_ADD "$ADMIN" "" "$NOSYNC"
no_principal "$NOSYNC" addprinc-absent
if bind_ok "$NOSYNC" "$PASS"; then
    p_ok "addprinc-absent: the directory bind stands"
else
    p_bad "addprinc-absent: the directory bind failed"
fi
kinit_missing "$NOSYNC" "$PASS" addprinc-absent
refused addprinc-case "addprinc -pw K1casePass2026! K1sync" \
    "Operation requires \`\`add'' privilege" "create" AUTH_ADD "$ADMIN" "" "K1sync"
no_principal K1sync addprinc-case
refused renprinc-onto "renprinc -force $SVC $NOSYNC" \
    "Operation requires \`\`add'' privilege" "rename" AUTH_ADD "$ADMIN" "" "$NOSYNC"
if kadmin_q "getprinc $SVC" >"$D/svc-stays.txt" 2>&1 \
    && grep -q "^Principal: $SVC@$REALM" "$D/svc-stays.txt"; then
    p_ok "renprinc-onto left $SVC in place"
else
    p_bad "renprinc-onto removed $SVC"
fi
no_principal "$NOSYNC" renprinc-onto
note "[NOTE] ${PHASE}: alias-target and alias-name are IC's Rust rows. This image's kadmin is MIT 1.21 and has no add_alias."
refused addprinc-synced "addprinc -pw K1latePass2026! $LATE" \
    "Operation requires \`\`add'' privilege" "create" AUTH_ADD "$ADMIN" "" "$LATE"
no_principal "$LATE" addprinc-synced

take_snap
MARK="$(log_mark)" || MARK=""
if kadmin_q "modprinc -unlock $SYNC" >"$D/unlock.txt" 2>&1 && ! grep -q " while " "$D/unlock.txt"; then
    p_ok "modprinc -unlock produced no error text"
else
    p_bad "modprinc -unlock failed (see unlock.txt)"
fi
UNLOCK="kadmin unlock by $ADMIN"
if [ -n "$MARK" ] && log_one KERBEROS_SYNC "$SYNC@$REALM" "$UNLOCK" true unlock "$MARK" "$ADMIN"; then
    p_ok "unlock: exactly one kerberos_sync names the kadmin caller, protocol KADMIN, actor $ADMIN"
else
    p_bad "unlock: kerberos_sync '$UNLOCK' with protocol KADMIN and actor $ADMIN is not exactly one"
fi
kadmin_q "getprinc $SYNC" >"$D/unlock-princ.txt" 2>&1 || true
if grep -qx 'Failed password attempts: 0' "$D/unlock-princ.txt"; then
    p_ok "unlock: Failed password attempts: 0. Not locked first: a lock needs a policy, and $SYNC takes none"
else
    p_bad "unlock: getprinc does not show 'Failed password attempts: 0' (see unlock-princ.txt)"
fi
same_record unlock
refused unlock-maxlife "modprinc -unlock -maxlife \"1 hour\" $SYNC" \
    "Cannot change protected principal" "modify" PROTECT_PRINCIPAL "$ADMIN"
life_was="$(grep '^Maximum ticket life:' "$D/snap-princ.txt")"
if [ -n "$life_was" ] && [ "$life_was" = "$(grep '^Maximum ticket life:' "$D/now-princ.txt")" ]; then
    p_ok "unlock-maxlife: the maximum ticket life is unchanged"
else
    p_bad "unlock-maxlife: the maximum ticket life changed or is missing (see snap-princ.txt, now-princ.txt)"
fi

if kadmin_q "getprinc $SYNC" >"$D/getprinc-mark.txt" 2>&1 \
    && ! grep -q " while " "$D/getprinc-mark.txt" \
    && grep -q "^Principal: $SYNC@$REALM" "$D/getprinc-mark.txt"; then
    p_ok "getprinc returns $SYNC. This MIT client does not print the mark; that proof is IC's Rust row"
else
    p_bad "getprinc did not return $SYNC (see getprinc-mark.txt)"
fi
if kadmin_q listprincs >"$D/listprincs.txt" 2>&1 \
    && ! grep -q " while " "$D/listprincs.txt" \
    && grep -q "$SYNC" "$D/listprincs.txt"; then
    p_ok "listprincs names $SYNC"
else
    p_bad "listprincs did not name $SYNC"
fi

if kadmin_user "$SYNC" "$CUR" "getprinc $SYNC" >"$D/self-get.txt" 2>&1 \
    && grep -q "^Principal: $SYNC@$REALM" "$D/self-get.txt"; then
    p_ok "$SYNC can open kadmin"
else
    p_bad "$SYNC could not open kadmin (see self-get.txt)"
fi
refused purgekeys-self "purgekeys $SYNC" \
    "Cannot change protected principal" "purge_keys" PROTECT_PRINCIPAL "$SYNC@$REALM" "$SYNC"
refused purgekeys-all-self "purgekeys -all $SYNC" \
    "Cannot change protected principal" "purge_keys" PROTECT_PRINCIPAL "$SYNC@$REALM" "$SYNC"

KV="$(kvno_of "$SYNC")"
MARK="$(log_mark)" || MARK=""
kadmin_user "$SYNC" "$CUR" "cpw -pw $SELF $SYNC" >"$D/self-cpw.txt" 2>&1 || true
if ! grep -q " while " "$D/self-cpw.txt"; then
    p_ok "self-service cpw produced no error text"
else
    p_bad "self-service cpw failed (see self-cpw.txt)"
fi
now="$(kvno_of "$SYNC")"
if [ -n "$KV" ] && [ "$now" = "$((KV + 1))" ] \
    && bind_ok "$SYNC" "$SELF" && ! bind_ok "$SYNC" "$CUR" \
    && kinit_pw "$SYNC@$REALM" "$SELF" >"$D/kinit-self.log" 2>&1; then
    p_ok "self-service cpw: bind and kinit take the new password and the key version increased by one"
else
    p_bad "self-service cpw: the doors did not follow (kvno '${now:-empty}')"
fi
SELF_DETAIL="kadmin change_password by $SYNC@$REALM (self-service)"
if [ -n "$MARK" ] && log_one PASSWORD_CHANGE "$SYNC@$REALM" "$SELF_DETAIL" true self-cpw "$MARK" "$SYNC@$REALM"; then
    p_ok "self-service cpw: exactly one password_change names the user, protocol KADMIN, actor $SYNC@$REALM"
else
    p_bad "self-service cpw: password_change '$SELF_DETAIL' with protocol KADMIN and actor $SYNC@$REALM is not exactly one"
fi
CUR="$SELF"

ctl_kv="$(kvno_of "$CTL")"
if kadmin_q "cpw -pw K1svcNewPass2026! $CTL" >"$D/ctl-cpw.txt" 2>&1 \
    && ! grep -q " while " "$D/ctl-cpw.txt" \
    && kinit_pw "$CTL@$REALM" "K1svcNewPass2026!" >"$D/kinit-ctl.log" 2>&1 \
    && [ "$(kvno_of "$CTL")" = "$((ctl_kv + 1))" ]; then
    p_ok "control cpw on $CTL is carried out"
else
    p_bad "control cpw on $CTL failed (see ctl-cpw.txt, kinit-ctl.log)"
fi
if kadmin_q "delprinc -force $CTL" >"$D/ctl-del.txt" 2>&1 \
    && ! grep -q " while " "$D/ctl-del.txt"; then
    no_principal "$CTL" control-del
else
    p_bad "control delprinc failed (see ctl-del.txt)"
fi

flood_ok=""
while [ -n "$FLOOD_MARK" ]; do
    if flood_check end "$FLOOD_MARK"; then
        flood_ok=1
        break
    fi
    [ "$(date +%s)" -ge $((FLOOD_END + 45)) ] && break
    sleep 1
done
if [ -n "$flood_ok" ]; then
    p_ok "flood: one 'access-denied flood resolved: 2 denials, 1 actors' for $FLOOD@$REALM, and no admin refusal coalesced"
else
    p_bad "flood: $(cat "$D/flood-end.out" 2>/dev/null || echo 'no rows read (see mark.err, flood-end.err)')"
fi

# The server's KRB5_CONFIG names OTHER.TEST; the clients keep the client_config, /data/krb5.conf.
OTHER_CONF=/data/other-krb5.conf
OTHER_NEW=K1otherPass2026!
D2_ARGS=(${GATE_EXTRA_RUN_ARGS[@]+"${GATE_EXTRA_RUN_ARGS[@]}"})
# shellcheck disable=SC2034
d2_swap() {
    local label="$1"
    shift
    local -a GATE_EXTRA_RUN_ARGS=(${D2_ARGS[@]+"${D2_ARGS[@]}"} "$@")
    t docker stop "$CONTAINER" >/dev/null 2>&1
    docker logs "$CONTAINER" >"$D/d2-$label.log" 2>&1
    docker rm -v "$CONTAINER" >/dev/null 2>&1 || return 1
    start_main_container && wait_healthy 120 && discover_ports && TOKEN="$(gate_login)"
}
d2_exec() { t docker exec -e KRB5_CONFIG=/data/krb5.conf "$CONTAINER" "$@"; }
d2_kadmin() { d2_exec kadmin -k -t /data/kadm5.keytab -p "$ADMIN" -q "$1"; }
d2_kvno() { d2_kadmin "getprinc $SYNC" 2>/dev/null | awk '/Key: vno/ {print $3; exit}' | tr -d ','; }
d2_kinit() {
    # shellcheck disable=SC2016
    d2_exec sh -c 'printf "%s\n" "$1" | KRB5CCNAME=/tmp/gate_d2_$$ kinit "$0"' "$SYNC@$REALM" "$1"
}

if gexec sh -c 'printf "[libdefaults]\n default_realm = OTHER.TEST\n" >"$0"' "$OTHER_CONF" \
    && d2_swap before-other -e "KRB5_CONFIG=$OTHER_CONF"; then
    p_ok "d2: the server restarted with KRB5_CONFIG=$OTHER_CONF"
else
    p_bad "d2: the server did not restart with KRB5_CONFIG=$OTHER_CONF"
fi
if [ "$(gexec printenv KRB5_CONFIG 2>/dev/null)" = "$OTHER_CONF" ] \
    && file_contains "$OTHER_CONF" "default_realm = OTHER.TEST" \
    && file_contains /data/krb5.conf "default_realm = $REALM"; then
    p_ok "d2: KRB5_CONFIG names OTHER.TEST; the client_config written at boot names $REALM"
else
    p_bad "d2: KRB5_CONFIG and the client_config are not the two realms this case needs"
fi

KV="$(d2_kvno)"
MARK="$(log_mark)" || MARK=""
if d2_kadmin "cpw -pw $OTHER_NEW $SYNC" >"$D/d2-cpw.txt" 2>&1 && ! grep -q " while " "$D/d2-cpw.txt"; then
    p_ok "d2: cpw of $SYNC produced no error text"
else
    p_bad "d2: cpw of $SYNC failed (see d2-cpw.txt)"
fi
now="$(d2_kvno)"
if [ -n "$KV" ] && [ "$now" = "$((KV + 1))" ] \
    && bind_ok "$SYNC" "$OTHER_NEW" && ! bind_ok "$SYNC" "$CUR" \
    && d2_kinit "$OTHER_NEW" >"$D/d2-kinit-new.log" 2>&1 \
    && ! d2_kinit "$CUR" >"$D/d2-kinit-old.log" 2>&1; then
    p_ok "d2: bind and kinit in $REALM take the new password and the key version increased by one"
else
    p_bad "d2: the doors did not follow the new password (kvno '${now:-empty}')"
fi
if [ -n "$MARK" ] && log_one PASSWORD_CHANGE "$SYNC@$REALM" "$CPW_DETAIL" true d2-cpw "$MARK" "$ADMIN"; then
    p_ok "d2: exactly one password_change names $SYNC@$REALM, protocol KADMIN, actor $ADMIN"
else
    p_bad "d2: password_change '$CPW_DETAIL' on $SYNC@$REALM is not exactly one"
fi
CUR="$OTHER_NEW"
KV="$now"

MARK="$(log_mark)" || MARK=""
d2_kadmin "cpw -keepold -pw K1otherKeepPass2026! $SYNC" >"$D/d2-keepold.txt" 2>&1 || true
if grep -qF "Cannot change protected principal" "$D/d2-keepold.txt"; then
    p_ok "d2-keepold: Cannot change protected principal"
else
    p_bad "d2-keepold: expected 'Cannot change protected principal' (see d2-keepold.txt)"
fi
detail="kadmin change_password on $SYNC@$REALM by $ADMIN: PROTECT_PRINCIPAL"
if [ -n "$MARK" ] && log_one ACCESS_DENIED "$SYNC@$REALM" "$detail" false d2-keepold "$MARK" "$ADMIN"; then
    p_ok "d2-keepold: one access_denied names $SYNC@$REALM and PROTECT_PRINCIPAL"
else
    p_bad "d2-keepold: access_denied '$detail' is not exactly one (see d2-keepold-log.json)"
fi
if [ -n "$KV" ] && [ "$(d2_kvno)" = "$KV" ] && bind_ok "$SYNC" "$CUR" \
    && d2_kinit "$CUR" >"$D/d2-kinit-kept.log" 2>&1; then
    p_ok "d2-keepold: the key version, the bind and kinit are unchanged"
else
    p_bad "d2-keepold: the record moved (see d2-kinit-kept.log)"
fi

if d2_swap with-other && gexec rm -f "$OTHER_CONF" \
    && [ "$(gexec printenv KRB5_CONFIG 2>/dev/null)" = /data/krb5.conf ]; then
    p_ok "d2: the server is back on the image's KRB5_CONFIG"
else
    p_bad "d2: the server did not come back on the image's KRB5_CONFIG"
fi

# shellcheck disable=SC2016
for user in "$SYNC" "$NOSYNC" "$LATE" "$FLOOD"; do
    if graphql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' \
        '{"u": "'"$user"'"}' >"$D/delete-$user.json" 2>"$D/delete-$user.err"; then
        gone=""
        for _ in $(seq 1 20); do
            if kadmin_q "getprinc $user" >"$D/gone-$user.txt" 2>&1 \
                && grep -q 'Principal does not exist' "$D/gone-$user.txt"; then
                gone=1
                break
            fi
            sleep 0.5
        done
        if [ -n "$gone" ] && ! graphql "{ user(userId: \"$user\") { id } }" '{}' \
            >"$D/still-$user.json" 2>"$D/still-$user.err"; then
            p_ok "cleanup removed $user"
        else
            p_bad "cleanup left $user (see gone-$user.txt)"
        fi
    else
        p_bad "deleteUser $user failed"
    fi
done
if kadmin_q "delprinc -force $SVC" >"$D/del-svc.txt" 2>&1 && ! grep -q " while " "$D/del-svc.txt"; then
    no_principal "$SVC" cleanup-svc
else
    p_bad "cleanup delprinc $SVC failed"
fi
if kadmin_q "delpol -force k1pol" >"$D/delpol.txt" 2>&1 && ! grep -q " while " "$D/delpol.txt" \
    && kadmin_q "getpol k1pol" >"$D/getpol.txt" 2>&1 \
    && grep -q 'Policy does not exist' "$D/getpol.txt"; then
    p_ok "cleanup removed policy k1pol"
else
    p_bad "cleanup left policy k1pol (see delpol.txt, getpol.txt)"
fi
