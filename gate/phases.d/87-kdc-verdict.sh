# shellcheck shell=bash
# Phase: KDC verdict and notice. Every wrong answer is FAIL.
# This phase's server is SQLite, not the main container's database.
# The corrections against rows.md are logs/PROPER/K1/note-phases-6.md and PH/note-phases-7.md.
# This phase's server is GATE_KILL_IMAGE. The release image is GATE_IMAGE.

D="$(phase_dir)"
KDC_C="$CONTAINER-kdcv"
KDC_VOL="klldap-gate-kdcv-$RUNID"
KDC_KVOL="klldap-gate-kdcv-kdc-$RUNID"
EXTRA_CONTAINERS+=("$KDC_C")
EXTRA_VOLUMES+=("$KDC_VOL" "$KDC_KVOL")
ADMIN="admin/admin@$REALM"
AS=k1as
HOLD=k1hold
GONE=k1gone
SVC=k1svc/k1
PASS=K1asPass2026!
old_http="$HTTP_PORT"
old_ldap="$LDAP_PORT"
old_token="$TOKEN"

restore_gate() {
    HTTP_PORT="$old_http"
    LDAP_PORT="$old_ldap"
    TOKEN="$old_token"
}
kdc_stop() {
    docker logs -t "$KDC_C" >"$D/docker.log" 2>&1 || true
    docker rm -fv "$KDC_C" >/dev/null 2>&1 || true
    docker volume rm "$KDC_VOL" "$KDC_KVOL" >/dev/null 2>&1 || true
    restore_gate
}
kdc_kinit() {
    # shellcheck disable=SC2016
    gexec_in "$KDC_C" sh -c 'printf "%s\n" "$1" | KRB5CCNAME="$2" kinit "$0"' \
        "$1" "$2" "$3"
}
kdc_kinit_renew() {
    # shellcheck disable=SC2016
    gexec_in "$KDC_C" sh -c 'printf "%s\n" "$1" | KRB5CCNAME="$2" kinit -r 1h "$0"' \
        "$1" "$2" "$3"
}
kdc_kinit_fast() {
    # shellcheck disable=SC2016
    gexec_in "$KDC_C" sh -c 'printf "%s\n" "$1" | KRB5CCNAME="$2" kinit -T /tmp/k1armor "$0"' \
        "$1" "$2" "$3"
}
notice_lines() {
    local n
    if ! n="$(gexec_in "$KDC_C" wc -l /data/k1-notices | awk '{print $1}')"; then
        return 1
    fi
    if [ -z "$n" ]; then
        return 1
    fi
    printf '%s\n' "$n"
}
copy_notices() {
    docker cp "$KDC_C:/data/k1-notices" "$D/notices.jsonl" >/dev/null
}
wait_one() {
    local before="$1" after="" _
    for _ in $(seq 1 20); do
        after="$(notice_lines)" || return 1
        if [ "$after" = "$((before + 1))" ]; then
            printf '%s\n' "$after"
            return 0
        fi
        sleep 0.5
    done
    printf '%s\n' "${after:-}"
    return 1
}
expect_one() {
    local tag="$1" reason="$2" mech="$3" code="$4" before="$5" client="$6"
    if ! wait_one "$before" >/dev/null; then
        p_bad "$tag: notice count did not rise by one from ${before:-empty} (see notices.jsonl)"
        return
    fi
    copy_notices || { p_bad "$tag: could not read the notice file"; return; }
    if REASON="$reason" MECH="$mech" CODE="$code" CLIENT="$client" \
        python3 - "$D/notices.jsonl" >"$D/$tag-notice.out" 2>"$D/$tag-notice.err" <<'PY'
import json, os, sys
lines = [ln for ln in open(sys.argv[1], encoding="utf-8") if ln.strip()]
row = json.loads(lines[-1])
mech = row.get("mechanism")
want = os.environ["MECH"]
mech_ok = mech is None if want == "null" else mech == want
peer = row.get("peer")
ok = (
    os.environ["CLIENT"] in str(row.get("client"))
    and row.get("reason") == os.environ["REASON"]
    and mech_ok
    and row.get("code") == int(os.environ["CODE"])
    and peer is not None
    and "127.0.0.1" in str(peer)
    and isinstance(row.get("time_ms"), int)
    and not isinstance(row.get("time_ms"), bool)
)
if not ok:
    print(json.dumps(row), file=sys.stderr)
sys.exit(0 if ok else 1)
PY
    then
        p_ok "$tag: notice is $reason / $mech / $code from 127.0.0.1"
    else
        p_bad "$tag: notice fields differ: $(tr '\n' ' ' <"$D/$tag-notice.err")"
    fi
}
no_prompt() {
    local tag="$1" file="$2"
    if grep -q 'Password for' "$file"; then
        p_bad "$tag: kinit asked for a password (see ${file##*/})"
    else
        p_ok "$tag: kinit did not ask for a password"
    fi
}

if [ -z "${GATE_KILL_IMAGE:-}" ]; then
    p_bad "GATE_KILL_IMAGE is unset; phase 87's server is the test image"
    restore_gate
    return 0
fi
if ! docker volume create "$KDC_VOL" >/dev/null || ! docker volume create "$KDC_KVOL" >/dev/null; then
    p_bad "could not create the verdict volumes"
    kdc_stop
    return 0
fi
if ! docker run --rm --entrypoint sh -v "$KDC_VOL:/data" "$GATE_KILL_IMAGE" -c \
    'touch /data/k1-refuse /data/k1-notices && chown 1000:1000 /data/k1-refuse /data/k1-notices' \
    >"$D/touch.log" 2>&1; then
    p_bad "could not create the admission files (see touch.log)"
    kdc_stop
    return 0
fi
if ! docker run -d --name "$KDC_C" --network "$NET" \
    -p "127.0.0.1::17170" -p "127.0.0.1::3890" \
    -v "$KDC_VOL:/data" -v "$KDC_KVOL:/var/kerberos/krb5kdc" \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_KEY_SEED="$KEY_SEED" \
    -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
    -e LLDAP_DATABASE_URL="sqlite:////data/users.db?mode=rwc" \
    -e LLDAP_VERBOSE=true -e LLDAP_ENABLE_MFA=true \
    -e LLDAP_TEST_ADMISSION_REFUSE=/data/k1-refuse \
    -e LLDAP_TEST_ADMISSION_NOTICES=/data/k1-notices \
    "$GATE_KILL_IMAGE" >"$D/run.id" 2>&1; then
    p_bad "could not start the verdict container (see run.id)"
    kdc_stop
    return 0
fi

healthy=""
for _ in $(seq 1 90); do
    if docker exec "$KDC_C" /app/lldap healthcheck --config-file /data/lldap_config.toml \
        >/dev/null 2>&1; then
        healthy=1
        break
    fi
    [ -z "$(docker ps -q -f "name=^${KDC_C}$")" ] && break
    sleep 1
done
docker logs -t "$KDC_C" >"$D/docker.log" 2>&1 || true
if [ -z "$healthy" ]; then
    p_bad "verdict container did not become healthy (see docker.log)"
    kdc_stop
    return 0
fi

HTTP_PORT="$(docker port "$KDC_C" 17170/tcp | head -1 | sed 's/.*://')"
LDAP_PORT="$(docker port "$KDC_C" 3890/tcp | head -1 | sed 's/.*://')"
TOKEN="$(gate_login)" || TOKEN=""
if [ -z "$TOKEN" ]; then
    p_bad "admin login on the verdict container failed"
    kdc_stop
    return 0
fi

copy_notices || true
if python3 - "$D/notices.jsonl" "$D/docker.log" "$REALM" >"$D/boot.out" 2>"$D/boot.err" <<'PY'
import json, sys
from datetime import datetime
notices, log_path, realm = sys.argv[1], sys.argv[2], sys.argv[3]
needle = f"Kerberos realm {realm} serving"
raw_lines = [ln for ln in open(notices, encoding="utf-8") if ln.strip()]
if not raw_lines:
    sys.exit("notice file is empty")
first_raw = raw_lines[0]
first = json.loads(first_raw)
if "installed" not in first or "reason" in first:
    sys.exit("first notice is not the install line: " + first_raw.strip())
if "installed_ms" not in first or isinstance(first["installed_ms"], bool) or not isinstance(first["installed_ms"], int):
    sys.exit("install line has no installed_ms: " + first_raw.strip())
installed_ms = first["installed_ms"]
serving = None
for raw in open(log_path, encoding="utf-8", errors="replace"):
    if needle in raw:
        serving = raw
        break
if serving is None:
    sys.exit("no " + needle + " line in the container log")
stamp = serving.split(" ", 1)[0]
when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
heard_ms = int(when.timestamp() * 1000)
if installed_ms > heard_ms:
    sys.exit(f"installed_ms {installed_ms} is after {serving.strip()}")
PY
then
    p_ok "installed_ms is not after the serving line; that line is only an upper bound, and IC's unit row is the proof"
else
    p_bad "boot order failed: $(tr '\n' ' ' <"$D/boot.err")"
fi

for user in "$AS" "$HOLD" "$GONE"; do
    # shellcheck disable=SC2016
    graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$user"'", "email": "'"$user"'@gate.test",
                "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
        >"$D/create-$user.json" 2>&1 || p_bad "createUser $user failed"
    # shellcheck disable=SC2016
    graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
        '{"id": "'"$user"'", "pw": "'"$PASS"'"}' >"$D/setpw-$user.json" 2>&1 \
        || p_bad "setUserPassword $user failed"
done
ready=""
for _ in $(seq 1 15); do
    if gexec_in "$KDC_C" kadmin -k -t /data/kadm5.keytab -p "$ADMIN" -q "getprinc $AS" \
        >"$D/get-as.txt" 2>/dev/null \
        && grep -q "^Principal: $AS@$REALM" "$D/get-as.txt"; then
        ready=1
        break
    fi
    sleep 1
done
if [ -n "$ready" ]; then
    p_ok "$AS has a principal"
else
    p_bad "$AS has no principal (see get-as.txt)"
fi
if gexec_in "$KDC_C" kadmin -k -t /data/kadm5.keytab -p "$ADMIN" -q "addprinc -randkey $SVC" \
    >"$D/add-svc.txt" 2>&1 && ! grep -q " while " "$D/add-svc.txt"; then
    p_ok "service principal $SVC exists"
else
    p_bad "could not create $SVC (see add-svc.txt)"
fi

before="$(notice_lines)" || before=""
if kdc_kinit "$AS@$REALM" "wrong-password" /tmp/k1wrong >"$D/kinit-wrong.log" 2>&1; then
    p_bad "wrong password kinit succeeded"
else
    p_ok "wrong password kinit failed"
fi
expect_one wrong PreauthFailed EncTimestamp 24 "$before" "$AS"

before="$(notice_lines)" || before=""
if kdc_kinit "$AS@$REALM" "$PASS" /tmp/k1right >"$D/kinit-right.log" 2>&1; then
    p_ok "plain kinit issued a ticket"
else
    p_bad "plain kinit failed (see kinit-right.log)"
fi
expect_one right Issued EncTimestamp 0 "$before" "$AS"

before="$(notice_lines)" || { p_bad "could not read the notice file before the unknown client"; before=""; }
if kdc_kinit "nosuch@$REALM" "not-a-password" /tmp/k1none >"$D/kinit-unknown.log" 2>&1; then
    p_bad "kinit of an unknown client succeeded"
elif grep -q 'not found in Kerberos database' "$D/kinit-unknown.log"; then
    p_ok "kinit of an unknown client finds no principal"
else
    p_bad "unknown client failed without 'not found in Kerberos database' (see kinit-unknown.log)"
fi
after="$(notice_lines)" || after=""
if [ -n "$before" ] && [ "$after" = "$before" ]; then
    p_ok "an unknown client leaves no notice"
else
    p_bad "unknown client changed the notice count ${before:-empty} -> ${after:-empty}"
fi
before="${after:-}"
if kdc_kinit "$AS@$REALM" "$PASS" /tmp/k1fence >"$D/kinit-fence.log" 2>&1; then
    p_ok "the fence kinit issued a ticket"
else
    p_bad "the fence kinit failed (see kinit-fence.log)"
fi
expect_one fence Issued EncTimestamp 0 "$before" "$AS"

if gexec_in "$KDC_C" kinit -k -t /data/kadm5.keytab -c /tmp/k1armor "admin/admin@$REALM" \
    >"$D/armor.log" 2>&1; then
    p_ok "armor ticket from the admin keytab"
else
    p_bad "armor kinit failed (see armor.log)"
fi
before="$(notice_lines)" || before=""
if kdc_kinit_fast "$AS@$REALM" "$PASS" /tmp/k1fast >"$D/kinit-fast.log" 2>&1; then
    p_ok "armored kinit issued a ticket"
else
    p_bad "armored kinit failed (see kinit-fast.log)"
fi
expect_one fast Issued EncChallenge 0 "$before" "$AS"
before="$(notice_lines)" || before=""
if kdc_kinit_fast "$AS@$REALM" "wrong-password" /tmp/k1fastwrong >"$D/kinit-fast-wrong.log" 2>&1; then
    p_bad "armored kinit with a wrong password succeeded"
else
    p_ok "armored kinit with a wrong password failed"
fi
expect_one fast-wrong PreauthFailed EncChallenge 24 "$before" "$AS"

# shellcheck disable=SC2016
gexec_in "$KDC_C" sh -c 'printf "%s\n" "$0" >> /data/k1-refuse' "$AS@$REALM" \
    >"$D/refuse-as.log" 2>&1 || p_bad "could not list $AS for refusal"
before="$(notice_lines)" || before=""
if kdc_kinit "$AS@$REALM" "$PASS" /tmp/k1host >"$D/kinit-host.log" 2>&1; then
    p_bad "kinit succeeded for a refused user"
elif grep -qi 'revoked' "$D/kinit-host.log"; then
    p_ok "kinit for a refused user says revoked"
else
    p_bad "refused kinit did not say revoked (see kinit-host.log)"
fi
no_prompt host "$D/kinit-host.log"
expect_one host HostRefused null 18 "$before" "$AS"
before="$(notice_lines)" || before=""
if kdc_kinit "$AS@$REALM" "wrong-password" /tmp/k1hostwrong >"$D/kinit-host-wrong.log" 2>&1; then
    p_bad "a wrong password was accepted for a refused user"
elif grep -qi 'revoked' "$D/kinit-host-wrong.log"; then
    p_ok "a wrong password for a refused user says revoked"
else
    p_bad "refused wrong-password kinit did not say revoked (see kinit-host-wrong.log)"
fi
no_prompt host-wrong "$D/kinit-host-wrong.log"
expect_one host-wrong HostRefused null 18 "$before" "$AS"
before="$(notice_lines)" || before=""
if kdc_kinit_fast "$AS@$REALM" "$PASS" /tmp/k1hostfast >"$D/kinit-host-fast.log" 2>&1; then
    p_bad "armored kinit succeeded for a refused user"
elif grep -qi 'revoked' "$D/kinit-host-fast.log"; then
    p_ok "armored kinit for a refused user says revoked"
else
    p_bad "refused armored kinit did not say revoked (see kinit-host-fast.log)"
fi
no_prompt host-fast "$D/kinit-host-fast.log"
expect_one host-fast HostRefused null 18 "$before" "$AS"

if kdc_kinit_renew "$HOLD@$REALM" "$PASS" /tmp/k1hold >"$D/kinit-hold.log" 2>&1; then
    p_ok "$HOLD has a renewable ticket"
else
    p_bad "$HOLD kinit failed (see kinit-hold.log)"
fi
if gexec_in "$KDC_C" sh -c 'KRB5CCNAME=/tmp/k1hold kinit -R' >"$D/renew-hold-ok.log" 2>&1; then
    p_ok "$HOLD renewal works before the refusal"
else
    p_bad "$HOLD renewal failed before the refusal (see renew-hold-ok.log)"
fi
# shellcheck disable=SC2016
if gexec_in "$KDC_C" sh -c 'KRB5CCNAME=/tmp/k1hold kvno --no-store "$0"' "$SVC@$REALM" \
    >"$D/kvno-hold-ok.log" 2>&1; then
    p_ok "$HOLD got a service ticket before the refusal"
else
    p_bad "$HOLD service ticket failed before the refusal (see kvno-hold-ok.log)"
fi
# shellcheck disable=SC2016
gexec_in "$KDC_C" sh -c 'printf "%s\n" "$0" >> /data/k1-refuse' "$HOLD@$REALM" \
    >"$D/refuse-hold.log" 2>&1 || p_bad "could not list $HOLD for refusal"
if gexec_in "$KDC_C" sh -c 'KRB5CCNAME=/tmp/k1hold kinit -R' >"$D/renew-hold.log" 2>&1; then
    p_bad "$HOLD renewal succeeded after the refusal"
elif grep -qi 'revoked' "$D/renew-hold.log"; then
    p_ok "$HOLD renewal says revoked"
else
    p_bad "$HOLD renewal did not say revoked (see renew-hold.log)"
fi
# shellcheck disable=SC2016
if gexec_in "$KDC_C" sh -c 'KRB5CCNAME=/tmp/k1hold kvno --no-store "$0"' "$SVC@$REALM" \
    >"$D/kvno-hold.log" 2>&1; then
    p_bad "$HOLD got a service ticket after the refusal"
elif grep -qi 'revoked' "$D/kvno-hold.log"; then
    p_ok "$HOLD was refused a service ticket"
else
    p_bad "$HOLD service ticket did not say revoked (see kvno-hold.log)"
fi

if kdc_kinit_renew "$GONE@$REALM" "$PASS" /tmp/k1gone >"$D/kinit-gone.log" 2>&1; then
    p_ok "$GONE has a renewable ticket"
else
    p_bad "$GONE kinit failed (see kinit-gone.log)"
fi
if gexec_in "$KDC_C" sh -c 'KRB5CCNAME=/tmp/k1gone kinit -R' >"$D/renew-gone-ok.log" 2>&1; then
    p_ok "$GONE renewal works before deletion"
else
    p_bad "$GONE renewal failed before deletion (see renew-gone-ok.log)"
fi
# shellcheck disable=SC2016
if gexec_in "$KDC_C" sh -c 'KRB5CCNAME=/tmp/k1gone kvno --no-store "$0"' "$SVC@$REALM" \
    >"$D/kvno-gone-ok.log" 2>&1; then
    p_ok "$GONE got a service ticket before deletion"
else
    p_bad "$GONE service ticket failed before deletion (see kvno-gone-ok.log)"
fi
# shellcheck disable=SC2016
graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
    '{"id": "'"$GONE"'"}' >"$D/delete-gone.json" 2>&1 || p_bad "deleteUser $GONE failed"
gone_principal=""
for _ in $(seq 1 20); do
    if gexec_in "$KDC_C" kadmin -k -t /data/kadm5.keytab -p "$ADMIN" -q "getprinc $GONE" \
        >"$D/gone-princ.txt" 2>&1 \
        && grep -q 'Principal does not exist' "$D/gone-princ.txt"; then
        gone_principal=1
        break
    fi
    sleep 0.5
done
if [ -n "$gone_principal" ]; then
    p_ok "$GONE's principal is gone"
else
    p_bad "$GONE's principal is still there (see gone-princ.txt)"
fi
if gexec_in "$KDC_C" sh -c 'KRB5CCNAME=/tmp/k1gone kinit -R' >"$D/renew-gone.log" 2>&1; then
    p_bad "$GONE renewal succeeded after deletion"
elif grep -qi 'revoked' "$D/renew-gone.log"; then
    p_ok "$GONE renewal says revoked after deletion"
else
    p_bad "$GONE renewal did not say revoked (see renew-gone.log)"
fi
# shellcheck disable=SC2016
if gexec_in "$KDC_C" sh -c 'KRB5CCNAME=/tmp/k1gone kvno --no-store "$0"' "$SVC@$REALM" \
    >"$D/kvno-gone.log" 2>&1; then
    p_bad "$GONE got a service ticket after deletion"
elif grep -qi 'revoked' "$D/kvno-gone.log"; then
    p_ok "$GONE was refused a service ticket after deletion"
else
    p_bad "$GONE service ticket did not say revoked (see kvno-gone.log)"
fi

kdc_stop
if docker volume inspect "$KDC_VOL" >/dev/null 2>&1 || docker volume inspect "$KDC_KVOL" >/dev/null 2>&1; then
    p_bad "the verdict volumes are still present"
else
    p_ok "the verdict volumes are gone"
fi

REL_C="$CONTAINER-kdcrel"
REL_VOL="klldap-gate-kdcrel-$RUNID"
REL_KVOL="klldap-gate-kdcrel-kdc-$RUNID"
EXTRA_CONTAINERS+=("$REL_C")
EXTRA_VOLUMES+=("$REL_VOL" "$REL_KVOL")
rel_stop() {
    docker rm -fv "$REL_C" >/dev/null 2>&1 || true
    docker volume rm "$REL_VOL" "$REL_KVOL" >/dev/null 2>&1 || true
    restore_gate
}
if ! docker volume create "$REL_VOL" >/dev/null || ! docker volume create "$REL_KVOL" >/dev/null; then
    p_bad "could not create the release-image volumes"
    rel_stop
    return 0
fi
if ! docker run -d --name "$REL_C" --network "$NET" \
    -p "127.0.0.1::17170" -p "127.0.0.1::3890" \
    -v "$REL_VOL:/data" -v "$REL_KVOL:/var/kerberos/krb5kdc" \
    -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_KEY_SEED="$KEY_SEED" \
    -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
    -e LLDAP_DATABASE_URL="sqlite:////data/users.db?mode=rwc" \
    -e LLDAP_VERBOSE=true \
    -e LLDAP_TEST_ADMISSION_REFUSE=/data/k1-refuse \
    -e LLDAP_TEST_ADMISSION_NOTICES=/data/k1-notices \
    "$GATE_IMAGE" >"$D/rel.id" 2>&1; then
    p_bad "could not start the release image (see rel.id)"
    rel_stop
    return 0
fi
rel_healthy=""
for _ in $(seq 1 90); do
    if docker exec "$REL_C" /app/lldap healthcheck --config-file /data/lldap_config.toml \
        >/dev/null 2>&1; then
        rel_healthy=1
        break
    fi
    [ -z "$(docker ps -q -f "name=^${REL_C}$")" ] && break
    sleep 1
done
if [ -z "$rel_healthy" ]; then
    p_bad "release image did not become healthy"
    rel_stop
    return 0
fi
HTTP_PORT="$(docker port "$REL_C" 17170/tcp | head -1 | sed 's/.*://')"
LDAP_PORT="$(docker port "$REL_C" 3890/tcp | head -1 | sed 's/.*://')"
rel_kinit=""
for _ in $(seq 1 10); do
    if gexec_in "$REL_C" kinit -k -t /data/kadm5.keytab -c /tmp/k1rel "$ADMIN" \
        >"$D/rel-kinit.log" 2>&1; then
        rel_kinit=1
        break
    fi
    sleep 1
done
if [ -z "$rel_kinit" ]; then
    p_bad "release image: kinit -k -t /data/kadm5.keytab of $ADMIN failed (see rel-kinit.log)"
elif ! gexec_in "$REL_C" sh -c 'test ! -e /data/k1-notices'; then
    p_bad "release image: the admin keytab kinit works, but /data/k1-notices was written"
else
    p_ok "release image: the admin keytab kinit works and no notice file is written"
fi
rel_stop
