# shellcheck shell=bash
# Phase: the headline Kerberos lifecycle — kerberossync user gets a real principal,
# real kinit works, lldap_disabled reflects to DISALLOW_ALL_TIX (and back, and is
# reasserted for password changes while disabled), deletion removes the principal.

D="$(phase_dir)"
SYNC_USER="gatesync"
NOSYNC_USER="gatenosync"
SYNC_PASS="GateSyncPass2026!"

principal_exists() {
    kadmin_q "getprinc $1" >"$D/getprinc.txt" 2>/dev/null && grep -q "^Principal: $1@$REALM" "$D/getprinc.txt"
}
principal_attrs() { kadmin_q "getprinc $1" 2>/dev/null | grep "^Attributes:"; }

graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$SYNC_USER"'", "email": "'"$SYNC_USER"'@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create-sync.json" 2>&1 || p_bad "createUser $SYNC_USER failed"
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$NOSYNC_USER"'", "email": "'"$NOSYNC_USER"'@gate.test"}}' \
    >"$D/create-nosync.json" 2>&1 || p_bad "createUser $NOSYNC_USER failed"

graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$SYNC_USER"'", "pw": "'"$SYNC_PASS"'"}' >"$D/setpw-sync.json" 2>&1 \
    || p_bad "setUserPassword $SYNC_USER failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$NOSYNC_USER"'", "pw": "'"$SYNC_PASS"'"}' >"$D/setpw-nosync.json" 2>&1 \
    || p_bad "setUserPassword $NOSYNC_USER failed"

created=""
for _ in $(seq 1 10); do
    if principal_exists "$SYNC_USER"; then created=1; break; fi
    sleep 1
done
if [ -n "$created" ]; then
    p_ok "kerberossync user got a principal"
else
    p_bad "no principal for $SYNC_USER after setUserPassword"
fi
if principal_exists "$NOSYNC_USER"; then
    p_bad "non-sync user unexpectedly has a principal"
else
    p_ok "non-sync user has no principal"
fi

if kinit_pw "$SYNC_USER@$REALM" "$SYNC_PASS" >"$D/kinit-1.log" 2>&1; then
    p_ok "real kinit with the set password succeeds"
else
    p_bad "kinit with the set password failed"
fi

disabled_gid="$(graphql '{ groups { id displayName } }' '{}' | GROUP=lldap_disabled python3 -c '
import json, os, sys
groups = json.load(sys.stdin)["groups"]
match = [g["id"] for g in groups if g["displayName"] == os.environ["GROUP"]]
print(match[0] if match else "")')"
if [ -n "$disabled_gid" ]; then
    p_ok "found lldap_disabled group (id $disabled_gid)"
else
    p_bad "lldap_disabled group not found"
fi

graphql 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
    '{"u": "'"$SYNC_USER"'", "g": '"${disabled_gid:-0}"'}' >"$D/disable.json" 2>&1 \
    || p_bad "addUserToGroup lldap_disabled failed"

if principal_attrs "$SYNC_USER" >"$D/attrs.txt" && grep -q DISALLOW_ALL_TIX "$D/attrs.txt"; then
    p_ok "disabled membership reflects to DISALLOW_ALL_TIX"
else
    p_bad "principal not marked DISALLOW_ALL_TIX after disable"
fi
if kinit_pw "$SYNC_USER@$REALM" "$SYNC_PASS" >"$D/kinit-disabled.log" 2>&1; then
    p_bad "kinit still succeeds while disabled"
else
    p_ok "kinit refused while disabled"
fi

graphql 'mutation($u: String!, $g: Int!) { removeUserFromGroup(userId: $u, groupId: $g) { ok } }' \
    '{"u": "'"$SYNC_USER"'", "g": '"${disabled_gid:-0}"'}' >"$D/enable.json" 2>&1 \
    || p_bad "removeUserFromGroup lldap_disabled failed"
if principal_attrs "$SYNC_USER" >"$D/attrs.txt" && grep -q DISALLOW_ALL_TIX "$D/attrs.txt"; then
    p_bad "DISALLOW_ALL_TIX not cleared after re-enable"
else
    p_ok "re-enable clears DISALLOW_ALL_TIX"
fi
if kinit_pw "$SYNC_USER@$REALM" "$SYNC_PASS" >"$D/kinit-2.log" 2>&1; then
    p_ok "kinit works again after re-enable"
else
    p_bad "kinit failed after re-enable"
fi

# Password change while disabled must not un-disable the principal (born-disabled
# reassert path in the mutation layer).
graphql 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
    '{"u": "'"$SYNC_USER"'", "g": '"${disabled_gid:-0}"'}' >"$D/disable-2.json" 2>&1 \
    || p_bad "second addUserToGroup lldap_disabled failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$SYNC_USER"'", "pw": "'"$SYNC_PASS"'x"}' >"$D/setpw-disabled.json" 2>&1 \
    || p_bad "setUserPassword while disabled failed"
if principal_attrs "$SYNC_USER" >"$D/attrs.txt" && grep -q DISALLOW_ALL_TIX "$D/attrs.txt"; then
    p_ok "password change while disabled keeps DISALLOW_ALL_TIX"
else
    p_bad "password change while disabled dropped DISALLOW_ALL_TIX"
fi

graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
    '{"id": "'"$SYNC_USER"'"}' >"$D/delete-sync.json" 2>&1 || p_bad "deleteUser $SYNC_USER failed"
gone=""
for _ in $(seq 1 10); do
    if ! principal_exists "$SYNC_USER"; then gone=1; break; fi
    sleep 1
done
if [ -n "$gone" ]; then
    p_ok "deleting the user removes the principal"
else
    p_bad "principal survived user deletion"
fi
graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
    '{"id": "'"$NOSYNC_USER"'"}' >"$D/delete-nosync.json" 2>&1 || p_bad "deleteUser $NOSYNC_USER failed"

# The browser's password envelope, sealed by OpenSSL instead of the app: RSA-OAEP with SHA-256
# and MGF1-SHA-256 under the published PKCS#1 key. The password travels on stdin only.
ENV_USER="gateenvelope"
ENV_PASS="GateEnvelopePass2026!"
SYNC_MUTATION='mutation($u: String!, $e: String!) { syncKerberosPassword(userId: $u, encryptedPassword: $e) }'
if ! gexec sh -c 'command -v openssl' >/dev/null 2>&1; then
    p_skip "envelope rows: no openssl in the image"
else
    graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$ENV_USER"'", "email": "'"$ENV_USER"'@gate.test",
                "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
        >"$D/create-envelope.json" 2>&1 || p_bad "createUser $ENV_USER failed"
    graphql '{ kerberosInfo { publicKeyDerBase64 } }' >"$D/envelope-key.json" 2>&1 \
        || p_bad "kerberosInfo for the envelope failed"
    pubkey="$(json_get kerberosInfo.publicKeyDerBase64 <"$D/envelope-key.json" 2>/dev/null)"
    printf '%s' "$ENV_PASS" | t docker exec -i -e KEY="$pubkey" "$CONTAINER" sh -c '
        printf %s "$KEY" | base64 -d >/tmp/gate_envelope.der &&
            openssl rsa -RSAPublicKey_in -inform DER -in /tmp/gate_envelope.der \
                -pubout -out /tmp/gate_envelope.pem 2>/dev/null &&
            openssl pkeyutl -encrypt -pubin -inkey /tmp/gate_envelope.pem \
                -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
                -pkeyopt rsa_mgf1_md:sha256 | base64 -w0
        rc=$?; rm -f /tmp/gate_envelope.der /tmp/gate_envelope.pem; exit $rc' \
        >"$D/envelope.b64" 2>"$D/envelope.err"
    sealed="$(cat "$D/envelope.b64")"
    if [ -n "$sealed" ] && graphql "$SYNC_MUTATION" '{"u": "'"$ENV_USER"'", "e": "'"$sealed"'"}' \
        >"$D/envelope-sync.json" 2>"$D/envelope-sync.err" \
        && [ "$(json_get syncKerberosPassword <"$D/envelope-sync.json")" = "True" ]; then
        p_ok "syncKerberosPassword takes an OpenSSL OAEP-SHA256 envelope"
    else
        p_bad "syncKerberosPassword refused the OpenSSL envelope (see envelope.err, envelope-sync.err)"
    fi
    if printf '%s\n' "$ENV_PASS" | t docker exec -i "$CONTAINER" \
        sh -c 'KRB5CCNAME=/tmp/gate_cc_envelope kinit "$0"; rc=$?; kdestroy -q 2>/dev/null; exit $rc' \
        "$ENV_USER@$REALM" >"$D/kinit-envelope.log" 2>&1; then
        p_ok "kinit with the enveloped password succeeds"
    else
        p_bad "kinit with the enveloped password failed"
    fi
    flipped="$(printf '%s' "$sealed" | python3 -c '
import base64, sys
sealed = bytearray(base64.b64decode(sys.stdin.read()))
sealed[-1] ^= 1
print(base64.b64encode(sealed).decode())' 2>/dev/null)"
    if graphql "$SYNC_MUTATION" '{"u": "'"$ENV_USER"'", "e": "'"$flipped"'"}' \
        >"$D/envelope-flipped.json" 2>"$D/envelope-flipped.err"; then
        p_bad "syncKerberosPassword took an envelope with one byte flipped"
    elif grep -q "Kerberos password decryption failed" "$D/envelope-flipped.err"; then
        p_ok "an envelope with one byte flipped is refused"
    else
        p_bad "flipped envelope: unexpected answer (see envelope-flipped.err)"
    fi
    graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
        '{"id": "'"$ENV_USER"'"}' >"$D/delete-envelope.json" 2>&1 || p_bad "deleteUser $ENV_USER failed"
fi

# A password the directory takes and the KDC refuses: a kadm5 policy (min length 40) on an
# existing principal, as MIT's kadm5_chpass_principal_3 applies it. The directory changes, the
# principal keeps its key, through GraphQL (an error) and through ldappasswd (Success).
POL_USER="gatepolicy"
POL_FIRST="GatePolicyFirstPassword2026!"
POL_GQL="GatePolicyGql2026!"
POL_LDAP="GatePolicyLdap2026!"
POL_NAME="gatepwpol"
POL_REFUSED="Kerberos sync failed after the directory password was set: while setting the Kerberos password: password policy: min_length 40"
POL_DN="uid=$POL_USER,ou=people,$BASE_DN"
SET_PW='mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }'
princ_kvno() { kadmin_q "getprinc $1" 2>/dev/null | awk '/Key: vno/ {print $3; exit}' | tr -d ','; }
user_bind() { t ldapwhoami -x -H "$(ldap_url)" -D "$1" -w "$2" >/dev/null 2>&1; }
kinit_refused() { ! kinit_pw "$1@$REALM" "$2" >"$3" 2>&1 && grep -q "Password incorrect" "$3"; }
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$POL_USER"'", "email": "'"$POL_USER"'@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create-policy.json" 2>&1 || p_bad "createUser $POL_USER failed"
graphql "$SET_PW" '{"id": "'"$POL_USER"'", "pw": "'"$POL_FIRST"'"}' >"$D/setpw-policy-first.json" 2>&1 \
    || p_bad "first setUserPassword $POL_USER failed"
if kadmin_q "addpol -minlength 40 $POL_NAME" >"$D/addpol.txt" 2>&1 \
    && kadmin_q "modprinc -policy $POL_NAME $POL_USER" >"$D/modprinc-policy.txt" 2>&1 \
    && ! grep -q " while " "$D/addpol.txt" "$D/modprinc-policy.txt"; then
    p_ok "policy $POL_NAME (min length 40) bound to $POL_USER"
else
    p_bad "could not bind policy $POL_NAME to $POL_USER (see addpol.txt, modprinc-policy.txt)"
fi
kvno_before="$(princ_kvno "$POL_USER")"
if graphql "$SET_PW" '{"id": "'"$POL_USER"'", "pw": "'"$POL_GQL"'"}' \
    >"$D/setpw-policy-gql.json" 2>"$D/setpw-policy-gql.err"; then
    p_bad "setUserPassword answered ok although the policy refuses the password"
elif grep -qF "$POL_REFUSED" "$D/setpw-policy-gql.err"; then
    p_ok "setUserPassword reports the policy refusal of the Kerberos half"
else
    p_bad "setUserPassword: unexpected answer (see setpw-policy-gql.err)"
fi
policy_holds() {
    local new="$1" via="$2"
    if user_bind "$POL_DN" "$new"; then
        p_ok "$via: the directory takes the new password"
    else
        p_bad "$via: the directory refuses the new password"
    fi
    if kinit_refused "$POL_USER" "$new" "$D/kinit-policy-new-$via.log"; then
        p_ok "$via: kinit with the refused password fails"
    else
        p_bad "$via: kinit with the refused password did not fail as expected"
    fi
    if kinit_pw "$POL_USER@$REALM" "$POL_FIRST" >"$D/kinit-policy-old-$via.log" 2>&1; then
        p_ok "$via: kinit with the old password still works"
    else
        p_bad "$via: kinit with the old password failed"
    fi
    if [ -n "$kvno_before" ] && [ "$(princ_kvno "$POL_USER")" = "$kvno_before" ]; then
        p_ok "$via: the principal's key version is unchanged ($kvno_before)"
    else
        p_bad "$via: the principal's key version moved"
    fi
}
policy_holds "$POL_GQL" graphql
if t ldappasswd -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" -s "$POL_LDAP" "$POL_DN" \
    >"$D/ldappasswd-policy.log" 2>&1; then
    p_ok "ldappasswd answers Success when the Kerberos half is refused"
else
    p_bad "ldappasswd failed (see ldappasswd-policy.log)"
fi
policy_holds "$POL_LDAP" ldappasswd
if lsearch -b "$POL_DN" -s base krbPrincipalName >"$D/policy-record.ldif" 2>&1 \
    && grep -qi "^krbPrincipalName: $POL_USER@$REALM" "$D/policy-record.ldif"; then
    p_ok "the first sync's principal-name record is there"
else
    p_bad "no principal-name record after the first sync (see policy-record.ldif)"
fi
graphql 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
    '{"u": "'"$POL_USER"'", "g": '"${disabled_gid:-0}"'}' >"$D/disable-policy.json" 2>&1 \
    || p_bad "addUserToGroup lldap_disabled for $POL_USER failed"
if graphql "$SET_PW" '{"id": "'"$POL_USER"'", "pw": "'"$POL_GQL"'x"}' \
    >"$D/setpw-policy-disabled.json" 2>"$D/setpw-policy-disabled.err"; then
    p_bad "disabled: setUserPassword answered ok although the policy refuses the password"
elif grep -qF "$POL_REFUSED" "$D/setpw-policy-disabled.err"; then
    p_ok "disabled: setUserPassword reports the policy refusal of the Kerberos half"
else
    p_bad "disabled: setUserPassword: unexpected answer (see setpw-policy-disabled.err)"
fi
if t ldappasswd -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" -s "${POL_LDAP}x" "$POL_DN" \
    >"$D/ldappasswd-policy-disabled.log" 2>&1; then
    p_ok "disabled: ldappasswd answers Success when the Kerberos half is refused"
else
    p_bad "disabled: ldappasswd failed (see ldappasswd-policy-disabled.log)"
fi
if principal_attrs "$POL_USER" >"$D/attrs-policy.txt" && grep -q DISALLOW_ALL_TIX "$D/attrs-policy.txt"; then
    p_ok "a refused change leaves DISALLOW_ALL_TIX in place"
else
    p_bad "after a refused change DISALLOW_ALL_TIX is not in place"
fi
graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
    '{"id": "'"$POL_USER"'"}' >"$D/delete-policy.json" 2>&1 || p_bad "deleteUser $POL_USER failed"
kadmin_q "delpol -force $POL_NAME" >"$D/delpol.txt" 2>&1 || p_bad "delpol $POL_NAME failed (see delpol.txt)"

# A user id the directory takes and Kerberos refuses (validate_kerberos_username): the first
# sync fails before any principal exists, so no principal-name record is made.
BAD_USER="gate~env"
BAD_PASS="GateBadIdPass2026!"
BAD_DN="uid=$BAD_USER,ou=people,$BASE_DN"
BAD_REFUSED="Kerberos sync failed after the directory password was set: Kerberos username must be ASCII alphanumeric plus '.', '_' or '-'"
if graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$BAD_USER"'", "email": "gate-env@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create-badid.json" 2>&1; then
    p_ok "the directory takes the user id $BAD_USER"
    if graphql "$SET_PW" '{"id": "'"$BAD_USER"'", "pw": "'"$BAD_PASS"'"}' \
        >"$D/setpw-badid.json" 2>"$D/setpw-badid.err"; then
        p_bad "setUserPassword answered ok for a name Kerberos refuses"
    elif grep -qF "$BAD_REFUSED" "$D/setpw-badid.err"; then
        p_ok "setUserPassword reports the refused Kerberos name"
    else
        p_bad "setUserPassword for $BAD_USER: unexpected answer (see setpw-badid.err)"
    fi
    if user_bind "$BAD_DN" "$BAD_PASS"; then
        p_ok "the directory takes $BAD_USER's password"
    else
        p_bad "the directory refuses $BAD_USER's password"
    fi
    if kadmin_q "getprinc $BAD_USER" >"$D/getprinc-badid.txt" 2>&1 && grep -q "^Principal:" "$D/getprinc-badid.txt"; then
        p_bad "a principal exists for $BAD_USER"
    else
        p_ok "no principal for $BAD_USER"
    fi
    if lsearch -b "$BAD_DN" -s base krbPrincipalName >"$D/badid-record.ldif" 2>&1 \
        && grep -q "^dn:" "$D/badid-record.ldif" && ! grep -qi "^krbPrincipalName:" "$D/badid-record.ldif"; then
        p_ok "no principal-name record for $BAD_USER"
    else
        p_bad "$BAD_USER: a principal-name record, or the entry was not found (see badid-record.ldif)"
    fi
    graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
        '{"id": "'"$BAD_USER"'"}' >"$D/delete-badid.json" 2>&1 || p_bad "deleteUser $BAD_USER failed"
else
    p_bad "the directory refuses the user id $BAD_USER (see create-badid.json); the row's premise does not hold"
fi
