# shellcheck shell=bash
# Phase: LDAP write matrix — ldapadd a user (with a custom attribute: it must persist
# or be cleanly rejected, never silently dropped), attribute modifies, and the wire
# userPassword replace on a kerberossync user proving password.rs → OPAQUE + KDC sync.

D="$(phase_dir)"
LDIF_USER="gateldif"
WIRE_SYNC_USER="gatewire"
WIRE_PASS="GateWirePass2026!"
WIRE_NEW_PASS="GateWireNewPass2026!"

graphql 'mutation($n: String!, $t: AttributeType!) {
    addUserAttribute(name: $n, attributeType: $t, isList: false, isVisible: true, isEditable: true) { ok } }' \
    '{"n": "gatecustom", "t": "STRING"}' >"$D/add-attr.json" 2>&1 \
    || p_bad "addUserAttribute gatecustom failed"

cat >"$D/add-user.ldif" <<EOF
dn: uid=$LDIF_USER,ou=people,$BASE_DN
changetype: add
objectClass: inetOrgPerson
objectClass: person
uid: $LDIF_USER
mail: $LDIF_USER@gate.test
cn: LDIF Gate User
sn: Gate
givenName: LDIF
gatecustom: brought by ldapadd
EOF
if lmodify -f "$D/add-user.ldif" >"$D/ldapadd.log" 2>&1; then
    p_ok "ldapadd creates a user over the wire"
    if lsearch -b "uid=$LDIF_USER,ou=people,$BASE_DN" -s base "(objectClass=*)" gatecustom \
        2>>"$D/ldapadd.log" | grep -q "^gatecustom: brought by ldapadd"; then
        p_ok "custom attribute from ldapadd persists"
    else
        p_bad "custom attribute silently dropped by ldapadd"
    fi
else
    p_bad "ldapadd failed (see ldapadd.log)"
fi

cat >"$D/add-ssh.ldif" <<EOF
dn: uid=$LDIF_USER,ou=people,$BASE_DN
changetype: modify
add: sshPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCGateTestKeyNotReal gate@test
EOF
if lmodify -f "$D/add-ssh.ldif" >"$D/add-ssh.log" 2>&1 \
    && lsearch -b "uid=$LDIF_USER,ou=people,$BASE_DN" -s base "(objectClass=*)" sshPublicKey \
        2>>"$D/add-ssh.log" | grep -q "^sshPublicKey: ssh-rsa"; then
    p_ok "ldapmodify add sshPublicKey + read-back"
else
    p_bad "sshPublicKey add/read-back failed"
fi

cat >"$D/multi-replace.ldif" <<EOF
dn: uid=$LDIF_USER,ou=people,$BASE_DN
changetype: modify
replace: mail
mail: updated@gate.test
-
replace: givenName
givenName: UpdatedFirst
-
replace: sn
sn: UpdatedLast
-
replace: cn
cn: Updated Display Name
EOF
if lmodify -f "$D/multi-replace.ldif" >"$D/multi-replace.log" 2>&1 \
    && lsearch -b "uid=$LDIF_USER,ou=people,$BASE_DN" -s base "(objectClass=*)" mail cn givenName sn \
        2>>"$D/multi-replace.log" >"$D/multi-readback.txt" \
    && grep -q "^mail: updated@gate.test" "$D/multi-readback.txt" \
    && grep -q "^cn: Updated Display Name" "$D/multi-readback.txt" \
    && grep -q "^givenName: UpdatedFirst" "$D/multi-readback.txt"; then
    p_ok "multi-attribute replace + read-back"
else
    p_bad "multi-attribute replace failed"
fi

# Wire password change on a kerberossync user: userPassword replace must re-register
# OPAQUE AND update the KDC principal so the NEW password kinits.
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$WIRE_SYNC_USER"'", "email": "'"$WIRE_SYNC_USER"'@gate.test",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/wire-user.json" 2>&1 || p_bad "createUser $WIRE_SYNC_USER failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$WIRE_SYNC_USER"'", "pw": "'"$WIRE_PASS"'"}' >"$D/wire-setpw.json" 2>&1 \
    || p_bad "initial setUserPassword failed"

cat >"$D/set-password.ldif" <<EOF
dn: uid=$WIRE_SYNC_USER,ou=people,$BASE_DN
changetype: modify
replace: userPassword
userPassword: $WIRE_NEW_PASS
EOF
if lmodify -f "$D/set-password.ldif" >"$D/set-password.log" 2>&1; then
    p_ok "wire replace userPassword accepted"
else
    p_bad "wire replace userPassword failed"
fi
if kinit_pw "$WIRE_SYNC_USER@$REALM" "$WIRE_NEW_PASS" >"$D/kinit-new.log" 2>&1; then
    p_ok "new wire-set password kinits (password.rs → OPAQUE + KDC end-to-end)"
else
    p_bad "new wire-set password does not kinit"
fi
if kinit_pw "$WIRE_SYNC_USER@$REALM" "$WIRE_PASS" >"$D/kinit-old.log" 2>&1; then
    p_bad "old password still kinits after wire change"
else
    p_ok "old password no longer kinits"
fi

# ldappasswd (RFC 3062 password modify): pin whichever behavior the server has —
# if it works the new password must kinit; a clean protocol rejection is recorded.
if t ldappasswd -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" \
    -s "${WIRE_NEW_PASS}x" "uid=$WIRE_SYNC_USER,ou=people,$BASE_DN" >"$D/ldappasswd.log" 2>&1; then
    if kinit_pw "$WIRE_SYNC_USER@$REALM" "${WIRE_NEW_PASS}x" >"$D/kinit-extop.log" 2>&1; then
        p_ok "ldappasswd extended op works and syncs to the KDC"
    else
        p_bad "ldappasswd claimed success but the password does not kinit"
    fi
else
    p_skip "ldappasswd extended op not supported (recorded; wire replace covers password sync)"
fi

graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
    '{"id": "'"$LDIF_USER"'"}' >"$D/cleanup-ldif.json" 2>&1 || p_bad "cleanup $LDIF_USER failed"
graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
    '{"id": "'"$WIRE_SYNC_USER"'"}' >"$D/cleanup-wire.json" 2>&1 || p_bad "cleanup $WIRE_SYNC_USER failed"
