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

ENV_USER="gateenvelope"
ENV_PLAIN="gateenvplain"
ENV_SET='mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }'
ENV_BOTH_NEW="bind-new=yes bind-old=no kinit-new=yes kinit-old=no"
ENV_BOTH_OLD="bind-new=no bind-old=yes kinit-new=no kinit-old=yes"
ENV_OLD="" ENV_PLAIN_OLD="" ENV_KEY="" ENV_GOT="" ENV_MADE=""
env_gen() { python3 -c 'import secrets; print("Ge" + secrets.token_hex(10) + "!")'; }
env_bind() { t ldapwhoami -x -H "$(ldap_url)" -D "uid=$1,ou=people,$BASE_DN" -w "$2" >/dev/null 2>&1; }
env_sides() {
    local bn=no bo=no kn=no ko=no
    env_bind "$1" "$2" && bn=yes
    env_bind "$1" "$3" && bo=yes
    kinit_pw "$1@$REALM" "$2" >"$D/kinit-envelope-new.log" 2>&1 && kn=yes
    kinit_pw "$1@$REALM" "$3" >"$D/kinit-envelope-old.log" 2>&1 && ko=yes
    ENV_GOT="bind-new=$bn bind-old=$bo kinit-new=$kn kinit-old=$ko"
}

env_setup() {
    ENV_OLD="$(env_gen)" ENV_PLAIN_OLD="$(env_gen)"
    graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$ENV_USER"'", "email": "'"$ENV_USER"'@gate.test",
                "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' >"$D/create-envelope.json" 2>&1 &&
        graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$ENV_PLAIN"'", "email": "'"$ENV_PLAIN"'@gate.test"}}' >>"$D/create-envelope.json" 2>&1 &&
        graphql "$ENV_SET" '{"id": "'"$ENV_USER"'", "pw": "'"$ENV_OLD"'"}' >>"$D/create-envelope.json" 2>&1 &&
        graphql "$ENV_SET" '{"id": "'"$ENV_PLAIN"'", "pw": "'"$ENV_PLAIN_OLD"'"}' >>"$D/create-envelope.json" 2>&1 &&
        env_bind "$ENV_USER" "$ENV_OLD" && env_bind "$ENV_PLAIN" "$ENV_PLAIN_OLD" &&
        kinit_pw "$ENV_USER@$REALM" "$ENV_OLD" >"$D/kinit-envelope-first.log" 2>&1 || {
        p_bad "[U1.env-setup] the envelope users could not be made, or a first password does not hold (see create-envelope.json, kinit-envelope-first.log)"
        return 1
    }
}

env_synced() {
    local new want="WIRE start-key=yes finish-envelope=yes rewrite=none finish-status=200 graphql-seal=no create-sent=no page=done"
    new="$(env_gen)"
    wire_page env-synced change "$ENV_USER" "$new"
    env_sides "$ENV_USER" "$new" "$ENV_OLD"
    if [ "$WIRE_LINE" = "$want" ] && [ "$ENV_GOT" = "$ENV_BOTH_NEW" ]; then
        ENV_OLD="$new"
        p_ok "[U1.env-page-synced] the change page for a synced user: register/start gives the key, the finish carries the envelope, and bind and kinit both take the new password"
    else
        env_bind "$ENV_USER" "$new" && ENV_OLD="$new"
        p_bad "[U1.env-page-synced] $WIRE_LINE ${WIRE_ALERT:+(alert: $WIRE_ALERT) }; $ENV_GOT; want $want and $ENV_BOTH_NEW"
    fi
}

env_nosync() {
    local new sealed bn=no bo=no made=no
    local want="WIRE start-key=no finish-envelope=no rewrite=added finish-status=400 graphql-seal=no create-sent=no page=stayed"
    new="$(env_gen)"
    sealed="$(wire_seal "$ENV_KEY" "$new" "$ENV_PLAIN")"
    [ -n "$sealed" ] || {
        p_bad "[U1.env-nosync-refused] OpenSSL did not seal (see seal.err)"
        return
    }
    wire_page env-nosync change "$ENV_PLAIN" "$new" add "$sealed"
    env_bind "$ENV_PLAIN" "$new" && bn=yes
    env_bind "$ENV_PLAIN" "$ENV_PLAIN_OLD" && bo=yes
    principal_exists "$ENV_PLAIN" && made=yes
    if [ "$WIRE_LINE" = "$want" ] && [ "bind-new=$bn bind-old=$bo principal=$made" = "bind-new=no bind-old=yes principal=no" ] &&
        grep -qF 'a Kerberos password envelope is taken only for a user with Kerberos sync' <<<"$WIRE_ALERT"; then
        p_ok "[U1.env-nosync-refused] a finish with an envelope for a user without sync: 400 '$WIRE_ALERT'; nothing written: the old password binds, the new one does not, and there is no principal"
    else
        p_bad "[U1.env-nosync-refused] $WIRE_LINE (alert: ${WIRE_ALERT:-none}); bind-new=$bn bind-old=$bo principal=$made; want $want, the sync sentence, bind-new=no bind-old=yes principal=no"
    fi
}

env_other() {
    local typed sealed
    local want="WIRE start-key=yes finish-envelope=yes rewrite=swapped finish-status=400 graphql-seal=no create-sent=no page=stayed"
    typed="$(env_gen)"
    sealed="$(wire_seal "$ENV_KEY" "$typed" "$ENV_PLAIN")"
    [ -n "$sealed" ] || {
        p_bad "[U1.env-other-label] OpenSSL did not seal (see seal.err)"
        return
    }
    wire_page env-other change "$ENV_USER" "$typed" swap "$sealed"
    env_sides "$ENV_USER" "$typed" "$ENV_OLD"
    if [ "$WIRE_LINE" = "$want" ] && [ "$ENV_GOT" = "$ENV_BOTH_OLD" ] &&
        grep -qF 'the Kerberos password envelope did not open' <<<"$WIRE_ALERT"; then
        p_ok "[U1.env-other-label] $ENV_USER's finish with an envelope sealed under $ENV_PLAIN's label: 400 '$WIRE_ALERT', and bind and kinit keep the old password"
    else
        p_bad "[U1.env-other-label] $WIRE_LINE (alert: ${WIRE_ALERT:-none}); $ENV_GOT; want $want, 'did not open', $ENV_BOTH_OLD"
    fi
}

if ! docker image inspect "$WIRE_IMAGE" >/dev/null 2>&1; then
    p_skip "[U1.env-pages] browser image absent: $WIRE_IMAGE; the envelope rows did not run"
else
    if env_setup; then
        ENV_MADE=1
        env_synced
        graphql '{ kerberosInfo { publicKeyDerBase64 } }' >"$D/envelope-key.json" 2>&1 &&
            ENV_KEY="$(json_get kerberosInfo.publicKeyDerBase64 <"$D/envelope-key.json" 2>/dev/null)"
        if [ -n "$ENV_KEY" ] && gexec sh -c 'command -v openssl' >/dev/null 2>&1; then
            env_nosync
            env_other
        else
            p_skip "[U1.env-openssl] no transport key or no openssl in the image (see envelope-key.json): the two refused-envelope rows did not run"
        fi
    fi
    for u in "$ENV_USER" "$ENV_PLAIN"; do
        graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' '{"id": "'"$u"'"}' \
            >"$D/delete-$u.json" 2>&1 || [ -z "$ENV_MADE" ] || p_bad "deleteUser $u failed"
    done
fi

# A password the directory takes and the KDC refuses: a kadm5 policy (min length 40) on an
# existing principal, as MIT applies it. The directory changes, the
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
