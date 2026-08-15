# shellcheck shell=bash
# Phase: the headline Kerberos lifecycle — kerberossync user gets a real principal,
# real kinit works, lldap_disabled reflects to DISALLOW_ALL_TIX (and back, and is
# reasserted for password changes while disabled), deletion removes the principal.

D="$(phase_dir)"
SYNC_USER="gatesync"
NOSYNC_USER="gatenosync"
SYNC_PASS="GateSyncPass2026!"

principal_exists() { kadmin_q "getprinc $1" 2>/dev/null | grep -q "^Principal: $1@$REALM"; }
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

if principal_attrs "$SYNC_USER" | grep -q DISALLOW_ALL_TIX; then
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
if principal_attrs "$SYNC_USER" | grep -q DISALLOW_ALL_TIX; then
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
if principal_attrs "$SYNC_USER" | grep -q DISALLOW_ALL_TIX; then
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
