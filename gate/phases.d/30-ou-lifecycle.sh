# shellcheck shell=bash
# Phase: OU lifecycle over GraphQL, verified over LDAP — create, move a user in, find
# it by subtree search, delete the OU and observe the reassignment branch.

D="$(phase_dir)"
OU_NAME="gateou"
OU_USER="gateoumover"

graphql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$OU_NAME"'"}' \
    >"$D/create-ou.json" 2>&1 || p_bad "createOu failed"
if graphql '{ listOus }' '{}' | grep -q "\"$OU_NAME\""; then
    p_ok "createOu → listOus shows $OU_NAME"
else
    p_bad "listOus does not show $OU_NAME"
fi

graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$OU_USER"'", "email": "'"$OU_USER"'@gate.test"}}' \
    >"$D/create-user.json" 2>&1 || p_bad "createUser $OU_USER failed"
graphql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
    '{"ids": ["'"$OU_USER"'"], "ou": "'"$OU_NAME"'"}' >"$D/change-ou.json" 2>&1 \
    || p_bad "changeUserOu failed"

if lsearch -b "ou=$OU_NAME,$BASE_DN" -s sub "(objectClass=person)" uid 2>"$D/search.err" \
    | grep -q "^uid: $OU_USER"; then
    p_ok "subtree search under ou=$OU_NAME finds the moved user"
else
    p_bad "moved user not found under ou=$OU_NAME"
fi

graphql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$OU_NAME"'"}' \
    >"$D/delete-ou.json" 2>&1 || p_bad "deleteOu failed"
if graphql '{ listOus }' '{}' | grep -q "\"$OU_NAME\""; then
    p_bad "$OU_NAME still listed after deleteOu"
else
    p_ok "deleteOu removes the OU"
fi
# Reassignment branch: members of a deleted OU return to the default people OU.
if lsearch -b "ou=people,$BASE_DN" -s sub "(uid=$OU_USER)" uid 2>>"$D/search.err" \
    | grep -q "^uid: $OU_USER"; then
    p_ok "deleteOu reassigned the member back to ou=people"
else
    p_bad "member not reassigned to ou=people after deleteOu"
fi

graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
    '{"id": "'"$OU_USER"'"}' >"$D/delete-user.json" 2>&1 || p_bad "cleanup deleteUser failed"
