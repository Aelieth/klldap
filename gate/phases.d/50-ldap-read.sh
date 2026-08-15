# shellcheck shell=bash
# Phase: LDAP read matrix — the openldap-tests.txt invocations as assertions: whoami,
# RootDSE, subschema (with duplicate-attributeType check), one-level children, OU
# subtree, operational leakage, scoped person search, mixed filter and per-entry "+".

D="$(phase_dir)"
READ_OU="gateread"
READ_USER="gatereader"

graphql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$READ_OU"'"}' \
    >"$D/setup-ou.json" 2>&1 || p_bad "setup createOu failed"
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$READ_USER"'", "email": "'"$READ_USER"'@gate.test"}}' \
    >"$D/setup-user.json" 2>&1 || p_bad "setup createUser failed"
graphql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
    '{"ids": ["'"$READ_USER"'"], "ou": "'"$READ_OU"'"}' >"$D/setup-move.json" 2>&1 \
    || p_bad "setup changeUserOu failed"

if lwhoami >"$D/whoami.txt" 2>&1 && grep -qi "admin" "$D/whoami.txt"; then
    p_ok "ldapwhoami binds and identifies admin"
else
    p_bad "ldapwhoami failed"
fi

lsearch -s base -b "" "(objectClass=*)" "+" "*" >"$D/rootdse.txt" 2>&1
if grep -qi "^namingcontexts: $BASE_DN" "$D/rootdse.txt"; then
    p_ok "RootDSE advertises the naming context"
else
    p_bad "RootDSE missing namingContexts"
fi

lsearch -b "cn=Subschema,$BASE_DN" -s base "(objectClass=*)" "+" "*" >"$D/subschema.txt" 2>&1
if grep -q "^attributeTypes:" "$D/subschema.txt"; then
    p_ok "subschema returns attributeTypes"
else
    p_bad "subschema empty"
fi
dups=0
for attr in createTimestamp modifyTimestamp givenName entryUUID; do
    n="$(grep -c "NAME '$attr'" "$D/subschema.txt")"
    if [ "$n" -gt 1 ]; then
        dups=$((dups + 1))
        note "  duplicate attributeType for $attr ($n entries)"
    fi
done
if [ "$dups" -eq 0 ]; then
    p_ok "no duplicate attributeTypes in the subschema"
else
    p_bad "$dups duplicated attributeTypes in the subschema"
fi

lsearch -b "$BASE_DN" -s one "(objectClass=*)" ou hasSubordinates structuralObjectClass \
    >"$D/onelevel.txt" 2>&1
if grep -q "^dn: ou=people,$BASE_DN" "$D/onelevel.txt" \
    && grep -q "^dn: ou=groups,$BASE_DN" "$D/onelevel.txt" \
    && grep -q "^hasSubordinates:" "$D/onelevel.txt"; then
    p_ok "one-level base search lists the OUs with requested attributes"
else
    p_bad "one-level base search missing OUs or attributes"
fi

lsearch -b "$BASE_DN" -s sub "(objectClass=organizationalUnit)" ou >"$D/ou-subtree.txt" 2>&1
if grep -q "^dn: ou=people,$BASE_DN" "$D/ou-subtree.txt" \
    && grep -q "^dn: ou=$READ_OU,$BASE_DN" "$D/ou-subtree.txt"; then
    p_ok "subtree OU search finds built-in and custom OUs"
else
    p_bad "subtree OU search incomplete"
fi

lsearch -b "$BASE_DN" -s one "(objectClass=*)" "*" >"$D/star-leakage.txt" 2>&1
if grep -qE "^(createTimestamp|entryUUID|modifyTimestamp):" "$D/star-leakage.txt"; then
    p_bad "operational attributes leak into the default * view"
else
    p_ok "no operational leakage on *"
fi

if lsearch -b "ou=$READ_OU,$BASE_DN" -s sub "(objectClass=person)" uid \
    >"$D/scoped-person.txt" 2>&1 && grep -q "^uid: $READ_USER" "$D/scoped-person.txt"; then
    p_ok "scoped person search under the custom OU works"
else
    p_bad "scoped person search failed"
fi

lsearch -b "$BASE_DN" -s sub "(|(objectClass=person)(objectClass=groupOfUniqueNames))" \
    cn uid mail memberOf "+" >"$D/mixed.txt" 2>&1
if grep -q "^uid: admin" "$D/mixed.txt" && grep -q "^dn: cn=lldap_admin,ou=groups,$BASE_DN" "$D/mixed.txt" \
    && grep -qi "^memberof:" "$D/mixed.txt"; then
    p_ok "mixed person/group filter with + returns users, groups and memberOf"
else
    p_bad "mixed filter search incomplete"
fi

lsearch -b "uid=admin,ou=people,$BASE_DN" -s base "(objectClass=*)" "+" >"$D/entry-plus.txt" 2>&1
if grep -q "^entryUUID:" "$D/entry-plus.txt" && grep -q "^createTimestamp:" "$D/entry-plus.txt"; then
    p_ok "per-entry base search with + exposes operational attributes"
else
    p_bad "per-entry + search missing operational attributes"
fi

graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' \
    '{"id": "'"$READ_USER"'"}' >"$D/cleanup-user.json" 2>&1 || p_bad "cleanup deleteUser failed"
graphql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$READ_OU"'"}' \
    >"$D/cleanup-ou.json" 2>&1 || p_bad "cleanup deleteOu failed"
