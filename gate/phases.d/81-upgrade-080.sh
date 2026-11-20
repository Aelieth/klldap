# shellcheck shell=bash
# Phase: the upgrade from the released 0.8.0 with stored require-mfa policies. 0.8.0 links
# require-mfa=enrolled and =always to two OUs through its own API; the new image starts on the
# same volume and reads them as enable-mfa=enabled and =always, links standing, the old key
# refused at input, and a user of each OU meets the resolved value at the bind.
# GATE_IMAGE_080 names the released 0.8.0 image; without it on this host the row is a NOTE.

D="$(phase_dir)"
U_OLD="$CONTAINER-u080old" U_NEW="$CONTAINER-u080new" U_VOL="klldap-gate-u080-$RUNID"
EXTRA_CONTAINERS+=("$U_OLD" "$U_NEW")
EXTRA_VOLUMES+=("$U_VOL")
U_PASS="U080-pass-2026!"

# u_up <name> <image>: a server on the phase's volume (kept across the two images); prints its ports.
u_up() {
    local name="$1" image="$2" i=0
    docker rm -fv "$name" >/dev/null 2>&1 || true
    LLDAP_JWT_SECRET="$JWT_SECRET" LLDAP_KEY_SEED="$KEY_SEED" LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        docker run -d --name "$name" --network "$NET" -p "127.0.0.1::17170" -p "127.0.0.1::3890" \
        -v "$U_VOL:/data" -e LLDAP_JWT_SECRET -e LLDAP_KEY_SEED -e LLDAP_LDAP_USER_PASS \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_DATABASE_URL="sqlite:////data/users.db?mode=rwc" \
        -e LLDAP_KERBEROS_OPTIONS__ENABLED=false -e LLDAP_VERBOSE=true \
        "$image" >/dev/null || return 1
    while ! docker exec "$name" /app/lldap healthcheck --config-file /data/lldap_config.toml \
        >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 90 ] && [ -n "$(docker ps -q -f "name=^${name}$")" ] || return 1
        sleep 1
    done
    printf '%s %s\n' "$(docker port "$name" 17170/tcp | head -1 | sed 's/.*://')" \
        "$(docker port "$name" 3890/tcp | head -1 | sed 's/.*://')"
}

# u_down <name> <log>: its log kept, then the container removed by name (the named volume stays).
u_down() {
    docker logs -t "$1" >"$2" 2>&1 || true
    docker rm -fv "$1" >/dev/null 2>&1 || true
}

u_gql() { graphql "$@" 2>"$D/last.err"; }

# shellcheck disable=SC2016
u_old_setup() {
    local ou user value id
    for value in enrolled always; do
        ou="u080$value" user="u080$value"
        id="$(u_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
            '{"n": "u080 '"$value"'", "i": [{"key": "require-mfa", "value": "'"$value"'"}]}' | json_get createPolicy.id)" &&
            [ -n "$id" ] && printf '%s %s\n' "$value" "$id" >>"$D/policy-ids.txt" &&
            u_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$ou"'"}' >/dev/null || return 1
        if ! u_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' \
            '{"o": "'"$ou"'", "p": '"$id"'}' >/dev/null; then
            graphql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$id"'}' >/dev/null 2>&1 || true
            return 1
        fi
        u_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$user"'", "email": "'"$user"'@gate.test"}}' >/dev/null &&
            u_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
                '{"id": "'"$user"'", "pw": "'"$U_PASS"'"}' >/dev/null &&
            u_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
                '{"ids": ["'"$user"'"], "ou": "'"$ou"'"}' >/dev/null || return 1
    done
}

# u_bind <user>: the LDAP result code of a bind with the password alone; the output in bind-<user>.out.
u_bind() {
    local dn
    dn="$(lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$1)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1)"
    [ -n "$dn" ] || { echo "no DN found for $1" >"$D/bind-$1.out" && echo none && return; }
    t ldapwhoami -x -H "$(ldap_url)" -D "$dn" -w "$U_PASS" >"$D/bind-$1.out" 2>&1
    echo $?
}

# shellcheck disable=SC2016
u_new_checks() {
    local got rc
    u_gql '{ policies { id name items { key value } linkedOus } }' >"$D/policies.json" || true
    got="$(IDS="$D/policy-ids.txt" python3 -c '
import json, os, sys
ids = dict(line.split() for line in open(os.environ["IDS"]))
by_id = {str(p["id"]): p for p in json.load(sys.stdin).get("policies", [])}
want = {"enrolled": ("enabled", "u080enrolled"), "always": ("always", "u080always")}
out = []
for old, pid in sorted(ids.items()):
    p = by_id.get(pid)
    if p is None:
        out.append(old + ": gone"); continue
    items = {i["key"]: i["value"] for i in p["items"]}
    value, ou = want[old]
    out.append("%s: items %s %s" % (old, "ok" if items == {"enable-mfa": value} else items,
                                      "linked" if ou in p["linkedOus"] else "unlinked %s" % p["linkedOus"]))
print("; ".join(out))' <"$D/policies.json" 2>"$D/policies.err")"
    if [ "$got" = "always: items ok linked; enrolled: items ok linked" ]; then
        p_ok "[U1.items] 0.8.0's require-mfa=enrolled and =always read enable-mfa=enabled and =always after the upgrade"
        p_ok "[U1.links] both policies stay linked to their OUs after the upgrade"
    else
        case "$got" in
        *"items ok"*"items ok"*) p_ok "[U1.items] 0.8.0's require-mfa=enrolled and =always read enable-mfa=enabled and =always after the upgrade" ;;
        *) p_bad "[U1.items] after the upgrade: ${got:-no answer} (see policies.json)" ;;
        esac
        case "$got" in
        *"linked;"*"linked") p_ok "[U1.links] both policies stay linked to their OUs after the upgrade" ;;
        *) p_bad "[U1.links] after the upgrade: ${got:-no answer}" ;;
        esac
    fi
    if u_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
        '{"n": "u080 old key", "i": [{"key": "require-mfa", "value": "always"}]}' >/dev/null; then
        p_bad "[U1.old-key] createPolicy with the old key require-mfa was accepted"
    elif grep -q "'require-mfa' is now 'enable-mfa'" "$D/last.err"; then
        p_ok "[U1.old-key] createPolicy with the old key require-mfa is refused, naming enable-mfa"
    else
        p_bad "[U1.old-key] createPolicy with the old key was refused without naming enable-mfa: $(head -c 200 "$D/last.err")"
    fi
    rc="$(u_bind u080enrolled)"
    if [ "$rc" = 0 ]; then
        p_ok "[U1.bind-enabled] the OU's enable-mfa=enabled, an unenrolled user: the bind with the password alone is let in"
    else
        p_bad "[U1.bind-enabled] the OU's enable-mfa=enabled, an unenrolled user: bind rc $rc (see bind-u080enrolled.out)"
    fi
    rc="$(u_bind u080always)"
    if [ "$rc" = 49 ] && grep -q "MFA enrollment required" "$D/bind-u080always.out"; then
        p_ok "[U1.bind-always] the OU's enable-mfa=always, an unenrolled user: the bind is refused, 'MFA enrollment required'"
    else
        p_bad "[U1.bind-always] the OU's enable-mfa=always, an unenrolled user: bind rc $rc without 'MFA enrollment required' (see bind-u080always.out)"
    fi
}

u_upgrade() {
    local ports
    if [ -z "${GATE_IMAGE_080:-}" ] || ! docker image inspect "$GATE_IMAGE_080" >/dev/null 2>&1; then
        note "[NOTE] ${PHASE}: [U1] the 0.8.0 image is absent (GATE_IMAGE_080=${GATE_IMAGE_080:-unset}): the upgrade row did not run; it belongs on the full final run"
        return
    fi
    : >"$D/policy-ids.txt"
    docker volume rm "$U_VOL" >/dev/null 2>&1 || true
    if ! docker volume create "$U_VOL" >/dev/null; then
        p_bad "[U1.setup] volume $U_VOL could not be made"
        return
    fi
    if ! ports="$(u_up "$U_OLD" "$GATE_IMAGE_080" 2>"$D/old.err")"; then
        p_bad "[U1.setup] the 0.8.0 server did not become healthy (see old.err, old.log)"
        u_down "$U_OLD" "$D/old.log"
        return
    fi
    # shellcheck disable=SC2086
    side_use $ports
    if [ -z "$TOKEN" ] || ! u_old_setup; then
        p_bad "[U1.setup] the policies, OUs and users on 0.8.0 could not be made: $(head -c 200 "$D/last.err")"
        side_back
        u_down "$U_OLD" "$D/old.log"
        return
    fi
    side_back
    u_down "$U_OLD" "$D/old.log"
    if ! ports="$(u_up "$U_NEW" "$GATE_IMAGE" 2>"$D/new.err")"; then
        p_bad "[U1.setup] the new image did not start on 0.8.0's volume (see new.err, new.log)"
        u_down "$U_NEW" "$D/new.log"
        return
    fi
    # shellcheck disable=SC2086
    side_use $ports
    if [ -z "$TOKEN" ]; then
        p_bad "[U1.setup] no admin token from the new image on 0.8.0's volume"
    else
        u_new_checks
    fi
    side_back
    u_down "$U_NEW" "$D/new.log"
}

u_upgrade
docker volume rm "$U_VOL" >/dev/null 2>&1 || true
