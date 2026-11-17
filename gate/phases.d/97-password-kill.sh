# shellcheck shell=bash
# Phase: X1′'s kill tests. An image built with kill-points aborts a synced password change, or an
# LDAP Add with a password, at each point of its one transaction; the release image then starts
# on the same volumes and database. Both stores hold the old state or both the new one, and a
# success row exists exactly when the change committed.

KP_D="$(phase_dir)"
KP_RUN="kp$(date +%H%M%S)"
KP_USER="${KP_RUN}u"
KP_DN="uid=${KP_USER},ou=people,${BASE_DN}"
KP_ADDS=()
KP_POINTS=(opaque-prepared callback-entered directory-written batch-written committed kerberos-changed)
KP_SET='mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }'
KP_RELEASE="$GATE_IMAGE"
KP_ARGS=(${GATE_EXTRA_RUN_ARGS[@]+"${GATE_EXTRA_RUN_ARGS[@]}"})
KP_SEQ=0 KP_UP="release" KP_CUR="" KP_SIDE=""

kp_gen() { python3 -c 'import secrets; print("Kp" + secrets.token_hex(10) + "!")'; }
kp_vars() { ID="$1" PW="$2" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "pw": os.environ["PW"]}))'; }

# kp_swap <label> <image> [run args...]: the server in place of the running one, on the same
# volumes, database and run arguments; the stopped one's log is kept.
# shellcheck disable=SC2034
kp_swap() {
    local label="$1" GATE_IMAGE="$2"
    shift 2
    local -a GATE_EXTRA_RUN_ARGS=(${KP_ARGS[@]+"${KP_ARGS[@]}"} "$@")
    KP_SEQ=$((KP_SEQ + 1))
    t docker stop "$CONTAINER" >/dev/null 2>&1
    docker logs "$CONTAINER" >"$KP_D/$(printf %02d "$KP_SEQ")-$KP_UP.log" 2>&1
    docker rm -v "$CONTAINER" >/dev/null 2>&1 || return 1
    KP_UP="$label"
    start_main_container && wait_healthy 120 && discover_ports && TOKEN="$(gate_login)"
}

kp_bind() {
    local f="$KP_D/.bindpw" rc
    (umask 077 && printf '%s' "$2" >"$f")
    t ldapwhoami -x -H "$(ldap_url)" -D "$1" -y "$f" >/dev/null 2>&1
    rc=$?
    rm -f "$f"
    return "$rc"
}
kp_kinit() { kinit_pw "$1@$REALM" "$2" >"$KP_D/kinit.out" 2>&1; }

# kp_sides <dn> <user> <old> <new>: KP_SIDE is old, new, or what bind and kinit each took.
kp_sides() {
    local b_old=no b_new=no k_old=no k_new=no
    kp_bind "$1" "$3" && b_old=yes
    kp_bind "$1" "$4" && b_new=yes
    kp_kinit "$2" "$3" && k_old=yes
    kp_kinit "$2" "$4" && k_new=yes
    case "$b_old $b_new $k_old $k_new" in
    "yes no yes no") KP_SIDE=old ;;
    "no yes no yes") KP_SIDE=new ;;
    *) KP_SIDE="mixed (bind old=$b_old new=$b_new, kinit old=$k_old new=$k_new)" ;;
    esac
}

# kp_successes <kind> <user>: how many success rows of that kind name the user.
kp_successes() {
    local out
    out="$(graphql '{ logs(filter: {kinds: ['"$1"'], target: "'"$2"'", success: true}, limit: 200) { detail } }' 2>/dev/null)"
    python3 -c 'import json,sys; print(len(json.load(sys.stdin)["logs"]))' <<<"$out" 2>/dev/null || echo error
}

# kp_want <point>: old before the commit, new from it on.
kp_want() { case "$1" in committed | kerberos-changed) echo new ;; *) echo old ;; esac; }

kp_change() {
    case "$1" in
    ldappasswd) t ldappasswd -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" -s "$2" "$KP_DN" ;;
    graphql) graphql "$KP_SET" "$(kp_vars "$KP_USER" "$2")" ;;
    modify)
        (umask 077 && printf 'dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n' "$KP_DN" "$2" >"$KP_D/modify.ldif")
        lmodify -f "$KP_D/modify.ldif"
        local rc=$?
        rm -f "$KP_D/modify.ldif"
        return "$rc"
        ;;
    esac
}

kp_setup() {
    KP_CUR="$(kp_gen)"
    graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$KP_USER"'", "email": "'"$KP_USER"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
        >"$KP_D/create.json" 2>&1 && kp_change graphql "$KP_CUR" >"$KP_D/first.json" 2>&1 || {
        p_bad "[X1.kill-setup] the synced user could not be made (see create.json, first.json)"
        return 1
    }
    kp_bind "$KP_DN" "$KP_CUR" && kp_kinit "$KP_USER" "$KP_CUR" || {
        p_bad "[X1.kill-setup] the first password is not on both sides (see kinit.out)"
        return 1
    }
}

kp_release_ignores() {
    local new running answered=no
    new="$(kp_gen)"
    kp_swap release-with-point "$KP_RELEASE" -e LLDAP_TEST_KILL_POINT=directory-written || {
        p_bad "[X1.release-ignores-kill-points] the release image did not come up with LLDAP_TEST_KILL_POINT set"
        return 1
    }
    kp_change ldappasswd "$new" >"$KP_D/release-point.change" 2>&1 && answered=yes
    running="$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>&1)"
    kp_sides "$KP_DN" "$KP_USER" "$KP_CUR" "$new"
    [ "$KP_SIDE" = new ] && KP_CUR="$new"
    if [ "$answered" = yes ] && [ "$running" = true ] && [ "$KP_SIDE" = new ]; then
        p_ok "[X1.release-ignores-kill-points] the release image with LLDAP_TEST_KILL_POINT=directory-written changes the password (bind and kinit take the new one) and keeps running"
    else
        p_bad "[X1.release-ignores-kill-points] the release image with LLDAP_TEST_KILL_POINT set: answered=$answered running=$running sides=$KP_SIDE"
    fi
    kp_swap release "$KP_RELEASE" || {
        p_bad "[X1.release-ignores-kill-points] the release image did not come back without the variable"
        return 1
    }
}

# kp_cycle <door> <point>; non-zero when the release did not come back.
kp_cycle() {
    local door="$1" point="$2" want new code before after rows
    local row="X1.kill-$door-$point"
    want="$(kp_want "$point")"
    new="$(kp_gen)"
    before="$(kp_successes PASSWORD_CHANGE "$KP_USER")"
    if ! kp_swap "kill-$door-$point" "$GATE_KILL_IMAGE" --init -e "LLDAP_TEST_KILL_POINT=$point"; then
        p_bad "[$row] the kill image did not come up"
        kp_swap release "$KP_RELEASE"
        return
    fi
    kp_change "$door" "$new" >"$KP_D/$door-$point.change" 2>&1
    code="$(t docker wait "$CONTAINER" 2>/dev/null)"
    kp_swap release "$KP_RELEASE" || {
        p_bad "[$row] the release image did not come up after the kill"
        return 1
    }
    kp_sides "$KP_DN" "$KP_USER" "$KP_CUR" "$new"
    [ "$KP_SIDE" = new ] && KP_CUR="$new"
    after="$(kp_successes PASSWORD_CHANGE "$KP_USER")"
    rows=$((after - before))
    local want_rows=0
    [ "$want" = new ] && want_rows=1
    if [ "$code" != 134 ]; then
        p_bad "[$row] the server did not abort at $point (exit '${code:-none within ${GATE_TIMEOUT:-30} s}', want 134); after it: $KP_SIDE"
    elif [ "$KP_SIDE" = "$want" ] && [ "$rows" = "$want_rows" ]; then
        p_ok "[$row] killed at $point (exit 134), then the release image: bind and kinit both take the $want password; $rows success row"
    else
        p_bad "[$row] killed at $point (exit 134), then the release image: $KP_SIDE, want both $want; success rows $before -> $after, want +$want_rows"
    fi
}

# kp_add_cycle <point>: an LDAP Add with a password for a synced user, killed at <point>.
kp_add_cycle() {
    local point="$1" want pw code found=no bound=no kinited=no add add_dn
    local row="X1.kill-add-$point"
    want="$(kp_want "$point")"
    add="${KP_RUN}a$(printf %02d "${#KP_ADDS[@]}")"
    add_dn="uid=${add},ou=people,${BASE_DN}"
    KP_ADDS+=("$add")
    pw="$(kp_gen)"
    if ! kp_swap "kill-add-$point" "$GATE_KILL_IMAGE" --init -e "LLDAP_TEST_KILL_POINT=$point"; then
        p_bad "[$row] the kill image did not come up"
        kp_swap release "$KP_RELEASE"
        return
    fi
    (umask 077 && cat >"$KP_D/add.ldif" <<EOF
dn: $add_dn
changetype: add
objectClass: inetOrgPerson
objectClass: person
uid: $add
mail: $add@gate.test
cn: $add
sn: $add
userPassword: $pw
kerberossync: 1
EOF
    )
    lmodify -f "$KP_D/add.ldif" >"$KP_D/add-$point.change" 2>&1
    rm -f "$KP_D/add.ldif"
    code="$(t docker wait "$CONTAINER" 2>/dev/null)"
    kp_swap release "$KP_RELEASE" || {
        p_bad "[$row] the release image did not come up after the kill"
        return 1
    }
    lsearch -b "$add_dn" -s base uid >"$KP_D/add-entry-$point.ldif" 2>&1 && grep -q "^uid: $add$" "$KP_D/add-entry-$point.ldif" && found=yes
    kp_bind "$add_dn" "$pw" && bound=yes
    kp_kinit "$add" "$pw" && kinited=yes
    local got="entry=$found bind=$bound kinit=$kinited"
    local want_got="entry=no bind=no kinit=no"
    [ "$want" = new ] && want_got="entry=yes bind=yes kinit=yes"
    if [ "$code" = 134 ] && [ "$got" = "$want_got" ]; then
        p_ok "[$row] an Add killed at $point (exit 134), then the release image: $got"
    else
        p_bad "[$row] exit '${code:-none}', $got; want 134, $want_got"
    fi
}

kp_all() {
    local door point
    for door in ldappasswd graphql modify; do
        for point in "${KP_POINTS[@]}"; do
            kp_cycle "$door" "$point" || return 1
        done
    done
    for point in "${KP_POINTS[@]}"; do
        kp_add_cycle "$point" || return 1
    done
}

if kp_setup; then
    if kp_release_ignores; then
        if [ -z "${GATE_KILL_IMAGE:-}" ] || ! docker image inspect "$GATE_KILL_IMAGE" >/dev/null 2>&1; then
            p_skip "[X1.kill] GATE_KILL_IMAGE '${GATE_KILL_IMAGE:-}' is not set or not found (make test-kill-points); the kill rows did not run"
        else
            kp_all
        fi
    fi
fi
for u in "$KP_USER" ${KP_ADDS[@]+"${KP_ADDS[@]}"}; do
    graphql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$u"'"}' >/dev/null 2>&1
done
[ "$KP_UP" = release ] || kp_swap release "$KP_RELEASE" || p_bad "[X1.kill-cleanup] the release image did not come back"
