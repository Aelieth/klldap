# shellcheck shell=bash
# Phase: the real Zepmann/lldap-cli against the gate server: every subcommand of its usage text
# that runs without a prompt, one row each, its output kept as <row>.txt. The tool was read at
# commit e383494b; server/tests/lldap_cli_compat.rs replays its requests in cargo.
# SKIPs unless GATE_LLDAP_CLI names the script or its checkout.
# The tool signs in as an admin of the phase's own, so the gate's admin session is not touched.
# A [DIFF] line is a difference from LLDAP that this phase expects, with its reason.

C85_D="$(phase_dir)"
C85_TOOL="${GATE_LLDAP_CLI:-}"
[ -d "$C85_TOOL" ] && C85_TOOL="$C85_TOOL/lldap-cli"
C85_ADMIN=cli85admin C85_ADMIN_PASS="Cli85-AdminPass-2026!"
C85_USER=cli85u C85_PW_USER=cli85pw C85_AV_USER=cli85av C85_GROUP=cli85g
C85_PW1="Cli85-FirstPass-2026!" C85_PW2="Cli85-SecondPass-2026!"
C85_USER_ATTRS=(cli85ustr cli85ulist cli85uint cli85udate cli85ujpeg)
C85_GROUP_ATTRS=(cli85gstr cli85glist cli85gjpeg)
C85_USER_CLASS=cli85UserClass C85_GROUP_CLASS=cli85GroupClass
C85_AVATAR="$C85_D/cli85-avatar.bmp"
C85_TOKEN="" C85_REFRESH="" C85_PHOTO_TYPE="" C85_DIFFS=0

c85_gql() { graphql "$1" "${2:-{\}}" 2>>"$C85_D/gate.err"; }
c85_word() { [ -n "$1" ] && [ "$1" != null ]; }
c85_has() { grep -qE -- "$2" "$C85_D/$1.txt"; }
c85_ok() { p_ok "[CLI.$1] lldap-cli $2"; }
c85_bad() { p_bad "[CLI.$1] lldap-cli $2 (see ${3:-$1}.txt)"; }
c85_diff() {
    C85_DIFFS=$((C85_DIFFS + 1))
    note "[DIFF] ${PHASE}: [CLI.$1] lldap-cli $2"
}
c85_bind() { t ldapwhoami -x -H "$(ldap_url)" -D "uid=$1,ou=people,$BASE_DN" -w "$2" >/dev/null 2>&1; }

# c85_as <token|password|refresh|session> <row> <args...>: the tool with one way to sign in.
c85_as() {
    local how="$1" row="$2" user="" pass="" token="" refresh=""
    shift 2
    case "$how" in
    token) token="$C85_TOKEN" ;;
    password) user="$C85_ADMIN" pass="$C85_ADMIN_PASS" ;;
    refresh) refresh="$C85_REFRESH" ;;
    session) token="$C85_TOKEN" refresh="$C85_REFRESH" ;;
    esac
    LLDAP_CONFIG="$C85_D/no-config" LLDAP_HTTPURL="$(http_url)" LLDAP_USERNAME="$user" \
        LLDAP_PASSWORD="$pass" LLDAP_TOKEN="$token" LLDAP_REFRESHTOKEN="$refresh" \
        C85_CONTAINER="$CONTAINER" PATH="$C85_D/bin:$PATH" \
        t "$C85_TOOL" "$@" >"$C85_D/$row.txt" 2>&1 </dev/null
}

# c85_row <row> <pattern> <args...>: the command exits 0 and its output has the pattern.
c85_row() {
    local row="$1" want="$2" rc
    shift 2
    c85_as token "$row" "$@"
    rc=$?
    if [ "$rc" = 0 ] && c85_has "$row" "$want"; then
        c85_ok "$row" "$*"
    else
        c85_bad "$row" "$*: rc $rc, wanted /$want/"
    fi
}

# c85_gone <row> <pattern> <args...>: the command exits 0 and its output lacks the pattern.
c85_gone() {
    local row="$1" gone="$2" rc
    shift 2
    c85_as token "$row" "$@"
    rc=$?
    if [ "$rc" = 0 ] && ! c85_has "$row" "$gone"; then
        c85_ok "$row" "$*: no /$gone/"
    else
        c85_bad "$row" "$*: rc $rc, or /$gone/ is still there"
    fi
}

# c85_type_row <row> <list row> <attribute> <command>: how the list names a photo attribute's type.
c85_type_row() {
    if c85_has "$2" "^$3 +JPEG_PHOTO "; then
        c85_ok "$1" "$4: $3 is listed as JPEG_PHOTO"
    elif c85_has "$2" "^$3 +AVATAR "; then
        c85_diff "$1" "$4: $3, added as jpeg_photo, is listed as AVATAR: KLLDAP names the type AVATAR and takes JPEG_PHOTO as an alias; LLDAP and the tool say JPEG_PHOTO"
    else
        c85_bad "$1" "$4: no row for $3" "$2"
    fi
}

# c85_file_row <row> <args...>: a photo attribute set from a file.
c85_file_row() {
    local row="$1" rc
    shift
    c85_as token "$row" "$@"
    rc=$?
    if [ "$rc" = 0 ] && c85_has "$row" '^Attribute set for '; then
        c85_ok "$row" "$*"
    elif [ "$rc" != 0 ] && [ "$C85_PHOTO_TYPE" = AVATAR ]; then
        c85_diff "$row" "$*: rc $rc: the tool sends a file's content only for a type the schema lists as JPEG_PHOTO; KLLDAP lists AVATAR, so the path went as the value"
    else
        c85_bad "$row" "$*: rc $rc"
    fi
}

c85_tools() {
    local tool missing=""
    for tool in curl jq column base64; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    [ -z "$missing" ] && return 0
    p_bad "[CLI.tools] lldap-cli needs these on the host:$missing"
    return 1
}

c85_group_id() {
    c85_gql '{ groups { id displayName } }' | WANT="$1" python3 -c '
import json, os, sys
groups = json.load(sys.stdin)["groups"]
print(next((g["id"] for g in groups if g["displayName"] == os.environ["WANT"]), ""))' 2>/dev/null
}

# shellcheck disable=SC2016
c85_user_field() {
    c85_gql 'query($u: String!) { user(userId: $u) { displayName avatar } }' '{"u": "'"$1"'"}' |
        json_get "user.$2" 2>/dev/null
}

# The tool runs lldap_set_password from PATH: here the image's own, at the server's inner address.
c85_shim() {
    mkdir -p "$C85_D/bin" || return 1
    cat >"$C85_D/bin/lldap_set_password" <<'SHIM'
#!/usr/bin/env bash
args=()
while [ $# -gt 0 ]; do
    case "$1" in
    -b)
        args+=(-b http://127.0.0.1:17170)
        shift 2
        ;;
    *)
        args+=("$1")
        shift
        ;;
    esac
done
exec docker exec "$C85_CONTAINER" /app/lldap_set_password "${args[@]}"
SHIM
    chmod 755 "$C85_D/bin/lldap_set_password"
}

c85_avatar() {
    python3 - "$C85_AVATAR" <<'PY'
import struct, sys
side = 8
pixels = b"".join(bytes((x * 30, y * 30, 128)) for y in range(side) for x in range(side))
with open(sys.argv[1], "wb") as f:
    f.write(b"BM" + struct.pack("<IHHI", 54 + len(pixels), 0, 0, 54))
    f.write(struct.pack("<IiiHHIIiiII", 40, side, side, 1, 24, 0, len(pixels), 2835, 2835, 0, 0))
    f.write(pixels)
PY
}

# shellcheck disable=SC2016
c85_setup() {
    local gid
    TOKEN="$(gate_login)" || {
        p_bad "[CLI.setup] the admin could not log in"
        return 1
    }
    gid="$(c85_group_id lldap_admin)"
    if [ -z "$gid" ] ||
        ! c85_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$C85_ADMIN"'", "email": "'"$C85_ADMIN"'@gate.test"}}' >/dev/null ||
        ! c85_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
            '{"id": "'"$C85_ADMIN"'", "pw": "'"$C85_ADMIN_PASS"'"}' >/dev/null ||
        ! c85_gql 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
            '{"u": "'"$C85_ADMIN"'", "g": '"$gid"'}' >/dev/null ||
        ! c85_shim || ! c85_avatar; then
        p_bad "[CLI.setup] the phase's admin $C85_ADMIN, the shim or the picture could not be made (see gate.err)"
        return 1
    fi
}

c85_sign_in_rows() {
    local rc new
    c85_as password password-login user list
    rc=$?
    if [ "$rc" = 0 ] && c85_has password-login "^$C85_ADMIN\$"; then
        c85_ok password-login "user list, signed in by LLDAP_USERNAME and LLDAP_PASSWORD and signed out after"
    else
        c85_bad password-login "user list by LLDAP_USERNAME and LLDAP_PASSWORD: rc $rc, wanted $C85_ADMIN in the list"
    fi
    c85_as password login login
    rc=$?
    C85_TOKEN="$(sed -n 's/^export LLDAP_TOKEN=//p' "$C85_D/login.txt" | head -1)"
    C85_REFRESH="$(sed -n 's/^export LLDAP_REFRESHTOKEN=//p' "$C85_D/login.txt" | head -1)"
    if [ "$rc" = 0 ] && c85_word "$C85_TOKEN" && c85_word "$C85_REFRESH"; then
        c85_ok login "login: a token and a refresh token"
    else
        c85_bad login "login: rc $rc, or no token and refresh token in its two export lines"
        C85_TOKEN="" C85_REFRESH=""
    fi
    if c85_word "$C85_REFRESH"; then
        c85_as refresh login-refresh login
        rc=$?
        new="$(sed -n 's/^export LLDAP_TOKEN=//p' "$C85_D/login-refresh.txt" | head -1)"
        if [ "$rc" = 0 ] && c85_word "$new"; then
            c85_ok login-refresh "login by LLDAP_REFRESHTOKEN alone: a new token, used from here on"
            C85_TOKEN="$new"
        else
            c85_bad login-refresh "login by LLDAP_REFRESHTOKEN alone: rc $rc, or no token"
        fi
    fi
    # Without the tool's own token the other rows still run, on one the gate asks for.
    c85_word "$C85_TOKEN" || C85_TOKEN="$(gate_login "$C85_ADMIN" "$C85_ADMIN_PASS" 2>>"$C85_D/gate.err")"
    c85_word "$C85_TOKEN"
}

c85_schema_rows() {
    local rc
    c85_row schema-attribute-user-add-string 'new user attribute: cli85ustr$' \
        schema attribute user add cli85ustr string -v -e
    c85_row schema-attribute-user-add-list 'new user attribute: cli85ulist$' \
        schema attribute user add cli85ulist string -l -v -e
    c85_row schema-attribute-user-add-integer 'new user attribute: cli85uint$' \
        schema attribute user add cli85uint integer -v -e
    c85_row schema-attribute-user-add-date 'new user attribute: cli85udate$' \
        schema attribute user add cli85udate date_time -v -e
    c85_row schema-attribute-user-add-jpeg 'new user attribute: cli85ujpeg$' \
        schema attribute user add cli85ujpeg jpeg_photo -v -e
    c85_as token schema-attribute-user-list schema attribute user list
    rc=$?
    if [ "$rc" = 0 ] && c85_has schema-attribute-user-list '^cli85ustr +STRING +false +true +true$' &&
        c85_has schema-attribute-user-list '^cli85ulist +STRING +true +true +true$' &&
        c85_has schema-attribute-user-list '^cli85uint +INTEGER +false ' &&
        c85_has schema-attribute-user-list '^cli85udate +DATE_TIME +false '; then
        c85_ok schema-attribute-user-list "schema attribute user list: the four new attributes with their types and flags"
    else
        c85_bad schema-attribute-user-list "schema attribute user list: rc $rc, or a new attribute's row is not as added"
    fi
    C85_PHOTO_TYPE="$(sed -n 's/^avatar  *\([A-Z_]*\) .*/\1/p' "$C85_D/schema-attribute-user-list.txt" | head -1)"
    c85_type_row schema-attribute-user-list-jpeg schema-attribute-user-list cli85ujpeg "schema attribute user list"

    c85_row schema-attribute-group-add-string 'new group attribute: cli85gstr$' \
        schema attribute group add cli85gstr string -v -e
    c85_row schema-attribute-group-add-list 'new group attribute: cli85glist$' \
        schema attribute group add cli85glist string -l -v -e
    c85_row schema-attribute-group-add-jpeg 'new group attribute: cli85gjpeg$' \
        schema attribute group add cli85gjpeg jpeg_photo -v -e
    c85_as token schema-attribute-group-list schema attribute group list
    rc=$?
    if [ "$rc" = 0 ] && c85_has schema-attribute-group-list '^cli85gstr +STRING +false +true +true$' &&
        c85_has schema-attribute-group-list '^cli85glist +STRING +true +true +true$'; then
        c85_ok schema-attribute-group-list "schema attribute group list: the two new text attributes with their flags"
    else
        c85_bad schema-attribute-group-list "schema attribute group list: rc $rc, or a new attribute's row is not as added"
    fi
    c85_type_row schema-attribute-group-list-jpeg schema-attribute-group-list cli85gjpeg "schema attribute group list"

    c85_row schema-objectclass-user-add "extra user object class: $C85_USER_CLASS\$" \
        schema objectclass user add "$C85_USER_CLASS"
    c85_row schema-objectclass-user-list '^cli85[Uu]ser[Cc]lass$' schema objectclass user list
    c85_row schema-objectclass-group-add "extra group object class: $C85_GROUP_CLASS\$" \
        schema objectclass group add "$C85_GROUP_CLASS"
    c85_row schema-objectclass-group-list '^cli85[Gg]roup[Cc]lass$' schema objectclass group list
}

c85_user_rows() {
    local rc mail="$C85_USER@gate.test"
    c85_row user-add "^Created user: $C85_USER\$" \
        user add "$C85_USER" "$mail" -d "Cli Eightyfive" -f Cli -l Eightyfive
    c85_row user-list "^$C85_USER\$" user list
    c85_row user-list-uid "^$C85_USER\$" user list uid
    c85_row user-list-email "^$C85_USER@gate\\.test\$" user list email
    c85_row user-info '^User ID \(user_id\) ' user info
    c85_row user-info-uid "^$C85_USER +$C85_USER@gate\\.test +Cli Eightyfive\$" user info "$C85_USER"
    c85_row user-info-email "^$C85_USER +$C85_USER@gate\\.test +Cli Eightyfive\$" user info "$mail"
    c85_row user-attribute-list '^mail$' user attribute list "$C85_USER"
    c85_row user-attribute-values "^$C85_USER@gate\\.test\$" user attribute values "$C85_USER" mail

    c85_row user-update-set "^Attribute set for user: $C85_USER, attribute: cli85ustr, value: hello\$" \
        user update set "$C85_USER" cli85ustr hello
    c85_row user-attribute-values-set '^hello$' user attribute values "$C85_USER" cli85ustr
    c85_row user-update-clear "^Attribute cleared for user: $C85_USER, attribute: cli85ustr\$" \
        user update clear "$C85_USER" cli85ustr
    c85_gone user-attribute-values-cleared '^hello$' user attribute values "$C85_USER" cli85ustr
    c85_row user-update-add "^Attribute list value added for user: $C85_USER, attribute: cli85ulist, value: one\$" \
        user update add "$C85_USER" cli85ulist one
    c85_row user-update-add-second "^Attribute list value added for user: $C85_USER, attribute: cli85ulist, value: two\$" \
        user update add "$C85_USER" cli85ulist two
    c85_as token user-attribute-values-list user attribute values "$C85_USER" cli85ulist
    rc=$?
    if [ "$rc" = 0 ] && c85_has user-attribute-values-list '^one$' && c85_has user-attribute-values-list '^two$'; then
        c85_ok user-attribute-values-list "user attribute values $C85_USER cli85ulist: one and two"
    else
        c85_bad user-attribute-values-list "user attribute values $C85_USER cli85ulist: rc $rc, wanted one and two"
    fi
    c85_row user-update-del "^Attribute list value deleted for user: $C85_USER, attribute: cli85ulist, value: one\$" \
        user update del "$C85_USER" cli85ulist one
    c85_gone user-attribute-values-deleted '^one$' user attribute values "$C85_USER" cli85ulist
    c85_row user-update-del-last "^Attribute cleared for user: $C85_USER, attribute: cli85ulist\$" \
        user update del "$C85_USER" cli85ulist two
    c85_row user-update-set-integer "attribute: cli85uint, value: 42\$" user update set "$C85_USER" cli85uint 42
    c85_row user-attribute-values-integer '^42$' user attribute values "$C85_USER" cli85uint
    c85_row user-update-set-date "attribute: cli85udate, value: 2026-01-02T03:04:05Z\$" \
        user update set "$C85_USER" cli85udate 2026-01-02T03:04:05Z
    c85_row user-attribute-values-date '^2026-01-02T03:04:05' user attribute values "$C85_USER" cli85udate

    c85_row user-update-set-displayname "^Attribute set for user: $C85_USER, attribute: displayname, value: Cli Renamed\$" \
        user update set "$C85_USER" displayname "Cli Renamed"
    c85_row user-attribute-values-displayname '^Cli Renamed$' user attribute values "$C85_USER" displayname

    c85_as token user-attribute-values-display_name user attribute values "$C85_USER" display_name
    rc=$?
    if [ "$rc" = 0 ] && c85_has user-attribute-values-display_name '^Cli Renamed$'; then
        c85_ok user-attribute-values-display_name "user attribute values $C85_USER display_name"
    elif [ "$rc" = 0 ] && [ ! -s "$C85_D/user-attribute-values-display_name.txt" ]; then
        c85_diff user-attribute-values-display_name "user attribute values $C85_USER display_name: nothing; KLLDAP gives the attribute as displayname and takes display_name only as an alias; LLDAP gives display_name"
    else
        c85_bad user-attribute-values-display_name "user attribute values $C85_USER display_name: rc $rc"
    fi
    c85_as token user-update-set-display_name user update set "$C85_USER" display_name "Cli Again"
    rc=$?
    if [ "$rc" != 0 ] || [ "$(c85_user_field "$C85_USER" displayName)" != "Cli Again" ]; then
        c85_bad user-update-set-display_name "user update set $C85_USER display_name: rc $rc, or the name is not set"
    elif c85_has user-update-set-display_name 'is not part of user schema'; then
        c85_diff user-update-set-display_name "user update set $C85_USER display_name: set, after 'Attribute display_name is not part of user schema': KLLDAP lists displayname and takes display_name as an alias"
    else
        c85_ok user-update-set-display_name "user update set $C85_USER display_name"
    fi
    c85_as token user-update-clear-last_name user update clear "$C85_USER" last_name
    rc=$?
    if [ "$rc" = 0 ] && c85_has user-update-clear-last_name '^Attribute cleared for user'; then
        c85_ok user-update-clear-last_name "user update clear $C85_USER last_name"
    elif c85_has user-update-clear-last_name 'has no value set for user'; then
        c85_diff user-update-clear-last_name "user update clear $C85_USER last_name: refused as unset; the tool reads the value under last_name and KLLDAP gives it as lastname"
    else
        c85_bad user-update-clear-last_name "user update clear $C85_USER last_name: rc $rc"
    fi
    c85_row user-update-clear-lastname "^Attribute cleared for user: $C85_USER, attribute: lastname\$" \
        user update clear "$C85_USER" lastname
}

c85_photo_rows() {
    local rc
    c85_as token user-add-avatar user add "$C85_AV_USER" "$C85_AV_USER@gate.test" -a "$C85_AVATAR"
    rc=$?
    if [ "$rc" = 0 ] && c85_has user-add-avatar "^Created user: $C85_AV_USER\$" &&
        c85_word "$(c85_user_field "$C85_AV_USER" avatar)" &&
        [ "$(c85_user_field "$C85_AV_USER" avatar)" != None ]; then
        c85_ok user-add-avatar "user add $C85_AV_USER -a: the user has a picture"
    else
        c85_bad user-add-avatar "user add $C85_AV_USER -a: rc $rc, or the user has no picture"
    fi
    c85_row user-attribute-values-avatar '^/9j/' user attribute values "$C85_AV_USER" avatar
    c85_file_row user-update-set-avatar user update set "$C85_AV_USER" avatar "$C85_AVATAR"
    c85_row user-update-clear-avatar "^Attribute cleared for user: $C85_AV_USER, attribute: avatar\$" \
        user update clear "$C85_AV_USER" avatar
}

c85_password_rows() {
    local rc
    c85_as token user-add-password user add "$C85_PW_USER" "$C85_PW_USER@gate.test" -p "$C85_PW1"
    rc=$?
    if [ "$rc" = 0 ] && c85_has user-add-password "^Created user: $C85_PW_USER\$" && c85_bind "$C85_PW_USER" "$C85_PW1"; then
        c85_ok user-add-password "user add $C85_PW_USER -p: the user binds with it (lldap_set_password is the image's, through the phase's shim)"
    else
        c85_bad user-add-password "user add $C85_PW_USER -p: rc $rc, or no bind with the password"
    fi
    c85_as token user-update-set-password user update set "$C85_PW_USER" password "$C85_PW2"
    rc=$?
    if [ "$rc" = 0 ] && c85_bind "$C85_PW_USER" "$C85_PW2" && ! c85_bind "$C85_PW_USER" "$C85_PW1"; then
        c85_ok user-update-set-password "user update set $C85_PW_USER password: the new one binds, the old one does not"
    else
        c85_bad user-update-set-password "user update set $C85_PW_USER password: rc $rc, or the binds are not new yes, old no"
    fi
}

c85_group_rows() {
    local rc
    c85_row group-add "^Created group: $C85_GROUP\$" group add "$C85_GROUP"
    c85_row group-list " $C85_GROUP\$" group list
    c85_row user-group-add '"ok": *true' user group add "$C85_USER" "$C85_GROUP"
    c85_row user-group-list "^$C85_GROUP\$" user group list "$C85_USER"
    c85_row group-info "^$C85_USER\$" group info "$C85_GROUP"
    c85_row user-group-del '"ok": *true' user group del "$C85_USER" "$C85_GROUP"
    c85_gone user-group-list-after "^$C85_GROUP\$" user group list "$C85_USER"

    c85_row group-update-set "^Attribute set for group: $C85_GROUP, attribute: cli85gstr, value: hello\$" \
        group update set "$C85_GROUP" cli85gstr hello
    c85_row group-attribute-list '^cli85gstr$' group attribute list "$C85_GROUP"
    c85_row group-attribute-values '^hello$' group attribute values "$C85_GROUP" cli85gstr
    c85_row group-update-clear "^Attribute cleared for group: $C85_GROUP, attribute: cli85gstr\$" \
        group update clear "$C85_GROUP" cli85gstr
    c85_row group-update-add "^Attribute list value added for group: $C85_GROUP, attribute: cli85glist, value: one\$" \
        group update add "$C85_GROUP" cli85glist one
    c85_row group-update-add-second "^Attribute list value added for group: $C85_GROUP, attribute: cli85glist, value: two\$" \
        group update add "$C85_GROUP" cli85glist two
    c85_row group-update-del "^Attribute list value deleted for group: $C85_GROUP, attribute: cli85glist, value: one\$" \
        group update del "$C85_GROUP" cli85glist one
    c85_as token group-attribute-values-list group attribute values "$C85_GROUP" cli85glist
    rc=$?
    if [ "$rc" = 0 ] && c85_has group-attribute-values-list '^two$' && ! c85_has group-attribute-values-list '^one$'; then
        c85_ok group-attribute-values-list "group attribute values $C85_GROUP cli85glist: two, and one is gone"
    else
        c85_bad group-attribute-values-list "group attribute values $C85_GROUP cli85glist: rc $rc, wanted two alone"
    fi
    c85_file_row group-update-set-jpeg group update set "$C85_GROUP" cli85gjpeg "$C85_AVATAR"
}

c85_delete_rows() {
    local name
    c85_row user-del-email "^Deleted user: $C85_USER\$" user del "$C85_USER@gate.test"
    c85_row user-del "^Deleted user: $C85_PW_USER\$" user del "$C85_PW_USER"
    c85_row user-del-avatar "^Deleted user: $C85_AV_USER\$" user del "$C85_AV_USER"
    c85_gone user-list-after "^cli85(u|pw|av)\$" user list
    c85_row group-del "^Deleted group: $C85_GROUP\$" group del "$C85_GROUP"
    c85_gone group-list-after " $C85_GROUP\$" group list
    for name in "${C85_USER_ATTRS[@]}"; do
        c85_row "schema-attribute-user-del-$name" "^Deleted from schema user attribute: $name\$" \
            schema attribute user del "$name"
    done
    for name in "${C85_GROUP_ATTRS[@]}"; do
        c85_row "schema-attribute-group-del-$name" "^Deleted from schema group attribute: $name\$" \
            schema attribute group del "$name"
    done
    c85_row schema-objectclass-user-del "extra user object class: $C85_USER_CLASS\$" \
        schema objectclass user del "$C85_USER_CLASS"
    c85_gone schema-objectclass-user-list-after '^cli85[Uu]ser[Cc]lass$' schema objectclass user list
    c85_row schema-objectclass-group-del "extra group object class: $C85_GROUP_CLASS\$" \
        schema objectclass group del "$C85_GROUP_CLASS"
    c85_gone schema-objectclass-group-list-after '^cli85[Gg]roup[Cc]lass$' schema objectclass group list
}

c85_sign_out_rows() {
    local rc
    if ! c85_word "$C85_REFRESH"; then
        p_bad "[CLI.logout] lldap-cli logout: not run, the login row gave no refresh token"
        return
    fi
    c85_as session logout logout
    rc=$?
    if [ "$rc" = 0 ] && c85_has logout '^unset LLDAP_TOKEN$' && c85_has logout '^unset LLDAP_REFRESHTOKEN$'; then
        c85_ok logout "logout: the two unset lines"
    else
        c85_bad logout "logout: rc $rc, or no unset lines"
    fi
    c85_as token logout-token user list
    if c85_has logout-token "^$C85_ADMIN\$"; then
        c85_bad logout-token "user list by the token after logout: it still lists the users"
    else
        c85_ok logout-token "user list by the token after logout: refused"
    fi
}

# shellcheck disable=SC2016
c85_cleanup() {
    local name gid left
    for name in "$C85_USER" "$C85_PW_USER" "$C85_AV_USER" "$C85_ADMIN"; do
        c85_gql 'mutation($u: String!) { deleteUser(userId: $u) { ok } }' '{"u": "'"$name"'"}' >/dev/null
    done
    gid="$(c85_group_id "$C85_GROUP")"
    [ -n "$gid" ] &&
        c85_gql 'mutation($g: Int!) { deleteGroup(groupId: $g) { ok } }' '{"g": '"$gid"'}' >/dev/null
    for name in "${C85_USER_ATTRS[@]}"; do
        c85_gql 'mutation($n: String!) { deleteUserAttribute(name: $n) { ok } }' '{"n": "'"$name"'"}' >/dev/null
    done
    for name in "${C85_GROUP_ATTRS[@]}"; do
        c85_gql 'mutation($n: String!) { deleteGroupAttribute(name: $n) { ok } }' '{"n": "'"$name"'"}' >/dev/null
    done
    c85_gql 'mutation($n: String!) { deleteUserObjectClass(name: $n) { ok } }' '{"n": "'"$C85_USER_CLASS"'"}' >/dev/null
    c85_gql 'mutation($n: String!) { deleteGroupObjectClass(name: $n) { ok } }' '{"n": "'"$C85_GROUP_CLASS"'"}' >/dev/null
    left="$(c85_gql '{ users { id } groups { displayName } schema {
        userSchema { attributes { name } extraLdapObjectClasses }
        groupSchema { attributes { name } extraLdapObjectClasses } } }' | python3 -c '
import json, sys
d = json.load(sys.stdin)
names = [u["id"] for u in d["users"]] + [g["displayName"] for g in d["groups"]]
for side in ("userSchema", "groupSchema"):
    names += [a["name"] for a in d["schema"][side]["attributes"]] + d["schema"][side]["extraLdapObjectClasses"]
print(" ".join(n for n in names if n.lower().startswith("cli85")) or "none")' 2>/dev/null)"
    case "$left" in
    none) p_ok "[CLI.clean] none of the phase's users, groups, attributes and object classes is left" ;;
    "") p_bad "[CLI.clean] the server could not be read after the phase (see gate.err)" ;;
    *) p_bad "[CLI.clean] left on the server: $left" ;;
    esac
}

if [ -z "${GATE_LLDAP_CLI:-}" ]; then
    p_skip "GATE_LLDAP_CLI not set"
elif [ ! -x "$C85_TOOL" ]; then
    p_bad "GATE_LLDAP_CLI=$GATE_LLDAP_CLI: $C85_TOOL is not executable"
elif c85_tools; then
    if c85_setup; then
        if c85_sign_in_rows; then
            c85_schema_rows
            c85_user_rows
            c85_photo_rows
            c85_password_rows
            c85_group_rows
            c85_delete_rows
            c85_sign_out_rows
        else
            p_bad "[CLI.token] no token for $C85_ADMIN: the rows after the sign-in did not run"
        fi
    fi
    c85_cleanup
    note "[NOTE] ${PHASE}: $C85_DIFFS expected difference(s) from LLDAP, each a [DIFF] line above"
fi
