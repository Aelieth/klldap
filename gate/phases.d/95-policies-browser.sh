# shellcheck shell=bash
# Phase: the policies workbench in a headless browser. Gate files only.

D="$(phase_dir)"
BROWSER_IMAGE="mcr.microsoft.com/playwright@sha256:766137e2d9caad4744187e53cdc89320ba6f2eb57cff097374020944b44dd0a9"
BROWSER_CTN="klldap-p3-${RUNID}"
TAG="$(printf '%s' "$RUNID" | tr -cd '0-9A-Za-z')"
PLAIN_USER="p3p${TAG}"
RO_USER="p3r${TAG}"
PRIMARY="p3o${TAG}"
CHILD_OU_NAME="p3c${TAG}"
CHILD_KEY="${PRIMARY}\\${CHILD_OU_NAME}"
FRONT="p3f${TAG}"
EDITED="p3e${TAG}"
OTHER="p3x${TAG}"
BADINT="p3i${TAG}"
BADHOURS="p3h${TAG}"
WARN_USER="p3a${TAG}"
WARN_OU="p3v${TAG}"
WARN_POLICY="p3n${TAG}"
OUT="$D/policies.out"

p3_pass() {
    python3 -c 'import secrets; print("Gw" + secrets.token_hex(8))'
}

p3_summary() {
    local rows=0 pass=0 finding=0 notes=0
    if [ -f "$OUT" ]; then
        rows="$(grep -c '^ROW ' "$OUT" || true)"
        pass="$(grep -c '^ROW [^ ]* PASS' "$OUT" || true)"
        finding="$(grep -c '^ROW [^ ]* FINDING' "$OUT" || true)"
        notes="$(grep -c '^ROW [^ ]* NOTE' "$OUT" || true)"
    fi
    note "P3 rows=${rows} pass=${pass} FINDING=${finding} NOTE=${notes}"
}

p3_judge() {
    local name="$1" label="$2" line
    line="$(grep "^ROW ${name} " "$OUT" 2>/dev/null | head -1 || true)"
    if [ -z "$line" ]; then
        p_bad "${name}: ${label}: not reached"
        return
    fi
    case "$line" in
    "ROW ${name} PASS"*)
        p_ok "${name}: ${label}"
        ;;
    "ROW ${name} FINDING"*)
        note "FINDING ${name}: ${label}: ${line#ROW "${name}" FINDING }"
        ;;
    "ROW ${name} NOTE"*)
        note "NOTE ${name}: ${label}: ${line#ROW "${name}" NOTE }"
        ;;
    *)
        p_bad "${name}: ${label} (${line#ROW "${name}" })"
        ;;
    esac
}

# Every catalog item is enforced, so the page shows no not-enforced notice at all.
p3_notice() {
    local line
    line="$(grep "^ROW notice " "$OUT" 2>/dev/null | head -1 || true)"
    if [ -n "$UNENFORCED" ]; then
        p_bad "notice: the catalog still lists items that are not enforced: ${UNENFORCED}"
    elif [ "$line" = "ROW notice PASS the catalog has no unenforced item" ]; then
        p_ok "notice: no not-enforced notice, every catalog item is enforced"
    else
        p3_judge notice "no not-enforced notice"
    fi
}

p3_match() {
    local line result
    line="$(grep "^ROW graphql-match PASS " "$OUT" 2>/dev/null | head -1 || true)"
    if [ -z "$line" ]; then
        p3_judge graphql-match "matches each value to effectivePolicyItems"
        return
    fi
    if ! result="$(ROW_LINE="$line" EFFECTIVE="$D/effective.json" python3 - 2>&1 <<'PY'
import json, os, sys
line = os.environ["ROW_LINE"]
detail = line.split(" ", 3)[3] if line.count(" ") >= 3 else ""
page = {}
for part in detail.split(";"):
    part = part.strip()
    if " page=" not in part:
        continue
    key, shown = part.split(" page=", 1)
    page[key] = shown
expect_page = {
    "enable-mfa": "always",
    "lockout-threshold": "3 tries",
    "lockout-duration-seconds": "120 s",
    "login-hours": "Mon-Fri 09:00-17:00",
    "allowed-networks": "10.0.0.0/8",
    "inactivity-days": "30 days",
}
expect_raw = {
    "enable-mfa": "always",
    "lockout-threshold": "3",
    "lockout-duration-seconds": "120",
    "login-hours": "Mon-Fri 09:00-17:00",
    "allowed-networks": "10.0.0.0/8",
    "inactivity-days": "30",
}
with open(os.environ["EFFECTIVE"], encoding="utf-8") as handle:
    data = json.load(handle)
items = {item["key"]: item["value"] for item in data["effectivePolicyItems"]}
bad = []
for key, shown in expect_page.items():
    if page.get(key) != shown:
        bad.append(f"{key} page={page.get(key)}")
    if items.get(key) != expect_raw[key]:
        bad.append(f"{key} gql={items.get(key)}")
if bad:
    print("mismatch " + "; ".join(bad))
    sys.exit(1)
print("ok")
PY
)"; then
        p_bad "graphql-match: ${result}"
        return
    fi
    p_ok "graphql-match: matches each value to effectivePolicyItems"
}

p3_cleanup() {
    local action id name
    graphql '{ listOus }' '{}' >"$D/cleanup-ous.json" 2>"$D/cleanup-ous.err" || true
    graphql '{ policies { id name } }' '{}' >"$D/cleanup-policies.json" 2>"$D/cleanup-policies.err" || true
    graphql '{ users { id } }' '{}' >"$D/cleanup-users.json" 2>"$D/cleanup-users.err" || true
    while IFS= read -r action; do
        [ -n "$action" ] || continue
        case "$action" in
        unblock)
            graphql "mutation(\$o: String!, \$b: Boolean!) { setOuPolicyInheritance(ou: \$o, blocked: \$b) { ok } }" \
                "$(CHILD_KEY="$CHILD_KEY" python3 -c 'import json,os; print(json.dumps({"o": os.environ["CHILD_KEY"], "b": False}))')" \
                >"$D/cleanup-unblock.json" 2>"$D/cleanup-unblock.err" \
                || p_bad "cleanup: could not turn the block switch off"
            ;;
        policy\ *)
            id="${action#policy }"
            graphql "mutation(\$p: Int!) { deletePolicy(policyId: \$p) { ok } }" \
                '{"p": '"$id"'}' >"$D/cleanup-policy-${id}.json" 2>"$D/cleanup-policy-${id}.err" \
                || p_bad "cleanup: could not delete policy ${id}"
            ;;
        ou\ *)
            name="${action#ou }"
            graphql "mutation(\$n: String!) { deleteOu(name: \$n) { ok } }" \
                "$(NAME="$name" python3 -c 'import json, os; print(json.dumps({"n": os.environ["NAME"]}))')" \
                >"$D/cleanup-ou.json" 2>"$D/cleanup-ou.err" \
                || p_bad "cleanup: could not delete OU ${name}"
            ;;
        user\ *)
            id="${action#user }"
            graphql "mutation(\$id: String!) { deleteUser(userId: \$id) { ok } }" \
                '{"id": "'"$id"'"}' >"$D/cleanup-user-${id}.json" 2>"$D/cleanup-user-${id}.err" \
                || p_bad "cleanup: could not delete user ${id}"
            ;;
        *)
            p_bad "cleanup: unexpected ${action}"
            ;;
        esac
    done < <(OUS="$D/cleanup-ous.json" POLICIES="$D/cleanup-policies.json" USERS="$D/cleanup-users.json" \
        CHILD_KEY="$CHILD_KEY" PRIMARY="$PRIMARY" \
        POLICY_NAMES="$(printf '%s\n' "$OTHER" "$FRONT" "$EDITED" "$BADINT" "$BADHOURS" "$WARN_POLICY")" \
        USER_NAMES="$(printf '%s\n' "$PLAIN_USER" "$RO_USER" "$WARN_USER")" WARN_OU="$WARN_OU" \
        python3 - <<'PY'
import json, os
def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
def named(value):
    return value.split("\n") if value else []
ous = load(os.environ["OUS"]).get("listOus") or []
policies = load(os.environ["POLICIES"]).get("policies") or []
users = load(os.environ["USERS"]).get("users") or []
child = os.environ["CHILD_KEY"]
primary = os.environ["PRIMARY"]
policy_names = set(named(os.environ.get("POLICY_NAMES", "")))
user_names = set(named(os.environ.get("USER_NAMES", "")))
if child in ous:
    print("unblock")
for policy in policies:
    if policy.get("name") in policy_names:
        print(f"policy {policy['id']}")
if child in ous:
    print(f"ou {child}")
if primary in ous:
    print(f"ou {primary}")
for user in users:
    if user.get("id") in user_names:
        print(f"user {user['id']}")
if os.environ["WARN_OU"] in ous:
    print(f"ou {os.environ['WARN_OU']}")
PY
)
}

# A phase admin alone in an OU of its own: only its own save can refuse it.
p3_warn_admin() {
    local gid
    gid="$(p3_group lldap_admin)"
    [ -n "$gid" ] &&
        graphql "mutation(\$n: String!) { createOu(name: \$n) { ok } }" '{"n": "'"$WARN_OU"'"}' >"$D/warn-ou.json" 2>&1 &&
        graphql "mutation(\$u: CreateUserInput!) { createUser(user: \$u) { id } }" \
            '{"u": {"id": "'"$WARN_USER"'", "email": "'"$WARN_USER"'@gate.test"}}' >"$D/warn-user.json" 2>&1 &&
        graphql "mutation(\$id: String!, \$pw: String!) { setUserPassword(userId: \$id, password: \$pw) { ok } }" \
            "$(ID="$WARN_USER" PW="$WARN_PASS" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "pw": os.environ["PW"]}))')" \
            >"$D/warn-pass.json" 2>&1 &&
        graphql "mutation(\$u: String!, \$g: Int!) { addUserToGroup(userId: \$u, groupId: \$g) { ok } }" \
            '{"u": "'"$WARN_USER"'", "g": '"$gid"'}' >"$D/warn-group.json" 2>&1 &&
        graphql "mutation(\$ids: [String!]!, \$ou: String!) { changeUserOu(userIds: \$ids, newOu: \$ou) { ok } }" \
            '{"ids": ["'"$WARN_USER"'"], "ou": "'"$WARN_OU"'"}' >"$D/warn-move.json" 2>&1
}

p3_group() {
    graphql '{ groups { id displayName } }' '{}' | GROUP="$1" python3 -c '
import json, os, sys
groups = json.load(sys.stdin)["groups"]
match = [g["id"] for g in groups if g["displayName"] == os.environ["GROUP"]]
print(match[0] if match else "")'
}

p3_run() {
    docker rm -f "$BROWSER_CTN" >/dev/null 2>&1 || true
    (
        export BROWSER_ADMIN_PASS="$ADMIN_PASS"
        export BROWSER_PLAIN_USER="$PLAIN_USER"
        export BROWSER_PLAIN_PASS="$PLAIN_PASS"
        export BROWSER_RO_USER="$RO_USER"
        export BROWSER_RO_PASS="$RO_PASS"
        export BROWSER_WARN_PASS="$WARN_PASS"
        timeout 300 docker run --rm --name "$BROWSER_CTN" \
            --network "$NET" \
            --init \
            --shm-size=1g \
            --user "$(id -u):$(id -g)" \
            --entrypoint node \
            -v "$GATE_ROOT/lib/browser-policies.mjs:/work/browser-policies.mjs:ro" \
            -v "$D:/out" \
            -e HOME=/tmp/home \
            -e BROWSER_OUT=/out \
            -e BROWSER_URL="http://${CONTAINER}:17170" \
            -e BROWSER_ADMIN_PASS \
            -e BROWSER_PLAIN_USER \
            -e BROWSER_PLAIN_PASS \
            -e BROWSER_RO_USER \
            -e BROWSER_RO_PASS \
            -e BROWSER_WARN_USER="$WARN_USER" \
            -e BROWSER_WARN_PASS \
            -e BROWSER_WARN_OU="$WARN_OU" \
            -e BROWSER_WARN_POLICY="$WARN_POLICY" \
            -e BROWSER_ZONE="$ZONE" \
            -e BROWSER_PRIMARY="$PRIMARY" \
            -e BROWSER_CHILD="$CHILD_OU_NAME" \
            -e BROWSER_FRONT="$FRONT" \
            -e BROWSER_EDITED="$EDITED" \
            -e BROWSER_OTHER="$OTHER" \
            -e BROWSER_BADINT="$BADINT" \
            -e BROWSER_BADHOURS="$BADHOURS" \
            -e BROWSER_UNENFORCED="$UNENFORCED" \
            -e BROWSER_SERVER_WIDE="$SERVER_WIDE" \
            "$BROWSER_IMAGE" /work/browser-policies.mjs \
            >"$OUT" 2>"$D/policies.err"
    ) &
    BROWSER_PID=$!
}

if ! docker image inspect "$BROWSER_IMAGE" >/dev/null 2>&1; then
    p_skip "browser image absent: ${BROWSER_IMAGE}"
    p3_summary
else
    EXTRA_CONTAINERS+=("$BROWSER_CTN")
    PLAIN_PASS="$(p3_pass)"
    RO_PASS="$(p3_pass)"
    WARN_PASS="$(p3_pass)"
    if [ -z "$TAG" ]; then
        p_bad "run id is empty"
    elif [ -z "$PLAIN_PASS" ] || [ -z "$RO_PASS" ] || [ -z "$WARN_PASS" ]; then
        p_bad "generated password is empty"
    else
        graphql "mutation(\$u: CreateUserInput!) { createUser(user: \$u) { id } }" \
            '{"u": {"id": "'"$PLAIN_USER"'", "email": "'"$PLAIN_USER"'@gate.test"}}' \
            >"$D/plain-user.json" 2>&1 || p_bad "createUser $PLAIN_USER failed"
        graphql "mutation(\$u: CreateUserInput!) { createUser(user: \$u) { id } }" \
            '{"u": {"id": "'"$RO_USER"'", "email": "'"$RO_USER"'@gate.test"}}' \
            >"$D/ro-user.json" 2>&1 || p_bad "createUser $RO_USER failed"
        graphql "mutation(\$id: String!, \$pw: String!) { setUserPassword(userId: \$id, password: \$pw) { ok } }" \
            '{"id": "'"$PLAIN_USER"'", "pw": "'"$PLAIN_PASS"'"}' \
            >"$D/plain-pass.json" 2>&1 || p_bad "setUserPassword $PLAIN_USER failed"
        graphql "mutation(\$id: String!, \$pw: String!) { setUserPassword(userId: \$id, password: \$pw) { ok } }" \
            '{"id": "'"$RO_USER"'", "pw": "'"$RO_PASS"'"}' \
            >"$D/ro-pass.json" 2>&1 || p_bad "setUserPassword $RO_USER failed"
        RO_GID="$(p3_group lldap_strict_readonly)"
        if [ -n "$RO_GID" ]; then
            graphql "mutation(\$u: String!, \$g: Int!) { addUserToGroup(userId: \$u, groupId: \$g) { ok } }" \
                '{"u": "'"$RO_USER"'", "g": '"$RO_GID"'}' \
                >"$D/ro-group.json" 2>&1 || p_bad "addUserToGroup lldap_strict_readonly failed"
        else
            p_bad "lldap_strict_readonly group not found"
        fi
        p3_warn_admin || p_bad "the phase admin $WARN_USER in $WARN_OU could not be made"
        # The main server sets no login_hours_timezone: its default is UTC.
        ZONE=UTC
        graphql '{ policyItemCatalog { key enforced } }' '{}' \
            >"$D/catalog.json" 2>"$D/catalog.err" || p_bad "policyItemCatalog failed"
        UNENFORCED="$(CATALOG="$D/catalog.json" python3 - <<'PY'
import json, os
try:
    with open(os.environ["CATALOG"], encoding="utf-8") as handle:
        items = json.load(handle).get("policyItemCatalog") or []
except (OSError, json.JSONDecodeError, AttributeError):
    items = []
print(",".join(
    item["key"] for item in items if item.get("enforced") is False and item.get("key")
))
PY
)"
        # The main server's explicit LLDAP_ENABLE_MFA=true, by the name the page gives it.
        SERVER_WIDE=enabled
        p3_run
        ready_for=$((SECONDS + 280))
        while [ ! -f "$D/graphql-match.ready" ] && [ "$SECONDS" -lt "$ready_for" ]; do
            if ! kill -0 "$BROWSER_PID" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done
        if [ -f "$D/graphql-match.ready" ]; then
            graphql "query(\$o: String!) { effectivePolicyItems(ou: \$o) { key value } }" \
                "$(CHILD_KEY="$CHILD_KEY" python3 -c 'import json,os; print(json.dumps({"o": os.environ["CHILD_KEY"]}))')" \
                >"$D/effective.json" 2>"$D/effective.err" || true
            : >"$D/graphql-match.done"
        fi
        wait "$BROWSER_PID" || true
        TOKEN="$(gate_login)" || p_bad "could not log in again after the browser"
        export TOKEN
        p3_judge admin-login "admin logs in"
        p3_judge create-ou "creates a primary OU and a child"
        p3_judge open-policies "opens the policies page on the child"
        p3_judge zone-note "the login-hours field says 'judged in UTC'"
        p3_judge address-note "the allowed-networks field says the address the server sees for this session"
        p3_judge save-controls "saves every rule"
        p3_judge reload-page "shows the six values after reload"
        p3_match
        p3_judge edit-policy "edits the policy name"
        p3_judge swap "swaps the attached policy"
        p3_judge block-inheritance "blocks inheritance on the child"
        p3_judge remove "removes the policy from the child"
        p3_judge delete-policy "deletes the policy: 'Policy <name> deleted'"
        p3_judge no-save-warning "no save warning after the five saves and the delete on the child, which holds no admin"
        p3_notice
        p3_judge override-line "the main server's explicit enable_mfa is said to override the OUs' enable-mfa"
        p3_judge empty-name "refuses an empty name"
        p3_judge invalid-int "refuses a lockout threshold of 101"
        p3_judge invalid-string "refuses a bad login-hours and a bad CIDR"
        p3_judge plain-user "a plain user is refused the page"
        p3_judge readonly "what a read-only admin is shown"
        p3_judge save-warning "a phase admin's own list that refuses it: the save stands with its warning and the way back, then the refused refetch is said in words, with no red alert"
        p3_cleanup
    fi
    p3_summary
    docker rm -f "$BROWSER_CTN" >/dev/null 2>&1 || true
fi
