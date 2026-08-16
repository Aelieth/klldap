#!/usr/bin/env bash
#
# Regenerates the committed stock-lldap migration fixtures in
# server/tests/fixtures/ (lldap_v11.sql, fixture.md).
#
# This is a manual tool, not part of CI: it boots a *stock* upstream lldap
# server (tag v0.6.3, schema v11) on a temporary database, creates the fixture
# content through its real GraphQL API and OPAQUE password registration, then
# dumps the result. The committed fixtures are consumed by
# server/tests/migration_compat.rs to prove that a genuine lldap database migrates
# into KLLDAP with its data intact (passwords are set again under a fresh key).
#
# Usage:
#   git clone https://github.com/lldap/lldap /tmp/lldap-stock
#   git -C /tmp/lldap-stock checkout v0.6.3
#   LLDAP_SRC=/tmp/lldap-stock scripts/generate_lldap_fixture.sh
#
# The stock checkout's rust-toolchain.toml (1.89.0) is honored by rustup.
# Requires: bash, python3 (stdlib only). No sqlite3 CLI needed.

set -euo pipefail

LLDAP_SRC="${LLDAP_SRC:?Set LLDAP_SRC to a stock lldap checkout at tag v0.6.3}"
FIXTURES_DIR="$(cd "$(dirname "$0")/.." && pwd)/server/tests/fixtures"
HTTP_PORT="${FIXTURE_HTTP_PORT:-27170}"
LDAP_PORT="${FIXTURE_LDAP_PORT:-23890}"
BASE_URL="http://localhost:${HTTP_PORT}"

# Fixture constants. These are mirrored in fixture.md and asserted verbatim by
# migration_compat.rs — change them in all three places or not at all.
ADMIN_PASS="FixtureAdminPass2026!"
BOB_PASS="FixtureBobPass2026!"
DATE_VALUE="2024-05-01T12:00:00Z"
GROUP_NAME="Fixture Crew"
GROUP_NOTE="stock group attribute survives"
# A genuine 4x4 baseline JPEG (649 bytes); stock validates JpegPhoto values.
JPEG_B64="/9j/4AAQSkZJRgABAgAAAQABAAD/wAARCAAEAAQDAREAAhEBAxEB/9sAQwAIBgYHBgUIBwcHCQkICgwUDQwLCwwZEhMPFB0aHx4dGhwcICQuJyAiLCMcHCg3KSwwMTQ0NB8nOT04MjwuMzQy/9sAQwEJCQkMCwwYDQ0YMiEcITIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDa8KW8f9gQfLXLmGT4T279093NKkvrMj//2Q=="

if ! tag="$(git -C "$LLDAP_SRC" describe --tags --exact-match 2>/dev/null)" \
    || [[ "$tag" != "v0.6.3" ]]; then
    echo "WARNING: LLDAP_SRC is not exactly at tag v0.6.3 (found: ${tag:-none})." >&2
    echo "         The dump-time schema check will abort if this is not v11." >&2
fi

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "Building stock lldap + lldap_set_password from $LLDAP_SRC ..."
(cd "$LLDAP_SRC" && cargo build -p lldap -p lldap_set_password)
BIN="${CARGO_TARGET_DIR:-$LLDAP_SRC/target}/debug"

lldap_env() {
    env LLDAP_DATABASE_URL="sqlite://$WORK/fixture.db?mode=rwc" \
        LLDAP_KEY_FILE="$WORK/server_key" \
        LLDAP_KEY_SEED="" \
        LLDAP_JWT_SECRET="fixture-jwt-secret" \
        LLDAP_LDAP_USER_DN="admin" \
        LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        LLDAP_HTTP_PORT="$HTTP_PORT" \
        LLDAP_LDAP_PORT="$LDAP_PORT" \
        "$@"
}

echo "Booting stock lldap on ports $HTTP_PORT (http) / $LDAP_PORT (ldap) ..."
lldap_env "$BIN/lldap" run --config-file=/dev/null >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

healthy=""
for _ in $(seq 1 60); do
    if lldap_env "$BIN/lldap" healthcheck --config-file=/dev/null >/dev/null 2>&1; then
        healthy=1
        break
    fi
    sleep 0.5
done
if [[ -z "$healthy" ]]; then
    echo "Stock server did not become healthy; log follows:" >&2
    cat "$WORK/server.log" >&2
    exit 1
fi

TOKEN="$(LOGIN_URL="$BASE_URL/auth/simple/login" LOGIN_PASS="$ADMIN_PASS" python3 - <<'PY'
import json, os, urllib.request
req = urllib.request.Request(
    os.environ["LOGIN_URL"],
    data=json.dumps({"username": "admin", "password": os.environ["LOGIN_PASS"]}).encode(),
    headers={"Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["token"])
PY
)"

# gq <query> <variables-json>: POST to GraphQL, abort on errors, print data JSON.
gq() {
    GQ_QUERY="$1" GQ_VARS="$2" GQ_URL="$BASE_URL/api/graphql" GQ_TOKEN="$TOKEN" \
        python3 - <<'PY'
import json, os, sys, urllib.request
req = urllib.request.Request(
    os.environ["GQ_URL"],
    data=json.dumps({"query": os.environ["GQ_QUERY"],
                     "variables": json.loads(os.environ["GQ_VARS"])}).encode(),
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer " + os.environ["GQ_TOKEN"]})
body = json.load(urllib.request.urlopen(req))
if body.get("errors"):
    sys.exit("GraphQL error: " + json.dumps(body["errors"]))
json.dump(body["data"], sys.stdout)
PY
}

echo "Creating custom attribute schema ..."
ADD_USER_ATTR='mutation($n: String!, $t: AttributeType!, $l: Boolean!) {
  addUserAttribute(name: $n, attributeType: $t, isList: $l, isVisible: true, isEditable: true) { ok } }'
gq "$ADD_USER_ATTR" '{"n": "fixturejpeg", "t": "JPEG_PHOTO", "l": false}' >/dev/null
gq "$ADD_USER_ATTR" '{"n": "fixturedate", "t": "DATE_TIME", "l": false}' >/dev/null
gq "$ADD_USER_ATTR" '{"n": "fixturetags", "t": "STRING", "l": true}' >/dev/null
gq "$ADD_USER_ATTR" '{"n": "fixturenumber", "t": "INTEGER", "l": false}' >/dev/null
gq 'mutation($n: String!, $t: AttributeType!) {
      addGroupAttribute(name: $n, attributeType: $t, isList: false, isVisible: true, isEditable: true) { ok } }' \
    '{"n": "fixturegroupnote", "t": "STRING"}' >/dev/null

echo "Creating users, group, membership ..."
gq 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "bob", "email": "bob@example.com", "displayName": "Bob Fixture",
            "firstName": "Bincode Bob", "lastName": "Fixtureson"}}' >/dev/null
gq 'mutation($u: UpdateUserInput!) { updateUser(user: $u) { ok } }' \
    '{"u": {"id": "bob", "avatar": "'"$JPEG_B64"'", "insertAttributes": [
        {"name": "fixturejpeg", "value": ["'"$JPEG_B64"'"]},
        {"name": "fixturedate", "value": ["'"$DATE_VALUE"'"]},
        {"name": "fixturetags", "value": ["alpha", "beta"]},
        {"name": "fixturenumber", "value": ["4242"]}]}}' >/dev/null
gq 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "charlie", "email": "charlie@example.com"}}' >/dev/null

GID="$(gq 'mutation($n: String!) { createGroup(name: $n) { id } }' \
    '{"n": "'"$GROUP_NAME"'"}' | python3 -c 'import sys, json; print(json.load(sys.stdin)["createGroup"]["id"])')"
gq 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
    '{"u": "bob", "g": '"$GID"'}' >/dev/null
gq 'mutation($g: UpdateGroupInput!) { updateGroup(group: $g) { ok } }' \
    '{"g": {"id": '"$GID"', "insertAttributes": [
        {"name": "fixturegroupnote", "value": ["'"$GROUP_NOTE"'"]}]}}' >/dev/null

echo "Registering bob's password through stock OPAQUE ..."
"$BIN/lldap_set_password" --base-url "$BASE_URL" --token "$TOKEN" \
    --username bob --password "$BOB_PASS"

echo "Stopping the stock server ..."
kill -TERM "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

mkdir -p "$FIXTURES_DIR"

echo "Dumping to $FIXTURES_DIR/lldap_v11.sql ..."
FIXTURE_DB="$WORK/fixture.db" OUT_SQL="$FIXTURES_DIR/lldap_v11.sql" python3 - <<'PY'
import os, sqlite3
conn = sqlite3.connect(os.environ["FIXTURE_DB"])
version = conn.execute("SELECT version FROM metadata").fetchone()[0]
assert version == 11, f"expected stock schema v11, found v{version}"
hashes = dict(conn.execute("SELECT user_id, password_hash IS NOT NULL FROM users"))
assert hashes == {"admin": 1, "bob": 1, "charlie": 0}, hashes
with open(os.environ["OUT_SQL"], "w") as f:
    f.write("-- Genuine stock lldap v0.6.3 (schema v11) SQLite dump.\n")
    f.write("-- Generated by scripts/generate_lldap_fixture.sh; constants in fixture.md.\n")
    for line in conn.iterdump():
        f.write(line + "\n")
PY

SRC_COMMIT="$(git -C "$LLDAP_SRC" rev-parse HEAD)"
GENERATED="$(date -u +%Y-%m-%d)"
cat >"$FIXTURES_DIR/fixture.md" <<EOF
# Stock lldap migration fixture

Genuine artifacts from stock upstream lldap **v0.6.3** (schema **v11**), produced by
\`scripts/generate_lldap_fixture.sh\` on $GENERATED from commit \`$SRC_COMMIT\`:
the server booted on a fresh SQLite database, all content was created through its
GraphQL API, and both passwords were registered through the real OPAQUE flows
(admin at first boot, bob via \`lldap_set_password\`). \`lldap_v11.sql\` is the
python-\`iterdump\` of the resulting database. Consumed by
\`server/tests/migration_compat.rs\`, which adopts it under a fresh key: the stock
passwords are only asserted to be gone.

## Constants (asserted by the test — keep in sync with the script)

| What | Value |
|---|---|
| admin password | \`FixtureAdminPass2026!\` |
| bob password | \`FixtureBobPass2026!\` |
| bob email / display / first / last | \`bob@example.com\` / \`Bob Fixture\` / \`Bincode Bob\` / \`Fixtureson\` |
| bob avatar + \`fixturejpeg\` (JPEG_PHOTO) | the 649-byte JPEG, base64 in the script; byte-identical after migration |
| \`fixturedate\` (DATE_TIME) | \`2024-05-01T12:00:00Z\` (epoch 1714564800 after re-encode) |
| \`fixturetags\` (STRING list) | \`["alpha", "beta"]\` |
| \`fixturenumber\` (INTEGER) | \`4242\` |
| group | \`Fixture Crew\`, member: bob, \`fixturegroupnote\` = \`stock group attribute survives\` |
| charlie | no password ever registered (bind must fail cleanly) |

UUIDs and creation/modification dates are whatever generation produced — the test
asserts the constants above, not those. Regeneration rewrites both files; diff
before committing.
EOF

echo "Done. Fixtures written to $FIXTURES_DIR/"
