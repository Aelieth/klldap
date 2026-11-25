# shellcheck shell=bash
# Gate library: tally, results, timeouts, container/GraphQL/LDAP helpers.
# Sourced by gate/run-gate.sh; every phase in gate/phases.d/ runs with these.

RED=""; GREEN=""; YELLOW=""; NC=""
if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
fi

PASS_N=0; FAIL_N=0; SKIP_N=0
# The image's ports inside the container (its Dockerfile ENV).
KDC_INNER_PORT=1088
KADMIN_INNER_PORT=1749
PHASE="setup"

note() { printf '%s\n' "$*"; }
p_ok() { PASS_N=$((PASS_N + 1)); note "${GREEN}[PASS]${NC} ${PHASE}: $1"; }
p_skip() { SKIP_N=$((SKIP_N + 1)); note "${YELLOW}[SKIP]${NC} ${PHASE}: $1"; }
p_bad() {
    FAIL_N=$((FAIL_N + 1))
    note "${RED}[FAIL]${NC} ${PHASE}: $1"
    if [ -n "${CONTAINER:-}" ]; then
        docker logs "$CONTAINER" >"$RESULTS_DIR/$PHASE-docker.log" 2>&1 || true
    fi
}

phase_dir() {
    mkdir -p "$RESULTS_DIR/$PHASE"
    printf '%s\n' "$RESULTS_DIR/$PHASE"
}

# t <cmd...>: run with the standard remote-op timeout.
t() { timeout "${GATE_TIMEOUT:-30}" "$@"; }

# gexec <cmd...>: run inside the main container (root, like the entrypoint).
gexec() { t docker exec "$CONTAINER" "$@"; }
# gexec_in <container> <cmd...>
gexec_in() { local c="$1"; shift; t docker exec "$c" "$@"; }

# uid_of_comm <name>: effective UID of the first in-container process with that comm,
# via /proc (the runtime image may lack ps/pgrep). The kernel truncates comm to 15
# characters, so the requested name is truncated to match. Prints nothing if not running.
uid_of_comm() {
    local want
    want="$(printf '%.15s' "$1")"
    gexec sh -c '
        for p in /proc/[0-9]*; do
            [ -r "$p/comm" ] || continue
            read -r comm <"$p/comm" || continue
            if [ "$comm" = "'"$want"'" ]; then
                awk "/^Uid:/ {print \$2; exit}" "$p/status"
                exit 0
            fi
        done
        exit 1'
}

# ---- HTTP / GraphQL (host-driven; python3 for JSON, no jq dependency) ----

http_url() { printf 'http://127.0.0.1:%s' "$HTTP_PORT"; }
ldap_url() { printf 'ldap://127.0.0.1:%s' "$LDAP_PORT"; }

# gate_login [user] [pass]: prints a bearer token.
gate_login() {
    local user="${1:-admin}" pass="${2:-$ADMIN_PASS}"
    LOGIN_URL="$(http_url)/auth/simple/login" LOGIN_USER="$user" LOGIN_PASS="$pass" \
        t python3 - <<'PY'
import json, os, sys, urllib.error, urllib.request
req = urllib.request.Request(
    os.environ["LOGIN_URL"],
    data=json.dumps({"username": os.environ["LOGIN_USER"],
                     "password": os.environ["LOGIN_PASS"]}).encode(),
    headers={"Content-Type": "application/json"})
try:
    print(json.load(urllib.request.urlopen(req))["token"])
except urllib.error.HTTPError as e:
    sys.exit("HTTP %d: %s" % (e.code, e.read().decode(errors="replace")[:500]))
PY
}

# gate_enrollment_proof <user> <pass>: prints a first-enrollment proof. The same door as
# gate_login, asked for one; the token it also returns is not a proof.
gate_enrollment_proof() {
    local user="$1" pass="$2"
    LOGIN_URL="$(http_url)/auth/simple/login" LOGIN_USER="$user" LOGIN_PASS="$pass" \
        t python3 - <<'PY'
import json, os, sys, urllib.error, urllib.request
req = urllib.request.Request(
    os.environ["LOGIN_URL"],
    data=json.dumps({"username": os.environ["LOGIN_USER"],
                     "password": os.environ["LOGIN_PASS"],
                     "enrollmentProof": True}).encode(),
    headers={"Content-Type": "application/json"})
try:
    print(json.load(urllib.request.urlopen(req))["enrollmentProof"])
except urllib.error.HTTPError as e:
    sys.exit("HTTP %d: %s" % (e.code, e.read().decode(errors="replace")[:500]))
except KeyError:
    sys.exit("the answer carries no enrollmentProof")
PY
}

# graphql <query> <variables-json>: prints the data JSON; fails on transport, HTTP or
# GraphQL errors (error text, or the HTTP status and body, on stderr). Uses $TOKEN.
graphql() {
    GQ_URL="$(http_url)/api/graphql" GQ_TOKEN="$TOKEN" GQ_QUERY="$1" GQ_VARS="${2:-{\}}" \
        t python3 - <<'PY'
import json, os, sys, urllib.error, urllib.request
req = urllib.request.Request(
    os.environ["GQ_URL"],
    data=json.dumps({"query": os.environ["GQ_QUERY"],
                     "variables": json.loads(os.environ["GQ_VARS"])}).encode(),
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer " + os.environ["GQ_TOKEN"]})
try:
    body = json.load(urllib.request.urlopen(req))
except urllib.error.HTTPError as e:
    sys.exit("HTTP %d: %s" % (e.code, e.read().decode(errors="replace")[:500]))
if body.get("errors"):
    sys.exit("GraphQL error: " + json.dumps(body["errors"]))
json.dump(body["data"], sys.stdout)
PY
}

# json_get <path.dotted>: extract a field from JSON on stdin (lists by index).
json_get() {
    PATH_EXPR="$1" python3 -c '
import json, os, sys
value = json.load(sys.stdin)
for part in os.environ["PATH_EXPR"].split("."):
    value = value[int(part)] if isinstance(value, list) else value[part]
print(value)'
}

# log_rows <sql condition>: rows of logs matching it, read from the lane's database
# (a copy of the SQLite file, or psql in the gate postgres). Booleans as `success`/`NOT success`.
log_rows() {
    case "$GATE_DB" in
    postgres)
        gexec_in "$PG_CONTAINER" psql -U klldap -d klldap -tAc \
            "SELECT COUNT(*) FROM logs WHERE $1" | tr -d '[:space:]'
        ;;
    sqlite)
        local copy
        copy="$(phase_dir)/logs-copy.db"
        docker cp "$CONTAINER:/data/users.db" "$copy" >/dev/null 2>&1 || {
            echo -1
            return
        }
        LOGS_DB="$copy" LOGS_WHERE="$1" python3 - <<'PY'
import os, sqlite3
con = sqlite3.connect(os.environ["LOGS_DB"])
print(con.execute("SELECT COUNT(*) FROM logs WHERE " + os.environ["LOGS_WHERE"]).fetchone()[0])
PY
        ;;
    *)
        echo -1
        ;;
    esac
}

# ---- LDAP (host openldap-clients against the published port) ----

admin_dn() { printf 'uid=admin,ou=people,%s' "$BASE_DN"; }

lsearch() { t ldapsearch -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" "$@"; }
lmodify() { t ldapmodify -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" "$@"; }
lwhoami() { t ldapwhoami -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS"; }

# ---- Container lifecycle ----

# start_main_container: boots $CONTAINER from $GATE_IMAGE on the run network with
# per-run volumes and ephemeral published ports, plus any GATE_EXTRA_RUN_ARGS.
start_main_container() {
    docker run -d --name "$CONTAINER" \
        --network "$NET" \
        -p "127.0.0.1::3890" -p "127.0.0.1::17170" \
        "${GATE_EXTRA_RUN_ARGS[@]}" \
        -v "$VOL_DATA:/data" -v "$VOL_KDC:/var/kerberos/krb5kdc" \
        -e LLDAP_JWT_SECRET="$JWT_SECRET" \
        -e LLDAP_KEY_SEED="$KEY_SEED" \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" \
        -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        -e LLDAP_DATABASE_URL="$GATE_DATABASE_URL" \
        -e LLDAP_VERBOSE=true \
        -e LLDAP_ENABLE_MFA=true \
        "$GATE_IMAGE" >/dev/null
}

discover_ports() {
    LDAP_PORT="$(docker port "$CONTAINER" 3890/tcp | head -1 | sed 's/.*://')"
    HTTP_PORT="$(docker port "$CONTAINER" 17170/tcp | head -1 | sed 's/.*://')"
    [ -n "$LDAP_PORT" ] && [ -n "$HTTP_PORT" ]
}

# wait_healthy [seconds]: poll the in-container healthcheck until it passes.
wait_healthy() {
    local limit="${1:-90}" i=0
    while [ "$i" -lt "$limit" ]; do
        if docker exec "$CONTAINER" /app/lldap healthcheck \
            --config-file /data/lldap_config.toml >/dev/null 2>&1; then
            return 0
        fi
        if [ -z "$(docker ps -q -f "name=^$CONTAINER$")" ]; then
            note "container $CONTAINER exited while waiting for health"
            return 1
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# side_up <name> <volume> [-e NAME=value ...]: another server on its own SQLite volume with
# Kerberos off, removed and made again by its exact name; prints its HTTP and LDAP ports.
side_up() {
    local name="$1" vol="$2" i=0
    shift 2
    docker rm -fv "$name" >/dev/null 2>&1 || true
    docker volume rm "$vol" >/dev/null 2>&1 || true
    docker volume create "$vol" >/dev/null || return 1
    LLDAP_JWT_SECRET="$JWT_SECRET" LLDAP_KEY_SEED="$KEY_SEED" LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        docker run -d --name "$name" --network "$NET" -p "127.0.0.1::17170" -p "127.0.0.1::3890" \
        -v "$vol:/data" -e LLDAP_JWT_SECRET -e LLDAP_KEY_SEED -e LLDAP_LDAP_USER_PASS \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_DATABASE_URL="sqlite:////data/users.db?mode=rwc" \
        -e LLDAP_KERBEROS_OPTIONS__ENABLED=false -e LLDAP_VERBOSE=true "$@" \
        "$GATE_IMAGE" >/dev/null || return 1
    while ! docker exec "$name" /app/lldap healthcheck --config-file /data/lldap_config.toml \
        >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 90 ] && [ -n "$(docker ps -q -f "name=^${name}$")" ] || return 1
        sleep 1
    done
    printf '%s %s\n' "$(docker port "$name" 17170/tcp | head -1 | sed 's/.*://')" \
        "$(docker port "$name" 3890/tcp | head -1 | sed 's/.*://')"
}

# side_up_kdc <name> <volume> <kdc volume> [-e NAME=value ...]: another server on its own SQLite
# volume with its own realm on a second volume (Kerberos on, nothing set server-wide), removed and
# made again by its exact name; prints its HTTP, LDAP and KDC (tcp) ports. kinit runs inside it.
side_up_kdc() {
    local name="$1" vol="$2" kvol="$3" i=0
    shift 3
    docker rm -fv "$name" >/dev/null 2>&1 || true
    docker volume rm "$vol" "$kvol" >/dev/null 2>&1 || true
    docker volume create "$vol" >/dev/null || return 1
    docker volume create "$kvol" >/dev/null || return 1
    LLDAP_JWT_SECRET="$JWT_SECRET" LLDAP_KEY_SEED="$KEY_SEED" LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        docker run -d --name "$name" --network "$NET" -p "127.0.0.1::17170" -p "127.0.0.1::3890" \
        -p "127.0.0.1::1088/tcp" -v "$vol:/data" -v "$kvol:/var/kerberos/krb5kdc" \
        -e LLDAP_JWT_SECRET -e LLDAP_KEY_SEED -e LLDAP_LDAP_USER_PASS \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_DATABASE_URL="sqlite:////data/users.db?mode=rwc" \
        -e LLDAP_VERBOSE=true "$@" "$GATE_IMAGE" >/dev/null || return 1
    while ! docker exec "$name" /app/lldap healthcheck --config-file /data/lldap_config.toml \
        >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 90 ] && [ -n "$(docker ps -q -f "name=^${name}$")" ] || return 1
        sleep 1
    done
    printf '%s %s %s\n' "$(docker port "$name" 17170/tcp | head -1 | sed 's/.*://')" \
        "$(docker port "$name" 3890/tcp | head -1 | sed 's/.*://')" \
        "$(docker port "$name" 1088/tcp | head -1 | sed 's/.*://')"
}

# side_down <name> <volume> <log>: its log kept, then the container and its volume removed by name.
side_down() {
    docker logs -t "$1" >"$3" 2>&1 || true
    docker rm -fv "$1" >/dev/null 2>&1 || true
    docker volume rm "$2" >/dev/null 2>&1 || true
}

# side_use <http port> <ldap port>: the gate's helpers talk to that server, as admin, until side_back.
side_use() {
    SIDE_SAVED="$HTTP_PORT $LDAP_PORT $TOKEN"
    HTTP_PORT="$1" LDAP_PORT="$2"
    TOKEN="$(gate_login)"
}
side_back() {
    read -r HTTP_PORT LDAP_PORT TOKEN <<<"$SIDE_SAVED"
}

# file_contains <path> <needle>: pure-sh substring check inside the container
# (the minimal runtime image is not guaranteed to ship grep).
file_contains() {
    gexec sh -c 'case "$(cat "$0" 2>/dev/null)" in *"$1"*) exit 0 ;; *) exit 1 ;; esac' \
        "$1" "$2"
}

# kadmin_q <query>: kadmin inside the container, authenticated by the admin keytab.
kadmin_q() { gexec kadmin -k -t /data/kadm5.keytab -p "admin/admin@$REALM" -q "$1"; }

admin_kvno() { kadmin_q "getprinc admin/admin@$REALM" | awk '/Key: vno/ {print $3; exit}' | tr -d ','; }

# kadmin_protected <user> <modprinc query> <out>: K1's refusal. KP_WHY says what did not hold.
kadmin_protected() {
    local user="$1" query="$2" out="$3" mark before got="" i
    KP_WHY=""
    mark="$(graphql '{ logs(limit: 1) { id } }' '{}' 2>/dev/null | json_get logs.0.id 2>/dev/null)"
    before="$(kadmin_q "getprinc $user" 2>/dev/null | kp_view)"
    kadmin_q "$query" >"$out" 2>&1
    if ! grep -qF "Cannot change protected principal" "$out"; then
        KP_WHY="kadmin did not say 'Cannot change protected principal': $(grep -v '^Authenticating' "$out" | head -1)"
    elif [ -z "$before" ] || [ "$(kadmin_q "getprinc $user" 2>/dev/null | kp_view)" != "$before" ]; then
        KP_WHY="getprinc $user: no record, or its policy, flags, expiry or keys moved"
    elif [ -z "$mark" ]; then
        KP_WHY="no log marker could be read"
    else
        for i in $(seq 1 20); do
            got="$(kp_denied "$user" "$mark")"
            case "$got" in "" | "0 "*) sleep 0.5 ;; *) break ;; esac
        done
        [ "$got" = one ] && sleep 1 && got="$(kp_denied "$user" "$mark")"
        [ "$got" = one ] || KP_WHY="access_denied rows for $user@$REALM after the marker: ${got:-unread}"
    fi
    [ -z "$KP_WHY" ]
}
kp_view() { awk '/^(Policy:|Attributes:|Expiration date:|Password expiration date:|Number of keys:|Key:)/'; }
kp_denied() {
    graphql 'query($id: ID!, $t: String!) { logs(filter: {kinds: [ACCESS_DENIED], target: $t}, afterId: $id, limit: 20) { success protocol actor detail } }' \
        '{"id": "'"$2"'", "t": "'"$1@$REALM"'"}' 2>/dev/null |
        WANT="kadmin modify on $1@$REALM by admin/admin@$REALM: PROTECT_PRINCIPAL" ACTOR="admin/admin@$REALM" python3 -c '
import json, os, sys
rows = json.load(sys.stdin)["logs"]
row = rows[0] if len(rows) == 1 else {}
ok = (row.get("detail") == os.environ["WANT"] and row.get("success") is False
      and row.get("protocol") == "KADMIN" and row.get("actor") == os.environ["ACTOR"])
print("one" if ok else "%d %s" % (len(rows), json.dumps(rows)[:300]))' 2>/dev/null
}

log_mark() { graphql '{ logs(limit: 1) { id } }' '{}' 2>/dev/null | json_get logs.0.id 2>/dev/null; }

# flood_quiet <KIND> <PROTOCOL>: wait until no flood window for refused rows of that kind over
# that protocol can still be open on the server (20 s without a refusal, then the writer's 5 s
# tick), so the next refusal is the first of its window. Prints the seconds waited; gives up at 60.
flood_quiet() {
    local waited=0
    while [ "$waited" -lt 60 ] && [ "$(flood_state "$1" "$2")" != closed ]; do
        sleep 1
        waited=$((waited + 1))
    done
    printf '%s\n' "$waited"
}
# flood_state <KIND> <PROTOCOL>: "closed" when the newest refused row of the kind is over 27 s old
# and no sign_in_flood row of the kind is a `started` without its `resolved`; else "open", also
# when the log cannot be read.
flood_state() {
    graphql "{ logs(filter: {kinds: [$1, SIGN_IN_FLOOD], protocol: $2, success: false}, limit: 100) { kind timestamp peer target detail } }" '{}' 2>/dev/null |
        KIND="$1" python3 -c '
import calendar, json, os, sys, time
kind = os.environ["KIND"]
rows = json.load(sys.stdin)["logs"]
newest = {}
for r in rows:
    detail = r.get("detail") or ""
    if r["kind"] == "SIGN_IN_FLOOD" and detail.startswith(kind.lower() + " flood"):
        newest.setdefault((r.get("peer"), r.get("target"), "many sources" in detail), detail)
ages = [time.time() - calendar.timegm(time.strptime(r["timestamp"][:19], "%Y-%m-%dT%H:%M:%S"))
        for r in rows if r["kind"] == kind]
started = any(d.endswith("started") for d in newest.values())
print("open" if started or (ages and min(ages) < 27) else "closed")' 2>/dev/null || echo open
}

# log_once <true|false> <kind> <target> <detail> <mark> <protocol>: one such row after the marker; else FAIL_WHY.
log_once() {
    local got="" i
    FAIL_WHY=""
    if [ -z "$5" ]; then
        FAIL_WHY="no log marker could be read"
        return 1
    fi
    for i in $(seq 1 20); do
        got="$(once_rows "$@")"
        case "$got" in "" | "0 "*) sleep 0.5 ;; *) break ;; esac
    done
    [ "$got" = one ] && sleep 1 && got="$(once_rows "$@")"
    [ "$got" = one ] || FAIL_WHY="$2 rows for $3 after the marker: ${got:-unread}; want one, success $1, protocol $6, '$4'"
    [ -z "$FAIL_WHY" ]
}
fail_once() { log_once false "$@"; }
once_rows() {
    graphql "query(\$id: ID!, \$t: String!) { logs(filter: {kinds: [$2], target: \$t}, afterId: \$id, limit: 20) { success protocol detail } }" \
        "$(ID="$5" T="$3" python3 -c 'import json,os; print(json.dumps({"id": os.environ["ID"], "t": os.environ["T"]}))')" 2>/dev/null |
        OK="$1" WANT="$4" PROTO="$6" python3 -c '
import json, os, sys
rows = json.load(sys.stdin)["logs"]
row = rows[0] if len(rows) == 1 else {}
ok = (row.get("success") is (os.environ["OK"] == "true") and row.get("detail") == os.environ["WANT"]
      and row.get("protocol") == os.environ["PROTO"])
print("one" if ok else "%d %s" % (len(rows), json.dumps(rows)[:300]))' 2>/dev/null
}

fail_row() {
    local row="$1"
    shift
    if fail_once "$@"; then
        p_ok "[$row] one $1 row names $2 after the refusal: success false, protocol $5, '$3'"
    else
        p_bad "[$row] $FAIL_WHY"
    fi
}

# kinit_pw <principal> <password>: password kinit inside the container, isolated cache.
kinit_pw() {
    gexec sh -c "printf '%s\n' \"\$1\" | KRB5CCNAME=/tmp/gate_cc_\$\$ kinit \"\$0\"" \
        "$1" "$2"
}

WIRE_IMAGE="mcr.microsoft.com/playwright@sha256:766137e2d9caad4744187e53cdc89320ba6f2eb57cff097374020944b44dd0a9"

# wire_seal <key> <plaintext> <label user>, wire_seal_in <key> <label user> (plaintext on stdin): a
# seal order for wire_page. The page's driver seals it when it holds the page's finish, under the
# label klldap-kerberos-envelope-v2:<label user>:<that finish's server data>, so the envelope belongs
# to the start the page's own session made and goes out once, with that session.
wire_seal() { printf '%s' "$2" | wire_seal_in "$1" "$3"; }

wire_seal_in() {
    [ -n "$1" ] || return 1
    printf 'seal:%s:%s:%s\n' "$1" "$2" "$(base64 -w0)"
}

# wire_page <tag> <change|create> <user> <typed> [<add|swap> <envelope or seal order>] [<mail>]:
# WIRE_LINE, WIRE_ALERT. With WIRE_OTHER_TOKEN set, a copy of the page's finish goes first with that
# bearer (WIRE_OTHER: its status and body); with WIRE_AGAIN=1 the page's finish goes once more with
# the page's own token (WIRE_AGAIN).
# shellcheck disable=SC2034
wire_page() {
    local tag="$1" kind="$2" user="$3" typed="$4" mode="${5:-}" envelope="${6:-}" mail="${7:-}"
    local dir ctn="klldap-wire-${RUNID}"
    dir="$(phase_dir)"
    case " ${EXTRA_CONTAINERS[*]:-} " in *" $ctn "*) ;; *) EXTRA_CONTAINERS+=("$ctn") ;; esac
    docker rm -f "$ctn" >/dev/null 2>&1 || true
    (
        export BROWSER_ADMIN_PASS="$ADMIN_PASS" BROWSER_PASS="$typed" BROWSER_FINISH_ENVELOPE="$envelope"
        export BROWSER_FINISH_OTHER_TOKEN="${WIRE_OTHER_TOKEN:-}"
        timeout 180 docker run --rm --name "$ctn" --network "$NET" --init --shm-size=1g \
            --user "$(id -u):$(id -g)" --entrypoint node \
            -v "$GATE_ROOT/lib/password-wire.mjs:/work/password-wire.mjs:ro" -v "$dir:/out" \
            -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_URL="http://${CONTAINER}:17170" \
            -e BROWSER_PAGE="$kind" -e BROWSER_USER="$user" -e BROWSER_TAG="$tag" -e BROWSER_MAIL="$mail" \
            -e BROWSER_FINISH_MODE="$mode" -e BROWSER_ADMIN_PASS -e BROWSER_PASS -e BROWSER_FINISH_ENVELOPE \
            -e BROWSER_FINISH_OTHER_TOKEN -e BROWSER_FINISH_AGAIN="${WIRE_AGAIN:-}" \
            "$WIRE_IMAGE" /work/password-wire.mjs >"$dir/wire-$tag.out" 2>"$dir/wire-$tag.err"
    )
    docker rm -f "$ctn" >/dev/null 2>&1 || true
    WIRE_LINE="$(grep -m1 '^WIRE \|^ROW wire FAIL' "$dir/wire-$tag.out" 2>/dev/null || echo "no line (see wire-$tag.err)")"
    WIRE_ALERT="$(grep -m1 '^ALERT ' "$dir/wire-$tag.out" 2>/dev/null | sed 's/^ALERT //')"
    WIRE_OTHER="$(grep -m1 '^OTHER ' "$dir/wire-$tag.out" 2>/dev/null | sed 's/^OTHER //')"
    WIRE_AGAIN_SAID="$(grep -m1 '^AGAIN ' "$dir/wire-$tag.out" 2>/dev/null | sed 's/^AGAIN //')"
}

gate_summary() {
    note ""
    note "Gate results: ${GREEN}$PASS_N passed${NC}, ${RED}$FAIL_N failed${NC}, ${YELLOW}$SKIP_N skipped${NC}"
    note "Logs: $RESULTS_DIR"
}
