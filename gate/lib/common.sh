# shellcheck shell=bash
# Gate library: tally, results, timeouts, container/GraphQL/LDAP helpers.
# Sourced by gate/run-gate.sh; every phase in gate/phases.d/ runs with these.

RED=""; GREEN=""; YELLOW=""; NC=""
if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
fi

PASS_N=0; FAIL_N=0; SKIP_N=0
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

proc_running() { uid_of_comm "$1" >/dev/null 2>&1; }

# ---- HTTP / GraphQL (host-driven; python3 for JSON, no jq dependency) ----

http_url() { printf 'http://127.0.0.1:%s' "$HTTP_PORT"; }
ldap_url() { printf 'ldap://127.0.0.1:%s' "$LDAP_PORT"; }

# gate_login [user] [pass]: prints a bearer token.
gate_login() {
    local user="${1:-admin}" pass="${2:-$ADMIN_PASS}"
    LOGIN_URL="$(http_url)/auth/simple/login" LOGIN_USER="$user" LOGIN_PASS="$pass" \
        t python3 - <<'PY'
import json, os, urllib.request
req = urllib.request.Request(
    os.environ["LOGIN_URL"],
    data=json.dumps({"username": os.environ["LOGIN_USER"],
                     "password": os.environ["LOGIN_PASS"]}).encode(),
    headers={"Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["token"])
PY
}

# graphql <query> <variables-json>: prints the data JSON; fails on transport or
# GraphQL errors (error text on stderr). Uses $TOKEN.
graphql() {
    GQ_URL="$(http_url)/api/graphql" GQ_TOKEN="$TOKEN" GQ_QUERY="$1" GQ_VARS="${2:-{\}}" \
        t python3 - <<'PY'
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

# json_get <path.dotted>: extract a field from JSON on stdin (lists by index).
json_get() {
    PATH_EXPR="$1" python3 -c '
import json, os, sys
value = json.load(sys.stdin)
for part in os.environ["PATH_EXPR"].split("."):
    value = value[int(part)] if isinstance(value, list) else value[part]
print(value)'
}

# ---- LDAP (host openldap-clients against the published port) ----

admin_dn() { printf 'uid=admin,ou=people,%s' "$BASE_DN"; }

lsearch() { t ldapsearch -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" "$@"; }
lmodify() { t ldapmodify -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" "$@"; }
lwhoami() { t ldapwhoami -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS"; }

# ---- Container lifecycle ----

# start_main_container: boots $CONTAINER from $GATE_IMAGE on the run network with
# per-run volumes and ephemeral published ports.
start_main_container() {
    docker run -d --name "$CONTAINER" \
        --network "$NET" \
        -p "127.0.0.1::3890" -p "127.0.0.1::17170" \
        -v "$VOL_DATA:/data" -v "$VOL_KDC:/var/kerberos/krb5kdc" \
        -e LLDAP_JWT_SECRET="$JWT_SECRET" \
        -e LLDAP_KEY_SEED="$KEY_SEED" \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" \
        -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        -e LLDAP_DATABASE_URL="$GATE_DATABASE_URL" \
        -e LLDAP_VERBOSE=true \
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

# file_contains <path> <needle>: pure-sh substring check inside the container
# (the minimal runtime image is not guaranteed to ship grep).
file_contains() {
    gexec sh -c 'case "$(cat "$0" 2>/dev/null)" in *"$1"*) exit 0 ;; *) exit 1 ;; esac' \
        "$1" "$2"
}

# file_digest <path>: content digest inside the container (sha256sum, cksum fallback).
file_digest() {
    gexec sh -c 'sha256sum "$0" 2>/dev/null || cksum "$0"' "$1" | awk '{print $1}'
}

# wait_kerberos_healthy [seconds]: poll the full healthcheck including the Kerberos leg
# (the KDC bootstraps after LLDAP is ready, so plain health races ahead of it).
wait_kerberos_healthy() {
    local limit="${1:-90}" i=0
    while [ "$i" -lt "$limit" ]; do
        if docker exec "$CONTAINER" /app/lldap healthcheck \
            --config-file /data/lldap_config.toml --kerberos >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# kadmin_q <query>: kadmin.local inside the container.
kadmin_q() { gexec kadmin.local -q "$1"; }

# kinit_pw <principal> <password>: password kinit inside the container, isolated cache.
kinit_pw() {
    gexec sh -c "printf '%s\n' \"\$1\" | KRB5CCNAME=/tmp/gate_cc_\$\$ kinit \"\$0\"" \
        "$1" "$2"
}

gate_summary() {
    note ""
    note "Gate results: ${GREEN}$PASS_N passed${NC}, ${RED}$FAIL_N failed${NC}, ${YELLOW}$SKIP_N skipped${NC}"
    note "Logs: $RESULTS_DIR"
}
