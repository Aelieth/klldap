#!/usr/bin/env bash
#
# KLLDAP container gate: boots the real image (entrypoint.sh and all) and asserts the
# full stack from boot through OU/user lifecycle to Kerberos attributes, as CLI
# invocations. See working docs / CONTRIBUTING for the phase list.
#
# Environment contract:
#   GATE_IMAGE        image to test (default: klldap-test — build with `make test`)
#   GATE_DB           sqlite (default) | postgres (gate-managed postgres:16) | mysql (best-effort)
#   GATE_DATABASE_URL override the database URL entirely (advanced)
#   GATE_PHASES       substring filter, comma/space separated (e.g. "boot,kerberos")
#   GATE_RESULTS_DIR  where to write logs (default gate/results)
#   GATE_KEEP=1       keep containers/volumes/network for inspection
#   GATE_TIMEOUT      per-remote-op timeout, seconds (default 30)
#   GATE_FIXTURE_DATA / GATE_FIXTURE_KDC / GATE_FIXTURE_BASE_DN / GATE_FIXTURE_ADMIN_PASS
#                     enable the migration_boot phase (dirs mounted over /data and the KDC)
#   GATE_LLDAP_CLI    path to a Zepmann/lldap-cli checkout to enable the lldap-cli phase

set -uo pipefail

GATE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$GATE_ROOT/.." || exit 1

GATE_IMAGE="${GATE_IMAGE:-klldap-test}"
GATE_DB="${GATE_DB:-sqlite}"
GATE_PHASES="${GATE_PHASES:-}"
GATE_KEEP="${GATE_KEEP:-}"

RUNID="$(date +%Y%m%d-%H%M%S)-$$"
RESULTS_DIR="${GATE_RESULTS_DIR:-gate/results}/$RUNID"
mkdir -p "$RESULTS_DIR"
RESULTS_DIR="$(cd "$RESULTS_DIR" && pwd)"

# shellcheck source=lib/common.sh
. "$GATE_ROOT/lib/common.sh"

CONTAINER="klldap-gate-$RUNID"
NET="klldap-gate-net-$RUNID"
VOL_DATA="klldap-gate-data-$RUNID"
VOL_KDC="klldap-gate-kdc-$RUNID"
PG_CONTAINER="klldap-gate-pg-$RUNID"
EXTRA_CONTAINERS=()

BASE_DN="dc=gate,dc=test"
REALM="GATE.TEST"
ADMIN_PASS="GateAdminPass2026!"
JWT_SECRET="gate-jwt-secret-not-for-production"
KEY_SEED="gate-key-seed-not-for-production"
LDAP_PORT=""
HTTP_PORT=""
TOKEN=""

cleanup() {
    if [ -n "$GATE_KEEP" ]; then
        note "GATE_KEEP set — leaving $CONTAINER (and helpers) running"
        return
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    for c in "${EXTRA_CONTAINERS[@]:-}"; do
        [ -n "$c" ] && docker rm -f "$c" >/dev/null 2>&1
    done
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    docker volume rm "$VOL_DATA" "$VOL_KDC" >/dev/null 2>&1
}
trap cleanup EXIT

note "KLLDAP gate: image=$GATE_IMAGE db=$GATE_DB run=$RUNID"
docker image inspect "$GATE_IMAGE" >/dev/null 2>&1 || {
    note "Image $GATE_IMAGE not found. Run: make test"
    exit 1
}

docker network create "$NET" >/dev/null || exit 1

case "$GATE_DB" in
sqlite)
    GATE_DATABASE_URL="${GATE_DATABASE_URL:-sqlite:////data/users.db?mode=rwc}"
    ;;
postgres)
    note "Starting gate-managed postgres:16 ..."
    docker run -d --name "$PG_CONTAINER" --network "$NET" \
        -e POSTGRES_USER=klldap -e POSTGRES_PASSWORD=klldap -e POSTGRES_DB=klldap \
        -p "127.0.0.1::5432" \
        postgres:16 >/dev/null || exit 1
    for _ in $(seq 1 60); do
        if docker exec "$PG_CONTAINER" pg_isready -U klldap -q 2>/dev/null; then
            break
        fi
        sleep 1
    done
    docker exec "$PG_CONTAINER" pg_isready -U klldap -q || {
        note "postgres did not become ready"
        exit 1
    }
    GATE_DATABASE_URL="${GATE_DATABASE_URL:-postgres://klldap:klldap@$PG_CONTAINER:5432/klldap}"
    # Host-side URL for cargo's #[ignore] postgres lane, if the caller wants it.
    PG_HOST_PORT="$(docker port "$PG_CONTAINER" 5432/tcp | head -1 | sed 's/.*://')"
    note "postgres up (host port $PG_HOST_PORT): export KLLDAP_TEST_DATABASE_URL=postgres://klldap:klldap@127.0.0.1:$PG_HOST_PORT/klldap"
    ;;
mysql)
    # Best-effort per the audit decision: accepted, never gated.
    GATE_DATABASE_URL="${GATE_DATABASE_URL:?GATE_DB=mysql requires GATE_DATABASE_URL}"
    ;;
*)
    note "Unknown GATE_DB=$GATE_DB"
    exit 1
    ;;
esac

note "Booting $CONTAINER ..."
start_main_container || exit 1
if ! wait_healthy 90; then
    PHASE="setup"
    p_bad "container did not become healthy within 90s"
    docker logs "$CONTAINER" >"$RESULTS_DIR/boot-failure-docker.log" 2>&1
    gate_summary
    exit 1
fi
discover_ports || {
    note "could not discover published ports"
    exit 1
}
note "Ports: ldap=127.0.0.1:$LDAP_PORT http=127.0.0.1:$HTTP_PORT"
TOKEN="$(gate_login)" || {
    PHASE="setup"
    p_bad "admin login failed at startup"
    gate_summary
    exit 1
}

phase_selected() {
    [ -z "$GATE_PHASES" ] && return 0
    local sel
    for sel in $(printf '%s' "$GATE_PHASES" | tr ',' ' '); do
        case "$1" in *"$sel"*) return 0 ;; esac
    done
    return 1
}

for phase_file in "$GATE_ROOT"/phases.d/*.sh; do
    [ -e "$phase_file" ] || continue
    PHASE="$(basename "$phase_file" .sh)"
    if ! phase_selected "$PHASE"; then
        continue
    fi
    note ""
    note "=== phase: $PHASE ==="
    # shellcheck disable=SC1090
    . "$phase_file"
done

PHASE="summary"
gate_summary
[ "$FAIL_N" -eq 0 ] || exit 1
exit 0
