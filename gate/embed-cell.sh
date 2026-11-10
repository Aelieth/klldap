#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
#
# Embed cell driver: boots the image with its KDC published on loopback, seeds
# kerberossync users, runs gate/lib/embed_cell.py's paced loops (kinit, ldappasswd
# writes, LDAP and GraphQL probes) for the window, then checks principals and health.
#
#   gate/embed-cell.sh [--image IMG] [knobs...]    knobs and frozen defaults: --help
#
# Results: gate/results/cell-<run>/ (GATE_RESULTS_DIR overrides). GATE_KEEP=1 keeps the
# container. Client tools come from the host: kinit, ldappasswd, ldapsearch, python3.

set -uo pipefail

GATE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$GATE_ROOT/.." || exit 1
CELL_PY=(python3 -I "$GATE_ROOT/lib/embed_cell.py")

case "${1:-}" in
-h | --help) exec "${CELL_PY[@]}" config /dev/null --help ;;
esac

RUNID="$(date +%Y%m%d-%H%M%S)-$$"
RESULTS_DIR="${GATE_RESULTS_DIR:-gate/results}/cell-$RUNID"
mkdir -p "$RESULTS_DIR" || exit 1
RESULTS_DIR="$(cd "$RESULTS_DIR" && pwd)"

read -r GATE_IMAGE USERS KDC_PORT < <("${CELL_PY[@]}" config "$RESULTS_DIR" "$@") || exit 2

# shellcheck source=lib/common.sh
. "$GATE_ROOT/lib/common.sh"
PHASE="cell"

CONTAINER="klldap-cell-$RUNID"
NET="klldap-cell-net-$RUNID"
VOL_DATA="klldap-cell-data-$RUNID"
VOL_KDC="klldap-cell-kdc-$RUNID"
BASE_DN="dc=gate,dc=test"
REALM="GATE.TEST"
ADMIN_PASS="GateAdminPass2026!"
JWT_SECRET="gate-jwt-secret-not-for-production"
KEY_SEED="gate-key-seed-not-for-production"
GATE_DATABASE_URL="sqlite:////data/users.db?mode=rwc"
GATE_EXTRA_RUN_ARGS=(-p "127.0.0.1:$KDC_PORT:88/udp" -p "127.0.0.1:$KDC_PORT:88/tcp")
LDAP_PORT=""
HTTP_PORT=""
TOKEN=""

cleanup() {
    docker logs "$CONTAINER" >"$RESULTS_DIR/docker.log" 2>&1
    if [ -n "${GATE_KEEP:-}" ]; then
        note "GATE_KEEP set: leaving $CONTAINER running"
        return
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    docker volume rm "$VOL_DATA" "$VOL_KDC" >/dev/null 2>&1
}
trap cleanup EXIT

docker image inspect "$GATE_IMAGE" >/dev/null 2>&1 || {
    note "Image $GATE_IMAGE not found"
    exit 1
}
note "Embed cell: image=$GATE_IMAGE users=$USERS kdc=127.0.0.1:$KDC_PORT run=$RUNID"
docker network create "$NET" >/dev/null || exit 1
start_main_container || exit 1
wait_kerberos_healthy 120 || {
    p_bad "container not healthy with its KDC within 120s"
    exit 1
}
discover_ports || {
    p_bad "could not discover published ports"
    exit 1
}
TOKEN="$(gate_login)" || {
    p_bad "admin login failed"
    exit 1
}

export LDAP_PORT HTTP_PORT TOKEN ADMIN_PASS BASE_DN REALM CONTAINER
driver_rev="$(git rev-parse --short HEAD 2>/dev/null)"
git diff --quiet HEAD -- gate 2>/dev/null || driver_rev="$driver_rev+dirty"
IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$GATE_IMAGE")" \
    DRIVER_REV="$driver_rev" \
    CLIENTS="$(rpm -q krb5-workstation krb5-libs openldap-clients 2>/dev/null | tr '\n' ' ')" \
    "${CELL_PY[@]}" run "$RESULTS_DIR"
loops=$?

PHASE="checks"
gexec kadmin -k -t /data/kadm5.keytab -p admin/admin -q listprincs \
    >"$RESULTS_DIR/listprincs.txt" 2>"$RESULTS_DIR/kadmin.err"
found="$(grep -cE "^cell([0-9]{4}|idle)@$REALM\$" "$RESULTS_DIR/listprincs.txt")"
if [ "$found" -eq $((USERS + 1)) ]; then
    p_ok "kadmin with the admin keytab lists all $found cell principals"
else
    p_bad "kadmin with the admin keytab lists $found of $((USERS + 1)) cell principals"
fi
health="$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")"
if [ "$health" = "healthy" ]; then
    p_ok "container healthy at the end"
else
    p_bad "container health at the end: $health"
fi
if [ "$loops" -eq 0 ]; then
    p_ok "loops finished with no failed request"
else
    p_bad "loops reported failures, see $RESULTS_DIR/summary.txt"
fi

gate_summary
[ "$FAIL_N" -eq 0 ]
