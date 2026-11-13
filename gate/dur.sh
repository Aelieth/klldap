#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Durability cells ACC-3 and ACC-4 (D127), run by gate/lib/dur.py; usage below. Results in
# gate/results/dur-<run>/ (GATE_RESULTS_DIR overrides); GATE_KEEP=1 keeps the containers.
set -uo pipefail
GATE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$GATE_ROOT/.." || exit 1
usage() {
    echo "usage: gate/dur.sh acc3|acc4 --db sqlite|postgres [--image IMG] [--kills N] [--times N] [--cases i,ii,iii]" >&2
    exit 2
}
case "${1:-}" in
acc3 | acc4) ROW="$1" && shift ;;
*) usage ;;
esac
DB="sqlite"
GATE_IMAGE="klldap-test"
KILLS=25
TIMES=5
CASES="i,ii,iii"
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case "$1" in
    --db) DB="$2" ;;
    --image) GATE_IMAGE="$2" ;;
    --kills) KILLS="$2" ;;
    --times) TIMES="$2" ;;
    --cases) CASES="$2" ;;
    *) usage ;;
    esac
    shift 2
done
case "$DB" in
sqlite | postgres) ;;
*) usage ;;
esac
RUNID="$(date +%Y%m%d-%H%M%S)-$$"
RESULTS_DIR="${GATE_RESULTS_DIR:-gate/results}/dur-$RUNID"
mkdir -p "$RESULTS_DIR" || exit 1
RESULTS_DIR="$(cd "$RESULTS_DIR" && pwd)"
# shellcheck source=lib/common.sh
. "$GATE_ROOT/lib/common.sh"
PREFIX="klldap-dur-$RUNID"
NET="$PREFIX-net"
PG_CONTAINER="$PREFIX-pg"
cleanup() {
    if [ -n "${GATE_KEEP:-}" ]; then
        note "GATE_KEEP set: leaving $PREFIX-*"
        return
    fi
    docker ps -aq -f "name=^$PREFIX-" | xargs -r docker rm -f >/dev/null 2>&1
    docker volume ls -q -f "name=^$PREFIX-" | xargs -r docker volume rm >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
docker image inspect "$GATE_IMAGE" >/dev/null 2>&1 || {
    note "Image $GATE_IMAGE not found"
    exit 1
}
docker network create "$NET" >/dev/null || exit 1
if [ "$DB" = postgres ]; then
    docker run -d --name "$PG_CONTAINER" --network "$NET" \
        -e POSTGRES_USER=klldap -e POSTGRES_PASSWORD=klldap -e POSTGRES_DB=klldap \
        postgres:16 >/dev/null || exit 1
    for _ in $(seq 1 60); do
        if docker exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U klldap -q 2>/dev/null; then
            break
        fi
        sleep 1
    done
    docker exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U klldap -q || {
        docker logs "$PG_CONTAINER" >"$RESULTS_DIR/postgres.log" 2>&1
        note "postgres did not become ready (see postgres.log)"
        exit 1
    }
fi
note "Durability $ROW: image=$GATE_IMAGE db=$DB run=$RUNID results=$RESULTS_DIR"
driver_rev="$(git rev-parse --short HEAD 2>/dev/null)"
git diff --quiet HEAD -- gate 2>/dev/null || driver_rev="$driver_rev+dirty"
DUR_ROW="$ROW" DUR_DB="$DB" DUR_IMAGE="$GATE_IMAGE" DUR_PREFIX="$PREFIX" DUR_NET="$NET" \
    DUR_PG="$PG_CONTAINER" DUR_KILLS="$KILLS" DUR_TIMES="$TIMES" DUR_CASES="$CASES" DUR_REV="$driver_rev" \
    DUR_IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$GATE_IMAGE")" \
    python3 -I "$GATE_ROOT/lib/dur.py" "$RESULTS_DIR"
