#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Durability cells ACC-3, ACC-4 and ACC-8 (D127, D178), run by gate/lib/dur.py; usage below.
# Results in gate/results/dur-<run>/ (GATE_RESULTS_DIR overrides); GATE_KEEP=1 keeps the containers.
# acc8 runs the server in the lab guest and cuts it with virsh destroy, holding lab.lock throughout.
set -uo pipefail
GATE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$GATE_ROOT/.." || exit 1
usage() {
    echo "usage: gate/dur.sh acc3|acc4|acc8 --db sqlite|postgres [--image IMG] [--kills N] [--times N]" \
        "[--cases i,ii,iii] [--kill power --cuts N --settle S --guest NAME --addr IP --lab-home DIR]" >&2
    exit 2
}
case "${1:-}" in
acc3 | acc4 | acc8) ROW="$1" && shift ;;
*) usage ;;
esac
DB="sqlite"
GATE_IMAGE="klldap-test"
KILLS=25
TIMES=5
CASES="i,ii,iii"
KILL="process"
CUTS=3
GUEST="kerber-klldap"
ADDR="192.168.177.30"
LAB_HOME="$HOME/kerber-lab"
SETTLE=0
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case "$1" in
    --db) DB="$2" ;;
    --image) GATE_IMAGE="$2" ;;
    --kills) KILLS="$2" ;;
    --times) TIMES="$2" ;;
    --cases) CASES="$2" ;;
    --kill) KILL="$2" ;;
    --cuts) CUTS="$2" ;;
    --guest) GUEST="$2" ;;
    --addr) ADDR="$2" ;;
    --lab-home) LAB_HOME="$2" ;;
    --settle) SETTLE="$2" ;;
    *) usage ;;
    esac
    shift 2
done
case "$DB" in
sqlite | postgres) ;;
*) usage ;;
esac
case "$ROW:$KILL" in
acc8:power | acc3:process | acc4:process) ;;
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
vsh() {
    if command -v virsh >/dev/null 2>&1; then
        virsh -q -c qemu:///system "$@"
    else
        distrobox-host-exec virsh -q -c qemu:///system "$@"
    fi
}
DUR_RC=""
OWNER_SAVED=""
cleanup() {
    if [ "$ROW" = acc8 ]; then
        echo "GUEST $GUEST domstate at exit: $(vsh domstate "$GUEST" 2>&1)" | tee -a "$RESULTS_DIR/dur.log"
        [ -n "$OWNER_SAVED" ] && cp "$RESULTS_DIR/lab.lock.owner.before" "$LAB_LOCK.owner"
        if [ "$DUR_RC" != 0 ]; then
            echo "KEPT the run's containers and volumes in the guest ($PREFIX-*): the run ended with a FAIL," \
                "a FINDING or an error (rc=${DUR_RC:-none})" | tee -a "$RESULTS_DIR/dur.log"
            return
        fi
    fi
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
IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$GATE_IMAGE")"
LAB_LOCK=""
SSH_CONFIG=""
if [ "$ROW" = acc8 ]; then
    # lab.sh's hold_lab_lock: fd 9, flock -w 60, reused when the caller already holds it on fd 9.
    LAB_LOCK="$LAB_HOME/state/lab.lock"
    if ! { [ -e /proc/self/fd/9 ] && [ "$(readlink -f /proc/self/fd/9)" = "$(readlink -f "$LAB_LOCK")" ]; }; then
        exec 9>>"$LAB_LOCK"
    fi
    flock -w 60 9 || {
        note "the lab is held ($LAB_LOCK): waited 60s"
        exit 1
    }
    cp "$LAB_LOCK.owner" "$RESULTS_DIR/lab.lock.owner.before" 2>/dev/null || : >"$RESULTS_DIR/lab.lock.owner.before"
    OWNER_SAVED=1
    echo "IC dur.sh acc8 $RUNID $$ $(date '+%F %T %Z')" >"$LAB_LOCK.owner"
    # virsh destroy must only ever reach the machine the driver talks to.
    state="$(vsh domstate "$GUEST" 2>&1)"
    addrs="$(vsh domifaddr "$GUEST" --source lease 2>&1; vsh domifaddr "$GUEST" --source agent 2>&1)"
    if [ "$state" != running ] || ! grep -qF " $ADDR/" <<<"$addrs"; then
        note "guest $GUEST is '$state' and its addresses are: $addrs; expected running with $ADDR. Nothing cut."
        exit 1
    fi
    SSH_CONFIG="$RESULTS_DIR/ssh_config"
    cat >"$SSH_CONFIG" <<EOF
Host $ADDR
    User lab
    IdentityFile $LAB_HOME/ssh/lab_ed25519
    IdentitiesOnly yes
    BatchMode yes
    UserKnownHostsFile $LAB_HOME/ssh/known_hosts
    StrictHostKeyChecking accept-new
    HostKeyAlias klldap.kerber.test
    ConnectTimeout 5
    ServerAliveInterval 15
    LogLevel ERROR
EOF
    real_ssh="$(command -v ssh)"
    mkdir -p "$RESULTS_DIR/bin" "$RESULTS_DIR/tmp"
    printf '#!/bin/sh\nexec %s -F %s "$@"\n' "$real_ssh" "$SSH_CONFIG" >"$RESULTS_DIR/bin/ssh"
    chmod 755 "$RESULTS_DIR/bin/ssh"
    export PATH="$RESULTS_DIR/bin:$PATH" TMPDIR="$RESULTS_DIR/tmp"
    groups="$(ssh "$ADDR" id -nG 2>&1)"
    enabled="$(ssh "$ADDR" systemctl is-enabled docker 2>&1)"
    case " $groups " in
    *" docker "*) ;;
    *)
        note "lab is not in the guest's docker group ($groups)"
        exit 1
        ;;
    esac
    [ "$enabled" = enabled ] || {
        note "the guest's docker is not enabled at boot ($enabled)"
        exit 1
    }
    DOCKER_ROOT="$(ssh "$ADDR" findmnt -no SOURCE,FSTYPE,OPTIONS --target /var/lib/docker 2>&1)"
    export DOCKER_HOST="ssh://lab@$ADDR"
    env -u DOCKER_HOST docker save "$GATE_IMAGE" | docker load >/dev/null || {
        note "could not load $GATE_IMAGE into the guest"
        exit 1
    }
    guest_id="$(docker image inspect -f '{{.Id}}' "$GATE_IMAGE")"
    [ "$guest_id" = "$IMAGE_ID" ] || {
        note "the guest's $GATE_IMAGE is $guest_id, not $IMAGE_ID"
        exit 1
    }
fi
docker network create "$NET" >/dev/null || exit 1
if [ "$DB" = postgres ]; then
    pg_keep=()
    [ "$ROW" = acc8 ] && pg_keep=(--restart always -v "$PREFIX-pgdata:/var/lib/postgresql/data")
    docker run -d --name "$PG_CONTAINER" --network "$NET" "${pg_keep[@]}" \
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
    for setting in fsync synchronous_commit wal_sync_method full_page_writes; do
        printf '%s=%s\n' "$setting" "$(docker exec "$PG_CONTAINER" psql -U klldap -d klldap -Atc "SHOW $setting")"
    done >"$RESULTS_DIR/postgres-settings.txt"
fi
note "Durability $ROW: image=$GATE_IMAGE db=$DB run=$RUNID results=$RESULTS_DIR"
driver_rev="$(git rev-parse --short HEAD 2>/dev/null)"
git diff --quiet HEAD -- gate 2>/dev/null || driver_rev="$driver_rev+dirty"
DUR_ROW="$ROW" DUR_DB="$DB" DUR_IMAGE="$GATE_IMAGE" DUR_PREFIX="$PREFIX" DUR_NET="$NET" \
    DUR_PG="$PG_CONTAINER" DUR_KILLS="$KILLS" DUR_TIMES="$TIMES" DUR_CASES="$CASES" DUR_REV="$driver_rev" \
    DUR_IMAGE_ID="$IMAGE_ID" DUR_CUTS="$CUTS" DUR_GUEST="$GUEST" DUR_LAB_LOCK="$LAB_LOCK" \
    DUR_SSH_CONFIG="$SSH_CONFIG" DUR_ADDR="$([ "$ROW" = acc8 ] && echo "$ADDR" || echo 127.0.0.1)" \
    DUR_SETTLE="$SETTLE" DUR_DOCKER_ROOT="${DOCKER_ROOT:-}" \
    python3 -I "$GATE_ROOT/lib/dur.py" "$RESULTS_DIR"
DUR_RC=$?
exit "$DUR_RC"
