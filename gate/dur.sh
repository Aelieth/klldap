#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Durability cells ACC-3, ACC-4 and ACC-8 (D127, D178), run by gate/lib/dur.py; usage below.
# mysql and mariadb (acc3, acc4) start the scratch server gate/mysql-lane.sh starts, on the run's network.
# Results in gate/results/dur-<run>/ (GATE_RESULTS_DIR overrides); GATE_KEEP=1 keeps the containers.
# acc8 runs the server in the lab guest and cuts it with virsh destroy, holding lab.lock throughout.
set -uo pipefail
GATE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$GATE_ROOT/.." || exit 1
usage() {
    echo "usage: gate/dur.sh acc3|acc4|acc8 --db sqlite|postgres|mysql|mariadb [--image IMG] [--kills N] [--times N]" \
        "[--kinds abcd] [--cases i,ii,iii,iv]" \
        "[--kill power --cuts N --settle S --guest NAME --addr IP --lab-home DIR" \
        "[--install container|host --binary PATH]]" >&2
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
KINDS="abc"
CASES="i,ii,iii,iv"
KILL="process"
CUTS=3
GUEST="kerber-klldap"
ADDR="192.168.177.30"
LAB_HOME="$HOME/kerber-lab"
SETTLE=0
INSTALL="container"
BINARY=""
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case "$1" in
    --db) DB="$2" ;;
    --image) GATE_IMAGE="$2" ;;
    --kills) KILLS="$2" ;;
    --times) TIMES="$2" ;;
    --kinds) KINDS="$2" ;;
    --cases) CASES="$2" ;;
    --kill) KILL="$2" ;;
    --cuts) CUTS="$2" ;;
    --guest) GUEST="$2" ;;
    --addr) ADDR="$2" ;;
    --lab-home) LAB_HOME="$2" ;;
    --settle) SETTLE="$2" ;;
    --install) INSTALL="$2" ;;
    --binary) BINARY="$2" ;;
    *) usage ;;
    esac
    shift 2
done
case "$DB" in
sqlite | postgres | mysql | mariadb) ;;
*) usage ;;
esac
case "$ROW:$DB" in
acc8:mysql | acc8:mariadb)
    echo "gate/dur.sh: acc8 does not take --db $DB: this release has no power leg for an external MySQL or" \
        "MariaDB server (acc3 and acc4 cover them)" >&2
    exit 2
    ;;
esac
case "$ROW:$KILL" in
acc8:power | acc3:process | acc4:process) ;;
*) usage ;;
esac
case "$KINDS" in
"" | *[!abcd]*) usage ;;
esac
[ "$ROW" != acc4 ] || [ "$KINDS" = abc ] || usage
case "$INSTALL" in
container) ;;
host) [ "$ROW" = acc8 ] && [ -f "$BINARY" ] || usage ;;
*) usage ;;
esac
[ "$INSTALL" = container ] || GATE_IMAGE="none (host install)"
RUNID="$(date +%Y%m%d-%H%M%S)-$$"
RESULTS_DIR="${GATE_RESULTS_DIR:-gate/results}/dur-$RUNID"
mkdir -p "$RESULTS_DIR" || exit 1
RESULTS_DIR="$(cd "$RESULTS_DIR" && pwd)"
# shellcheck source=lib/common.sh
. "$GATE_ROOT/lib/common.sh"
PREFIX="klldap-dur-$RUNID"
NET="$PREFIX-net"
PG_CONTAINER="$PREFIX-pg"
MY_CONTAINER="$PREFIX-db"
MY_ENV="${DB^^}"
KEPT_LIST=/home/lab/klldap-dur-kept
vsh() {
    if command -v virsh >/dev/null 2>&1; then
        virsh -q -c qemu:///system "$@"
    else
        distrobox-host-exec virsh -q -c qemu:///system "$@"
    fi
}
my_sql() {
    local tool="$1" user="$2" pass="${MY_ENV}_PASSWORD"
    [ "$user" = root ] && pass="${MY_ENV}_ROOT_PASSWORD"
    shift 2
    docker exec "$MY_CONTAINER" sh -c "exec \"\$0\" -h 127.0.0.1 -u$user -p\"\$$pass\" \"\$@\"" "$tool" "$@"
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
        if [ -e "$RESULTS_DIR/keep" ]; then
            echo "KEPT the run's containers and volumes in the guest ($PREFIX-*):" \
                "$(head -1 "$RESULTS_DIR/keep")" | tee -a "$RESULTS_DIR/dur.log"
            docker ps -a --format '{{.Names}}' -f "name=^$PREFIX-" >"$RESULTS_DIR/kept-containers"
            ssh "$ADDR" "cat >>$KEPT_LIST && sync $KEPT_LIST" <"$RESULTS_DIR/kept-containers" ||
                echo "KEPT names not recorded in the guest ($KEPT_LIST): see kept-containers" |
                tee -a "$RESULTS_DIR/dur.log"
            return
        fi
    fi
    if [ -n "${GATE_KEEP:-}" ]; then
        note "GATE_KEEP set: leaving $PREFIX-*"
        return
    fi
    docker ps -aq -f "name=^$PREFIX-" | xargs -r docker rm -fv >/dev/null 2>&1
    docker volume ls -q -f "name=^$PREFIX-" | xargs -r docker volume rm >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
if [ "$INSTALL" = host ]; then
    IMAGE_ID="none"
    BINARY_SHA="$(sha256sum "$BINARY" | cut -c1-64)"
    UNIT_SHA="$(sha256sum example_configs/lldap.service | cut -c1-64)"
else
    docker image inspect "$GATE_IMAGE" >/dev/null 2>&1 || {
        note "Image $GATE_IMAGE not found"
        exit 1
    }
    IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$GATE_IMAGE")"
fi
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
    groups="$(ssh -n "$ADDR" id -nG 2>&1)"
    enabled="$(ssh -n "$ADDR" systemctl is-enabled docker 2>&1)"
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
    DOCKER_ROOT="$(ssh -n "$ADDR" findmnt -no SOURCE,FSTYPE,OPTIONS --target /var/lib/docker 2>&1)"
    export DOCKER_HOST="ssh://lab@$ADDR"
    if [ "$INSTALL" = host ]; then
        # A leg that ended with `keep` left its containers on the ports this install needs.
        for name in $(ssh -n "$ADDR" cat "$KEPT_LIST" 2>/dev/null); do
            case "$name" in
            klldap-dur-*) ;;
            *) continue ;;
            esac
            if docker rm -f -v "$name" >/dev/null 2>&1; then
                note "removed the kept container $name (its named volumes stay)"
            elif docker container inspect "$name" >/dev/null 2>&1; then
                note "could not remove the kept container $name"
                exit 1
            fi
        done
        ssh -n "$ADDR" rm -f "$KEPT_LIST"
        stage=/home/lab/klldap-stage
        if ! { ssh -n "$ADDR" mkdir -p "$stage" &&
            scp -q -F "$SSH_CONFIG" "$BINARY" "$ADDR:$stage/lldap" &&
            scp -q -F "$SSH_CONFIG" example_configs/lldap.service gate/lib/dur-host.sh \
                "$ADDR:$stage/"; }; then
            note "could not stage the host install in the guest"
            exit 1
        fi
        { ssh -n "$ADDR" systemctl is-active firewalld; ssh -n "$ADDR" sudo -n firewall-cmd --list-all; } \
            >"$RESULTS_DIR/firewall-before.txt" 2>&1
        FIREWALL="firewalld not active"
        if [ "$(head -1 "$RESULTS_DIR/firewall-before.txt")" = active ]; then
            if ! { ssh -n "$ADDR" sudo -n firewall-cmd --permanent --add-port=3890/tcp \
                --add-port=17170/tcp >/dev/null &&
                ssh -n "$ADDR" sudo -n firewall-cmd --reload >/dev/null; }; then
                note "could not open 3890/tcp and 17170/tcp in the guest's firewalld"
                exit 1
            fi
            FIREWALL="3890/tcp and 17170/tcp opened permanently (the next reset removes them)"
        fi
    else
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
fi
docker network create "$NET" >/dev/null || exit 1
if [ "$DB" = postgres ]; then
    pg_keep=()
    [ "$ROW" = acc8 ] && pg_keep=(--restart always -v "$PREFIX-pgdata:/var/lib/postgresql/data")
    [ "$INSTALL" = host ] && pg_keep+=(-p 127.0.0.1:5432:5432)
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
if [ "$DB" = mysql ] || [ "$DB" = mariadb ]; then
    if [ "$DB" = mysql ]; then
        my_image="mysql:9.7@sha256:df90258da46f6e7ff8574ff84f17618aba0765cac749928299c69fd4e7cb8ad8"
        my_admin=mysqladmin
    else
        my_image="mariadb:12.3@sha256:4ebbcf100a3ba320766dfa0e1af008df12261301db6ef72798c7650f70794aed"
        my_admin=mariadb-admin
    fi
    grep -qF "$my_image" gate/mysql-lane.sh || {
        note "$my_image is not the image gate/mysql-lane.sh starts for $DB"
        exit 1
    }
    docker run -d --name "$MY_CONTAINER" --network "$NET" \
        -e "${MY_ENV}_ROOT_PASSWORD=klldap-root" -e "${MY_ENV}_DATABASE=klldap" \
        -e "${MY_ENV}_USER=klldap" -e "${MY_ENV}_PASSWORD=klldap" "$my_image" >/dev/null || exit 1
    ready=""
    for _ in $(seq 1 90); do
        if my_sql "$my_admin" klldap ping --silent >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done
    [ -n "$ready" ] || {
        docker logs "$MY_CONTAINER" >"$RESULTS_DIR/$DB.log" 2>&1
        note "$DB did not become ready (see $DB.log)"
        exit 1
    }
    read -r my_version my_flush my_sync my_log_bin < <(my_sql "$DB" root --batch --skip-column-names \
        -e "SELECT VERSION(), @@innodb_flush_log_at_trx_commit, @@sync_binlog, @@log_bin")
    [ -n "${my_log_bin:-}" ] || {
        note "could not read $DB's version and flush settings"
        exit 1
    }
    DB_SETTINGS="server=$DB version=$my_version innodb_flush_log_at_trx_commit=$my_flush"
    DB_SETTINGS+=" sync_binlog=$my_sync log_bin=$my_log_bin image=$my_image"
    echo "$DB_SETTINGS" >"$RESULTS_DIR/db-settings.txt"
fi
note "Durability $ROW: image=$GATE_IMAGE db=$DB run=$RUNID results=$RESULTS_DIR"
driver_rev=""
if [ "$(git rev-parse --show-toplevel 2>/dev/null)" = "$(pwd -P)" ]; then
    driver_rev="$(git rev-parse --short HEAD 2>/dev/null)"
    git diff --quiet HEAD -- gate 2>/dev/null || driver_rev="$driver_rev+dirty"
fi
DUR_ROW="$ROW" DUR_DB="$DB" DUR_IMAGE="$GATE_IMAGE" DUR_PREFIX="$PREFIX" DUR_NET="$NET" \
    DUR_PG="$PG_CONTAINER" DUR_KILLS="$KILLS" DUR_TIMES="$TIMES" DUR_CASES="$CASES" DUR_REV="$driver_rev" \
    DUR_IMAGE_ID="$IMAGE_ID" DUR_CUTS="$CUTS" DUR_GUEST="$GUEST" DUR_LAB_LOCK="$LAB_LOCK" \
    DUR_SSH_CONFIG="$SSH_CONFIG" DUR_ADDR="$([ "$ROW" = acc8 ] && echo "$ADDR" || echo 127.0.0.1)" \
    DUR_SETTLE="$SETTLE" DUR_DOCKER_ROOT="${DOCKER_ROOT:-}" DUR_KINDS="$KINDS" DUR_INSTALL="$INSTALL" \
    DUR_BINARY_SHA="${BINARY_SHA:-}" DUR_UNIT_SHA="${UNIT_SHA:-}" DUR_FIREWALL="${FIREWALL:-}" \
    DUR_MY="$MY_CONTAINER" DUR_DB_SETTINGS="${DB_SETTINGS:-}" \
    python3 -I "$GATE_ROOT/lib/dur.py" "$RESULTS_DIR" </dev/null
DUR_RC=$?
exit "$DUR_RC"
