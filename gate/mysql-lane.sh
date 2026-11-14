#!/usr/bin/env bash
#
# MySQL lane, one lane and two flavours. Starts mysql:9.7 or mariadb:12.3 on
# 127.0.0.1, sets KLLDAP_TEST_DATABASE_URL, runs the ignored lane tests on one
# thread, and removes the container and its anonymous volume.
#
#   GATE_MYSQL_FLAVOR   mysql (default) or mariadb
#   GATE_KEEP=1         leave the container up

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FLAVOR="${GATE_MYSQL_FLAVOR:-mysql}"
case "$FLAVOR" in
mysql)
    IMAGE="mysql:9.7@sha256:df90258da46f6e7ff8574ff84f17618aba0765cac749928299c69fd4e7cb8ad8"
    PING=(mysqladmin ping -h 127.0.0.1 -uklldap -pklldap --silent)
    SQL=(mysql -h 127.0.0.1 -uklldap -pklldap --batch --skip-column-names)
    DB_ENV=(
        -e MYSQL_ROOT_PASSWORD=klldap-root
        -e MYSQL_DATABASE=klldap
        -e MYSQL_USER=klldap
        -e MYSQL_PASSWORD=klldap
    )
    ROOT_SQL=(mysql -h 127.0.0.1 -uroot -pklldap-root --batch)
    ;;
mariadb)
    IMAGE="mariadb:12.3@sha256:4ebbcf100a3ba320766dfa0e1af008df12261301db6ef72798c7650f70794aed"
    PING=(mariadb-admin ping -h 127.0.0.1 -uklldap -pklldap --silent)
    SQL=(mariadb -h 127.0.0.1 -uklldap -pklldap --batch --skip-column-names)
    DB_ENV=(
        -e MARIADB_ROOT_PASSWORD=klldap-root
        -e MARIADB_DATABASE=klldap
        -e MARIADB_USER=klldap
        -e MARIADB_PASSWORD=klldap
    )
    ROOT_SQL=(mariadb -h 127.0.0.1 -uroot -pklldap-root --batch)
    ;;
*)
    echo "GATE_MYSQL_FLAVOR must be mysql or mariadb" >&2
    exit 1
    ;;
esac

NAME="klldap-mysql-lane-$$"
cleanup() {
    if [ "${GATE_KEEP:-}" != 1 ]; then
        docker rm -fv "$NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

docker run -d --name "$NAME" \
    "${DB_ENV[@]}" \
    -p "127.0.0.1::3306" \
    "$IMAGE" >/dev/null

ready=0
for _ in $(seq 1 90); do
    if docker exec "$NAME" "${PING[@]}" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" != 1 ]; then
    docker logs "$NAME" >&2 || true
    echo "mysql lane: $FLAVOR did not become ready" >&2
    exit 1
fi
docker exec "$NAME" "${ROOT_SQL[@]}" \
    -e "GRANT ALL PRIVILEGES ON *.* TO 'klldap'@'%'; FLUSH PRIVILEGES;"

PORT="$(docker port "$NAME" 3306/tcp | head -1 | sed 's/.*://')"
echo "mysql lane: flavor=$FLAVOR port=$PORT image=$IMAGE"
docker exec "$NAME" "${SQL[@]}" klldap \
    -e "SELECT VERSION(); SELECT @@innodb_flush_log_at_trx_commit, @@sync_binlog, @@log_bin;"

export KLLDAP_TEST_DATABASE_URL="mysql://klldap:klldap@127.0.0.1:${PORT}/klldap"

sql_rc=0
cargo test --locked -p lldap_sql_backend_handler -- --ignored --test-threads=1 || sql_rc=$?
kerberos_rc=0
cargo test --locked -p lldap-kerberos -- --ignored --test-threads=1 || kerberos_rc=$?
if [ "$sql_rc" -ne 0 ]; then
    exit "$sql_rc"
fi
if [ "$kerberos_rc" -ne 0 ]; then
    exit "$kerberos_rc"
fi
