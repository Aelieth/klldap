#!/usr/bin/env bash
# Throwaway non-root MIT KDC + kadmind on ephemeral ports (MIT's own k5test technique).
# Usage: gate/kdc-sandbox.sh cargo test -p lldap-kerberos -- --ignored
# Exports KRB5_CONFIG / KRB5_KDC_PROFILE / LLDAP_KERB_* so the command under test uses it.
set -euo pipefail

ROOT="$(mktemp -d)"
KDC_PID=""
KADMIN_PID=""
STATUS=1
cleanup() {
    [ -n "$KDC_PID" ] && kill "$KDC_PID" 2>/dev/null || true
    [ -n "$KADMIN_PID" ] && kill "$KADMIN_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    if [ "$STATUS" -ne 0 ]; then
        for log in kdc kadmind; do
            echo "--- $ROOT/$log.log ---" >&2
            tail -n 40 "$ROOT/$log.log" >&2 2>/dev/null || true
        done
    fi
    rm -rf "$ROOT"
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()'
}
KDC_PORT="${KDC_PORT:-$(free_port)}"
KADMIN_PORT="${KADMIN_PORT:-$(free_port)}"
KPASSWD_PORT="${KPASSWD_PORT:-$(free_port)}"
REALM="${LLDAP_KERB_REALM_NAME:-SANDBOX.TEST}"

mkdir -p "$ROOT/kdc" "$ROOT/data"
cat >"$ROOT/krb5.conf" <<CONF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    $REALM = {
        kdc = 127.0.0.1:$KDC_PORT
        admin_server = 127.0.0.1:$KADMIN_PORT
        kpasswd_server = 127.0.0.1:$KPASSWD_PORT
    }
[domain_realm]
    .sandbox.test = $REALM
    sandbox.test = $REALM
[logging]
    kdc = FILE:$ROOT/kdc.log
    admin_server = FILE:$ROOT/kadmind.log
CONF

cat >"$ROOT/kdc.conf" <<CONF
[kdcdefaults]
    kdc_ports = $KDC_PORT
    kdc_tcp_ports = $KDC_PORT
[realms]
    $REALM = {
        database_name = $ROOT/kdc/principal
        acl_file = $ROOT/kdc/kadm5.acl
        admin_keytab = $ROOT/kdc/kadm5.keytab
        key_stash_file = $ROOT/kdc/stash
        kadmind_port = $KADMIN_PORT
        kpasswd_port = $KPASSWD_PORT
        max_life = 12h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
    }
CONF
echo "admin/admin@$REALM    *" >"$ROOT/kdc/kadm5.acl"

export KRB5_CONFIG="$ROOT/krb5.conf"
export KRB5_KDC_PROFILE="$ROOT/kdc.conf"
printf 'sandbox-master\nsandbox-master\n' | kdb5_util create -s >/dev/null
kadmin.local -q "ktadd -k $ROOT/kdc/kadm5.keytab kadmin/admin kadmin/changepw" >/dev/null
kadmin.local -q "addprinc -pw sandbox-admin admin/admin@$REALM" >/dev/null
kadmin.local -q "ktadd -k $ROOT/data/kadm5.keytab admin/admin@$REALM" >/dev/null

krb5kdc -n &
KDC_PID=$!
kadmind -nofork &
KADMIN_PID=$!

wait_port() {
    for _ in $(seq 1 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.2
    done
    echo "kdc-sandbox: $2 is not listening on 127.0.0.1:$1" >&2
    return 1
}
wait_port "$KDC_PORT" krb5kdc
wait_port "$KADMIN_PORT" kadmind

export LLDAP_KERB_ADMIN_KEYTAB="$ROOT/data/kadm5.keytab"
export LLDAP_KERB_KEYCLOAK_KEYTAB="$ROOT/data/keycloak-http.keytab"
export LLDAP_KERB_KDC_DIR="$ROOT/kdc"
export LLDAP_KERB_KRB5_CONF="$ROOT/krb5.conf"
export LLDAP_KERB_KDC_CONF="$ROOT/kdc.conf"
export LLDAP_KERB_KADM5_ACL="$ROOT/kdc/kadm5.acl"
export LLDAP_KERB_KDC_PORT="$KDC_PORT"
export LLDAP_KERB_REALM_NAME="$REALM"
export LLDAP_LDAP_BASE_DN="dc=sandbox,dc=test"
export KLLDAP_TEST_KDC=1

set +e
"$@"
STATUS=$?
exit "$STATUS"
