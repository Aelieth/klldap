#!/bin/bash
set -e

CONFIG_FILE=/data/lldap_config.toml

# === UID/GID for rootless-friendly operation (matches upstream LLDAP docker entrypoint style) ===
# LLDAP_UID/LLDAP_GID take precedence; legacy UID/GID are read with printenv because
# some bash builds reset $UID to the process uid and mark it readonly — printenv reads
# the environment directly, so the override works under either bash behavior.
LLDAP_UID="${LLDAP_UID:-$(printenv UID || echo 1000)}"
LLDAP_GID="${LLDAP_GID:-$(printenv GID || echo 1000)}"

# === Required env checks ===
if [ -z "$LLDAP_JWT_SECRET" ]; then
    echo "ERROR: LLDAP_JWT_SECRET is required."
    echo "Please set a strong random secret (32+ characters) via environment variable."
    echo "Example: -e LLDAP_JWT_SECRET=\"$(openssl rand -hex 32)\""
    exit 1
fi
if [ -z "$LLDAP_LDAP_BASE_DN" ]; then
    echo "ERROR: LLDAP_LDAP_BASE_DN is required."
    echo "Example: -e LLDAP_LDAP_BASE_DN=\"dc=homelab,dc=local\""
    exit 1
fi

# === Start LLDAP ===
echo "Starting LLDAP..."
/start-lldap.sh "$@" &
LLDAP_PID=$!

echo "Waiting for LLDAP to become ready..."
ready=""
for _ in $(seq 1 60); do
    # A server that already exited (bad config, or the one-shot force flags) is reported at
    # once, with its own status, instead of after the full wait.
    if ! kill -0 "$LLDAP_PID" 2>/dev/null; then
        status=0
        wait "$LLDAP_PID" || status=$?
        echo "ERROR: LLDAP exited with status $status before becoming ready."
        exit "$status"
    fi
    # Run healthcheck as the target user (prevents root from creating root-owned
    # 0400 "server_key" files in /app that the real lldap process cannot read).
    # Also pass --config-file so we reliably load the /data copy (with key_seed etc.),
    # matching upstream LLDAP docker CMD + HEALTHCHECK behavior.
    # The KDC starts after this loop, so this probe must not require it.
    if LLDAP_HEALTHCHECK_OPTIONS__KERBEROS=false gosu "${LLDAP_UID}:${LLDAP_GID}" /app/lldap healthcheck --config-file "$CONFIG_FILE" >/dev/null 2>&1; then
        echo "LLDAP is ready!"
        ready=1
        break
    fi
    sleep 1
done

if [ -z "$ready" ]; then
    echo "ERROR: LLDAP failed to start within 60 seconds."
    exit 1
fi

echo "Starting Kerberos manager..."
/app/kerberos_manager &
KERBEROS_PID=$!

trap 'echo "Shutting down..."; kill $LLDAP_PID $KERBEROS_PID 2>/dev/null || true; wait; exit 0' INT TERM

wait $LLDAP_PID
