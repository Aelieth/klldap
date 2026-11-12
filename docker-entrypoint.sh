#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/data/lldap_config.toml
# bash's own $UID is read-only and is the shell's uid, so the environment's is read with printenv.
# KLLDAP 0.7.2's LLDAP_UID and LLDAP_GID win when set.
uid="${LLDAP_UID:-$(printenv UID || echo 1000)}"
gid="${LLDAP_GID:-$(printenv GID || echo 1000)}"

if [[ ( ! -w "/data" ) ]] || [[ ( ! -d "/data" ) ]]; then
  echo "[entrypoint] The /data folder doesn't exist or cannot be written to. Make sure to mount
  a volume or folder to /data to persist data across restarts, and that the current user can
  write to it."
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Copying the default config to $CONFIG_FILE"
  echo "[entrypoint] Edit this file to configure LLDAP."
  cp /app/lldap_config.docker_template.toml $CONFIG_FILE
fi

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Config file is not readable. Check the permissions"
  exit 1;
fi

mkdir -p /data/keytab /data/cert
echo "> Setup permissions.."
find /app \! -user "$uid" -exec chown "$uid:$gid" '{}' +
find /data \! -user "$uid" -exec chown "$uid:$gid" '{}' +
find /var/kerberos/krb5kdc \! -user "$uid" -exec chown "$uid:$gid" '{}' +

echo "> Starting lldap.."
echo ""
exec gosu "$uid:$gid" /app/lldap "$@"
