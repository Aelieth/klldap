#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/data/lldap_config.toml

# === UID/GID support (rootless-friendly, matches upstream LLDAP docker behavior) ===
LLDAP_UID="${UID:-1000}"
LLDAP_GID="${GID:-1000}"

# Create required persistent directories (kerberos_manager now owns its own dirs)
mkdir -p /data /data/keytab /data/cert

# Repair ownership on /data and /app so the target user can read/write its files
# (including the config we may copy, the sqlite DB, and any key material if not using seed).
# We attempt this when running as root (the normal container ENTRYPOINT case).
# In true rootless (non-root from the start) we skip to avoid `set -e` aborts on
# permission errors; the volume permissions or prior setup are relied upon.
# This is best-effort and matches the spirit of upstream while being safe under
# `set -euo pipefail`.
echo "[start-lldap] Ensuring ownership for UID=${LLDAP_UID} GID=${LLDAP_GID}"
if [ "$(id -u)" -eq 0 ]; then
  find /app \! -user "${LLDAP_UID}" -exec chown "${LLDAP_UID}:${LLDAP_GID}" '{}' + || true
  find /data \! -user "${LLDAP_UID}" -exec chown "${LLDAP_UID}:${LLDAP_GID}" '{}' + || true
else
  echo "[start-lldap] Not root; skipping ownership repair (rely on volume setup)."
fi

# Touch marker on first sight (kerberos_manager may still use absence of some files for its bootstrap)
if [ ! -f /data/.lldap_initialized ]; then
  touch /data/.lldap_initialized
fi

# Official LLDAP writable check
if [[ ( ! -w "/data" ) ]] || [[ ( ! -d "/data" ) ]]; then
  echo "[start-lldap] The /data folder doesn't exist or cannot be written to. Make sure to mount a volume."
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[start-lldap] Copying the default config to $CONFIG_FILE"
  echo "[start-lldap] Edit this file to configure LLDAP."
  cp /app/lldap_config.docker_template.toml $CONFIG_FILE
  if [ "$(id -u)" -eq 0 ]; then
    chown "${LLDAP_UID}:${LLDAP_GID}" "$CONFIG_FILE" || true
  fi
fi

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "[start-lldap] Config file is not readable. Check the permissions"
  exit 1
fi

echo "> Starting lldap.."
echo ""

# Pass through "$@" (which in normal Docker usage comes from the ENTRYPOINT/CMD
# that now includes `--config-file /data/lldap_config.toml` right after the
# subcommand, per upstream LLDAP style). This guarantees the persistent config
# (key_seed, volume DB path, etc.) is used.
#
# We do NOT prefix --config-file before "$@" because that would produce invalid
# `lldap --config-file ... run ...` (clap requires subcommand before its flags).
# The Dockerfile CMD + entrypoint polling supply the flag in the correct position.
exec gosu "${LLDAP_UID}:${LLDAP_GID}" /app/lldap "$@"
