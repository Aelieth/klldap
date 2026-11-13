#!/usr/bin/env bash
# ACC-8's host leg (D182): installs the staged binary under the tree's unit in the lab guest, as
# HOST row 4 did, and starts it enabled so it comes back after a cut. Run as root by dur.py.
# Usage: dur-host.sh DB_URL JWT SEED ADMIN_PASS BASE_DN REALM
set -euo pipefail
STAGE=/home/lab/klldap-stage
OPT=/opt/nitnelave
UNIT=/etc/systemd/system/klldap.service
DROP=/etc/systemd/system/klldap.service.d
db_url="$1" jwt="$2" seed="$3" admin="$4" base_dn="$5" realm="$6"
id klldap >/dev/null 2>&1 || useradd --system --home-dir "$OPT" --create-home --shell /sbin/nologin klldap
install -d -o klldap -g klldap -m 755 "$OPT"
install -o root -g root -m 755 "$STAGE/lldap" "$OPT/lldap"
install -o root -g root -m 644 "$STAGE/lldap.service" "$UNIT"
install -d -o root -g root -m 755 "$DROP"
install -d -o root -g root -m 700 "$OPT/secret"
(
    umask 077
    printf 'LLDAP_JWT_SECRET=%s\nLLDAP_KEY_SEED=%s\nLLDAP_LDAP_USER_PASS=%s\n' "$jwt" "$seed" "$admin" \
        >"$OPT/secret/env"
)
printf '[Service]\nEnvironmentFile=%s/secret/env\n' "$OPT" >"$DROP/env.conf"
case "$db_url" in
postgres*)
    printf '[Unit]\nWants=docker.service\nAfter=docker.service\n\n[Service]\n%s\n%s\n' \
        Restart=on-failure RestartSec=5 >"$DROP/postgres.conf"
    ;;
esac
cat >"$OPT/lldap_config.toml" <<EOF
ldap_base_dn = "$base_dn"
database_url = "$db_url"

[kerberos_options]
realm = "$realm"
data_dir = "$OPT/krb5kdc"
admin_keytab = "$OPT/kadm5.keytab"
client_config = "$OPT/krb5.conf"
EOF
chown klldap:klldap "$OPT/lldap_config.toml"
sha256sum "$OPT/lldap" "$UNIT" "$DROP"/*.conf "$OPT/lldap_config.toml"
systemctl daemon-reload
systemctl enable --now klldap
systemctl is-enabled klldap
