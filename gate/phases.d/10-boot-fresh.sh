# shellcheck shell=bash
# Phase: fresh boot health — one process serves LDAP, HTTP and the realm, as the lldap user,
# with the realm's files in place and a first kinit. The runner started and health-polled it.

D="$(phase_dir)"

docker logs "$CONTAINER" >"$D/docker.log" 2>&1
if grep -q "Kerberos realm $REALM serving" "$D/docker.log"; then
    p_ok "server reported the realm serving"
else
    p_bad "missing 'Kerberos realm $REALM serving' in logs"
fi

# Server identity: must run as the lldap user (1000), not root. Regression assertion
# for the bash-readonly-UID bug.
lldap_uid="$(uid_of_comm lldap)"
if [ "$lldap_uid" = "1000" ]; then
    p_ok "lldap server runs as uid 1000"
else
    p_bad "lldap server runs as uid '${lldap_uid:-unknown}' (expected 1000)"
fi
# gosu passes no capability: the server holds none.
caps="$(gexec sh -c 'for p in /proc/[0-9]*; do
    read -r comm <"$p/comm" 2>/dev/null
    if [ "$comm" = lldap ]; then awk "/^Cap(Prm|Eff|Amb):/ {printf \"%s \", \$2}" "$p/status"; exit 0; fi
done; exit 1')"
if [ "$caps" = "0000000000000000 0000000000000000 0000000000000000 " ]; then
    p_ok "the server holds no capability (permitted, effective, ambient)"
else
    p_bad "the server's CapPrm/CapEff/CapAmb are '$caps' (expected none)"
fi

# /proc/net/udp lists each socket's port in hex and its owner uid.
kdc_hex="$(printf ':%04X' "$KDC_INNER_PORT")"
kdc_uid="$(gexec awk -v port="$kdc_hex" 'NR > 1 && substr($2, length($2) - 4) == port {print $8; exit}' /proc/net/udp)"
if [ "$kdc_uid" = "1000" ]; then
    p_ok "the KDC on UDP $KDC_INNER_PORT belongs to uid 1000"
else
    p_bad "UDP $KDC_INNER_PORT belongs to uid '${kdc_uid:-nobody}' (expected 1000)"
fi
if gexec sh -c '[ ! -e /usr/sbin/krb5kdc ] && [ ! -e /usr/sbin/kadmind ] && [ ! -e /usr/sbin/kadmin.local ]'; then
    p_ok "no MIT server programs in the image"
else
    p_bad "MIT server programs are still in the image"
fi

if gexec sh -c '[ -f /data/kadm5.keytab ]'; then
    p_ok "admin keytab exists"
    mode_owner="$(gexec stat -c '%a %U:%G' /data/kadm5.keytab 2>/dev/null || echo unknown)"
    if [ "$mode_owner" = "600 lldap:lldap" ]; then
        p_ok "keytab is 600 lldap:lldap"
    else
        p_bad "keytab mode/owner is '$mode_owner' (expected '600 lldap:lldap')"
    fi
else
    p_bad "/data/kadm5.keytab missing"
fi
realm_dir="$(gexec stat -c '%a %U:%G' /var/kerberos/krb5kdc 2>/dev/null || echo unknown)"
if [ "$realm_dir" = "700 lldap:lldap" ]; then
    p_ok "realm directory is 700 lldap:lldap"
else
    p_bad "realm directory is '$realm_dir' (expected '700 lldap:lldap')"
fi

if [ "$(gexec printenv KRB5_CONFIG)" = "/data/krb5.conf" ] && file_contains /data/krb5.conf "$REALM"; then
    p_ok "KRB5_CONFIG points at /data/krb5.conf, which carries realm $REALM"
else
    p_bad "KRB5_CONFIG is not /data/krb5.conf, or the file lacks $REALM"
fi

kadmin_q listprincs >"$D/listprincs.txt" 2>&1
if grep -q "admin/admin@$REALM" "$D/listprincs.txt" && grep -q "K/M@$REALM" "$D/listprincs.txt"; then
    p_ok "KDB contains admin/admin and K/M"
else
    p_bad "listprincs missing admin/admin or K/M (see listprincs.txt)"
fi

if gexec sh -c "KRB5CCNAME=/tmp/gate_boot_cc kinit -kt /data/kadm5.keytab admin/admin@$REALM" \
    >"$D/kinit-keytab.log" 2>&1; then
    p_ok "kinit with the admin keytab succeeds"
else
    p_bad "kinit -kt with the admin keytab failed"
fi
