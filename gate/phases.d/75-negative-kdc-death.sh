# shellcheck shell=bash
# Phase: negative — when the KDC dies, the container must STOP looking healthy.
# The --kerberos healthcheck leg is what turns silent sync degradation into a hard
# health failure. Runs late: it leaves the Kerberos stack dead on purpose.

D="$(phase_dir)"

kill_comm() {
    gexec sh -c '
        killed=1
        for p in /proc/[0-9]*; do
            [ -r "$p/comm" ] || continue
            read -r comm <"$p/comm" || continue
            if [ "$comm" = "'"$1"'" ]; then
                kill "${p#/proc/}" && killed=0
            fi
        done
        exit $killed'
}

if gexec /app/lldap healthcheck --config-file /data/lldap_config.toml --kerberos \
    >"$D/health-before.log" 2>&1; then
    p_ok "healthcheck --kerberos passes with a live KDC"
else
    p_bad "healthcheck --kerberos failed while the KDC is alive"
fi

if kill_comm krb5kdc && kill_comm kadmind; then
    p_ok "killed krb5kdc and kadmind"
else
    p_bad "could not kill the KDC daemons"
fi
sleep 2

if gexec /app/lldap healthcheck --config-file /data/lldap_config.toml --kerberos \
    >"$D/health-after.log" 2>&1; then
    p_bad "healthcheck --kerberos still passes with a dead KDC"
else
    p_ok "healthcheck --kerberos fails once the KDC is dead"
fi

# LDAP/HTTP health must be unaffected — the KDC leg is additive (the image turns it on by
# default, so it is switched off explicitly here).
if gexec env LLDAP_HEALTHCHECK_OPTIONS__KERBEROS=false /app/lldap healthcheck \
    --config-file /data/lldap_config.toml >"$D/health-plain.log" 2>&1; then
    p_ok "plain healthcheck still passes (LDAP/HTTP unaffected)"
else
    p_bad "plain healthcheck failed after KDC death"
fi
