# shellcheck shell=bash
# Phase: fresh boot health — supervisor markers, process identities, KDC bootstrap
# artifacts, first kinit. The container was started and health-polled by the runner.

D="$(phase_dir)"

# The entrypoint polls the healthcheck once a second, as the runner does from outside; the
# markers can trail the runner's first success by a poll interval.
for _ in $(seq 1 30); do
    docker logs "$CONTAINER" >"$D/docker.log" 2>&1
    grep -q "Starting Kerberos manager" "$D/docker.log" && break
    sleep 1
done
if grep -q "LLDAP is ready!" "$D/docker.log"; then
    p_ok "entrypoint reported LLDAP ready"
else
    p_bad "missing 'LLDAP is ready!' marker in logs"
fi
if grep -q "Starting Kerberos manager" "$D/docker.log"; then
    p_ok "entrypoint reached the Kerberos manager stage"
else
    p_bad "missing 'Starting Kerberos manager' marker in logs"
fi

# The KDC bootstraps after LLDAP is healthy; give it a moment on slow machines.
kdc_up=""
for _ in $(seq 1 60); do
    if proc_running krb5kdc && proc_running kadmind; then
        kdc_up=1
        break
    fi
    sleep 1
done
if [ -n "$kdc_up" ]; then
    p_ok "krb5kdc and kadmind are running"
else
    p_bad "krb5kdc/kadmind did not come up within 60s of a healthy server"
fi
if proc_running kerberos_manager; then
    p_ok "kerberos_manager is running"
else
    p_bad "kerberos_manager is not running"
fi

# Server identity: must run as the lldap user (1000), not root. Regression assertion
# for the bash-readonly-UID gosu bug.
lldap_uid="$(uid_of_comm lldap)"
if [ "$lldap_uid" = "1000" ]; then
    p_ok "lldap server runs as uid 1000"
else
    p_bad "lldap server runs as uid '${lldap_uid:-unknown}' (expected 1000)"
fi

if gexec sh -c '[ -f /data/kadm5.keytab ]'; then
    p_ok "admin keytab exists"
    mode_owner="$(gexec stat -c '%a %U:%G' /data/kadm5.keytab 2>/dev/null || echo unknown)"
    if [ "$mode_owner" = "640 lldap:lldap" ]; then
        p_ok "keytab is 640 lldap:lldap"
    else
        p_bad "keytab mode/owner is '$mode_owner' (expected '640 lldap:lldap')"
    fi
else
    p_bad "/data/kadm5.keytab missing"
fi

if file_contains /etc/krb5.conf "$REALM" && file_contains /var/kerberos/krb5kdc/kdc.conf "$REALM"; then
    p_ok "rendered configs carry realm $REALM"
else
    p_bad "krb5.conf / kdc.conf do not both mention $REALM"
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

# kadmind must actually write its configured log (regression for the template
# pointing at a path the image never created).
if gexec sh -c '[ -s /var/log/kadmind.log ] || [ -s /var/log/krb5/kadmind.log ]'; then
    p_ok "kadmind log is being written"
else
    p_bad "kadmind log missing/empty (template path vs created dirs)"
fi
