# shellcheck shell=bash
# Phase: bootstrap idempotence — a restart reopens the existing realm without creating or
# losing principals, and a deleted admin keytab is written again with the same key version.

D="$(phase_dir)"

kadmin_q listprincs 2>/dev/null | grep '@' | sort >"$D/listprincs-before.txt"
kvno_before="$(admin_kvno)"
gexec rm -f /data/kadm5.keytab
restart_stamp="$(date +%s)"

if t docker restart "$CONTAINER" >/dev/null 2>&1 && wait_healthy 90; then
    p_ok "healthy again after a restart without the admin keytab"
else
    p_bad "container did not become healthy after the restart"
fi
discover_ports || p_bad "port discovery failed after restart"
TOKEN="$(gate_login)" || p_bad "admin login failed after restart"

docker logs --since "$restart_stamp" "$CONTAINER" >"$D/restart-docker.log" 2>&1
if grep -q "Kerberos realm $REALM serving" "$D/restart-docker.log"; then
    p_ok "the realm reopened"
else
    p_bad "no 'Kerberos realm $REALM serving' after restart"
fi
if gexec sh -c '[ -s /data/kadm5.keytab ]'; then
    p_ok "the deleted admin keytab is back"
else
    p_bad "/data/kadm5.keytab was not written again"
fi
kadmin_q listprincs 2>/dev/null | grep '@' | sort >"$D/listprincs-after.txt"
if [ -s "$D/listprincs-before.txt" ] && cmp -s "$D/listprincs-before.txt" "$D/listprincs-after.txt"; then
    p_ok "the restart created and lost no principals"
else
    p_bad "principals differ across the restart (see listprincs-before/after.txt)"
fi
kvno_after="$(admin_kvno)"
if [ -n "$kvno_before" ] && [ "$kvno_before" = "$kvno_after" ]; then
    p_ok "admin key vno unchanged ($kvno_after)"
else
    p_bad "admin key vno changed ($kvno_before → $kvno_after)"
fi
