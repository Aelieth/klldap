# shellcheck shell=bash
# Phase: bootstrap idempotence — re-running the manager's bootstrap against a live,
# already-bootstrapped system must take the existing-database path and change nothing.

D="$(phase_dir)"

keytab_before="$(file_digest /data/kadm5.keytab)"
kvno_before="$(kadmin_q "getprinc admin/admin@$REALM" | grep -m1 "vno" | awk '{print $3}' | tr -d ',')"

if gexec /app/kerberos_manager --bootstrap-only >"$D/bootstrap-only.log" 2>&1; then
    p_ok "second --bootstrap-only run exits cleanly"
else
    p_bad "second --bootstrap-only run failed (see bootstrap-only.log)"
fi
if grep -q "Existing KDC database detected" "$D/bootstrap-only.log"; then
    p_ok "re-run takes the existing-database path"
else
    p_bad "re-run did not report the existing database"
fi
if grep -q "addprinc" "$D/bootstrap-only.log"; then
    p_bad "re-run created principals"
else
    p_ok "re-run created no principals"
fi

keytab_after="$(file_digest /data/kadm5.keytab)"
kvno_after="$(kadmin_q "getprinc admin/admin@$REALM" | grep -m1 "vno" | awk '{print $3}' | tr -d ',')"
if [ -n "$keytab_before" ] && [ "$keytab_before" = "$keytab_after" ]; then
    p_ok "keytab untouched by the re-run"
else
    p_bad "keytab changed on re-run"
fi
if [ -n "$kvno_before" ] && [ "$kvno_before" = "$kvno_after" ]; then
    p_ok "admin key vno untouched by the re-run ($kvno_after)"
else
    p_bad "admin key vno changed on re-run ($kvno_before → $kvno_after)"
fi
