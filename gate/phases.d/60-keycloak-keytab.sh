# shellcheck shell=bash
# Phase: Keycloak keytab export — the GraphQL mutation must produce a real keytab with
# the HTTP service principal and modern enctypes. Standing net for the sudo-surface
# fragility around export_keytab_for_keycloak.

D="$(phase_dir)"
KC_HOST="keycloak.gate.test"

if graphql 'mutation($h: String!) { exportKeytabForKeycloak(hostname: $h) { ok path errorMsg } }' \
    '{"h": "'"$KC_HOST"'"}' >"$D/export.json" 2>"$D/export.err"; then
    ok="$(json_get exportKeytabForKeycloak.ok <"$D/export.json")"
    path="$(json_get exportKeytabForKeycloak.path <"$D/export.json")"
    if [ "$ok" = "True" ] || [ "$ok" = "true" ]; then
        p_ok "exportKeytabForKeycloak reports success ($path)"
    else
        p_bad "exportKeytabForKeycloak ok=false: $(json_get exportKeytabForKeycloak.errorMsg <"$D/export.json")"
    fi
else
    p_bad "exportKeytabForKeycloak mutation failed"
fi

gexec klist -kt /data/keytab/keycloak-http.keytab >"$D/klist.txt" 2>&1
if grep -q "HTTP/$KC_HOST@$REALM" "$D/klist.txt"; then
    p_ok "keytab holds HTTP/$KC_HOST@$REALM"
else
    p_bad "service principal missing from the exported keytab"
fi
if gexec klist -kte /data/keytab/keycloak-http.keytab | grep -q "aes256-cts"; then
    p_ok "keytab uses aes256"
else
    p_bad "keytab lacks aes256 enctype"
fi

princ_count="$(grep -c "HTTP/$KC_HOST@$REALM" "$D/klist.txt")"
note "  keytab entries for the principal: $princ_count"
