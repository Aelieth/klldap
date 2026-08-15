# shellcheck shell=bash
# Phase: GraphQL auth surface — admin login (done by the runner) and the Kerberos
# public-key endpoint the web password flows depend on.

D="$(phase_dir)"

if [ -n "$TOKEN" ]; then
    p_ok "admin simple login yields a token"
else
    p_bad "no admin token"
fi

if graphql '{ kerberosInfo { publicKeyDerBase64 } }' >"$D/kerberos-info.json" 2>"$D/kerberos-info.err"; then
    pubkey="$(json_get kerberosInfo.publicKeyDerBase64 <"$D/kerberos-info.json")"
    if [ -n "$pubkey" ] && [ "$pubkey" != "None" ]; then
        p_ok "kerberosInfo.publicKeyDerBase64 is non-empty"
    else
        p_bad "kerberosInfo.publicKeyDerBase64 empty"
    fi
else
    p_bad "kerberosInfo query failed (see kerberos-info.err)"
fi
