# shellcheck shell=bash
# Phase: GraphQL auth surface — admin login (done by the runner) and kerberosInfo, which names the
# realm's state and no envelope key: the pages take the key a sign-in bound (phase 98's driver).

D="$(phase_dir)"

if [ -n "$TOKEN" ]; then
    p_ok "admin simple login yields a token"
else
    p_bad "no admin token"
fi

if graphql '{ kerberosInfo { enabled state } }' >"$D/kerberos-info.json" 2>"$D/kerberos-info.err"; then
    p_ok "kerberosInfo answers: $(cat "$D/kerberos-info.json")"
else
    p_bad "kerberosInfo query failed (see kerberos-info.err)"
fi

GQ_URL="$(http_url)/api/graphql" GQ_TOKEN="$TOKEN" t python3 - >"$D/kerberos-info-key.out" 2>&1 <<'PY'
import json, os, urllib.error, urllib.request
req = urllib.request.Request(
    os.environ["GQ_URL"],
    data=json.dumps({"query": "{ kerberosInfo { publicKeyDerBase64 } }"}).encode(),
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer " + os.environ["GQ_TOKEN"]})
try:
    body = urllib.request.urlopen(req).read().decode()
except urllib.error.HTTPError as e:
    body = e.read().decode()
try:
    answer = json.loads(body)
    errors = [error.get("message", "") for error in answer.get("errors") or []]
    print(" | ".join(errors) if errors else json.dumps(answer.get("data")))
except (ValueError, TypeError):
    print(body.strip()[:300])
PY
if grep -qF 'Unknown field "publicKeyDerBase64" on type "KerberosInfo"' "$D/kerberos-info-key.out"; then
    p_ok "kerberosInfo answers no envelope key: publicKeyDerBase64 is an unknown field"
else
    p_bad "kerberosInfo.publicKeyDerBase64 answered (see kerberos-info-key.out)"
fi
