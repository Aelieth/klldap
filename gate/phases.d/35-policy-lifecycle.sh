# shellcheck shell=bash
# Phase: OU security policies over GraphQL — create, attach, resolve, block, clean up.

D="$(phase_dir)"
OU_NAME="gatepolicyou"

graphql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$OU_NAME"'"}' \
    >"$D/create-ou.json" 2>&1 || p_bad "createOu $OU_NAME failed"

graphql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id name } }' \
    '{"n": "GateHours", "i": [{"key": "require-mfa", "value": "always"}]}' \
    >"$D/create-policy.json" 2>&1 || p_bad "createPolicy failed"
PID="$(json_get createPolicy.id <"$D/create-policy.json")"
[ -n "$PID" ] || p_bad "createPolicy did not return an id"

graphql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' \
    '{"o": "'"$OU_NAME"'", "p": '"$PID"'}' >"$D/set.json" 2>&1 || p_bad "setOuPolicy failed"

graphql 'query($o: String!) { effectivePolicyItems(ou: $o) { key value sourceOu } }' \
    '{"o": "'"$OU_NAME"'"}' >"$D/effective.json" 2>&1 || p_bad "effectivePolicyItems failed"
if json_get effectivePolicyItems <"$D/effective.json" | grep -q always; then
    p_ok "effectivePolicyItems shows require-mfa=always from $OU_NAME"
else
    p_bad "effectivePolicyItems missing always: $(cat "$D/effective.json")"
fi

graphql 'mutation($o: String!, $b: Boolean!) { setOuPolicyInheritance(ou: $o, blocked: $b) { ok } }' \
    '{"o": "'"$OU_NAME"'", "b": true}' >"$D/block.json" 2>&1 || p_bad "block inheritance failed"

if graphql 'mutation { setOuPolicyInheritance(ou: "", blocked: true) { ok } }' '{}' \
    >"$D/root-block.json" 2>&1; then
    p_bad "root was allowed to block inheritance"
else
    p_ok "root cannot block inheritance"
fi

graphql 'mutation($n: String!) { deleteOu(name: $n) { ok } }' '{"n": "'"$OU_NAME"'"}' \
    >"$D/delete-ou.json" 2>&1 || p_bad "deleteOu failed"
graphql '{ ouPolicyStates { ou } }' '{}' >"$D/states.json" 2>&1 || p_bad "ouPolicyStates failed"
if grep -q "$OU_NAME" "$D/states.json"; then
    p_bad "ouPolicyStates still lists $OU_NAME after deleteOu"
else
    p_ok "deleteOu dropped policy state for $OU_NAME"
fi

ROWS="$(log_rows "kind='policy_change'")"
if [ "${ROWS:-0}" -gt 0 ]; then
    p_ok "policy_change rows recorded ($ROWS)"
else
    p_bad "no policy_change rows"
fi

graphql 'mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }' '{"p": '"$PID"'}' \
    >"$D/delete-policy.json" 2>&1 || p_bad "cleanup deletePolicy failed"
