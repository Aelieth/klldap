# shellcheck shell=bash
# Phase: lldap-cli replay — run the real Zepmann/lldap-cli against the gate server.
# SKIPs unless GATE_LLDAP_CLI points at the lldap-cli script (the in-repo raw-JSON
# replay in server/tests/lldap_cli_compat.rs covers the same surface in cargo).

D="$(phase_dir)"

if [ -z "${GATE_LLDAP_CLI:-}" ]; then
    p_skip "GATE_LLDAP_CLI not set"
elif [ ! -x "$GATE_LLDAP_CLI" ]; then
    p_bad "GATE_LLDAP_CLI=$GATE_LLDAP_CLI is not executable"
else
    export LLDAP_HTTPURL="http://127.0.0.1:$HTTP_PORT"
    export LLDAP_USERNAME="admin"
    export LLDAP_PASSWORD="$ADMIN_PASS"
    if t "$GATE_LLDAP_CLI" user list >"$D/user-list.txt" 2>&1 \
        && grep -q "admin" "$D/user-list.txt"; then
        p_ok "lldap-cli lists users (admin present)"
    else
        p_bad "lldap-cli user list failed (see user-list.txt)"
    fi
    if t "$GATE_LLDAP_CLI" group list >"$D/group-list.txt" 2>&1 \
        && grep -q "lldap_admin" "$D/group-list.txt"; then
        p_ok "lldap-cli lists groups (lldap_admin present)"
    else
        p_bad "lldap-cli group list failed (see group-list.txt)"
    fi
    unset LLDAP_HTTPURL LLDAP_USERNAME LLDAP_PASSWORD
fi
