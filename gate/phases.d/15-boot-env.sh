# shellcheck shell=bash
# Phase: env validation — the entrypoint must refuse to boot, fast and with the exact
# message, when a required variable is missing. Uses throwaway containers.

D="$(phase_dir)"

check_missing_env() {
    local label="$1" expected="$2"
    shift 2
    local out rc
    out="$(timeout 25 docker run --rm --network none "$@" "$GATE_IMAGE" 2>&1)"
    rc=$?
    printf '%s\n' "$out" >"$D/$label.log"
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF "$expected"; then
        p_ok "$label: fast nonzero exit with the exact message"
    else
        p_bad "$label: rc=$rc or message missing (see $label.log)"
    fi
}

check_missing_env missing-jwt-secret "ERROR: LLDAP_JWT_SECRET is required." \
    -e LLDAP_LDAP_BASE_DN="$BASE_DN"

check_missing_env missing-base-dn "ERROR: LLDAP_LDAP_BASE_DN is required." \
    -e LLDAP_JWT_SECRET="$JWT_SECRET"
