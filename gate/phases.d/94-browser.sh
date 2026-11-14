# shellcheck shell=bash
# Phase: the real web app in a headless browser, then kinit against the
# embedded KDC. Gate files only. The browser image is not part of the release.

D="$(phase_dir)"
BROWSER_IMAGE="mcr.microsoft.com/playwright@sha256:766137e2d9caad4744187e53cdc89320ba6f2eb57cff097374020944b44dd0a9"
BROWSER_CTN="klldap-browser-${RUNID}"
BROWSER_USER="bwuser"

gen_pass() {
    python3 -c 'import secrets; print("Gw" + secrets.token_hex(8))'
}

expect_row() {
    local file="$1" name="$2" label="$3" line
    line="$(grep "^ROW ${name} " "$file" 2>/dev/null | head -1 || true)"
    if [ -z "$line" ]; then
        p_bad "$label: not reached"
        return 1
    fi
    case "$line" in
    "ROW ${name} PASS"*)
        p_ok "$label"
        return 0
        ;;
    *)
        p_bad "$label (${line#ROW "${name}" })"
        return 1
        ;;
    esac
}

note_marks() {
    local file="$1" line
    [ -f "$file" ] || return 0
    while IFS= read -r line; do
        case "$line" in
        CONTEXT\ * | FINDING\ *) note "$line" ;;
        esac
    done <"$file"
}

# Poll kinit. The principal can land just after the app's sync returns.
kinit_ok() {
    local principal="$1" password="$2" log="$3" start deadline
    start=$SECONDS
    deadline=$((SECONDS + ${GATE_TIMEOUT:-30}))
    KINIT_ATTEMPTS=0
    while [ "$SECONDS" -le "$deadline" ]; do
        KINIT_ATTEMPTS=$((KINIT_ATTEMPTS + 1))
        if kinit_pw "$principal" "$password" >"$log" 2>&1; then
            KINIT_WAITED=$((SECONDS - start))
            return 0
        fi
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 1
    done
    KINIT_WAITED=$((SECONDS - start))
    return 1
}

run_mode() {
    local mode="$1"
    docker rm -f "$BROWSER_CTN" >/dev/null 2>&1 || true
    # -e NAME, not -e NAME=value, so the passwords are not on the host's command line.
    (
        export BROWSER_ADMIN_PASS="$ADMIN_PASS"
        export BROWSER_PASS="$FIRST_PASS"
        export BROWSER_NEW_PASS="$SECOND_PASS"
        timeout 180 docker run --rm --name "$BROWSER_CTN" \
            --network "$NET" \
            --init \
            --shm-size=1g \
            --user "$(id -u):$(id -g)" \
            --entrypoint node \
            -v "$GATE_ROOT/lib/browser.mjs:/work/browser.mjs:ro" \
            -v "$D:/out" \
            -e HOME=/tmp/home \
            -e BROWSER_OUT=/out \
            -e BROWSER_MODE="$mode" \
            -e BROWSER_URL="http://${CONTAINER}:17170" \
            -e BROWSER_USER="$BROWSER_USER" \
            -e BROWSER_ADMIN_PASS \
            -e BROWSER_PASS \
            -e BROWSER_NEW_PASS \
            "$BROWSER_IMAGE" /work/browser.mjs \
            >"$D/${mode}.out" 2>"$D/${mode}.err"
    )
}

# Own check of the kinit log: the row passes only when it says Password incorrect.
old_password_refused() {
    ! kinit_pw "${BROWSER_USER}@${REALM}" "$FIRST_PASS" >"$D/kinit-old.log" 2>&1 \
        && grep -q "Password incorrect" "$D/kinit-old.log"
}

if ! docker image inspect "$BROWSER_IMAGE" >/dev/null 2>&1; then
    p_skip "browser image absent: ${BROWSER_IMAGE}"
else
    EXTRA_CONTAINERS+=("$BROWSER_CTN")
    FIRST_PASS="$(gen_pass)"
    SECOND_PASS="$(gen_pass)"
    if [ -z "$FIRST_PASS" ] || [ -z "$SECOND_PASS" ]; then
        p_bad "could not make a per-run password"
        p_bad "admin logs in through the app: not reached"
        p_bad "creates a user: not reached"
        p_bad "kinit with the first password gets a ticket: not reached"
        p_bad "the user logs in through the app: not reached"
        p_bad "changes the password: not reached"
        p_bad "kinit with the old password is refused: not reached"
        p_bad "kinit with the new password succeeds: not reached"
    else
    run_mode create || true
    note_marks "$D/create.out"
    if ! expect_row "$D/create.out" admin-login "admin logs in through the app"; then
        p_bad "creates a user: not reached"
        p_bad "kinit with the first password gets a ticket: not reached"
        p_bad "the user logs in through the app: not reached"
        p_bad "changes the password: not reached"
        p_bad "kinit with the old password is refused: not reached"
        p_bad "kinit with the new password succeeds: not reached"
    elif ! expect_row "$D/create.out" create "creates a user"; then
        p_bad "kinit with the first password gets a ticket: not reached"
        p_bad "the user logs in through the app: not reached"
        p_bad "changes the password: not reached"
        p_bad "kinit with the old password is refused: not reached"
        p_bad "kinit with the new password succeeds: not reached"
    elif ! kinit_ok "${BROWSER_USER}@${REALM}" "$FIRST_PASS" "$D/kinit-first.log"; then
        note "first kinit waited ${KINIT_WAITED}s attempts ${KINIT_ATTEMPTS}"
        p_bad "kinit with the first password failed"
        p_bad "the user logs in through the app: not reached"
        p_bad "changes the password: not reached"
        p_bad "kinit with the old password is refused: not reached"
        p_bad "kinit with the new password succeeds: not reached"
    else
        note "first kinit waited ${KINIT_WAITED}s attempts ${KINIT_ATTEMPTS}"
        p_ok "kinit with the first password gets a ticket"
        run_mode change || true
        note_marks "$D/change.out"
        if ! expect_row "$D/change.out" user-login "the user logs in through the app"; then
            p_bad "changes the password: not reached"
            p_bad "kinit with the old password is refused: not reached"
            p_bad "kinit with the new password succeeds: not reached"
        elif ! expect_row "$D/change.out" change "changes the password"; then
            p_bad "kinit with the old password is refused: not reached"
            p_bad "kinit with the new password succeeds: not reached"
        elif ! old_password_refused; then
            p_bad "kinit with the old password was not refused with 'Password incorrect'"
            p_bad "kinit with the new password succeeds: not reached"
        elif kinit_ok "${BROWSER_USER}@${REALM}" "$SECOND_PASS" "$D/kinit-new.log"; then
            p_ok "kinit with the old password is refused"
            p_ok "kinit with the new password succeeds"
        else
            p_ok "kinit with the old password is refused"
            p_bad "kinit with the new password failed"
        fi
    fi
    fi
    docker rm -f "$BROWSER_CTN" >/dev/null 2>&1 || true
fi
