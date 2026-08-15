# shellcheck shell=bash
# Phase: migration boot — boot the image against an existing /data + KDC volume set
# (the 03 contract). SKIPs unless the fixture env is provided; `test-klldap/` next to
# the repo is the local reference set. The fixture dirs are copied first: booting
# migrates the database in place.
#
# Required env: GATE_FIXTURE_DATA, GATE_FIXTURE_KDC, GATE_FIXTURE_BASE_DN
# Optional:     GATE_FIXTURE_ADMIN_PASS (enables the login assertion)

D="$(phase_dir)"

if [ -z "${GATE_FIXTURE_DATA:-}" ] || [ -z "${GATE_FIXTURE_KDC:-}" ] || [ -z "${GATE_FIXTURE_BASE_DN:-}" ]; then
    p_skip "GATE_FIXTURE_DATA/GATE_FIXTURE_KDC/GATE_FIXTURE_BASE_DN not set"
else
    MIG_CONTAINER="klldap-gate-mig-$RUNID"
    EXTRA_CONTAINERS+=("$MIG_CONTAINER")
    WORK="$D/volumes"
    mkdir -p "$WORK"
    cp -a "$GATE_FIXTURE_DATA" "$WORK/data"
    cp -a "$GATE_FIXTURE_KDC" "$WORK/krb5kdc"

    docker run -d --name "$MIG_CONTAINER" \
        --network "$NET" \
        -p "127.0.0.1::17170" \
        -v "$WORK/data:/data" -v "$WORK/krb5kdc:/var/kerberos/krb5kdc" \
        -e LLDAP_JWT_SECRET="$JWT_SECRET" \
        -e LLDAP_LDAP_BASE_DN="$GATE_FIXTURE_BASE_DN" \
        "$GATE_IMAGE" >/dev/null

    mig_healthy=""
    for _ in $(seq 1 120); do
        if docker exec "$MIG_CONTAINER" /app/lldap healthcheck \
            --config-file /data/lldap_config.toml >/dev/null 2>&1; then
            mig_healthy=1
            break
        fi
        if [ -z "$(docker ps -q -f "name=^$MIG_CONTAINER$")" ]; then
            break
        fi
        sleep 1
    done
    if [ -n "$mig_healthy" ]; then
        p_ok "fixture volumes boot to healthy"
    else
        p_bad "fixture boot did not become healthy"
        docker logs "$MIG_CONTAINER" >"$D/mig-docker.log" 2>&1
    fi

    if [ -n "$mig_healthy" ]; then
        # The KDC bootstraps after LLDAP is healthy; wait for the Kerberos leg too.
        for _ in $(seq 1 90); do
            if docker exec "$MIG_CONTAINER" /app/lldap healthcheck \
                --config-file /data/lldap_config.toml --kerberos >/dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        if gexec_in "$MIG_CONTAINER" kadmin.local -q listprincs >"$D/listprincs.txt" 2>&1 \
            && grep -q "@" "$D/listprincs.txt"; then
            p_ok "migrated KDC lists principals"
        else
            p_bad "migrated KDC has no principals"
        fi
        if [ -n "${GATE_FIXTURE_ADMIN_PASS:-}" ]; then
            mig_http="$(docker port "$MIG_CONTAINER" 17170/tcp | head -1 | sed 's/.*://')"
            if HTTP_PORT="$mig_http" gate_login admin "$GATE_FIXTURE_ADMIN_PASS" >/dev/null 2>"$D/login.err"; then
                p_ok "admin logs in on the migrated database"
            else
                p_bad "admin login failed on the migrated database"
            fi
        else
            p_skip "GATE_FIXTURE_ADMIN_PASS not set — login assertion skipped"
        fi
    fi

    # The container wrote into the bind-mounted copies as root; hand them back to the
    # invoking user so the results directory stays deletable without sudo.
    docker exec "$MIG_CONTAINER" chown -R "$(id -u):$(id -g)" /data /var/kerberos/krb5kdc \
        >/dev/null 2>&1
    docker rm -f "$MIG_CONTAINER" >/dev/null 2>&1
fi
