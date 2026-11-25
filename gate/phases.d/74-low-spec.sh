# shellcheck shell=bash
# Phase: the low-spec row. The image held to 1 CPU and 256 MB as its own SQLite side server (the
# realm on); a flood of each kind of request that needs no credential, one kind at a time; per
# kind the rows the event log gained, the server's memory before, at its highest and after, and
# the time of an ordinary bind meanwhile. A threshold left empty reports its number as measured.

# What the environment may set:
LS_SECONDS="${GATE_LOWSPEC_SECONDS:-20}"       # the length of each kind's flood
LS_SENDERS="${GATE_LOWSPEC_SENDERS:-8}"        # the parallel senders of each kind
LS_SETTLE="${GATE_LOWSPEC_SETTLE:-25}"         # quiet seconds after a flood: its windows close (20 s idle), the writer ticks
LS_CPUSET="${GATE_LOWSPEC_CPUSET:-0}"          # the one core the server is pinned to
LS_BIND_WAIT="${GATE_LOWSPEC_BIND_WAIT:-30}"   # the seconds an ordinary bind is waited for
LS_KINDS="${GATE_LOWSPEC_KINDS:-}"             # some of the kinds below, comma or space separated; empty: all
# The thresholds, each for every kind; empty: measured, neither PASS nor FAIL.
LS_MAX_ROWS="${GATE_LOWSPEC_MAX_ROWS:-}"       # the most one-to-one log rows a kind may write
LS_MAX_MEM_MB="${GATE_LOWSPEC_MAX_MEM_MB:-}"   # the most megabytes the server may have grown by after the settle
LS_MAX_BIND_MS="${GATE_LOWSPEC_MAX_BIND_MS:-}" # the longest an ordinary bind may take during a flood

LS_ALL="ldap-unknown ldap-wrong ldap-locked web-start web-finish simple-wrong refresh-junk reset-unknown kinit-wrong"
LS_CPUS=1 LS_MEM_MB=256
LS_START_WAIT=180 LS_SAMPLE_EVERY=5
LS_D="$(phase_dir)"
LS_RUN="ls$(date +%H%M%S)"
LS_SRV="${CONTAINER}-ls" LS_VOL="${CONTAINER}-ls-data" LS_KVOL="${CONTAINER}-ls-kdc"
LS_CLIENT="klldap-lsclient-${RUNID}" LS_PROBE="klldap-lsprobe-${RUNID}"
LS_LEGIT="${LS_RUN}-legit" LS_FREE="${LS_RUN}-free" LS_HELD="${LS_RUN}-held" LS_OU="${LS_RUN}ou"
LS_LEGIT_DN="" LS_FREE_DN="" LS_HELD_DN="" LS_WHY="" LS_SEEN="" LS_PORTS="default"
LS_USED=0 LS_STARTS=0 LS_PRINCIPAL=0
LS_LIMITS=(--cpus "$LS_CPUS" --cpuset-cpus "$LS_CPUSET" --memory "${LS_MEM_MB}m" --memory-swap "${LS_MEM_MB}m")
# Read inside a container: its own cgroup (v2), each value after its file's name.
LS_LIMITS_SH='for f in memory.max memory.swap.max cpu.max cpuset.cpus.effective; do printf "%s " "$f"; cat "/sys/fs/cgroup/$f" 2>/dev/null || echo unread; done'
LS_MEM_SH='for f in memory.current memory.peak; do printf "%s " "$f"; cat "/sys/fs/cgroup/$f" 2>/dev/null || echo unread; done; cat /sys/fs/cgroup/memory.stat /sys/fs/cgroup/memory.events 2>/dev/null'
LS_XT=0
case $- in *x*) LS_XT=1 ;; esac
{ set +x; } 2>/dev/null
LS_PASS="$(python3 -c 'import secrets; print("Ls" + secrets.token_hex(10) + "!")')"
[ "$LS_XT" = 1 ] && set -x
EXTRA_CONTAINERS+=("$LS_SRV" "$LS_CLIENT" "$LS_PROBE")
EXTRA_VOLUMES+=("$LS_VOL" "$LS_KVOL")

ls_note() { note "[NOTE] ${PHASE}: $1"; }
ls_py() { python3 "$GATE_ROOT/lib/lowspec.py" "$@"; }
ls_gql() { graphql "$1" "$2" 2>"$LS_D/last.err"; }
ls_hush() {
    local xt=0 rc
    case $- in *x*) xt=1 ;; esac
    { set +x; } 2>/dev/null
    "$@"
    rc=$?
    [ "$xt" = 1 ] && set -x
    return "$rc"
}
ls__pw_vars() { LSU="$1" LSP="$LS_PASS" python3 -c 'import json,os; print(json.dumps({"id": os.environ["LSU"], "pw": os.environ["LSP"]}))'; }
ls_number() { case "$1" in "" | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }
ls_val() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" <<<"$2"; }

# ls_args: the settings are whole numbers and the kinds are known ones; else LS_WHY.
ls_args() {
    local name kind
    for name in LS_SECONDS LS_SENDERS LS_SETTLE LS_CPUSET LS_BIND_WAIT; do
        ls_number "${!name}" || LS_WHY+="GATE_LOWSPEC_${name#LS_}='${!name}' is not a whole number; "
    done
    for name in LS_MAX_ROWS LS_MAX_MEM_MB LS_MAX_BIND_MS; do
        [ -z "${!name}" ] || ls_number "${!name}" || LS_WHY+="GATE_LOWSPEC_${name#LS_}='${!name}' is not a whole number; "
    done
    [ -n "$LS_WHY" ] || [ "$LS_SECONDS" -ge 1 ] || LS_WHY+="GATE_LOWSPEC_SECONDS is 0; "
    [ -n "$LS_WHY" ] || [ "$LS_SENDERS" -ge 1 ] || LS_WHY+="GATE_LOWSPEC_SENDERS is 0; "
    [ -n "$LS_WHY" ] || [ "$LS_BIND_WAIT" -ge 1 ] || LS_WHY+="GATE_LOWSPEC_BIND_WAIT is 0; "
    LS_KINDS="$(printf '%s' "${LS_KINDS:-$LS_ALL}" | tr ',' ' ')"
    for kind in $LS_KINDS; do
        case " $LS_ALL " in *" $kind "*) ;; *) LS_WHY+="GATE_LOWSPEC_KINDS names '$kind' (the kinds: $LS_ALL); " ;; esac
    done
    [ -z "$LS_WHY" ]
}

# ls_limits_check <file>: the limits as that container's cgroup shows them; LS_SEEN, or LS_WHY.
ls_limits_check() {
    local verdict
    verdict="$(ls_py limits --memory $((LS_MEM_MB * 1048576)) --cpus "$LS_CPUS" --cpuset "$LS_CPUSET" <"$1" 2>"$LS_D/limits-check.err")"
    case "$verdict" in
    "ok "*)
        LS_SEEN="${verdict#ok }"
        return 0
        ;;
    esac
    LS_WHY="${verdict#no }"
    LS_WHY="${LS_WHY:-the limits could not be judged (see limits-check.err)}"
    return 1
}

# ls_limits_probe: can this host hold a container to the limits? One short container says, before any server.
ls_limits_probe() {
    local rc
    docker rm -f -v "$LS_PROBE" >/dev/null 2>&1
    timeout 120 docker run --rm --name "$LS_PROBE" "${LS_LIMITS[@]}" --entrypoint sh "$GATE_IMAGE" -c "$LS_LIMITS_SH" \
        >"$LS_D/limits-probe.out" 2>"$LS_D/limits-probe.err"
    rc=$?
    docker rm -f -v "$LS_PROBE" >/dev/null 2>&1
    if [ "$rc" != 0 ]; then
        LS_WHY="docker run ${LS_LIMITS[*]} exited $rc: $(head -c 300 "$LS_D/limits-probe.err" | tr '\n' ' ')"
        return 1
    fi
    ls_limits_check "$LS_D/limits-probe.out" && return 0
    [ -s "$LS_D/limits-probe.err" ] && LS_WHY+="; docker said: $(head -c 300 "$LS_D/limits-probe.err" | tr '\n' ' ')"
    return 1
}

# The client: the image itself, idle on the gate's network and under no limit. A wide port range
# and early reuse of closed ports keep a minute of new connections going; without them, as it is.
ls_client_up() {
    docker rm -f -v "$LS_CLIENT" >/dev/null 2>&1
    LS_PORTS="wide"
    docker run -d --name "$LS_CLIENT" --network "$NET" --sysctl "net.ipv4.ip_local_port_range=1024 65535" \
        --sysctl net.ipv4.tcp_tw_reuse=1 --entrypoint sleep "$GATE_IMAGE" 86400 >/dev/null 2>"$LS_D/client.err" || {
        docker rm -f -v "$LS_CLIENT" >/dev/null 2>&1
        LS_PORTS="default"
        docker run -d --name "$LS_CLIENT" --network "$NET" --entrypoint sleep "$GATE_IMAGE" 86400 \
            >/dev/null 2>>"$LS_D/client.err" || return 1
    }
    printf '[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n dns_lookup_realm = false\n udp_preference_limit = 1\n rdns = false\n[realms]\n %s = {\n  kdc = %s:%s\n }\n' \
        "$REALM" "$REALM" "$LS_SRV" "$KDC_INNER_PORT" >"$LS_D/krb5.conf"
    docker cp "$LS_D/krb5.conf" "$LS_CLIENT:/tmp/lowspec-krb5.conf" >/dev/null 2>>"$LS_D/client.err" &&
        docker cp "$GATE_ROOT/lib/lowspec-client.sh" "$LS_CLIENT:/tmp/lowspec-client.sh" >/dev/null 2>>"$LS_D/client.err"
}

ls_healthy() { docker exec "$LS_SRV" /app/lldap healthcheck --config-file /data/lldap_config.toml >/dev/null 2>&1; }

# ls_server_up: the limited server, its limits read back, its users and policy. 0; 1 with LS_WHY;
# 2 with LS_WHY when the server runs but its cgroup does not show the limits.
ls_server_up() {
    local ports i=0
    LS_WHY=""
    LS_STARTS=$((LS_STARTS + 1))
    # Password reset is on for the reset kind. Only names with no user are sent, and those are
    # answered before any mail; the mail server named is the container's own discard port.
    ports="$(side_up_kdc "$LS_SRV" "$LS_VOL" "$LS_KVOL" "${LS_LIMITS[@]}" -e LLDAP_VERBOSE=false \
        -e LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET=true -e LLDAP_SMTP_OPTIONS__SERVER=127.0.0.1 \
        -e LLDAP_SMTP_OPTIONS__PORT=9 -e LLDAP_SMTP_OPTIONS__SMTP_ENCRYPTION=NONE 2>"$LS_D/server-up.err")" || {
        # side_up_kdc waits 90 s; on one core the start may take longer.
        while [ -n "$(docker ps -q -f "name=^${LS_SRV}$")" ] && [ "$i" -lt "$LS_START_WAIT" ] && ! ls_healthy; do
            sleep 1
            i=$((i + 1))
        done
        ls_healthy || {
            LS_WHY="the server under ${LS_LIMITS[*]} did not start, stopped, or was not healthy $((90 + i)) s after its start: $(head -c 200 "$LS_D/server-up.err" | tr '\n' ' ')(see server-$LS_STARTS.log)"
            return 1
        }
        ports="$(docker port "$LS_SRV" 17170/tcp | head -1 | sed 's/.*://') $(docker port "$LS_SRV" 3890/tcp | head -1 | sed 's/.*://')"
    }
    timeout 30 docker exec "$LS_SRV" sh -c "$LS_LIMITS_SH" >"$LS_D/limits-server.out" 2>"$LS_D/limits-server.err"
    ls_limits_check "$LS_D/limits-server.out" || return 2
    LS_SEEN+=" verbose=$(timeout 30 docker exec "$LS_SRV" printenv LLDAP_VERBOSE 2>/dev/null || echo unread)"
    # shellcheck disable=SC2086
    side_use $ports
    LS_USED=1
    ls_setup
}

ls_user() {
    local attrs=""
    [ "$2" = sync ] && attrs=', "attributes": [{"name": "kerberossync", "value": ["1"]}]'
    ls_gql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$1"'", "email": "'"$1"'@gate.test"'"$attrs"'}}' >/dev/null &&
        ls_hush ls__set_pw "$1"
}
ls__set_pw() {
    ls_gql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' "$(ls__pw_vars "$1")" >/dev/null
}
ls_dn() { lsearch -o ldif-wrap=no -b "$BASE_DN" -s sub "(uid=$1)" dn 2>/dev/null | sed -n 's/^dn: //p' | head -1; }

# The ordinary user and the held user sit in an OU whose policy locks after 3 failures; the free
# user sits outside it, so its every wrong password is checked (the lockout is on for the server).
ls_setup() {
    local policy i
    [ -n "$TOKEN" ] || {
        LS_WHY="the admin could not sign in to the limited server"
        return 1
    }
    ls_user "$LS_LEGIT" plain && ls_user "$LS_FREE" sync && ls_user "$LS_HELD" plain &&
        ls_gql 'mutation($n: String!) { createOu(name: $n) { ok } }' '{"n": "'"$LS_OU"'"}' >/dev/null &&
        policy="$(ls_gql 'mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }' \
            '{"n": "'"$LS_RUN"' lockout", "i": [{"key": "lockout-threshold", "value": "3"}, {"key": "lockout-duration-seconds", "value": "0"}]}' |
            json_get createPolicy.id 2>/dev/null)" && [ -n "$policy" ] &&
        ls_gql 'mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }' '{"o": "'"$LS_OU"'", "p": '"$policy"'}' >/dev/null &&
        ls_gql 'mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }' \
            '{"ids": ["'"$LS_LEGIT"'", "'"$LS_HELD"'"], "ou": "'"$LS_OU"'"}' >/dev/null || {
        LS_WHY="the users, the OU $LS_OU and its policy lockout-threshold 3 could not be made: $(head -c 300 "$LS_D/last.err")"
        return 1
    }
    LS_LEGIT_DN="$(ls_dn "$LS_LEGIT")" LS_FREE_DN="$(ls_dn "$LS_FREE")" LS_HELD_DN="$(ls_dn "$LS_HELD")"
    [ -n "$LS_LEGIT_DN" ] && [ -n "$LS_FREE_DN" ] && [ -n "$LS_HELD_DN" ] && ls_hush ls__bind || {
        LS_WHY="a DN is missing ('$LS_LEGIT_DN', '$LS_FREE_DN', '$LS_HELD_DN'), or $LS_LEGIT did not bind with the right password"
        return 1
    }
    LS_PRINCIPAL=0
    case " $LS_KINDS " in *" kinit-wrong "*) ;; *) return 0 ;; esac
    for i in $(seq 1 30); do
        timeout 30 docker exec "$LS_SRV" kadmin -k -t /data/kadm5.keytab -p "admin/admin@$REALM" -q "getprinc $LS_FREE" 2>/dev/null |
            grep -q "^Principal: $LS_FREE@$REALM" && LS_PRINCIPAL=1 && break
        sleep 1
    done
    return 0
}

# ls__bind [timed]: one ordinary bind with the right password, from the host through the published
# port, waited for LS_BIND_WAIT seconds (then 124). With "timed" it prints "<exit code>
# <milliseconds>", the client's own start included.
ls__bind() {
    local f="$LS_D/.bindpw" rc t0=0
    (umask 077 && printf '%s' "$LS_PASS" >"$f")
    [ "${1:-}" = timed ] && t0="$(date +%s%N)"
    timeout "$LS_BIND_WAIT" ldapwhoami -x -H "$(ldap_url)" -D "$LS_LEGIT_DN" -y "$f" >/dev/null 2>&1
    rc=$?
    [ "${1:-}" = timed ] && printf '%s %s\n' "$rc" "$((($(date +%s%N) - t0) / 1000000))"
    rm -f "$f"
    return "$rc"
}

# ls_send <kind> <seconds> <senders> <count, 0 for none>: one kind's requests; prints the sender's line.
ls_send() {
    local bound=$(($2 + 90))
    case "$1" in
    ldap-unknown) ls_client "$bound" ldap "$2" "$3" "$4" "ldap://$LS_SRV:3890" "uid=${LS_RUN}-x{n},ou=people,$BASE_DN" ;;
    ldap-wrong) ls_client "$bound" ldap "$2" "$3" "$4" "ldap://$LS_SRV:3890" "$LS_FREE_DN" ;;
    ldap-locked) ls_client "$bound" ldap "$2" "$3" "$4" "ldap://$LS_SRV:3890" "$LS_HELD_DN" ;;
    kinit-wrong) ls_client "$bound" kinit "$2" "$3" "$4" - "$LS_FREE@$REALM" ;;
    web-start) ls_http "$bound" web-start "$LS_HELD" "$2" "$3" "$4" ;;
    web-finish) ls_http "$bound" web-finish "${LS_RUN}-nobody" "$2" "$3" "$4" ;;
    simple-wrong) ls_http "$bound" simple "$LS_FREE" "$2" "$3" "$4" ;;
    refresh-junk) ls_http "$bound" refresh "$LS_FREE" "$2" "$3" "$4" ;;
    reset-unknown) ls_http "$bound" reset "${LS_RUN}-nobody" "$2" "$3" "$4" ;;
    esac
}
ls_client() {
    local bound="$1"
    shift
    timeout "$bound" docker exec -e KRB5_CONFIG=/tmp/lowspec-krb5.conf -e KRB5CCNAME=/tmp/lowspec_cc "$LS_CLIENT" \
        bash /tmp/lowspec-client.sh "$@"
}
ls_http() {
    timeout "$1" python3 "$GATE_ROOT/lib/lowspec.py" flood --kind "$2" --base "$(http_url)" --user "$3" \
        --seconds "$4" --senders "$5" --count "$6"
}
# ls_want <kind>: what one such request is answered on a quiet server when it reaches its code.
ls_want() {
    case "$1" in
    ldap-*) echo 49 ;;
    web-start | reset-unknown) echo 200 ;;
    kinit-wrong) echo incorrect ;;
    *) echo 401 ;;
    esac
}

ls_mem_sample() {
    printf '== %s %s\n' "$1" "$(date +%s)"
    timeout 10 docker exec "$LS_SRV" sh -c "$LS_MEM_SH" 2>/dev/null
}
# ls_sampler <file> <flag file>: a sample every few seconds while the flag file is there. Each one is a
# docker exec, which runs on the server's one core: few of them, so they take little of it.
ls_sampler() {
    local i
    while [ -e "$2" ]; do
        ls_mem_sample during >>"$1"
        for i in $(seq 1 "$LS_SAMPLE_EVERY"); do
            [ -e "$2" ] && sleep 1
        done
    done
}
# ls_mark: the newest log row's id, from a copy of the quiet server's database; nothing when unread.
ls_mark() {
    local i
    for i in 1 2 3; do
        rm -f "$LS_D/logs-copy.db"
        docker cp "$LS_SRV:/data/users.db" "$LS_D/logs-copy.db" >/dev/null 2>&1 &&
            ls_py mark --db "$LS_D/logs-copy.db" 2>"$LS_D/mark.err" && return 0
        sleep 1
    done
    return 1
}
ls_row() {
    local line state text
    line="$(grep -m1 "^$3 " "$LS_D/$1.report" 2>/dev/null)"
    line="${line#"$3" }"
    state="${line%% *}" text="${line#* }"
    case "$state" in
    measured) ls_note "[R1d.$1-$2] measured: $text" ;;
    pass) p_ok "[R1d.$1-$2] $text" ;;
    fail) p_bad "[R1d.$1-$2] $text" ;;
    *) p_bad "[R1d.$1-$2] not read: ${text:-no line in $1.report}" ;;
    esac
}

# ls_kind <kind>: one kind's flood and its numbers. Returns 1 when the server is gone after it.
ls_kind() {
    local kind="$1" want warm mark pid sampler began state rc line oom alive=no
    want="$(ls_want "$kind")"
    if [ "$kind" = kinit-wrong ] && [ "$LS_PRINCIPAL" != 1 ]; then
        p_bad "[R1d.$kind-reach] no principal $LS_FREE@$REALM on the limited server; the kind was not sent"
        return 0
    fi
    warm="$(ls_send "$kind" 30 1 1 2>"$LS_D/$kind.warm.err")"
    case " $warm" in
    *" answers=$want:1") ;;
    *)
        p_bad "[R1d.$kind-reach] one $kind request on the quiet server gave '${warm:-no line: $(head -c 200 "$LS_D/$kind.warm.err" | tr '\n' ' ')}' (want answers=$want:1): the request does not reach its code, the kind was not sent"
        return 0
        ;;
    esac
    sleep 2
    mark="$(ls_mark)"
    ls_mem_sample before >"$LS_D/$kind.mem"
    : >"$LS_D/$kind.probe"
    : >"$LS_D/$kind.on"
    ls_sampler "$LS_D/$kind.mem" "$LS_D/$kind.on" &
    sampler=$!
    ls_send "$kind" "$LS_SECONDS" "$LS_SENDERS" 0 >"$LS_D/$kind.flood" 2>"$LS_D/$kind.flood.err" &
    pid=$!
    began=$SECONDS
    while kill -0 "$pid" 2>/dev/null && [ $((SECONDS - began)) -lt $((LS_SECONDS + 120 + LS_BIND_WAIT)) ]; do
        ls_hush ls__bind timed >>"$LS_D/$kind.probe"
        sleep 1
    done
    [ $((SECONDS - began)) -lt $((LS_SECONDS + 120 + LS_BIND_WAIT)) ] || kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    if ! grep -q '^sent=' "$LS_D/$kind.flood"; then
        # No line: the senders failed or were cut off at their bound. Loops left in the client end with it.
        p_bad "[R1d.$kind-senders] the senders printed no line (their bound: $((LS_SECONDS + 90)) s), so what was sent is not known: $(head -c 200 "$LS_D/$kind.flood.err" | tr '\n' ' ')"
        case "$kind" in ldap-* | kinit-*) ls_client_up || true ;; esac
    fi
    rm -f "$LS_D/$kind.on"
    wait "$sampler" 2>/dev/null
    sleep "$LS_SETTLE"
    ls_mem_sample after >>"$LS_D/$kind.mem"
    state="$(docker inspect -f '{{.State.Running}} {{.State.OOMKilled}} {{.RestartCount}}' "$LS_SRV" 2>/dev/null)"
    ls_hush ls__bind
    rc=$?
    [ "$state" = "true false 0" ] && [ "$rc" = 0 ] && alive=yes
    sleep 2
    [ -n "$mark" ] && ls_mark >/dev/null
    ls_py report --kind "$kind" --seconds "$LS_SECONDS" --senders "$LS_SENDERS" --flood "$LS_D/$kind.flood" \
        --probe "$LS_D/$kind.probe" --mem "$LS_D/$kind.mem" --db "$LS_D/logs-copy.db" --mark "$mark" \
        --legit "$LS_LEGIT" --alive "$alive" --bind-wait "$LS_BIND_WAIT" --max-rows "$LS_MAX_ROWS" --max-mem-mb "$LS_MAX_MEM_MB" \
        --max-bind-ms "$LS_MAX_BIND_MS" >"$LS_D/$kind.report" 2>"$LS_D/$kind.report.err"
    line="$(grep -m1 '^LOWSPEC ' "$LS_D/$kind.report")"
    if [ -n "$line" ]; then
        note "$line"
        printf '%s\n' "$line" >>"$LS_D/lowspec.txt"
        ls_note "[R1d.$kind] $(sed -n 's/^HUMAN //p' "$LS_D/$kind.report")"
    else
        p_bad "[R1d.$kind] no report: $(head -c 300 "$LS_D/$kind.report.err" | tr '\n' ' ')"
    fi
    ls_row "$kind" rows ROWS
    ls_row "$kind" memory MEM
    ls_row "$kind" bind BIND
    oom="$(ls_val oom_kills "$line")"
    oom="${oom:-unread}"
    if [ "$alive" = yes ] && { [ "$oom" = 0 ] || [ "$oom" = unread ]; }; then
        p_ok "[R1d.$kind-alive] after the $kind flood the server runs, was not restarted or killed for memory (out-of-memory kills in its cgroup: $oom), and answers a bind with the right password"
    else
        p_bad "[R1d.$kind-alive] after the $kind flood: running, killed for memory, restarts '$state' (want 'true false 0'); out-of-memory kills in its cgroup: $oom (want 0); the bind with the right password exited $rc (want 0)"
    fi
    [ "$alive" = yes ] || return 1
    if [ "$kind" = ldap-locked ]; then
        ls_gql 'mutation($u: String!) { unlockUser(userId: $u) { ok } }' '{"u": "'"$LS_HELD"'"}' >/dev/null ||
            ls_note "[R1d.$kind] unlockUser $LS_HELD failed, the kinds after it meet a locked $LS_HELD: $(head -c 200 "$LS_D/last.err")"
    fi
    return 0
}

ls_server_down() {
    [ "$LS_USED" = 1 ] && side_back
    LS_USED=0
    side_down "$LS_SRV" "$LS_VOL" "$LS_D/server-$LS_STARTS.log"
    docker volume rm "$LS_KVOL" >/dev/null 2>&1 || true
}
ls_cleanup() {
    local left
    ls_server_down
    docker rm -f -v "$LS_CLIENT" >/dev/null 2>&1
    left="$(docker ps -aq -f "name=^${LS_SRV}$")$(docker ps -aq -f "name=^${LS_CLIENT}$")$(docker ps -aq -f "name=^${LS_PROBE}$")"
    docker volume inspect "$LS_VOL" >/dev/null 2>&1 && left+=" $LS_VOL"
    docker volume inspect "$LS_KVOL" >/dev/null 2>&1 && left+=" $LS_KVOL"
    if [ -z "$left" ]; then
        p_ok "[R1d.cleanup] the limited server, the client container and their volumes are gone"
    else
        p_bad "[R1d.cleanup] left behind: $left"
    fi
}

ls_main() {
    local kind rc n=0 total
    ls_args || {
        p_bad "[R1d.settings] ${LS_WHY%; }"
        return 0
    }
    if [ "$GATE_DB" != sqlite ]; then
        p_skip "[R1d.lane] the low-spec row has its own SQLite server and runs on the SQLite lane only; on $GATE_DB it is not run"
        return 0
    fi
    if ! ls_limits_probe; then
        p_skip "[R1d.limits] this host does not hold a container to $LS_CPUS CPU and $LS_MEM_MB MB, the row is not run: $LS_WHY"
        return 0
    fi
    ls_client_up || p_bad "[R1d.client] the client container could not be made (see client.err); the LDAP and kinit kinds will not be sent"
    ls_server_up
    rc=$?
    # shellcheck disable=SC2086
    set -- $LS_KINDS
    total=$#
    case "$rc" in
    0)
        p_ok "[R1d.limits] the server runs under ${LS_LIMITS[*]}, read back from its own cgroup: $LS_SEEN"
        note "LOWSPEC limits cpus=$LS_CPUS memory_mb=$LS_MEM_MB $LS_SEEN client_ports=$LS_PORTS seconds=$LS_SECONDS senders=$LS_SENDERS settle=$LS_SETTLE" |
            tee -a "$LS_D/lowspec.txt"
        for kind in "$@"; do
            n=$((n + 1))
            ls_kind "$kind" && continue
            [ "$n" -lt "$total" ] || break
            # The server is gone: a new one, so the kinds left still report.
            ls_server_down
            ls_server_up || {
                p_bad "[R1d.server] no new server after $kind, the $((total - n)) kinds after it were not sent: $LS_WHY"
                break
            }
        done
        ;;
    2) p_skip "[R1d.limits] the server started, but its cgroup does not show the limits, the row is not run: $LS_WHY" ;;
    *) p_bad "[R1d.server] $LS_WHY" ;;
    esac
    ls_cleanup
}

ls_main
