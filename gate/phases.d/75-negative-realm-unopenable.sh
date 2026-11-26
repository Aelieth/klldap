# shellcheck shell=bash
# Phase: negative — a realm that cannot open (its stash moved away), in both values of
# kerberos_options.on_realm_failure. admin-only (the key written into the server's file): unhealthy
# with the state, LDAP and HTTP on the container's loopback only, admins only, writes refused.
# directory-only (the default, the key taken out again): the directory is served to everyone as
# configured, /health answers 200 and names the state, the KDC and kadmin do not serve, and each
# change that needs a principal is refused with one sentence at every door, its row keeping the
# full cause. Moving the stash back and restarting restores the realm; the file ends as it began.

D="$(phase_dir)"
DEG_USER="gatedeg"
DEG_PASS="GateDegPass2026!"
DEG_NEXT="GateDegNext2026!"
DEG_SYNC="gatedegs"
DEG_SYNC_PASS="GateDegSync2026!"
DEG_NEW="gatedegn"
DEG_GROUP="gatedeg-group"
STASH="/var/kerberos/krb5kdc/.k5.$REALM"
CONF="/data/lldap_config.toml"
D75_KEY='on_realm_failure = "admin-only"'
D75_PUBLIC="the realm's records did not open"
D75_TOLD="Kerberos KDC unavailable: $D75_PUBLIC; the change will be possible when this server's realm opens"
D75_FULL="Kerberos KDC unavailable: the Kerberos realm $REALM did not open"
D75_503="503 Service Unavailable: Kerberos is admin-only: $D75_PUBLIC"
D75_503_NO_REALM="503 Service Unavailable: Kerberos is admin-only: this database holds no Kerberos realm yet"
D75_FLAG="--kerberos passes only a ready Kerberos realm, and this server's is directory-only"
D75_ADMINS="Only admins may sign in"
D75_OPEN_LINE="is closed and this server is directory-only"
D75_STAYS="but this server stays admin-only"
D75_STATUS="the Kerberos realm is closed on this server: the status of a principal, if there is one, is left for the realm's next opening, which sets it from lldap_disabled before the KDC serves"
D75_NOTICE="The Kerberos realm did not open and this server is directory-only: the directory is served to everyone."
D75_LOCKED="The Kerberos realm is not ready: Kerberos sync cannot be changed until it is."
D75_PAGE="${CONTAINER}-d75page"
D75_SUM0="" D75_GID="" D75_DIRONLY=""
EXTRA_CONTAINERS+=("$D75_PAGE")
cip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER")"
in_ldap() { gexec "$1" -x -H ldap://127.0.0.1:3890 "${@:2}"; }
d75_dn() { printf 'uid=%s,ou=people,%s' "$1" "$BASE_DN"; }
d75_health() { gexec /app/lldap healthcheck "$@" --config-file "$CONF"; }
d75_conf_sum() { gexec cat "$CONF" 2>/dev/null | sha256sum | cut -d' ' -f1; }

# d75_key_in: the key written under the file's own [kerberos_options] table, the first copy kept
# beside it. d75_key_out: that copy moved back, so the file is the bytes it was.
d75_key_in() {
    gexec cp -p "$CONF" "$CONF.gate75" &&
        gexec sh -c 'found=1
            while IFS= read -r line || [ -n "$line" ]; do
                printf "%s\n" "$line"
                if [ "$line" = "[kerberos_options]" ]; then
                    printf "%s\n" "$1"
                    found=0
                fi
            done <"$0.gate75" >"$0"
            exit "$found"' "$CONF" "$D75_KEY" &&
        file_contains "$CONF" "$D75_KEY"
}
d75_key_out() { gexec mv "$CONF.gate75" "$CONF" && [ "$(d75_conf_sum)" = "$D75_SUM0" ]; }

# d75_restart <log> <line> [seconds]: the gate's server restarted; 0 once its log since then says <line>.
d75_restart() {
    local stamp i=0
    stamp="$(date +%s)"
    t docker restart "$CONTAINER" >/dev/null 2>&1 || return 1
    while [ "$i" -lt "${3:-100}" ]; do
        docker logs --since "$stamp" "$CONTAINER" >"$D/$1" 2>&1
        grep -qF "$2" "$D/$1" && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# d75_health_body: /health on the published port, as "<status> <kerberos> <cause>".
d75_health_body() {
    t curl -s -m 5 -o "$D/health.body" -w '%{http_code}' "$(http_url)/health" >"$D/health.code" 2>/dev/null
    CODE="$(cat "$D/health.code" 2>/dev/null)" python3 - "$D/health.body" <<'PY'
import json, os, sys
try:
    body = json.load(open(sys.argv[1], encoding="utf-8"))
    print(os.environ["CODE"], body.get("kerberos"), body.get("cause", "no cause"))
except (OSError, ValueError) as e:
    print(os.environ["CODE"] or "000", "unread", e)
PY
}

# d75_rows <KIND> <target> <mark> <true|false> <detail head>: "one" when the only row of the kind
# that names the target after the marker has that success and a detail that starts so.
d75_rows() {
    local got="" i
    for i in $(seq 1 20); do
        got="$(graphql "query(\$id: ID!, \$t: String!) { logs(filter: {kinds: [$1], target: \$t}, afterId: \$id, limit: 20) { success detail } }" \
            '{"id": "'"$3"'", "t": "'"$2"'"}' 2>/dev/null | OK="$4" HEAD="$5" python3 -c '
import json, os, sys
rows = json.load(sys.stdin)["logs"]
good = [r for r in rows if r.get("success") is (os.environ["OK"] == "true")
        and (r.get("detail") or "").startswith(os.environ["HEAD"])]
print("one" if len(rows) == 1 and len(good) == 1 else "%d %s" % (len(rows), json.dumps(rows)[:300]))' 2>/dev/null)"
        case "$got" in "" | "0 "*) sleep 0.5 ;; *) break ;; esac
    done
    printf '%s\n' "${got:-unread}"
}

# d75_start_rows <mark>: how many kerberos_sync failure rows after the marker say "directory-only: "
# and the cause; that row names no user.
d75_start_rows() {
    graphql 'query($id: ID!) { logs(filter: {kinds: [KERBEROS_SYNC], success: false}, afterId: $id, limit: 50) { target detail } }' \
        '{"id": "'"$1"'"}' 2>/dev/null | HEAD="directory-only: " WANT="the Kerberos realm $REALM did not open" python3 -c '
import json, os, sys
rows = json.load(sys.stdin)["logs"]
print(sum(1 for r in rows if r.get("target") is None and (r.get("detail") or "").startswith(os.environ["HEAD"])
          and os.environ["WANT"] in r["detail"]))' 2>/dev/null
}

d75_sync_of() {
    graphql 'query($id: String!) { user(userId: $id) { attributes { name value } } }' '{"id": "'"$1"'"}' 2>/dev/null | python3 -c '
import json, sys
attrs = json.load(sys.stdin)["user"]["attributes"]
vals = [",".join(a["value"]) for a in attrs if a["name"] == "kerberossync"]
print(vals[0] if vals else "absent")' 2>/dev/null
}

# d75_refused <row> <what> <out> <rc> <KIND> <target> <mark>: a write refused for the realm: the
# door's answer carries the one sentence and no cause with the realm's name; its one row keeps the
# full cause.
d75_refused() {
    local row="$1" what="$2" out="$3" rc="$4" rows
    rows="$(d75_rows "$5" "$6" "$7" false "$D75_FULL")"
    if [ "$rc" != 0 ] && grep -qF "$D75_TOLD" "$out" && ! grep -qF "$REALM did not open" "$out" && [ "$rows" = one ]; then
        p_ok "[$row] $what is refused (exit $rc) with '$D75_TOLD', and its one $5 row keeps the full cause"
    else
        p_bad "[$row] $what: exit $rc, $(head -c 300 "$out" 2>/dev/null | tr '\n' ' '); $5 rows for $6: $rows; want a refusal with '$D75_TOLD', no '$REALM did not open' in the answer, and one row that starts '$D75_FULL'"
    fi
}

# d75_ldif <file> <lines...>: an LDIF for lmodify.
d75_ldif() {
    local file="$1"
    shift
    printf '%s\n' "$@" >"$file"
}

# d75_page <mode> <tag> <the regular user's password>: the page driver on the gate's server; its
# ROW lines in page-<tag>.out.
d75_page() {
    docker rm -f -v "$D75_PAGE" >/dev/null 2>&1 || true
    (
        BROWSER_ADMIN_PASS="$ADMIN_PASS" BROWSER_PASS="$3" \
            timeout 240 docker run --rm --name "$D75_PAGE" --network "$NET" --init --shm-size=1g \
            --user "$(id -u):$(id -g)" --entrypoint node \
            -v "$GATE_ROOT/lib/realm-notice.mjs:/work/realm-notice.mjs:ro" -v "$D:/out" \
            -e HOME=/tmp/home -e BROWSER_OUT=/out -e BROWSER_URL="http://${CONTAINER}:17170" \
            -e BROWSER_MODE="$1" -e BROWSER_USER="$DEG_USER" -e BROWSER_SYNCED="$DEG_SYNC" \
            -e BROWSER_NEW="${DEG_NEW}p" -e BROWSER_ADMIN_PASS -e BROWSER_PASS \
            "$WIRE_IMAGE" /work/realm-notice.mjs >"$D/page-$2.out" 2>"$D/page-$2.err"
    )
    docker rm -f -v "$D75_PAGE" >/dev/null 2>&1 || true
}
d75_page_row() { grep -m1 "^ROW $2 " "$D/page-$1.out" 2>/dev/null || echo "ROW $2 none (see page-$1.err)"; }
d75_page_want() {
    local got
    got="$(d75_page_row "$1" "$2")"
    if [ "$got" = "ROW $2 SEEN $3" ]; then
        p_ok "[P.$2] $4: $3"
    else
        p_bad "[P.$2] $4: $got; want 'SEEN $3'"
    fi
}

# A second server on the gate's database while the gate's server holds the realm (W1): it watches
# the realm for thirty-five seconds with no listener up, then exits naming the holder. With
# force_ldap_user_pass_reset it first resets the admin's directory password without the realm.
RW_PLAIN="${CONTAINER}-rwplain" RW_RESET="${CONTAINER}-rwreset"
RW_SAID="another server holds the Kerberos realm in this database; this one wrote nothing and stops"
RW_RAN="password ran without the Kerberos realm, because the Kerberos realm $REALM did not open: the directory password is the configured one"
RW_ROW="admin password reset from the configuration"
RW_SILENT="nothing listens on 17170 or 3890"
RW_QUIET="" RW_CODE="" RW_SECS=0
EXTRA_CONTAINERS+=("$RW_PLAIN" "$RW_RESET")
EXTRA_VOLUMES+=("$RW_PLAIN-data" "$RW_PLAIN-kdc" "$RW_RESET-data" "$RW_RESET-kdc")
# The rows of the directory-only work on the same helpers: a second server beside a directory-only
# holder (R1), one with a cause of its own beside a healthy holder (R2), and a server on a
# database that has never held a realm (R3). RW_SEED, when set, fills a second server's Kerberos
# volume before its start.
RW_BESIDE="${CONTAINER}-rwbeside" RW_LOCAL="${CONTAINER}-rwlocal" RW_FRESH="${CONTAINER}-rwfresh"
RW_FRESH_DB="gate75fresh"
RW_MIT="holds the MIT database of KLLDAP 0.7.2, which this server cannot open"
RW_NO_ROW="kerberos_options.on_realm_failure is directory-only, but this server stays admin-only: this database holds no Kerberos realm yet"
RW_SEED=""
EXTRA_CONTAINERS+=("$RW_BESIDE" "$RW_LOCAL" "$RW_LOCAL-seed" "$RW_FRESH" "$RW_FRESH-seed")
EXTRA_VOLUMES+=("$RW_BESIDE-data" "$RW_BESIDE-kdc" "$RW_LOCAL-data" "$RW_LOCAL-kdc" "$RW_FRESH-data" "$RW_FRESH-kdc")

# rw_up <name> [-e NAME=value ...]: a server with Kerberos on, on the gate's database, its volumes its own.
rw_up() {
    local name="$1"
    shift
    rw_down "$name"
    [ -z "$RW_SEED" ] || "$RW_SEED" "$name" || return 1
    LLDAP_JWT_SECRET="$JWT_SECRET" LLDAP_KEY_SEED="$KEY_SEED" LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        LLDAP_DATABASE_URL="$GATE_DATABASE_URL" t docker run -d --name "$name" --network "$NET" \
        -v "$name-data:/data" -v "$name-kdc:/var/kerberos/krb5kdc" \
        -e LLDAP_JWT_SECRET -e LLDAP_KEY_SEED -e LLDAP_LDAP_USER_PASS -e LLDAP_DATABASE_URL \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_ENABLE_MFA=true -e LLDAP_VERBOSE=true "$@" \
        "$GATE_IMAGE" >/dev/null 2>>"$D/second.err"
}
rw_down() {
    docker rm -fv "$1" >/dev/null 2>&1
    docker volume rm "$1-data" "$1-kdc" >/dev/null 2>&1
}

# rw_quiet <name>: while it runs, which of its HTTP and LDAP ports take a connection inside it.
rw_quiet() {
    local port open=""
    if ! gexec_in "$1" bash -c : 2>/dev/null; then
        echo "not running"
        return
    fi
    for port in 17170 3890; do
        gexec_in "$1" bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null && open="$open $port"
    done
    if [ -n "$open" ]; then
        echo "listening on$open"
    else
        echo "$RW_SILENT"
    fi
}

# rw_second <name> [-e NAME=value ...]: started beside the holder and waited for. RW_QUIET is what
# it answered fifteen seconds in; RW_CODE is its exit; RW_SECS is how long the server itself ran,
# by rw_ran; its log is <name>.log.
rw_second() {
    local name="$1"
    RW_QUIET="not started" RW_CODE="" RW_SECS=0
    rw_up "$@" || return 1
    sleep 15
    RW_QUIET="$(rw_quiet "$name")"
    RW_CODE="$(timeout 120 docker wait "$name" 2>/dev/null)"
    docker logs "$name" >"$D/$name.log" 2>&1
    RW_SECS="$(rw_ran "$name")"
}

# rw_ran <name>: whole seconds from the server's own first log line ("Starting LLDAP version", by
# the time docker stamped it) to the container's exit (docker's FinishedAt): nothing of docker run
# or of the entrypoint is counted. 0 when either time is unread. No line of the server says that
# its watch has begun, so the start of the watch itself is not in the log.
rw_ran() {
    docker logs -t "$1" >"$D/$1.timed.log" 2>&1
    END="$(docker inspect -f '{{.State.FinishedAt}}' "$1" 2>/dev/null)" python3 - "$D/$1.timed.log" <<'PY'
import calendar, os, re, sys, time

def stamp(text):
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z", text)
    if not m:
        return None
    return calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")) + float(m.group(2) or 0)

first = None
with open(sys.argv[1], encoding="utf-8", errors="replace") as log:
    for line in log:
        if "Starting LLDAP version" in line:
            first = stamp(line)
            break
end = stamp(os.environ.get("END", ""))
print(int(end - first) if first is not None and end is not None and end >= first else 0)
PY
}

# rw_seed_mit <name>: its Kerberos volume holds a 0.7.2 MIT database and no dump, a cause the
# server meets before it reads the realm from the database.
rw_seed_mit() {
    docker rm -f -v "$1-seed" >/dev/null 2>&1
    t docker run --rm --name "$1-seed" --entrypoint sh -v "$1-kdc:/var/kerberos/krb5kdc" "$GATE_IMAGE" \
        -c ': >/var/kerberos/krb5kdc/principal.kadm5' >/dev/null 2>>"$D/second.err"
}

# rw_first: the gate's server still serves with its realm: healthy, the admin logs in, the keytab
# kinits. Its two ports take rw_quiet's connection, which is that probe's control.
rw_first() {
    gexec /app/lldap healthcheck --config-file /data/lldap_config.toml >"$D/first-health.log" 2>&1 &&
        gexec bash -c "</dev/tcp/127.0.0.1/17170 && </dev/tcp/127.0.0.1/3890" 2>>"$D/first-health.log" &&
        TOKEN="$(gate_login 2>>"$D/first-health.log")" &&
        gexec sh -c "KRB5CCNAME=/tmp/gate_rw_cc kinit -kt /data/kadm5.keytab admin/admin@$REALM" \
            >"$D/first-kinit.log" 2>&1
}

# rw_first_directory_only: the gate's server is still up as it was: the plain healthcheck passes,
# /health says directory-only, the admin logs in. No kinit: its realm is closed.
rw_first_directory_only() {
    d75_health >"$D/first-health.log" 2>&1 &&
        [ "$(d75_health_body)" = "200 directory-only $D75_PUBLIC" ] &&
        TOKEN="$(gate_login 2>>"$D/first-health.log")"
}

# rw_watched <name>: nothing listened, it exited non-zero no sooner than the watch, and named the holder.
rw_watched() {
    [ "$RW_QUIET" = "$RW_SILENT" ] && [ -n "$RW_CODE" ] && [ "$RW_CODE" != 0 ] && [ "$RW_SECS" -ge 35 ] &&
        grep -qF "$RW_SAID" "$D/$1.log"
}

rw_admin_sync() {
    graphql '{ user(userId: "admin") { attributes { name value } } }' '{}' 2>/dev/null | python3 -c '
import json, sys
attrs = json.load(sys.stdin)["user"]["attributes"]
vals = [",".join(a["value"]) for a in attrs if a["name"] == "kerberossync"]
print(vals[0] if vals else "absent")' 2>/dev/null
}

# rw_reset_rows <mark>: the admin_bootstrap rows of a reset from the configuration after the marker.
rw_reset_rows() {
    graphql 'query($id: ID!) { logs(filter: {kinds: [ADMIN_BOOTSTRAP]}, afterId: $id, limit: 20) { detail } }' \
        '{"id": "'"$1"'"}' 2>/dev/null | WANT="$RW_ROW" python3 -c '
import json, os, sys
print(sum(1 for row in json.load(sys.stdin)["logs"] if row.get("detail") == os.environ["WANT"]))' 2>/dev/null
}

rw_watch_row() {
    local row="W1.second-watch" got
    if ! rw_second "$RW_PLAIN"; then
        p_bad "[$row] the second server did not start (see second.err)"
        return
    fi
    got="at 15 s: $RW_QUIET; exit ${RW_CODE:-none}, ${RW_SECS}s after its first log line"
    if rw_watched "$RW_PLAIN" && rw_first; then
        p_ok "[$row] a second server on the gate's database beside the holder: $got, its log says '$RW_SAID'; the gate's server stays healthy, logs the admin in and kinits"
    else
        p_bad "[$row] $got; want '$RW_SILENT', a non-zero exit 35 s or more after its first log line, '$RW_SAID' in $RW_PLAIN.log, and the gate's server healthy with its realm (see first-health.log, first-kinit.log)"
    fi
}

rw_reset_row() {
    local row="W1.second-reset" got mark sync rows
    sync="$(rw_admin_sync)"
    case "$sync" in
    absent | 0) ;;
    1)
        p_skip "[$row] the gate's admin has Kerberos sync on, and the reset would turn it off for the phases after; not run"
        return
        ;;
    *)
        p_bad "[$row] the admin's kerberossync could not be read; not run"
        return
        ;;
    esac
    mark="$(log_mark)"
    if ! rw_second "$RW_RESET" -e LLDAP_FORCE_LDAP_USER_PASS_RESET=always; then
        p_bad "[$row] the second server did not start (see second.err)"
        return
    fi
    got="at 15 s: $RW_QUIET; exit ${RW_CODE:-none}, ${RW_SECS}s after its first log line"
    if rw_watched "$RW_RESET" && grep -qF "$RW_RAN" "$D/$RW_RESET.log" && rw_first &&
        rows="$(rw_reset_rows "$mark")" && [ "$rows" = 1 ]; then
        p_ok "[$row] the same start with force_ldap_user_pass_reset=always: $got; its log says the reset ran without the realm, and '$RW_SAID'; one admin_bootstrap row '$RW_ROW'; the gate's server stays healthy, logs the admin in with the configured password and kinits"
    else
        p_bad "[$row] $got; admin_bootstrap rows '$RW_ROW' after the marker: ${rows:-unread}; want '$RW_SILENT', a non-zero exit 35 s or more after its first log line, '$RW_RAN' and '$RW_SAID' in $RW_RESET.log, one row, and the gate's server healthy with its realm"
    fi
}

# R1: beside a directory-only holder a second server serves nothing and exits; the holder stays.
rw_beside_row() {
    local row="R1.second-beside-directory-only" got
    if [ "$GATE_DB" != postgres ]; then
        p_skip "[$row] two servers need one shared database; on $GATE_DB this row is not run"
        return
    fi
    : >"$D/second.err"
    if ! rw_second "$RW_BESIDE"; then
        p_bad "[$row] the second server did not start (see second.err)"
        rw_down "$RW_BESIDE"
        return
    fi
    got="at 15 s: $RW_QUIET; exit ${RW_CODE:-none}, ${RW_SECS}s after its first log line"
    if rw_watched "$RW_BESIDE" && rw_first_directory_only; then
        p_ok "[$row] a second server beside the directory-only holder: $got, its log says '$RW_SAID'; the gate's server stays up directory-only and logs the admin in"
    else
        p_bad "[$row] $got; want '$RW_SILENT', a non-zero exit 35 s or more after its first log line, '$RW_SAID' in $RW_BESIDE.log, and the gate's server still directory-only (see first-health.log)"
    fi
    rw_down "$RW_BESIDE"
}

# R2: a second server with a cause of its own, met before it has looked for a holder, beside the
# healthy holder: it serves nothing during the watch and exits.
rw_local_row() {
    local row="R2.second-local-cause" got
    RW_SEED=rw_seed_mit
    if ! rw_second "$RW_LOCAL"; then
        RW_SEED=""
        p_bad "[$row] the second server did not start (see second.err)"
        return
    fi
    RW_SEED=""
    got="at 15 s: $RW_QUIET; exit ${RW_CODE:-none}, ${RW_SECS}s after its first log line"
    if rw_watched "$RW_LOCAL" && grep -qF "$RW_MIT" "$D/$RW_LOCAL.log" &&
        ! grep -qF "$D75_OPEN_LINE" "$D/$RW_LOCAL.log" && rw_first; then
        p_ok "[$row] a second server whose Kerberos volume holds a 0.7.2 MIT database and no dump, beside the healthy holder: $got; its log names its own cause and '$RW_SAID', and never says it is directory-only; the gate's server stays healthy, logs the admin in and kinits"
    else
        p_bad "[$row] $got; want '$RW_SILENT', a non-zero exit 35 s or more after its first log line, '$RW_MIT' and '$RW_SAID' in $RW_LOCAL.log, no '$D75_OPEN_LINE' there, and the gate's server healthy with its realm"
    fi
}

# rw_fresh_url: a database of the lane's kind that has never held a realm; empty when it cannot be made.
rw_fresh_url() {
    case "$GATE_DB" in
    sqlite) echo "sqlite:////data/users.db?mode=rwc" ;;
    postgres)
        gexec_in "$PG_CONTAINER" psql -U klldap -d klldap -q -c "DROP DATABASE IF EXISTS $RW_FRESH_DB" >/dev/null 2>>"$D/second.err"
        gexec_in "$PG_CONTAINER" psql -U klldap -d klldap -q -c "CREATE DATABASE $RW_FRESH_DB" >/dev/null 2>>"$D/second.err" &&
            echo "postgres://klldap:klldap@$PG_CONTAINER:5432/$RW_FRESH_DB"
        ;;
    esac
}
rw_fresh_gone() {
    rw_down "$RW_FRESH"
    [ "$GATE_DB" != postgres ] ||
        gexec_in "$PG_CONTAINER" psql -U klldap -d klldap -q -c "DROP DATABASE IF EXISTS $RW_FRESH_DB" >/dev/null 2>>"$D/second.err"
}

# R3: on a database that has never held a realm a server that cannot open stays admin-only, though
# the key is at its default.
rw_fresh_row() {
    local row="R3.no-realm-row" url i=0 said="" rc ip inner outer
    url="$(rw_fresh_url)"
    if [ -z "$url" ]; then
        case "$GATE_DB" in
        sqlite | postgres) p_bad "[$row] a fresh database could not be made (see second.err)" ;;
        *) p_skip "[$row] on $GATE_DB the gate makes no fresh database; not run" ;;
        esac
        return
    fi
    RW_SEED=rw_seed_mit
    if ! rw_up "$RW_FRESH" -e LLDAP_DATABASE_URL="$url"; then
        RW_SEED=""
        p_bad "[$row] the server on the fresh database did not start (see second.err)"
        rw_fresh_gone
        return
    fi
    RW_SEED=""
    while [ "$i" -lt 90 ] && [ -n "$(docker ps -q -f "name=^${RW_FRESH}$")" ]; do
        docker logs "$RW_FRESH" >"$D/$RW_FRESH.log" 2>&1
        grep -qF "$D75_ADMINS" "$D/$RW_FRESH.log" && said=1 && break
        sleep 1
        i=$((i + 1))
    done
    docker logs "$RW_FRESH" >"$D/$RW_FRESH.log" 2>&1
    gexec_in "$RW_FRESH" /app/lldap healthcheck --config-file "$CONF" >"$D/fresh-health.log" 2>&1
    rc=$?
    ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$RW_FRESH" 2>/dev/null)"
    inner=closed outer=closed
    gexec_in "$RW_FRESH" bash -c "</dev/tcp/127.0.0.1/17170 && </dev/tcp/127.0.0.1/3890" 2>/dev/null && inner=open
    { [ -z "$ip" ] || t bash -c "</dev/tcp/$ip/17170" 2>/dev/null || t bash -c "</dev/tcp/$ip/3890" 2>/dev/null; } && outer=open
    if [ -n "$said" ] && grep -qF "$RW_NO_ROW" "$D/$RW_FRESH.log" && grep -qF "$RW_MIT" "$D/$RW_FRESH.log" &&
        ! grep -qF "$D75_OPEN_LINE" "$D/$RW_FRESH.log" && [ "$rc" != 0 ] && grep -qF "$D75_503_NO_REALM" "$D/fresh-health.log" &&
        [ "$inner" = open ] && [ "$outer" = closed ]; then
        p_ok "[$row] a server that cannot open, on a $GATE_DB database that has never held a realm: admin-only though the key is at its default; its log says '$RW_NO_ROW'; the healthcheck fails with '$D75_503_NO_REALM'; HTTP and LDAP answer on its loopback only"
    else
        p_bad "[$row] admin-only line: ${said:-no}; healthcheck exit $rc; its loopback $inner, its address ${ip:-unread} $outer; want '$D75_ADMINS', '$RW_NO_ROW' and '$RW_MIT' in $RW_FRESH.log, no '$D75_OPEN_LINE', a failed healthcheck with '$D75_503_NO_REALM' (fresh-health.log), loopback open and its address closed"
    fi
    rw_fresh_gone
}

graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$DEG_USER"'", "email": "'"$DEG_USER"'@gate.test"}}' \
    >"$D/create.json" 2>&1 || p_bad "createUser $DEG_USER failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$DEG_USER"'", "pw": "'"$DEG_PASS"'"}' >"$D/setpw.json" 2>&1 \
    || p_bad "setUserPassword $DEG_USER failed"
graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
    '{"u": {"id": "'"$DEG_SYNC"'", "email": "'"$DEG_SYNC"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
    >"$D/create-synced.json" 2>&1 || p_bad "createUser $DEG_SYNC with Kerberos sync failed"
graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
    '{"id": "'"$DEG_SYNC"'", "pw": "'"$DEG_SYNC_PASS"'"}' >"$D/setpw-synced.json" 2>&1 \
    || p_bad "setUserPassword $DEG_SYNC failed"
if kinit_pw "$DEG_SYNC@$REALM" "$DEG_SYNC_PASS" >"$D/kinit-synced-before.log" 2>&1; then
    p_ok "the synced user $DEG_SYNC gets a ticket while the realm serves"
else
    p_bad "kinit $DEG_SYNC failed before the realm was closed (see kinit-synced-before.log)"
fi
D75_GID="$(graphql '{ groups { id displayName } }' '{}' 2>/dev/null | GROUP=lldap_disabled python3 -c '
import json, os, sys
groups = json.load(sys.stdin)["groups"]
print(next((g["id"] for g in groups if g["displayName"] == os.environ["GROUP"]), ""))' 2>/dev/null)"
D75_MARK0="$(log_mark)"
D75_SUM0="$(d75_conf_sum)"

if t bash -c "</dev/tcp/$cip/$KDC_INNER_PORT" 2>/dev/null; then
    p_ok "the KDC answers on the container's address ($cip:$KDC_INNER_PORT)"
else
    p_bad "the KDC does not answer on $cip:$KDC_INNER_PORT"
fi
if t bash -c "</dev/tcp/$cip/$KADMIN_INNER_PORT" 2>/dev/null; then
    p_bad "kadmin answers on the container's address ($cip:$KADMIN_INNER_PORT)"
else
    p_ok "kadmin is not reachable on the container's address"
fi
if kadmin_q listprincs >"$D/listprincs.txt" 2>/dev/null && grep -q "admin/admin@$REALM" "$D/listprincs.txt"; then
    p_ok "kadmin works inside the container"
else
    p_bad "kadmin_q listprincs failed inside the container"
fi

# ---- admin-only: the key in the file ----
if d75_key_in; then
    p_ok "[A.key] '$D75_KEY' is written under [kerberos_options] in $CONF, the first file kept beside it"
else
    p_bad "[A.key] '$D75_KEY' could not be written under [kerberos_options] in $CONF: the rows below do not run in admin-only"
fi
gexec mv "$STASH" "$STASH.gate-moved" || p_bad "could not move the stash"
if d75_restart degraded-docker.log "$D75_ADMINS" && grep -q "the Kerberos realm $REALM did not open" "$D/degraded-docker.log" &&
    ! grep -qF "$D75_OPEN_LINE" "$D/degraded-docker.log" && ! grep -qF "$D75_STAYS" "$D/degraded-docker.log"; then
    p_ok "[A.start] with the key at admin-only the server came up admin-only and logged the cause"
else
    p_bad "[A.start] no admin-only start with the cause in the log, or a directory-only line or a 'stays admin-only' line with it (see degraded-docker.log)"
fi

if d75_health >"$D/health-degraded.log" 2>&1; then
    p_bad "[A.health] healthcheck passes with the realm unopenable and the key at admin-only"
elif grep -qF "$D75_503" "$D/health-degraded.log" && ! grep -qF "$STASH" "$D/health-degraded.log"; then
    p_ok "[A.health] healthcheck fails with '$D75_503' and names no path"
else
    p_bad "[A.health] healthcheck fails without '$D75_503', or names the stash (see health-degraded.log)"
fi
discover_ports || p_bad "port discovery failed after the admin-only restart"
http_code="$(t curl -s -m 5 -o /dev/null -w '%{http_code}' "$(http_url)/health" 2>/dev/null)"
if [ "${http_code:-000}" = "000" ]; then
    p_ok "[A.http] the published HTTP port does not answer while admin-only"
else
    p_bad "[A.http] the published HTTP port answered $http_code while admin-only"
fi
if t ldapsearch -x -H "$(ldap_url)" -D "$(admin_dn)" -w "$ADMIN_PASS" -b "$BASE_DN" \
    "(uid=admin)" uid >/dev/null 2>&1; then
    p_bad "[A.ldap] the published LDAP port answers while admin-only"
else
    p_ok "[A.ldap] the published LDAP port does not answer while admin-only"
fi
if gexec bash -c "</dev/tcp/127.0.0.1/$KDC_INNER_PORT" 2>/dev/null; then
    p_bad "[A.kdc] the KDC port answers while admin-only"
else
    p_ok "[A.kdc] the KDC port refuses while admin-only"
fi

# Saved before the grep: under pipefail, grep -q closing the pipe early fails the exec.
in_ldap ldapsearch -D "$(admin_dn)" -w "$ADMIN_PASS" -b "$BASE_DN" "(uid=admin)" uid \
    >"$D/admin-search.out" 2>"$D/admin-search.err"
if grep -q "^uid: admin" "$D/admin-search.out"; then
    p_ok "[A.admin] an admin binds and searches on the container's loopback"
else
    p_bad "[A.admin] admin bind or search on loopback failed (see admin-search.err)"
fi
in_ldap ldapwhoami -D "$(d75_dn "$DEG_USER")" -w "$DEG_PASS" >"$D/user-bind.log" 2>&1
user_bind=$?
if [ "$user_bind" = "52" ]; then
    p_ok "[A.user] a regular user's bind gets 52 (unavailable)"
else
    p_bad "[A.user] a regular user's bind returned $user_bind (expected 52)"
fi
gexec sh -c 'printf "dn: uid=gatenew,ou=people,%s\nobjectClass: inetOrgPerson\nuid: gatenew\ncn: gatenew\nsn: gatenew\nmail: gatenew@gate.test\n" "$0" |
    ldapadd -x -H ldap://127.0.0.1:3890 -D "$1" -w "$2"' "$BASE_DN" "$(admin_dn)" "$ADMIN_PASS" \
    >"$D/write.log" 2>&1
if [ $? -ne 0 ] && grep -q "did not open" "$D/write.log"; then
    p_ok "[A.write] an admin's write is refused with the cause"
else
    p_bad "[A.write] an admin's write was not refused with the cause (see write.log)"
fi

# ---- directory-only: the default, the key taken out ----
if d75_key_out; then
    p_ok "[D.key] the key is out: $CONF is the bytes it was before the phase"
else
    p_bad "[D.key] $CONF is not the bytes it was (sha256 $(d75_conf_sum), was $D75_SUM0)"
fi
if d75_restart directory-only-docker.log "$D75_OPEN_LINE" && wait_answering 30 &&
    grep -q "the Kerberos realm $REALM did not open" "$D/directory-only-docker.log" &&
    grep -qF "the directory is served to everyone" "$D/directory-only-docker.log" &&
    ! grep -qF "$D75_ADMINS" "$D/directory-only-docker.log"; then
    D75_DIRONLY=1
    p_ok "[D.start] without the key the server came up directory-only: its log says the realm is closed, the cause, and that the directory is served to everyone"
else
    p_bad "[D.start] no directory-only start (see directory-only-docker.log): the directory-only rows are not run"
fi

d75_directory_only() {
    local got rc mark gid sync out user_pass="$DEG_PASS"
    discover_ports || p_bad "port discovery failed after the directory-only restart"
    TOKEN="$(gate_login)" || p_bad "[D.admin] the admin could not sign in on the published HTTP port"

    got="$(d75_start_rows "$D75_MARK0")"
    if [ "$got" = 1 ]; then
        p_ok "[D.row] one kerberos_sync failure row says 'directory-only: ' and the cause"
    else
        p_bad "[D.row] kerberos_sync failure rows that say 'directory-only: ' and the cause, since before the phase closed the realm: ${got:-unread}; want 1"
    fi
    got="$(d75_health_body)"
    if [ "$got" = "200 directory-only $D75_PUBLIC" ]; then
        p_ok "[D.health-body] /health answers 200 with the state directory-only and the cause '$D75_PUBLIC'"
    else
        p_bad "[D.health-body] /health answered '$got'; want '200 directory-only $D75_PUBLIC'"
    fi
    if d75_health >"$D/health-directory-only.log" 2>&1 && grep -qF "Success: Kerberos is directory-only" "$D/health-directory-only.log"; then
        p_ok "[D.health] the plain healthcheck passes and says 'Success: Kerberos is directory-only'"
    else
        p_bad "[D.health] the plain healthcheck fails on a directory-only server, or does not name the state (see health-directory-only.log)"
    fi
    d75_health --kerberos >"$D/health-kerberos.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] && grep -qF -e "$D75_FLAG" "$D/health-kerberos.log"; then
        p_ok "[D.health-flag] healthcheck --kerberos fails (exit $rc): '$D75_FLAG'"
    else
        p_bad "[D.health-flag] healthcheck --kerberos: exit $rc; want non-zero and '$D75_FLAG' (see health-kerberos.log)"
    fi
    if gexec bash -c "</dev/tcp/127.0.0.1/$KDC_INNER_PORT" 2>/dev/null ||
        gexec bash -c "</dev/tcp/127.0.0.1/$KADMIN_INNER_PORT" 2>/dev/null ||
        t bash -c "</dev/tcp/$cip/$KDC_INNER_PORT" 2>/dev/null; then
        p_bad "[D.kdc] the KDC or the kadmin port answers while directory-only"
    else
        p_ok "[D.kdc] the KDC port and the kadmin port refuse while directory-only"
    fi

    t ldapwhoami -x -H "$(ldap_url)" -D "$(d75_dn "$DEG_USER")" -w "$DEG_PASS" >"$D/user-bind-open.log" 2>&1
    rc=$?
    if [ "$rc" = 0 ] && gate_login "$DEG_USER" "$DEG_PASS" >/dev/null 2>"$D/user-login.err"; then
        p_ok "[D.user] a regular user binds on the published LDAP port (0) and signs in on the web"
    else
        p_bad "[D.user] a regular user's bind returned $rc (want 0), or the web sign-in failed (see user-login.err)"
    fi

    graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
        '{"id": "'"$DEG_USER"'", "pw": "'"$DEG_NEXT"'"}' >"$D/setpw-plain.json" 2>&1
    rc=$?
    t ldapwhoami -x -H "$(ldap_url)" -D "$(d75_dn "$DEG_USER")" -w "$DEG_NEXT" >/dev/null 2>&1
    got="new=$? "
    t ldapwhoami -x -H "$(ldap_url)" -D "$(d75_dn "$DEG_USER")" -w "$DEG_PASS" >/dev/null 2>&1
    got="${got}old=$?"
    case "$got" in new=0\ *) user_pass="$DEG_NEXT" ;; esac
    if [ "$rc" = 0 ] && [ "$got" = "new=0 old=49" ]; then
        p_ok "[D.plain-password] the password of a user without sync is changed: bind $got"
    else
        p_bad "[D.plain-password] setUserPassword of $DEG_USER: exit $rc, bind $got; want exit 0 and 'new=0 old=49' (see setpw-plain.json)"
    fi

    gid="$(graphql 'mutation($n: String!) { createGroup(name: $n) { id } }' '{"n": "'"$DEG_GROUP"'"}' 2>"$D/group.err" |
        json_get createGroup.id 2>/dev/null)"
    if [ -n "$gid" ] && graphql 'mutation($id: Int!) { deleteGroup(groupId: $id) { ok } }' '{"id": '"$gid"'}' >"$D/group-delete.json" 2>&1; then
        p_ok "[D.group] a group is made and deleted"
    else
        p_bad "[D.group] createGroup or deleteGroup failed while directory-only (see group.err, group-delete.json)"
    fi

    # The synced user's password, at the three doors.
    mark="$(log_mark)"
    d75_ldif "$D/pw-synced.ldif" "dn: $(d75_dn "$DEG_SYNC")" "changetype: modify" "replace: userPassword" "userPassword: $DEG_NEXT"
    lmodify -f "$D/pw-synced.ldif" >"$D/pw-synced-ldap.log" 2>&1
    rc=$?
    d75_refused D.synced-password-ldap "an LDAP Modify of the synced user's userPassword" "$D/pw-synced-ldap.log" "$rc" PASSWORD_CHANGE "$DEG_SYNC" "$mark"
    [ "$rc" = 52 ] || p_bad "[D.synced-password-ldap-code] the LDAP Modify returned $rc (want 52)"
    mark="$(log_mark)"
    gexec /app/lldap_set_password --base-url http://127.0.0.1:17170 --token "$TOKEN" \
        --username "$DEG_SYNC" --password "$DEG_NEXT" >"$D/pw-synced-http.log" 2>&1
    rc=$?
    d75_refused D.synced-password-http "the set-password tool for the synced user" "$D/pw-synced-http.log" "$rc" PASSWORD_CHANGE "$DEG_SYNC" "$mark"
    grep -qF "503 Service Unavailable" "$D/pw-synced-http.log" ||
        p_bad "[D.synced-password-http-code] the tool does not say '503 Service Unavailable' (see pw-synced-http.log)"
    mark="$(log_mark)"
    graphql 'mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }' \
        '{"id": "'"$DEG_SYNC"'", "pw": "'"$DEG_NEXT"'"}' >"$D/pw-synced-graphql.log" 2>&1
    rc=$?
    d75_refused D.synced-password-graphql "setUserPassword of the synced user" "$D/pw-synced-graphql.log" "$rc" PASSWORD_CHANGE "$DEG_SYNC" "$mark"
    t ldapwhoami -x -H "$(ldap_url)" -D "$(d75_dn "$DEG_SYNC")" -w "$DEG_SYNC_PASS" >/dev/null 2>&1
    got="old=$? "
    t ldapwhoami -x -H "$(ldap_url)" -D "$(d75_dn "$DEG_SYNC")" -w "$DEG_NEXT" >/dev/null 2>&1
    got="${got}new=$?"
    if [ "$got" = "old=0 new=49" ]; then
        p_ok "[D.synced-password-kept] after the three refusals the synced user binds with the old password only: $got"
    else
        p_bad "[D.synced-password-kept] the synced user's bind: $got; want 'old=0 new=49'"
    fi

    # Create with sync, at two doors: nothing is written.
    mark="$(log_mark)"
    graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$DEG_NEW"'", "email": "'"$DEG_NEW"'@gate.test", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}' \
        >"$D/create-sync-graphql.log" 2>&1
    rc=$?
    d75_refused D.create-sync-graphql "createUser with Kerberos sync" "$D/create-sync-graphql.log" "$rc" USER_CREATE "$DEG_NEW" "$mark"
    mark="$(log_mark)"
    d75_ldif "$D/create-sync.ldif" "dn: $(d75_dn "$DEG_NEW")" "changetype: add" "objectClass: inetOrgPerson" "uid: $DEG_NEW" \
        "cn: $DEG_NEW" "sn: $DEG_NEW" "mail: $DEG_NEW@gate.test" "kerberossync: 1"
    lmodify -f "$D/create-sync.ldif" >"$D/create-sync-ldap.log" 2>&1
    rc=$?
    d75_refused D.create-sync-ldap "an LDAP Add with kerberossync 1" "$D/create-sync-ldap.log" "$rc" USER_CREATE "$DEG_NEW" "$mark"
    [ "$rc" = 52 ] || p_bad "[D.create-sync-ldap-code] the LDAP Add returned $rc (want 52)"
    out="$(lsearch -b "$BASE_DN" "(uid=$DEG_NEW)" dn 2>/dev/null | grep -c '^dn: ')"
    if [ "$out" = 0 ]; then
        p_ok "[D.create-sync-nothing] after the two refusals no user $DEG_NEW exists"
    else
        p_bad "[D.create-sync-nothing] a search for uid=$DEG_NEW found $out entries (want 0)"
    fi

    # Sync on and sync off: refused, the attribute as it was.
    mark="$(log_mark)"
    graphql 'mutation($u: UpdateUserInput!) { updateUser(user: $u) { ok } }' \
        '{"u": {"id": "'"$DEG_USER"'", "insertAttributes": [{"name": "kerberossync", "value": ["1"]}]}}' >"$D/sync-on.log" 2>&1
    rc=$?
    d75_refused D.sync-on "turning Kerberos sync on" "$D/sync-on.log" "$rc" USER_UPDATE "$DEG_USER" "$mark"
    mark="$(log_mark)"
    graphql 'mutation($u: UpdateUserInput!) { updateUser(user: $u) { ok } }' \
        '{"u": {"id": "'"$DEG_SYNC"'", "insertAttributes": [{"name": "kerberossync", "value": ["0"]}]}}' >"$D/sync-off.log" 2>&1
    rc=$?
    d75_refused D.sync-off "turning Kerberos sync off" "$D/sync-off.log" "$rc" USER_UPDATE "$DEG_SYNC" "$mark"
    sync="$(d75_sync_of "$DEG_USER") $(d75_sync_of "$DEG_SYNC")"
    case "$sync" in
    "absent 1" | "0 1") p_ok "[D.sync-kept] kerberossync is as it was: $DEG_USER and $DEG_SYNC read '$sync'" ;;
    *) p_bad "[D.sync-kept] kerberossync of $DEG_USER and $DEG_SYNC reads '$sync'; want 'absent 1' or '0 1'" ;;
    esac

    # lldap_disabled of the synced user commits; its status is left for the realm's next opening.
    mark="$(log_mark)"
    got=""
    if [ -n "$D75_GID" ] &&
        graphql 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
            '{"u": "'"$DEG_SYNC"'", "g": '"$D75_GID"'}' >"$D/disable.json" 2>&1 &&
        got="$(d75_rows KERBEROS_SYNC "$DEG_SYNC" "$mark" true "$D75_STATUS")" && [ "$got" = one ]; then
        p_ok "[D.disabled] adding the synced user to lldap_disabled commits, and one kerberos_sync row says its status is left for the realm's next opening"
    else
        p_bad "[D.disabled] lldap_disabled=${D75_GID:-not found}; $(head -c 300 "$D/disable.json" 2>/dev/null); kerberos_sync rows: ${got:-unread}; want ok and one row '$D75_STATUS'"
    fi

    # The synced user's delete: refused at both doors (the confirmed delete is not built).
    mark="$(log_mark)"
    graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' '{"id": "'"$DEG_SYNC"'"}' >"$D/delete-graphql.log" 2>&1
    rc=$?
    d75_refused D.delete-graphql "deleteUser of the synced user" "$D/delete-graphql.log" "$rc" USER_DELETE "$DEG_SYNC" "$mark"
    mark="$(log_mark)"
    d75_ldif "$D/delete.ldif" "dn: $(d75_dn "$DEG_SYNC")" "changetype: delete"
    lmodify -f "$D/delete.ldif" >"$D/delete-ldap.log" 2>&1
    rc=$?
    d75_refused D.delete-ldap "an LDAP Delete of the synced user" "$D/delete-ldap.log" "$rc" USER_DELETE "$DEG_SYNC" "$mark"
    [ "$rc" = 52 ] || p_bad "[D.delete-ldap-code] the LDAP Delete returned $rc (want 52)"
    out="$(lsearch -b "$BASE_DN" "(uid=$DEG_SYNC)" dn 2>/dev/null | grep -c '^dn: ')"
    if [ "$out" = 1 ]; then
        p_ok "[D.delete-nothing] after the two refusals the synced user is still there"
    else
        p_bad "[D.delete-nothing] a search for uid=$DEG_SYNC found $out entries (want 1)"
    fi

    # The pages: the admins' notice, the locked switch on the create page and on a synced user's page.
    d75_page admin admin "$user_pass"
    got="$(d75_page_row admin notice-admin)"
    case "$got" in
    "ROW notice-admin SEEN $D75_NOTICE"*"Cause: the Kerberos realm $REALM did not open"*)
        p_ok "[P.notice-admin] an admin sees #kerberos-notice with the state sentence and 'Cause:' with the full cause"
        ;;
    *) p_bad "[P.notice-admin] $got; want '$D75_NOTICE', then 'Cause: the Kerberos realm $REALM did not open'" ;;
    esac
    d75_page_want admin create-switch "On=disabled,idle Off=disabled,active | $D75_LOCKED" \
        "on the create-user page both sync buttons are disabled with Off active"
    d75_page_want admin create-submit "path /users" "the create with the locked switch succeeds"
    sync="$(d75_sync_of "${DEG_NEW}p")"
    case "$sync" in
    0 | absent) p_ok "[P.create-sync] the user the page made has kerberossync $sync" ;;
    *) p_bad "[P.create-sync] the user the page made reads kerberossync '$sync'; want 0 or absent" ;;
    esac
    d75_page_want admin details-switch "On=disabled,active Off=disabled,idle | $D75_LOCKED" \
        "on the synced user's page the switch is locked at On"
    d75_page_want admin details-save "User successfully updated!" "saving another attribute of the synced user works"
    d75_page user user "$user_pass"
    d75_page_want user notice-user "none" "a regular user sees no #kerberos-notice"
    graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' '{"id": "'"${DEG_NEW}p"'"}' >"$D/delete-page-user.json" 2>&1 ||
        p_bad "[P.cleanup] the user the page made could not be deleted (see delete-page-user.json)"
}
[ -z "$D75_DIRONLY" ] || d75_directory_only

[ -z "$D75_DIRONLY" ] || rw_beside_row

# ---- the stash back: the realm opens ----
# A copy still there means the key could not be taken out above: once more, before the restart.
gexec sh -c '[ ! -e "$0.gate75" ] || mv "$0.gate75" "$0"' "$CONF" || p_bad "could not put $CONF back"
gexec mv "$STASH.gate-moved" "$STASH" || p_bad "could not restore the stash"
if t docker restart "$CONTAINER" >/dev/null 2>&1 && wait_healthy 120; then
    p_ok "healthy again once the stash is back: healthcheck --kerberos passes"
else
    p_bad "not healthy with a ready realm after restoring the stash"
fi
discover_ports || p_bad "port discovery failed after the restore"
TOKEN="$(gate_login)" || p_bad "admin login failed after the restore"
d75_got="$(d75_health_body)"
if [ "$d75_got" = "200 ready no cause" ]; then
    p_ok "/health answers 200 with the state ready and no cause"
else
    p_bad "/health answered '$d75_got' after the restore; want '200 ready no cause'"
fi
if gexec sh -c "KRB5CCNAME=/tmp/gate_restore_cc kinit -kt /data/kadm5.keytab admin/admin@$REALM" \
    >"$D/kinit-restored.log" 2>&1; then
    p_ok "the restored realm issues tickets"
else
    p_bad "kinit -kt failed after the restore"
fi
if [ "$(d75_conf_sum)" = "$D75_SUM0" ] && gexec sh -c '[ ! -e "$0.gate75" ]' "$CONF"; then
    p_ok "$CONF is the bytes it was before the phase, and the kept copy is gone"
else
    p_bad "$CONF differs from before the phase (sha256 $(d75_conf_sum), was $D75_SUM0), or $CONF.gate75 is still there"
fi

# The status left while directory-only has followed: the synced user, added to lldap_disabled with
# the realm closed, gets no ticket; out of the group, the password from before the phase signs in.
if [ -n "$D75_DIRONLY" ]; then
    kinit_pw "$DEG_SYNC@$REALM" "$DEG_SYNC_PASS" >"$D/kinit-synced-disabled.log" 2>&1
    d75_rc=$?
    if [ "$d75_rc" != 0 ] && grep -qi "revoked" "$D/kinit-synced-disabled.log"; then
        p_ok "[D.status-followed] the realm opened with the synced user's principal disabled: kinit says its credentials are revoked"
    else
        p_bad "[D.status-followed] kinit $DEG_SYNC after the restore: exit $d75_rc, $(head -c 200 "$D/kinit-synced-disabled.log" | tr '\n' ' '); want a refusal that says revoked"
    fi
    if [ -n "$D75_GID" ] &&
        graphql 'mutation($u: String!, $g: Int!) { removeUserFromGroup(userId: $u, groupId: $g) { ok } }' \
            '{"u": "'"$DEG_SYNC"'", "g": '"$D75_GID"'}' >"$D/enable.json" 2>&1 &&
        kinit_pw "$DEG_SYNC@$REALM" "$DEG_SYNC_PASS" >"$D/kinit-synced-after.log" 2>&1; then
        p_ok "[D.password-kept] out of lldap_disabled, the synced user gets a ticket with the password from before the phase"
    else
        p_bad "[D.password-kept] removeUserFromGroup or kinit $DEG_SYNC with the first password failed (see enable.json, kinit-synced-after.log)"
    fi
fi
graphql 'mutation($id: String!) { deleteUser(userId: $id) { ok } }' '{"id": "'"$DEG_SYNC"'"}' >"$D/delete-synced.json" 2>&1 ||
    p_bad "the synced user $DEG_SYNC could not be deleted once the realm was open (see delete-synced.json)"

if [ "$GATE_DB" != postgres ]; then
    p_skip "[W1.second-watch] two servers need one shared database; on $GATE_DB this row is not run"
    p_skip "[W1.second-reset] two servers need one shared database; on $GATE_DB this row is not run"
    p_skip "[R2.second-local-cause] two servers need one shared database; on $GATE_DB this row is not run"
elif ! rw_first; then
    p_bad "[W1.second-setup] the gate's server is not healthy with its realm before the rows (see first-health.log, first-kinit.log); not run"
else
    : >"$D/second.err"
    rw_watch_row
    rw_down "$RW_PLAIN"
    rw_reset_row
    rw_down "$RW_RESET"
    rw_local_row
    rw_down "$RW_LOCAL"
fi
rw_fresh_row
