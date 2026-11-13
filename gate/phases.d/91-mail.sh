# shellcheck shell=bash
# Phase: password-reset mail. The sink is python:3.14-alpine on this run's network,
# host name smtp-gate. NONE, TLS and STARTTLS deliver one mail each. TLS without
# the SMTP root is refused, and the default log does not contain the reset token.
# The program is inlined here.

# shellcheck disable=SC2154
D="$(phase_dir)"
PY_IMAGE="python:3.14-alpine"
SINK="klldap-gate-smtp-$RUNID"
MAIL_NONE="$CONTAINER-mail-none"
MAIL_TLS="$CONTAINER-mail-tls"
MAIL_START="$CONTAINER-mail-starttls"
MAIL_BAD="$CONTAINER-mail-untrusted"
MAIL_VOL="klldap-gate-mail-$RUNID"
EXTRA_CONTAINERS+=("$SINK" "$MAIL_NONE" "$MAIL_TLS" "$MAIL_START" "$MAIL_BAD")
EXTRA_VOLUMES+=("$MAIL_VOL")
MAIL_USER="mailuser"
MAIL_ADDR="${MAIL_USER}@gate.test"
NEW_PASS="MailUserPass2026!"
ROOT_FILE="/smtp-root/cert/ca.pem"

SAVED_HTTP="$HTTP_PORT"
SAVED_LDAP="$LDAP_PORT"
SAVED_TOKEN="$TOKEN"
mail_restore() {
    HTTP_PORT="$SAVED_HTTP"
    LDAP_PORT="$SAVED_LDAP"
    TOKEN="$SAVED_TOKEN"
}

mail_stop() {
    docker rm -fv "$SINK" "$MAIL_NONE" "$MAIL_TLS" "$MAIL_START" "$MAIL_BAD" >/dev/null 2>&1 || true
    docker volume rm "$MAIL_VOL" >/dev/null 2>&1 || true
    mail_restore
}

if ! docker image inspect "$PY_IMAGE" >/dev/null 2>&1; then
    if ! docker pull "$PY_IMAGE" >"$D/pull.log" 2>&1; then
        if [ "${CI:-}" = "true" ]; then
            p_bad "$PY_IMAGE could not be pulled"
        else
            p_skip "$PY_IMAGE could not be pulled (no network)"
        fi
        mail_restore
        return 0
    fi
fi
docker image inspect "$PY_IMAGE" --format '{{json .RepoDigests}}' >"$D/image-digest.txt"

cat >"$D/sink.py" <<'PY'
import socket, ssl, threading
from pathlib import Path

mail_dir = Path("/data/mail")
mail_dir.mkdir(parents=True, exist_ok=True)
lock = threading.Lock()

def save(raw):
    with lock:
        n = len(list(mail_dir.glob("*.eml"))) + 1
        (mail_dir / f"{n}.eml").write_bytes(raw)

def session(conn, ctx):
    def send(line):
        conn.sendall((line + "\r\n").encode())
    send("220 smtp-gate ESMTP")
    buf = b""
    data_mode = False
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            return
        buf += chunk
        while True:
            if data_mode:
                mark = buf.find(b"\r\n.\r\n")
                if mark < 0:
                    break
                save(buf[:mark])
                buf = buf[mark + 5:]
                data_mode = False
                send("250 ok")
                continue
            nl = buf.find(b"\r\n")
            if nl < 0:
                break
            line = buf[:nl].decode("utf-8", "replace").strip()
            buf = buf[nl + 2:]
            cmd = line.upper()
            if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                send("250-smtp-gate")
                if ctx is not None:
                    send("250-STARTTLS")
                send("250 HELP")
            elif cmd == "STARTTLS" and ctx is not None:
                send("220 go")
                conn = ctx.wrap_socket(conn, server_side=True)
                ctx = None
            elif cmd == "DATA":
                send("354 go")
                data_mode = True
            elif cmd == "QUIT":
                send("221 bye")
                return
            else:
                send("250 ok")

def serve(port, ctx, implicit):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(8)
    while True:
        conn, _ = sock.accept()
        use = ctx
        if implicit:
            try:
                conn = ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                conn.close()
                continue
            use = None
        threading.Thread(target=session, args=(conn, use), daemon=True).start()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/data/cert/cert.pem", "/data/cert/key.pem")
threading.Thread(target=serve, args=(2525, None, False), daemon=True).start()
threading.Thread(target=serve, args=(587, ctx, False), daemon=True).start()
serve(465, ctx, True)
PY

if ! docker volume create "$MAIL_VOL" >/dev/null; then
    p_bad "could not create the mail volume"
    mail_stop
    return 0
fi
if ! docker run --rm --entrypoint sh -v "$MAIL_VOL:/data" "$GATE_IMAGE" -c \
    'mkdir -p /data/cert /data/mail &&
     openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=smtp-gate-ca" \
       -addext "basicConstraints=critical,CA:TRUE" \
       -keyout /data/cert/ca.key -out /data/cert/ca.pem &&
     openssl req -newkey rsa:2048 -nodes -subj "/CN=smtp-gate" \
       -keyout /data/cert/key.pem -out /data/cert/leaf.csr &&
     printf "%s\n" "basicConstraints=critical,CA:FALSE" \
       "subjectAltName=DNS:smtp-gate" "extendedKeyUsage=serverAuth" \
       > /data/cert/leaf.ext &&
     openssl x509 -req -in /data/cert/leaf.csr \
       -CA /data/cert/ca.pem -CAkey /data/cert/ca.key -CAcreateserial -days 2 \
       -extfile /data/cert/leaf.ext -out /data/cert/cert.pem &&
     chmod 644 /data/cert/ca.pem /data/cert/cert.pem /data/cert/key.pem' \
    >"$D/openssl.log" 2>&1; then
    p_bad "the image openssl could not write the sink certificate (see openssl.log)"
    mail_stop
    return 0
fi

docker create --name "$SINK" --hostname smtp-gate --network "$NET" \
    --network-alias smtp-gate -v "$MAIL_VOL:/data" \
    --entrypoint python3 "$PY_IMAGE" /sink.py >/dev/null || {
    p_bad "could not create the SMTP sink"
    mail_stop
    return 0
}
docker cp "$D/sink.py" "$SINK:/sink.py"
docker start "$SINK" >/dev/null || {
    p_bad "could not start the SMTP sink"
    mail_stop
    return 0
}

mail_up() {
    local name="$1" enc="$2" port="$3" root="${4:-}"
    docker rm -fv "$name" >/dev/null 2>&1 || true
    local extra=()
    if [ -n "$root" ]; then
        extra=(-e "LLDAP_SMTP_OPTIONS__TLS_ROOT_CERT_FILE=$root" -v "$MAIL_VOL:/smtp-root:ro")
    fi
    docker run -d --name "$name" --network "$NET" \
        -p "127.0.0.1::3890" -p "127.0.0.1::17170" \
        -e LLDAP_JWT_SECRET="$JWT_SECRET" -e LLDAP_KEY_SEED="$KEY_SEED" \
        -e LLDAP_LDAP_BASE_DN="$BASE_DN" -e LLDAP_LDAP_USER_PASS="$ADMIN_PASS" \
        -e LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET=true \
        -e LLDAP_SMTP_OPTIONS__SERVER=smtp-gate \
        -e LLDAP_SMTP_OPTIONS__PORT="$port" \
        -e LLDAP_SMTP_OPTIONS__SMTP_ENCRYPTION="$enc" \
        -e LLDAP_HTTP_URL=http://smtp-gate \
        "${extra[@]}" \
        "$GATE_IMAGE" >/dev/null
}

mail_healthy() {
    local name="$1"
    local _
    for _ in $(seq 1 90); do
        if docker exec "$name" /app/lldap healthcheck \
            --config-file /data/lldap_config.toml >/dev/null 2>&1; then
            return 0
        fi
        [ -z "$(docker ps -q -f "name=^${name}$")" ] && return 1
        sleep 1
    done
    return 1
}

use_mail_ports() {
    local name="$1"
    HTTP_PORT="$(docker port "$name" 17170/tcp | head -1 | sed 's/.*://')"
    LDAP_PORT="$(docker port "$name" 3890/tcp | head -1 | sed 's/.*://')"
    TOKEN="$(gate_login)" || return 1
}

step1_code() {
    STEP_URL="http://127.0.0.1:${HTTP_PORT}/auth/reset/step1/${MAIL_USER}" \
        t python3 - <<'PY'
import os, urllib.error, urllib.request
req = urllib.request.Request(os.environ["STEP_URL"], data=b"", method="POST")
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(resp.status)
except urllib.error.HTTPError as err:
    print(err.code)
PY
}

mail_count() {
    docker exec "$SINK" sh -c 'ls /data/mail/*.eml 2>/dev/null | wc -l'
}

# The sink stores the message quoted-printable, with the link folded.
mail_decode() {
    python3 -c '
import email, sys
from email import policy
raw = open(sys.argv[1], "rb").read()
try:
    text = email.message_from_bytes(raw, policy=policy.default).get_content()
except Exception:
    text = ""
sys.stdout.write(text)
' "$1"
}

# A delivered reset: one new message, the link sets the password, the new password binds.
mail_delivered() {
    local name="$1" enc="$2" port="$3" root="$4" label="$5" n="$6"
    if ! mail_up "$name" "$enc" "$port" "$root" || ! mail_healthy "$name"; then
        p_bad "$label mail container did not become healthy"
        return 0
    fi
    if ! use_mail_ports "$name"; then
        p_bad "$label admin login failed"
        return 0
    fi
    # shellcheck disable=SC2016
    graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
        '{"u": {"id": "'"$MAIL_USER"'", "email": "'"$MAIL_ADDR"'"}}' \
        >"$D/${label}-create.json" 2>&1 || p_bad "$label createUser failed"
    local code
    code="$(step1_code)"
    docker exec "$SINK" cat "/data/mail/${n}.eml" >"$D/${label}-mail.txt" 2>/dev/null || true
    mail_decode "$D/${label}-mail.txt" >"$D/${label}-body.txt" || true
    local got
    got="$(mail_count | tr -d '[:space:]')"
    if [ "$code" != "200" ] || [ "$got" != "$n" ] \
        || ! grep -q "To: $MAIL_ADDR" "$D/${label}-mail.txt" \
        || ! grep -q 'Subject: \[LLDAP\] Password reset requested' "$D/${label}-mail.txt" \
        || [ "$(grep -c 'reset-password/step2/' "$D/${label}-body.txt")" != "1" ]; then
        p_bad "$label: reset mail was not message $n (status $code, count $got)"
        return 0
    fi
    local reset_tok jwt
    reset_tok="$(python3 -c '
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
m = re.search(r"reset-password/step2/([A-Za-z0-9]+)", text)
print(m.group(1) if m else "")
' "$D/${label}-body.txt")"
    jwt="$(STEP2="http://127.0.0.1:${HTTP_PORT}/auth/reset/step2/${reset_tok}" \
        t python3 - <<'PY'
import json, os, urllib.request
with urllib.request.urlopen(os.environ["STEP2"], timeout=30) as resp:
    print(json.load(resp)["token"])
PY
)"
    if docker exec "$name" /app/lldap_set_password \
        --base-url http://127.0.0.1:17170 --token "$jwt" \
        --username "$MAIL_USER" --password "$NEW_PASS" \
        >"$D/${label}-set-password.log" 2>&1 \
        && t ldapsearch -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
            -D "uid=${MAIL_USER},ou=people,${BASE_DN}" -w "$NEW_PASS" \
            -b "$BASE_DN" "(uid=${MAIL_USER})" uid \
            >"$D/${label}-bind.out" 2>"$D/${label}-bind.err" \
        && grep -q "^uid: ${MAIL_USER}" "$D/${label}-bind.out" \
        && grep -q 'result: 0 Success' "$D/${label}-bind.out"; then
        p_ok "$label: one reset mail, the link sets the password, and the new password binds"
    else
        p_bad "$label: the mail arrived but the password was not set"
    fi
}

mail_delivered "$MAIL_NONE" NONE 2525 "" none 1
mail_delivered "$MAIL_TLS" TLS 465 "$ROOT_FILE" tls 2
mail_delivered "$MAIL_START" STARTTLS 587 "$ROOT_FILE" starttls 3

if ! mail_up "$MAIL_BAD" TLS 465 || ! mail_healthy "$MAIL_BAD"; then
    p_bad "untrusted mail container did not become healthy"
else
    if ! use_mail_ports "$MAIL_BAD"; then
        p_bad "untrusted admin login failed"
    else
        # shellcheck disable=SC2016
        graphql 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
            '{"u": {"id": "'"$MAIL_USER"'", "email": "'"$MAIL_ADDR"'"}}' \
            >"$D/untrusted-create.json" 2>&1 || p_bad "untrusted createUser failed"
        code="$(step1_code)"
        got="$(mail_count | tr -d '[:space:]')"
        docker logs "$MAIL_BAD" >"$D/untrusted-docker.log" 2>&1 || true
        # This container, not whichever HTTP_PORT a previous row left behind.
        HTTP_PORT="$(docker port "$MAIL_BAD" 17170/tcp | head -1 | sed 's/.*://')"
        log_row=0
        for _ in $(seq 1 8); do
            graphql '{ logs(filter: {kinds: [PASSWORD_RESET_REQUEST], success: false}) { kind success detail } }' \
                >"$D/untrusted-log.json" 2>"$D/untrusted-log.err" || true
            if grep -q 'PASSWORD_RESET_REQUEST' "$D/untrusted-log.json" \
                && grep -q 'could not send email' "$D/untrusted-log.json"; then
                log_row=1
                break
            fi
            sleep 0.3
        done
        if [ "$code" = "500" ] && [ "$got" = "3" ] && [ "$log_row" = "1" ] \
            && grep -q 'invalid peer certificate: UnknownIssuer' "$D/untrusted-docker.log"; then
            p_ok "TLS without the SMTP root is refused and no mail is stored"
        else
            p_bad "untrusted SMTP certificate: status $code count $got (see untrusted-log.json, untrusted-docker.log)"
        fi
        if grep -q 'Error sending email' "$D/untrusted-docker.log" \
            && ! grep -q 'Reset token:' "$D/untrusted-docker.log"; then
            p_ok "the default log holds the send failure and no reset token"
        else
            p_bad "the default log did not show the send failure without a reset token (see untrusted-docker.log)"
        fi
    fi
fi

mail_stop
