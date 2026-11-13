"""ACC-3: kill after an acknowledged write, recorded on the host first; ACC-4: two servers on
one database (D127). One line per kill or case in dur.log."""

import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request

ENV = os.environ
RUN_DIR = sys.argv[1]
ROW, DB, IMAGE = ENV["DUR_ROW"], ENV["DUR_DB"], ENV["DUR_IMAGE"]
PREFIX, NET, PG = ENV["DUR_PREFIX"], ENV["DUR_NET"], ENV["DUR_PG"]
REALM, BASE_DN = "GATE.TEST", "dc=gate,dc=test"
ADMIN_PASS = "GateAdminPass2026!"
JWT, SEED = "gate-jwt-secret-not-for-production", "gate-key-seed-not-for-production"
KDC_DIR = "/var/kerberos/krb5kdc"
SERVICE, WRITER, LOCKED, POLICY, MAX_FAIL = "HTTP/dur.gate.test", "durbob", "durlock", "durpol", 3
HEALTH_LIMIT, EXIT_LIMIT, STOPPED_FOR = 90, 30, 40
FIND_LLDAP = ('p=; for q in /proc/[0-9]*; do read -r c <"$q/comm" 2>/dev/null || continue; '
              '[ "$c" = lldap ] && { p=${q#/proc/}; break; }; done; [ -n "$p" ] || exit 3')


def run(*args, stdin=None, timeout=60):
    try:
        return subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(args, 124, "", f"timed out after {e.timeout} s")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def tag(secret):
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


def test_password(n):
    return f"Dur-{n}-{secrets.token_hex(6)}"


class Record:
    def __init__(self):
        self.log = open(os.path.join(RUN_DIR, "dur.log"), "a", encoding="utf-8")
        self.acks = open(os.path.join(RUN_DIR, "acks.jsonl"), "a", encoding="utf-8")
        self.counts = {}

    @staticmethod
    def _sync(handle, text):
        handle.write(text + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    def ack(self, entry):
        self._sync(self.acks, json.dumps(entry, sort_keys=True))

    def line(self, key, ok, text):
        passed, failed = self.counts.get(key, (0, 0))
        self.counts[key] = (passed + ok, failed + (not ok))
        text = f"{text} {'PASS' if ok else 'FAIL'}"
        print(text, flush=True)
        self._sync(self.log, text)

    def note(self, text):
        print(text, flush=True)
        self._sync(self.log, text)


class Server:
    def __init__(self, name, data, kdc, db_url, shared=None):
        self.name = f"{PREFIX}-{name}"
        self.ldap, self.http = free_port(), free_port()
        mounts = ["-v", f"{data}:/data", "-v", f"{kdc}:{KDC_DIR}"]
        if shared:
            mounts += ["-v", f"{shared}:/shared"]
        self.args = [
            "docker", "run", "-d", "--name", self.name, "--network", NET,
            "-p", f"127.0.0.1:{self.ldap}:3890", "-p", f"127.0.0.1:{self.http}:17170",
            *mounts,
            "-e", f"LLDAP_JWT_SECRET={JWT}", "-e", f"LLDAP_KEY_SEED={SEED}",
            "-e", f"LLDAP_LDAP_BASE_DN={BASE_DN}", "-e", f"LLDAP_LDAP_USER_PASS={ADMIN_PASS}",
            "-e", f"LLDAP_DATABASE_URL={db_url}", IMAGE,
        ]

    def create(self):
        result = run(*self.args)
        if result.returncode != 0:
            raise RuntimeError(f"docker run {self.name}: {result.stderr.strip()}")

    def start(self):
        run("docker", "start", self.name)

    def kill(self):
        run("docker", "kill", "--signal", "KILL", self.name)

    def remove(self):
        run("docker", "rm", "-f", self.name)

    def logs(self):
        result = run("docker", "logs", self.name)
        return result.stdout + result.stderr

    def keep_logs(self, label):
        with open(os.path.join(RUN_DIR, f"{label}-{self.name}.log"), "w", encoding="utf-8") as f:
            f.write(self.logs())

    def state(self, field):
        return run("docker", "inspect", "-f", "{{.State." + field + "}}", self.name).stdout.strip()

    def running(self):
        return self.state("Running") == "true"

    def healthy(self):
        check = ["/app/lldap", "healthcheck", "--config-file", "/data/lldap_config.toml"]
        return run("docker", "exec", self.name, *check, timeout=30).returncode == 0

    def wait(self, until, limit):
        start = time.monotonic()
        while time.monotonic() - start < limit:
            if until():
                return time.monotonic() - start
            time.sleep(1)
        return None

    def wait_healthy(self, limit=HEALTH_LIMIT):
        return self.wait(lambda: self.running() and self.healthy(), limit)

    def wait_exit(self, limit=EXIT_LIMIT):
        return self.wait(lambda: not self.running(), limit)

    def kadmin(self, query):
        principal = f"admin/admin@{REALM}"
        result = run("docker", "exec", self.name, "kadmin", "-k", "-t", "/data/kadm5.keytab",
                     "-p", principal, "-q", query)
        refused = result.returncode != 0 or " while " in result.stderr
        return result.stdout, not refused

    def kinit(self, principal, password):
        script = 'KRB5CCNAME="/tmp/dur_cc_$$" kinit "$0"'
        result = run("docker", "exec", "-i", self.name, "sh", "-c", script, principal,
                     stdin=password + "\n")
        return result.returncode == 0, result.stderr

    def field(self, principal, label):
        out, _ = self.kadmin(f"getprinc {principal}")
        for text in out.splitlines():
            if text.strip().startswith(label):
                return text.split(label, 1)[1].strip().split(",")[0].strip()
        return None

    def kvno(self, principal):
        value = self.field(principal, "Key: vno")
        return int(value) if value and value.isdigit() else None

    def post(self, path, body, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(f"http://127.0.0.1:{self.http}{path}",
                                         data=json.dumps(body).encode(), headers=headers)
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)

    def graphql(self, query, variables):
        token = self.post("/auth/simple/login", {"username": "admin", "password": ADMIN_PASS})["token"]
        return self.post("/api/graphql", {"query": query, "variables": variables}, token)

    def set_password(self, user, password):
        query = ("mutation($id: String!, $pw: String!) "
                 "{ setUserPassword(userId: $id, password: $pw) { ok } }")
        try:
            body = self.graphql(query, {"id": user, "pw": password})
        except Exception:
            return False
        result = (body.get("data") or {}).get("setUserPassword") or {}
        return not body.get("errors") and bool(result.get("ok"))

    def create_user(self, user, password):
        query = "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }"
        user_input = {"id": user, "email": f"{user}@gate.test",
                      "attributes": [{"name": "kerberossync", "value": ["1"]}]}
        body = self.graphql(query, {"u": user_input})
        if body.get("errors") or not self.set_password(user, password):
            raise RuntimeError(f"could not create {user}: {body.get('errors')}")

    def bind(self, user, password):
        result = run("ldapwhoami", "-x", "-H", f"ldap://127.0.0.1:{self.ldap}",
                     "-D", f"uid={user},ou=people,{BASE_DN}", "-w", password, timeout=15)
        return result.returncode == 0

    def has_keytab(self):
        return run("docker", "cp", f"{self.name}:/data/kadm5.keytab", "-").returncode == 0

    def write_then_kill(self, *command):
        script = (f"rm -f /data/dur-*; {FIND_LLDAP}; "
                  '"$@" >/data/dur-out 2>&1; rc=$?; t1=$(date +%s%N); echo "$rc" >/data/dur-rc; '
                  't2=$(date +%s%N); echo "$t1 $t2" >/data/dur-ret; kill -9 "$p"')
        run("docker", "exec", self.name, "sh", "-c", script, "sh", *command, timeout=90)

    def kill_result(self):
        read = run("docker", "exec", self.name, "sh", "-c",
                   "cat /data/dur-rc /data/dur-ret; echo; cat /data/dur-out").stdout
        lines = read.splitlines()
        if len(lines) < 2 or not lines[0].strip().isdigit():
            return None, None, read
        t1, t2 = (int(x) for x in lines[1].split())
        return int(lines[0]), (t2 - t1) / 1e6, "\n".join(lines[2:])

    def arm_killer(self):
        script = (f"rm -f /data/dur-*; {FIND_LLDAP}; echo ready; read -r x; "
                  't=$(date +%s%N); echo "$t" >/data/dur-kill; [ "$x" = k ] && kill -9 "$p"')
        killer = subprocess.Popen(["docker", "exec", "-i", self.name, "sh", "-c", script],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        if killer.stdout.readline().strip() != "ready":
            killer.kill()
            return None
        return killer

    def killed_at(self):
        read = run("docker", "exec", self.name, "cat", "/data/dur-kill").stdout.strip()
        return int(read) if read.isdigit() else None

    def signal(self, name):
        find = f'{FIND_LLDAP}; echo "$p"'
        pid = run("docker", "exec", self.name, "sh", "-c", find).stdout.strip()
        send = run("docker", "exec", self.name, "sh", "-c", 'kill -"$0" "$1"', name, pid)
        return bool(pid) and send.returncode == 0


def volume(label):
    return f"{PREFIX}-{label}"


def db_url(shared):
    if DB == "postgres":
        return f"postgres://klldap:klldap@{PG}:5432/klldap", None
    if not shared:
        return "sqlite:////data/users.db?mode=rwc", None
    return "sqlite:////shared/users.db?mode=rwc", volume("shared")


def reset_database(shared):
    if DB == "postgres":
        sql = "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
        run("docker", "exec", PG, "psql", "-U", "klldap", "-d", "klldap", "-q", "-c", sql)
    elif shared:
        # The entrypoint owns /data and the KDC directory for the server's user, not /shared.
        run("docker", "volume", "rm", "-f", shared)
        run("docker", "run", "--rm", "-v", f"{shared}:/shared", "--entrypoint", "sh", IMAGE,
            "-c", "chown 1000:1000 /shared && chmod 700 /shared")


def acc3(record, kills):
    url, shared = db_url(False)
    server = Server("acc3", volume("acc3-data"), volume("acc3-kdc"), url, shared)
    server.create()
    if server.wait_healthy() is None:
        server.keep_logs("start")
        raise RuntimeError("the server did not become healthy")
    lock_password = test_password(0)
    server.create_user(WRITER, test_password(0))
    server.create_user(LOCKED, lock_password)
    for query in (f"addprinc -randkey {SERVICE}",
                  f"addpol -maxfailure {MAX_FAIL} -failurecountinterval 0 -lockoutduration 0 {POLICY}",
                  f"modprinc -policy {POLICY} {LOCKED}"):
        if not server.kadmin(query)[1]:
            raise RuntimeError(f"kadmin {query} failed")
    n = 0
    for kind in "abc":
        for i in range(kills):
            n += 1
            if not one_kill(record, server, n, kind, i, lock_password):
                raise RuntimeError(f"the server did not come back after kill {n}")


def one_kill(record, server, n, kind, i, lock_password):
    head = f"KILL n={n} db={DB} kind={kind}"
    if kind == "a":
        target, before = SERVICE, server.kvno(SERVICE)
        expect = before + 1 if before is not None else None
        server.write_then_kill("kadmin", "-k", "-t", "/data/kadm5.keytab", "-p",
                               f"admin/admin@{REALM}", "-q", f"cpw -randkey {SERVICE}")
    elif kind == "b":
        target, password = WRITER, test_password(n)
        expect = tag(password)
        killer = server.arm_killer()
        acked = killer is not None and server.set_password(WRITER, password)
        replied = time.time_ns()
        if killer is not None:
            killer.stdin.write("k\n" if acked else "n\n")
            killer.stdin.flush()
            try:
                killer.wait(timeout=30)
            except subprocess.TimeoutExpired:
                killer.kill()
        if not acked:
            record.line(kind, False, f"{head} target={target} the write was not acknowledged")
            return server.healthy()
    else:
        target, count = LOCKED, i % MAX_FAIL + 1
        expect = f"{count},locked={count == MAX_FAIL}"
        # A failure in the same whole second as the last unlock resets the count (MIT's audit).
        time.sleep(2)
        refused = all(not server.kinit(LOCKED, test_password(n))[0] for _ in range(count - 1))
        server.write_then_kill("sh", "-c", 'printf "%s\\n" "$0" | KRB5CCNAME=/tmp/dur_cc kinit "$1"',
                               test_password(n), LOCKED)
    server.wait_exit(EXIT_LIMIT)
    server.start()
    back = server.wait_healthy()
    if back is None:
        server.keep_logs(f"kill-{n}")
        record.line(kind, False, f"{head} target={target} not healthy after restart")
        return False
    if kind == "b":
        at = server.killed_at()
        gap_ms = (at - replied) / 1e6 if at else None
    else:
        rc, gap_ms, out = server.kill_result()
        acked = rc == 0 and " while " not in out if kind == "a" else refused and rc not in (None, 0)
    if not acked:
        record.line(kind, False, f"{head} target={target} the write was not acknowledged")
        return True
    gap = f"{gap_ms:.1f}" if gap_ms is not None else "unknown"
    record.ack({"n": n, "db": DB, "kind": kind, "target": target, "expect": expect, "gap_ms": gap})
    if kind == "a":
        got = server.kvno(SERVICE)
        ok = got == expect
    elif kind == "b":
        bound, (signed, _) = server.bind(WRITER, password), server.kinit(WRITER, password)
        got, ok = f"bind={bound},kinit={signed}", bound and signed
    else:
        failures = server.field(LOCKED, "Failed password attempts:")
        signed, why = server.kinit(LOCKED, lock_password)
        locked = not signed and "revoked" in why
        got = f"{failures},locked={locked}"
        ok = got == expect
        server.kadmin(f"modprinc -unlock {LOCKED}")
    if not ok:
        server.keep_logs(f"kill-{n}")
    record.line(kind, ok, f"{head} target={target} gap_ms={gap} back_s={back:.1f} "
                          f"expect={expect} got={got}")
    return True


def acc4(record, times):
    n = 0
    for case in ENV.get("DUR_CASES", "i,ii,iii").split(","):
        for k in range(times):
            n += 1
            url, shared = db_url(True)
            reset_database(shared)
            kdc = volume(f"acc4-{n}-kdc")
            a = Server(f"acc4-{n}-a", volume(f"acc4-{n}-a-data"), kdc, url, shared)
            b = Server(f"acc4-{n}-b", volume(f"acc4-{n}-b-data"), kdc, url, shared)
            a.create()
            if a.wait_healthy() is None:
                a.keep_logs(f"case-{n}")
                record.line(case, False, f"CASE n={n} db={DB} case={case} A did not become healthy")
                continue
            a.create_user(WRITER, test_password(n))
            ok, text = {"i": case_i, "ii": case_ii, "iii": case_iii}[case](a, b, n)
            if not ok:
                a.keep_logs(f"case-{n}")
                b.keep_logs(f"case-{n}")
            record.line(case, ok, f"CASE n={n} db={DB} case={case} {text}")
            a.remove()
            b.remove()
            run("docker", "volume", "rm", "-f", kdc, volume(f"acc4-{n}-a-data"), volume(f"acc4-{n}-b-data"))


def write_through(server, n, suffix):
    password = test_password(n) + suffix
    written = server.set_password(WRITER, password)
    signed = written and server.kinit(WRITER, password)[0]
    return written and signed, password


def case_i(a, b, n):
    b.create()
    gone = b.wait_exit(HEALTH_LIMIT)
    code = b.state("ExitCode")
    cause = "another server holds the Kerberos realm" in b.logs()
    keytab = b.has_keytab()
    write, _ = write_through(a, n, "a")
    one = a.healthy() and not b.running()
    ok = gone is not None and code not in ("", "0") and cause and not keytab and write and one
    return ok, (f"b_exit={code} b_cause={cause} b_keytab={keytab} write_via_a={write} "
                f"one_healthy={one}")


def case_ii(a, b, n):
    a.kill()
    b.create()
    back = b.wait_healthy()
    write, _ = write_through(b, n, "b") if back is not None else (False, None)
    one = back is not None and b.healthy() and not a.running()
    back_s = f"{back:.1f}" if back is not None else "none"
    return back is not None and write and one, f"b_back_s={back_s} write_via_b={write} one_healthy={one}"


def case_iii(a, b, n):
    if not a.signal("STOP"):
        return False, "could not stop A's lldap process"
    stopped_at = time.monotonic()
    b.create()
    time.sleep(max(0.0, STOPPED_FOR - (time.monotonic() - stopped_at)))
    a.signal("CONT")
    password_a = test_password(n) + "a"
    a_answer = a.set_password(WRITER, password_a)
    a_gone = a.wait_exit(EXIT_LIMIT)
    a_code = a.state("ExitCode")
    a_cause = next((line for line in a.logs().splitlines() if line.startswith("Error:")), "")
    b_back = b.wait_healthy()
    serving = b_back is not None
    directory_has_a = b.bind(WRITER, password_a) if serving else None
    realm_has_a = b.kinit(WRITER, password_a)[0] if serving else None
    write, _ = write_through(b, n, "b") if serving else (False, None)
    one = serving and b.healthy() and not a.running()
    ok = a_gone is not None and a_code not in ("", "0") and realm_has_a is False and write and one
    return ok, (f"a_exit={a_code} realm_has_a_password={realm_has_a} write_via_b={write} "
                f"one_healthy={one} recorded: a_answer={a_answer} "
                f"directory_has_a_password={directory_has_a} a_cause={a_cause!r}")


def main():
    record = Record()
    started = time.time()
    record.note(f"START row={ROW} db={DB} image={IMAGE} image_id={ENV.get('DUR_IMAGE_ID', '')} "
                f"driver={ENV.get('DUR_REV', '')}")
    error = None
    try:
        if ROW == "acc3":
            acc3(record, int(ENV["DUR_KILLS"]))
        else:
            acc4(record, int(ENV["DUR_TIMES"]))
    except Exception as e:
        error = str(e)
        record.note(f"ABORT {error}")
    summary = {"row": ROW, "db": DB, "image": IMAGE, "image_id": ENV.get("DUR_IMAGE_ID", ""),
               "driver": ENV.get("DUR_REV", ""), "seconds": round(time.time() - started),
               "counts": {k: {"pass": p, "fail": f} for k, (p, f) in record.counts.items()},
               "aborted": error}
    with open(os.path.join(RUN_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    failed = sum(f for _, f in record.counts.values())
    record.note(f"END failed={failed} aborted={error is not None} seconds={summary['seconds']}")
    return 0 if failed == 0 and error is None and record.counts else 1


if __name__ == "__main__":
    sys.exit(main())
