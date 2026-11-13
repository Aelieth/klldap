"""ACC-3: kill after an acknowledged write, recorded on the host first; ACC-4: two servers on
one database (D127); ACC-8: the same writes, the lab guest cut by `virsh destroy` (D178).
One line per kill, cut or case in dur.log."""

import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
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
REFUSED = "Password incorrect while getting initial credentials"
GAP_TARGET_MS = 20
POWER = ROW == "acc8"
ADDR = ENV.get("DUR_ADDR", "127.0.0.1")
GUEST = ENV.get("DUR_GUEST", "")
BOOT_LIMIT = 240
SETTLE = int(ENV.get("DUR_SETTLE", "0"))
LOCKOUT = f"{KDC_DIR}/lockout"
NOISE, NOISE_POLICY = "durnoise", "durnoisepol"
LOCKOUT_CAUSES = ("lockout file", "is not a kerber-rust lockout file")
CACHE_NOTE = ("guest disk qcow2 with QEMU's default cache (writeback): a cut loses the guest's RAM "
              "and page cache; a device's volatile cache is not tested (O, pwr-lab-readback.md 2)")
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
        self.gaps = {}
        self.aborted = 0
        self.losses = []
        self.degraded = 0

    @staticmethod
    def _sync(handle, text):
        handle.write(text + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    def ack(self, entry):
        try:
            self._sync(self.acks, json.dumps(entry, sort_keys=True))
        except OSError as e:
            self.note(f"ACK-WRITE-FAILED n={entry.get('n')} {e}")
            return False
        return True

    def abort(self, text):
        self.aborted += 1
        self.note(f"{text} ABORTED")

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
        self.ldap, self.http = (3890, 17170) if POWER else (free_port(), free_port())
        mounts = ["-v", f"{data}:/data", "-v", f"{kdc}:{KDC_DIR}"]
        if shared:
            mounts += ["-v", f"{shared}:/shared"]
        restart = ["--restart", "always"] if POWER else []
        self.args = [
            "docker", "run", "-d", "--name", self.name, "--network", NET, *restart,
            "-p", f"{ADDR}:{self.ldap}:3890", "-p", f"{ADDR}:{self.http}:17170",
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

    def logs(self, since=None):
        result = run("docker", "logs", *(["--since", since] if since else []), self.name)
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
        request = urllib.request.Request(f"http://{ADDR}:{self.http}{path}",
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
        result = run("ldapwhoami", "-x", "-H", f"ldap://{ADDR}:{self.ldap}",
                     "-D", f"uid={user},ou=people,{BASE_DN}", "-w", password, timeout=15)
        return result.returncode == 0

    def has_keytab(self):
        return run("docker", "cp", f"{self.name}:/data/kadm5.keytab", "-").returncode == 0

    def client_then_kill(self, *command):
        """The client's result streams to the host; the shell then waits for k to kill lldap."""
        script = (f"rm -f /data/dur-*; {FIND_LLDAP}; "
                  '"$@" >/data/dur-out 2>&1; rc=$?; t=$(date +%s%N); '
                  'echo "RESULT $rc $t"; cat /data/dur-out; echo END-OF-OUTPUT; read -r x; '
                  'k=$(date +%s%N); echo "$t $k" >/data/dur-kill; [ "$x" = k ] && kill -9 "$p"')
        shell = subprocess.Popen(
            ["docker", "exec", "-i", self.name, "sh", "-c", script, "sh", *command],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        head = shell.stdout.readline().split()
        if len(head) != 3 or head[0] != "RESULT" or not head[1].isdigit():
            release(shell, False)
            return None, None, ""
        out = []
        for line in shell.stdout:
            if line.rstrip("\n") == "END-OF-OUTPUT":
                break
            out.append(line)
        return shell, int(head[1]), "".join(out)

    def arm_killer(self):
        script = (f"rm -f /data/dur-*; {FIND_LLDAP}; echo ready; read -r x; "
                  't=$(date +%s%N); echo "- $t" >/data/dur-kill; [ "$x" = k ] && kill -9 "$p"')
        killer = subprocess.Popen(["docker", "exec", "-i", self.name, "sh", "-c", script],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        if killer.stdout.readline().strip() != "ready":
            killer.kill()
            return None
        return killer

    def killed_at(self):
        read = run("docker", "exec", self.name, "cat", "/data/dur-kill").stdout.split()
        if len(read) != 2 or not read[1].isdigit():
            return None, None
        return (int(read[0]) if read[0].isdigit() else None), int(read[1])

    def signal(self, name):
        find = f'{FIND_LLDAP}; echo "$p"'
        pid = run("docker", "exec", self.name, "sh", "-c", find).stdout.strip()
        send = run("docker", "exec", self.name, "sh", "-c", 'kill -"$0" "$1"', name, pid)
        return bool(pid) and send.returncode == 0


def release(killer, go):
    try:
        killer.stdin.write("k\n" if go else "n\n")
        killer.stdin.flush()
    except OSError:
        pass
    try:
        killer.wait(timeout=30)
    except subprocess.TimeoutExpired:
        killer.kill()


def refused(result):
    signed, text = result
    return not signed and REFUSED in text


def virsh(*args):
    command = ["virsh", "-q", "-c", "qemu:///system", *args]
    if shutil.which("virsh") is None:
        command.insert(0, "distrobox-host-exec")
    return run(*command, timeout=120)


def cut_guest():
    started = time.perf_counter_ns()
    result = virsh("destroy", GUEST)
    if result.returncode != 0:
        raise RuntimeError(f"virsh destroy {GUEST}: {result.stderr.strip()}")
    return (time.perf_counter_ns() - started) / 1e6


def boot_guest():
    started = time.monotonic()
    result = virsh("start", GUEST)
    if result.returncode != 0:
        raise RuntimeError(f"virsh start {GUEST}: {result.stderr.strip()}")
    while time.monotonic() - started < BOOT_LIMIT:
        if run("docker", "info", timeout=10).returncode == 0:
            return time.monotonic() - started
        time.sleep(2)
    raise RuntimeError(f"the guest's docker did not answer within {BOOT_LIMIT} s of virsh start")


def lockout_state(server):
    """The lockout file read in the container: guest clock, and size/birth/modify or missing."""
    script = f'date +%s.%N; stat -c "%s %W %Y" {LOCKOUT} 2>/dev/null || echo missing'
    lines = run("docker", "exec", "-u", "0", server.name, "sh", "-c", script, timeout=30).stdout.split()
    if len(lines) < 2:
        return None
    if lines[1] == "missing":
        return {"now": float(lines[0]), "exists": False}
    size, birth, modify = (int(x) if x.lstrip("-").isdigit() else 0 for x in lines[1:4])
    return {"now": float(lines[0]), "exists": True, "size": size, "birth": birth, "modify": modify}


def lockout_text(state):
    if state is None:
        return "unread"
    if not state["exists"]:
        return "missing"
    return f"size={state['size']},birth={state['birth']},modify={state['modify']}"


def wait_up(server, since):
    """Healthy, or the log since the boot names a lockout cause: (seconds, cause) or (None, None)."""
    started = time.monotonic()
    while time.monotonic() - started < BOOT_LIMIT:
        if server.running():
            if server.healthy():
                return time.monotonic() - started, None
            logs = server.logs(since)
            if "did not open" in logs:
                cause = next((c for c in LOCKOUT_CAUSES if c in logs), None)
                if cause:
                    return time.monotonic() - started, cause
        time.sleep(1)
    return None, None


def save_evidence(server, n):
    where = os.path.join(RUN_DIR, f"evidence-{n}")
    os.makedirs(where, exist_ok=True)
    stash = f"{KDC_DIR}/.k5.{REALM}"
    listing = run("docker", "exec", "-u", "0", server.name, "sh", "-c",
                  f"ls -la --full-time {KDC_DIR}; stat {KDC_DIR} {stash} {LOCKOUT}", timeout=30)
    with open(os.path.join(where, "kdc.txt"), "w", encoding="utf-8") as f:
        f.write(listing.stdout + listing.stderr)
    with open(os.path.join(where, "docker-logs.txt"), "w", encoding="utf-8") as f:
        f.write(server.logs())


def recover(record, server, n):
    """An empty lockout file with the KDC directory's owner, synced with its directory; then restart."""
    script = (f'owner=$(stat -c %u:%g {KDC_DIR}) && : > {LOCKOUT} && chown "$owner" {LOCKOUT} '
              f"&& chmod 600 {LOCKOUT} && sync {LOCKOUT} {KDC_DIR}")
    made = run("docker", "exec", "-u", "0", server.name, "sh", "-c", script, timeout=30)
    restart = run("docker", "restart", server.name, timeout=120)
    back = server.wait_healthy(BOOT_LIMIT)
    record.note(f"RECOVERY n={n} file_rc={made.returncode} {made.stderr.strip()!r} "
                f"restart_rc={restart.returncode} {restart.stderr.strip()!r} healthy_after_s="
                f"{'none' if back is None else f'{back:.1f}'}")
    return back


class Noise(threading.Thread):
    """Failed logins for NOISE once a second, so the lockout file is being written at the cut."""

    def __init__(self, server):
        super().__init__(daemon=True)
        self.server, self.stopped = server, threading.Event()
        self.tries = self.refused = 0

    def run(self):
        while not self.stopped.is_set():
            self.tries += 1
            self.refused += refused(self.server.kinit(NOISE, test_password(0)))
            self.stopped.wait(1)


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


def set_up(row):
    url, shared = db_url(False)
    server = Server(row, volume(f"{row}-data"), volume(f"{row}-kdc"), url, shared)
    server.create()
    if server.wait_healthy(BOOT_LIMIT if POWER else HEALTH_LIMIT) is None:
        server.keep_logs("start")
        raise RuntimeError("the server did not become healthy")
    lock_password = test_password(0)
    server.create_user(WRITER, test_password(0))
    server.create_user(LOCKED, lock_password)
    queries = [f"addprinc -randkey {SERVICE}",
               f"addpol -maxfailure {MAX_FAIL} -failurecountinterval 0 -lockoutduration 0 {POLICY}",
               f"modprinc -policy {POLICY} {LOCKED}"]
    if POWER:
        server.create_user(NOISE, test_password(0))
        queries += [f"addpol -maxfailure 1000000 -failurecountinterval 0 {NOISE_POLICY}",
                    f"modprinc -policy {NOISE_POLICY} {NOISE}"]
    for query in queries:
        if not server.kadmin(query)[1]:
            raise RuntimeError(f"kadmin {query} failed")
    return server, lock_password


def acc3(record, kills):
    server, lock_password = set_up("acc3")
    n = 0
    for kind in "abc":
        for i in range(kills):
            n += 1
            if not one_kill(record, server, n, kind, i, lock_password):
                raise RuntimeError(f"the server did not come back after kill {n}")


def acc8(record, cuts):
    server, lock_password = set_up("acc8")
    noise = Noise(server)
    noise.start()
    time.sleep(SETTLE)
    try:
        for n in range(1, cuts + 1):
            kind, i = "abc"[(n - 1) % 3], (n - 1) // 3
            if not one_kill(record, server, n, kind, i, lock_password):
                raise RuntimeError(f"the server did not come back after cut {n}")
    finally:
        noise.stopped.set()
        noise.join(timeout=90)
        record.note(f"NOISE user={NOISE} tries={noise.tries} refused={noise.refused} (recorded, not judged)")


def one_kill(record, server, n, kind, i, lock_password):
    head = f"KILL n={n} db={DB} kind={kind}"
    if POWER:
        with open(os.path.join(RUN_DIR, f"pre-cut-{n}.log"), "w", encoding="utf-8") as f:
            f.write(server.logs())
        lock_before, lock_before_at = lockout_state(server), time.perf_counter_ns()
    if kind == "b":
        target, password = WRITER, test_password(n)
        expect = tag(password)
        killer = server.arm_killer()
        acked = killer is not None and server.set_password(WRITER, password)
        read_at, returned = time.perf_counter_ns(), time.time_ns()
    else:
        if kind == "a":
            target, before = SERVICE, server.kvno(SERVICE)
            expect = before + 1 if before is not None else None
            command = ("kadmin", "-k", "-t", "/data/kadm5.keytab", "-p", f"admin/admin@{REALM}",
                       "-q", f"cpw -randkey {SERVICE}")
        else:
            target, count = LOCKED, i % MAX_FAIL + 1
            expect = f"{count},locked={count == MAX_FAIL}"
            # A failure in the same whole second as the last unlock resets the count (MIT's audit).
            time.sleep(2)
            refused_before = all(refused(server.kinit(LOCKED, test_password(n)))
                                 for _ in range(count - 1))
            command = ("sh", "-c", 'printf "%s\\n" "$0" | KRB5CCNAME=/tmp/dur_cc kinit "$1"',
                       test_password(n), LOCKED)
        killer, rc, out = server.client_then_kill(*command)
        read_at, returned = time.perf_counter_ns(), None
        if kind == "a":
            acked = killer is not None and rc == 0 and " while " not in out
        else:
            acked = killer is not None and refused_before and rc != 0 and REFUSED in out
    if not acked:
        if killer is not None:
            release(killer, False)
        if kind == "c":
            server.kadmin(f"modprinc -unlock {LOCKED}")
        record.line(kind, False, f"{head} target={target} the write was not acknowledged")
        return server.healthy()
    if not record.ack({"n": n, "db": DB, "kind": kind, "target": target, "expect": expect}):
        release(killer, False)
        record.abort(f"{head} target={target} the host's ack was not written; no kill")
        return server.healthy()
    ack_ms = (time.perf_counter_ns() - read_at) / 1e6
    timing, finding = "", None
    if POWER:
        destroy_ms = cut_guest()
        cut_at = time.perf_counter_ns()
        gap_ms = (cut_at - read_at) / 1e6
        killer.kill()
        try:
            killer.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        boot_s = boot_guest()
        back, finding = wait_up(server, since)
        timing = f"destroy_ms={destroy_ms:.0f} boot_s={boot_s:.1f} "
        age = (lock_before["now"] - lock_before["birth"] + (cut_at - lock_before_at) / 1e9
               if lock_before and lock_before["exists"] and lock_before["birth"] > 0 else None)
        record.note(f"LOCKOUT n={n} before_cut={lockout_text(lock_before)} age_at_cut_s="
                    f"{'unknown' if age is None else f'{age:.1f}'} after_boot={lockout_text(lockout_state(server))}")
        if back is not None and finding:
            record.degraded += 1
            save_evidence(server, n)
            waited = back
            recovered = recover(record, server, n)
            if recovered is None:
                record.line(kind, False, f"{head} target={target} {timing}FINDING degraded start "
                                         f"({finding!r}) after {waited:.1f} s; the recovery did not bring it back")
                return False
            back = waited + recovered
    else:
        release(killer, True)
        server.wait_exit(EXIT_LIMIT)
        server.start()
        back = server.wait_healthy()
    if back is None:
        if POWER:
            save_evidence(server, n)
        return not_back(record, server, kind, f"{head} target={target} {timing}".rstrip(), n)
    if not POWER:
        client_return, kill_stamp = server.killed_at()
        start_ns = returned if kind == "b" else client_return
        gap_ms = (kill_stamp - start_ns) / 1e6 if kill_stamp and start_ns else None
    if gap_ms is not None:
        record.gaps.setdefault(kind, []).append(gap_ms)
    gap = f"{gap_ms:.1f}" if gap_ms is not None else "unknown"
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
        if POWER:
            # A cut may forget recent counts (no fsync), never mix them: any value it had since the unlock.
            had = int(failures) if failures and failures.isdigit() else None
            ok = had is not None and had <= count and locked == (had >= MAX_FAIL)
            got += f",lost={count - had if had is not None else 'unknown'}"
            if had is not None and had < count:
                record.losses.append(count - had)
        server.kadmin(f"modprinc -unlock {LOCKED}")
    if not ok or finding:
        server.keep_logs(f"kill-{n}")
    found = f"FINDING degraded start ({finding!r}), evidence-{n}/, recovered; " if finding else ""
    record.line(kind, ok and not finding,
                f"{head} target={target} {found}gap_ms={gap} ack_written_ms={ack_ms:.1f} "
                f"{timing}back_s={back:.1f} expect={expect} got={got}")
    if finding and SETTLE:
        time.sleep(SETTLE)
    return True


def not_back(record, server, kind, head, n):
    server.keep_logs(f"kill-{n}")
    record.line(kind, False, f"{head} not healthy after restart")
    return False


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
    if POWER:
        record.note(f"START guest={GUEST} addr={ADDR} docker_host={ENV.get('DOCKER_HOST', '')} "
                    f"lab_lock={ENV.get('DUR_LAB_LOCK', '')} ssh_config={ENV.get('DUR_SSH_CONFIG', '')}")
        record.note(f"START cache: {CACHE_NOTE}")
        record.note(f"START docker root: {ENV.get('DUR_DOCKER_ROOT', 'unknown')} settle_s={SETTLE}")
    error = None
    try:
        if ROW == "acc3":
            acc3(record, int(ENV["DUR_KILLS"]))
        elif POWER:
            acc8(record, int(ENV["DUR_CUTS"]))
        else:
            acc4(record, int(ENV["DUR_TIMES"]))
    except Exception as e:
        error = str(e)
        record.note(f"ABORT {error}")
    gaps = {k: {"min": round(min(v), 1), "median": round(sorted(v)[len(v) // 2], 1),
                "max": round(max(v), 1), "over_target": sum(g > GAP_TARGET_MS for g in v)}
            for k, v in record.gaps.items()}
    for kind, g in sorted(gaps.items()):
        record.note(f"GAPS kind={kind} min={g['min']} median={g['median']} max={g['max']} "
                    f"over_{GAP_TARGET_MS}ms={g['over_target']}")
    summary = {"row": ROW, "db": DB, "image": IMAGE, "image_id": ENV.get("DUR_IMAGE_ID", ""),
               "driver": ENV.get("DUR_REV", ""), "seconds": round(time.time() - started),
               "counts": {k: {"pass": p, "fail": f} for k, (p, f) in record.counts.items()},
               "gaps_ms": gaps, "aborted_iterations": record.aborted, "aborted": error,
               "lockout_lost_cuts": len(record.losses), "lockout_lost_sum": sum(record.losses),
               "degraded_starts": record.degraded, "findings": record.degraded}
    with open(os.path.join(RUN_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    failed = sum(f for _, f in record.counts.values())
    power = (f" lockout_lost_cuts={len(record.losses)} lockout_lost_sum={sum(record.losses)} "
             f"degraded_starts={record.degraded} findings={record.degraded}") if POWER else ""
    record.note(f"END failed={failed} aborted={error is not None} aborted_iterations={record.aborted} "
                f"seconds={summary['seconds']}{power}")
    return 0 if failed == 0 and error is None and record.aborted == 0 and record.counts else 1


if __name__ == "__main__":
    sys.exit(main())
