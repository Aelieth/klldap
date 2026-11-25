"""Helpers of the gate's low-spec phase (74): the HTTP flood, the limits read-back and one kind's report.

  lowspec.py flood  --kind K --base URL --user NAME --seconds S --senders N [--count C]
  lowspec.py limits --memory BYTES --cpus N --cpuset LIST        (the cgroup text on stdin)
  lowspec.py mark   --db FILE                                    (the newest log row's id)
  lowspec.py report --kind K --flood F --probe F --mem F --db F --mark ID --legit NAME ...

Standard library only. A flood sends requests of one kind as fast as its senders allow and prints
how many it sent and how many answers of each status it got."""

import argparse
import collections
import http.client
import json
import re
import sqlite3
import statistics
import sys
import threading
import time
import urllib.parse

# ristretto255's base point: a valid element, so a start is read as one.
POINT = list(bytes.fromhex("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"))
FLOOD_KINDS = ("bind_flood", "access_denied_flood", "sign_in_flood")
HTTP_KINDS = ("simple", "web-start", "web-finish", "refresh", "reset")
JSON = {"Content-Type": "application/json"}


def post(path, body):
    return ("POST", path, JSON, json.dumps(body).encode())


def start_request(name):
    message = {"blinded_element": POINT, "ke1_message": {"client_nonce": [7] * 32, "client_e_pk": POINT}}
    return post("/auth/opaque/login/start", {"username": name, "login_start_request": message})


def build_request(kind, user, sender, n, state=None):
    """Request number n of one sender: (method, path, headers, body)."""
    if kind == "simple":
        return post("/auth/simple/login", {"username": user, "password": "wrong-%d-%d" % (sender, n)})
    if kind == "web-start":
        return start_request(user)
    if kind == "web-finish":
        junk = {"ke3_message": {"mac": [(sender + n) % 256] * 64}}
        return post("/auth/opaque/login/finish", {"server_data": state, "credential_finalization": junk})
    if kind == "refresh":
        return ("GET", "/auth/refresh", {"refresh-token": "junk-%d-%d+%s" % (sender, n, user)}, None)
    if kind == "reset":
        return ("POST", "/auth/reset/step1/%s-%d-%d" % (user, sender, n), {}, b"")
    raise ValueError("unknown kind " + kind)


def exchange(conn, method, path, headers, body):
    conn.request(method, path, body=body, headers=headers)
    answer = conn.getresponse()
    return answer.status, answer.read()


def send(args, host, port, sender, deadline, tally):
    conn, state, n = None, None, 0
    while time.monotonic() < deadline and (args.count == 0 or n < args.count):
        n += 1
        try:
            if conn is None:
                conn = http.client.HTTPConnection(host, port, timeout=args.timeout)
            if args.kind == "web-finish" and state is None:
                # One start per sender, for a name with no user; its sealed state is sent each time.
                status, text = exchange(conn, *start_request("%s-%d" % (args.user, sender)))
                if status != 200:
                    tally["start-%d" % status] += 1
                    time.sleep(0.2)
                    continue
                state = json.loads(text)["server_data"]
            status, _ = exchange(conn, *build_request(args.kind, args.user, sender, n, state))
            tally[str(status)] += 1
        except (OSError, http.client.HTTPException, ValueError, KeyError):
            tally["error"] += 1
            if conn is not None:
                conn.close()
            conn = None
            time.sleep(0.05)
    if conn is not None:
        conn.close()


def flood_line(tallies, seconds, senders):
    total = collections.Counter()
    for tally in tallies:
        total.update(tally)
    answers = ",".join("%s:%d" % item for item in sorted(total.items())) or "none"
    return "sent=%d seconds=%.1f senders=%d answers=%s" % (sum(total.values()), seconds, senders, answers)


def flood(args):
    url = urllib.parse.urlsplit(args.base)
    began = time.monotonic()
    tallies = [collections.Counter() for _ in range(args.senders)]
    threads = [
        threading.Thread(target=send, args=(args, url.hostname, url.port, i, began + args.seconds, tallies[i]), daemon=True)
        for i in range(args.senders)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0.0, began + args.seconds + 2 * args.timeout + 5 - time.monotonic()))
    print(flood_line(tallies, time.monotonic() - began, args.senders))


def parse_cgroup(text):
    """Lines of "<key> <value>" (the phase's reader, memory.stat, memory.events) as a dict."""
    seen = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        if key and key not in seen:
            seen[key] = value.strip()
    return seen


def check_limits(seen, memory, cpus, cpuset):
    """(held, text): whether the container's own cgroup shows the limits that were asked for."""
    wrong = []
    if seen.get("memory.max") != str(memory):
        wrong.append("memory.max is '%s', want %d" % (seen.get("memory.max", "unread"), memory))
    quota = seen.get("cpu.max", "unread").split()
    if len(quota) != 2 or not quota[0].isdigit() or not quota[1].isdigit() or int(quota[0]) != cpus * int(quota[1]):
        wrong.append("cpu.max is '%s', want %d CPU" % (seen.get("cpu.max", "unread"), cpus))
    if seen.get("cpuset.cpus.effective") != cpuset:
        wrong.append("cpuset.cpus.effective is '%s', want %s" % (seen.get("cpuset.cpus.effective", "unread"), cpuset))
    swap = seen.get("memory.swap.max", "unread")
    if swap not in ("0", "unread"):
        wrong.append("memory.swap.max is '%s', want 0" % swap)
    if wrong:
        return False, "; ".join(wrong)
    return True, "memory.max=%d cpu.max=%s cpuset.cpus.effective=%s memory.swap.max=%s" % (
        memory, "/".join(quota), cpuset, swap)


def limits(args):
    held, text = check_limits(parse_cgroup(sys.stdin.read()), args.memory, args.cpus, args.cpuset)
    print(("ok " if held else "no ") + text)


def open_db(path):
    return sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(path), uri=True)


def newest_id(path):
    con = open_db(path)
    try:
        return con.execute("SELECT COALESCE(MAX(id), 0) FROM logs").fetchone()[0]
    finally:
        con.close()


def read_rows(path, mark, legit):
    """The log rows after the mark, split: one-to-one, flood, log_gap, and the phase's own binds."""
    con = open_db(path)
    try:
        newest = con.execute("SELECT COALESCE(MAX(id), 0) FROM logs").fetchone()[0]
        rows = con.execute("SELECT kind, success, actor, detail FROM logs WHERE id > ?", (mark,)).fetchall()
    finally:
        con.close()
    out = {"written": newest - mark, "one": 0, "flood": 0, "gap": 0, "dropped": 0, "own": 0}
    kinds = collections.Counter()
    for kind, success, actor, detail in rows:
        if kind in FLOOD_KINDS:
            out["flood"] += 1
        elif kind == "log_gap":
            out["gap"] += 1
            found = re.search(r"dropped events: (\d+)", detail or "")
            out["dropped"] += int(found.group(1)) if found else 0
        elif success and (actor or "").lower() == legit.lower():
            out["own"] += 1
        else:
            out["one"] += 1
            kinds[kind] += 1
    out["pruned"] = max(0, out["written"] - len(rows))
    out["kinds"] = ",".join("%s:%d" % item for item in kinds.most_common(6)) or "none"
    return out


def read_probe(text):
    """Lines of "<exit code> <milliseconds>", one per ordinary bind: 0 bound, 51 busy, 124 not
    answered within the phase's wait (its time still counts toward the worst), else failed."""
    times, late, busy, failed = [], [], 0, 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        if parts[0] == "0":
            times.append(int(parts[1]))
        elif parts[0] == "124":
            late.append(int(parts[1]))
        elif parts[0] == "51":
            busy += 1
        else:
            failed += 1
    out = {"n": len(times) + len(late) + busy + failed, "ok": len(times), "late": len(late), "busy": busy, "failed": failed}
    out["median"] = int(statistics.median(times)) if times else None
    out["worst"] = max(times + late) if times or late else None
    return out


def read_mem(text):
    """Samples of the phase's reader, each after a "== <before|during|after> <time>" line."""
    samples = []
    for block in text.split("== ")[1:]:
        head, _, body = block.partition("\n")
        seen = parse_cgroup(body)
        sample = {"tag": head.split()[0] if head.split() else ""}
        for name, key in (("anon", "anon"), ("current", "memory.current"), ("peak", "memory.peak"), ("oom", "oom_kill")):
            sample[name] = int(seen[key]) if seen.get(key, "").isdigit() else None
        samples.append(sample)

    def first(tag, name):
        return next((s[name] for s in samples if s["tag"] == tag and s[name] is not None), None)

    def last(name):
        return next((s[name] for s in reversed(samples) if s[name] is not None), None)

    def highest(name):
        return max((s[name] for s in samples if s[name] is not None), default=None)

    out = {"before": first("before", "anon"), "after": first("after", "anon"), "peak": highest("anon")}
    out["samples"] = sum(1 for s in samples if s["anon"] is not None)
    # The last sample that could be read: a server that is gone gives none after its flood.
    out["high"], out["high_source"] = last("peak"), "memory.peak"
    if out["high"] is None:
        out["high"], out["high_source"] = highest("current"), "sampled-memory.current"
    oom_before, oom_last = first("before", "oom"), last("oom")
    out["oom"] = None if oom_before is None or oom_last is None else oom_last - oom_before
    return out


def megabytes(value):
    return "unread" if value is None else "%.1f" % (value / 1048576)


def shown(value):
    return "unread" if value is None else str(value)


def verdict(value, limit):
    if value is None:
        return "unread"
    if limit == "":
        return "measured"
    return "pass" if value <= float(limit) else "fail"


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def report(args):
    sent = dict(part.split("=", 1) for part in read_text(args.flood).split() if "=" in part)
    rows, rows_why = None, "the log's newest id could not be read before the flood (a copy of users.db)"
    if args.mark.isdigit():
        try:
            rows = read_rows(args.db, int(args.mark), args.legit)
        except sqlite3.Error as e:
            rows_why = "the log could not be read after the flood (a copy of users.db): %s" % e
    probe = read_probe(read_text(args.probe))
    mem = read_mem(read_text(args.mem))
    growth = None if mem["before"] is None or mem["after"] is None else mem["after"] - mem["before"]

    pairs = [("kind", args.kind), ("seconds", args.seconds), ("senders", args.senders),
             ("sent", sent.get("sent", "unread")), ("answers", sent.get("answers", "unread"))]
    for key, name in (("written", "rows_written"), ("one", "rows_one_to_one"), ("flood", "rows_flood"),
                      ("gap", "rows_log_gap"), ("dropped", "log_gap_dropped"), ("own", "rows_own_binds"),
                      ("pruned", "rows_pruned"), ("kinds", "one_to_one_kinds")):
        pairs.append((name, "unread" if rows is None else rows[key]))
    pairs += [("mem_source", "cgroup-v2:memory.stat:anon"), ("mem_samples", mem["samples"]),
              ("mem_before_mb", megabytes(mem["before"])), ("mem_peak_mb", megabytes(mem["peak"])),
              ("mem_after_mb", megabytes(mem["after"])), ("mem_growth_mb", megabytes(growth)),
              ("container_high_mb", megabytes(mem["high"])), ("container_high_source", mem["high_source"]),
              ("oom_kills", shown(mem["oom"])),
              ("bind_n", probe["n"]), ("bind_ok", probe["ok"]), ("bind_late", probe["late"]),
              ("bind_busy", probe["busy"]), ("bind_failed", probe["failed"]), ("bind_median_ms", shown(probe["median"])),
              ("bind_worst_ms", shown(probe["worst"])), ("alive", args.alive)]
    print("LOWSPEC " + " ".join("%s=%s" % pair for pair in pairs))

    print("HUMAN %s requests in %s s by %s senders, answers %s" % (
        sent.get("sent", "unread"), args.seconds, args.senders, sent.get("answers", "unread")))

    if rows is None:
        print("ROWS unread " + rows_why)
    else:
        text = "%d one-to-one log rows (%s), %d flood rows, %d log_gap rows with %d dropped events" % (
            rows["one"], rows["kinds"], rows["flood"], rows["gap"], rows["dropped"])
        text += "; %d ids given, %d rows are this phase's own binds, %d already pruned" % (
            rows["written"], rows["own"], rows["pruned"])
        state = verdict(rows["one"], args.max_rows)
        if state in ("pass", "fail"):
            text += "; at most %s one-to-one rows allowed" % args.max_rows
        print("ROWS %s %s" % (state, text))

    if growth is None:
        print("MEM unread the server's memory.stat gave no anon figure before or after the flood (%d samples)" % mem["samples"])
    else:
        text = "memory %s MB before, %s MB at the highest of %d samples, %s MB after the settle: grown %s MB" % (
            megabytes(mem["before"]), megabytes(mem["peak"]), mem["samples"], megabytes(mem["after"]), megabytes(growth))
        text += " (anon of the container's memory.stat; the container's high-water mark is %s MB, from %s)" % (
            megabytes(mem["high"]), mem["high_source"])
        state = verdict(growth / 1048576, args.max_mem_mb)
        if state in ("pass", "fail"):
            text += "; at most %s MB of growth allowed" % args.max_mem_mb
        print("MEM %s %s" % (state, text))

    if probe["n"] == 0:
        print("BIND unread no ordinary bind was timed during the flood")
    else:
        text = "%d ordinary binds during the flood: %d bound (median %s ms), %d not answered within %s s, worst %s ms" % (
            probe["n"], probe["ok"], shown(probe["median"]), probe["late"], args.bind_wait, shown(probe["worst"]))
        text += "; %d answered busy, %d failed" % (probe["busy"], probe["failed"])
        state = "measured"
        if args.max_bind_ms != "":
            held = probe["failed"] == 0 and probe["late"] == 0
            held = held and probe["worst"] is not None and probe["worst"] <= float(args.max_bind_ms)
            state = "pass" if held else "fail"
            text += "; none may fail or go unanswered and the worst may take at most %s ms" % args.max_bind_ms
        print("BIND %s %s" % (state, text))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("flood")
    p.add_argument("--kind", required=True, choices=HTTP_KINDS)
    p.add_argument("--base", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--seconds", type=float, required=True)
    p.add_argument("--senders", type=int, required=True)
    p.add_argument("--count", type=int, default=0)
    p.add_argument("--timeout", type=float, default=10.0)
    p = sub.add_parser("limits")
    p.add_argument("--memory", type=int, required=True)
    p.add_argument("--cpus", type=int, required=True)
    p.add_argument("--cpuset", required=True)
    p = sub.add_parser("mark")
    p.add_argument("--db", required=True)
    p = sub.add_parser("report")
    for name in ("kind", "seconds", "senders", "flood", "probe", "mem", "db", "mark", "legit", "alive", "bind-wait"):
        p.add_argument("--" + name, required=True)
    for name in ("max-rows", "max-mem-mb", "max-bind-ms"):
        p.add_argument("--" + name, default="")
    args = parser.parse_args()
    if args.command == "flood":
        flood(args)
    elif args.command == "limits":
        limits(args)
    elif args.command == "mark":
        print(newest_id(args.db))
    else:
        report(args)


if __name__ == "__main__":
    main()
