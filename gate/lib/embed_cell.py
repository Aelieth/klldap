"""Paced load for gate/embed-cell.sh: kinit, ldappasswd writes and LDAP/GraphQL probes
against one container, each request timed from its scheduled tick."""

import argparse
import csv
import itertools
import json
import math
import os
import platform
import subprocess
import sys
import threading
import time
import urllib.request

# rate stays None until the saturation run's ceiling R sets it (0.6 x R).
FROZEN = {
    "users": 200,
    "window": 300.0,
    "idle": 90.0,
    "burst": 120.0,
    "rate": None,
    "writers": 4,
    "verify_every": 10,
    "kinit_interval": 0.1,
    "ldap_interval": 1.0,
    "http_interval": 0.2,
    "kdc_port": 18888,
}
SATURATION_RATE = 25.0
MIN_RATE_SHARE = 0.95
CALL_TIMEOUT = 15
MAX_BACKLOG = 60.0
SKIPPED = "skipped"
IDLE_USER = "cellidle"


def parse_knobs(argv):
    parser = argparse.ArgumentParser(prog="gate/embed-cell.sh")
    parser.add_argument("--image", default="klldap-test", help="default: %(default)s")
    for name, default in FROZEN.items():
        parser.add_argument(
            "--" + name.replace("_", "-"), type=float if default is None else type(default),
            default=default,
            help="frozen: none yet" if default is None else "frozen: %(default)s",
        )
    parser.add_argument("--saturation", action="store_true",
                        help=f"write at {SATURATION_RATE:g}/s to measure the ceiling R")
    parser.add_argument("--dry-run", action="store_true", help="mark the run as not a baseline")
    knobs = parser.parse_args(argv)
    if knobs.saturation:
        if knobs.rate not in (None, SATURATION_RATE):
            parser.error(f"--saturation writes at {SATURATION_RATE:g}/s; drop --rate")
        knobs.rate = SATURATION_RATE
    elif knobs.rate is None:
        parser.error("--rate has no frozen value until the saturation run sets it; "
                     "pass --rate or --saturation")
    if knobs.idle + knobs.burst > knobs.window:
        parser.error("--idle plus --burst must fit in --window")
    if knobs.users < 2 * knobs.writers:
        parser.error("--users must be at least twice --writers")
    return knobs


def config(run_dir, argv):
    knobs = parse_knobs(argv)
    deviations = {
        name: getattr(knobs, name)
        for name, default in FROZEN.items()
        if default is not None and getattr(knobs, name) != default
    }
    reasons = []
    if knobs.dry_run:
        reasons.append("dry run: its numbers are not quoted anywhere")
    if knobs.saturation:
        reasons.append("saturation run: it measures the ceiling R")
    elif FROZEN["rate"] is None:
        reasons.append("--rate is not calibrated yet")
    elif knobs.rate != FROZEN["rate"]:
        deviations["rate"] = knobs.rate
    if deviations:
        reasons.append(f"knobs differ from the frozen table: {deviations}")
    meta = {
        "knobs": vars(knobs),
        "frozen": FROZEN,
        "deviations": deviations,
        "dry_run": knobs.dry_run,
        "saturation": knobs.saturation,
        "baseline": not reasons,
        "not_baseline_because": reasons,
    }
    write_json(os.path.join(run_dir, "meta.json"), meta)
    print(knobs.image, knobs.users, knobs.kdc_port)


def write_json(path, value):
    with open(path, "w") as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")


def cell_users(count):
    return [f"cell{i:04d}" for i in range(1, count + 1)]


def password(user, tick):
    return f"Cell-{user}-{tick}!"


class Clients:
    def __init__(self, run_dir, env, kdc_port):
        self.base_dn = env["BASE_DN"]
        self.realm = env["REALM"]
        self.admin_pass = env["ADMIN_PASS"]
        self.token = env["TOKEN"]
        self.ldap_url = f"ldap://127.0.0.1:{env['LDAP_PORT']}"
        self.graphql_url = f"http://127.0.0.1:{env['HTTP_PORT']}/api/graphql"
        self.admin_dn = f"uid=admin,ou=people,{self.base_dn}"
        self.run_dir = run_dir
        krb5_conf = os.path.join(run_dir, "krb5.conf")
        with open(krb5_conf, "w") as out:
            out.write(
                "[libdefaults]\n"
                f"    default_realm = {self.realm}\n"
                "    dns_lookup_kdc = false\n"
                "    dns_lookup_realm = false\n"
                "    rdns = false\n"
                "[realms]\n"
                f"    {self.realm} = {{\n"
                f"        kdc = 127.0.0.1:{kdc_port}\n"
                "    }\n"
            )
        self.krb5_env = dict(os.environ, KRB5_CONFIG=krb5_conf)

    def run(self, argv, stdin=None, env=None):
        try:
            done = subprocess.run(
                argv, input=stdin, env=env, capture_output=True, text=True,
                timeout=CALL_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return False, f"timeout after {CALL_TIMEOUT}s"
        if done.returncode == 0:
            return True, ""
        return False, (done.stderr or done.stdout).strip().replace("\n", " ")[-300:]

    def kinit(self, user, secret, cache):
        env = dict(self.krb5_env, KRB5CCNAME="FILE:" + os.path.join(self.run_dir, cache))
        return self.run(["kinit", f"{user}@{self.realm}"], stdin=secret + "\n", env=env)

    def ldappasswd(self, user, secret):
        return self.run([
            "ldappasswd", "-x", "-H", self.ldap_url, "-D", self.admin_dn,
            "-w", self.admin_pass, "-s", secret, f"uid={user},ou=people,{self.base_dn}",
        ])

    def ldapsearch(self):
        return self.run([
            "ldapsearch", "-x", "-LLL", "-H", self.ldap_url, "-D", self.admin_dn,
            "-w", self.admin_pass, "-b", f"ou=people,{self.base_dn}",
            f"(uid={IDLE_USER})", "uid",
        ])

    def graphql(self, query, variables=None):
        request = urllib.request.Request(
            self.graphql_url,
            data=json.dumps({"query": query, "variables": variables or {}}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.token},
        )
        try:
            with urllib.request.urlopen(request, timeout=CALL_TIMEOUT) as response:
                body = json.load(response)
        except (OSError, ValueError) as error:
            return False, str(error)[-300:]
        if body.get("errors"):
            return False, json.dumps(body["errors"])[-300:]
        return True, ""


class Recorder:
    def __init__(self, t0, knobs):
        self.t0 = t0
        self.knobs = knobs
        self.rows = []
        self.lock = threading.Lock()

    def phase(self, due):
        offset = due - self.t0
        if offset < self.knobs.idle:
            return "idle"
        if offset < self.knobs.idle + self.knobs.burst:
            return "burst"
        return "recovery"

    def add(self, loop, op, tick, due, start, end, ok, detail):
        row = {
            "loop": loop, "op": op, "tick": tick, "phase": self.phase(due),
            "due_s": round(due - self.t0, 4), "start_s": round(start - self.t0, 4),
            "end_s": round(end - self.t0, 4), "call_ms": round((end - start) * 1000, 3),
            "graded_ms": round((end - due) * 1000, 3), "ok": int(ok), "detail": detail,
        }
        with self.lock:
            self.rows.append(row)


def sleep_until(moment):
    delay = moment - time.monotonic()
    if delay > 0:
        time.sleep(delay)


def timed(recorder, loop, op, tick, due, call):
    """A due of None is an unscheduled request, graded from its own start."""
    start = time.monotonic()
    ok, detail = call()
    end = time.monotonic()
    recorder.add(loop, op, tick, start if due is None else due, start, end, ok, detail)
    return ok, end


def behind(recorder, loop, tick, due):
    if time.monotonic() - due <= MAX_BACKLOG:
        return False
    recorder.add(loop, SKIPPED, tick, due, due, due, False,
                 f"more than {MAX_BACKLOG:.0f}s behind schedule")
    return True


def paced(recorder, loop, interval, stop_at, step):
    """One request in flight; a late tick starts at once, so lateness reaches the graded
    figure. Only a tick past MAX_BACKLOG is skipped, and it is counted as skipped."""
    for tick in itertools.count():
        due = recorder.t0 + tick * interval
        if due >= stop_at:
            return
        if behind(recorder, loop, tick, due):
            continue
        sleep_until(due)
        step(tick, due)


def writes(recorder, clients, knobs, users, verify_every):
    """At --rate, ticks are scheduled and each goes to a free writer. With --saturation
    every writer writes back to back until the burst ends."""
    first = recorder.t0 + knobs.idle
    end = first + knobs.burst
    ticks = int(knobs.burst * knobs.rate)
    counter = itertools.count()
    lock = threading.Lock()
    last = {}

    def next_write():
        with lock:
            tick = next(counter)
        if knobs.saturation:
            return (tick, None) if time.monotonic() < end else (None, None)
        return (tick, first + tick / knobs.rate) if tick < ticks else (None, None)

    def worker(slot):
        sleep_until(first)
        while True:
            tick, due = next_write()
            if tick is None:
                return
            if due is not None:
                if behind(recorder, "B", tick, due):
                    continue
                sleep_until(due)
            user = users[tick % len(users)]
            secret = password(user, tick + 1)
            ok, wrote_at = timed(recorder, "B", "ldappasswd", tick, due,
                                 lambda: clients.ldappasswd(user, secret))
            if not ok:
                continue
            verify = tick % verify_every == verify_every - 1
            with lock:
                if wrote_at > last.get("at", 0):
                    last.update(tick=tick, user=user, secret=secret, at=wrote_at,
                                verified=verify)
            if verify:
                timed(recorder, "V", "kinit", tick, wrote_at,
                      lambda: clients.kinit(user, secret, f"ccache-v{slot}"))

    pool = [threading.Thread(target=worker, args=(slot,)) for slot in range(knobs.writers)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    if last and not last["verified"]:
        timed(recorder, "V", "kinit", last["tick"], None,
              lambda: clients.kinit(last["user"], last["secret"], "ccache-vlast"))


def parse_bytes(text):
    units = {"B": 1, "KiB": 2**10, "MiB": 2**20, "GiB": 2**30, "kB": 10**3, "MB": 10**6,
             "GB": 10**9}
    value = text.strip()
    for unit in sorted(units, key=len, reverse=True):
        if value.endswith(unit):
            return float(value[: -len(unit)]) * units[unit]
    return float("nan")


def sample(container, t0, stop, samples):
    last_health = None
    while not stop.is_set():
        at = time.monotonic() - t0
        health = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", container],
            capture_output=True, text=True,
        ).stdout.strip()
        stats = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}", container],
            capture_output=True, text=True,
        ).stdout.strip()
        try:
            parsed = json.loads(stats)
            cpu = float(parsed["CPUPerc"].rstrip("%"))
            rss = parse_bytes(parsed["MemUsage"].split("/")[0])
        except (ValueError, KeyError):
            cpu = rss = float("nan")
        samples.append({"t_s": round(at, 3), "cpu_pct": cpu, "rss_bytes": rss,
                        "health": health, "health_changed": int(health != last_health)})
        last_health = health
        stop.wait(1.0)


def seed(clients, users, writers):
    created, failures = 0, []
    for user in [IDLE_USER, *users]:
        ok, detail = clients.graphql(
            "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
            {"u": {"id": user, "email": f"{user}@gate.test",
                   "attributes": [{"name": "kerberossync", "value": ["1"]}]}},
        )
        created += ok
        if not ok:
            failures.append(f"createUser {user}: {detail}")
    queue = iter([IDLE_USER, *users])
    lock = threading.Lock()

    def worker():
        while True:
            with lock:
                user = next(queue, None)
            if user is None:
                return
            ok, detail = clients.ldappasswd(user, password(user, 0))
            if not ok:
                with lock:
                    failures.append(f"ldappasswd {user}: {detail}")

    pool = [threading.Thread(target=worker) for _ in range(writers)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    ok, detail = clients.kinit(IDLE_USER, password(IDLE_USER, 0), "ccache-seed")
    if not ok:
        failures.append(f"first kinit {IDLE_USER}: {detail}")
    return created, failures


def percentile(values, share):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(share * len(ordered)) - 1)] if ordered else None


def summarize(rows, samples, knobs, meta):
    skips = [r for r in rows if r["op"] == SKIPPED]
    rows = [r for r in rows if r["op"] != SKIPPED]
    groups = {}
    for row in rows:
        groups.setdefault((row["loop"], row["op"], row["phase"]), []).append(row)
    figures = []
    for (loop, op, phase), members in sorted(groups.items()):
        good = [r for r in members if r["ok"]]
        figures.append({
            "loop": loop, "op": op, "phase": phase, "requests": len(members),
            "errors": len(members) - len(good),
            "graded_p50_ms": percentile([r["graded_ms"] for r in good], 0.50),
            "graded_p99_ms": percentile([r["graded_ms"] for r in good], 0.99),
            "call_p50_ms": percentile([r["call_ms"] for r in good], 0.50),
            "call_p99_ms": percentile([r["call_ms"] for r in good], 0.99),
        })
    written = [r for r in rows if r["loop"] == "B" and r["ok"]]
    if knobs.saturation:
        achieved = len(written) / knobs.burst
    else:
        span = max((r["end_s"] for r in written), default=knobs.idle) - knobs.idle
        achieved = len(written) / span if span > 0 else 0.0
    reasons = list(meta["not_baseline_because"])
    if not knobs.saturation and achieved < MIN_RATE_SHARE * knobs.rate:
        reasons.append(f"B reached {achieved:.2f}/s, under {MIN_RATE_SHARE:.0%} of {knobs.rate}/s")
    skipped = {}
    for row in skips:
        skipped[row["loop"]] = skipped.get(row["loop"], 0) + 1
    if skipped:
        reasons.append(f"ticks skipped more than {MAX_BACKLOG:.0f}s behind schedule: {skipped}")
    resources = {}
    for phase in ("idle", "burst", "recovery"):
        offsets = {"idle": (0, knobs.idle), "burst": (knobs.idle, knobs.idle + knobs.burst),
                   "recovery": (knobs.idle + knobs.burst, knobs.window)}[phase]
        inside = [s for s in samples if offsets[0] <= s["t_s"] < offsets[1]
                  and not math.isnan(s["cpu_pct"])]
        resources[phase] = {
            "samples": len(inside),
            "cpu_pct_mean": round(sum(s["cpu_pct"] for s in inside) / len(inside), 2)
            if inside else None,
            "cpu_pct_max": max((s["cpu_pct"] for s in inside), default=None),
            "rss_bytes_max": max((s["rss_bytes"] for s in inside), default=None),
        }
    return {
        "figures": figures,
        "errors": sum(1 for r in rows if not r["ok"]),
        "skipped": skipped,
        "b_target_rate": knobs.rate,
        "b_achieved_rate": round(achieved, 3),
        "ceiling_rate_r": round(achieved, 3) if knobs.saturation else None,
        "overrun_s": round(max((r["end_s"] for r in rows), default=0) - knobs.window, 3),
        "health": [{"t_s": s["t_s"], "health": s["health"]} for s in samples
                   if s["health_changed"]],
        "resources": resources,
        "baseline": not reasons,
        "not_baseline_because": reasons,
        "method": "graded = completion minus scheduled tick; call = the request alone; "
                  "nearest-rank percentiles over successful requests; client process start "
                  "is inside A, B, V and the ldapsearch probe; each ldapsearch is a fresh "
                  "admin bind",
    }


def render(summary):
    lines = [f"{'loop':4} {'op':10} {'phase':8} {'n':>6} {'err':>4} "
             f"{'graded p50':>11} {'graded p99':>11} {'call p50':>9} {'call p99':>9}"]
    for f in summary["figures"]:
        cells = [f[k] for k in ("graded_p50_ms", "graded_p99_ms", "call_p50_ms", "call_p99_ms")]
        shown = ["-" if c is None else f"{c:.1f}" for c in cells]
        lines.append(f"{f['loop']:4} {f['op']:10} {f['phase']:8} {f['requests']:>6} "
                     f"{f['errors']:>4} {shown[0]:>11} {shown[1]:>11} {shown[2]:>9} "
                     f"{shown[3]:>9}")
    lines.append(f"B rate: {summary['b_achieved_rate']}/s of {summary['b_target_rate']}/s; "
                 f"errors: {summary['errors']}; skipped: {summary['skipped'] or 0}; "
                 f"overrun: {summary['overrun_s']}s")
    if summary["ceiling_rate_r"] is not None:
        lines.append(f"saturation: ceiling R = {summary['ceiling_rate_r']}/s")
    lines.append("baseline: " + ("yes" if summary["baseline"]
                                 else "no (" + "; ".join(summary["not_baseline_because"]) + ")"))
    return "\n".join(lines) + "\n"


def run(run_dir):
    meta_path = os.path.join(run_dir, "meta.json")
    with open(meta_path) as source:
        meta = json.load(source)
    knobs = argparse.Namespace(**meta["knobs"])
    env = os.environ
    meta.update({
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "image_id": env.get("IMAGE_ID", ""),
        "driver_rev": env.get("DRIVER_REV", ""),
        "clients": env.get("CLIENTS", ""),
        "host": {"name": platform.node(), "cpus": os.cpu_count()},
    })
    clients = Clients(run_dir, env, knobs.kdc_port)
    users = cell_users(knobs.users)
    seed_start = time.monotonic()
    created, failures = seed(clients, users, knobs.writers)
    meta["seed"] = {"created": created, "seconds": round(time.monotonic() - seed_start, 1),
                    "failures": failures}
    write_json(meta_path, meta)
    if failures:
        print("seeding failed: " + "; ".join(failures[:5]), file=sys.stderr)
        return 1

    t0 = time.monotonic() + 1.0
    recorder = Recorder(t0, knobs)
    stop_at = t0 + knobs.window
    samples, stop = [], threading.Event()

    def kinit_step(tick, due):
        timed(recorder, "A", "kinit", tick, due,
              lambda: clients.kinit(IDLE_USER, password(IDLE_USER, 0), "ccache-a"))

    def ldap_step(tick, due):
        timed(recorder, "C", "ldapsearch", tick, due, clients.ldapsearch)

    def http_step(tick, due):
        timed(recorder, "C", "graphql", tick, due, lambda: clients.graphql("{ users { id } }"))

    loops = [
        threading.Thread(target=paced, args=(recorder, "A", knobs.kinit_interval, stop_at,
                                             kinit_step)),
        threading.Thread(target=paced, args=(recorder, "C", knobs.ldap_interval, stop_at,
                                             ldap_step)),
        threading.Thread(target=paced, args=(recorder, "C", knobs.http_interval, stop_at,
                                             http_step)),
        threading.Thread(target=writes, args=(recorder, clients, knobs, users,
                                              knobs.verify_every)),
    ]
    sampler = threading.Thread(target=sample, args=(env["CONTAINER"], t0, stop, samples))
    sampler.start()
    for loop in loops:
        loop.start()
    for loop in loops:
        loop.join()
    stop.set()
    sampler.join()

    rows = sorted(recorder.rows, key=lambda r: (r["due_s"], r["loop"], r["op"]))
    for name, table in (("requests.csv", rows), ("resources.csv", samples)):
        with open(os.path.join(run_dir, name), "w", newline="") as out:
            if table:
                writer = csv.DictWriter(out, fieldnames=list(table[0]))
                writer.writeheader()
                writer.writerows(table)
    summary = summarize(rows, samples, knobs, meta)
    write_json(os.path.join(run_dir, "summary.json"), summary)
    text = render(summary)
    with open(os.path.join(run_dir, "summary.txt"), "w") as out:
        out.write(text)
    sys.stdout.write(text)
    return 1 if summary["errors"] else 0


def main(argv):
    if len(argv) >= 2 and argv[0] == "config":
        config(argv[1], argv[2:])
        return 0
    if len(argv) == 2 and argv[0] == "run":
        return run(argv[1])
    print("usage: embed_cell.py config <run-dir> [knobs...] | run <run-dir>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
