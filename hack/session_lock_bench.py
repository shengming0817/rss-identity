#!/usr/bin/env python3
"""Run a compiled session_lock_bench release test on pinned PG and output timing evidence.

Each record covers one warmed group. PostgreSQL logs waits of at least 1 ms.
Lock retention is measured from completion of the first observed Identity lock
statement until COMMIT on the same backend. Issuance uses several transactions.
"""
import argparse
import bisect
import json
import os
import re
import subprocess
import time
from pathlib import Path
from providers import PG, container

PREFIX = re.compile(r"^(\d+\.\d+)\|(\d+)\|([^|]*)\|\s*LOG:\s+(.*)")
ACQUIRED = re.compile(r"process \d+ acquired .* after ([\d.]+) ms")
FINISHED = re.compile(r"duration: [\d.]+ ms\s+(?:execute [^:]+|statement):\s*(.*)", re.I)
LOCK = re.compile(r"SELECT (?:identity_authority\.lock_session\(|tenant_id FROM identity_authority\.(?:guard|tenants) WHERE.* FOR (?:KEY SHARE|SHARE|UPDATE|NO KEY UPDATE))", re.I)


def summarize(lines, rows):
    starts = [r["begin_us"] for r in rows]
    held = {}
    for line in lines:
        found = PREFIX.match(line)
        if not found:
            continue
        instant, pid, db, msg = found.groups()
        now = round(float(instant) * 1_000_000)
        index = bisect.bisect_right(starts, now) - 1
        if index < 0 or now > rows[index]["end_us"] or db != rows[index]["db"]:
            held.pop(pid, None)
            continue
        row = rows[index]
        wait = ACQUIRED.match(msg)
        if wait:
            row["observed_wait_us"].append(round(float(wait[1]) * 1000))
            continue
        completed = FINISHED.match(msg)
        if not completed:
            continue
        query = completed[1].strip().upper()
        if query.startswith("BEGIN"):
            held.pop(pid, None)
        elif LOCK.match(query):
            held.setdefault(pid, (index, now))
        elif query.startswith(("COMMIT", "ROLLBACK")):
            moment = held.pop(pid, None)
            if moment and moment[0] == index and query.startswith("COMMIT"):
                row["lock_to_commit_us"].append(now - moment[1])
    for row in rows:
        for key in ("observed_wait_us", "lock_to_commit_us"):
            values = sorted(row.pop(key))
            row[key + "_count"] = len(values)
            row[key + "_sum"] = sum(values)
            row[key + "_p95"] = values[(95 * len(values) + 99) // 100 - 1] if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with container(PG, [5432], [("POSTGRES_PASSWORD", "fixture-only")],
                   args=["-c", "log_line_prefix=%n|%p|%d| ", "-c", "log_min_duration_statement=0",
                         "-c", "log_parameter_max_length=0", "-c", "log_lock_waits=on",
                         "-c", "deadlock_timeout=1ms"]) as (cid, ports):
        for _ in range(120):
            ready = subprocess.run(["docker", "exec", cid, "pg_isready", "-U", "postgres"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        run = subprocess.run([args.binary.resolve(), "--ignored", "--exact",
                              "session_lock_measurements", "--nocapture"],
                             env={**os.environ, "IDENTITY_TEST_PG_PORT": str(ports[5432])},
                             text=True, stdout=subprocess.PIPE, check=False)
        if run.returncode:
            raise RuntimeError(run.stdout[-3000:])
        rows = [json.loads(line.split("LOCK_BENCH ", 1)[1]) for line in run.stdout.splitlines()
                if "LOCK_BENCH " in line]
        if len(rows) != 81:
            raise RuntimeError(f"incomplete benchmark: {len(rows)} groups")
        for row in rows:
            row.update(observed_wait_us=[], lock_to_commit_us=[])
        with subprocess.Popen(["docker", "logs", cid], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True) as logs:
            summarize(logs.stdout, rows)
        if logs.returncode:
            raise RuntimeError("failed to read PG lock timings")
        args.output.write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
