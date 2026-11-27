#!/usr/bin/env python3
"""Run a compiled session_lock_bench release test on pinned PG and output timing evidence.

Each record covers one warmed group. PostgreSQL logs waits of at least 1 ms.
The separate --trace pass observes the first tenant row lock, including locks inside\nPL/pgSQL. Ordinary runs report the completed scope SQL to COMMIT and host admission\nto COMMIT. Server log timestamps resolve milliseconds. Issuance uses several transactions.
"""
import argparse
import bisect
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from providers import PG, container

PREFIX = re.compile(r"^(\d+\.\d+)\|(\d+)\|([^|]*)\|\s*LOG:\s+(.*)")
ACQUIRED = re.compile(r"process \d+ acquired .* after ([\d.]+) ms")
FINISHED = re.compile(r"duration: [\d.]+ ms\s+(?:execute [^:]+|statement):\s*(.*)", re.I)
LOCK = re.compile(r"SELECT (?:identity_authority\.lock_session\(|tenant_id FROM identity_authority\.(?:guard|tenants) WHERE.* FOR (?:KEY SHARE|SHARE|UPDATE|NO KEY UPDATE))", re.I)


def summarize(lines, rows):
    # PostgreSQL %n timestamps have millisecond resolution.
    starts = [r["begin_us"] // 1000 * 1000 for r in rows]
    plan = None
    held = {}
    for line in lines:
        found = PREFIX.match(line)
        if not found:
            if plan and line.strip().upper().startswith("QUERY TEXT:"):
                query = line.strip()[len("Query Text:"):].strip()
                if re.match(r"SELECT +(?:tenant_id +)?FROM identity_authority\.(?:tenants|guard)\b.* FOR (?:KEY SHARE|SHARE|UPDATE|NO KEY UPDATE)",query,re.I):
                    pid, index, now = plan
                    held.setdefault(pid,(index,now))
                plan=None
            continue
        plan=None
        instant, pid, db, msg = found.groups()
        now = round(float(instant) * 1_000_000)
        index = bisect.bisect_right(starts, now) - 1
        if index < 0 or now // 1000 > rows[index]["end_us"] // 1000 or db != rows[index]["db"]:
            held.pop(pid, None)
            continue
        row = rows[index]
        if row["trace"] and msg.rstrip().endswith("plan:"):
            plan=(pid,index,now)
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
        elif LOCK.match(query) and (not row["trace"] or "LOCK_SESSION(" not in query):
            held.setdefault(pid, (index, now))
        elif query.startswith(("COMMIT", "ROLLBACK")):
            moment = held.pop(pid, None)
            if moment and moment[0] == index and query.startswith("COMMIT"):
                row["lock_to_commit_us"].append(now - moment[1])
    for row in rows:
        for key in ("observed_wait_us", "lock_to_commit_us"):
            values = sorted(row.pop(key))
            if key=="lock_to_commit_us":
                key="first_lock_to_commit_us" if row["trace"] else "scope_sql_to_commit_us"
                if not values:
                    raise RuntimeError(f"missing lock samples for {row['work']}/{row['shape']}")
            row[key + "_count"] = len(values)
            row[key + "_sum"] = sum(values)
            row[key + "_p95"] = values[(95 * len(values) + 99) // 100 - 1] if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--trace",action="store_true",help="separate diagnostic pass with nested PG statement completion")
    args = parser.parse_args()
    tracing = ["-c","session_preload_libraries=auto_explain","-c","auto_explain.log_min_duration=0",
               "-c","auto_explain.log_nested_statements=on"] if args.trace else []
    with container(PG, [5432], [("POSTGRES_PASSWORD", "fixture-only")],
                   args=["-c", "log_line_prefix=%n|%p|%d| ", "-c", "log_min_duration_statement=0",
                         "-c", "log_parameter_max_length=0", "-c", "log_lock_waits=on",
                         "-c", "deadlock_timeout=1ms", *tracing]) as (cid, ports):
        for _ in range(120):
            ready = subprocess.run(["docker", "exec", cid, "pg_isready", "-h","127.0.0.1","-U", "postgres"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("PostgreSQL TCP readiness timed out")
        run = subprocess.run([args.binary.resolve(), "--ignored", "--exact",
                              "session_lock_measurements", "--nocapture"],
                             env={**os.environ, "IDENTITY_TEST_PG_PORT": str(ports[5432]), **({"IDENTITY_BENCH_TRACE":"1"} if args.trace else {})},
                             text=True, stdout=subprocess.PIPE, check=False,timeout=1200)
        if run.returncode:
            raise RuntimeError(run.stdout[-3000:])
        rows = [json.loads(line.split("LOCK_BENCH ", 1)[1]) for line in run.stdout.splitlines()
                if "LOCK_BENCH " in line]
        if len(rows) != (27 if args.trace else 81):
            raise RuntimeError(f"incomplete benchmark: {len(rows)} groups")
        for row in rows:
            row.update(observed_wait_us=[], lock_to_commit_us=[])
        with tempfile.TemporaryFile(mode="w+t") as logs:
            subprocess.run(["docker","logs",cid],stdout=logs,stderr=subprocess.STDOUT,check=True,timeout=180)
            logs.seek(0)
            summarize(logs,rows)
        args.output.write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
