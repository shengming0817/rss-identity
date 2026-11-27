"""Measure Profile receipt heap/index rows in the normal PG fixture, using production SQL."""
import argparse
import json
import subprocess
from pathlib import Path
from uuid import UUID

from providers import postgres

ROOT = Path(__file__).resolve().parents[1]
PG = ROOT / "crates/identity-postgres"
SQL = PG / "src/profiles"
TENANT = str(UUID(int=1))
# name, latest revision, physical rows, active rows, capacity
CASES = [
    ("empty", 0, 0, 0, 4096),
    ("half", 6144, 2048, 2048, 4096),
    ("last-slot", 8191, 4095, 4095, 4096),
    ("full", 8192, 4096, 4096, 4096),
    ("mixed", 13312, 1088, 1024, 4096),
    ("8192-to-1", 8192, 8192, 0, 1),
]


def psql(container, sql):
    return subprocess.run(
        ["docker", "exec", "-i", container, "psql", "-XqAt", "-U", "postgres",
         "-v", "ON_ERROR_STOP=1"], input=sql, check=True, capture_output=True,
        text=True, timeout=60,
    ).stdout.strip()


def prepare_fixture(container):
    psql(container, (PG / "migrations/0001_authority.sql").read_text())
    psql(container, """
        CREATE ROLE identity_runtime;
        GRANT USAGE ON SCHEMA identity_authority TO identity_runtime;
        GRANT SELECT, INSERT, DELETE ON identity_authority.profile_operations TO identity_runtime;
    """)
    for principal, (_, revision, physical, active, _) in enumerate(CASES, 1):
        key = f"'{TENANT}', '{UUID(int=principal)}'"
        psql(container, f"""
            INSERT INTO identity_authority.accounts VALUES ({key},true,1);
            INSERT INTO identity_authority.local_profiles(tenant_id,principal_id,revision)
             SELECT {key},{revision} WHERE {revision}>0;
            INSERT INTO identity_authority.profile_operations
             (tenant_id,principal_id,operation_id,actor,digest,revision,accepted_at_ms)
             SELECT {key},
               (CASE WHEN n>{revision-active} THEN '00000600-0000-7' ELSE '00000000-0064-7' END || right(overlay(gen_random_uuid()::text placing '8' from 20 for 1),21))::uuid,
               '{UUID(int=principal)}', decode(repeat('00',32),'hex'), n,
               CASE WHEN n>{revision-active} THEN 100663296 ELSE 100 END
             FROM generate_series({revision-physical+1},{revision}) n;
        """)
    psql(container, "ANALYZE identity_authority.profile_operations")


def scans(plan):
    if "Scan" in plan["Node Type"] and ("Index Name" in plan or "Relation Name" in plan):
        yield plan
    for child in plan.get("Plans", []):
        yield from scans(child)


def explain(container, filename, arguments, mode, evidence):
    statement = (SQL / filename).read_text()
    out = psql(container, f"""
        BEGIN;
        SET LOCAL ROLE identity_runtime;
        SET LOCAL rss.tenant_id='{TENANT}';
        SET LOCAL plan_cache_mode=force_{mode}_plan;
        PREPARE measured AS {statement};
        EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE measured({arguments});
        ROLLBACK;
    """)
    result = json.loads(out)[0]
    evidence[filename] = result
    nodes = list(scans(result["Plan"]))
    if not nodes:
        raise RuntimeError(f"no receipt access path: {filename}")
    rows = 0
    for node in nodes:
        kind = node["Node Type"]
        if kind not in {"Index Scan", "Index Only Scan", "Tid Scan", "Bitmap Index Scan", "Bitmap Heap Scan"}:
            raise RuntimeError(f"unexpected {kind} in {filename}")
        if "Index Name" in node:
            keys = ["tenant_id", "operation_id"] if filename == "replay_receipt.sql" else ["tenant_id", "principal_id"]
            if filename == "receipt_capacity.sql":
                keys.append("revision")
            condition = node.get("Index Cond", "")
            if any(key not in condition for key in keys):
                raise RuntimeError(f"incomplete index condition in {filename}: {condition}")
        examined = sum(node.get(field, 0) for field in
                       ("Actual Rows", "Rows Removed by Filter", "Rows Removed by Index Recheck"))
        rows += node["Actual Loops"] * examined
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plans", type=Path, help="write full provider EXPLAIN JSON including buffers")
    plans = parser.parse_args().plans
    evidence = {}
    try:
        with postgres() as (container, _):
            prepare_fixture(container)
            print("mode | case | replay lookup | capacity pivot | oldest probe | cleanup source + delete | shared blocks hit+read")
            for mode in ("custom", "generic"):
                for principal, (name, revision, physical, active, capacity) in enumerate(CASES, 1):
                    account = f"'{TENANT}','{UUID(int=principal)}'"
                    case = evidence.setdefault(mode, {})[name] = {}

                    def measure(filename, parameters):
                        return explain(container, filename, parameters, mode, case)

                    miss = measure("replay_receipt.sql", f"'{TENANT}','00000000-0000-7000-8000-000000000000',14263296")
                    pivot = measure("receipt_capacity.sql", f"{account},{revision-capacity+1},14263296") if revision >= capacity else 0
                    oldest = measure("oldest_receipt.sql", account) if active < capacity else 0
                    cleanup = measure("reclaim_receipts.sql", f"{account},14263296") if physical > active and active < capacity else 0
                    blocks = sum(result["Plan"].get(field, 0) for result in case.values()
                                 for field in ("Shared Hit Blocks", "Shared Read Blocks"))
                    print(f"{mode} | {name} | {miss} | {pivot} | {oldest} | {cleanup} | {blocks}", flush=True)
                    if miss > 1 or pivot > 1 or oldest > 1 or cleanup > 128:
                        raise RuntimeError(f"receipt scan bound exceeded in {mode}/{name}")
    finally:
        if plans:
            plans.write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
