"""Measure Profile receipt heap/index rows in the normal PG fixture, using production SQL."""
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


def scanned(node):
    total = 0
    if node.get("Relation Name") == "profile_operations" and "Scan" in node["Node Type"]:
        examined = sum(node.get(field, 0) for field in
                       ("Actual Rows", "Rows Removed by Filter", "Rows Removed by Index Recheck"))
        total = node["Actual Loops"] * examined
    return total + sum(scanned(child) for child in node.get("Plans", []))


def explain(container, filename, arguments):
    statement = (SQL / filename).read_text()
    out = psql(container, f"""
        BEGIN;
        SET LOCAL ROLE identity_runtime;
        SET LOCAL rss.tenant_id='{TENANT}';
        PREPARE measured AS {statement};
        EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE measured({arguments});
        ROLLBACK;
    """)
    return scanned(json.loads(out)[0]["Plan"])


def main():
    with postgres() as (container, _):
        prepare_fixture(container)
        print("case | replay lookup | capacity pivot | oldest probe | cleanup source + delete")
        for principal, (name, revision, physical, active, capacity) in enumerate(CASES, 1):
            account = f"'{TENANT}','{UUID(int=principal)}'"
            miss = explain(container, "replay_receipt.sql",
                           f"'{TENANT}','00000000-0000-7000-8000-000000000000',14263296")
            pivot = explain(container, "receipt_capacity.sql",
                            f"{account},{revision-capacity+1},14263296") if revision >= capacity else 0
            oldest = explain(container, "oldest_receipt.sql", account) if active < capacity else 0
            cleanup = explain(container, "reclaim_receipts.sql", f"{account},14263296") if physical > active and active < capacity else 0
            print(f"{name} | {miss} | {pivot} | {oldest} | {cleanup}", flush=True)
            if miss > 1 or pivot > 1 or oldest > 1 or cleanup > 128:
                raise RuntimeError(f"receipt scan bound exceeded in {name}")


if __name__ == "__main__":
    main()
