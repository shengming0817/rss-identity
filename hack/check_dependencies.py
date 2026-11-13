#!/usr/bin/env python3
"""Check effective source identities, not just manifest strings."""
import argparse
from datetime import date, datetime, timezone
import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent

RSS_FEATURES = {
    'rss-audit-core': {'default'}, 'rss-audit-postgres': {'default','messaging'},
    # Cargo metadata retains inactive optional Ledger nodes; production artifacts exclude them.
    'rss-ledger': set(), 'rss-ledger-postgres': {'messaging'},
    'rss-runtime': {'default'}, 'rss-axum': {'http1','managed-server'},
    'rss-contract': {'default'}, 'rss-request-context': {'default'},
    'rss-redact': {'default'}, 'rss-diag-context': {'default'},
    'rss-transactional-messaging': {'consumer', 'default', 'producer'},
    'rss-transactional-messaging-postgres': {'integration', 'test-support'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)

def check_features(actual, profile):
    expected = {name: set(features) for name, features in RSS_FEATURES.items()}
    if profile == 'production':
        expected['rss-transactional-messaging-postgres'] = set()
        del expected['rss-ledger']
        del expected['rss-ledger-postgres']
    require(actual == expected, f'{profile} RSS feature closure drift: {actual}')

SQLITE_EXCEPTION = {
    'id': 'RUSTSEC-2026-0459',
    'reason': '#3184: RSS dependency owner accepts inactive SQLx SQLite lock entries only; expires 2026-12-13 UTC; revoke on activation or a compatible SQLx fix.',
}


def check_advisory_policy(policy):
    require(policy.get('advisories', {}).get('ignore') == [SQLITE_EXCEPTION], 'unreviewed advisory exception')
    require(policy['advisories'].get('unused-ignored-advisory') == 'deny', 'stale exception must fail')


def check_sqlite_lock(packages, active, today=None):
    # The upstream #3184 acceptance covers only these inactive lock identities.
    require((today or datetime.now(timezone.utc).date()) < date(2026, 12, 13), 'SQLite exception expired')
    identities = {
        'libsqlite3-sys': ('0.37.0', 'b1f111c8c41e7c61a49cd34e44c7619462967221a6443b0ec299e0ac30cfb9b1'),
        'sqlx-sqlite': ('0.9.0', '488e99c397a62007e4229aec669a179816339afc6d2620ca6fa420dbee2e982c'),
        'sqlx': ('0.9.0', '378620ccc25c62c89d8be1c819e76a88d59bdcc3304733330788948e619bfd71'),
        'sqlx-macros': ('0.9.0', 'bd2b84f2bc39a5705ef27ec785a11c934a41bbd4a24941e257927cddc26b60bf'),
        'sqlx-macros-core': ('0.9.0', 'fb8d96de5fdc85a5c4ec813432b523ec637e80ba98f046555f75f7908ddac7c3'),
    }
    for name, identity in identities.items():
        selected = [p for p in packages if p['name'] == name]
        require(len(selected) == 1, 'remove stale SQLite exception when the dependency exits')
        package = selected[0]
        require((package['version'], package.get('checksum')) == identity and
                package.get('source') == 'registry+https://github.com/rust-lang/crates.io-index',
                'SQLite exception identity changed')
    for child, expected in {
        'libsqlite3-sys': {'sqlx-sqlite'}, 'sqlx-sqlite': {'sqlx', 'sqlx-macros-core'},
        'sqlx-macros-core': {'sqlx-macros'}, 'sqlx-macros': {'sqlx'},
    }.items():
        parents = {p['name'] for p in packages if any(d.split()[0] == child for d in p.get('dependencies', []))}
        require(parents == expected, 'SQLite exception dependency parents changed')
    require('sqlx' in active and not {'libsqlite3-sys', 'sqlx-sqlite'} & active,
            'SQLite exception covers inactive lock entries only')


def check(metadata, manifest):
    declarations = manifest["workspace"]["dependencies"]
    members = set(metadata["workspace_members"])
    local_names = {p["name"] for p in metadata["packages"] if p["id"] in members}
    roots = {k:v for k,v in declarations.items() if k.startswith("rss-") and k not in local_names}
    require(roots, 'RSS dependency roots missing')
    source_pins = {}
    for name, declaration in roots.items():
        url = 'https://dev.azure.com/shengming0923/rss/_git/' + ('rss-audit' if name in {'rss-audit-core','rss-audit-postgres','rss-ledger','rss-ledger-postgres'} else 'rss')
        rev = declaration.get('rev')
        require(declaration.get('git') == url, 'unknown RSS source')
        require(isinstance(rev,str) and len(rev)==40 and all(c in '0123456789abcdef' for c in rev), 'full SHA required')
        require(not any(k in declaration for k in ('branch','tag','path','registry')), 'ambiguous RSS source')
        require(url not in source_pins or source_pins[url] == rev, 'mixed RSS source declarations')
        source_pins[url] = rev
    require(not manifest.get('patch') and not manifest.get('replace'), 'source overrides forbidden')
    found = {}
    for p in metadata["packages"]:
        if p["name"].startswith("rss-") and p["id"] not in members:
            url = 'https://dev.azure.com/shengming0923/rss/_git/' + ('rss-audit' if p['name'] in {'rss-audit-core','rss-audit-postgres','rss-ledger','rss-ledger-postgres'} else 'rss')
            rev = source_pins.get(url)
            require(rev is not None and p['source'] == f'git+{url}?rev={rev}#{rev}', f"wrong source for {p['name']}")
            require(p['name'] not in found, f"duplicate RSS package {p['name']}")
            found[p["name"]] = p["version"]
        if p["source"] is None:
            require(p['id'] in members, 'external path dependency')
            Path(p["manifest_path"]).resolve().relative_to(Path(metadata["workspace_root"]).resolve())
    require({'rss-contract', 'rss-request-context', 'rss-redact', 'rss-diag-context', 'rss-transactional-messaging', 'rss-transactional-messaging-postgres'} <= found.keys(), 'required RSS closure missing')
    packages = {p['id']: p for p in metadata['packages']}
    actual = {packages[n['id']]['name']: set(n['features']) for n in metadata['resolve']['nodes'] if packages[n['id']]['name'].startswith('rss-') and n['id'] not in members}
    check_features(actual, 'test')
    return {"sources":source_pins,"packages":found}

def check_artifacts(data, output):
    # Use the actual release/check compiler artifacts, including cached artifacts.
    packages = {p['id']: p for p in data['packages']}
    actual = {}
    for line in output.splitlines():
        message = json.loads(line)
        if message.get('reason') != 'compiler-artifact':
            continue
        package = packages[message['package_id']]
        name = package['name']
        if name.startswith('rss-') and package['id'] not in data['workspace_members']:
            values = set(message['features'])
            require(name not in actual or actual[name] == values, 'conflicting production feature sets')
            actual[name] = values
    check_features(actual, 'production')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--metadata', type=Path)
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    if bool(args.metadata) != bool(args.artifacts):
        parser.error('--metadata and --artifacts must be provided together')
    data = json.loads(args.metadata.read_text() if args.metadata else subprocess.check_output(["cargo","metadata","--locked","--format-version","1"],cwd=ROOT))
    manifest = tomllib.loads((ROOT/"Cargo.toml").read_text())
    check_advisory_policy(tomllib.loads((ROOT / "deny.toml").read_text()))
    active = subprocess.check_output(['cargo', 'tree', '--locked', '--workspace', '--all-features',
        '--target', 'all', '--edges', 'normal,build,dev', '--prefix', 'none', '--format', '{p}'], cwd=ROOT, text=True)
    check_sqlite_lock(tomllib.loads((ROOT / 'Cargo.lock').read_text())['package'],
                      {line.split()[0] for line in active.splitlines() if line.strip()})
    result = check(data, manifest)
    output = args.artifacts.read_text() if args.artifacts else subprocess.check_output(['cargo', 'check', '--locked', '--workspace', '--lib', '--bins', '--message-format=json'], cwd=ROOT, text=True)
    check_artifacts(data, output)
    print(json.dumps(result, sort_keys=True))
