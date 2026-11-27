#!/usr/bin/env python3
"""Check effective source identities, not just manifest strings."""
import argparse
import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent

RSS_URL = 'https://dev.azure.com/shengming0923/rss/_git/rss'
PRODUCT_PACKAGES = {'rss-identity-app', 'rss-identity-service-http'}
PRODUCT_BINARIES = {'identity-server', 'identity-admin', 'identity-migrate'}

RSS_FEATURES = {
    'rss-identity-core': set(), 'rss-identity-postgres': set(),
    'rss-identity-web-credentials': set(), 'rss-identity-oidc': {'test-support'},
    'rss-audit-core': {'default'}, 'rss-audit-postgres': {'default','messaging'},
    # Cargo metadata retains inactive optional Ledger nodes; production artifacts exclude them.
    'rss-ledger': set(), 'rss-ledger-postgres': {'messaging'},
    'rss-runtime': {'default'}, 'rss-axum': {'http1','managed-server'},
    'rss-contract': {'default'}, 'rss-request-context': {'default'},
    'rss-redact': {'default'}, 'rss-diag-context': {'default'},
    'rss-transactional-messaging': {'consumer', 'default', 'producer'},
    'rss-transactional-messaging-postgres': {'default', 'integration', 'test-support'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)

def check_features(actual, profile):
    expected = {name: set(features) for name, features in RSS_FEATURES.items()}
    if profile == 'production':
        expected['rss-transactional-messaging-postgres'] = {'default'}
        expected['rss-identity-oidc'] = set()
        del expected['rss-ledger']
        del expected['rss-ledger-postgres']
    require(actual == expected, f'{profile} RSS feature closure drift: {actual}')

def check_advisory_policy(policy):
    require(policy.get('advisories', {}).get('ignore') == [], 'unreviewed advisory exception')
    require(policy['advisories'].get('unused-ignored-advisory') == 'deny', 'stale exception must fail')


def check(metadata, manifest):
    declarations = manifest["workspace"]["dependencies"]
    members = set(metadata["workspace_members"])
    local_names = {p["name"] for p in metadata["packages"] if p["id"] in members}
    require(local_names == PRODUCT_PACKAGES, 'unexpected product workspace')
    binaries = {t['name'] for p in metadata['packages'] if p['id'] in members
               for t in p['targets'] if 'bin' in t['kind']}
    require(binaries == PRODUCT_BINARIES, 'unexpected product binaries')
    roots = {k:v for k,v in declarations.items() if k.startswith("rss-") and k not in local_names}
    require(roots, 'RSS dependency roots missing')
    revisions = set()
    for declaration in roots.values():
        rev = declaration.get('rev')
        require(declaration.get('git') == RSS_URL, 'unknown RSS source')
        require(isinstance(rev,str) and len(rev)==40 and all(c in '0123456789abcdef' for c in rev), 'full SHA required')
        require(not any(k in declaration for k in ('branch','tag','path','registry')), 'ambiguous RSS source')
        revisions.add(rev)
    require(len(revisions) == 1, 'mixed RSS source declarations')
    rev = revisions.pop()
    require(not manifest.get('patch') and not manifest.get('replace'), 'source overrides forbidden')
    found = {}
    for p in metadata["packages"]:
        if p["name"].startswith("rss-") and p["id"] not in members:
            require(p['source'] == f'git+{RSS_URL}?rev={rev}#{rev}', f"wrong source for {p['name']}")
            require(p['name'] not in found, f"duplicate RSS package {p['name']}")
            found[p["name"]] = p["version"]
        if p["source"] is None:
            require(p['id'] in members, 'external path dependency')
            Path(p["manifest_path"]).resolve().relative_to(Path(metadata["workspace_root"]).resolve())
    packages = {p['id']: p for p in metadata['packages']}
    actual = {packages[n['id']]['name']: set(n['features']) for n in metadata['resolve']['nodes'] if packages[n['id']]['name'].startswith('rss-') and n['id'] not in members}
    check_features(actual, 'test')
    return {"sources":{RSS_URL:rev},"packages":found}

def check_artifacts(data, output):
    # Use the actual release/check compiler artifacts, including cached artifacts.
    packages = {p['id']: p for p in data['packages']}
    actual = {}
    binaries = set()
    for line in output.splitlines():
        message = json.loads(line)
        if message.get('reason') != 'compiler-artifact':
            continue
        package = packages[message['package_id']]
        name = package['name']
        if name == 'rss-identity-app' and 'bin' in message['target']['kind']:
            binaries.add(message['target']['name'])
        if name.startswith('rss-') and package['id'] not in data['workspace_members']:
            values = set(message['features'])
            require(name not in actual or actual[name] == values, 'conflicting production feature sets')
            actual[name] = values
    require(binaries == PRODUCT_BINARIES, 'missing compiled product binaries')
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
    result = check(data, manifest)
    output = args.artifacts.read_text() if args.artifacts else subprocess.check_output(['cargo', 'check', '--locked', '--workspace', '--lib', '--bins', '--message-format=json'], cwd=ROOT, text=True)
    check_artifacts(data, output)
    print(json.dumps(result, sort_keys=True))
