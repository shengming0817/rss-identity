#!/usr/bin/env python3
"""Check effective source identities, not just manifest strings."""
import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent

RSS_FEATURES = {
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
    require(actual == expected, f'{profile} RSS feature closure drift: {actual}')

def check_advisory_path(metadata):
    # #2357: owner shengming; public verification only. Any graph drift revokes acceptance.
    packages = {p['id']: p for p in metadata['packages']}
    expected = {'rsa': '0.9.10', 'openidconnect': '4.0.1', 'rss-identity-oidc': '0.1.0'}
    ids = {}
    for name, version in expected.items():
        matches = [p for p in packages.values() if p['name'] == name]
        require(len(matches) == 1 and matches[0]['version'] == version, f'RSA exception version drift: {name}')
        p = matches[0]
        require(p['source'] == (None if name == 'rss-identity-oidc' else 'registry+https://github.com/rust-lang/crates.io-index'), 'RSA exception source drift')
        ids[name] = p['id']
    for child, parent in [('rsa', 'openidconnect'), ('openidconnect', 'rss-identity-oidc')]:
        parents = {n['id'] for n in metadata['resolve']['nodes'] if any(d['pkg'] == ids[child] for d in n['deps'])}
        require(parents == {ids[parent]}, f'RSA exception dependency path drift: {child}')

def check_advisory_policy(policy):
    require(policy.get('advisories', {}).get('ignore') == ['RUSTSEC-2023-0071'], 'unreviewed advisory exception')
    require(policy['advisories'].get('unused-ignored-advisory') == 'deny', 'stale exception must fail')

def check(metadata, manifest):
    declarations = manifest["workspace"]["dependencies"]
    members = set(metadata["workspace_members"])
    local_names = {p["name"] for p in metadata["packages"] if p["id"] in members}
    roots = [v for k, v in declarations.items() if k.startswith("rss-") and k not in local_names]
    require(roots, 'RSS dependency roots missing')
    urls = {d.get("git") for d in roots}
    revs = {d.get("rev") for d in roots}
    require(len(urls) == 1 and len(revs) == 1, 'mixed RSS source declarations')
    url, rev = next(iter(urls)), next(iter(revs))
    require(url == 'https://dev.azure.com/shengming0923/rss/_git/rss', 'unknown RSS source')
    require(isinstance(rev, str) and len(rev) == 40 and all((c in '0123456789abcdef' for c in rev)), 'full SHA required')
    require(all((not any((k in d for k in ('branch', 'tag', 'path', 'registry'))) for d in roots)), 'ambiguous RSS source')
    require(not manifest.get('patch') and (not manifest.get('replace')), 'source overrides forbidden')
    expected = f"git+{url}?rev={rev}#{rev}"
    found = {}
    for p in metadata["packages"]:
        if p["name"].startswith("rss-") and p["id"] not in members:
            require(p['source'] == expected, f"wrong source for {p['name']}")
            require(p['name'] not in found, f"duplicate RSS package {p['name']}")
            found[p["name"]] = p["version"]
        if p["source"] is None:
            require(p['id'] in members, 'external path dependency')
            Path(p["manifest_path"]).resolve().relative_to(Path(metadata["workspace_root"]).resolve())
    require({'rss-contract', 'rss-request-context', 'rss-redact', 'rss-diag-context', 'rss-transactional-messaging', 'rss-transactional-messaging-postgres'} <= found.keys(), 'required RSS closure missing')
    packages = {p['id']: p for p in metadata['packages']}
    actual = {packages[n['id']]['name']: set(n['features']) for n in metadata['resolve']['nodes'] if packages[n['id']]['name'].startswith('rss-') and n['id'] not in members}
    check_features(actual, 'test')
    check_advisory_path(metadata)
    return {"git":url,"revision":rev,"packages":found}

if __name__ == "__main__":
    data = json.loads(subprocess.check_output(["cargo","metadata","--locked","--format-version","1"],cwd=ROOT))
    manifest = tomllib.loads((ROOT/"Cargo.toml").read_text())
    check_advisory_policy(tomllib.loads((ROOT / "deny.toml").read_text()))
    result = check(data, manifest)
    # Read actual normal library build artifacts, not a display approximation of resolution.
    output = subprocess.check_output(['cargo', 'check', '--locked', '--workspace', '--lib', '--message-format=json'], cwd=ROOT, text=True)
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
    print(json.dumps(result, sort_keys=True))
