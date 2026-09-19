"""Rebuild independent local/OIDC hosts from one immutable Identity Git revision."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib
import providers
from bounded_process import run as bounded_run

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = 'https://dev.azure.com/shengming0923/rss/_git/rss-identity'
RSS = 'https://dev.azure.com/shengming0923/rss/_git/rss'
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
NAMES = {'local': 'local_host_authentication_and_router_composition', 'oidc': 'oidc_host_uses_real_keycloak_and_public_groups'}

def require(value, message):
    if not value:
        raise ValueError(message)

def check(metadata, revision, rss_revision, profile, fixture=False):
    packages = {p['id']: p for p in metadata['packages']}
    members = set(metadata['workspace_members'])
    expected = {'rss-identity-core', 'rss-identity-postgres', 'rss-identity-http-axum'}
    if profile == 'oidc':
        expected.add('rss-identity-oidc')
    identities = [p for p in packages.values() if p['name'].startswith('rss-identity-')]
    require({p['name'] for p in identities} == expected and len(identities) == len(expected), 'Identity closure drift')
    require(len(members) == 1, 'consumer must be a standalone workspace')
    for p in packages.values():
        if p['id'] in members:
            require(p['name'] == f'identity-{profile}-consumer' and p['source'] is None, 'unexpected consumer root')
        elif p['name'].startswith('rss-identity-'):
            require(p['source'] == f'git+{IDENTITY}?rev={revision}#{revision}', 'Identity source drift')
        elif p['name'].startswith('rss-'):
            require(p['source'] == f'git+{RSS}?rev={rss_revision}#{rss_revision}', 'RSS source drift')
        else:
            require(p['source'] == REGISTRY, 'external path/source override')
    if profile == 'local':
        require({'openidconnect', 'reqwest', 'rsa'}.isdisjoint(p['name'] for p in packages.values()), 'local host acquired an OIDC dependency')
    else:
        for name, version, parent in [('rsa', '0.9.10', 'openidconnect'), ('openidconnect', '4.0.1', 'rss-identity-oidc')]:
            found = [p for p in packages.values() if p['name'] == name]
            require(len(found) == 1 and found[0]['version'] == version, 'public verification exception version drift')
            parents = {packages[n['id']]['name'] for n in metadata['resolve']['nodes'] if any(d['pkg'] == found[0]['id'] for d in n['deps'])}
            require(parents == {parent}, 'public verification exception path drift')
    oidc_nodes = [n for n in metadata['resolve']['nodes'] if packages[n['id']]['name'] == 'rss-identity-oidc']
    if profile == 'oidc':
        require(len(oidc_nodes) == 1 and ('test-support' in oidc_nodes[0]['features']) == fixture, 'OIDC fixture feature escaped its declared mode')
    return {n['id']: {'name': packages[n['id']]['name'], 'version': packages[n['id']]['version'], 'source': packages[n['id']]['source'], 'features': n['features']} for n in metadata['resolve']['nodes']}

def source_hashes():
    # Production commit A and evidence commit B must have identical effective source/config.
    paths = [ROOT/'Cargo.toml', ROOT/'Cargo.lock', ROOT/'rust-toolchain.toml']
    for base in ['crates', 'app', 'deployment', 'hack', 'tests/consumers']:
        paths.extend(p for p in (ROOT/base).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}

def manifest(profile, revision, rss_revision):
    lines = ['[workspace]', 'resolver = "3"', '[package]', f'name = "identity-{profile}-consumer"', 'version = "0.1.0"', 'edition = "2024"', 'publish = false', '[dependencies]']
    names = ['core', 'postgres', 'http-axum'] + (['oidc'] if profile == 'oidc' else [])
    lines += [f'rss-identity-{name} = {{ git = "{IDENTITY}", rev = "{revision}" }}' for name in names]
    lines += [f'rss-request-context = {{ git = "{RSS}", rev = "{rss_revision}" }}',
              f'rss-transactional-messaging = {{ git = "{RSS}", rev = "{rss_revision}", default-features = false, features = ["producer"] }}',
              f'rss-transactional-messaging-postgres = {{ git = "{RSS}", rev = "{rss_revision}", default-features = false, features = ["integration"] }}',
              'anyhow = "1"', 'tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }',
              'sqlx = { version = "=0.9.0", default-features = false, features = ["runtime-tokio", "tls-rustls", "postgres", "uuid"] }',
              'axum = "=0.8.9"', 'tower = { version = "0.5", features = ["util"] }']
    if profile == 'oidc':
        lines += ['reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "cookies"] }', 'zeroize = "1"', '[dev-dependencies]', 'scraper = "=0.26.0"', '[features]', 'default = []', 'loopback-fixture = ["rss-identity-oidc/test-support"]']
    return '\n'.join(lines) + '\n'

def execute(command, directory, env, timeout=1800):
    result = bounded_run(command, cwd=directory, env=env, timeout=timeout, text=True, capture_output=True)
    if result.returncode:
        # Commands are controlled, but auth/provider diagnostics are never persisted in evidence.
        print(result.stdout[-12000:] if command[:2] != ['cargo', 'test'] else 'consumer test failed; raw provider output withheld')
        print(result.stderr[-12000:] if command[:2] != ['cargo', 'test'] else '')
        raise RuntimeError(f'consumer command failed: {command[0:2]} exit={result.returncode}')
    return result.stdout

def verify_test(result, name):
    expected = f'test {name} ... ok'
    require(expected in result and 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' in result, 'consumer canonical execution incomplete')

def compiled_features(result, closure, profile):
    compiled = {}
    for line in result.splitlines():
        if not line.startswith('{'):
            continue
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact':
            compiled.setdefault(item['package_id'], set()).update(item['features'])
    if profile == 'oidc':
        oidc = [key for key, value in closure.items() if value['name'] == 'rss-identity-oidc']
        require(len(oidc) == 1 and oidc[0] in compiled and compiled[oidc[0]] == set(closure[oidc[0]]['features']), 'actual OIDC compiler features differ from declared mode')
    require(compiled, 'compiler evidence absent')
    return {key: sorted(features) for key, features in compiled.items()}

def run(revision, output):
    require(re.fullmatch(r'[0-9a-f]{40}', revision), 'complete Identity SHA required')
    output = output.resolve()
    require(not output.exists(), 'use a fresh output directory')
    # No repository ancestor or inherited Cargo configuration participates in resolution/build.
    for parent in [output, *output.parents]:
        require(not (parent/'.git').exists() and not (parent/'Cargo.toml').exists(), 'consumer directory has repository/workspace ancestor')
        require(not (parent/'.cargo/config').exists() and not (parent/'.cargo/config.toml').exists(), 'consumer inherits ancestor Cargo configuration')
    require(subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=ROOT,text=True).strip() == revision, 'run from the committed source revision')
    require(not subprocess.check_output(['/usr/bin/git','status','--porcelain','--','Cargo.toml','Cargo.lock','rust-toolchain.toml','crates','app','deployment','hack','tests/consumers'],cwd=ROOT,text=True).strip(), 'production source must be committed')
    rss_revision = tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']['dependencies']['rss-request-context']['rev']
    output.mkdir(parents=True)
    report = {'identity_git': IDENTITY, 'identity_revision': revision, 'rss_revision': rss_revision, 'source_sha256': source_hashes(), 'providers': providers.IMAGES, 'consumers': {}}
    for profile in NAMES:
        directory = output/profile
        (directory/'src').mkdir(parents=True)
        (directory/'Cargo.toml').write_text(manifest(profile, revision, rss_revision))
        shutil.copyfile(ROOT/'tests/consumers'/profile/'lib.rs', directory/'src/lib.rs')
        shutil.copyfile(ROOT/'tests/consumers/host.rs', directory/'src/host.rs')
        shutil.copyfile(ROOT/'rust-toolchain.toml', directory/'rust-toolchain.toml')
        env = {k:v for k,v in os.environ.items() if not k.startswith(('CARGO_', 'RUST', 'SCCACHE_'))}
        env['CARGO_TARGET_DIR'] = str(directory/'target')
        env['CARGO_NET_GIT_FETCH_WITH_CLI'] = 'true'
        execute(['cargo','generate-lockfile'], directory, env)
        metadata = json.loads(execute(['cargo','metadata','--locked','--format-version','1'], directory, env))
        closure = check(metadata, revision, rss_revision, profile)
        (directory/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
        execute(['cargo','fmt','--','--check'], directory, env)
        execute(['cargo','clippy','--locked','--all-targets','--','-D','warnings'], directory, env,3600)
        deny = (ROOT/'deny.toml').read_text().replace(f'allow-git = ["{RSS}"]', f'allow-git = ["{RSS}", "{IDENTITY}"]')
        if profile == 'local':
            deny = deny.replace('ignore = ["RUSTSEC-2023-0071"]','ignore = []')
        (directory/'deny.toml').write_text(deny)
        execute(['cargo','deny','--locked','check','advisories','licenses','sources'],directory,env)
        modes = {}
        if profile == 'oidc':
            result = execute(['cargo','test','--locked','--lib','--message-format=json','--','--test-threads=1'],directory,env)
            verify_test(result, 'production::production_transport_rejects_loopback')
            modes['production'] = {'tests': {'passed':1,'failed':0,'ignored':0}, 'features': [], 'closure': closure, 'compiled_features': compiled_features(result, closure, profile)}
            features = ['--features','loopback-fixture']
            fixture_metadata = json.loads(execute(['cargo','metadata','--locked','--format-version','1',*features],directory,env))
            fixture_closure = check(fixture_metadata,revision,rss_revision,profile,fixture=True)
            (directory/'metadata-fixture.json').write_text(json.dumps(fixture_metadata,indent=2)+'\n')
            execute(['cargo','clippy','--locked','--all-targets',*features,'--','-D','warnings'],directory,env,3600)
        else:
            features, fixture_closure = [], closure
        with contextlib.ExitStack() as stack:
            _, ports = stack.enter_context(providers.postgres())
            provider_env = {'IDENTITY_CONSUMER_PG_PORT': str(ports[5432])}
            if profile == 'oidc':
                provider_env.update(stack.enter_context(providers.keycloak('https://embedded.example.test/api/v2/oidc/callback')))
            result = execute(['cargo','test','--locked','--lib','--message-format=json',*features,'--','--test-threads=1'],directory,{**env,**provider_env},1800)
            verify_test(result, f'tests::{NAMES[profile]}')
        modes['loopback-fixture' if profile == 'oidc' else 'production'] = {'tests':{'passed':1,'failed':0,'ignored':0}, 'features':['loopback-fixture'] if features else [], 'closure':fixture_closure, 'compiled_features':compiled_features(result, fixture_closure, profile)}
        hashes = {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ['Cargo.toml','Cargo.lock','src/lib.rs','src/host.rs']}
        report['consumers'][profile] = {'directory':str(directory), 'modes':modes, 'checks':['fmt','clippy -D warnings (each mode)','cargo deny advisories licenses sources','test --locked --lib (each mode)'], 'sha256':hashes}
        (output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print(f'{profile} consumer: fixed Git, independent target, {len(modes)} mode(s) passed', flush=True)
    require(source_hashes() == report['source_sha256'], 'production source changed while proving consumers')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.revision, args.output)
