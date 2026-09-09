"""Independent consumer closure: no server internals or implicit workspace features."""
import json,subprocess,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def check(metadata):
    packages={p['id']:p for p in metadata['packages']}
    local={p['name'] for p in packages.values() if p['source'] is None}
    if local!={'identity-consumer-proof','rss-identity-client','rss-identity-contracts'}:raise ValueError('consumer internal dependency')
    for p in packages.values():
        if p['source'] is not None and p['source']!='registry+https://github.com/rust-lang/crates.io-index':raise ValueError('consumer source drift')
    expected={'rsa':'0.9.10','openidconnect':'4.0.1'}
    ids={}
    for name,version in expected.items():
        found=[p for p in packages.values() if p['name']==name]
        if len(found)!=1 or found[0]['version']!=version:raise ValueError('consumer public-verification exception drift')
        ids[name]=found[0]['id']
    for child,parent in [('rsa','openidconnect'),('openidconnect','identity-consumer-proof')]:
        parents={packages[n['id']]['name'] for n in metadata['resolve']['nodes'] if any(d['pkg']==ids[child] for d in n['deps'])}
        if parents!={parent}:raise ValueError('consumer verification dependency drift')
    # A clean consumer cannot inherit a server feature via another workspace member.
    for n in metadata['resolve']['nodes']:
        if packages[n['id']]['name'].startswith('rss-identity-') and n['features']:raise ValueError('unexpected consumer feature')
if __name__=='__main__':
    meta=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1','--manifest-path','tests/consumer/Cargo.toml'],cwd=ROOT))
    check(meta)
    import os
    target=Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'consumer'
    env={**os.environ,'CARGO_TARGET_DIR':str(target)}
    subprocess.run(['cargo','fmt','--manifest-path','tests/consumer/Cargo.toml','--','--check'],cwd=ROOT,env=env,check=True)
    subprocess.run(['cargo','clippy','--locked','--manifest-path','tests/consumer/Cargo.toml','--all-targets','--','-D','warnings'],cwd=ROOT,env=env,check=True)
    subprocess.run(['cargo','deny','--manifest-path','tests/consumer/Cargo.toml','--locked','check','--config','tests/consumer/deny.toml','advisories','licenses','sources'],cwd=ROOT,check=True)
