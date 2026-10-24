#!/usr/bin/env python3
"""Run an independent public consumer pinned to a full Identity commit; never use source path overrides."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--revision',required=True)
    args=parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',args.revision):
        parser.error('full immutable revision required')
    workspace=tomllib.loads((ROOT/'Cargo.toml').read_text())
    rss=workspace['workspace']['dependencies']['rss-request-context']
    manifest='[package]\nname="identity-independent-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
    for package in ['rss-identity-core','rss-identity-postgres','rss-identity-oidc','rss-identity-http-axum']:
        manifest+=f'{package}={{git="https://dev.azure.com/shengming0923/rss/_git/rss-identity",rev="{args.revision}"}}\n'
    for package in ['rss-request-context','rss-transactional-messaging']:
        manifest+=f'{package}={{git="{rss["git"]}",rev="{rss["rev"]}"}}\n'
    manifest+='serde_json="1"\nurl="2.5"\naxum={version="=0.8.9",default-features=false}\n'
    with tempfile.TemporaryDirectory(prefix='identity-public-consumer-') as directory:
        directory=Path(directory);(directory/'src').mkdir()
        (directory/'Cargo.toml').write_text(manifest)
        (directory/'src/main.rs').write_text((ROOT/'examples/identity_consumer.rs').read_text())
        env={**os.environ,'CARGO_TARGET_DIR':str(ROOT/'target/independent-consumer')}
        subprocess.run(['cargo','generate-lockfile'],cwd=directory,env=env,check=True)
        subprocess.run(['cargo','run','--locked'],cwd=directory,env=env,check=True)
        print(f'Identity revision verified: {args.revision}')
if __name__=='__main__':main()
