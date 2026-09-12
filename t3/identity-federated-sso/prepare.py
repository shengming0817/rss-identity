#!/usr/bin/env python3
"""Prepare the product candidate and test tools from one clean immutable source revision."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import proof

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def run(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def identity():
    if run(['/usr/bin/git', 'status', '--porcelain'], cwd=ROOT):
        raise ValueError('T33 preparation requires clean committed source')
    return run(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT)


def prepare(out, ui_source, ui_dist):
    revision = identity()
    if out.exists():
        raise ValueError('T33 artifact directory must be new')
    tools = json.loads((HERE / 'tools.lock.json').read_text())
    if tools['ui_revision'] != proof.UI_REVISION or run(['/usr/bin/git', '-C', str(ui_source), 'rev-parse', 'HEAD']) != proof.UI_REVISION:
        raise ValueError('T33 UI identity mismatch')
    out.mkdir(parents=True)
    env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='identity-t33-build-') as tmp:
        stage = Path(tmp)
        # The canonical candidate builder accepts only an explicit BuildKit secret. Resolve the
        # existing credential without printing it or exposing it to compilation/runtime steps.
        if not env.get('SYSTEM_ACCESSTOKEN') and not env.get('IDENTITY_GIT_AUTH_HEADER_FILE'):
            result = subprocess.run(['/usr/bin/git', 'credential', 'fill'], cwd=ROOT,
                input='protocol=https\nhost=dev.azure.com\npath=shengming0923/rss/_git/rss\n\n',
                text=True, capture_output=True, timeout=30)
            fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            if result.returncode == 0 and fields.get('password'):
                import base64
                encoded = base64.b64encode((fields.get('username', '') + ':' + fields['password']).encode()).decode()
                header = stage / 'git-header'
                header.write_text('Authorization: Basic ' + encoded)
                header.chmod(0o600)
                env['IDENTITY_GIT_AUTH_HEADER_FILE'] = str(header)
        subprocess.run([sys.executable, str(ROOT / 'hack/release.py'), '--output', str(out / 'candidate'),
                        '--ui-source', str(ui_source), '--ui-dist', str(ui_dist)], cwd=ROOT, env=env, check=True)
        archive = stage / 'source.tar'
        with archive.open('wb') as stream:
            subprocess.run(['/usr/bin/git', 'archive', revision], cwd=ROOT, stdout=stream, check=True)
        source = stage / 'source'
        source.mkdir()
        with tarfile.open(archive) as stream:
            stream.extractall(source, filter='data')
        providers = json.loads((source / 'deployment/providers.lock.json').read_text())
        subprocess.run(['docker', 'buildx', 'build', '--platform', 'linux/amd64',
                        '-f', str(source / 't3/identity-federated-sso/consumer.Dockerfile'),
                        '--build-arg', 'RUST_IMAGE=' + providers['rust'], '--output',
                        'type=local,dest=' + str(out / 'consumer'), str(source)], check=True)
        browser_name = 'rss-identity/t33-browser:' + revision
        browser_archive = out / 'browser.oci.tar'
        browser_source = source / 't3/identity-federated-sso'
        subprocess.run(['docker', 'buildx', 'build', '-f', str(browser_source / 'browser.Dockerfile'),
                        '--build-arg', 'BROWSER_IMAGE=' + tools['browser'], '--tag', browser_name,
                        '--provenance=false', '--output', 'type=oci,dest=' + str(browser_archive),
                        str(browser_source)], check=True)
        subprocess.run(['docker', 'load', '-i', str(browser_archive)], check=True)
        inspected = json.loads(run(['docker', 'image', 'inspect', browser_name]))[0]
        (out / 'runner').mkdir()
        shutil.copy(browser_source / 'browser.mjs', out / 'runner/browser.mjs')
        c = json.loads((out / 'candidate/candidate.json').read_text())
        record = {
            'format_version': 1, 'revision': revision, 'ui_revision': proof.UI_REVISION,
            'candidate_sha256': proof.sha(out / 'candidate/candidate.json'),
            'consumer': {'revision': revision, 'target': 'x86_64-unknown-linux-gnu',
                         'sha256': proof.sha(out / 'consumer/identity-federated-t3-consumer'),
                         'lock_sha256': proof.sha(source / 'tests/consumer/Cargo.lock'),
                         'manifest_sha256': proof.sha(source / 'tests/consumer/Cargo.toml'),
                         'source_archive_sha256': proof.sha(archive),
                         'toolchain': (out / 'consumer/toolchain.txt').read_text()},
            'browser': {'image': browser_name, 'image_id': inspected['Id'],
                        'platform': inspected['Os'] + '/' + inspected['Architecture'],
                        'base': tools['browser'], 'archive_sha256': proof.sha(browser_archive),
                        'lock_sha256': proof.sha(browser_source / 'package-lock.json')},
            'files': {name: proof.sha(out / name) for name in [
                'runner/browser.mjs', 'candidate/deploy.py', 'candidate/deployment/providers.lock.json',
                'candidate/deployment/example.json', 'candidate/deployment/keycloak-totp.json']},
        }
        if identity() != revision or c['revision'] != revision:
            raise ValueError('source changed during T33 preparation')
        (out / 't33.json').write_text(json.dumps(record, indent=2) + '\n')
        proof.load_artifacts(out, revision)
        print('T33 immutable artifacts prepared: ' + revision)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--ui-source', required=True, type=Path)
    parser.add_argument('--ui-dist', required=True, type=Path)
    args = parser.parse_args()
    prepare(args.output.resolve(), args.ui_source.resolve(), args.ui_dist.resolve())
