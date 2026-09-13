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
from run import cancellation, nonempty_path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def run(operation, args, *, budget='command', **kwargs):
    defaults = {'command': 30, 'build': 3600, 'transfer': 600}
    variable = 'T33_' + budget.upper() + '_TIMEOUT_SECONDS'
    try:
        timeout = int(os.environ.get(variable, defaults[budget]))
        if timeout <= 0:
            raise ValueError
    except ValueError:
        raise ValueError(variable + ' must be a positive integer') from None
    # Never expose command arguments, credential output or provider diagnostics.
    kwargs.setdefault('stdout', subprocess.PIPE)
    kwargs.setdefault('stderr', subprocess.PIPE)
    try:
        result = subprocess.run(args, text=True, check=True, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'T33 preparation {operation} timed out after {timeout}s') from None
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f'T33 preparation {operation} failed: exit={error.returncode}') from None
    except OSError:
        raise RuntimeError(f'T33 preparation {operation} could not start') from None
    return (result.stdout or '').strip()


def identity():
    if run('git-status', ['/usr/bin/git', 'status', '--porcelain'], cwd=ROOT):
        raise ValueError('T33 preparation requires clean committed source')
    return run('git-revision', ['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT)


def prepare(out, ui_source, ui_dist):
    revision = identity()
    if out.exists():
        raise ValueError('T33 artifact directory must be new')
    tools = json.loads((HERE / 'tools.lock.json').read_text())
    if tools['ui_revision'] != proof.UI_REVISION or run('ui-revision', ['/usr/bin/git', '-C', str(ui_source), 'rev-parse', 'HEAD']) != proof.UI_REVISION:
        raise ValueError('T33 UI identity mismatch')
    out.mkdir(parents=True)
    env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='identity-t33-build-') as tmp:
        stage = Path(tmp)
        # The canonical candidate builder accepts only an explicit BuildKit secret. Resolve the
        # existing credential without printing it or exposing it to compilation/runtime steps.
        if not env.get('SYSTEM_ACCESSTOKEN') and not env.get('IDENTITY_GIT_AUTH_HEADER_FILE'):
            result = run('git-credential', ['/usr/bin/git', 'credential', 'fill'], cwd=ROOT,
                input='protocol=https\nhost=dev.azure.com\npath=shengming0923/rss/_git/rss\n\n')
            fields = dict(line.split('=', 1) for line in result.splitlines() if '=' in line)
            if fields.get('password'):
                import base64
                encoded = base64.b64encode((fields.get('username', '') + ':' + fields['password']).encode()).decode()
                header = stage / 'git-header'
                header.write_text('Authorization: Basic ' + encoded)
                header.chmod(0o600)
                env['IDENTITY_GIT_AUTH_HEADER_FILE'] = str(header)
        run('candidate-build', [sys.executable, str(ROOT / 'hack/release.py'), '--output', str(out / 'candidate'),
                        '--ui-source', str(ui_source), '--ui-dist', str(ui_dist)], cwd=ROOT, env=env, budget='build')
        archive = stage / 'source.tar'
        with archive.open('wb') as stream:
            run('source-archive', ['/usr/bin/git', 'archive', revision], cwd=ROOT, stdout=stream)
        source = stage / 'source'
        source.mkdir()
        with tarfile.open(archive) as stream:
            stream.extractall(source, filter='data')
        providers = json.loads((source / 'deployment/providers.lock.json').read_text())
        run('consumer-build', ['docker', 'buildx', 'build', '--platform', 'linux/amd64',
                        '-f', str(source / 't3/identity-federated-sso/consumer.Dockerfile'),
                        '--build-arg', 'RUST_IMAGE=' + providers['rust'], '--output',
                        'type=local,dest=' + str(out / 'consumer'), str(source)], budget='build')
        browser_name = 'rss-identity/t33-browser:' + revision
        browser_archive = out / 'browser.oci.tar'
        browser_source = source / 't3/identity-federated-sso'
        run('browser-build', ['docker', 'buildx', 'build', '-f', str(browser_source / 'browser.Dockerfile'),
                        '--build-arg', 'BROWSER_IMAGE=' + tools['browser'], '--tag', browser_name,
                        '--provenance=false', '--output', 'type=oci,dest=' + str(browser_archive),
                        str(browser_source)], budget='build')
        run('browser-load', ['docker', 'load', '-i', str(browser_archive)], budget='transfer')
        inspected = json.loads(run('browser-inspect', ['docker', 'image', 'inspect', browser_name]))[0]
        (out / 'runner').mkdir()
        shutil.copy(browser_source / 'browser.mjs', out / 'runner/browser.mjs')
        c = json.loads((out / 'candidate/candidate.json').read_text())
        provider_artifacts = {}
        (out / 'providers').mkdir()
        for key in sorted(proof.PROVIDERS):
            image = providers[key]
            run('provider-pull', ['docker', 'pull', image], budget='transfer')
            inspected_provider = json.loads(run('provider-inspect', ['docker', 'image', 'inspect', image]))[0]
            if not any(v.endswith('@' + image.split('@')[1]) for v in inspected_provider.get('RepoDigests', [])):
                raise ValueError('provider registry identity mismatch')
            provider_archive = out / 'providers' / (key + '.tar')
            run('provider-save', ['docker', 'save', '-o', str(provider_archive), inspected_provider['Id']], budget='transfer')
            provider_artifacts[key] = {'source': image, 'image_id': inspected_provider['Id'],
                'platform': inspected_provider['Os'] + '/' + inspected_provider['Architecture'],
                'archive_sha256': proof.sha(provider_archive)}
        lock = json.loads((browser_source / 'package-lock.json').read_text())
        playwright = lock['packages']['node_modules/@playwright/test']['version']
        if playwright != lock['packages']['node_modules/playwright']['version'] or ':' + 'v' + playwright + '-noble@' not in tools['browser']:
            raise ValueError('browser tool lock mismatch')
        record = {
            'format_version': 1, 'revision': revision, 'ui_revision': proof.UI_REVISION,
            'candidate_sha256': proof.sha(out / 'candidate/candidate.json'),
            'providers': provider_artifacts,
            'consumer': {'revision': revision, 'target': 'x86_64-unknown-linux-gnu',
                         'sha256': proof.sha(out / 'consumer/identity-federated-t3-consumer'),
                         'lock_sha256': proof.sha(source / 'tests/consumer/Cargo.lock'),
                         'manifest_sha256': proof.sha(source / 'tests/consumer/Cargo.toml'),
                         'source_archive_sha256': proof.sha(archive),
                         'toolchain': (out / 'consumer/toolchain.txt').read_text()},
            'browser': {'image': browser_name, 'image_id': inspected['Id'],
                        'platform': inspected['Os'] + '/' + inspected['Architecture'],
                        'base': tools['browser'], 'playwright': playwright, 'archive_sha256': proof.sha(browser_archive),
                        'lock_sha256': proof.sha(browser_source / 'package-lock.json')},
            'files': {name: proof.sha(out / name) for name in [
                'runner/browser.mjs', 'candidate/deploy.py', 'candidate/deployment/providers.lock.json',
                'candidate/deployment/example.json', 'candidate/deployment/keycloak-totp.json']},
        }
        if identity() != revision or c['revision'] != revision:
            raise ValueError('source changed during T33 preparation')
        (out / 't33.json').write_text(json.dumps(record, indent=2) + '\n')
        digest = proof.sha(out / 't33.json')
        proof.load_artifacts(out, revision, digest)
        print('T33_ARTIFACTS_SHA256=' + digest, flush=True)
        print('T33 immutable artifacts prepared: ' + revision)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=nonempty_path)
    parser.add_argument('--ui-source', required=True, type=nonempty_path)
    parser.add_argument('--ui-dist', required=True, type=nonempty_path)
    args = parser.parse_args()
    with cancellation():
        prepare(args.output.resolve(), args.ui_source.resolve(), args.ui_dist.resolve())
