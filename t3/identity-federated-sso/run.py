#!/usr/bin/env python3
"""Run the independent T33 deployment proof using externally pinned prepared artifacts."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import signal
import subprocess
import proof
from stack import Stack, docker, command, redact

ROOT = Path(__file__).resolve().parents[2]


class Cancelled(RuntimeError):
    pass


@contextmanager
def cancellation():
    previous = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    interrupted = False
    def stop(signum, _frame):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise Cancelled('T33 execution interrupted: ' + signal.Signals(signum).name)
    try:
        for sig in previous:
            signal.signal(sig, stop)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def write_result(output, public, secrets):
    try:
        proof.assert_safe(public, secrets)
    except ValueError:
        public = {'format_version': 1, 'revision': public['revision'], 'observations':
                  {'result': 'failed', 'stage': 'evidence', 'failure': 'sensitive_material_rejected'},
                  'cleanup': public['cleanup']}
    target = output / 'result.tmp'
    target.write_text(json.dumps(public, indent=2) + '\n')
    target.chmod(0o600)
    target.replace(output / 'result.json')
    return public['observations']['result'] == 'passed'


def execute(artifacts, output, expected_sha256):
    if output.exists():
        raise ValueError('T33 output directory must be new')
    if command(['/usr/bin/git', 'status', '--porcelain'], timeout=30, cwd=ROOT):
        raise ValueError('T33 requires clean committed carrier')
    revision = command(['/usr/bin/git', 'rev-parse', 'HEAD'], timeout=30, cwd=ROOT)
    record, candidate = proof.load_artifacts(artifacts, revision, expected_sha256)
    output.mkdir(parents=True, mode=0o700)
    stack = Stack(artifacts, output, record, candidate)
    result = {'result': 'failed', 'stage': 'environment', 'checks': []}
    environment = {'docker': 'unavailable', 'host_architecture': 'unavailable', 'candidate_platform': 'linux/amd64'}
    clean = safe = False
    diagnostics = []
    try:
        environment['docker'] = docker('version', '--format', '{{.Server.Version}}')
        environment['host_architecture'] = docker('info', '--format', '{{.Architecture}}')
        for item in candidate['archives'].values():
            docker('load', '-i', artifacts / 'candidate' / item['file'])
        for name, item in record['providers'].items():
            docker('load', '-i', artifacts / 'providers' / (name + '.tar'))
            image = json.loads(docker('image', 'inspect', item['image_id']))[0]
            if image['Id'] != item['image_id'] or image['Os'] + '/' + image['Architecture'] != item['platform']:
                raise ValueError('runtime provider image identity mismatch')
        docker('load', '-i', artifacts / 'browser.oci.tar')
        if docker('image', 'inspect', '--format', '{{.Id}}', record['browser']['image']) != record['browser']['image_id']:
            raise ValueError('browser image identity mismatch')
        stack.configure()
        stack.stage()
        stack.initialize()
        result = stack.run_browser()
        if result['result'] != 'passed':
            raise ValueError('browser scenario failed')
        proof.verify_checks(result['checks'])
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        result['result'] = 'failed'
        result['diagnostic'] = redact(str(error))
        print('T33 failed: ' + result['diagnostic'], flush=True)
        diagnostics = stack.diagnostics()
    finally:
        try:
            clean = stack.cleanup()
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            diagnostics.append({'cleanup': 'unavailable', 'diagnostic': redact(str(error))})
        if not clean:
            result['result'] = 'failed'
        if result['result'] == 'passed':
            try:
                if command(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT) != revision or command(['/usr/bin/git', 'status', '--porcelain'], cwd=ROOT):
                    raise ValueError('carrier identity changed')
                proof.load_artifacts(artifacts, revision, expected_sha256)
            except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
                result['result'] = 'failed'
                result['diagnostic'] = redact(str(error))
        public = {'format_version': 1, 'scenario': 'identity-federated-sso', 'revision': revision,
            'artifacts_sha256': expected_sha256, 'candidate': candidate,
            'consumer': record['consumer'], 'browser_tool': record['browser'],
            'runtime_providers': record['providers'],
            'provider_config': getattr(stack, 'public_config', {}), 'execution': environment,
            'observations': result, 'diagnostics': diagnostics,
            'cleanup': {'result': 'passed' if clean else 'failed'}}
        safe = write_result(output, public, stack.secrets)
    proof.finish(result['checks'], cleanup=clean)
    if not safe or result['result'] != 'passed' or command(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT) != revision or command(['/usr/bin/git', 'status', '--porcelain'], cwd=ROOT):
        raise ValueError('T33 execution identity changed or failed')
    print('T33 passed: ' + revision, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--artifacts-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with cancellation():
        execute(args.artifacts.resolve(), args.output.resolve(), args.artifacts_sha256)
