#!/usr/bin/env python3
"""Run the independent T33 deployment proof using prepared artifacts only."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import proof
from stack import Stack, docker, command

ROOT = Path(__file__).resolve().parents[2]


def execute(artifacts, output):
    if output.exists():
        raise ValueError('T33 output directory must be new')
    if command(['/usr/bin/git', 'status', '--porcelain'], timeout=30, cwd=ROOT):
        raise ValueError('T33 requires clean committed carrier')
    revision = command(['/usr/bin/git', 'rev-parse', 'HEAD'], timeout=30, cwd=ROOT)
    record, candidate = proof.load_artifacts(artifacts, revision)
    output.mkdir(parents=True, mode=0o700)
    stack = Stack(artifacts, output, record, candidate)
    result = {'result': 'failed', 'stage': 'environment', 'checks': []}
    clean = False
    try:
        for item in candidate['archives'].values():
            docker('load', '-i', artifacts / 'candidate' / item['file'])
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
        print('T33 failed: ' + (str(error) if isinstance(error, (RuntimeError, ValueError)) else type(error).__name__), flush=True)
        result['result'] = 'failed'
    finally:
        clean = stack.cleanup()
        public = {'format_version': 1, 'scenario': 'identity-federated-sso', 'revision': revision,
            'artifacts_sha256': proof.sha(artifacts / 't33.json'), 'candidate': candidate,
            'consumer': record['consumer'], 'browser_tool': record['browser'],
            'provider_config': getattr(stack, 'public_config', {}),
            'execution': {'docker': docker('version', '--format', '{{.Server.Version}}'),
                          'host_architecture': docker('info', '--format', '{{.Architecture}}'),
                          'candidate_platform': 'linux/amd64'},
            'observations': result, 'cleanup': {'result': 'passed' if clean else 'failed'}}
        proof.assert_safe(public, stack.secrets)
        (output / 'result.json').write_text(json.dumps(public, indent=2) + '\n')
    proof.finish(result['checks'], cleanup=clean)
    if result['result'] != 'passed' or command(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT) != revision or command(['/usr/bin/git', 'status', '--porcelain'], cwd=ROOT):
        raise ValueError('T33 execution identity changed or failed')
    print('T33 passed: ' + revision, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    execute(args.artifacts.resolve(), args.output.resolve())
