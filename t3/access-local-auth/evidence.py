"""Small acceptance checks; candidate.json remains the artifact identity owner."""
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

SCENARIOS = ('login', 'protection', 'refresh', 'logout', 'logout_all', 'password',
             'disable', 'storage_failure', 'cleanup_failure', 'events')
PUBLIC_FIELDS = {'stage', 'status', 'passed', 'online', 'remaining', 'control_status',
                 'correlation_id', 'action', 'tenant', 'principal', 'session_id',
                 'grant_id', 'epoch', 'seq', 'contract', 'version', 'count', 'steps',
                 'browser_version', 'events', 'failure', 'identity_status'}


class Refused(ValueError):
    """Only code-owned, non-secret diagnostics cross the harness boundary."""


def require(value, message):
    if not value:
        raise Refused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_file(path, digest):
    require(re.fullmatch('[a-f0-9]{64}', digest) and not path.is_symlink()
            and path.is_file() and sha(path) == digest, 'artifact_digest_mismatch')


def check_steps(steps):
    require(set(steps) == set(SCENARIOS), 'incomplete_scenarios')
    require(all(v.get('passed') is True for v in steps.values()), 'scenario_failed')


def check_revocation(result, control_status, remaining):
    require(result.get('online') is True and result.get('status') in (401, 403)
            and control_status == 200 and remaining > 0, 'unproven_online_revocation')


def check_public(value):
    if isinstance(value, dict):
        require(set(value) <= PUBLIC_FIELDS, 'unsafe_evidence_field')
        for key, child in value.items():
            if key == 'steps':
                require(isinstance(child, dict) and set(child) <= set(SCENARIOS), 'unsafe_scenario')
                for step in child.values():
                    check_public(step)
            else:
                check_public(child)
    elif isinstance(value, list):
        for child in value:
            check_public(child)
    elif isinstance(value, str):
        require(len(value) <= 160 and not any(x in value for x in ('Bearer ', '__Host-', '://')),
                'unsafe_evidence_value')
    else:
        require(value is None or type(value) in (int, bool, float), 'unsafe_evidence_type')


def candidate(directory, repository):
    path = directory / 'candidate.json'
    data = json.loads(path.read_text())
    require(data['format_version'] == 1 and data['platform'] == 'linux/amd64', 'unsupported_candidate')
    require(re.fullmatch('[a-f0-9]{40}', data['revision']), 'invalid_revision')
    require(set(data['archives']) == set(data['images']) == {'server', 'operator', 'gateway'},
            'incomplete_candidate')
    require(set(data['binaries']) == {'identity-admin', 'identity-server', 'identity-clients', 'identity-migrate'},
            'incomplete_binaries')
    for kind, item in data['archives'].items():
        require(item['file'] == kind + '.oci.tar', 'invalid_archive_path')
        archive = directory / item['file']
        check_file(archive, item['sha256'])
        require(data['images'][kind] == f"rss-identity/{kind}:{data['revision']}@{item['manifest_digest']}",
                'image_identity_mismatch')
        with tarfile.open(archive) as tar:
            digest = item['manifest_digest'].removeprefix('sha256:')
            raw = tar.extractfile('blobs/sha256/' + digest).read()
            require(hashlib.sha256(raw).hexdigest() == digest, 'manifest_digest_mismatch')
            manifest = json.loads(raw)
            raw = tar.extractfile('blobs/sha256/' + manifest['config']['digest'].split(':')[1]).read()
            require('sha256:' + hashlib.sha256(raw).hexdigest() == manifest['config']['digest'], 'config_digest_mismatch')
            config = json.loads(raw)
            require(config['architecture'] == 'amd64' and config['os'] == 'linux'
                    and config['config']['User'] == '10001:10001'
                    and config['config']['Labels']['org.opencontainers.image.revision'] == data['revision'],
                    'runtime_identity_mismatch')
    for name, digest in data['binaries'].items():
        require(name in ('identity-admin', 'identity-server', 'identity-clients', 'identity-migrate'),
                'unknown_binary')
        check_file(directory / 'binaries' / name, digest)
    # The existing manifest does not hash the deployment helper: bind it to its exact source commit.
    for local, source in [('deploy.py', 'hack/deploy.py'), ('deployment/example.json', 'deployment/example.json'),
                          ('deployment/providers.lock.json', 'deployment/providers.lock.json')]:
        expected = subprocess.check_output(['/usr/bin/git', '-C', str(repository), 'show', data['revision'] + ':' + source])
        require((directory / local).read_bytes() == expected, 'candidate_deployment_source_mismatch')
    require(json.loads((directory / 'deployment/providers.lock.json').read_text()) == data['providers'],
            'provider_identity_mismatch')
    return data
