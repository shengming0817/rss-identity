"""Small, closed evidence contract for the Identity federated deployment scenario."""
import hashlib
import json
import re
from pathlib import Path

TOOLS = json.loads((Path(__file__).resolve().parent / 'tools.lock.json').read_text())
UI_REVISION = TOOLS['ui_revision']
PROVIDERS = {'postgres', 'keycloak', 'hydra', 'nginx', 'runtime'}
SCENARIOS = (
    'tenant_sso', 'consumer_sso', 'browser_binding', 'tenant_binding', 'callback_replay',
    'return_target', 'configuration_version', 'configuration_disabled', 'jit_disabled',
    'same_email', 'explicit_link', 'link_conflict', 'downstream_binding', 'central_logout',
    'provider_revocation', 'keycloak_unavailable', 'hydra_unavailable',
    'validation_unavailable', 'cleanup', 'events',
)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def verify_file(root, name, digest):
    if not isinstance(name, str) or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('unsafe artifact path')
    path = Path(root)
    for part in name.split('/'):
        path /= part
        if path.is_symlink():
            raise ValueError('artifact symlink')
    if not path.is_file() or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or sha(path) != digest:
        raise ValueError('artifact digest mismatch')
    return path


def verify_identity(value, revision):
    if (value.get('format_version') != 1 or value.get('revision') != revision
            or not re.fullmatch('[0-9a-f]{40}', revision) or value.get('ui_revision') != UI_REVISION):
        raise ValueError('T33 identity mismatch')


def verify_checks(checks):
    if not isinstance(checks, list) or len(checks) != len(SCENARIOS):
        raise ValueError('incomplete T33 checks')
    if {v.get('name') for v in checks} != set(SCENARIOS) or any(v.get('result') != 'passed' for v in checks):
        raise ValueError('T33 checks failed or repeated')


def finish(checks, *, cleanup):
    verify_checks(checks)
    if cleanup is not True:
        raise ValueError('T33 cleanup failed')


def assert_safe(value, secrets):
    text = json.dumps(value, ensure_ascii=False)
    if any(s and s in text for s in secrets) or re.search(r'(?i)[?&](code|state|nonce|access_token)=', text):
        raise ValueError('sensitive T33 evidence')
    forbidden = {'authorization', 'cookie', 'set-cookie', 'password', 'access_token', 'id_token',
                 'refresh_token', 'verifier', 'client_secret', 'validation_secret'}
    def visit(item):
        if isinstance(item, dict):
            if any(str(key).lower() in forbidden for key in item):
                raise ValueError('sensitive T33 field')
            for child in item.values():
                visit(child)
        elif isinstance(item, str) and any(s and s in item for s in secrets):
            raise ValueError('sensitive T33 evidence')
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(value)


def load_artifacts(root, revision, expected_sha256):
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('T33_ARTIFACTS_SHA256 must be externally pinned')
    root = Path(root).resolve(strict=True)
    record = json.loads(verify_file(root, 't33.json', expected_sha256).read_text())
    verify_identity(record, revision)
    for name, digest in record['files'].items():
        verify_file(root, name, digest)
    candidate_path = verify_file(root, 'candidate/candidate.json', record['candidate_sha256'])
    candidate = json.loads(candidate_path.read_text())
    if (candidate['format_version'] != 1 or candidate['revision'] != revision
            or candidate['platform'] != 'linux/amd64' or candidate['ui']['revision'] != UI_REVISION
            or set(candidate['images']) != {'server', 'operator', 'gateway'}
            or set(candidate['archives']) != {'server', 'operator', 'gateway'}):
        raise ValueError('candidate identity mismatch')
    for key, item in candidate['archives'].items():
        verify_file(root / 'candidate', item['file'], item['sha256'])
        if not candidate['images'][key].endswith('@' + item['manifest_digest']):
            raise ValueError('candidate manifest identity mismatch')
    if record['consumer']['revision'] != revision or record['consumer']['target'] != 'x86_64-unknown-linux-gnu':
        raise ValueError('consumer identity mismatch')
    verify_file(root, 'consumer/identity-federated-t3-consumer', record['consumer']['sha256'])
    verify_file(root, 'browser.oci.tar', record['browser']['archive_sha256'])
    if set(record['files']) != {'runner/browser.mjs', 'candidate/deploy.py', 'candidate/deployment/providers.lock.json',
                               'candidate/deployment/example.json', 'candidate/deployment/keycloak-totp.json'}:
        raise ValueError('T33 file identities incomplete')
    if set(record['providers']) != PROVIDERS:
        raise ValueError('runtime provider closure incomplete')
    for key, item in record['providers'].items():
        if item['source'] != candidate['providers'][key] or not re.fullmatch('sha256:[0-9a-f]{64}', item['image_id']):
            raise ValueError('runtime provider identity mismatch')
        verify_file(root, 'providers/' + key + '.tar', item['archive_sha256'])
    return record, candidate
