"""Generate throwaway fixture inputs inside a private volume, then use the candidate renderer."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import uuid

ROOT = Path('/run/t32')
TENANT = '11111111-1111-4111-8111-111111111111'
IDENTITY = 'identity.t32.test'
PRODUCT = 'product.t32.test'


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def main():
    ROOT.chmod(0o700)
    inputs = ROOT / 'input'
    inputs.mkdir(mode=0o700)
    data = json.loads(Path('/candidate/deployment/example.json').read_text())

    def generate(value):
        if isinstance(value, dict):
            return {key: generate(child) for key, child in value.items()}
        if isinstance(value, list):
            return [generate(child) for child in value]
        if isinstance(value, str) and value.startswith('/srv/rss-identity/input/'):
            path = inputs / Path(value).name
            path.write_text(secrets.token_hex(32) if path.name == 'state-key-hex' else secrets.token_urlsafe(40))
            path.chmod(0o600)
            os.chown(path, 10001, 10001)
            return str(path)
        return value

    data = generate(data)
    runtime = data['runtime']
    runtime['identity_origin'].update(environment_id='t32-' + str(uuid.uuid4()),
                                      identity_public_origin='https://' + IDENTITY,
                                      product_public_origin='https://' + PRODUCT)
    runtime['storage'].update(target=list(secrets.token_bytes(16)), lineage=list(secrets.token_bytes(16)))
    provider = runtime['oidc']['providers'][0]
    provider['issuer'] = 'https://sso.t32.test/realms/identity'
    # Use non-overlapping networks allocated by the outer runner.
    backend, protocol, network = json.loads(Path('/allocation.json').read_text())
    data.update(backend_subnet=backend + '.0/24', protocol_subnet=protocol + '.0/24', consumer_network=network)
    runtime.update(public_gateway=backend + '.2', private_gateway=backend + '.3')
    provider['addresses'] = [protocol + '.2/32']
    runtime['hydra']['addresses'] = [protocol + '.5/32']
    ca = inputs / 'ca.pem'
    ca_key = inputs / 'ca.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
            '-subj', '/CN=Identity T32 temporary CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-keyout', str(ca_key), '-out', str(ca))
    ca_key.chmod(0o600)
    ca.chmod(0o644)
    for name, hosts, uid, gid in [('public', [IDENTITY, 'sso.t32.test'], 10001, 10001),
                                   ('postgres', ['postgres'], 10001, 10001),
                                   ('hydra-admin', ['hydra-admin'], 10001, 10001),
                                   ('keycloak', ['keycloak'], 1000, 0),
                                   ('product', [PRODUCT], 10001, 10001)]:
        key, cert, csr, ext = [inputs / (name + suffix) for suffix in ('.key', '.pem', '.csr', '.ext')]
        command('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + hosts[0],
                '-keyout', str(key), '-out', str(csr))
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join('DNS:' + host for host in hosts))
        command('openssl', 'x509', '-req', '-days', '2', '-in', str(csr), '-CA', str(ca),
                '-CAkey', str(ca_key), '-CAcreateserial', '-extfile', str(ext), '-out', str(cert))
        key.chmod(0o600)
        cert.chmod(0o644)
        os.chown(key, uid, gid)
    for name in ('database-ca.pem', 'keycloak-ca.pem', 'hydra-ca.pem'):
        (inputs / name).write_bytes(ca.read_bytes())
        (inputs / name).chmod(0o644)
    principal = str(uuid.uuid4())
    for name in ('admin-password', 'member-password', 'new-password'):
        path = inputs / name
        path.write_text(secrets.token_urlsafe(32))
        path.chmod(0o600)
        os.chown(path, 10001, 10001)
    spec = importlib.util.spec_from_file_location('candidate_deploy', '/candidate/deploy.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.render(data, ROOT / 'rendered', json.loads(Path('/candidate/candidate.json').read_text()))
    public = {'tenant': TENANT, 'admin_principal': principal,
              'identity_origin': 'https://' + IDENTITY, 'product_origin': 'https://' + PRODUCT,
              'client_id': runtime['hydra']['clients'][0]['client_id'],
              'audience': runtime['hydra']['clients'][0]['audience'],
              'grant_horizon_seconds': sum(runtime['hydra'][key] for key in
                  ('request_seconds', 'code_seconds', 'access_token_seconds', 'clock_skew_seconds')),
              'identity_origin_config': runtime['identity_origin'], 'storage': runtime['storage']}
    (ROOT / 'public.json').write_text(json.dumps(public))
    (ROOT / 'public.json').chmod(0o644)


if __name__ == '__main__':
    main()
