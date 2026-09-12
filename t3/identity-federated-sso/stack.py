"""Disposable delivery of the unmodified candidate Compose topology and test-only observers."""
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import uuid
import proof

TENANTS = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222']
ORIGIN = 'https://identity.t33.test'
IDP = 'https://sso.t33.test'
PRODUCT = 'https://product.t33.test'
VALIDATION = 'https://validation.t33.test'
HOST, IDP_HOST, PRODUCT_HOST, VALIDATION_HOST = [urlsplit(v).hostname for v in (ORIGIN, IDP, PRODUCT, VALIDATION)]
SENSITIVE = set()

def redact(value):
    for secret in sorted(SENSITIVE, key=len, reverse=True):
        if secret:
            value = value.replace(secret, '<redacted>')
    value = re.sub(r'(https?://[^\s?]+)\?[^\s]+', r'\1?<redacted>', value)
    value = re.sub(r'(?i)(authorization|password|cookie|token|verifier|secret)(\s*[:=]\s*)[^\n]+', r'\1\2<redacted>', value)
    return value[-4096:]



def command(args, *, timeout=180, input=None, cwd=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout, cwd=cwd)
    if result.returncode:
        raise RuntimeError('T33 command failed: ' + ' '.join(str(v) for v in args[:3]) + ' exit=' + str(result.returncode) + ': ' + redact(result.stderr))
    return result.stdout.strip()


def docker(*args, **kwargs):
    return command(['docker', *map(str, args)], **kwargs)


def wait(check, stage, seconds=180):
    end = time.monotonic() + seconds
    last = 'not ready'
    while time.monotonic() < end:
        try:
            if check():
                return
        except (RuntimeError, subprocess.SubprocessError, ValueError) as error:
            last = redact(str(error))
        time.sleep(1)
    raise RuntimeError('T33 readiness failed: ' + stage + ': ' + last)


class Stack:
    def __init__(self, artifacts, output, record, candidate):
        self.artifacts, self.output = artifacts, output
        self.record, self.candidate = record, candidate
        self.name = 'identity-t33-' + uuid.uuid4().hex[:10]
        self.volumes, self.containers = [], []
        self.network_created = False
        self.compose_created = False
        self.secrets = []
        self.image = record['browser']['image_id']
        self.runtime = output / 'private'
        self.runtime.mkdir(mode=0o700)
        self.inputs = self.runtime / 'input'
        self.inputs.mkdir(mode=0o700)
        self.channel = self.runtime / 'channel'
        self.channel.mkdir(mode=0o700)
        self.compose_path = self.runtime / 'compose.json'
        self.work = self.name + '-work'
        self.consumer_network = self.name + '-consumer'
        self.snapshots = {}

    def compose(self, *args, **kwargs):
        return command(['docker', 'compose', '-p', self.name, '-f', str(self.compose_path), *args], **kwargs)

    def volume(self, name):
        self.volumes.append(name)
        docker('volume', 'create', '--label', 'rss.t33.run=' + self.name, name)
        return name

    def write(self, name, value):
        path = self.inputs / name
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        path.chmod(0o600)
        return '/srv/t33/input/' + name

    def ephemeral_secret(self, name):
        value = secrets.token_urlsafe(36)
        self.secrets.append(value)
        SENSITIVE.add(value)
        return self.write(name, value)

    def certificate(self, name, names):
        key, csr, crt = [self.inputs / (name + suffix) for suffix in ['.key', '.csr', '.crt']]
        command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + names[0], '-keyout', str(key), '-out', str(csr)])
        ext = self.inputs / (name + '.ext')
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join('DNS:' + n for n in names) + '\n')
        command(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(self.inputs / 'ca.crt'), '-CAkey', str(self.inputs / 'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', str(ext), '-out', str(crt)])
        key.chmod(0o600)
        SENSITIVE.add(key.read_text())
        self.secrets.append(key.read_text())
        return '/srv/t33/input/' + crt.name, '/srv/t33/input/' + key.name

    def subnets(self):
        ids = docker('network', 'ls', '-q').split()
        used = []
        if ids:
            for n in json.loads(docker('network', 'inspect', *ids)):
                used.extend(ipaddress.ip_network(x['Subnet']) for x in (n.get('IPAM', {}).get('Config') or []) if x.get('Subnet'))
        chosen = []
        for i in range(10, 240):
            net = ipaddress.ip_network(f'10.233.{i}.0/24')
            if not any(net.overlaps(n) for n in used if n.version == 4):
                chosen.append(net)
            if len(chosen) == 3:
                return chosen
        raise RuntimeError('T33 isolated network unavailable')

    def configure(self):
        back, proto, front = self.subnets()
        self.front = front
        data = json.loads((self.artifacts / 'candidate/deployment/example.json').read_text())
        def remap(value):
            if isinstance(value, dict):
                return {k: remap(v) for k, v in value.items()}
            if isinstance(value, list):
                return [remap(v) for v in value]
            if isinstance(value, str) and value.startswith('/srv/rss-identity/input/'):
                return self.ephemeral_secret(Path(value).name)
            return value
        data = remap(data)
        data['backend_subnet'], data['protocol_subnet'] = str(back), str(proto)
        data['consumer_network'] = self.consumer_network
        runtime = data['runtime']
        runtime['identity_origin'] = {'environment_id': self.name, 'config_version': 1,
                                     'identity_public_origin': ORIGIN, 'product_public_origin': PRODUCT}
        runtime['storage'] = {'target': list(uuid.uuid4().bytes), 'lineage': list(uuid.uuid4().bytes),
                              'tenants': [{'tenant_id': t, 'epoch': 1} for t in TENANTS]}
        runtime['public_gateway'], runtime['private_gateway'] = str(back[2]), str(back[3])
        runtime['hydra']['addresses'] = [str(proto[5]) + '/32']
        state_key = secrets.token_hex(32)
        SENSITIVE.add(state_key); self.secrets.append(state_key)
        runtime['oidc']['state_key_file'] = self.write('state-key-hex', state_key)
        runtime['oidc']['providers'] = []
        runtime['hydra']['clients'] = []
        for index, tenant in enumerate(TENANTS):
            name = ['alpha', 'beta'][index]
            runtime['oidc']['providers'].append({'tenant_id': tenant, 'issuer': IDP + '/realms/' + name,
                'client_id': 'identity-' + name, 'secret_ref': name + '@1',
                'secret_file': self.ephemeral_secret('idp-' + name), 'addresses': [str(proto[2]) + '/32'], 'keycloak_totp': False})
            runtime['hydra']['clients'].append({'tenant_id': tenant, 'client_id': 't33-' + name,
                'audience': 't33-' + name + '-api', 'config_version': 1,
                'validation_secret_file': self.ephemeral_secret('validation-' + name),
                'oidc_secret_file': self.ephemeral_secret('oidc-' + name)})
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Identity T33 CA',
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                 '-keyout', str(self.inputs / 'ca.key'), '-out', str(self.inputs / 'ca.crt')])
        (self.inputs / 'ca.key').chmod(0o600)
        ca = '/srv/t33/input/ca.crt'
        runtime['database']['ca_file'] = ca
        runtime['oidc']['ca_file'] = ca
        runtime['hydra']['ca_file'] = ca
        for key, names in [('tls', [HOST, IDP_HOST, PRODUCT_HOST, VALIDATION_HOST]),
                           ('keycloak', ['keycloak']), ('hydra_admin', ['hydra-admin']), ('postgres', ['postgres'])]:
            data[key + '_certificate_file'], data[key + '_key_file'] = self.certificate(key, names)
        password = 'T33-only-' + secrets.token_urlsafe(24)
        self.secrets.append(password)
        SENSITIVE.add(password)
        self.write('user-password', password)
        self.admins = [str(uuid.uuid5(uuid.NAMESPACE_URL, self.name + t)) for t in TENANTS]
        self.data = data
        self.write('deployment.json', data)
        self.browser_config = {'origin': ORIGIN, 'idp': IDP, 'product': PRODUCT, 'tenants': TENANTS,
            'admins': self.admins, 'password': password, 'providers': runtime['oidc']['providers'],
            'clients': runtime['hydra']['clients'], 'ca_file': '/input/ca.crt',
            'ui_revision': self.record['ui_revision'], 'playwright': self.record['browser']['playwright']}
        # Browser input contains fixture secrets only and is never copied to the public receipt.
        self.write('browser.json', self.browser_config)
        self.public_config = {'identity_origin': runtime['identity_origin'],
            'tenants': TENANTS, 'providers': [{k: v for k, v in p.items() if k != 'secret_file'} for p in runtime['oidc']['providers']],
            'clients': [{k: v for k, v in c.items() if not k.endswith('_file')} for c in runtime['hydra']['clients']],
            'lifetimes': {k: runtime['hydra'][k] for k in ['request_seconds', 'code_seconds', 'access_token_seconds', 'clock_skew_seconds']}}

    def root(self, script, *, volumes=(), input=None):
        name = self.name + '-stage-' + uuid.uuid4().hex[:8]
        self.containers.append(name)
        return docker('run', '-i', '--rm', '--pull', 'never', '--name', name, '--user', '0:0', '--network', 'none', '--entrypoint', 'python3',
                      '-v', self.work + ':/srv/t33', '-v', str(self.artifacts) + ':/artifacts:ro',
                      *[v for mount in volumes for v in ['-v', mount]], self.image, '-c', script, input=input)

    def stage(self):
        self.volume(self.work)
        script = '''import os,shutil,subprocess,json
from pathlib import Path
shutil.copytree('/staging','/srv/t33/input')
for p in Path('/srv/t33/input').iterdir():
 os.chmod(p,0o644 if p.suffix=='.crt' else 0o600);os.chown(p,10001,10001)
os.chown('/srv/t33/input/keycloak.key',1000,0)
subprocess.run(['python3','/artifacts/candidate/deploy.py','--input','/srv/t33/input/deployment.json','--output','/srv/t33/rendered','--candidate','/artifacts/candidate/candidate.json'],check=True)
pw=Path('/srv/t33/input/user-password').read_text()
for p in Path('/srv/t33/rendered').glob('realm-*.json'):
 data=json.loads(p.read_text());data['users']=[{'username':name,'enabled':True,'email':email,'emailVerified':True,'firstName':'T33','lastName':'Fixture','credentials':[{'type':'password','value':pw,'temporary':False}]} for name,email in [('alice','alice@example.test'),('linker','linker@example.test'),('fresh','fresh@example.test')]]
 p.write_text(json.dumps(data));os.chown(p,1000,0)
print(Path('/srv/t33/rendered/compose.json').read_text())
'''
        self.config = json.loads(self.root(script, volumes=[str(self.inputs) + ':/staging:ro']))
        config = self.config
        services = config['services']
        services['public-gateway'].pop('ports')
        services['public-gateway']['networks']['front'] = {'ipv4_address': str(self.front[11])}
        config['networks']['front'] = {'internal': True, 'ipam': {'config': [{'subnet': str(self.front)}]}}
        services['private-gateway']['networks']['consumer']['aliases'].append(VALIDATION_HOST)
        # One test-only public ingress gives the real gateway its external port-443 mapping.
        # It never routes Identity API requests directly to the application.
        front_config = '''pid /tmp/nginx.pid; error_log stderr crit; events {} http { access_log off; error_log stderr crit; resolver 127.0.0.11 ipv6=off;
client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;
ssl_certificate /run/input/tls.crt; ssl_certificate_key /run/input/tls.key; ssl_protocols TLSv1.2 TLSv1.3;
server { listen 443 ssl; server_name @IDENTITY@ @IDP@; location / { proxy_ssl_verify on; proxy_ssl_trusted_certificate /run/input/ca.crt; proxy_ssl_server_name on; proxy_ssl_name $host; proxy_set_header Host $host; proxy_pass https://public-gateway:8443; } }
server { listen 443 ssl; server_name @PRODUCT@; location / { proxy_set_header Host $host; set $consumer t33-consumer:8080; proxy_pass http://$consumer; } } }
'''.replace('@IDENTITY@', HOST).replace('@IDP@', IDP_HOST).replace('@PRODUCT@', PRODUCT_HOST)
        consumer_config = {'listen': '0.0.0.0:8080', 'product_origin': PRODUCT, 'issuer': ORIGIN + '/oidc',
            'validation_origin': VALIDATION, 'public_address': str(self.front[10]) + ':443',
            'ca_file': '/run/input/ca.crt', 'clients': [{**c,
                'oidc_secret_file': '/run/input/' + Path(c['oidc_secret_file']).name,
                'validation_secret_file': '/run/input/' + Path(c['validation_secret_file']).name}
                for c in self.data['runtime']['hydra']['clients']]}
        for c in consumer_config['clients']:
            c.pop('config_version')
        self.root("from pathlib import Path;import json,sys,os\nv=json.load(sys.stdin)\nfor k,x in v.items():\n p=Path('/srv/t33/input')/k;p.write_text(x);p.chmod(0o600);os.chown(p,10001,10001)",
                  input=json.dumps({'front.conf': front_config, 'consumer.json': json.dumps(consumer_config)}))
        def bind(source, target):
            return {'type': 'bind', 'source': source, 'target': target, 'read_only': True}
        consumer_files = ['ca.crt', 'consumer.json'] + [Path(c[k]).name for c in self.data['runtime']['hydra']['clients'] for k in ['oidc_secret_file', 'validation_secret_file']]
        services['t33-consumer'] = {'image': self.candidate['providers']['runtime'], 'platform': 'linux/amd64', 'user': '10001:10001',
            'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
            'entrypoint': ['/artifact/identity-federated-t3-consumer', '/run/input/consumer.json'],
            'volumes': [bind('/srv/t33/input/' + n, '/run/input/' + n) for n in consumer_files] +
                       [bind(str(self.artifacts / 'consumer'), '/artifact')],
            'networks': ['front', 'consumer'], 'tmpfs': ['/tmp:rw,noexec,nosuid,size=64m']}
        services['t33-front'] = {'image': self.candidate['providers']['nginx'], 'user': '10001:10001',
            'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
            'sysctls': {'net.ipv4.ip_unprivileged_port_start': '0'}, 'tmpfs': ['/tmp:rw,noexec,nosuid,size=64m'],
            'entrypoint': ['nginx', '-e', 'stderr', '-c', '/run/config/front.conf', '-g', 'daemon off;'],
            'volumes': [bind('/srv/t33/input/' + n, '/run/input/' + n) for n in ['tls.crt', 'tls.key', 'ca.crt']] +
                       [bind('/srv/t33/input/front.conf', '/run/config/front.conf')],
            'networks': {'front': {'ipv4_address': str(self.front[10]), 'aliases': [HOST, IDP_HOST, PRODUCT_HOST]}}}
        # Docker Desktop cannot bind the renderer's Linux-owned files directly from macOS.
        # Deliver each service's exact declared files through separate read-only volumes;
        # a service never receives another service's credential files.
        groups = []
        for name, service in services.items():
            by_parent = {}
            keep = []
            for mount in service.get('volumes', []):
                if mount.get('type') == 'bind' and mount['source'].startswith('/srv/t33/'):
                    by_parent.setdefault(str(Path(mount['target']).parent), []).append(mount)
                else:
                    keep.append(mount)
            for index, (parent, mounts) in enumerate(by_parent.items()):
                logical = 't33-' + name + '-' + str(index)
                volume = self.volume(self.name + '-' + logical)
                config['volumes'][logical] = {'external': True, 'name': volume}
                keep.append({'type': 'volume', 'source': logical, 'target': parent, 'read_only': True})
                groups.append((volume, mounts))
            service['volumes'] = keep
        for volume, mounts in groups:
            self.root("import json,sys,shutil,os\nfrom pathlib import Path\nfor m in json.load(sys.stdin):\n p=Path('/delivery')/Path(m['target']).name;shutil.copy2(m['source'],p);s=Path(m['source']).stat();os.chown(p,s.st_uid,s.st_gid)",
                      volumes=[volume + ':/delivery'], input=json.dumps(mounts))
        for service in services.values():
            service['pull_policy'] = 'never'
            if service['image'] in self.candidate['images'].values():
                service['platform'] = 'linux/amd64'
            else:
                for item in self.record['providers'].values():
                    if service['image'] == item['source']:
                        service['image'] = item['image_id']
                        service['platform'] = item['platform']
                        break
        self.compose_path.write_text(json.dumps(config))
        self.compose_path.chmod(0o600)
        self.network_created = True
        docker('network', 'create', '--label', 'rss.t33.run=' + self.name, self.consumer_network)
        self.compose_created = True

    def initialize(self):
        print('T33 stage: deployment', flush=True)
        self.compose('run', '--rm', 'volume-init')
        self.compose('up', '-d', 'postgres')
        self.compose('run', '--rm', 'migrate')
        self.compose('run', '--rm', 'hydra-migrate')
        self.compose('up', '-d', 'hydra', 'hydra-admin', 'keycloak')
        self.compose('run', '--rm', 'hydra-clients')
        # Keep the original tenant-scoped maintenance command and permission profile.
        for tenant, principal in zip(TENANTS, self.admins):
            cid = self.name + '-maintenance-' + tenant[:4]
            self.containers.append(cid)
            # The renderer's maintenance volume holds only maintenance credentials.
            service = self.config['services']['maintenance']
            mounts = []
            for mount in service['volumes']:
                source = self.config['volumes'][mount['source']]['name']
                mounts += ['-v', source + ':' + mount['target'] + ':ro']
            # Stage a separate config for the second tenant without changing any authority data.
            config_volume = next(self.config['volumes'][v['source']]['name'] for v in service['volumes'] if v['target'] == '/run/config')
            self.root("import json,sys,os\nfrom pathlib import Path\np=Path('/delivery/maintenance.json');v=json.loads(p.read_text());v['tenant_id']=sys.stdin.read().strip();p.write_text(json.dumps(v));p.chmod(0o600);os.chown(p,10001,10001)",
                      volumes=[config_volume + ':/delivery'], input=tenant)
            input_volume = next(self.config['volumes'][v['source']]['name'] for v in service['volumes'] if v['target'] == '/run/input')
            self.root("import shutil,os;shutil.copy2('/srv/t33/input/user-password','/delivery/init-password');os.chown('/delivery/init-password',10001,10001)", volumes=[input_volume + ':/delivery'])
            docker('run', '--rm', '--pull', 'never', '--name', cid, '--platform', 'linux/amd64', '--user', '10001:10001',
                   '--network', self.name + '_protocol', '--entrypoint', 'identity-admin', *mounts,
                   self.candidate['images']['operator'], '/run/config/maintenance.json', 'initialize', principal, 'admin', '/run/input/init-password')
        self.compose('up', '-d', 'identity', 'public-gateway', 'private-gateway')
        self.compose('up', '-d', 't33-front')
        wait(lambda: self.compose('exec', '-T', 't33-front', 'curl', '--fail', '--silent', '--max-time', '3', '--cacert', '/run/input/ca.crt', '--resolve', HOST + ':443:127.0.0.1', ORIGIN + '/oidc/.well-known/openid-configuration') != '', 'public OIDC ingress')
        self.compose('up', '-d', 't33-consumer')
        wait(lambda: self.compose('exec', '-T', 't33-front', 'curl', '--silent', '--max-time', '3', '--output', '/dev/null', '--write-out', '%{http_code}', '--cacert', '/run/input/ca.crt', '--resolve', PRODUCT_HOST + ':443:127.0.0.1', PRODUCT + '/ready') == '204', 'consumer HTTPS readiness')

    def sql(self, sql):
        return self.compose('exec', '-T', 'postgres', 'psql', '-X', '-U', 'postgres', '-d', 'identity', '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql)

    def events(self):
        rows = self.sql("SELECT coalesce(json_agg(envelope),'[]'::json) FROM rss_transactional_messaging.outbox")
        events = [json.loads(bytes(row['payload'])) for row in json.loads(rows)]
        proof.assert_safe(events, self.secrets)
        return events

    def control(self, request):
        action = request['action']
        if action in ('stop', 'start'):
            if request['service'] not in ('keycloak', 'hydra', 'private-gateway'):
                raise ValueError('unknown fault target')
            self.compose(action, request['service'])
            return {'result': 'ok'}
        if action == 'cleanup_snapshot':
            session = str(uuid.UUID(request['session_id']))
            rows = json.loads(self.sql("SELECT coalesce(json_agg(json_build_object('id',grant_id,'state',state,'horizon',horizon,'now',extract(epoch from clock_timestamp())::bigint)),'[]'::json) FROM identity_authority.downstream_grants WHERE session_id='" + session + "'"))
            if session not in self.snapshots and rows:
                self.snapshots[session] = rows
            known = self.snapshots.get(session, [])
            events = self.events()
            cleaned = {e.get('grant_id') for e in events if e.get('action') == 'cleaned'}
            return {'grants': rows, 'known': known, 'cleaned': sorted(str(g) for g in cleaned if g),
                    'now': int(self.sql('SELECT extract(epoch from clock_timestamp())::bigint'))}
        if action == 'events':
            events = self.events()
            return {'events': events}
        raise ValueError('unknown T33 control action')

    def run_browser(self):
        input_volume = self.volume(self.name + '-browser-input')
        channel_volume = self.volume(self.name + '-channel')
        self.root("import shutil,os\nfor n in ['browser.json','ca.crt']:\n shutil.copy2('/srv/t33/input/'+n,'/input/'+n);os.chown('/input/'+n,10001,10001)\nos.chown('/channel',10001,10001);os.chmod('/channel',0o700)",
                  volumes=[input_volume + ':/input', channel_volume + ':/channel'])
        control = self.name + '-control'
        browser = self.name + '-browser'
        flags = ['--pull', 'never', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp:rw,nosuid,size=1g']
        self.containers.append(control)
        docker('run', '-d', '--name', control, *flags, '--network', 'none', '-v', channel_volume + ':/channel',
               '--entrypoint', 'sleep', self.image, 'infinity')
        self.containers.append(browser)
        docker('run', '-d', '--name', browser, '--label', 'rss.t33.run=' + self.name, *flags,
               '--network', self.name + '_front', '--shm-size', '1g', '-e', 'NODE_EXTRA_CA_CERTS=/input/ca.crt',
               '-v', channel_volume + ':/out', '-v', input_volume + ':/input:ro', self.image)
        end = time.monotonic() + 2400
        processed = progress = None
        while time.monotonic() < end:
            observed = json.loads(docker('exec', control, 'python3', '-B', '-c',
                "import json;from pathlib import Path;print(json.dumps({n:json.loads(p.read_text()) for n in ['progress','request','result'] if (p:=Path('/channel')/(n+'.json')).exists()}))"))
            current = observed.get('progress', {}).get('stage')
            if current in proof.SCENARIOS and current != progress:
                progress = current
                print('T33 check passed: ' + current, flush=True)
            if 'result' in observed:
                value = observed['result']
                proof.assert_safe(value, self.secrets)
                wait(lambda: docker('inspect', '--format', '{{.State.Running}}', browser) == 'false', 'browser exit', seconds=30)
                if docker('inspect', '--format', '{{.State.ExitCode}}', browser) != '0':
                    value['result'] = 'failed'
                return value
            request = observed.get('request')
            if request and request['id'] != processed:
                processed = request['id']
                try:
                    response = {'id': processed, 'value': self.control(request)}
                except (RuntimeError, ValueError, subprocess.SubprocessError) as error:
                    response = {'id': processed, 'error': 'control_failed', 'action': request.get('action'), 'diagnostic': redact(str(error))}
                docker('exec', '-i', control, 'python3', '-B', '-c',
                    "import sys,os;from pathlib import Path;p=Path('/channel/response.tmp');p.write_text(sys.stdin.read());p.chmod(0o600);os.replace(p,'/channel/response.json')",
                    input=json.dumps(response))
            if docker('inspect', '--format', '{{.State.Running}}', browser) != 'true':
                raise RuntimeError('T33 browser exited without a result: ' + redact(docker('logs', '--tail', '30', browser)))
            time.sleep(.5)
        raise RuntimeError('T33 browser deadline exceeded')

    def diagnostics(self):
        results = []
        try:
            ids = self.compose('ps', '-a', '-q').split() if self.compose_created else []
            for cid in ids:
                value = json.loads(docker('inspect', cid))[0]
                state = value['State']
                logs = subprocess.run(['docker', 'logs', '--tail', '15', cid], capture_output=True, text=True, timeout=10)
                results.append({'service': value['Config']['Labels'].get('com.docker.compose.service', 'unknown'),
                    'state': state['Status'], 'exit_code': state['ExitCode'],
                    'health': state.get('Health', {}).get('Status'),
                    'health_diagnostics': [redact(v.get('Output', '')) for v in state.get('Health', {}).get('Log', [])[-2:]],
                    'summary': redact(logs.stdout + logs.stderr)})
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            results.append({'state': 'diagnostic_unavailable', 'summary': redact(str(error))})
        return results

    def cleanup(self):
        failures = []
        for name in reversed(self.containers):
            try:
                result = subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)
                # --rm staging/maintenance containers have already been removed.
                if result.returncode and b'No such container' not in result.stderr:
                    failures.append('container')
            except (OSError, subprocess.SubprocessError):
                failures.append('container')
        if self.compose_created:
            try:
                self.compose('down', '--volumes', '--remove-orphans', timeout=240)
            except (RuntimeError, subprocess.SubprocessError):
                failures.append('compose')
        if self.network_created:
            try:
                docker('network', 'rm', self.consumer_network)
            except (RuntimeError, subprocess.SubprocessError):
                failures.append('network')
        for name in reversed(self.volumes):
            try:
                docker('volume', 'rm', name)
            except (RuntimeError, subprocess.SubprocessError):
                failures.append('volume')
        if not failures:
            shutil.rmtree(self.runtime)
        return not failures
