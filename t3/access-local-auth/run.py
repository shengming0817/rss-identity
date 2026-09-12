#!/usr/bin/env python3
"""Run the immutable Identity candidate's local-auth journey in owned Docker resources."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

import evidence

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / 'hack'))
from bounded_process import run as bounded_run


class CommandFailed(evidence.Refused):
    def __init__(self, operation, code, stderr):
        super().__init__('command_failed')
        # Keep only fixed diagnostics, never the command, provider logs or secret-bearing response.
        categories = ('invalid interpolation format', 'invalid mount config', 'no matching manifest',
                      'permission denied', 'network is unreachable', 'address already in use',
                      'connection refused', 'unhealthy', 'pull access denied', 'no such file', 'timed out')
        self.facts = {'operation': operation, 'exit_code': code,
                      'diagnostic': next((v.replace(' ', '_') for v in categories if v in stderr.lower()), 'command_error'),
                      'stderr_sha256': hashlib.sha256(stderr.encode()).hexdigest()}


def execute(args, *, timeout=120, input=None, operation=None):
    operation = operation or '_'.join(Path(a).name for a in args[:2])
    try:
        result = bounded_run(args, timeout=timeout, input=input, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        error = CommandFailed(operation, None, 'timed out')
        error.facts['timeout_seconds'] = timeout
        raise error from None
    if result.returncode:
        raise CommandFailed(operation, result.returncode, result.stderr)
    return result.stdout.strip()


def carrier_sources(repository, revision):
    paths = execute(['/usr/bin/git', '-C', str(repository), 'ls-tree', '-r', '--name-only', revision,
                     't3/access-local-auth', 'hack/bounded_process.py']).splitlines()
    sources = {}
    for name in paths:
        raw = subprocess.check_output(['/usr/bin/git', '-C', str(repository), 'show', revision + ':' + name])
        evidence.check_source(repository / name, raw)
        sources[name] = raw
    return sources


def write_record(path, record):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x') as stream:
            os.chmod(temporary, 0o600)
            json.dump(record, stream, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)



def docker(*args, **kwargs):
    return execute(['docker', *args], **kwargs)


def allocation():
    ids = docker('network', 'ls', '-q').split()
    networks = json.loads(docker('network', 'inspect', *ids)) if ids else []
    used = [ipaddress.ip_network(c['Subnet']) for n in networks for c in (n['IPAM'].get('Config') or []) if 'Subnet' in c]
    for number in range(80, 220, 2):
        pair = [ipaddress.ip_network(f'10.234.{i}.0/24') for i in (number, number + 1)]
        if not any(a.overlaps(b) for a in pair for b in used if b.version == 4):
            return [f'10.234.{number}', f'10.234.{number+1}']
    raise evidence.Refused('no_isolated_subnets')


def clean_owned(project, volume, control, network, tag, process):
    cleanup = []
    def attempt(kind, identifier, operation, fn):
        try:
            fn()
        except (Exception, SystemExit) as error:
            cleanup.append({'kind': kind, 'id': identifier, 'operation': operation,
                            'error_code': str(error) if isinstance(error, evidence.Refused) else type(error).__name__})
    if process and process.poll() is None:
        attempt('process', str(process.pid), 'kill', lambda: (process.kill(), process.wait(timeout=10)))
    # Each resource is attempted independently; only owned labels/names are eligible.
    for kind, args_list in [('container', ['ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project]),
                            ('network', ['network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project]),
                            ('volume', ['volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project])]:
        ids = []
        attempt(kind, project, 'list', lambda: ids.extend(docker(*args_list).split()))
        for identifier in ids:
            if kind == 'container':
                def remove_container():
                    if json.loads(docker('inspect', identifier))[0]['State'].get('Paused'):
                        docker('unpause', identifier, timeout=20)
                    docker('rm', '-f', identifier)
                attempt(kind, identifier, 'remove', remove_container)
            else:
                attempt(kind, identifier, 'remove', lambda: docker(kind, 'rm', identifier))
    for kind, name in [('network', network), ('volume', volume), ('volume', control), ('image', tag)]:
        def remove_named():
            result = bounded_run(['docker', kind, 'inspect', name], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                docker(kind, 'rm', name, timeout=30)
            elif not any(v in result.stderr.lower() for v in ('not found', 'no such')):
                raise evidence.Refused('inspect_failed')
        attempt(kind, name, 'remove', remove_named)
    return cleanup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--record', type=Path, required=True)
    args = parser.parse_args()
    args.record.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the output before doing work; an existing receipt is never overwritten.
    try:
        with args.record.open('x') as output:
            os.chmod(args.record, 0o600)
            output.write('{}\n')
    except FileExistsError:
        print('T32 refused: record_must_be_new', flush=True)
        return 2
    project = 'identity-t32-' + uuid.uuid4().hex[:12]
    volume, control, network = (project + suffix for suffix in ('-input', '-control', '-consumer'))
    tag = project + ':controller'
    record = {'issue': 2341, 'project': project, 'steps': {},
              'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'passed': False}
    compose = None
    process = None
    stage = 'candidate_preflight'
    started_resources = False
    def interrupted(signum, _frame):
        raise evidence.Refused('interrupted_' + str(signum))
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        source = args.candidate.resolve(strict=True)
        data = evidence.candidate(source, REPO)
        revision = execute(['/usr/bin/git', '-C', str(REPO), 'rev-parse', 'HEAD'])
        sources = carrier_sources(REPO, revision)
        record.update(candidate_manifest_sha256=evidence.sha(source / 'candidate.json'), candidate=data,
                      carrier_revision=revision,
                      carrier_files={name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()})
        schemas = {contract: 'sha256:' + hashlib.sha256(subprocess.check_output(
            ['/usr/bin/git', '-C', str(REPO), 'show', data['revision'] + ':crates/identity-postgres/src/' + filename])).hexdigest()
            for contract, (_, filename) in evidence.EVENT_SCHEMAS.items()}
        stage = 'candidate_load'
        started_resources = True
        print('T32: verify candidate and build isolated test controller', flush=True)
        for item in data['archives'].values():
            docker('load', '-i', str(source / item['file']), timeout=300)
        stage = 'controller_build'
        # Build from frozen Git bytes, never the live worktree or an output receipt.
        with tempfile.TemporaryDirectory(prefix=project + '-build-') as build:
            for name, raw in sources.items():
                if name.startswith('t3/access-local-auth/'):
                    (Path(build) / Path(name).name).write_bytes(raw)
            docker('build', '-t', tag, build, timeout=1200)
        image = json.loads(docker('image', 'inspect', tag))[0]['Id']
        record['controller_image'] = image
        stage = 'fixture_prepare'
        for name in (volume, control):
            docker('volume', 'create', '--label', 'identity.t32=' + project, name)
        docker('network', 'create', '--internal', '--label', 'identity.t32=' + project, network)
        with tempfile.TemporaryDirectory(prefix=project) as temp:
            root = Path(temp)
            alloc = allocation() + [network]
            (root / 'allocation.json').write_text(json.dumps(alloc))
            docker('run', '--rm', '--user', '0:0', '--network', 'none',
                   '-v', volume + ':/run/t32', '-v', control + ':/control',
                   '-v', str(source) + ':/candidate:ro', '-v', str(root / 'allocation.json') + ':/allocation.json:ro',
                   image, 'sh', '-ec', 'chown 10001:10001 /control; chmod 700 /control; python3 /carrier/prepare.py')

            def read_volume(path):
                return docker('run', '--rm', '--user', '0:0', '--network', 'none', '-v', volume + ':/run/t32:ro', image, 'cat', '/run/t32/' + path)

            configuration = json.loads(read_volume('public.json'))
            topology = json.loads(read_volume('rendered/compose.json'))
            record['configuration'] = configuration
            record['rendered_topology_sha256'] = hashlib.sha256(json.dumps(topology, sort_keys=True).encode()).hexdigest()
            topology['name'] = project
            topology['volumes']['fixture'] = {'external': True, 'name': volume}
            topology['volumes']['control'] = {'external': True, 'name': control}
            topology['networks']['browser'] = {'internal': True}
            topology['networks']['egress'] = {'internal': True}
            services = topology['services']
            for service in services.values():
                if service.get('image') in data['images'].values():
                    service['platform'] = 'linux/amd64'
                for mount in service.get('volumes', []):
                    if isinstance(mount, dict) and mount['type'] == 'bind':
                        relative = Path(mount['source']).relative_to('/run/t32').as_posix()
                        mount.update(type='volume', source='fixture', volume={'subpath': relative, 'nocopy': True})
            services['public-gateway'].pop('ports')
            services['public-gateway']['networks']['egress'] = {}

            def mount(path, target):
                return {'type': 'volume', 'source': 'fixture', 'target': target,
                        'read_only': True, 'volume': {'subpath': path, 'nocopy': True}}

            def fixture(command, networks, files):
                return {'image': image, 'user': '10001:10001', 'read_only': True,
                        'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                        'tmpfs': ['/tmp', '/home/t32:uid=10001,gid=10001,mode=0700'],
                        'sysctls': {'net.ipv4.ip_unprivileged_port_start': '0'},
                        'command': command, 'networks': networks,
                        'volumes': [mount(path, '/run/test/' + name) for path, name in files]}

            common = [('public.json', 'public.json'), ('input/ca.pem', 'ca.pem')]
            services['consumer'] = fixture(['node', '/carrier/consumer.mjs'],
                {'consumer': {}, 'egress': {}, 'browser': {'aliases': ['product.t32.test']}},
                common + [('input/mdm-validation-secret', 'validation-secret'), ('input/mdm-oidc-secret', 'oidc-secret'),
                          ('input/product.pem', 'product.pem'), ('input/product.key', 'product.key')])
            services['consumer']['volumes'].append({'type': 'volume', 'source': 'control', 'target': '/control'})
            # This is raw TCP forwarding: candidate TLS termination and all HTTP handling stay intact.
            services['ingress'] = fixture(['node', '/carrier/ingress.mjs'],
                {'browser': {'aliases': ['identity.t32.test', 'sso.t32.test']}, 'egress': {}}, [])
            services['browser'] = fixture(['sh', '-ec',
                'mkdir -p /home/t32/.pki/nssdb; certutil -N -d sql:/home/t32/.pki/nssdb --empty-password; '
                'certutil -A -d sql:/home/t32/.pki/nssdb -n t32 -t "C,," -i /run/test/ca.pem; node /carrier/scenario.mjs'],
                ['browser'], common + [(f'input/{name}', name) for name in ('admin-password', 'member-password', 'new-password')])
            services['browser']['volumes'].append({'type': 'volume', 'source': 'control', 'target': '/control'})
            services['browser']['profiles'] = ['test']
            services['browser']['environment'] = {'NODE_EXTRA_CA_CERTS': '/run/test/ca.pem'}
            config_file = root / 'compose.json'
            config_file.write_text(json.dumps(topology))
            compose = ['docker', 'compose', '-p', project, '-f', str(config_file)]

            def dc(*command, timeout=120):
                return execute(compose + list(command), timeout=timeout, operation='compose_' + '_'.join(command[:3]))

            def query():
                sql = "BEGIN READ ONLY; SELECT COALESCE(json_agg(json_build_object('seq',seq,'contract',envelope->>'contract','version',envelope->'version','schema',envelope->>'schema','payload',envelope->'payload') ORDER BY seq),'[]'::json) FROM rss_transactional_messaging.outbox; COMMIT;"
                raw = dc('exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'identity', '-Atq', '-c', sql)
                events = json.loads(raw)
                return [evidence.project_event(event, configuration['tenant'], schemas) for event in events]

            print('T32: install candidate providers, migrations and administrator', flush=True)
            stage = 'volume_initialize'
            dc('run', '--rm', 'volume-init')
            stage = 'postgres_start'
            dc('up', '-d', '--wait', 'postgres')
            stage = 'identity_migrate'
            dc('run', '--rm', 'migrate')
            stage = 'hydra_migrate'
            dc('run', '--rm', 'hydra-migrate')
            stage = 'providers_start'
            dc('up', '-d', 'hydra', 'hydra-admin', 'keycloak')
            stage = 'clients_initialize'
            dc('run', '--rm', 'hydra-clients')
            services['maintenance']['volumes'].append(mount('input/admin-password', '/run/input/new-password'))
            config_file.write_text(json.dumps(topology))
            stage = 'administrator_initialize'
            dc('run', '--rm', 'maintenance', 'initialize', configuration['admin_principal'], 'admin', '/run/input/new-password')
            stage = 'services_start'
            dc('up', '-d', '--wait', 'identity', 'public-gateway', 'private-gateway', 'consumer', 'ingress', timeout=180)
            observed = {}
            for name in ('identity', 'public-gateway', 'private-gateway', 'postgres', 'hydra', 'keycloak', 'consumer', 'ingress'):
                cid = dc('ps', '-q', name)
                instance = json.loads(docker('inspect', cid))[0]
                image_config = json.loads(docker('image', 'inspect', instance['Image']))[0]
                evidence.require(instance['Config']['Image'] == services[name]['image'], 'running_image_mismatch')
                if name in ('consumer', 'ingress'):
                    evidence.require(instance['Image'] == image, 'controller_image_mismatch')
                observed[name] = {'reference': instance['Config']['Image'], 'image_id': instance['Image'],
                                  'architecture': image_config['Architecture'], 'user': instance['Config']['User']}
            record['running_images'] = observed
            record['steps'] = {}
            process = subprocess.Popen(compose + ['run', '--rm', '-T', '--name', project + '-browser', 'browser'],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, bufsize=1)
            while True:
                readable, _, _ = select.select([process.stdout], [], [], 180)
                evidence.require(readable, 'browser_stage_timeout')
                line = process.stdout.readline()
                if not line:
                    break
                message = json.loads(line)
                operation = message.pop('operation')
                if operation == 'stage':
                    if 'browser_image' not in record:
                        instance = json.loads(docker('inspect', project + '-browser'))[0]
                        evidence.require(instance['Image'] == image, 'browser_image_mismatch')
                        record['browser_image'] = instance['Image']
                    stage = message['stage']
                    evidence.require(stage in evidence.SCENARIOS, 'unknown_stage')
                    print('T32: ' + stage, flush=True)
                    answer = {}
                elif operation == 'events':
                    answer = query()
                elif operation == 'fault':
                    service, action = message['service'], message['action']
                    evidence.require(service in ('postgres', 'hydra') and action in ('pause', 'unpause'), 'invalid_fault')
                    dc(action, service)
                    answer = {}
                elif operation in ('progress', 'result'):
                    evidence.check_public(message)
                    if 'steps' in message:
                        record['steps'] = message['steps']
                        record['browser_version'] = message['browser_version']
                    else:
                        process.stdin.write('{}\n')
                        process.stdin.flush()
                        raise evidence.Refused('browser_' + message['failure'])
                    answer = {}
                else:
                    raise evidence.Refused('unknown_browser_operation')
                process.stdin.write(json.dumps(answer) + '\n')
                process.stdin.flush()
            evidence.require(process.wait(timeout=15) == 0, 'browser_failed')
            evidence.check_steps(record['steps'])
            for result in record['steps'].values():
                if 'online' in result:
                    evidence.check_revocation(result, result['control_status'], result['remaining'])
            record['events'] = query()
            record['passed'] = True
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        if isinstance(error, CommandFailed):
            record['command_failure'] = error.facts
        record['failed_stage'] = stage
        record['failure'] = ('interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else
                             str(error) if isinstance(error, evidence.Refused) else type(error).__name__)
        frame = traceback.extract_tb(error.__traceback__)[-1]
        record['failure_location'] = Path(frame.filename).name + ':' + str(frame.lineno)
        print('T32 failed: ' + record['failed_stage'] + '/' + record['failure'] + ' at ' + record['failure_location'], flush=True)
    finally:
        # The first cancellation enters cleanup; repeated cancellation cannot strand paused providers.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        cleanup = clean_owned(project, volume, control, network, tag, process) if started_resources else []
        record['cleanup_failures'] = cleanup
        record['cleanup_passed'] = not cleanup
        record['passed'] = record['passed'] and not cleanup
        record['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        write_record(args.record, record)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
