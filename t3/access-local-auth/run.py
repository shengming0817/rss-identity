#!/usr/bin/env python3
"""Run the immutable Identity candidate's local-auth journey in owned Docker resources."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import uuid

import evidence

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / 'hack'))
from bounded_process import run as bounded_run


def execute(args, *, timeout=120, input=None):
    result = bounded_run(args, timeout=timeout, input=input, capture_output=True, text=True)
    if result.returncode:
        print('Failed command: ' + ' '.join(args[:8]), flush=True)
        raise evidence.Refused('command_failed_' + Path(args[0]).name + '_' + str(result.returncode))
    return result.stdout.strip()


def docker(*args, **kwargs):
    return execute(['docker', *args], **kwargs)


def allocation():
    ids = docker('network', 'ls', '-q').split()
    networks = json.loads(docker('network', 'inspect', *ids)) if ids else []
    used = [ipaddress.ip_network(c['Subnet']) for n in networks for c in n['IPAM'].get('Config', []) if 'Subnet' in c]
    for number in range(80, 220, 2):
        pair = [ipaddress.ip_network(f'172.28.{i}.0/24') for i in (number, number + 1)]
        if not any(a.overlaps(b) for a in pair for b in used if b.version == 4):
            return [f'172.28.{number}', f'172.28.{number+1}']
    raise evidence.Refused('no_isolated_subnets')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--record', type=Path, required=True)
    args = parser.parse_args()
    source = args.candidate.resolve(strict=True)
    evidence.require(not args.record.exists(), 'record_must_be_new')
    data = evidence.candidate(source, REPO)
    project = 'identity-t32-' + uuid.uuid4().hex[:12]
    volume, control, network = (project + suffix for suffix in ('-input', '-control', '-consumer'))
    image = 'identity-local-auth-t3:' + evidence.sha(HERE / 'pnpm-lock.yaml')[:12]
    record = {'issue': 2341, 'candidate_manifest_sha256': evidence.sha(source / 'candidate.json'),
              'candidate': data, 'carrier_revision': execute(['/usr/bin/git', '-C', str(REPO), 'rev-parse', 'HEAD']),
              'carrier_files': {p.name: evidence.sha(p) for p in HERE.iterdir() if p.is_file()},
              'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'passed': False}
    compose = None
    process = None
    stage = 'environment'
    args.record.parent.mkdir(parents=True, exist_ok=True)
    try:
        print('T32: verify candidate and build isolated test controller', flush=True)
        for item in data['archives'].values():
            docker('load', '-i', str(source / item['file']), timeout=300)
        docker('build', '-t', image, str(HERE), timeout=1200)
        record['controller_image'] = json.loads(docker('image', 'inspect', image))[0]['Id']
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
            record['rendered_topology_sha256'] = __import__('hashlib').sha256(json.dumps(topology, sort_keys=True).encode()).hexdigest()
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
            config_file = root / 'compose.json'
            config_file.write_text(json.dumps(topology))
            compose = ['docker', 'compose', '-p', project, '-f', str(config_file)]

            def dc(*command, timeout=120):
                return execute(compose + list(command), timeout=timeout)

            def query():
                sql = "BEGIN READ ONLY; SELECT COALESCE(json_agg(json_build_object('seq',seq,'contract',envelope->>'contract','version',envelope->'version','payload',envelope->'payload') ORDER BY seq),'[]'::json) FROM rss_transactional_messaging.outbox; COMMIT;"
                raw = dc('exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'identity', '-Atq', '-c', sql)
                events = json.loads(raw)
                # Reject extra payload fields before projecting the allowed evidence.
                result = []
                schemas = {'identity.account.security': {'action', 'tenant', 'principal', 'actor', 'epoch', 'state'},
                           'identity.session.security': {'action', 'tenant', 'principal', 'session_id', 'replaced_session_id', 'epoch'},
                           'identity.downstream.security': {'tenant', 'grant_id', 'action'}}
                for event in events:
                    payload = json.loads(bytes(event.pop('payload')))
                    evidence.require(event['contract'] in schemas and isinstance(payload, dict)
                                     and set(payload) == schemas[event['contract']], 'unsafe_event_payload')
                    event.update({k: v for k, v in payload.items() if k in evidence.PUBLIC_FIELDS})
                    result.append(event)
                evidence.check_public(result)
                return result

            print('T32: install candidate providers, migrations and administrator', flush=True)
            dc('run', '--rm', 'volume-init')
            dc('up', '-d', '--wait', 'postgres')
            dc('run', '--rm', 'migrate')
            dc('run', '--rm', 'hydra-migrate')
            dc('up', '-d', 'hydra', 'hydra-admin', 'keycloak')
            dc('run', '--rm', 'hydra-clients')
            services['maintenance']['volumes'].append(mount('input/admin-password', '/run/input/new-password'))
            config_file.write_text(json.dumps(topology))
            dc('run', '--rm', 'maintenance', 'initialize', configuration['admin_principal'], 'admin', '/run/input/new-password')
            dc('up', '-d', '--wait', 'identity', 'public-gateway', 'private-gateway', 'consumer', 'ingress', timeout=180)
            observed = {}
            for name in ('identity', 'public-gateway', 'private-gateway', 'postgres', 'hydra', 'keycloak', 'consumer'):
                cid = dc('ps', '-q', name)
                instance = json.loads(docker('inspect', cid))[0]
                image_config = json.loads(docker('image', 'inspect', instance['Image']))[0]
                evidence.require(instance['Config']['Image'] == services[name]['image'], 'running_image_mismatch')
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
                elif operation == 'result':
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
    except Exception as error:
        record['failed_stage'] = stage
        record['failure'] = str(error) if isinstance(error, evidence.Refused) else type(error).__name__
        print('T32 failed: ' + record['failed_stage'] + '/' + record['failure'], flush=True)
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        # Cleanup by project/explicit IDs only; never prune shared Docker resources.
        cleanup = []
        for kind, args_list in [('container', ['ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project]),
                                ('network', ['network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project]),
                                ('volume', ['volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project])]:
            try:
                ids = docker(*args_list).split()
                for item in ids:
                    if kind == 'container':
                        execute(['docker', 'unpause', item], timeout=20) if json.loads(docker('inspect', item))[0]['State'].get('Paused') else None
                        docker('rm', '-f', item)
                    else:
                        docker(kind, 'rm', item)
            except Exception:
                cleanup.append(kind)
        for kind, name in [('network', network), ('volume', volume), ('volume', control)]:
            result = subprocess.run(['docker', kind, 'rm', name], capture_output=True, timeout=30)
            if result.returncode and b'not found' not in result.stderr and b'No such' not in result.stderr:
                cleanup.append(kind)
        record['cleanup_passed'] = not cleanup
        record['passed'] = record['passed'] and not cleanup
        record['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        args.record.write_text(json.dumps(record, indent=2) + '\n')
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
