"""Fault injection for runner ownership, cancellation and safe diagnostics; no Docker required."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch
import run as runner


class RunnerTests(unittest.TestCase):
    def test_allocation_claims_disjoint_pairs_and_rolls_back_partial_failure(self):
        networks, removed = {}, []
        lock = threading.Lock()
        def docker(*args, **_):
            with lock:
                if args[:2] == ('network', 'create'):
                    subnet, name = args[args.index('--subnet') + 1], args[-1]
                    # First runner loses its second subnet to a competing owner.
                    if subnet == '10.234.81.0/24' and 'competitor' not in networks:
                        networks['competitor'] = subnet
                    if subnet in networks.values():
                        raise runner.CommandFailed('network_create', 1, 'overlap')
                    networks[name] = subnet
                    return name
                if args[:2] == ('network', 'ls'):
                    return ' '.join(networks)
                if args[:2] == ('network', 'inspect'):
                    return json.dumps([{'IPAM': {'Config': [{'Subnet': networks[n]}]}} for n in args[2:]])
                if args[:2] == ('network', 'rm'):
                    removed.append(args[2]); del networks[args[2]]
                    return ''
                self.fail(args)
        with patch.object(runner, 'docker', side_effect=docker), ThreadPoolExecutor(2) as pool:
            first, second = list(pool.map(runner.allocation, ['owner-a', 'owner-b']))
        self.assertFalse(set(first) & set(second))
        self.assertEqual(len(networks), 5)
        self.assertTrue(removed)
        self.assertIn('competitor', networks)

    def test_external_binding_refuses_candidate_ipam_or_isolation_drift(self):
        prefixes = ['10.234.80', '10.234.81']
        original = {'services': {'identity': {'networks': {'backend': {'ipv4_address': prefixes[0] + '.4'}}}},
                    'networks': {key: {'internal': True, 'ipam': {'config': [{'subnet': prefix + '.0/24', 'ip_range': prefix + '.128/25'}]}}
                                 for key, prefix in zip(('backend', 'protocol'), prefixes)}}
        def observed(*args, **_):
            key = args[-1].split('-')[-1]
            prefix = prefixes[('backend', 'protocol').index(key)]
            return json.dumps([{'Internal': True, 'Driver': 'bridge', 'EnableIPv6': False,
                                'Labels': {'identity.t32': 'owner'},
                                'IPAM': {'Driver': 'default', 'Config': [{'Subnet': prefix + '.0/24', 'IPRange': prefix + '.128/25', 'Gateway': prefix + '.1'}]}}])
        import copy
        with patch.object(runner, 'docker', side_effect=observed):
            for change in ('isolation', 'subnet', 'ip_range'):
                topology = copy.deepcopy(original)
                definition = topology['networks']['backend']
                if change == 'isolation': definition['internal'] = False
                elif change == 'subnet': definition['ipam']['config'][0]['subnet'] = '10.99.0.0/24'
                else: definition['ipam']['config'][0].pop('ip_range')
                with self.assertRaises(runner.evidence.Refused):
                    runner.bind_reserved(topology, 'owner', prefixes)
            topology = copy.deepcopy(original)
            runner.bind_reserved(topology, 'owner', prefixes)
            self.assertEqual(topology['services'], original['services'])
            self.assertEqual(topology['networks']['backend'], {'external': True, 'name': 'owner-backend'})

    def test_preflight_failure_writes_receipt_without_starting_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'record.json'
            args = ['run.py', '--candidate', str(Path(temp) / 'missing'), '--record', str(output)]
            with patch('sys.argv', args), patch.object(runner, 'docker', side_effect=AssertionError('unexpected Docker')):
                self.assertEqual(runner.main(), 1)
                record = json.loads(output.read_text())
                self.assertFalse(record['passed'])
                self.assertEqual(record['failed_stage'], 'candidate_preflight')
                self.assertTrue(record['cleanup_passed'])
                self.assertEqual(runner.main(), 2)
                self.assertEqual(json.loads(output.read_text()), record)

    def test_sigterm_enters_cleanup_and_restores_handlers(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'record.json'
            before = signal.getsignal(signal.SIGTERM)
            def stop(*_):
                os.kill(os.getpid(), signal.SIGTERM)
            with patch('sys.argv', ['run.py', '--candidate', temp, '--record', str(output)]), patch.object(runner.evidence, 'candidate', side_effect=stop):
                self.assertEqual(runner.main(), 1)
            self.assertEqual(signal.getsignal(signal.SIGTERM), before)
            self.assertEqual(json.loads(output.read_text())['failure'], 'interrupted_15')

    def test_cleanup_continues_after_one_resource_failure_and_timeout(self):
        calls = []
        def docker(*args, **_):
            calls.append(args)
            if args[0] == 'ps':
                return 'bad good'
            if args[:2] in [('network', 'ls'), ('volume', 'ls')]:
                return ''
            if args == ('inspect', 'bad'):
                raise runner.evidence.Refused('inspect_failed')
            if args == ('inspect', 'good'):
                return '[{"State":{"Paused":true}}]'
            return ''
        with patch.object(runner, 'docker', side_effect=docker), patch.object(runner, 'bounded_run', side_effect=subprocess.TimeoutExpired('docker', 30)):
            failures = runner.clean_owned('project', 'input', 'control', 'network', 'tag', None)
        self.assertIn(('unpause', 'good'), calls)
        self.assertIn(('rm', '-f', 'good'), calls)
        self.assertEqual(len(failures), 5)
        self.assertEqual(failures[0]['id'], 'bad')
        self.assertTrue(all(f['error_code'] == 'TimeoutExpired' for f in failures[1:]))

    def test_command_timeout_keeps_operation_and_deadline_without_raw_output(self):
        with patch.object(runner, 'bounded_run', side_effect=subprocess.TimeoutExpired('private command', 7, stderr='private')):
            with self.assertRaises(runner.CommandFailed) as captured:
                runner.execute(['docker', 'test'], operation='outbox_query', timeout=7)
        self.assertEqual(captured.exception.facts['operation'], 'outbox_query')
        self.assertEqual(captured.exception.facts['timeout_seconds'], 7)
        self.assertEqual(captured.exception.facts['diagnostic'], 'timed_out')
        self.assertNotIn('private', json.dumps(captured.exception.facts))

    def test_untracked_receipt_cannot_enter_carrier_source_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            carrier = root / 't3/access-local-auth'
            carrier.mkdir(parents=True)
            (carrier / 'run.py').write_text('source')
            (carrier / 'record.json').write_text('{}')
            with patch.object(runner, 'execute', return_value='t3/access-local-auth/run.py'), patch.object(runner.subprocess, 'check_output', return_value=b'source'):
                sources = runner.carrier_sources(root, 'revision')
            self.assertEqual(sources, {'t3/access-local-auth/run.py': b'source'})

    def test_command_diagnostics_cannot_include_raw_secret(self):
        failure = runner.CommandFailed('volume_initialize', 1, 'invalid interpolation format secret=private-credential')
        self.assertEqual(failure.facts['diagnostic'], 'invalid_interpolation_format')
        self.assertNotIn('private-credential', json.dumps(failure.facts))
