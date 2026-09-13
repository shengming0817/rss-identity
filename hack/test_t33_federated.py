"""T33 evidence rejects incomplete runs, substituted inputs and leaked credentials."""
import importlib.util
import json
import sys
import subprocess
import signal
import ipaddress
from unittest.mock import patch, Mock
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 't3/identity-federated-sso/proof.py'
SPEC = importlib.util.spec_from_file_location('t33_proof', PATH)
proof = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = proof
SPEC.loader.exec_module(proof)
sys.path.insert(0, str(PATH.parent))
import stack
import prepare
import deploy
RUN_SPEC = importlib.util.spec_from_file_location('t33_run', PATH.parent / 'run.py')
runner = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(runner)


class FederatedProof(unittest.TestCase):
    def test_prepare_timeout_and_failure_diagnostics_exclude_command_and_output(self):
        for error in [subprocess.TimeoutExpired(['secret-command'], 30, output='secret-output'),
                      subprocess.CalledProcessError(7, ['secret-command'], stderr='secret-output')]:
            with self.subTest(error=type(error).__name__), patch.object(prepare.subprocess, 'run', side_effect=error):
                with self.assertRaisesRegex(RuntimeError, 'T33 preparation git-status') as caught:
                    prepare.run('git-status', ['secret-command'])
                self.assertNotIn('secret', str(caught.exception))

    def test_prepare_budgets_input_archive_and_real_timeout(self):
        with patch.dict(prepare.os.environ, {'T33_COMMAND_TIMEOUT_SECONDS': '1'}):
            self.assertEqual(prepare.run('credential-test', [sys.executable, '-c',
                'import sys; print(sys.stdin.read())'], input='synthetic-input'), 'synthetic-input')
            with tempfile.TemporaryFile() as stream:
                prepare.run('archive-test', [sys.executable, '-c',
                    'import sys; sys.stdout.buffer.write(bytes([0, 255, 10]))'], stdout=stream)
                stream.seek(0)
                self.assertEqual(stream.read(), bytes([0, 255, 10]))
            with self.assertRaisesRegex(RuntimeError, 'sleep-test timed out after 1s'):
                prepare.run('sleep-test', [sys.executable, '-c', 'import time; time.sleep(60)'])
        for budget, seconds in [('command', 30), ('build', 3600), ('transfer', 600)]:
            variable = 'T33_' + budget.upper() + '_TIMEOUT_SECONDS'
            with patch.dict(prepare.os.environ, {}, clear=True), patch.object(prepare.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, 'ok')) as call:
                self.assertEqual(prepare.run('budget-test', ['tool'], budget=budget), 'ok')
                self.assertEqual(call.call_args.kwargs['timeout'], seconds)
            for invalid in ['0', '-1', 'nan', 'inf', '']:
                with patch.dict(prepare.os.environ, {variable: invalid}), patch.object(prepare.subprocess, 'run') as call:
                    with self.assertRaisesRegex(ValueError, variable):
                        prepare.run('budget-test', ['tool'], budget=budget)
                    call.assert_not_called()

    def test_empty_cli_paths_are_rejected_at_the_argument_boundary(self):
        cases = [('prepare.py', {'--output': 'out', '--ui-source': 'source', '--ui-dist': 'dist'}),
                 ('run.py', {'--artifacts': 'artifacts', '--output': 'out', '--artifacts-sha256': 'a' * 64})]
        for script, defaults in cases:
            for flag in defaults:
                if flag == '--artifacts-sha256':
                    continue
                for empty in ['', '   ']:
                    with self.subTest(script=script, flag=flag, empty=empty):
                        args = {**defaults, flag: empty}
                        result = subprocess.run([sys.executable, str(PATH.parent / script),
                            *[v for pair in args.items() for v in pair]], capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2)
                        self.assertIn(flag, result.stderr)
                        self.assertIn('nonempty path', result.stderr)
                        self.assertNotIn('Traceback', result.stderr)

    def test_digest_rejects_substitution_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / 'artifact'
            artifact.write_bytes(b'approved artifact')
            expected = proof.sha(artifact)
            proof.verify_file(root, 'artifact', expected)
            artifact.write_bytes(b'substituted artifact')
            with self.assertRaises(ValueError):
                proof.verify_file(root, 'artifact', expected)
            for name in ['../artifact', '/artifact', './artifact']:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    proof.verify_file(root, name, expected)
            (root / 'link').symlink_to(artifact)
            with self.assertRaises(ValueError):
                proof.verify_file(root, 'link', proof.sha(artifact))

    def test_manifest_and_artifact_replacement_cannot_change_the_pinned_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / 't33.json'
            artifact = root / 'consumer'
            artifact.write_bytes(b'approved executable')
            manifest.write_text(json.dumps({'revision': 'a' * 40, 'sha256': proof.sha(artifact)}))
            expected = proof.sha(manifest)
            artifact.write_bytes(b'substituted executable')
            manifest.write_text(json.dumps({'revision': 'a' * 40, 'sha256': proof.sha(artifact)}))
            with self.assertRaises(ValueError):
                proof.load_artifacts(root, 'a' * 40, expected)

    def test_all_scenarios_must_execute_exactly_once_and_pass(self):
        checks = [{'name': name, 'result': 'passed'} for name in proof.SCENARIOS]
        proof.verify_checks(checks)
        for invalid in [[], checks[:-1], checks + checks[:1],
                        [{**checks[0], 'result': 'failed'}, *checks[1:]],
                        [{**checks[0], 'result': 'skipped'}, *checks[1:]]]:
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                proof.verify_checks(invalid)

    def test_failure_and_cleanup_cannot_be_reported_as_passed(self):
        checks = [{'name': name, 'result': 'passed'} for name in proof.SCENARIOS]
        proof.finish(checks, cleanup=True)
        for checks, cleanup in [(checks, False), (checks[:-1], True)]:
            with self.assertRaises(ValueError):
                proof.finish(checks, cleanup=cleanup)

    def test_secret_canaries_and_callback_queries_never_enter_evidence(self):
        proof.assert_safe({'status': 401, 'code': 'invalid_credential'}, ['synthetic-secret'])
        for value in [{'detail': 'synthetic-secret'}, {'nested': ['prefix synthetic-secret suffix']},
                      {'url': 'https://identity.test/api/v1/oidc/callback?code=x&state=y'},
                      {'authorization': 'Basic value'}, {'cookie': 'value'}, {'access_token': 'value'}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                proof.assert_safe(value, ['synthetic-secret'])

    def test_cleanup_continues_after_container_timeout_and_fails_the_run(self):
        value = stack.Stack.__new__(stack.Stack)
        value.containers = ['owned-container']
        value.volumes = ['owned-volume']
        value.compose_created = value.network_created = False
        with patch.object(stack.subprocess, 'run', side_effect=subprocess.TimeoutExpired('docker', 30)), \
                patch.object(stack, 'docker', return_value='removed') as docker:
            self.assertFalse(value.cleanup())
            docker.assert_called_once_with('volume', 'rm', 'owned-volume')

    def test_start_unknown_tracks_the_owned_container_for_cleanup(self):
        value = stack.Stack.__new__(stack.Stack)
        value.containers = []
        value.name, value.work, value.image = 'owned', 'owned-work', 'fixed-image'
        value.artifacts = Path('/fixed-artifacts')
        with patch.object(stack, 'docker', side_effect=subprocess.TimeoutExpired('docker', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                value.root('pass')
        self.assertEqual(len(value.containers), 1)
        self.assertTrue(value.containers[0].startswith('owned-stage-'))

    def test_failed_administrator_setup_never_opens_runtime_ingress(self):
        value = stack.Stack.__new__(stack.Stack)
        value.name, value.platform_admin, value.containers = 'owned', 'platform-admin', []
        value.candidate = {'images': {'operator': 'fixed-operator'}}
        value.config = {
            'services': {'maintenance': {'volumes': [
                {'source': name, 'target': '/run/' + name} for name in ['config', 'input']]}},
            'volumes': {name: {'name': 'owned-' + name} for name in ['config', 'input']},
        }
        value.compose, value.root = Mock(), Mock()
        def compose(*args):
            if 'maintenance' in args:
                raise RuntimeError('maintenance rejected')
        value.compose.side_effect = compose
        with patch.object(stack, 'docker'):
            with self.assertRaisesRegex(RuntimeError, 'maintenance rejected'):
                value.initialize()
        started = [call.args[2:] for call in value.compose.call_args_list
                   if call.args[:2] == ('up', '-d')]
        for forbidden in ['identity', 'public-gateway', 'private-gateway', 't33-front', 't33-consumer']:
            self.assertFalse(any(forbidden in services for services in started), forbidden)

    def test_initialize_bootstraps_once_without_rewriting_maintenance_authority(self):
        value = stack.Stack.__new__(stack.Stack)
        value.name, value.platform_admin, value.containers = 'owned', 'platform-admin', []
        value.candidate = {'images': {'operator': 'fixed-operator'}}
        value.config = {'services': {'maintenance': {'volumes': [
            {'source': name, 'target': '/run/' + name} for name in ['config', 'input']]}},
            'volumes': {name: {'name': 'owned-' + name} for name in ['config', 'input']}}
        value.compose, value.root = Mock(), Mock()
        original = json.dumps(value.config)
        with patch.object(stack, 'docker') as docker, patch.object(stack, 'wait'):
            value.initialize()
        calls = [c.args for c in value.compose.call_args_list if 'initialize' in c.args]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:4], ('run', '--rm', '--no-deps', '--name'))
        self.assertIn('maintenance', calls[0])
        docker.assert_not_called()
        self.assertEqual(calls[0][-4:], ('initialize', 'platform-admin', 'platform', '/run/input/init-password'))
        self.assertEqual(json.dumps(value.config), original)
        self.assertEqual(len(value.root.call_args_list), 1)
        self.assertIn('/srv/t33/input/platform-password', value.root.call_args.args[0])

    def test_configure_matches_current_candidate_renderer_and_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts = root / 'artifacts'
            (artifacts / 'candidate/deployment').mkdir(parents=True)
            (artifacts / 'candidate/deployment/example.json').write_bytes((deploy.ROOT / 'deployment/example.json').read_bytes())
            output = root / 'output'; output.mkdir()
            candidate = {'providers': deploy.IMAGES, 'images': {
                k: k + '@sha256:' + 'a' * 64 for k in ['server', 'operator', 'gateway']}}
            record = {'browser': {'image_id': 'fixed-tool', 'playwright': '1.60.0'},
                      'providers': {}, 'ui_revision': proof.UI_REVISION}
            value = stack.Stack(artifacts, output, record, candidate)
            with patch.object(value, 'subnets', return_value=[ipaddress.ip_network(f'10.233.{n}.0/24') for n in [10, 11, 12]]):
                value.configure()
            def paths(item):
                if isinstance(item, dict): return {k: paths(v) for k, v in item.items()}
                if isinstance(item, list): return [paths(v) for v in item]
                if isinstance(item, str) and item.startswith('/srv/t33/input/'):
                    return str(value.inputs / Path(item).name)
                return item
            with patch.multiple(deploy, DEPLOY_UID=stack.os.getuid(), DEPLOY_GID=stack.os.getgid(),
                                KEYCLOAK_UID=stack.os.getuid(), KEYCLOAK_GID=stack.os.getgid()):
                path = deploy.render(paths(value.data), root / 'rendered', candidate)
            runtime = json.loads((root / 'rendered/runtime.json').read_text())
            self.assertEqual(runtime['storage']['system_domain_id'], stack.SYSTEM_DOMAIN)
            self.assertNotIn('tenants', runtime['storage'])
            self.assertNotIn('providers', runtime['oidc'])
            self.assertNotIn('ca_file', runtime['oidc'])
            self.assertEqual(len(runtime['oidc']['credential_keyring']['keys']), 1)
            for index, realm in enumerate(sorted((root / 'rendered').glob('realm-*.json'))):
                client = json.loads(realm.read_text())['clients'][0]
                self.assertEqual(client['secret'], value.browser_config['providers'][index]['client_secret'])
            proof.assert_safe(value.public_config, value.secrets)
            with patch.object(value, 'root', side_effect=[path.read_text()] + [''] * 40) as execute, \
                    patch.object(value, 'volume', side_effect=lambda name: name), patch.object(stack, 'docker'):
                value.stage()
            maintenance = value.config['services']['maintenance']
            canonical = json.loads(path.read_text())['services']['maintenance']
            for field in ['read_only', 'cap_drop', 'security_opt', 'tmpfs', 'entrypoint', 'networks', 'user']:
                self.assertEqual(maintenance[field], canonical[field], field)
            pool = value.config['networks']['front']['ipam']['config'][0]
            self.assertEqual(pool['ip_range'], '10.233.12.128/25')
            consumer = value.config['services']['t33-consumer']
            self.assertEqual(consumer['image'], candidate['images']['server'])
            self.assertEqual(consumer['platform'], 'linux/amd64')
            extra = next(json.loads(c.kwargs['input']) for c in execute.call_args_list
                         if 'front.conf' in c.kwargs.get('input', ''))
            self.assertIn('proxy_pass https://public-gateway:443;', extra['front.conf'])
            self.assertNotIn(':8443', extra['front.conf'])

    def test_cli_unknown_write_cannot_be_reissued(self):
        value = stack.Stack.__new__(stack.Stack)
        value.cli_started = True
        with patch.object(stack, 'docker') as docker, self.assertRaisesRegex(ValueError, 'never replay'):
            value.onboard_cli()
        docker.assert_not_called()

    def test_hydra_fault_recovery_recreates_the_shared_namespace_owners(self):
        value = stack.Stack.__new__(stack.Stack)
        value.compose = Mock()
        value.control({'action': 'stop', 'service': 'hydra'})
        value.compose.assert_called_with('stop', 'hydra-admin', 'hydra')
        value.control({'action': 'start', 'service': 'hydra'})
        value.compose.assert_called_with('up', '-d', '--force-recreate', '--pull', 'never', 'hydra', 'hydra-admin')

    def test_signal_and_daemon_failure_keep_cleanup_and_failure_receipt(self):
        for cause in ['signal', 'daemon']:
            with self.subTest(cause=cause), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                fake = Mock()
                fake.secrets = []
                fake.public_config = {}
                fake.diagnostics.return_value = []
                fake.cleanup.return_value = cause == 'signal'
                if cause == 'signal':
                    fake.configure.side_effect = lambda: signal.raise_signal(signal.SIGTERM)
                record = {'consumer': {}, 'browser': {'image': 'tool', 'image_id': 'image'}, 'providers': {}}
                command = lambda args, **kw: 'a' * 40 if 'rev-parse' in args else ''
                with patch.object(runner, 'Stack', return_value=fake), \
                        patch.object(runner.proof, 'load_artifacts', return_value=(record, {'archives': {}})), \
                        patch.object(runner, 'command', side_effect=command), \
                        patch.object(runner, 'docker', return_value='image', side_effect=RuntimeError('daemon unavailable') if cause == 'daemon' else None):
                    with self.assertRaises(ValueError), runner.cancellation():
                        runner.execute(root / 'artifacts', root / 'result', 'b' * 64)
                fake.cleanup.assert_called_once()
                result = json.loads((root / 'result/result.json').read_text())
                self.assertEqual(result['observations']['result'], 'failed')
                self.assertIn('SIGTERM' if cause == 'signal' else 'daemon', result['observations']['diagnostic'])

    def test_root_caller_cannot_start_a_privileged_browser(self):
        value = stack.Stack.__new__(stack.Stack)
        value.name, value.image = 'owned', 'fixed-image'
        value.containers, value.secrets = [], []
        value.volume = lambda name: name
        value.root = Mock()
        def docker(*args, **kwargs):
            if args[0] == 'exec':
                return json.dumps({'result': {'result': 'passed', 'checks': []}})
            if '{{.State.Running}}' in args:
                return 'false'
            if '{{.State.ExitCode}}' in args:
                return '0'
            return 'container'
        with patch.object(stack.os, 'getuid', return_value=0), patch.object(stack, 'docker', side_effect=docker) as call:
            value.run_browser()
        browser = next(c.args for c in call.call_args_list if c.args[:4] == ('run', '-d', '--name', 'owned-browser'))
        self.assertEqual(browser[browser.index('--user') + 1], '10001:10001')
        self.assertIn('--read-only', browser)
        self.assertEqual(browser[browser.index('--cap-drop') + 1], 'ALL')
        self.assertIn('no-new-privileges:true', browser)

    def test_input_identity_has_no_legacy_or_missing_value_fallback(self):
        revision = 'a' * 40
        value = {'format_version': 1, 'revision': revision, 'ui_revision': proof.UI_REVISION}
        proof.verify_identity(value, revision)
        for change in [{'format_version': 0}, {'revision': 'b' * 40}, {'ui_revision': 'c' * 40}]:
            with self.assertRaises(ValueError):
                proof.verify_identity({**value, **change}, revision)
        for field in value:
            with self.assertRaises(ValueError):
                proof.verify_identity({k: v for k, v in value.items() if k != field}, revision)


if __name__ == '__main__':
    unittest.main()
