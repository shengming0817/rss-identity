"""T33 evidence rejects incomplete runs, substituted inputs and leaked credentials."""
import importlib.util
import json
import sys
import subprocess
import signal
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
RUN_SPEC = importlib.util.spec_from_file_location('t33_run', PATH.parent / 'run.py')
runner = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(runner)


class FederatedProof(unittest.TestCase):
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
