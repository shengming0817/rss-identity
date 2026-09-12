"""T33 evidence rejects incomplete runs, substituted inputs and leaked credentials."""
import importlib.util
import json
import sys
import subprocess
from unittest.mock import patch
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
