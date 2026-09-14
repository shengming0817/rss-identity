import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import ui

class UiReceiptTests(unittest.TestCase):
    def test_record_is_replaced_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.json'
            ui.write_record(path, {'result': 'running'})
            ui.write_record(path, {'result': 'failed'})
            self.assertEqual(json.loads(path.read_text()), {'result': 'failed'})
            self.assertFalse(path.with_name(path.name + '.tmp').exists())

    @patch('ui.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout=''))
    def test_absence_requires_confirmed_removal(self, run):
        name = 'identity-t2-' + 'a' * 32
        self.assertEqual(ui.verify_cleanup({name: 'removed'})['status'], 'passed')
        result = ui.verify_cleanup({name: 'precreate'})
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['recovery_targets'], [name])

    @patch('ui.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='b' * 64 + '\n'))
    def test_volume_left_after_container_removal_fails_cleanup(self, run):
        result = ui.verify_cleanup({}, ['b' * 64])
        self.assertEqual(result['recovery_targets'], ['volume:' + 'b' * 64])

    @patch('ui.subprocess.run', side_effect=subprocess.TimeoutExpired('docker', 10))
    def test_unavailable_docker_never_proves_cleanup(self, run):
        self.assertEqual(ui.verify_cleanup({'identity-t2-' + 'a' * 32: 'removed'})['status'], 'failed')

    def test_environment_failure_still_writes_cleanup_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.json'
            with patch.dict('os.environ', {'IDENTITY_UI_FIXTURE_RECORD': str(path), 'IDENTITY_UI_DIST': str(Path(directory)/'absent')}, clear=True):
                with self.assertRaises(SystemExit): ui.main()
            value = json.loads(path.read_text())
            self.assertEqual(value['result'], 'failed')
            self.assertEqual(value['failure']['phase'], 'environment')
            self.assertEqual(value['cleanup']['status'], 'passed')

    def test_browser_timeout_keeps_timeout_classification(self):
        import ui_browser
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory) / 'runner.mjs'; runner.touch()
            receipt = Path(directory) / 'browser.json'
            environment = {'PATH': '/bin', 'IDENTITY_UI_RUNNER': str(runner),
                           'IDENTITY_UI_BROWSER_RECORD': str(receipt),
                           'IDENTITY_TEST_UI_ORIGIN': 'https://localhost',
                           'IDENTITY_TEST_FEDERATED_ISSUER': 'https://localhost',
                           'IDENTITY_TEST_FEDERATED_CA': str(runner)}
            with patch.dict('os.environ', environment, clear=True), patch('ui_browser.shutil.which', return_value='/bin/node'), patch('ui_browser.run', side_effect=subprocess.TimeoutExpired('node', 180)):
                with self.assertRaises(SystemExit): ui_browser.main()
            self.assertEqual(json.loads(receipt.read_text()), {'stage': 'environment', 'failure': 'timeout'})

    def test_cleanup_callback_failure_is_environment_failure(self):
        from contextlib import contextmanager
        @contextmanager
        def database(**_):
            yield None, {5432: 12345}
            raise RuntimeError('cleanup failed')
        @contextmanager
        def upstream(**_):
            yield {}
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'fixture.json'
            environment = {'IDENTITY_UI_DIST': directory, 'IDENTITY_UI_RUNNER': directory,
                           'IDENTITY_UI_FIXTURE_RECORD': str(receipt)}
            with patch.dict('os.environ', environment, clear=True), patch('ui.subprocess.run'), patch('ui.providers.postgres', database), patch('ui.providers.keycloak', upstream), patch('ui.http.server.ThreadingHTTPServer'), patch('ui.ssl.SSLContext'), patch('ui.threading.Thread') as thread, patch('ui.providers.cargo'):
                thread.return_value.is_alive.return_value = False
                with self.assertRaises(SystemExit): ui.main()
            self.assertEqual(json.loads(receipt.read_text())['failure'], {'phase': 'cleanup', 'classification': 'environment'})

    def test_container_settlement_drives_cleanup(self):
        import providers
        for startup_failed in (False, True):
            for removal in (None, subprocess.TimeoutExpired('docker', 30), subprocess.CalledProcessError(1, 'docker')):
                with self.subTest(startup_failed=startup_failed, removal=removal):
                    states = {}; events = []
                    def observe(name, state):
                        states[name] = state
                        events.append(state)
                    with patch('providers.docker', side_effect=subprocess.TimeoutExpired('docker', 180) if startup_failed else None, return_value='cid'), patch('providers.diagnostics'), patch('providers.subprocess.run', side_effect=removal):
                        if startup_failed or removal:
                            with self.assertRaises(subprocess.TimeoutExpired if startup_failed else RuntimeError):
                                with providers.container('fixture', [], on_container=observe): pass
                        else:
                            with providers.container('fixture', [], on_container=observe): pass
                    self.assertEqual(events, ['precreate'] + ([] if startup_failed else ['created']) + ['remove-unknown' if removal else 'removed'])
                    with patch('ui.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='')):
                        self.assertEqual(ui.verify_cleanup(states)['status'], 'failed' if removal else 'passed')
                    with patch('ui.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout=next(iter(states)))):
                        self.assertEqual(ui.verify_cleanup(states)['status'], 'failed')
