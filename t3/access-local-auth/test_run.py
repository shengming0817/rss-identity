"""Fault injection for runner ownership, cancellation and safe diagnostics; no Docker required."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import run as runner


class RunnerTests(unittest.TestCase):
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

    def test_command_diagnostics_cannot_include_raw_secret(self):
        failure = runner.CommandFailed('volume_initialize', 1, 'invalid interpolation format secret=private-credential')
        self.assertEqual(failure.facts['diagnostic'], 'invalid_interpolation_format')
        self.assertNotIn('private-credential', json.dumps(failure.facts))
