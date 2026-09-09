import subprocess
import unittest
from unittest.mock import patch
import providers

class CleanupTests(unittest.TestCase):
    @patch("providers.docker", return_value="fixture-id")
    @patch("providers.subprocess.run", side_effect=subprocess.CalledProcessError(1, "docker"))
    def test_cleanup_failure_fails_successful_test(self, run, docker):
        with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            with providers.container("fixture", []):
                pass
        self.assertTrue(run.call_args.args[0][-1].startswith("identity-t2-"))

    @patch("providers.docker", side_effect=subprocess.TimeoutExpired("docker", 180))
    @patch("providers.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""))
    def test_start_timeout_still_cleans_named_container(self, run, docker):
        with self.assertRaises(subprocess.TimeoutExpired):
            with providers.container("fixture", []):
                self.fail("must not yield")
        self.assertTrue(run.call_args.args[0][-1].startswith("identity-t2-"))

    @patch("providers.docker", return_value="fixture-id")
    @patch("providers.subprocess.run", side_effect=subprocess.CalledProcessError(1, "docker"))
    @patch("providers.sys.stderr")
    def test_original_failure_survives_cleanup_failure(self, stderr, run, docker):
        with self.assertRaisesRegex(ValueError, "original"):
            with providers.container("fixture", []):
                raise ValueError("original")
        self.assertTrue(stderr.write.called)


class ProviderProofTests(unittest.TestCase):
    def test_diagnostics_precede_cleanup_and_do_not_leak(self):
        import io
        output=io.StringIO()
        calls=[]
        def run(command, **kwargs):
            calls.append(command[1])
            return subprocess.CompletedProcess(command,0,stdout='error token=secret-123\npassword: secret-456',stderr='Authorization: bearer secret-789')
        with patch('providers.docker',return_value='cid'),patch('providers.subprocess.run',side_effect=run),patch('providers.sys.stderr',output):
            with self.assertRaisesRegex(ValueError,'original'):
                with providers.container('provider',[]): raise ValueError('original')
        self.assertEqual(calls,['inspect','logs','rm'])
        self.assertNotIn('secret-',output.getvalue())
        self.assertIn('severity_counts',output.getvalue())

    def test_readiness_preserves_http_status(self):
        import urllib.error
        with patch('providers.time.monotonic',side_effect=[0,0,121]),patch('providers.time.sleep'),patch('providers.urllib.request.urlopen',side_effect=urllib.error.HTTPError('http://secret',503,'sensitive',{},None)):
            with self.assertRaisesRegex(RuntimeError,'HTTP 503'):
                providers.wait('http://fixture')

class SafeTestReportTests(unittest.TestCase):
    def test_failure_preserves_canonical_name_without_payload(self):
        import io
        output=io.StringIO()
        result=subprocess.CompletedProcess([],101,stdout='test known ... FAILED\ntest secret ... FAILED\npassword=secret\n',stderr='token=secret')
        with patch('providers.sys.stdout',output):
            providers.report_tests('package','suite',{'known'},result)
        self.assertIn('known: FAILED',output.getvalue())
        self.assertIn('exit=101',output.getvalue())
        self.assertNotIn('secret',output.getvalue())

if __name__ == "__main__":
    unittest.main()
