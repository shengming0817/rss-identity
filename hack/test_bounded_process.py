import subprocess,sys,time,unittest
import bounded_process
class ProcessTests(unittest.TestCase):
    def test_hung_fixture_process_is_reaped(self):
        begin=time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            bounded_process.run([sys.executable,'-c','import time; time.sleep(20)'],timeout=.05,capture_output=True,text=True)
        self.assertLess(time.monotonic()-begin,6)
    def test_descendant_is_reaped_after_parent_exit(self):
        code='import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(20)"])'
        begin=time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            bounded_process.run([sys.executable,'-c',code],timeout=.1,capture_output=True,text=True)
        self.assertLess(time.monotonic()-begin,6)

    def test_bounded_process_preserves_result(self):
        result=bounded_process.run([sys.executable,'-c','print("fixture")'],timeout=5,capture_output=True,text=True,check=True)
        self.assertEqual(result.stdout,'fixture\n')
