import unittest,subprocess,json
import recovery
class Diagnostics(unittest.TestCase):
 def test_failure_records_only_closed_action_stage_and_process_status(self):
  error=subprocess.CalledProcessError(17,['tool','synthetic-secret'],output='synthetic-secret',stderr='synthetic-secret')
  value=recovery.safe_failure('restore-current','verify-backup',error)
  self.assertEqual(value,dict(action='restore-current',stage='verify-backup',error='process',returncode=17))
  self.assertNotIn('synthetic-secret',json.dumps(value))
  self.assertEqual(recovery.safe_failure('synthetic-secret','synthetic-secret',ValueError('synthetic-secret'))['stage'],'unknown')
