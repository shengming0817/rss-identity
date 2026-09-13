import contextlib,io,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ui_browser
class BrowserDiagnostics(unittest.TestCase):
    def test_timeout_has_closed_stdout_without_child_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner=Path(tmp)/'runner.mjs';runner.write_text('')
            output=io.StringIO()
            with patch.dict(os.environ,{'IDENTITY_UI_RUNNER':str(runner),'IDENTITY_TEST_UI_ORIGIN':'https://localhost:1234','IDENTITY_TEST_FEDERATED_ISSUER':'https://localhost:1234','IDENTITY_TEST_FEDERATED_CA':str(runner)}), patch('ui_browser.shutil.which',return_value='/node'), patch('ui_browser.run',side_effect=subprocess.TimeoutExpired('private-command',180,output=b'private secret')), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit): ui_browser.main()
            self.assertEqual(output.getvalue(),'Identity browser failure: environment/timeout\n')
