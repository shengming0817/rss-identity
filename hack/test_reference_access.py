import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import deploy
from deployment_fixture import fixture

class ReferenceAccessTests(unittest.TestCase):
    def test_v5_reaches_all_binaries_and_mfa_resource_reaches_gateway(self):
        with fixture() as (root, data, images):
            data = copy.deepcopy(data)
            data['runtime']['formatVersion'] = 5
            with patch('os.geteuid', return_value=0), patch('os.chown'), patch.object(deploy, 'preflight'):
                deploy.render(data, root/'v5', images)
            for name in ['runtime', 'maintenance', 'migration']:
                self.assertEqual(json.loads((root/'v5'/f'{name}.json').read_text())['formatVersion'], 5)
            gateway = (root/'v5'/'gateway.conf').read_text()
            self.assertIn('mfa-example', gateway)
            self.assertIn('proxy_next_upstream off', gateway)
