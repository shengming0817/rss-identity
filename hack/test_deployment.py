import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import deploy

class DeploymentTests(unittest.TestCase):
    def test_local_reference_has_one_config_authority_and_no_oidc_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            value=json.loads((deploy.ROOT/'deployment/example.json').read_text())
            for name in ['runtime','owner','maintenance','ca','cert','key','pgcert','pgkey']:
                p=root/name;p.write_text('fixture-'+name);p.chmod(0o600)
            value['database'].update(passwordFile=str(root/'runtime'),caFile=str(root/'ca'))
            data={'runtime':value,'ownerPasswordFile':str(root/'owner'),'maintenancePasswordFile':str(root/'maintenance'),'tlsCertificateFile':str(root/'cert'),'tlsKeyFile':str(root/'key'),'postgresCertificateFile':str(root/'pgcert'),'postgresKeyFile':str(root/'pgkey'),'backendSubnet':'172.29.0.0/24'}
            candidate={'identity_schema':9,'config_version':3,'providers':deploy.IMAGES,'images':{k:'fixture/'+k+'@sha256:'+'1'*64 for k in ['server','operator','gateway']}}
            with patch('os.geteuid',return_value=0),patch('os.chown'):
                deploy.render(data,root/'output',candidate)
            runtime=json.loads((root/'output/runtime.json').read_text())
            maintenance=json.loads((root/'output/maintenance.json').read_text())
            self.assertEqual(runtime['bootstrapAccounts'],maintenance['bootstrapAccounts'])
            self.assertEqual(runtime['storage'],maintenance['storage'])
            self.assertEqual(json.loads((root/'output/ui.json').read_text()),{'canonicalOrigin':value['publicOrigin'],'oidcEnabled':False})
            compose=json.loads((root/'output/compose.json').read_text())
            self.assertEqual(set(compose['services']),{'postgres','identity','gateway','migrate','maintenance','volume-init'})
            self.assertNotIn('keycloak',json.dumps(compose))
            self.assertNotIn('hydra',json.dumps(compose))
            self.assertIn('/api/v2/',(root/'output/gateway.conf').read_text())
    def test_compose_preserves_dollar_literals_and_rejects_unknown_configuration(self):
        self.assertEqual(deploy.compose_literals({'command':['$secret','${name}']}),{'command':['$$secret','$${name}']})
        with self.assertRaises(ValueError):deploy.fields({'legacy':1},{'runtime'},'deployment')

class OperationTests(unittest.TestCase):
    def test_unknown_process_result_is_never_success_or_retried(self):
        import operate, subprocess
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],1)) as run:
            with self.assertRaisesRegex(RuntimeError,'unknown'):operate.command(['fixture'])
            self.assertEqual(run.call_count,1)
    def test_corrupt_backup_rejected_before_restore(self):
        import operate
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'cut.dump';path.write_bytes(b'fixture')
            path.with_suffix('.dump.json').write_text(json.dumps({'schema':9,'sha256':operate.sha(path)}))
            self.assertEqual(operate.check_backup(path)['schema'],9)
            path.write_bytes(b'corrupted')
            with self.assertRaises(ValueError):operate.check_backup(path)
    def test_restore_refuses_live_source_before_creating_target(self):
        import operate, argparse, subprocess
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);images={k:'fixed/'+k for k in ['server','operator','gateway']}
            (root/'compose.json').write_text(json.dumps({'services':{s:{'image':images[i]} for s,i in [('identity','server'),('gateway','gateway'),('migrate','operator'),('maintenance','operator')]}}))
            args=argparse.Namespace(candidate=root,command='restore',project='identity-target',deployment=root,backup=root/'cut.dump')
            with patch.object(operate,'candidate',return_value={'images':images}),patch.object(operate,'check_backup',return_value={'project':'identity-source'}),patch.object(operate,'command',return_value=subprocess.CompletedProcess([],0,stdout=b'identity\n')) as run:
                with self.assertRaisesRegex(ValueError,'source authority'):operate.operate(args)
                self.assertEqual(run.call_count,1)
