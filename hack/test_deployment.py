import argparse
import contextlib
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import deploy
import operate

@contextlib.contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        value=json.loads((deploy.ROOT/'deployment/example.json').read_text())
        for name in ['runtime','owner','maintenance','ca','cert','key','pgcert','pgkey']:
            p=root/name;p.write_text('fixture-'+name);p.chmod(0o600)
        value['database'].update(passwordFile=str(root/'runtime'),caFile=str(root/'ca'))
        data={'runtime':value,'ownerPasswordFile':str(root/'owner'),'maintenancePasswordFile':str(root/'maintenance'),'tlsCertificateFile':str(root/'cert'),'tlsKeyFile':str(root/'key'),'postgresCertificateFile':str(root/'pgcert'),'postgresKeyFile':str(root/'pgkey'),'backendSubnet':'172.29.0.0/24'}
        images={k:'sha256:'+str(i)*64 for i,k in enumerate(['identity','web','postgres','runtime'],1)}
        with patch('os.geteuid',return_value=0),patch('os.chown'),patch.object(deploy,'preflight'):
            deploy.render(data,root/'output',images)
        yield root,data,images

def receipt(path,data,images):
    path.write_bytes(b'fixture')
    value={'schema':9,'instanceId':data['runtime']['instanceId'],'storage':data['runtime']['storage'],'backendVersion':'a'*40,'project':'identity-source','sha256':operate.sha(path)}
    path.with_suffix('.dump.json').write_text(json.dumps(value))
    return value

class DeploymentTests(unittest.TestCase):
    def test_local_reference_has_one_config_authority_and_no_oidc_dependency(self):
        with fixture() as (root,data,images):
            out=root/'output';runtime=json.loads((out/'runtime.json').read_text());maintenance=json.loads((out/'maintenance.json').read_text())
            self.assertEqual(runtime['bootstrapAccounts'],maintenance['bootstrapAccounts'])
            self.assertEqual(runtime['storage'],maintenance['storage'])
            self.assertEqual(json.loads((out/'ui.json').read_text()),{'canonicalOrigin':data['runtime']['publicOrigin'],'oidcEnabled':False})
            compose=json.loads((out/'compose.json').read_text())
            self.assertEqual(set(compose['services']),{'postgres','identity','gateway','migrate','maintenance','volume-init'})
            self.assertNotIn('keycloak',json.dumps(compose));self.assertNotIn('hydra',json.dumps(compose))
            for service in compose['services'].values():
                for volume in service.get('volumes',[]):
                    if volume['type']=='bind':self.assertTrue(Path(volume['source']).is_file())
    def test_compose_preserves_dollar_literals(self):
        self.assertEqual(deploy.compose_literals({'command':['$secret','${name}']}),{'command':['$$secret','$${name}']})
    def test_late_input_and_binary_rejections_leave_no_secret_output_and_allow_retry(self):
        with fixture() as (root,data,images):
            out=root/'new'
            for invalid in ['file','binary']:
                bad=copy.deepcopy(data)
                if invalid=='file':bad['postgresKeyFile']=str(root/'missing')
                with patch('os.geteuid',return_value=0),patch('os.chown'),patch.object(deploy,'preflight',side_effect=ValueError('rejected')):
                    with self.assertRaises((ValueError,OSError)):deploy.render(bad,out,images)
                self.assertFalse(out.exists());self.assertEqual(list(root.glob('.new-*')),[])
            with patch('os.geteuid',return_value=0),patch('os.chown'),patch.object(deploy,'preflight') as preflight:
                deploy.render(data,out,images);preflight.assert_called_once()
            self.assertTrue((out/'compose.json').is_file())
    def test_images_preflight_is_offline_and_covers_each_owner(self):
        with fixture() as (root,data,images),patch('subprocess.run',return_value=subprocess.CompletedProcess([],0)) as run:
            deploy.preflight(root/'output',images)
            self.assertEqual(run.call_count,3)
            for call in run.call_args_list:
                argv=call.args[0]
                self.assertEqual(argv[argv.index('--network')+1],'none')
                self.assertIn('--check-config',argv)

class OperationTests(unittest.TestCase):
    def test_failed_reads_and_unknown_writes_have_distinct_redacted_outcomes(self):
        for mutating in [False,True]:
            with patch('subprocess.run',return_value=subprocess.CompletedProcess(['secret'],1,stderr=b'secret')) as run:
                with self.assertRaises(operate.OperationError) as caught:operate.command(['secret'],stage='rekey',mutating=mutating)
                error=caught.exception
                self.assertEqual(error.outcome_known,not mutating);self.assertEqual(error.stage,'rekey');self.assertNotIn('secret',str(error));self.assertEqual(run.call_count,1)
    def test_receipt_is_closed_typed_and_images_bound(self):
        with fixture() as (root,data,images):
            path=root/'cut.dump';valid=receipt(path,data,images)
            self.assertEqual(operate.check_backup(path,'a'*40,data['runtime']),valid)
            invalid=[{'schema':9,'sha256':valid['sha256']},{**valid,'backendVersion':'b'*40}, {**{k:v for k,v in valid.items() if k!='backendVersion'},'candidate':'a'*40},{**valid,'project':'../bad'},{**valid,'instanceId':'bad'},{**valid,'unknown':True},{**valid,'storage':{**valid['storage'],'generation':True}},{**valid,'storage':{**valid['storage'],'target':[True]*16}}]
            for value in invalid:
                path.with_suffix('.dump.json').write_text(json.dumps(value))
                with self.assertRaises(ValueError):operate.check_backup(path,'a'*40,data['runtime'])
            path.with_suffix('.dump.json').write_text(json.dumps(valid));path.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):operate.check_backup(path)
    def test_all_executed_services_are_bound_before_any_docker_action(self):
        with fixture() as (root,data,images):
            path=root/'output/compose.json';spec=json.loads(path.read_text())
            for service in spec['services']:
                bad=copy.deepcopy(spec);bad['services'][service]['image']='untrusted:latest';path.write_text(json.dumps(bad))
                args=argparse.Namespace(deployment=root/'output',project='identity-fixture',command='verify')
                with patch.object(deploy,'inspect_image') as inspect,patch.object(operate,'command') as run:
                    with self.assertRaises(ValueError):operate.operate(args)
                    run.assert_not_called()
    def test_restore_refuses_live_source_before_creating_target(self):
        with fixture() as (root,data,images):
            archive=root/'cut.dump';receipt(archive,data,images)
            args=argparse.Namespace(command='restore',project='identity-target',deployment=root/'output',backup=archive)
            with patch.object(operate,'deployment_images',return_value='a'*40),patch.object(operate,'project_locks') as locks,patch.object(operate,'require_closed',side_effect=ValueError('source authority')) as closed,patch.object(operate,'command',return_value=subprocess.CompletedProcess([],0,stdout=b'daemon')) as run:
                with self.assertRaisesRegex(ValueError,'source authority'):operate.operate(args)
                closed.assert_called_once_with('identity-source');self.assertEqual(run.call_count,1)
                locks.assert_called_once_with('daemon',['identity-target','identity-source'])
    def test_project_lock_excludes_other_processes_and_releases_after_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'locks'
            script="import operate,sys; from pathlib import Path\nwith operate.project_locks('daemon',['identity-source'],Path(sys.argv[1])): pass"
            env={**os.environ,'PYTHONPATH':str(deploy.ROOT/'hack')}
            with self.assertRaises(RuntimeError):
                with operate.project_locks('daemon',['identity-target','identity-source'],root):
                    result=subprocess.run([sys.executable,'-c',script,str(root)],env=env,capture_output=True,timeout=10)
                    self.assertNotEqual(result.returncode,0);self.assertIn(b'project-busy',result.stderr)
                    raise RuntimeError('interrupted')
            self.assertEqual(subprocess.run([sys.executable,'-c',script,str(root)],env=env,capture_output=True,timeout=10).returncode,0)
    def test_closed_requires_terminal_state_and_confirmed_drain(self):
        stopped={'Status':'exited','Running':False,'Paused':False,'Restarting':False,'ExitCode':0,'OOMKilled':False}
        for status in ['running','paused','restarting','dead','unknown']:
            with patch.object(operate,'authority_states',return_value={'id':('identity',{**stopped,'Status':status})}):
                with self.assertRaises(ValueError):operate.require_closed('fixture')
        for extra in [{'ExitCode':1},{'ExitCode':137},{'OOMKilled':True}]:
            with patch.object(operate,'authority_states',return_value={'id':('identity',{**stopped,**extra})}):
                with self.assertRaisesRegex(ValueError,'drain'):operate.require_closed('fixture',drained=True)
    def test_backup_listing_is_offline_and_uses_the_fixed_pg_tool(self):
        with fixture() as (root,data,images):
            archive=root/'cut.dump';receipt(archive,data,images)
            args=argparse.Namespace(command='check-backup',project='identity-source',deployment=root/'output',backup=archive)
            def execute(argv,**kwargs):
                self.assertEqual(argv[argv.index('--network')+1],'none');self.assertEqual(argv[-2:],[images['postgres'],'--list']);self.assertEqual(kwargs['stdin'].read(),b'fixture')
                return subprocess.CompletedProcess(argv,0)
            with patch.object(operate,'deployment_images',return_value='a'*40),patch.object(operate,'command',side_effect=execute) as run:
                operate.operate(args);self.assertEqual(run.call_count,1)

class ImageContractTests(unittest.TestCase):
    def test_all_backend_commands_share_image_and_credentials_stay_scoped(self):
        with fixture() as (root,_,_):
            services=json.loads((root/'output/compose.json').read_text())['services']
            self.assertEqual(services['identity']['image'],services['migrate']['image'])
            self.assertEqual(services['identity']['image'],services['maintenance']['image'])
            self.assertEqual(services['migrate']['entrypoint'],['identity-migrate'])
            for name in ['identity','gateway','migrate','maintenance']:
                self.assertEqual(services[name]['pull_policy'],'never')
            for name,forbidden in [('identity',['owner-password','maintenance-password']),('maintenance',['owner-password','runtime-password']),('migrate',['maintenance-password','runtime-password'])]:
                mounts=[v['target'] for v in services[name]['volumes']]
                for secret in forbidden:self.assertNotIn('/run/input/'+secret,mounts)

    def test_inspection_rejects_missing_wrong_platform_user_or_version(self):
        good={'Id':'sha256:'+'1'*64,'Os':'linux','Architecture':'amd64','Config':{'User':'10001:10001','Labels':{'org.opencontainers.image.revision':'a'*40}}}
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=json.dumps([good]))) as run:
            self.assertEqual(deploy.inspect_image('backend:ready',True),good)
            self.assertEqual(run.call_args.args[0],['docker','image','inspect','--platform','linux/amd64','backend:ready'])
        for image in [[],[{**good,'Architecture':'arm64'}],[{**good,'Id':'mutable:tag'}],[{**good,'Config':{'User':'0'}}],[{**good,'Config':{'User':'10001:10001','Labels':{}}}]]:
            with patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=json.dumps(image))):
                with self.assertRaises(ValueError):deploy.inspect_image('fixture',True)
        with patch('subprocess.run',side_effect=subprocess.CalledProcessError(1,['docker'])):
            with self.assertRaises(subprocess.CalledProcessError):deploy.inspect_image('missing',True)

    def test_frontend_redeployment_does_not_invalidate_backup(self):
        with fixture() as (root,data,images):
            path=root/'cut.dump';value=receipt(path,data,images)
            spec=json.loads((root/'output/compose.json').read_text())
            spec['services']['gateway']['image']='sha256:'+'5'*64
            def inspect(image,product):
                return {'Id':image,'Config':{'Labels':{'org.opencontainers.image.revision':'a'*40 if image==images['identity'] else 'b'*40}}}
            with patch.object(deploy,'inspect_image',side_effect=inspect):
                backend=operate.deployment_images(spec)
            self.assertEqual(operate.check_backup(path,backend,data['runtime']),value)

    def test_old_cli_parameters_are_rejected(self):
        for script in ['deploy.py','operate.py','reference_seams.py']:
            result=subprocess.run([sys.executable,str(deploy.ROOT/'hack'/script),'--candidate','old'],capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
        result=subprocess.run(['make','candidate'],cwd=deploy.ROOT,capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
