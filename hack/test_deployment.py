import copy,json,tempfile,unittest,os,subprocess
from unittest.mock import patch
from pathlib import Path
import deploy

class Deployment(unittest.TestCase):
 def setUp(self):
  uid=patch.object(deploy,'DEPLOY_UID',os.getuid());gid=patch.object(deploy,'DEPLOY_GID',os.getgid());uid.start();gid.start();self.addCleanup(uid.stop);self.addCleanup(gid.stop)
  for name,value in [('KEYCLOAK_UID',os.getuid()),('KEYCLOAK_GID',os.getgid())]:
   item=patch.object(deploy,name,value);item.start();self.addCleanup(item.stop)
 def candidate(self):return {'images':{k:k+'@sha256:'+'a'*64 for k in ['server','operator','gateway']},'providers':deploy.IMAGES}

 def data(self,root):
  source=json.loads((deploy.ROOT/'deployment/example.json').read_text())
  def files(v):
   if isinstance(v,dict):return {k:files(x) for k,x in v.items()}
   if isinstance(v,list):return [files(x) for x in v]
   if isinstance(v,str) and v.startswith('/srv/rss-identity/input/'):
    p=root/Path(v).name;p.write_text('TestSecret_'+p.stem.replace('-','_')+'_'*64);p.chmod(0o600);return str(p)
   return v
  return files(source)
 def test_compose_preserves_volume_initialization_shell_expansion(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);path=deploy.render(self.data(root),root/'rendered',self.candidate())
   result=subprocess.run(['docker','compose','-f',str(path),'--profile','install','config','--format','json'],capture_output=True,text=True,timeout=30)
   self.assertEqual(result.returncode,0,result.stderr)
   # Compose serializes literal shell dollars as $$ so its output can be consumed again.
   command=json.loads(result.stdout)['services']['volume-init']['command'][0]
   self.assertIn('d="$${spec%%:*}"',command)
   self.assertIn('owner="$${spec#*:}"',command)
   self.assertIn('$$(find "$$d"',command)
   self.assertIn('chown "$$owner" "$$d"',command)

 def test_configuration_diagnostics_are_actionable_without_input_values(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   for field in ['hydra_system_secret_files','hydra_cookie_secret_files']:
    data=self.data(root);data.pop(field)
    with self.assertRaises(ValueError) as error:deploy.render(data,root/field,self.candidate())
    self.assertIn(field,deploy.configuration_diagnostic(error.exception))
   data=self.data(root);data['runtime']['oidc']['providers'][0].pop('keycloak_totp')
   with self.assertRaises(ValueError) as error:deploy.render(data,root/'profile',self.candidate())
   self.assertIn('keycloak_totp',deploy.configuration_diagnostic(error.exception))
   for error in [ValueError('synthetic-secret'),KeyError('synthetic-secret'),OSError('synthetic-secret')]:
    self.assertNotIn('synthetic-secret',deploy.configuration_diagnostic(error))

 def test_render_keeps_credentials_and_ingress_separate(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);data=self.data(root)
   path=deploy.render(data,root/'rendered',self.candidate())
   c=json.loads(path.read_text());services=c['services']
   runtime={v['target'] for v in services['identity']['volumes']}
   self.assertNotIn('/run/input/owner-password',runtime);self.assertNotIn('/run/input/maintenance-password',runtime)
   self.assertNotIn('ports',services['identity']);self.assertNotIn('ports',services['hydra']);self.assertNotIn('ports',services['hydra-admin'])
   self.assertEqual(services['identity']['networks']['backend']['ipv4_address'],'172.29.0.4')
   public=(root/'rendered/public.conf').read_text();self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;',public);self.assertNotIn('proxy_add_x_forwarded_for',public);self.assertIn('location ^~ /internal/ { return 404; }',public)
   self.assertEqual(json.loads((root/'rendered/runtime.json').read_text())['identity_origin'],data['runtime']['identity_origin'])
   self.assertEqual(json.loads((root/'rendered/hydra.json').read_text())['urls']['self']['issuer'],'https://identity.example.test/oidc')
   registration=services['hydra-clients']
   self.assertEqual(registration['network_mode'],'service:hydra')
   self.assertEqual(registration['depends_on'],{'hydra':{'condition':'service_healthy'}})
   self.assertEqual(services['hydra']['healthcheck']['test'],['CMD','wget','-q','-T','3','-O','/dev/null','http://127.0.0.1:4445/health/ready'])
   self.assertEqual(registration['entrypoint'],['identity-clients'])
   self.assertIn('/run/config/runtime.json',{v['target'] for v in registration['volumes']})
   self.assertNotIn('/run/input/owner-password',{v['target'] for v in registration['volumes']})
 def test_topology_drift_and_unsafe_secret_are_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);data=self.data(root);data['runtime']['public_gateway']='172.29.0.9'
   with self.assertRaises(ValueError):deploy.render(data,root/'bad',self.candidate())
   data=self.data(root);Path(data['runtime']['database']['password_file']).chmod(0o644)
   with self.assertRaises(ValueError):deploy.render(data,root/'unsafe',self.candidate())

 def test_candidate_provider_identity_does_not_follow_new_checkout(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);data=self.data(root);candidate=copy.deepcopy(self.candidate())
   changed={**deploy.IMAGES,'postgres':'postgres:new@sha256:'+'b'*64}
   with patch.object(deploy,'IMAGES',changed):path=deploy.render(data,root/'rendered',candidate)
   self.assertEqual(json.loads(path.read_text())['services']['postgres']['image'],candidate['providers']['postgres'])

 def test_native_keyrings_and_approved_totp_profile(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);data=self.data(root)
   keys=[]
   for name in ['new-system','old-system','cookie']:
    path=root/name;path.write_text(name+'_'*64);path.chmod(0o600);keys.append(str(path))
   data.pop('hydra_system_secret_file',None)
   data['hydra_system_secret_files']=keys[:2];data['hydra_cookie_secret_files']=keys[2:]
   data['runtime']['oidc']['providers'][0]['keycloak_totp']=True
   deploy.render(data,root/'rendered',self.candidate())
   hydra=json.loads((root/'rendered/hydra.json').read_text())
   self.assertEqual(hydra['secrets'],{'system':[Path(p).read_text() for p in keys[:2]],'cookie':[Path(keys[2]).read_text()]})
   realms=list((root/'rendered').glob('realm-*.json'));self.assertEqual(len(realms),1)
   realm=json.loads(realms[0].read_text());self.assertEqual(realm['browserFlow'],'identity-step-up')
   self.assertNotIn('users',realm)
   for files in [[],[keys[0],keys[0]]]:
    bad=copy.deepcopy(data);bad['hydra_system_secret_files']=files
    with self.assertRaises(ValueError):deploy.render(bad,root/('bad-'+str(len(files))),self.candidate())
   bad=copy.deepcopy(data);bad['hydra_cookie_secret_files']=[keys[0]]
   with self.assertRaises(ValueError):deploy.render(bad,root/'overlap',self.candidate())
