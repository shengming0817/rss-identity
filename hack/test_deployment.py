import copy,json,tempfile,unittest
from pathlib import Path
import deploy

class Deployment(unittest.TestCase):
 def data(self,root):
  source=json.loads((deploy.ROOT/'deployment/example.json').read_text())
  def files(v):
   if isinstance(v,dict):return {k:files(x) for k,x in v.items()}
   if isinstance(v,list):return [files(x) for x in v]
   if isinstance(v,str) and v.startswith('/srv/rss-identity/input/'):
    p=root/Path(v).name;p.write_text('TestSecret_'+p.stem.replace('-','_')+'_'*64);p.chmod(0o600);return str(p)
   return v
  return files(source)
 def test_render_keeps_credentials_and_ingress_separate(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);data=self.data(root)
   path=deploy.render(data,root/'rendered',{'server':'server@sha256:test','operator':'operator@sha256:test','gateway':'gateway@sha256:test'})
   c=json.loads(path.read_text());services=c['services']
   runtime={v['target'] for v in services['identity']['volumes']}
   self.assertNotIn('/run/input/owner-password',runtime);self.assertNotIn('/run/input/maintenance-password',runtime)
   self.assertNotIn('ports',services['identity']);self.assertNotIn('ports',services['hydra']);self.assertNotIn('ports',services['hydra-admin'])
   self.assertEqual(services['identity']['networks']['backend']['ipv4_address'],'172.29.0.4')
   public=(root/'rendered/public.conf').read_text();self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;',public);self.assertNotIn('proxy_add_x_forwarded_for',public);self.assertIn('location ^~ /internal/ { return 404; }',public)
   self.assertEqual(json.loads((root/'rendered/runtime.json').read_text())['identity_origin'],data['runtime']['identity_origin'])
   self.assertEqual(json.loads((root/'rendered/hydra.json').read_text())['urls']['self']['issuer'],'https://identity.example.test/oidc')
   self.assertEqual(json.loads((root/'rendered/clients.json').read_text())[0]['redirect_uris'],['https://mdm.example.test/auth/callback'])
 def test_topology_drift_and_unsafe_secret_are_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);data=self.data(root);data['runtime']['public_gateway']='172.29.0.9'
   with self.assertRaises(ValueError):deploy.render(data,root/'bad',{})
   data=self.data(root);Path(data['runtime']['database']['password_file']).chmod(0o644)
   with self.assertRaises(ValueError):deploy.render(data,root/'unsafe',{})
