import copy
import unittest
import check_consumer as c

class ConsumerBoundary(unittest.TestCase):
    def fixture(self):
        packages=[{'id':'root','name':'identity-local-consumer','source':None,'version':'0.1.0'}]
        for name in ['core','postgres','http-axum']:
            packages.append({'id':name,'name':'rss-identity-'+name,'source':f'git+{c.IDENTITY}?rev={"a"*40}#{"a"*40}','version':'0.1.0'})
        return {'packages':packages,'workspace_members':['root'],'resolve':{'nodes':[{'id':p['id'],'features':[],'deps':[]} for p in packages]}}

    def test_rejects_path_source_and_reference_application(self):
        fixture=self.fixture()
        c.check(fixture,'a'*40,'b'*40,'local')
        for change in ['path','revision','app','oidc']:
            data=copy.deepcopy(fixture)
            if change=='path': data['packages'][1]['source']=None
            if change=='revision': data['packages'][1]['source']=f'git+{c.IDENTITY}?rev=main#'+('a'*40)
            if change=='app': data['packages'][1]['name']='rss-identity-app'
            if change=='oidc': data['packages'].append({'id':'reqwest','name':'reqwest','source':c.REGISTRY,'version':'0.12.28'})
            with self.subTest(change=change),self.assertRaises(ValueError):c.check(data,'a'*40,'b'*40,'local')

    def test_manifest_is_standalone_fixed_git_without_source_override(self):
        import tomllib
        for profile in ['local','oidc']:
            m=tomllib.loads(c.manifest(profile,'a'*40,'b'*40))
            self.assertIn('workspace',m)
            self.assertNotIn('patch',m)
            self.assertNotIn('replace',m)
            for name,dep in m['dependencies'].items():
                if name.startswith('rss-'):
                    self.assertEqual(dep['rev'],'a'*40 if name.startswith('rss-identity-') else 'b'*40)
                    self.assertNotIn('path',dep)
