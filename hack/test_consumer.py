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

    def test_report_keeps_same_name_multiple_versions(self):
        data=self.fixture()
        for version in ['1.0.0','2.0.0']:
            package_id='registry+example#shared@'+version
            data['packages'].append({'id':package_id,'name':'shared','version':version,'source':c.REGISTRY})
            data['resolve']['nodes'].append({'id':package_id,'features':[version],'deps':[]})
        closure=c.check(data,'a'*40,'b'*40,'local')
        shared=[v for v in closure.values() if v['name']=='shared']
        self.assertEqual({v['version'] for v in shared},{'1.0.0','2.0.0'})
        self.assertEqual({tuple(v['features']) for v in shared},{('1.0.0',),('2.0.0',)})

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

    def test_oidc_fixture_feature_is_explicit_and_mode_checked(self):
        import tomllib
        m=tomllib.loads(c.manifest('oidc','a'*40,'b'*40))
        self.assertEqual(m['features'], {'default': [], 'loopback-fixture': ['rss-identity-oidc/test-support']})
        data=self.fixture()
        data['packages'][0]['name']='identity-oidc-consumer'
        for name, version, source in [('rss-identity-oidc','0.1.0',f'git+{c.IDENTITY}?rev={"a"*40}#{"a"*40}'),('openidconnect','4.0.1',c.REGISTRY),('rsa','0.9.10',c.REGISTRY)]:
            data['packages'].append({'id':name,'name':name,'version':version,'source':source})
            data['resolve']['nodes'].append({'id':name,'features':[],'deps':[]})
        nodes={n['id']:n for n in data['resolve']['nodes']}
        nodes['rss-identity-oidc']['deps']=[{'pkg':'openidconnect'}]
        nodes['openidconnect']['deps']=[{'pkg':'rsa'}]
        c.check(data,'a'*40,'b'*40,'oidc')
        with self.assertRaises(ValueError):c.check(data,'a'*40,'b'*40,'oidc',fixture=True)
        nodes['rss-identity-oidc']['features']=['test-support']
        c.check(data,'a'*40,'b'*40,'oidc',fixture=True)
        with self.assertRaises(ValueError):c.check(data,'a'*40,'b'*40,'oidc')

    def test_actual_compiler_features_cannot_hide_fixture_mode(self):
        import json
        closure={'oidc': {'name':'rss-identity-oidc','features':[]}}
        artifact={'reason':'compiler-artifact','package_id':'oidc','features':[]}
        self.assertEqual(c.compiled_features(json.dumps(artifact),closure,'oidc'),{'oidc':[]})
        artifact['features']=['test-support']
        with self.assertRaises(ValueError):c.compiled_features(json.dumps(artifact),closure,'oidc')
        with self.assertRaises(ValueError):c.compiled_features('',closure,'oidc')
