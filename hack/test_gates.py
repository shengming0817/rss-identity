import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tomllib
import unittest
from unittest.mock import patch
import check_dependencies as deps
import providers

class Gates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata = json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1']))
        cls.manifest = tomllib.loads(Path('Cargo.toml').read_text())

    def test_workspace_identity_and_binary(self):
        members = [p for p in self.metadata['packages'] if p['id'] in self.metadata['workspace_members']]
        self.assertEqual({p['name'] for p in members}, {'rss-identity-core', 'rss-identity-postgres', 'rss-identity-oidc', 'rss-identity-app', 'rss-identity-http-axum', 'rss-identity-hydra', 'rss-identity-contracts', 'rss-identity-client'})
        binaries = [t['name'] for p in members for t in p['targets'] if 'bin' in t['kind']]
        self.assertEqual(set(binaries), {'identity-admin','identity-server','identity-migrate','identity-clients'})

    def test_independent_consumer_rejects_server_dependencies(self):
        import check_consumer
        metadata=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1','--manifest-path','tests/consumer/Cargo.toml']))
        check_consumer.check(metadata)
        metadata['packages'].append({'id':'forbidden','name':'rss-identity-postgres','source':None})
        with self.assertRaises(ValueError):check_consumer.check(metadata)

    def test_local_identity_packages_preserve_rss_source_checks(self):
        deps.check(self.metadata, self.manifest)
        data = copy.deepcopy(self.metadata)
        next(p for p in data['packages'] if p['name'] == 'rss-contract')['source'] = None
        with self.assertRaises(ValueError):
            deps.check(data, self.manifest)

    def test_optimized_interpreter_rejects_source(self):
        script = "import check_dependencies as d,json,tomllib; m=json.load(open('/dev/stdin')); c=tomllib.load(open('Cargo.toml','rb')); c['workspace']['dependencies']['rss-contract']['git']='https://invalid.test'; d.check(m,c)"
        result = subprocess.run([sys.executable,'-O','-c',script], input=json.dumps(self.metadata),text=True,capture_output=True,env={**os.environ,'PYTHONPATH':'hack'})
        self.assertNotEqual(result.returncode,0)

    def test_resolved_feature_drift(self):
        for features in [[], ['integration','test-support','unexpected'], ['integration']]:
            data=copy.deepcopy(self.metadata)
            ids={p['id'] for p in data['packages'] if p['name']=='rss-transactional-messaging-postgres'}
            for node in data['resolve']['nodes']:
                if node['id'] in ids: node['features']=features
            with self.subTest(features=features), self.assertRaises(ValueError): deps.check(data,self.manifest)

    def test_ci_credentials_only_reach_fetch(self):
        with patch.dict(os.environ, {'SYSTEM_ACCESSTOKEN':'synthetic-secret','PATH':'/usr/bin'},clear=True), patch('subprocess.run') as run:
            runpy.run_path('hack/ci.py',run_name='__main__')
        calls=run.call_args_list
        self.assertEqual(calls[0].args[0],['cargo','fetch','--locked'])
        self.assertIn('synthetic-secret',str(calls[0].kwargs['env']))
        self.assertNotIn('synthetic-secret',str(calls[1:]))
        self.assertEqual(calls[-1].kwargs['env']['CARGO_NET_OFFLINE'],'true')

    def test_provider_zero_tests_rejected(self):
        with patch('providers.bounded_run',return_value=subprocess.CompletedProcess([],0,stdout='0 tests, 0 benchmarks\n')):
            with self.assertRaises(RuntimeError): providers.cargo('rss-identity-oidc','provider',{})

    def test_provider_partial_execution_rejected(self):
        listing='real_provider_flows: test\n\n1 test, 0 benchmarks\n'
        result='test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n'
        with patch('providers.bounded_run',side_effect=[subprocess.CompletedProcess([],0,stdout=listing),subprocess.CompletedProcess([],0,stdout=result)]):
            with self.assertRaises(RuntimeError): providers.cargo('rss-identity-oidc','provider',{})

    def test_production_features_do_not_include_test_support(self):
        actual = {k:set(v) for k,v in deps.RSS_FEATURES.items()}
        with self.assertRaises(ValueError): deps.check_features(actual,'production')
        actual['rss-transactional-messaging-postgres']=set()
        deps.check_features(actual,'production')

    def test_advisory_acceptance_revoked_on_version_or_path_drift(self):
        for change in ['version','path']:
            data=copy.deepcopy(self.metadata)
            rsa=next(p for p in data['packages'] if p['name']=='rsa')
            if change=='version': rsa['version']='0.9.11'
            else:
                node=next(n for n in data['resolve']['nodes'] if n['id'] in data['workspace_members'])
                node['deps'].append({'pkg':rsa['id']})
            with self.subTest(change=change),self.assertRaises(ValueError): deps.check_advisory_path(data)

    def test_other_advisories_cannot_be_ignored(self):
        policy=tomllib.loads(Path('deny.toml').read_text())
        policy['advisories']['ignore'].append('RUSTSEC-2099-0001')
        with self.assertRaises(ValueError): deps.check_advisory_policy(policy)

    def test_ci_removes_inherited_git_authentication(self):
        inherited={'PATH':'/usr/bin','SYSTEM_ACCESSTOKEN':'synthetic-job', 'GIT_CONFIG_COUNT':'1',
                   'GIT_CONFIG_KEY_0':'http.extraheader','GIT_CONFIG_VALUE_0':'bearer synthetic-inherited'}
        with patch.dict(os.environ,inherited,clear=True),patch('subprocess.run') as run:
            runpy.run_path('hack/ci.py',run_name='__main__')
        self.assertEqual(run.call_args_list[0].kwargs['env']['GIT_CONFIG_COUNT'],'2')
        self.assertNotIn('synthetic-',str(run.call_args_list[1:]))

    def test_ci_fetch_failure_prevents_build(self):
        with patch.dict(os.environ,{'PATH':'/usr/bin'},clear=True),patch('subprocess.run',side_effect=subprocess.CalledProcessError(1,'cargo')) as run:
            with self.assertRaises(subprocess.CalledProcessError): runpy.run_path('hack/ci.py',run_name='__main__')
        self.assertEqual(run.call_count,1)
