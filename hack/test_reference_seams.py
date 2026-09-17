import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import operate
import reference_seams as seams

class RecordTests(unittest.TestCase):
    def test_only_complete_matching_subject_and_confirmed_cleanup_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runner=root/'runner.py';runner.write_text('fixture')
            (root/'candidate.json').write_text(json.dumps({'revision':'a'*40,'ui':{'revision':'b'*40}}))
            good={'formatVersion':1,'scope':'candidate-operator-seams','subject':{'candidateSha256':operate.sha(root/'candidate.json'),'identityRevision':'a'*40,'webRevision':'b'*40,'runnerSha256':operate.sha(runner)},'steps':[{'name':name,'status':'passed','elapsedMs':1} for name in seams.STEPS],'result':'passed','failure':None,'cleanup':{'status':'passed','remaining':[]}}
            record=root/'record.json';seams.save(record,good);seams.verify_record(record,root,runner)
            variants=[]
            for field,value in [('result','running'),('cleanup',{'status':'failed','remaining':['fixture']}),('steps',good['steps'][:-1]),('failure',{'stage':'rekey','reason':'timeout'})]:
                variants.append({**good,field:value})
            wrong=copy.deepcopy(good);wrong['subject']['candidateSha256']='0'*64;variants.append(wrong)
            wrong=copy.deepcopy(good);wrong['steps'][0]['status']='failed';variants.append(wrong)
            variants.append({**good,'extra':'unverified'})
            for value in variants:
                seams.save(record,value)
                with self.assertRaises(ValueError):seams.verify_record(record,root,runner)
            seams.save(record,good);runner.write_text('changed')
            with self.assertRaises(ValueError):seams.verify_record(record,root,runner)

    def test_fixture_subnets_avoid_existing_broad_networks(self):
        networks=[{'IPAM':{'Config':[{'Subnet':'172.29.0.0/16'},{'Subnet':'10.243.0.0/20'},{'Subnet':'fd00::/64'}]}}]
        with patch.object(seams,'process',side_effect=[b'id',json.dumps(networks).encode()]):
            self.assertEqual(seams.free_subnets(),['10.243.16.0/24','10.243.17.0/24'])
