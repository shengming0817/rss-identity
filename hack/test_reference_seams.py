import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import reference_seams as seams

class RecordTests(unittest.TestCase):
    def test_deployment_starts_with_previous_web_image_id(self):
        details={name:{'Id':'sha256:'+str(number)*64} for name,number in [('identity',1),('web',2),('postgres',3),('runtime',4)]}
        images,updated_web=seams.deployment_images(details,{'Id':'sha256:'+'5'*64})
        self.assertEqual(images,{'identity':'sha256:'+'1'*64,'web':'sha256:'+'5'*64,'postgres':'sha256:'+'3'*64,'runtime':'sha256:'+'4'*64})
        self.assertEqual(updated_web,'sha256:'+'2'*64)

    def test_only_complete_matching_subject_and_confirmed_cleanup_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            def image(number,revision,architecture,variant=None):
                return seams.product_image({'Id':'sha256:'+str(number)*64,'Os':'linux','Architecture':architecture,'Variant':variant,'Config':{'Labels':{'org.opencontainers.image.revision':revision}}})
            subject={'images':{'identity':image(1,'a'*40,'arm64','v8'),'web':image(2,'b'*40,'arm64','v8'),'previousWeb':image(3,'c'*40,'amd64')}}
            good={'formatVersion':3,'scope':'image-operation-seams','subject':subject,'steps':[{'name':name,'status':'passed','elapsedMs':1} for name in seams.STEPS],'result':'passed','failure':None,'cleanup':{'status':'passed','remaining':[]}}
            record=root/'record.json';seams.save(record,good);seams.verify_record(record,subject)
            variants=[]
            for field,value in [('result','running'),('cleanup',{'status':'failed','remaining':['fixture']}),('steps',good['steps'][:-1]),('failure',{'stage':'rekey','reason':'timeout'})]:
                variants.append({**good,field:value})
            wrong=copy.deepcopy(good);wrong['subject']['images']['identity']['id']='0'*64;variants.append(wrong)
            wrong=copy.deepcopy(good);wrong['steps'][0]['status']='failed';variants.append(wrong)
            variants.append({**good,'extra':'unverified'})
            for value in variants:
                seams.save(record,value)
                with self.assertRaises(ValueError):seams.verify_record(record,subject)

    def test_fixture_subnets_avoid_existing_broad_networks(self):
        networks=[{'IPAM':{'Config':[{'Subnet':'172.29.0.0/16'},{'Subnet':'10.243.0.0/20'},{'Subnet':'fd00::/64'}]}}]
        with patch.object(seams,'process',side_effect=[b'id',json.dumps(networks).encode()]):
            self.assertEqual(seams.free_subnets(),['10.243.16.0/24','10.243.17.0/24'])
