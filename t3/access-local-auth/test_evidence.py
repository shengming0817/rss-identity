"""Prevent artifact substitution and empty or secret-bearing acceptance evidence."""
import copy
import json
import pathlib
import tempfile
import unittest

import evidence


class EvidenceTests(unittest.TestCase):
    def test_changed_execution_helper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'helper.py').write_bytes(b'original')
            evidence.check_source(root / 'helper.py', b'original')
            (root / 'helper.py').write_bytes(b'changed')
            with self.assertRaises(evidence.Refused):
                evidence.check_source(root / 'helper.py', b'original')

    def test_archive_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'archive'
            path.write_bytes(b'original')
            digest = evidence.sha(path)
            evidence.check_file(path, digest)
            path.write_bytes(b'changed')
            with self.assertRaises(evidence.Refused):
                evidence.check_file(path, digest)

    def test_incomplete_or_failed_journey_cannot_pass(self):
        good = {name: {'passed': True} for name in evidence.SCENARIOS}
        evidence.check_steps(good)
        for name in evidence.SCENARIOS:
            missing = copy.deepcopy(good)
            missing.pop(name)
            with self.assertRaises(evidence.Refused):
                evidence.check_steps(missing)
            failed = copy.deepcopy(good)
            failed[name]['passed'] = False
            with self.assertRaises(evidence.Refused):
                evidence.check_steps(failed)

    def test_cookie_removal_is_not_online_revocation_evidence(self):
        with self.assertRaises(evidence.Refused):
            evidence.check_revocation({'status': 401, 'online': False}, 200, 60)
        with self.assertRaises(evidence.Refused):
            evidence.check_revocation({'status': 503, 'online': True}, 503, 60)
        with self.assertRaises(evidence.Refused):
            evidence.check_revocation({'status': 403, 'online': True}, 200, 0)
        evidence.check_revocation({'status': 403, 'online': True}, 200, 60)

    def test_nested_event_secrets_and_wrong_contract_versions_are_rejected(self):
        tenant = '11111111-1111-4111-8111-111111111111'
        payload = {'action': 'initialized', 'tenant': tenant, 'principal': tenant, 'actor': None, 'epoch': 1,
                   'state': {'enabled': True, 'administrator': True, 'emergency': True, 'member_active': True, 'membership_epoch': 1}}
        envelope = {'seq': 1, 'contract': 'identity.account.security', 'version': 'v2', 'schema': 'sha256:' + 'a' * 64,
                    'payload': list(json.dumps(payload).encode())}
        schemas = {envelope['contract']: envelope['schema']}
        evidence.project_event(envelope, tenant, schemas)
        payload['state']['password'] = 'private'
        with self.assertRaises(evidence.Refused):
            evidence.project_event({**envelope, 'payload': list(json.dumps(payload).encode())}, tenant, schemas)
        for field, value in [('version', 'v1'), ('schema', 'sha256:' + 'b' * 64)]:
            with self.assertRaises(evidence.Refused):
                evidence.project_event({**envelope, field: value}, tenant, schemas)

    def test_secrets_and_unknown_evidence_fields_are_rejected(self):
        evidence.check_public({'stage': 'login', 'status': 200, 'passed': True})
        for field in ['password', 'cookie', 'credential', 'csrf_token', 'debug']:
            with self.assertRaises(evidence.Refused):
                evidence.check_public({field: 'sensitive'})


if __name__ == '__main__':
    unittest.main()
