"""Prevent artifact substitution and empty or secret-bearing acceptance evidence."""
import copy
import pathlib
import tempfile
import unittest

import evidence


class EvidenceTests(unittest.TestCase):
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

    def test_secrets_and_unknown_evidence_fields_are_rejected(self):
        evidence.check_public({'stage': 'login', 'status': 200, 'passed': True})
        for field in ['password', 'cookie', 'credential', 'csrf_token', 'debug']:
            with self.assertRaises(evidence.Refused):
                evidence.check_public({field: 'sensitive'})


if __name__ == '__main__':
    unittest.main()
