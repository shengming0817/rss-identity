import copy
import unittest
import reference_t3 as t3


class EvidenceTests(unittest.TestCase):
    def complete(self):
        subject = {"identity": {"revision": "a" * 40, "id": "sha256:" + "1" * 64}}
        record = t3.new_record(subject, None)
        record["steps"] = [
            {"name": name, "status": "passed", "elapsedMs": 1, "observations": {}}
            for name in t3.STEPS
        ]
        record["cleanup"] = {"status": "passed", "remaining": []}
        record["measurements"] = {name: 1 for name in t3.MEASUREMENTS}
        record["result"] = "measured"
        return record, subject

    def test_unapproved_baseline_is_never_acceptance(self):
        record, subject = self.complete()
        t3.verify_record(record, subject)
        record["result"] = "passed"
        with self.assertRaises(ValueError):
            t3.verify_record(record, subject)

    def test_partial_failed_or_mismatched_evidence_cannot_pass(self):
        original, subject = self.complete()
        for field, value in [
            ("steps", original["steps"][:-1]),
            ("cleanup", {"status": "failed", "remaining": ["owned-container"]}),
            ("failure", {"stage": "restore", "reason": "unconfirmed"}),
            ("subject", {}),
            ("measurements", {}),
        ]:
            record = copy.deepcopy(original)
            record[field] = value
            with self.assertRaises(ValueError):
                t3.verify_record(record, subject)

    def test_closed_result_rejects_extra_fields_and_secrets(self):
        record, subject = self.complete()
        record["password"] = "synthetic-password"
        with self.assertRaises(ValueError):
            t3.verify_record(record, subject)
        with self.assertRaises(ValueError):
            t3.assert_redacted({"value": "synthetic-password"}, ["synthetic-password"])

    def test_target_input_requires_explicit_candidate_and_approval(self):
        for value in [{}, {"limits": {}}, {"acceptedBy": "owner"}]:
            with self.assertRaises(ValueError):
                t3.validate_targets(value, {"identity": {}})
