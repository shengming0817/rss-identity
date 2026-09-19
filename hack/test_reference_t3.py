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

    def approved(self):
        import json

        record, subject = self.complete()
        raw = json.dumps(record).encode()
        targets = {
            "subject": subject,
            "approvalReference": "https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1057?discussionId=123",
            "baselineSha256": t3.digest(raw),
            "limits": {name: 1 for name in t3.LIMITS},
        }
        return targets, subject, raw

    def test_approval_cannot_be_an_unrelated_or_secret_bearing_url(self):
        targets, subject, raw = self.approved()
        t3.validate_targets(targets, subject, raw)
        for reference in [
            "https://dev.azure.com/org",
            targets["approvalReference"] + "&token=secret",
            targets["approvalReference"] + "#secret",
            "https://dev.azure.com/another/rss/_git/rss-identity/pullrequest/1057?discussionId=123",
        ]:
            targets["approvalReference"] = reference
            with self.assertRaises(ValueError):
                t3.validate_targets(targets, subject, raw)

    def test_acceptance_requires_the_exact_complete_baseline(self):
        import json

        targets, subject, raw = self.approved()
        for invalid in [None, raw + b" ", b"{}"]:
            with self.assertRaises(ValueError):
                t3.validate_targets(targets, subject, invalid)
        baseline = json.loads(raw)
        baseline["result"] = "failed"
        invalid = json.dumps(baseline).encode()
        targets["baselineSha256"] = t3.digest(invalid)
        with self.assertRaises(ValueError):
            t3.validate_targets(targets, subject, invalid)

    def test_daemon_mismatch_fails_before_creating_private_workspace(self):
        from unittest.mock import patch

        with (
            patch.object(t3, "docker", return_value=b"different"),
            patch.object(t3.Path, "mkdir") as mkdir,
        ):
            with self.assertRaisesRegex(ValueError, "docker-daemon-mismatch"):
                t3.Run({"subject": {"resources": {"daemonId": "expected"}}})
            mkdir.assert_not_called()

    def test_browser_lock_rejects_same_version_different_integrity(self):
        identity = {"version": "1.60.0", "integrity": "sha512-" + "A" * 86 + "=="}
        lock = (
            "packages:\n  playwright-core@1.60.0:\n    resolution: {integrity: "
            + identity["integrity"]
            + "}\n"
        ).encode()
        t3.verify_browser_lock(lock, identity)
        for invalid in [
            lock.replace(b"sha512-A", b"sha512-B"),
            lock + lock,
            b"playwright-core@1.60.0",
        ]:
            with self.assertRaises(ValueError):
                t3.verify_browser_lock(invalid, identity)

    def test_outer_interruptions_never_publish_success_before_cleanup(self):
        import argparse, json, tempfile
        from pathlib import Path
        from unittest.mock import patch

        for when in [
            "executing",
            "report-copy",
            "cleanup",
            "cleanup-failed",
            "success",
        ]:
            with self.subTest(when=when), tempfile.TemporaryDirectory() as temp:
                report, subject = self.complete()
                args = argparse.Namespace(record=Path(temp) / "result.json")

                def docker(*words, **kwargs):
                    if words[:2] == ("volume", "inspect"):
                        return b'[{"Mountpoint":"/private"}]'
                    if words[:2] == ("network", "inspect"):
                        return b'[{"IPAM":{"Config":[{"Gateway":"172.17.0.1"}]}}]'
                    if "cat" in words:
                        if when == "report-copy":
                            raise KeyboardInterrupt()
                        return json.dumps(report).encode()
                    return b""

                def cleanup(*_):
                    self.assertEqual(
                        json.loads(args.record.read_text())["result"], "running"
                    )
                    if when == "cleanup":
                        raise SystemExit(143)
                    return ["owned-resource"] if when == "cleanup-failed" else []

                with (
                    patch.object(
                        t3,
                        "candidate",
                        return_value=(
                            {"identity": {"Id": "image"}},
                            {"Id": "tools"},
                            subject,
                            None,
                            None,
                        ),
                    ),
                    patch.object(t3, "docker", side_effect=docker),
                    patch.object(t3, "process", return_value=b"archive"),
                    patch.object(
                        t3,
                        "bounded_run",
                        side_effect=SystemExit(143) if when == "executing" else None,
                        return_value=argparse.Namespace(returncode=0),
                    ),
                    patch.object(t3, "cleanup_operator", side_effect=cleanup),
                ):
                    self.assertEqual(t3.outside(args), when == "success")
                final = json.loads(args.record.read_text())
                self.assertEqual(
                    final["result"], "measured" if when == "success" else "failed"
                )

    def test_process_diagnostics_keep_closed_action_and_exit_code_only(self):
        import subprocess
        from unittest.mock import patch

        with patch.object(
            t3,
            "bounded_run",
            return_value=subprocess.CompletedProcess(
                [], 7, b"password=secret", b"token=secret"
            ),
        ):
            with self.assertRaises(t3.ProcessFailure) as caught:
                t3.process(["docker", "run", "--password=secret"])
        fact = t3.failure_fact(caught.exception, "install")
        self.assertEqual(
            fact,
            {
                "stage": "install",
                "reason": "process-failed",
                "action": "docker-run",
                "exitCode": 7,
            },
        )
        t3.assert_redacted(fact, ["secret"])

    def test_single_make_entry_builds_fixed_tools_before_runner(self):
        import subprocess

        result = subprocess.run(
            ["make", "-n", "test-reference"],
            cwd=t3.ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertLess(
            result.index("docker buildx build"), result.index("hack/reference_t3.py")
        )
        self.assertNotIn("git archive HEAD", result)
        self.assertIn("git rev-parse HEAD", result)
