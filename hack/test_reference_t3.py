import copy
import unittest
import reference_t3 as t3

class EvidenceTests(unittest.TestCase):

    def test_passed_evidence_cannot_omit_coverage_boundaries(self):
        record, subject = self.complete()
        self.assertIn("uncovered", record)
        record["uncovered"] = []
        with self.assertRaises(ValueError):
            t3.verify_record(record, subject)

    def test_prepare_run_timeout_still_runs_owned_cleanup_and_writes_failure(self):
        import argparse, json, tempfile, subprocess
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp:
            args = argparse.Namespace(record=Path(temp) / "result.json")
            with (
                patch.object(
                    t3, "prepare_run", side_effect=subprocess.TimeoutExpired("docker", 1)
                ) as prepare,
                patch.object(t3, "cleanup_operator", return_value=[]) as cleanup,
            ):
                self.assertFalse(t3.outside(args))
            prefix = prepare.call_args.args[1]
            self.assertEqual(
                cleanup.call_args.args,
                (prefix, prefix + "-operator", prefix + "-private"),
            )
            report = json.loads(args.record.read_text())
            self.assertEqual(report["result"], "failed")
            self.assertEqual(report["failure"]["kind"], "timeout")
            self.assertEqual(report["cleanup"]["status"], "passed")

    def test_image_probes_have_exact_cleanup_identity(self):
        from unittest.mock import patch

        with patch.object(t3, "docker", return_value=b"profile") as docker:
            self.assertEqual(
                t3.image_probe(
                    "owned-prefix",
                    "policy",
                    "sha256:fixed",
                    "identity-server",
                    "--acceptance-profile",
                ),
                b"profile",
            )
        words = docker.call_args.args
        self.assertEqual(words[words.index("--name") + 1], "owned-prefix-policy")
        self.assertEqual(
            words[words.index("--label") + 1], "rss.identity.t3=owned-prefix"
        )

    def test_networks_are_reserved_before_deployment_and_retry_only_overlap(self):
        import subprocess
        from unittest.mock import patch

        run = object.__new__(t3.Run)
        run.prefix = "identity-t3-test"
        run.source, run.stale, run.restored = [
            run.prefix + "-" + name for name in ["source", "stale", "restored"]
        ]
        run.provider_network = run.prefix + "-provider"
        overlap = subprocess.CalledProcessError(
            1,
            "docker",
            stderr=b"Error response from daemon: invalid pool request: Pool overlaps with other one on this address space\n",
        )
        with patch.object(
            t3, "bounded_run", side_effect=[overlap, None, None, None, None]
        ) as create:
            run.reserve_networks()
        self.assertEqual(run.subnets, [f"10.243.{n}.0/24" for n in range(1, 5)])
        calls = [call.args[0] for call in create.call_args_list]
        self.assertEqual(
            [args[-1] for args in calls],
            [run.source + "_backend"] * 2
            + [run.stale + "_backend", run.restored + "_backend", run.provider_network],
        )
        for args in calls:
            self.assertIn("--internal", args)
            self.assertIn("rss.identity.t3=" + run.prefix, args)
        for args, project in zip(calls[1:4], [run.source, run.stale, run.restored]):
            self.assertIn("com.docker.compose.project=" + project, args)
            self.assertIn("com.docker.compose.network=backend", args)

    def test_binary_policy_is_read_from_the_actual_image(self):
        import json
        from unittest.mock import patch

        profile = {"formatVersion": 1, "schemaVersion": 999,
                   "session": {"idleSeconds": 60, "absoluteSeconds": 120},
                   "mfaMaxAgeSeconds": 30}
        with patch.object(t3, "docker", return_value=json.dumps(profile).encode()) as docker:
            self.assertEqual(t3.binary_profile("sha256:fixed", "owned-prefix"), {
                "session": profile["session"], "mfaMaxAgeSeconds": 30})
        self.assertEqual(docker.call_args.args[-3:],
                         ("identity-server", "sha256:fixed", "--acceptance-profile"))
        for extra in [{"session": {}}, {"mfaMaxAgeSeconds": 0},
                      {"session": {"idleSeconds": 3, "absoluteSeconds": 2}},
                      {"formatVersion": 2}]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                t3.validate_binary_profile({**profile, **extra})

    def test_each_step_requires_nonempty_facts(self):
        original, subject = self.complete()
        for index in range(len(t3.STEPS)):
            with self.subTest(step=t3.STEPS[index]):
                record = copy.deepcopy(original)
                record["steps"][index]["observations"] = {}
                with self.assertRaises(ValueError):
                    t3.verify_record(record, subject)

    def test_observation_mutations_cannot_manufacture_complete_evidence(self):
        original, subject = self.complete()
        for index, step in enumerate(original["steps"]):
            for key, value in step["observations"].items():
                for replacement in [None, False if value is True else {}]:
                    with self.subTest(step=step["name"], key=key):
                        record = copy.deepcopy(original)
                        if replacement is None:
                            del record["steps"][index]["observations"][key]
                        else:
                            record["steps"][index]["observations"][key] = replacement
                        with self.assertRaises((ValueError, TypeError, KeyError)):
                            t3.verify_record(record, subject)
        record = copy.deepcopy(original)
        record["steps"][0]["observations"], record["steps"][1]["observations"] = (
            record["steps"][1]["observations"],
            record["steps"][0]["observations"],
        )
        with self.assertRaises(ValueError):
            t3.verify_record(record, subject)

    def test_profile_normalizes_fixture_identity_but_binds_policy(self):
        runtime = t3.runtime_template()
        expected = t3.runtime_profile(runtime)
        runtime["instanceId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        runtime["storage"]["target"] = [3] * 16
        runtime["publicGateway"] = "10.243.1.2"
        runtime["database"]["passwordFile"] = "/another/private/runtime-password"
        self.assertEqual(t3.runtime_profile(runtime), expected)
        runtime["budgets"]["requestSeconds"] += 1
        self.assertNotEqual(t3.runtime_profile(runtime), expected)
        runtime["oidc"]["privateProviders"][0]["cidrs"] = ["10.0.0.0/8"]
        with self.assertRaises(ValueError):
            t3.runtime_profile(runtime)

    def test_cross_language_phases_and_step_registry_are_closed(self):
        import ast, re

        tree = ast.parse((t3.ROOT / "hack/reference_t3.py").read_text())
        phases = {
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "browser"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        }
        phases.update(phase for _, method, phase in t3.SCENARIOS if method == "browser")
        cases = re.findall(
            r'case "([a-z-]+)":',
            (t3.ROOT / "hack/reference_t3_browser.mjs").read_text(),
        )
        self.assertEqual(phases, set(cases))
        self.assertEqual(len(cases), len(set(cases)))
        self.assertEqual(set(t3.STEPS), set(t3.TRUE_FACTS))
        self.assertTrue(all(hasattr(t3.Run, method) for _, method, _ in t3.SCENARIOS))

    def test_failure_categories_survive_without_exception_text(self):
        import json, subprocess

        for error, kind in [
            (subprocess.TimeoutExpired("secret", 1), "timeout"),
            (OSError("secret"), "spawn"),
            (json.JSONDecodeError("secret", "secret", 0), "decode"),
            (AssertionError("secret"), "assertion"),
        ]:
            fact = t3.failure_fact(error, "fixture")
            self.assertEqual(fact.get("kind"), kind)
            t3.assert_redacted(fact, ["secret"])

    def test_make_rejects_missing_inputs_before_build(self):
        import subprocess

        result = subprocess.run(
            ["make", "test-reference", "WEB_IMAGE="],
            cwd=t3.ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WEB_IMAGE required", result.stderr)

    def complete(self):
        import json

        subject = {
            "images": {"identity": {"id": "sha256:" + "1" * 64}},
            "resources": {"daemonId": "fixture"},
            "runtimeProfile": t3.runtime_profile(t3.runtime_template()),
            "policy": {"session": {"idleSeconds": 900, "absoluteSeconds": 14400}, "mfaMaxAgeSeconds": 300},
        }
        record = t3.new_record(subject)
        sha = "a" * 64
        rows = {name: 1 for name in t3.TABLES}
        rows.update(accounts=6, providers=2)
        observations = {
            "install": {
                "tenants": 2,
                "initializationReplayRejected": True,
                "configurationSha256": t3.digest(
                    json.dumps(subject["runtimeProfile"], sort_keys=True).encode()
                ),
            },
            "local": {
                "cookieAttributes": True,
                "tenantAndPrivilegeDenied": True,
                "sessionRotationAndRevocation": True,
                "authoritativePolicyMatched": True,
                "failedAttempts": 6,
                "assertions": 55,
            },
            "oidc": {
                "jitAndExplicitLink": True,
                "tenantIdentityIsolated": True,
                "wrongPasswordRejected": True,
                "browserBindingAndReplay": True,
                "federatedLogout": True,
                "assertions": 21,
            },
            "mfa": {
                "freshMfaConsumed": True,
                "realExpiryRejected": True,
                "oldSessionRejected": True,
                "wrongSubjectAndDowngradeRejected": True,
                "wrongTotpRejected": True,
                "federatedAccountRevocation": True,
                "assertions": 34,
            },
            "events": {
                "rollbackPreserved": True,
                "failedAttemptBudgetCommitted": True,
                "responseLossObservedCommitted": True,
                "durableEvents": 1,
                "outboxSha256": sha,
                "eventIds": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
            },
            "availability": {
                "localSurvivesIdpFailure": True,
                "storageFailureClosed": True,
            },
            "credential-rotation": {
                "oldCiphertextRejectedWithoutKey": True,
                "retiredKeyRejected": True,
                "singleNewKeyVerified": True,
            },
            "state-rotation": {"oldStateRejected": True, "newFlowAccepted": True},
            "client-secret-rotation": {
                "oldClientSecretRejected": True,
                "newClientSecretAccepted": True,
            },
            "database-rotation": {
                "roles": ["identity_runtime", "identity_maintenance", "postgres"],
                "wrongAndRetiredPasswordsRejected": True,
                "newPasswordsAccepted": True,
            },
            "tls-rotation": {
                "publicAndDatabaseTrustRotated": True,
                "retiredTrustRejected": True,
            },
            "backup": {
                "backupBytes": 1,
                "dumpSha256": sha,
                "receiptSha256": sha,
                "tamperRejected": True,
            },
            "stale-backup": {
                "staleCutIdentified": True,
                "staleAuthorityRemainsClosed": True,
            },
            "restore": {
                "matchedSafetyCut": True,
                "outboxSha256": sha,
                "sourceAndTargetGuards": True,
                "operatorOpenedAfterVerification": True,
                "dumpSha256": sha,
                "receiptSha256": sha,
                "datasetRows": rows,
            },
        }
        record["steps"] = [
            {
                "name": name,
                "status": "passed",
                "elapsedMs": 300001 if name == "mfa" else 1,
                "observations": observations[name],
            }
            for name in t3.STEPS
        ]
        record["cleanup"] = {"status": "passed", "remaining": []}
        record["result"] = "passed"
        return record, subject

    def test_partial_failed_or_mismatched_evidence_cannot_pass(self):
        original, subject = self.complete()
        for field, value in [
            ("steps", original["steps"][:-1]),
            ("cleanup", {"status": "failed", "remaining": ["owned-container"]}),
            ("failure", {"stage": "restore", "reason": "unconfirmed"}),
            ("subject", {}),
            ("formatVersion", 1),
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

    def test_daemon_mismatch_fails_before_creating_private_workspace(self):
        from unittest.mock import patch

        with (
            patch.object(t3, "docker", return_value=b"different"),
            patch.object(t3.Path, "mkdir") as mkdir,
        ):
            with self.assertRaisesRegex(ValueError, "docker-daemon-mismatch"):
                t3.Run({"subject": {"resources": {"daemonId": "expected"}}})
            mkdir.assert_not_called()

    def test_outer_interruptions_never_publish_success_before_cleanup(self):
        import argparse, json, tempfile
        from pathlib import Path
        from unittest.mock import patch

        for when in [
            "executing",
            "report-copy",
            "cleanup",
            "cleanup-failed",
            "executing-cleanup",
            "success",
        ]:
            with self.subTest(when=when), tempfile.TemporaryDirectory() as temp:
                report, subject = self.complete()
                args = argparse.Namespace(record=Path(temp) / "result.json")
                cleaned = False

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
                    nonlocal cleaned
                    cleaned = True
                    self.assertEqual(
                        json.loads(args.record.read_text())["result"], "running"
                    )
                    if when in ["cleanup", "executing-cleanup"]:
                        raise SystemExit(143)
                    return ["owned-resource"] if when == "cleanup-failed" else []

                with (
                    patch.object(
                        t3,
                        "prepare_run",
                        return_value=(
                            {"identity": {"Id": "image"}},
                            {"Id": "tools"},
                            subject,
                        ),
                    ),
                    patch.object(t3, "docker", side_effect=docker),
                    patch.object(t3, "process", return_value=b"archive"),
                    patch.object(
                        t3,
                        "bounded_run",
                        side_effect=(
                            SystemExit(143)
                            if when in ["executing", "executing-cleanup"]
                            else None
                        ),
                        return_value=argparse.Namespace(returncode=0),
                    ),
                    patch.object(t3, "cleanup_operator", side_effect=cleanup),
                ):
                    self.assertEqual(t3.outside(args), when == "success")
                final = json.loads(args.record.read_text())
                if when == "executing-cleanup":
                    self.assertEqual(final["failure"]["stage"], "operator")
                    self.assertEqual(final["cleanup"]["status"], "failed")
                self.assertEqual(final["result"], "passed" if when == "success" else "failed")

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
                "kind": "exit",
                "reason": "process-failed",
                "action": "docker-run",
                "exitCode": 7,
            },
        )
        t3.assert_redacted(fact, ["secret"])

    def test_single_make_entry_builds_tools_before_runner(self):
        import subprocess

        result = subprocess.run(
            ["make", "-n", "test-reference", "WEB_IMAGE=web", "REFERENCE_RECORD=/tmp/identity-result.json"],
            cwd=t3.ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertLess(
            result.index("docker buildx build"), result.index("hack/reference_t3.py")
        )
        self.assertNotIn("git archive HEAD", result)
        self.assertNotIn("git rev-parse HEAD", result)
        # Feed Make's actual invocation to the production CLI parser without Docker.
        import shlex, sys
        from unittest.mock import patch
        command = shlex.split(result.splitlines()[-1])
        with patch.object(sys, "argv", command[1:]), patch.object(t3, "outside", return_value=True) as outside:
            with self.assertRaises(SystemExit) as stopped:
                t3.main()
            self.assertEqual(stopped.exception.code, 0)
            self.assertEqual(outside.call_args.args[0].web_image, "web")


    def test_private_provider_is_connected_before_formal_open(self):
        import json, subprocess
        from unittest.mock import patch

        run = t3.Run.__new__(t3.Run)
        run.source = "fixture-source"
        run.directories = {run.source: t3.ROOT}
        run.provider_network = "fixture-provider"
        connected = False

        def docker(*words, **kwargs):
            nonlocal connected
            if words[:2] == ("network", "connect"):
                connected = True
                return b""
            return json.dumps(
                [
                    {
                        "NetworkSettings": {
                            "Networks": {"fixture-provider": {}} if connected else {}
                        }
                    }
                ]
            ).encode()

        def operation(*args, **kwargs):
            self.assertTrue(
                connected, "formal open must not expose gateway before provider wiring"
            )
            return subprocess.CompletedProcess([], 0, b'{"status":"passed"}', b"")

        with (
            patch.object(t3.operate, "require_closed"),
            patch.object(run, "compose", return_value=b"container"),
            patch.object(t3, "docker", side_effect=docker),
            patch.object(t3, "bounded_run", side_effect=operation),
        ):
            run.op("open")

    def test_secret_in_checkpoint_writes_only_a_failed_redacted_record(self):
        import json, tempfile
        from pathlib import Path

        record, subject = self.complete()
        record["steps"][0]["observations"]["leak"] = "private-test-secret"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "result.json"
            with self.assertRaisesRegex(ValueError, "secret-in-evidence"):
                t3.save_evidence(path, record, ["private-test-secret"])
            raw = path.read_text()
            self.assertNotIn("private-test-secret", raw)
            sanitized = json.loads(raw)
            self.assertEqual(sanitized["result"], "failed")
            self.assertEqual(sanitized["failure"]["reason"], "secret-in-evidence")
            self.assertEqual(sanitized["steps"], [])
