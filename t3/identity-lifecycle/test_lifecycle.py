"""Offline tests for false-positive and artifact-substitution failure modes."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys
from unittest.mock import patch

from run import Failure, RunResult, load_candidate, harness_identity, finalize


def digest(data):
    return hashlib.sha256(data).hexdigest()


class CandidateTests(unittest.TestCase):
    def test_verified_snapshot_survives_source_replacement(self):
        from run import snapshot_candidate
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            expected, lock = self.candidate(source)
            snapshot = root / "snapshot"
            self.assertEqual(snapshot_candidate(source, snapshot, lock), expected)
            (source / "deploy.py").write_text("# replaced after verification")
            (source / "server.oci.tar").unlink()
            self.assertEqual(load_candidate(snapshot, lock), expected)
            self.assertEqual((snapshot / "deploy.py").stat().st_mode & 0o777, 0o400)

    def candidate(self, root):
        revision = "a" * 40
        value = {
            "format_version": 1, "revision": revision, "identity_schema": 7,
            "platform": "linux/amd64", "images": {}, "archives": {}, "binaries": {},
            "migrations": {"schema_version": 7}, "providers": {"rust": "rust@sha256:" + "b" * 64},
        }
        for name in ("server", "operator", "gateway"):
            config = json.dumps({"os": "linux", "architecture": "amd64", "config": {
                "User": "10001:10001", "Labels": {"org.opencontainers.image.revision": revision},
            }}).encode()
            manifest = json.dumps({"config": {"digest": "sha256:" + digest(config)}}).encode()
            image_digest = "sha256:" + digest(manifest)
            index = json.dumps({"manifests": [{"digest": image_digest,
                "mediaType": "application/vnd.oci.image.manifest.v1+json"}]}).encode()
            archive = root / (name + ".oci.tar")
            with tarfile.open(archive, "w") as output:
                for path, data in {"index.json": index, "blobs/sha256/" + digest(manifest): manifest,
                                   "blobs/sha256/" + digest(config): config}.items():
                    item = tarfile.TarInfo(path)
                    item.size = len(data)
                    output.addfile(item, io.BytesIO(data))
            value["images"][name] = "identity/" + name + "@" + image_digest
            value["archives"][name] = {"file": archive.name, "sha256": digest(archive.read_bytes()),
                                       "manifest_digest": image_digest}
        (root / "binaries").mkdir()
        for name in ("identity-server", "identity-migrate", "identity-admin", "identity-clients"):
            (root / "binaries" / name).write_bytes(name.encode())
            value["binaries"][name] = digest(name.encode())
        (root / "deploy.py").write_text("# approved renderer\n")
        (root / "candidate.json").write_text(json.dumps(value))
        lock = {"manifest_sha256": digest((root / "candidate.json").read_bytes()),
                "files": {"deploy.py": digest((root / "deploy.py").read_bytes())}}
        return value, lock

    def test_approved_artifacts_are_read_without_building(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected, lock = self.candidate(root)
            self.assertEqual(load_candidate(root, lock), expected)

    def test_corrupt_artifact_or_renderer_is_rejected(self):
        for name in ("candidate.json", "server.oci.tar", "binaries/identity-server", "deploy.py"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, lock = self.candidate(root)
                with (root / name).open("ab") as output:
                    output.write(b"corruption")
                with self.assertRaises(Failure):
                    load_candidate(root, lock)

    def test_symlink_cannot_substitute_an_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, lock = self.candidate(root)
            source = root / "server.oci.tar"
            source.rename(root / "other.tar")
            source.symlink_to(root / "other.tar")
            with self.assertRaises(Failure):
                load_candidate(root, lock)


class ResultTests(unittest.TestCase):
    def test_missing_or_failed_phase_cannot_pass(self):
        result = RunResult(("first", "second"))
        with result.phase("first"):
            pass
        self.assertFalse(result.finish(cleanup_ok=True))
        with self.assertRaises(Failure), result.phase("second"):
            raise Failure("synthetic_failure")
        self.assertFalse(result.finish(cleanup_ok=True))

    def test_cleanup_failure_cannot_pass_a_successful_suite(self):
        result = RunResult(("first",))
        with result.phase("first"):
            pass
        self.assertFalse(result.finish(cleanup_ok=False))

    def test_unexpected_errors_do_not_publish_secret_values(self):
        result = RunResult(("first",))
        with self.assertRaises(ValueError), result.phase("first"):
            raise ValueError("sentinel-password-token")
        result.finish(cleanup_ok=True)
        self.assertNotIn("sentinel-password-token", json.dumps(result.data))

    def test_pass_requires_the_whole_ordered_suite(self):
        result = RunResult(("first", "second"))
        for name in ("first", "second"):
            with result.phase(name):
                pass
        self.assertTrue(result.finish(cleanup_ok=True))
        reversed_result = RunResult(("first", "second"))
        for name in ("second", "first"):
            with reversed_result.phase(name):
                pass
        self.assertFalse(reversed_result.finish(cleanup_ok=True))


class ProcessAndCleanupTests(unittest.TestCase):
    def test_port_isolation_rejects_a_broken_renderer_port(self):
        from fixture import isolate_public_port
        for ports in (None, [], ["443:8443"]):
            with self.subTest(ports=ports), self.assertRaisesRegex(Failure, "renderer_public_port"):
                isolate_public_port({"ports": ports})
        service = {"ports": ["443:443"], "networks": {"public": {}}}
        isolate_public_port(service)
        self.assertEqual(service, {"ports": [{"target": 443, "host_ip": "127.0.0.1", "protocol": "tcp"}],
                                   "networks": {"public": {}}})

    def test_helper_receives_input_through_the_owned_pipe(self):
        from fixture import command
        result = command([sys.executable, "-c", "import sys; print(sys.stdin.read())"], input="fixture-input")
        self.assertEqual(result.stdout.strip(), "fixture-input")

    def test_partial_prepare_cleanup_does_not_depend_on_compose_parsing(self):
        from fixture import Fixture
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = Fixture(root, {}, root)
            removed = []
            def docker(*args, **kwargs):
                if "--filter" in args:
                    self.assertIn(args[args.index("--filter") + 1],
                                  ["label=" + key + fixture.project for key in ("com.docker.compose.project=", "rss.t31=")])
                    name = ""
                    if "label=rss.t31=" + fixture.project in args:
                        name = fixture.helper if args[0] == "ps" else fixture.control if args[0] == "volume" else ""
                    return subprocess.CompletedProcess(args, 0, name, "")
                removed.append(args)
                return subprocess.CompletedProcess(args, 0, "", "")
            with patch.object(fixture, "docker", side_effect=docker):
                self.assertTrue(fixture.cleanup())
            self.assertEqual(removed, [("rm", "--force", fixture.helper), ("volume", "rm", fixture.control)])


class ProvenanceAndFinalizationTests(unittest.TestCase):
    def test_changed_candidate_snapshot_cannot_pass_finalization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            _, lock = CandidateTests().candidate(snapshot)
            (snapshot / "deploy.py").write_text("# substituted")
            self.assertFalse(finalize(RunResult(()), None, root, {}, root=root,
                                      candidate_snapshot=snapshot, candidate_lock=lock))
            recorded = json.loads((root / "result.json").read_text())
            self.assertEqual(recorded["failure"], "candidate_changed_during_run")
            self.assertTrue(recorded["cleanup"])

    def test_dirty_checkout_cannot_supply_a_harness_identity(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["/usr/bin/git", "-c", "user.name=T31", "-c", "user.email=t31@example.test", *args], cwd=root)
            git("init", "--quiet")
            (root / "runner.py").write_text("# committed\n")
            git("add", "runner.py")
            git("commit", "--quiet", "-m", "fixture")
            self.assertEqual(harness_identity(root), git("rev-parse", "HEAD").decode().strip())
            (root / "runner.py").write_text("# uncommitted\n")
            with self.assertRaisesRegex(Failure, "dirty_harness"):
                harness_identity(root)

    def test_removed_or_replaced_harness_always_writes_failed_evidence(self):
        from run import sha
        for removed in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "runner.py"
                path.write_text("# original")
                hashes = {path.name: sha(path)}
                path.unlink()
                if not removed:
                    (root / "replacement.py").write_text("# original")
                    path.symlink_to(root / "replacement.py")
                result = RunResult(())
                self.assertFalse(finalize(result, None, root, hashes, root=root))
                recorded = json.loads((root / "result.json").read_text())
                self.assertEqual(recorded["failure"], "harness_changed_during_run")
                self.assertTrue(recorded["cleanup"])

    def test_second_interrupt_during_cleanup_does_not_lose_result(self):
        import os, signal
        class InterruptedCleanup:
            def cleanup(self):
                os.kill(os.getpid(), signal.SIGINT)
                raise KeyboardInterrupt
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(finalize(RunResult(()), InterruptedCleanup(), root, {}, root=root))
            recorded = json.loads((root / "result.json").read_text())
            self.assertFalse(recorded["cleanup"])
            self.assertEqual(recorded["status"], "failed")
            self.assertEqual(recorded["cleanup_error"], "KeyboardInterrupt")

    def test_cleanup_has_one_budget_and_reports_remaining_resources(self):
        import subprocess
        from fixture import Fixture
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory), {}, Path(directory))
            def docker(*args, **kwargs):
                if args[0] == "ps":
                    return subprocess.CompletedProcess(args, 0, "owned-container", "")
                return subprocess.CompletedProcess(args, 0, "", "")
            with patch.object(f, "docker", side_effect=docker), patch("fixture.time.monotonic", side_effect=[0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]):
                self.assertFalse(f.cleanup(budget=1))
            self.assertTrue(f.cleanup_details["budget_exhausted"])
            self.assertEqual(f.cleanup_details["remaining"]["container"], 1)


if __name__ == "__main__":
    unittest.main()
