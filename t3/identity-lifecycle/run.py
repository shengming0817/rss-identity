#!/usr/bin/env python3
"""Execute one fixed candidate's product lifecycle; never build the product."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import re
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if __name__ == "__main__":
    sys.modules["run"] = sys.modules[__name__]
PHASES = ("candidate", "prepare", "install", "healthy", "cold_dependencies",
          "running_dependencies", "partial_start", "clean_drain", "timeout_drain",
          "persistent_restart", "mismatch")


class Failure(Exception):
    """Only code-owned diagnostic labels may enter this exception."""


def require(condition, code):
    if not condition:
        raise Failure(code)


def sha(path):
    require(path.is_file() and not path.is_symlink(), "artifact_not_regular")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def candidate_contract(value, lock):
    # Validate every producer field at the load boundary, before archive or Docker work.
    def fields(obj, names):
        require(type(obj) is dict and set(obj) == set(names.split()), "candidate_format_fields")
    def text(value, pattern=r"[^\x00]+"):
        require(type(value) is str and re.fullmatch(pattern, value) is not None, "candidate_format_value")
    digest = r"[a-f0-9]{64}"
    image = r"[A-Za-z0-9_./:-]+@sha256:" + digest
    fields(lock, "manifest_sha256 files")
    text(lock["manifest_sha256"], digest)
    fields(lock["files"], "deploy.py deployment/example.json deployment/providers.lock.json")
    for item in lock["files"].values(): text(item, digest)
    fields(value, "format_version revision version platform cargo_lock_sha256 rust ui providers migration_sha256 images archives rss migrations identity_schema toolchain production_features binaries")
    for key, expected in (("format_version", 1), ("identity_schema", 7)):
        require(type(value[key]) is int and value[key] == expected, "candidate_format_version")
    text(value["revision"], r"[a-f0-9]{40}")
    require(value["platform"] == "linux/amd64", "candidate_format_platform")
    for key in ("version", "rust", "toolchain"): text(value[key])
    for key in ("cargo_lock_sha256", "migration_sha256"): text(value[key], digest)
    fields(value["ui"], "repository revision lock_sha256 dist_sha256")
    text(value["ui"]["repository"], r"https://[^\s]+")
    text(value["ui"]["revision"], r"[a-f0-9]{40}")
    for key in ("lock_sha256", "dist_sha256"): text(value["ui"][key], digest)
    fields(value["providers"], "postgres keycloak hydra nginx rust runtime")
    fields(value["images"], "server operator gateway")
    for item in (*value["providers"].values(), *value["images"].values()): text(item, image)
    fields(value["archives"], "server operator gateway")
    for name, item in value["archives"].items():
        fields(item, "file sha256 manifest_digest")
        require(item["file"] == name + ".oci.tar", "candidate_format_archive_path")
        text(item["sha256"], digest)
        text(item["manifest_digest"], "sha256:" + digest)
    fields(value["binaries"], "identity-server identity-admin identity-migrate identity-clients")
    for item in value["binaries"].values(): text(item, digest)
    fields(value["migrations"], "identity_sql_sha256 rss_sql_sha256 schema_contract schema_version")
    require(type(value["migrations"]["schema_version"]) is int
            and value["migrations"]["schema_version"] == 7, "candidate_format_schema")
    for key in ("identity_sql_sha256", "rss_sql_sha256", "schema_contract"):
        text(value["migrations"][key], digest)
    require(value["migration_sha256"] == value["migrations"]["identity_sql_sha256"], "candidate_format_migration")
    require(type(value["rss"]) is list and bool(value["rss"]), "candidate_format_rss")
    packages = set()
    for item in value["rss"]:
        fields(item, "package version source")
        text(item["package"], r"rss-[a-z0-9-]+")
        text(item["version"])
        text(item["source"], r"git\+https://[^\s]+\?rev=([a-f0-9]{40})#\1")
        require(item["package"] not in packages, "candidate_format_duplicate_package")
        packages.add(item["package"])
    require(type(value["production_features"]) is dict
            and set(value["production_features"]) == packages, "candidate_format_features")
    for features in value["production_features"].values():
        require(type(features) is list, "candidate_format_features")
        for feature in features: text(feature, r"[a-z0-9_-]+")


def load_candidate(directory, lock):
    try:
        value = json.loads((directory / "candidate.json").read_text())
    except (ValueError, UnicodeError):
        raise Failure("candidate_format_json") from None
    candidate_contract(value, lock)
    require(sha(directory / "candidate.json") == lock["manifest_sha256"], "candidate_digest")
    require(value["format_version"] == 1 and value["identity_schema"] == 7
            and value["platform"] == "linux/amd64", "candidate_format")
    require(set(value["images"]) == set(value["archives"]) == {"server", "operator", "gateway"},
            "candidate_images")
    require(set(value["binaries"]) == {"identity-server", "identity-admin", "identity-migrate",
                                       "identity-clients"}, "candidate_binaries")
    for name, item in value["archives"].items():
        require(item["file"] == name + ".oci.tar", "archive_path")
        archive = directory / item["file"]
        require(sha(archive) == item["sha256"], "archive_digest")
        with tarfile.open(archive) as source:
            descriptor = json.load(source.extractfile("index.json"))["manifests"][0]
            require(descriptor["digest"] == item["manifest_digest"]
                    and value["images"][name].endswith("@" + descriptor["digest"]), "manifest_digest")
            manifest = json.load(source.extractfile("blobs/sha256/" + descriptor["digest"].split(":")[1]))
            config = json.load(source.extractfile("blobs/sha256/" + manifest["config"]["digest"].split(":")[1]))
            require(config["architecture"] == "amd64" and config["os"] == "linux"
                    and config["config"]["User"] == "10001:10001"
                    and config["config"]["Labels"]["org.opencontainers.image.revision"] == value["revision"],
                    "image_identity")
    require(not (directory / "binaries").is_symlink(), "artifact_not_regular")
    for name, expected in value["binaries"].items():
        require(sha(directory / "binaries" / name) == expected, "binary_digest")
    for name, expected in lock["files"].items():
        require(sha(directory / name) == expected, "deployment_digest")
    return value


def snapshot_candidate(source, destination, lock):
    value = load_candidate(source, lock)
    destination.mkdir(mode=0o700)
    names = ["candidate.json", *lock["files"],
             *(item["file"] for item in value["archives"].values()),
             *("binaries/" + name for name in value["binaries"])]
    for name in names:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(source / name, target)
        target.chmod(0o400)
    # Validate the copied bytes; all later Docker loads and renderer reads use this snapshot.
    return load_candidate(destination, lock)


class RunResult:
    def __init__(self, expected=PHASES):
        self.expected = expected
        self.data = {"issue": 2340, "status": "failed", "phases": [], "cleanup": False}

    @contextmanager
    def phase(self, name):
        item = {"name": name, "status": "running", "observations": {}}
        self.data["phases"].append(item)
        started = time.monotonic()
        print("T31 " + name, flush=True)
        try:
            yield item["observations"]
        except BaseException as error:
            item["status"] = "failed"
            item["failure"] = str(error) if isinstance(error, Failure) else type(error).__name__
            raise
        else:
            item["status"] = "passed"
        finally:
            item["elapsed_seconds"] = round(time.monotonic() - started, 3)

    def finish(self, *, cleanup_ok):
        self.data["cleanup"] = cleanup_ok
        passed = (tuple(p["name"] for p in self.data["phases"]) == self.expected
                  and all(p["status"] == "passed" for p in self.data["phases"]) and cleanup_ok
                  and "failure" not in self.data)
        self.data["status"] = "passed" if passed else "failed"
        self.data["not_run"] = [p for p in self.expected if p not in {v["name"] for v in self.data["phases"]}]
        return passed


def harness_identity(root):
    revision = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=10).strip()
    dirty = subprocess.check_output(["/usr/bin/git", "status", "--porcelain"], cwd=root, text=True, timeout=10).strip()
    require(not dirty, "dirty_harness")
    return revision


def finalize(result, fixture, output, harness_files, *, root=ROOT,
             candidate_snapshot=None, candidate_lock=None):
    def interrupted(_signal, _frame):
        result.data["cleanup_interrupted"] = True
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    cleanup_ok = False
    try:
        if fixture and hasattr(fixture, "diagnostics"):
            try:
                result.data["diagnostics"] = fixture.diagnostics()
            except BaseException as error:
                result.data["diagnostics"] = {"complete": False, "error": type(error).__name__}
        try:
            cleanup_ok = fixture.cleanup() if fixture else True
        except BaseException as error:
            result.data["cleanup_error"] = type(error).__name__
        if fixture and hasattr(fixture, "cleanup_details"):
            result.data["cleanup_details"] = fixture.cleanup_details
        try:
            unchanged = all(sha(root / name) == digest for name, digest in harness_files.items())
        except (Failure, OSError):
            unchanged = False
        if not unchanged:
            result.data["failure"] = "harness_changed_during_run"
        if candidate_snapshot is not None:
            try:
                load_candidate(candidate_snapshot, candidate_lock)
            except (Failure, OSError, ValueError, KeyError, tarfile.TarError):
                result.data["failure"] = "candidate_changed_during_run"
        passed = result.finish(cleanup_ok=cleanup_ok)
        (output / "result.json").write_text(json.dumps(result.data, indent=2) + "\n")
        return passed
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    def nonempty_path(value):
        if not value.strip():
            raise argparse.ArgumentTypeError("empty path")
        return Path(value)
    parser.add_argument("--candidate", required=True, type=nonempty_path)
    parser.add_argument("--output", required=True, type=nonempty_path)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.exists(), "output_already_exists")
    output.mkdir(parents=True, mode=0o700)
    result = RunResult()
    fixture = None
    directory, lock = None, None
    harness = [*HERE.glob("*.py"), HERE / "candidate.lock.json", ROOT / "hack/bounded_process.py"]
    harness_files = {str(p.relative_to(ROOT)): sha(p) for p in harness}
    result.data["harness_files"] = harness_files
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        with result.phase("candidate") as observed:
            lock = json.loads((HERE / "candidate.lock.json").read_text())
            snapshot = output / "candidate"
            candidate = snapshot_candidate(args.candidate.resolve(), snapshot, lock)
            directory = snapshot
            observed.update(manifest_sha256=lock["manifest_sha256"], metadata=candidate,
                            deployment_files=lock["files"], consumption="verified_readonly_snapshot")
            result.data["harness_revision"] = harness_identity(ROOT)
            result.data["harness_dirty"] = False
        from fixture import Fixture
        import scenarios
        fixture = Fixture(directory, candidate, output)
        with result.phase("prepare") as observed:
            observed.update(fixture.prepare())
        for name in PHASES[2:]:
            with result.phase(name) as observed:
                getattr(scenarios, name)(fixture, observed)
    except BaseException as error:
        result.data["failure"] = str(error) if isinstance(error, Failure) else type(error).__name__
    finally:
        try:
            passed = finalize(result, fixture, output, harness_files,
                              candidate_snapshot=directory, candidate_lock=lock)
        finally:
            signal.signal(signal.SIGTERM, previous)
    print("T31 " + result.data["status"], flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as error:
        print("T31 refused: " + str(error), file=sys.stderr)
        sys.exit(1)
