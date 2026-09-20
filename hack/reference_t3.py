#!/usr/bin/env python3
"""One fixed-candidate reference T3; production operations remain in deploy/operate."""

import argparse, copy, hashlib, ipaddress, json, math, os, re, secrets, signal
import subprocess, sys, tempfile, time, tomllib
from urllib.parse import urlsplit
from pathlib import Path
import deploy, operate
from bounded_process import run as bounded_run
from docker_network import create_network
from reference_approval import verify_approval, validate_receipt

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    ("install", "install", None),
    ("local", "browser", "local"),
    ("oidc", "browser", "oidc"),
    ("mfa", "browser", "mfa"),
    ("events", "events", None),
    ("availability", "availability", None),
    ("credential-rotation", "credential_rotation", None),
    ("state-rotation", "state_rotation", None),
    ("client-secret-rotation", "client_rotation", None),
    ("database-rotation", "database_rotation", None),
    ("tls-rotation", "tls_rotation", None),
    ("backup", "backup", None),
    ("stale-backup", "stale_backup", None),
    ("restore", "restore", None),
    ("capacity", "capacity", None),
)
STEPS = tuple(row[0] for row in SCENARIOS)

# Explicit exclusions travel with every archived result, including passed runs.
UNCOVERED = [
    "architectures-and-resources-other-than-subject",
    "oidc-providers-other-than-fixed-keycloak",
    "sustained-login-throughput",
    "independent-multiple-session-throughput",
    "disaster-recovery-without-prepared-images-and-configuration",
    "consumer-products-and-legacy-environment-retirement",
]

MEASUREMENTS = (
    "loginBurstP95Ms",
    "loginBurstRequestsPerSecond",
    "failedAttemptBurstP95Ms",
    "failedAttemptBurstRequestsPerSecond",
    "accountEventCommitP95Ms",
    "accountEventCommitsPerSecond",
    "session1P95Ms",
    "session1RequestsPerSecond",
    "session4P95Ms",
    "session4RequestsPerSecond",
    "session16P95Ms",
    "session16RequestsPerSecond",
    "unexpectedErrors",
    "restoreSeconds",
    "backupBytes",
    "lostSecurityChanges",
    "expiredAttemptsRemoved",
)
LIMITS = {
    "loginBurstP95Ms": "max",
    "loginBurstRequestsPerSecond": "min",
    "failedAttemptBurstP95Ms": "max",
    "failedAttemptBurstRequestsPerSecond": "min",
    "accountEventCommitP95Ms": "max",
    "accountEventCommitsPerSecond": "min",
    "session1P95Ms": "max",
    "session1RequestsPerSecond": "min",
    "session4P95Ms": "max",
    "session4RequestsPerSecond": "min",
    "session16P95Ms": "max",
    "session16RequestsPerSecond": "min",
    "unexpectedErrors": "max",
    "restoreSeconds": "max",
    "lostSecurityChanges": "max",
    "expiredAttemptsRemoved": "min",
}
TENANTS = [
    "11111111-1111-4111-8111-111111111111",
    "33333333-3333-4333-8333-333333333333",
]
PRINCIPALS = [
    "22222222-2222-4222-8222-222222222222",
    "44444444-4444-4444-8444-444444444444",
]
ORIGIN = "https://identity.example.test"
WORKLOAD = {
    "login": {
        "kind": "bounded-burst",
        "tenantIndex": 0,
        "warmup": 4,
        "samples": 24,
        "concurrency": 4,
    },
    "failedAttempt": {
        "kind": "bounded-burst",
        "tenantIndex": 1,
        "accounts": 4,
        "samples": 20,
        "concurrency": 4,
        "limitedChecks": 8,
    },
    "accountEvent": {
        "warmup": 4,
        "seconds": 30,
        "concurrency": 4,
        "minimumSamples": 20,
    },
    "sessionConcurrency": [1, 4, 16],
    "sessionDistribution": "one-shared-authoritative-session",
    "secondsPerConcurrency": 30,
    "expiredAttempts": 256,
}
POLICY = {
    "session": {"idleSeconds": 900, "absoluteSeconds": 14400},
    "attempts": {
        "sourceLimit": 30,
        "sourceSeconds": 300,
        "scopeLimit": 5,
        "scopeSeconds": 900,
    },
    "kdfConcurrency": 4,
    "revocation": {"maxStaleRequests": 0, "requestDeadlineSeconds": 30},
    "mfaMaxAgeSeconds": 300,
    "rotation": {
        "credential": "close-mixed-rekey-retire",
        "state": "reject-pending-flow",
        "clientSecret": "replace-both-tenants",
        "database": "close-replace-all-three-roles",
        "tls": "independent-public-and-database-trust",
        "restore": "closed-verify-explicit-open",
    },
}


def oidc_settings(issuer, address, state, key):
    return {
        "groupFactsMaxAgeSeconds": 300,
        "stateKeyFile": state,
        "credentialKeyring": {
            "activeKeyId": "old",
            "keys": [{"keyId": "old", "path": key}],
        },
        "returnTargets": {"resume": ORIGIN + "/auth/resume"},
        "assuranceProfiles": [
            {
                "tenantId": t,
                "issuer": issuer,
                "clientId": "reference",
                "keycloakTotp": True,
            }
            for t in TENANTS
        ],
        "privateProviders": [
            {
                "tenantId": t,
                "issuer": issuer,
                "clientId": "reference",
                "cidrs": [address + "/32"],
            }
            for t in TENANTS
        ],
    }


def runtime_template():
    value = json.loads((ROOT / "deployment/deploy.example.json").read_text())["runtime"]
    value["publicGateway"] = "10.243.254.2"
    value["storage"]["tenants"] = TENANTS
    value["bootstrapAccounts"] = [
        {"tenantId": t, "principalId": p} for t, p in zip(TENANTS, PRINCIPALS)
    ]
    value["database"].update(
        passwordFile="/private/runtime-password", caFile="/private/postgres-ca.pem"
    )
    value["oidc"] = oidc_settings(
        "https://10.243.255.3:8443/realms/identity",
        "10.243.255.3",
        "/private/state-key",
        "/private/credential-old",
    )
    return value


def runtime_profile(runtime):
    """Normalize only disposable fixture identities; retain every policy field."""
    import uuid

    value = copy.deepcopy(runtime)
    uuid.UUID(value["instanceId"])
    value["instanceId"] = "per-run-instance"
    for field in ["target", "lineage"]:
        raw = value["storage"][field]
        require(
            isinstance(raw, list)
            and len(raw) == 16
            and all(type(i) is int and 0 <= i < 256 for i in raw),
            "profile-storage-identity",
        )
        value["storage"][field] = "per-run-" + field
    require(
        ipaddress.ip_address(value["publicGateway"])
        in ipaddress.ip_network("10.243.0.0/16")
        and value["publicGateway"].endswith(".2"),
        "profile-gateway",
    )
    value["publicGateway"] = "source-backend-gateway"
    oidc = value["oidc"]
    issuer = oidc["privateProviders"][0]["issuer"]
    url = urlsplit(issuer)
    require(
        url.scheme == "https"
        and url.port == 8443
        and url.path == "/realms/identity"
        and not url.query
        and not url.fragment
        and not url.username
        and ipaddress.ip_address(url.hostname) in ipaddress.ip_network("10.243.0.0/16")
        and url.hostname.endswith(".3"),
        "profile-provider",
    )
    for binding in oidc["privateProviders"]:
        require(
            binding["issuer"] == issuer and binding["cidrs"] == [url.hostname + "/32"],
            "profile-provider-binding",
        )
        binding.update(issuer="private-provider-issuer", cidrs=["private-provider/32"])
    for binding in oidc["assuranceProfiles"]:
        require(binding["issuer"] == issuer, "profile-assurance-binding")
        binding["issuer"] = "private-provider-issuer"
    for holder, field in [
        (value["database"], "passwordFile"),
        (value["database"], "caFile"),
        (oidc, "stateKeyFile"),
        *[(key, "path") for key in oidc["credentialKeyring"]["keys"]],
    ]:
        path = Path(holder[field])
        require(path.is_absolute(), "profile-private-path")
        holder[field] = "private-file/" + path.name
    return value


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def file_digest(path):
    return digest(Path(path).read_bytes())


class ProcessFailure(RuntimeError):
    def __init__(self, action, exit_code, kind="exit"):
        self.action, self.exit_code, self.kind = action, exit_code, kind
        super().__init__("process-failed")


def failure_fact(error, stage):
    kind = next(
        (
            name
            for cls, name in [
                (subprocess.TimeoutExpired, "timeout"),
                (json.JSONDecodeError, "decode"),
                (UnicodeError, "decode"),
                (OSError, "spawn"),
                (AssertionError, "assertion"),
                (ValueError, "validation"),
                (KeyboardInterrupt, "interrupted"),
                (SystemExit, "interrupted"),
            ]
            if isinstance(error, cls)
        ),
        "execution",
    )
    value = {
        "stage": stage,
        "kind": kind,
        "reason": (
            "interrupted"
            if isinstance(error, (KeyboardInterrupt, SystemExit))
            else (
                str(error)
                if isinstance(error, ValueError)
                and re.fullmatch("[a-z-]{1,80}", str(error))
                else "execution-or-assertion"
            )
        ),
    }
    if isinstance(error, ProcessFailure):
        value.update(
            reason="process-failed",
            kind=error.kind,
            action=error.action,
            exitCode=error.exit_code,
        )
    return value


def process(args, **kwargs):
    program = Path(args[0]).name
    action = (
        program if program in {"docker", "git", "openssl", "certutil"} else "process"
    )
    if (
        program == "docker"
        and len(args) > 1
        and args[1]
        in {
            "info",
            "inspect",
            "network",
            "volume",
            "run",
            "exec",
            "compose",
            "ps",
            "rm",
            "start",
            "stop",
        }
    ):
        action += "-" + args[1]
    try:
        result = bounded_run(
            args, timeout=kwargs.pop("timeout", 240), capture_output=True, **kwargs
        )
    except subprocess.TimeoutExpired:
        raise ProcessFailure(action, None, "timeout") from None
    except OSError:
        raise ProcessFailure(action, None, "spawn") from None
    except subprocess.SubprocessError:
        raise ProcessFailure(action, None, "execution") from None
    if result.returncode:
        raise ProcessFailure(action, result.returncode)
    return result.stdout


def docker(*args, **kwargs):
    return process(["docker", *map(str, args)], **kwargs)


def git(repository, *args):
    return process(["/usr/bin/git", "-C", str(repository), *args]).decode().strip()


def assert_redacted(value, secrets_):
    text = json.dumps(value, sort_keys=True)
    require(
        all(not value or value not in text for value in secrets_), "secret-in-evidence"
    )


def new_record(subject, targets):
    return {
        "formatVersion": 1,
        "scope": "identity-reference-t3",
        "subject": subject,
        "steps": [],
        "measurements": {},
        "targets": targets,
        "approval": None,
        "uncovered": list(UNCOVERED),
        "result": "running",
        "failure": None,
        "cleanup": {"status": "pending", "remaining": []},
    }


TRUE_FACTS = {
    "install": "initializationReplayRejected",
    "local": "cookieAttributes tenantAndPrivilegeDenied sessionRotationAndRevocation authoritativePolicyMatched",
    "oidc": "jitAndExplicitLink tenantIdentityIsolated wrongPasswordRejected browserBindingAndReplay federatedLogout",
    "mfa": "freshMfaConsumed realExpiryRejected oldSessionRejected wrongSubjectAndDowngradeRejected wrongTotpRejected federatedAccountRevocation",
    "events": "rollbackPreserved failedAttemptBudgetCommitted responseLossObservedCommitted",
    "availability": "localSurvivesIdpFailure storageFailureClosed",
    "credential-rotation": "oldCiphertextRejectedWithoutKey retiredKeyRejected singleNewKeyVerified",
    "state-rotation": "oldStateRejected newFlowAccepted",
    "client-secret-rotation": "oldClientSecretRejected newClientSecretAccepted",
    "database-rotation": "wrongAndRetiredPasswordsRejected newPasswordsAccepted",
    "tls-rotation": "publicAndDatabaseTrustRotated retiredTrustRejected",
    "backup": "tamperRejected",
    "stale-backup": "staleCutIdentified staleAuthorityRemainsClosed",
    "restore": "matchedSafetyCut sourceAndTargetGuards operatorOpenedAfterVerification",
    "capacity": "",
}
EXTRA_FACTS = {
    "install": "tenants configurationSha256",
    "local": "failedAttempts assertions",
    "oidc": "assertions",
    "mfa": "assertions",
    "events": "durableEvents outboxSha256 eventIds",
    "database-rotation": "roles",
    "backup": "backupBytes dumpSha256 receiptSha256",
    "restore": "outboxSha256 dumpSha256 receiptSha256 datasetRows",
    "capacity": "datasetRows resourcesBefore resourcesAfter committedEvents expiredAttemptsBefore expiredAttemptsAfter createdAccounts sessionSamples sessionBefore sessionAfter profiles loginProfile failedAttemptProfile accountEventProfile assertions",
}
TABLES = {
    "accounts",
    "memberships",
    "credentials",
    "providers",
    "providerCredentials",
    "externalIdentities",
    "sessions",
    "attempts",
    "linkIntents",
    "oidcTransactions",
    "outbox",
}


def number(value, minimum=0):
    return type(value) in (int, float) and math.isfinite(value) and value >= minimum


def verify_observations(name, facts, subject, measurements):
    truth = TRUE_FACTS[name].split()
    require(
        set(facts) == set(truth + EXTRA_FACTS.get(name, "").split()),
        "observation-fields",
    )
    require(all(facts[key] is True for key in truth), "observation-false")
    for key, value in facts.items():
        if key.endswith("Sha256"):
            require(
                isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value),
                "observation-digest",
            )
        if key in {"assertions", "failedAttempts", "durableEvents", "backupBytes"}:
            require(type(value) is int and value > 0, "observation-count")
    if name == "install":
        require(
            facts["tenants"] == len(subject["runtimeProfile"]["storage"]["tenants"])
            and facts["configurationSha256"]
            == digest(json.dumps(subject["runtimeProfile"], sort_keys=True).encode()),
            "observation-configuration",
        )
    if name == "local":
        require(facts["failedAttempts"] == 6, "observation-attempts")
    if name == "events":
        import uuid

        ids = facts["eventIds"]
        require(
            isinstance(ids, list)
            and len(ids) == facts["durableEvents"]
            and len(set(ids)) == len(ids),
            "observation-events",
        )
        for value in ids:
            require(str(uuid.UUID(value)) == value, "observation-event-id")
    if name == "database-rotation":
        require(
            facts["roles"] == ["identity_runtime", "identity_maintenance", "postgres"],
            "observation-database-roles",
        )
    if name in {"restore", "capacity"}:
        rows = facts["datasetRows"]
        require(
            isinstance(rows, dict)
            and set(rows) == TABLES
            and all(type(v) is int and v >= 0 for v in rows.values())
            and rows["accounts"] >= 6
            and rows["providers"] == 2
            and rows["outbox"] > 0,
            "observation-dataset",
        )
    if name != "capacity":
        return
    workload = subject["workload"]
    require(
        facts["expiredAttemptsBefore"] == subject["workload"]["expiredAttempts"]
        and facts["expiredAttemptsAfter"] == 0
        and measurements["expiredAttemptsRemoved"] == facts["expiredAttemptsBefore"],
        "observation-cleanup",
    )
    require(
        facts["committedEvents"] == facts["createdAccounts"]
        and facts["createdAccounts"]
        == (
            workload["login"]["warmup"]
            + workload["login"]["samples"]
            + workload["failedAttempt"]["accounts"]
            + workload["accountEvent"]["warmup"]
            + facts["accountEventProfile"]["samples"]
        ),
        "observation-event-count",
    )
    for key in ["resourcesBefore", "resourcesAfter"]:
        rows = facts[key]
        require(isinstance(rows, list) and len(rows) == 3, "observation-resources")
        keys = {
            "BlockIO",
            "CPUPerc",
            "Container",
            "ID",
            "MemPerc",
            "MemUsage",
            "Name",
            "NetIO",
            "PIDs",
        }
        require(
            all(
                isinstance(row, dict)
                and set(row) == keys
                and all(isinstance(v, str) and v for v in row.values())
                for row in rows
            ),
            "observation-resource-fields",
        )
    for key in ["sessionBefore", "sessionAfter"]:
        row = facts[key]
        require(
            set(row)
            == {
                "status",
                "sessionIdSha256",
                "idleRemainingSeconds",
                "absoluteRemainingSeconds",
            }
            and row["status"] == 200
            and re.fullmatch("[a-f0-9]{64}", row["sessionIdSha256"])
            and number(row["idleRemainingSeconds"], 1)
            and number(row["absoluteRemainingSeconds"], 1),
            "observation-session-lifetime",
        )
    require(
        facts["sessionBefore"]["sessionIdSha256"]
        == facts["sessionAfter"]["sessionIdSha256"],
        "observation-session-replaced",
    )
    profiles = facts["profiles"]
    require(
        isinstance(profiles, list)
        and [p["concurrency"] for p in profiles]
        == subject["workload"]["sessionConcurrency"],
        "observation-concurrency",
    )
    require(
        facts["sessionSamples"] == sum(p["samples"] for p in profiles),
        "observation-session-samples",
    )
    definitions = [
        (
            p,
            200,
            f"session{p['concurrency']}",
            1,
            subject["workload"]["secondsPerConcurrency"],
        )
        for p in profiles
    ]
    definitions += [
        (facts["loginProfile"], 200, "loginBurst", workload["login"]["samples"], 0),
        (
            facts["failedAttemptProfile"],
            401,
            "failedAttemptBurst",
            workload["failedAttempt"]["samples"],
            0,
        ),
        (
            facts["accountEventProfile"],
            201,
            "accountEventCommit",
            workload["accountEvent"]["minimumSamples"],
            workload["accountEvent"]["seconds"],
        ),
    ]
    for profile, status, prefix, minimum, seconds in definitions:
        fields = {
            "concurrency",
            "samples",
            "elapsedSeconds",
            "statuses",
            "p95Ms",
            "maxMs",
            "requestsPerSecond",
        }
        if prefix.startswith("session"):
            fields.add("codes")
            require(profile["codes"] == {}, "observation-response-code")
        else:
            fields.add("warmup")
            expected = workload[
                {200: "login", 401: "failedAttempt", 201: "accountEvent"}[status]
            ]
            require(
                profile["concurrency"] == expected["concurrency"]
                and profile["warmup"] == expected.get("warmup", 0),
                "observation-auth-profile",
            )
            if status == 401:
                fields.add("limitedStatuses")
                require(
                    profile["limitedStatuses"] == {"429": expected["limitedChecks"]},
                    "observation-limited-checks",
                )
            if status in {200, 401}:
                require(profile["samples"] == minimum, "observation-burst-samples")
        require(
            set(profile) == fields
            and type(profile["samples"]) is int
            and profile["samples"] >= minimum
            and profile["statuses"] == {str(status): profile["samples"]},
            "observation-profile-status",
        )
        require(
            number(profile["elapsedSeconds"], max(seconds, 0.000001))
            and number(profile["p95Ms"], 0.000001)
            and number(profile["requestsPerSecond"], 0.000001)
            and number(profile["maxMs"], profile["p95Ms"])
            and profile["maxMs"]
            <= subject["policy"]["revocation"]["requestDeadlineSeconds"] * 1000,
            "observation-profile-measurement",
        )
        require(
            math.isclose(
                profile["requestsPerSecond"],
                profile["samples"] / profile["elapsedSeconds"],
                rel_tol=1e-9,
            ),
            "observation-throughput",
        )
        rate_key = (
            "accountEventCommitsPerSecond"
            if status == 201
            else prefix + "RequestsPerSecond"
        )
        require(
            measurements[prefix + "P95Ms"] == profile["p95Ms"]
            and measurements[rate_key] == profile["requestsPerSecond"],
            "observation-measurement-correlation",
        )
    require(
        measurements["unexpectedErrors"] == 0
        and measurements["lostSecurityChanges"] == 0,
        "observation-errors",
    )


def validate_targets(value, subject, baseline=None):
    require(
        isinstance(value, dict)
        and set(value) == {"subject", "approvalReference", "baselineSha256", "limits"},
        "target-fields",
    )
    require(value["subject"] == subject, "target-candidate-mismatch")
    reference = value["approvalReference"]
    require(isinstance(reference, str), "owner-approval-required")
    url = urlsplit(reference)
    require(
        url.scheme == "https"
        and url.netloc == "dev.azure.com"
        and url.path
        == f"/shengming0923/rss/_git/rss-identity/pullrequest/{subject['pullRequest']}"
        and not url.fragment
        and re.fullmatch(r"discussionId=[1-9][0-9]*", url.query),
        "owner-approval-required",
    )
    require(
        isinstance(baseline, bytes) and digest(baseline) == value["baselineSha256"],
        "baseline-digest",
    )
    measured = json.loads(baseline)
    require(
        measured.get("targets") is None and measured.get("result") == "measured",
        "complete-baseline-required",
    )
    verify_record(measured, subject)
    limits = value["limits"]
    require(isinstance(limits, dict) and set(limits) == set(LIMITS), "target-limits")
    require(
        all(
            type(v) in (int, float) and math.isfinite(v) and v >= 0
            for v in limits.values()
        ),
        "target-values",
    )
    return value


def verify_record(record, subject, baseline=None):
    profile = validate_binary_profile(subject.get("binaryProfile"))
    require(
        subject.get("schema", {}).get("version") == profile["schemaVersion"],
        "binary-schema-mismatch",
    )
    validate_migration_profile(
        subject.get("migrationProfile"), profile, subject["schema"]["signature"]
    )
    require(
        subject.get("runtimeProfile") == runtime_profile(runtime_template())
        and subject.get("policy") == POLICY
        and subject.get("workload") == WORKLOAD
        and subject.get("scenarios") == list(STEPS),
        "frozen-profile-mismatch",
    )
    require(
        set(record) == set(new_record(subject, None))
        and record["formatVersion"] == 1
        and record["scope"] == "identity-reference-t3",
        "record-fields",
    )
    require(record["subject"] == subject, "record-subject")
    require(record["uncovered"] == UNCOVERED, "coverage-boundaries")
    require(
        record["failure"] is None
        and record["cleanup"] == {"status": "passed", "remaining": []},
        "incomplete-cleanup-or-failure",
    )
    require([s["name"] for s in record["steps"]] == list(STEPS), "incomplete-scenarios")
    for step in record["steps"]:
        require(
            set(step) == {"name", "status", "elapsedMs", "observations"}
            and step["status"] == "passed",
            "step-status",
        )
        require(
            type(step["elapsedMs"]) is int
            and step["elapsedMs"] >= 0
            and isinstance(step["observations"], dict),
            "step-observation",
        )
    measurements = record["measurements"]
    require(
        set(measurements) == set(MEASUREMENTS)
        and all(
            type(v) in (int, float) and math.isfinite(v) and v >= 0
            for v in measurements.values()
        ),
        "measurements",
    )
    require(
        measurements["restoreSeconds"] > 0 and measurements["backupBytes"] > 0,
        "restore-measurements",
    )
    for step in record["steps"]:
        verify_observations(step["name"], step["observations"], subject, measurements)
    if record["targets"] is None:
        require(record["approval"] is None, "unexpected-approval")
        require(record["result"] == "measured", "baseline-is-not-acceptance")
    else:
        target = validate_targets(record["targets"], subject, baseline)
        validate_receipt(record["approval"], target)
        for name, direction in LIMITS.items():
            require(
                (
                    measurements[name] <= target["limits"][name]
                    if direction == "max"
                    else measurements[name] >= target["limits"][name]
                ),
                "target-not-met",
            )
        require(record["result"] == "passed", "record-verdict")
    return record


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save_evidence(path, record, secrets_):
    try:
        assert_redacted(record, secrets_)
    except ValueError:
        safe = new_record({}, None)
        safe.update(
            result="failed",
            failure={"stage": "redaction", "reason": "secret-in-evidence"},
            cleanup={"status": "unconfirmed", "remaining": []},
        )
        save(path, safe)
        raise
    save(path, record)


def image_identity(image):
    return {
        "id": image["Id"],
        "revision": (image["Config"].get("Labels") or {}).get(
            "org.opencontainers.image.revision"
        ),
        "os": image["Os"],
        "architecture": image["Architecture"],
        "variant": image.get("Variant") or None,
    }


def verify_browser_lock(lock, browser):
    text = lock.decode()
    sections = re.findall(r"^packages:\n(.*?)(?=^[^ \n]|\Z)", text, re.M | re.S)
    require(len(sections) == 1, "browser-lock-mismatch")
    entries = re.findall(
        r"^  playwright-core@1\.60\.0:\n((?:    .*\n|\n)*)", sections[0], re.M
    )
    require(len(entries) == 1, "browser-lock-mismatch")
    integrities = re.findall(
        r"^    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$", entries[0], re.M
    )
    require(
        browser.get("version") == "1.60.0"
        and integrities == [browser.get("integrity")],
        "browser-lock-mismatch",
    )


def validate_binary_profile(profile):
    require(
        isinstance(profile, dict)
        and set(profile)
        == {
            "formatVersion",
            "schemaVersion",
            "session",
            "attempts",
            "kdfConcurrency",
            "mfaMaxAgeSeconds",
        }
        and type(profile["formatVersion"]) is int
        and profile["formatVersion"] == 1
        and type(profile["schemaVersion"]) is int
        and profile["schemaVersion"] == 11
        and all(
            json.dumps(profile[key], sort_keys=True)
            == json.dumps(POLICY[key], sort_keys=True)
            for key in ["session", "attempts", "kdfConcurrency", "mfaMaxAgeSeconds"]
        ),
        "binary-policy-mismatch",
    )
    return profile


def candidate_probe(prefix, phase, image, entrypoint, *args):
    # outside() establishes this ownership and cleanup boundary before preflight.
    return docker(
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--name",
        prefix + "-" + phase,
        "--label",
        "rss.identity.t3=" + prefix,
        "--entrypoint",
        entrypoint,
        image,
        *args,
    )


def binary_profile(image, prefix):
    return validate_binary_profile(
        json.loads(
            candidate_probe(
                prefix,
                "policy",
                image,
                "identity-server",
                "--acceptance-profile",
            )
        )
    )


def validate_migration_profile(value, profile, signature, identity_sql_sha=None):
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema_version",
            "schema_contract",
            "identity_sql_sha256",
            "rss_sql_sha256",
        }
        and type(value["schema_version"]) is int
        and value["schema_version"] == profile["schemaVersion"] == 11
        and value["schema_contract"] == signature
        and all(
            isinstance(value[key], str) and re.fullmatch("[0-9a-f]{64}", value[key])
            for key in ["schema_contract", "identity_sql_sha256", "rss_sql_sha256"]
        )
        and (
            identity_sql_sha is None or value["identity_sql_sha256"] == identity_sql_sha
        ),
        "binary-migration-mismatch",
    )
    return value


def migration_profile(image, profile, signature, identity_sql_sha, prefix):
    value = json.loads(
        candidate_probe(prefix, "migration", image, "identity-migrate", "--describe")
    )
    return validate_migration_profile(value, profile, signature, identity_sql_sha)


def candidate(args, prefix):
    require(git(ROOT, "status", "--porcelain") == "", "committed-runner-required")
    require(
        type(args.pull_request) is int and args.pull_request > 0,
        "pull-request-required",
    )
    details = deploy.resolve_image_details(args.identity_image, args.web_image)
    tool = deploy.inspect_image(args.tools_image)
    require(
        (tool["Config"].get("Labels") or {}).get("org.opencontainers.image.revision")
        == git(ROOT, "rev-parse", "HEAD"),
        "tools-source-revision",
    )
    identity = image_identity(details["identity"])
    web = image_identity(details["web"])
    profile = binary_profile(identity["id"], prefix)
    lock = process(
        ["/usr/bin/git", "-C", str(ROOT), "show", identity["revision"] + ":Cargo.lock"]
    )
    manifest = tomllib.loads(
        process(
            [
                "/usr/bin/git",
                "-C",
                str(ROOT),
                "show",
                identity["revision"] + ":Cargo.toml",
            ]
        ).decode()
    )
    rss = manifest["workspace"]["dependencies"]["rss-request-context"]["rev"]
    web_lock = process(
        [
            "/usr/bin/git",
            "-C",
            str(args.web_repo),
            "show",
            web["revision"] + ":pnpm-lock.yaml",
        ]
    )
    schema = process(
        [
            "/usr/bin/git",
            "-C",
            str(ROOT),
            "show",
            identity["revision"]
            + ":crates/identity-postgres/src/schema-signature.sha256",
        ]
    )
    for path in [
        "crates/identity-postgres/src/schema-signature.sha256",
        "crates/identity-postgres/migrations/0001_authority.sql",
        "deployment/providers.lock.json",
        "deployment/deploy.example.json",
        "crates/identity-postgres/src/security-event-v3.json",
    ]:
        require(
            process(
                [
                    "/usr/bin/git",
                    "-C",
                    str(ROOT),
                    "show",
                    identity["revision"] + ":" + path,
                ]
            )
            == (ROOT / path).read_bytes(),
            "candidate-deployment-drift",
        )
    migration = migration_profile(
        identity["id"],
        profile,
        schema.decode().strip(),
        file_digest(ROOT / "crates/identity-postgres/migrations/0001_authority.sql"),
        prefix,
    )
    info = json.loads(docker("info", "--format", "{{json .}}"))
    subject = {
        "runnerRevision": git(ROOT, "rev-parse", "HEAD"),
        "identity": {**identity, "cargoLockSha256": digest(lock)},
        "web": {**web, "lockSha256": digest(web_lock)},
        "rssRevision": rss,
        "schema": {
            "version": profile["schemaVersion"],
            "signature": schema.decode().strip(),
        },
        "binaryProfile": profile,
        "migrationProfile": migration,
        "providers": {
            k: image_identity(v)
            for k, v in details.items()
            if k not in ["identity", "web"]
        },
        "providersLockSha256": file_digest(ROOT / "deployment/providers.lock.json"),
        "keycloak": image_identity(deploy.inspect_image(deploy.IMAGES["keycloak"])),
        "tools": image_identity(tool),
        "resources": {
            "daemonId": info["ID"],
            "serverVersion": info["ServerVersion"],
            "os": info["OSType"],
            "architecture": info["Architecture"],
            "cpus": info["NCPU"],
            "memoryBytes": info["MemTotal"],
        },
    }
    require(re.fullmatch("[0-9a-f]{40}", rss), "rss-revision")
    # Runtime package identity is independently checked inside the tools image.
    browser = json.loads(
        candidate_probe(
            prefix,
            "browser",
            tool["Id"],
            "node",
            "-e",
            "const p=require('/opt/playwright-core/package.json');console.log(JSON.stringify({version:p.version,integrity:require('fs').readFileSync('/opt/playwright-integrity','utf8')}))",
        )
    )
    verify_browser_lock(web_lock, browser)
    subject["browser"] = browser
    subject.update(
        pullRequest=args.pull_request,
        runtimeProfile=runtime_profile(runtime_template()),
        policy=copy.deepcopy(POLICY),
        supportedProviders={
            "keycloak": subject["keycloak"],
            "flows": ["code-pkce", "jit", "explicit-link", "totp-step-up"],
        },
        scenarios=list(STEPS),
        workload=copy.deepcopy(WORKLOAD),
    )
    require(bool(args.targets) == bool(args.baseline), "targets-require-baseline")
    baseline = args.baseline.read_bytes() if args.baseline else None
    targets = (
        validate_targets(json.loads(args.targets.read_text()), subject, baseline)
        if args.targets
        else None
    )
    return details, tool, subject, targets, baseline


class Run:
    def __init__(self, config):
        require(
            docker("info", "--format", "{{.ID}}").decode().strip()
            == config["subject"]["resources"]["daemonId"],
            "docker-daemon-mismatch",
        )
        self.config = config
        self.work = Path(config["work"])
        self.work.mkdir(mode=0o700)
        self.record = new_record(config["subject"], config["targets"])
        self.record["approval"] = config.get("approval")
        self.output = Path(config["output"])
        self.prefix = config["prefix"]
        self.source = self.prefix + "-source"
        self.restored = self.prefix + "-restored"
        self.stale = self.prefix + "-stale"
        self.directories = {}
        self.current = None
        self.secrets = []
        self.browser_private = self.work / "browser-private.json"
        self.images = config["images"]
        self.keycloak = self.prefix + "-keycloak"
        self.provider_network = self.prefix + "-provider"
        self.ca_files = []

    def write(self, name, value):
        path = self.work / name
        path.write_bytes(value if isinstance(value, bytes) else value.encode())
        path.chmod(0o600)
        os.chown(path, 10001, 10001)
        return str(path)

    def secret(self, name, size=24):
        value = secrets.token_hex(size)
        self.secrets.append(value)
        return value, self.write(name, value)

    def step(self, name, action):
        item = {"name": name, "status": "running", "elapsedMs": 0, "observations": {}}
        self.record["steps"].append(item)
        save_evidence(self.output, self.record, self.secrets)
        start = time.monotonic()
        try:
            item["observations"] = action() or {}
            self.record["measurements"].update(
                item["observations"].pop("measurements", {})
            )
            item["status"] = "passed"
        except BaseException:
            item["status"] = "failed"
            raise
        finally:
            item["elapsedMs"] = int((time.monotonic() - start) * 1000)
            save_evidence(self.output, self.record, self.secrets)
        print("T3 " + name + ": passed", flush=True)

    def compose(self, *args, project=None, directory=None, **kwargs):
        project = project or self.source
        directory = directory or self.directories[project]
        return docker(
            "compose",
            "--project-name",
            project,
            "--file",
            directory / "compose.json",
            *args,
            **kwargs,
        )

    def op(self, command, *args, project=None, directory=None, reject=False):
        project = project or self.source
        directory = directory or self.directories[project]
        if command == "open" and not reject:
            operate.require_closed(project)
            self.compose(
                "up",
                "--no-start",
                "--no-deps",
                "identity",
                project=project,
                directory=directory,
            )
            container = (
                self.compose(
                    "ps",
                    "--all",
                    "--quiet",
                    "identity",
                    project=project,
                    directory=directory,
                )
                .decode()
                .strip()
            )
            attached = json.loads(docker("inspect", container))[0]["NetworkSettings"][
                "Networks"
            ]
            if self.provider_network not in attached:
                docker("network", "connect", self.provider_network, container)
        result = bounded_run(
            [
                sys.executable,
                str(ROOT / "hack/operate.py"),
                "--deployment",
                str(directory),
                "--project",
                project,
                command,
                *map(str, args),
            ],
            timeout=240,
            capture_output=True,
        )
        status = json.loads(result.stdout)
        if not (result.returncode != 0 if reject else result.returncode == 0):
            if reject:
                raise ValueError("expected-rejection-" + command)
            raise ProcessFailure("operate-" + command, result.returncode)
        if reject:
            require(status["status"] != "passed", "expected-operation-rejection")
        if command == "open" and not reject:
            attached = json.loads(docker("inspect", container))[0]["NetworkSettings"][
                "Networks"
            ]
            require(
                self.provider_network in attached, "provider-network-lost-during-open"
            )
        return status

    def sql(self, query, project=None):
        raw = self.compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "identity",
            "-f",
            "-",
            project=project,
            input=query.encode(),
        )
        return raw.decode().strip()

    def cert(self, name, sans):
        ca = self.work / (name + "-ca.pem")
        ca_key = self.work / (name + "-ca.key")
        key = self.work / (name + ".key")
        csr = self.work / (name + ".csr")
        cert = self.work / (name + ".crt")
        process(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca),
                "-days",
                "2",
                "-subj",
                "/CN=" + name + "-test-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ]
        )
        process(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(csr),
                "-subj",
                "/CN=" + name,
            ]
        )
        extension = self.work / (name + ".ext")
        extension.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName="
            + ",".join(sans)
            + "\n"
        )
        process(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ca),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(cert),
                "-days",
                "2",
                "-extfile",
                str(extension),
            ]
        )
        for path in [ca, ca_key, key, csr, cert, extension]:
            path.chmod(0o600)
            os.chown(path, 10001, 10001)
        self.ca_files.append(ca)
        return str(ca), str(cert), str(key)

    def trust_browser(self):
        nss = Path("/root/.pki/nssdb")
        nss.mkdir(parents=True, exist_ok=True)
        if not (nss / "cert9.db").exists():
            process(["certutil", "-N", "--empty-password", "-d", "sql:" + str(nss)])
        for index, ca in enumerate(self.ca_files):
            process(
                [
                    "certutil",
                    "-A",
                    "-d",
                    "sql:" + str(nss),
                    "-n",
                    "t3-ca-" + str(index),
                    "-t",
                    "C,,",
                    "-i",
                    str(ca),
                ]
            )
        bundle = self.work / "browser-ca.pem"
        bundle.write_bytes(b"\n".join(p.read_bytes() for p in self.ca_files))
        bundle.chmod(0o600)
        return str(bundle)

    def browser(self, phase, **extra):
        config = {
            **self.browser_config,
            **extra,
            "phase": phase,
            "privateFile": str(self.browser_private),
        }
        path = self.work / "browser-input.json"
        save(path, config)
        path.chmod(0o600)
        reply = bounded_run(
            ["node", str(ROOT / "hack/reference_t3_browser.mjs"), str(path)],
            timeout=900,
            capture_output=True,
            env={**os.environ, "NODE_EXTRA_CA_CERTS": self.trust_browser()},
        )
        result = json.loads(reply.stdout)
        if result.get("diagnostics"):
            assert_redacted(result["diagnostics"], self.secrets)
            self.record["steps"][-1]["observations"]["diagnostics"] = result[
                "diagnostics"
            ]
        reason = result.get("diagnostic", "scenario")
        require(
            result.get("status") == "passed",
            (
                "browser-" + reason
                if re.fullmatch("[a-z-]{1,60}", reason)
                else "browser-scenario"
            ),
        )
        assert_redacted(result, self.secrets)
        if self.browser_private.exists():
            private = json.loads(self.browser_private.read_text())
            self.secrets.extend(private.get("secrets", []))
        return result["observations"]

    def render(self, name, data, project=None):
        path = self.work / name
        deploy.render(data, path, self.images)
        self.directories[project or self.source] = path
        return path

    def snapshot(self, project=None):
        # Full rows remain inside the private fixture; reports contain only IDs and digests.
        queries = {
            name: "SELECT * FROM identity_authority." + table + " ORDER BY " + order
            for name, table, order in [
                ("accounts", "accounts", "tenant_id,principal_id"),
                ("memberships", "memberships", "tenant_id,principal_id"),
                ("credentials", "local_credentials", "tenant_id,principal_id"),
                ("providers", "providers", "tenant_id,provider_id"),
                (
                    "providerCredentials",
                    "provider_credentials",
                    "tenant_id,provider_id",
                ),
                ("externalIdentities", "external_identities", "tenant_id,identity_id"),
                ("sessions", "sessions", "tenant_id,session_id"),
                ("attempts", "attempts", "tenant_id,key"),
                ("linkIntents", "link_intents", "tenant_id,intent_id"),
                ("oidcTransactions", "oidc_transactions", "tenant_id,attempt_id"),
            ]
        }
        queries["outbox"] = (
            "SELECT * FROM rss_transactional_messaging.outbox ORDER BY seq"
        )
        return {
            name: json.loads(
                self.sql(
                    "SELECT coalesce(json_agg(row_to_json(s)),'[]'::json) FROM ("
                    + sql
                    + ") s;",
                    project,
                )
            )
            for name, sql in queries.items()
        }

    def reserve_networks(self):
        candidates = iter(ipaddress.ip_network("10.243.0.0/16").subnets(new_prefix=24))

        def allocate(*args):
            return bounded_run(
                ["docker", *args], check=True, capture_output=True, timeout=180
            )

        self.subnets = []
        for project in [self.source, self.stale, self.restored, None]:
            labels = ["rss.identity.t3=" + self.prefix]
            if project:
                labels += [
                    "com.docker.compose.project=" + project,
                    "com.docker.compose.network=backend",
                ]
            self.subnets.append(
                create_network(
                    allocate,
                    project + "_backend" if project else self.provider_network,
                    candidates,
                    labels=labels,
                    internal=True,
                )
            )

    def install(self):
        network = json.loads(docker("network", "inspect", "bridge"))[0]
        gateway = network["IPAM"]["Config"][0]["Gateway"]
        require(ipaddress.ip_address(gateway).is_private, "daemon-private-gateway")
        self.gateway = gateway
        self.reserve_networks()
        networks = self.subnets
        public_ca, public_cert, public_key = self.cert(
            "public", ["DNS:identity.example.test"]
        )
        pg_ca, pg_cert, pg_key = self.cert("postgres", ["DNS:postgres"])
        provider_address = str(ipaddress.ip_network(networks[3]).network_address + 3)
        docker("network", "connect", self.provider_network, self.prefix + "-operator")
        kc_ca, kc_cert, kc_key = self.cert("keycloak", ["IP:" + provider_address])
        self.admin_password, admin_file = self.secret("admin-password")
        self.user_password, _ = self.secret("user-password")
        self.next_password, _ = self.secret("next-user-password")
        self.client_secret, _ = self.secret("client-secret")
        self.idp_password, _ = self.secret("idp-password")
        self.otp_secret, _ = self.secret("otp-secret", 20)
        self.kc_admin, self.kc_admin_file = self.secret("keycloak-admin-password")
        port = 8443
        self.issuer = f"https://{provider_address}:{port}/realms/identity"
        realm = {
            "realm": "identity",
            "enabled": True,
            "sslRequired": "all",
            "duplicateEmailsAllowed": True,
            "loginWithEmailAllowed": False,
            "clients": [
                {
                    "clientId": "reference",
                    "secret": self.client_secret,
                    "publicClient": False,
                    "standardFlowEnabled": True,
                    "directAccessGrantsEnabled": False,
                    "redirectUris": [ORIGIN + "/api/v2/oidc/callback"],
                    "attributes": {"pkce.code.challenge.method": "S256"},
                }
            ],
            "users": [
                {
                    "username": name,
                    "enabled": True,
                    "email": "same@example.test",
                    "emailVerified": True,
                    "firstName": name,
                    "lastName": "Fixture",
                    "credentials": [
                        {
                            "type": "password",
                            "value": self.idp_password,
                            "temporary": False,
                        },
                        {
                            "type": "otp",
                            "userLabel": "t3",
                            "secretData": json.dumps({"value": self.otp_secret}),
                            "credentialData": json.dumps(
                                {
                                    "digits": 6,
                                    "counter": 0,
                                    "period": 30,
                                    "algorithm": "HmacSHA1",
                                    "subType": "totp",
                                }
                            ),
                        },
                    ],
                }
                for name in ["alice", "bob"]
            ],
        }
        realm.update(json.loads((ROOT / "deployment/keycloak-totp.json").read_text()))
        realm_file = self.write("realm.json", json.dumps(realm))
        # Keycloak runs as the same isolated fixture UID, so private mounts stay 0600.
        kc_env = self.write(
            "keycloak.env",
            "KC_BOOTSTRAP_ADMIN_USERNAME=operator\nKC_BOOTSTRAP_ADMIN_PASSWORD="
            + self.kc_admin
            + "\n",
        )
        for path in [realm_file, kc_cert, kc_key]:
            os.chown(path, 1000, 1000)
        docker(
            "run",
            "-d",
            "--pull=never",
            "--name",
            self.keycloak,
            "--label",
            "rss.identity.t3=" + self.prefix,
            "--user",
            "1000:1000",
            "--env-file",
            kc_env,
            "--network",
            self.provider_network,
            "--ip",
            provider_address,
            "--mount",
            f"type=bind,source={realm_file},target=/opt/keycloak/data/import/realm.json,readonly",
            "--mount",
            f"type=bind,source={kc_cert},target=/opt/keycloak/conf/server.crt,readonly",
            "--mount",
            f"type=bind,source={kc_key},target=/opt/keycloak/conf/server.key,readonly",
            deploy.IMAGES["keycloak"],
            "start-dev",
            "--import-realm",
            "--http-enabled=false",
            "--hostname=" + self.issuer.split("/realms")[0],
            "--https-certificate-file=/opt/keycloak/conf/server.crt",
            "--https-certificate-key-file=/opt/keycloak/conf/server.key",
        )
        import ssl, urllib.request, urllib.error

        until = time.monotonic() + 180
        while True:
            try:
                with urllib.request.urlopen(
                    self.issuer + "/.well-known/openid-configuration",
                    context=ssl.create_default_context(cafile=kc_ca),
                    timeout=3,
                ) as r:
                    if r.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                pass
            require(time.monotonic() < until, "keycloak-readiness")
            time.sleep(0.5)
        value = json.loads((ROOT / "deployment/deploy.example.json").read_text())
        runtime = value["runtime"] = runtime_template()
        self.data = value
        runtime["instanceId"] = str(__import__("uuid").uuid4())
        runtime["storage"]["target"] = list(secrets.token_bytes(16))
        runtime["storage"]["lineage"] = list(secrets.token_bytes(16))
        runtime["storage"]["tenants"] = TENANTS
        runtime["bootstrapAccounts"] = [
            {"tenantId": t, "principalId": p} for t, p in zip(TENANTS, PRINCIPALS)
        ]
        _, runtime["database"]["passwordFile"] = self.secret("runtime-password")
        runtime["database"]["caFile"] = pg_ca
        _, value["ownerPasswordFile"] = self.secret("owner-password")
        _, value["maintenancePasswordFile"] = self.secret("maintenance-password")
        value.update(
            tlsCertificateFile=public_cert,
            tlsKeyFile=public_key,
            postgresCertificateFile=pg_cert,
            postgresKeyFile=pg_key,
            backendSubnet=networks[0],
        )
        runtime["publicGateway"] = networks[0].rsplit(".", 1)[0] + ".2"
        _, self.old_key = self.secret("credential-old", 32)
        _, self.new_key = self.secret("credential-new", 32)
        _, state = self.secret("state-key", 32)
        runtime["oidc"] = oidc_settings(
            self.issuer, provider_address, state, self.old_key
        )
        profile = runtime_profile(runtime)
        require(
            profile == self.record["subject"]["runtimeProfile"], "runtime-profile-drift"
        )
        self.browser_config = {
            "workload": self.record["subject"]["workload"],
            "policy": self.record["subject"]["policy"],
            "origin": ORIGIN,
            "tenants": TENANTS,
            "adminPassword": self.admin_password,
            "userPassword": self.user_password,
            "nextPassword": self.next_password,
            "idpPassword": self.idp_password,
            "otpSecret": self.otp_secret,
            "issuer": self.issuer,
            "clientSecret": self.client_secret,
            "idpCa": Path(kc_ca).read_text(),
        }
        self.render("initial", value)
        self.op("install")
        for tenant in TENANTS:
            self.op("initialize", tenant, "operator", admin_file)
        self.op("open")
        self.op("initialize", TENANTS[0], "operator", admin_file, reject=True)
        self.op("close")
        self.op("open")
        self.op("initialize", TENANTS[0], "operator", admin_file, reject=True)
        spec = json.loads((self.directories[self.source] / "compose.json").read_text())
        identity_id = self.compose("ps", "--quiet", "identity").decode().strip()
        inspected = json.loads(docker("inspect", identity_id))[0]
        require(
            inspected["Config"]["User"] == "10001:10001"
            and inspected["HostConfig"]["ReadonlyRootfs"],
            "runtime-uid",
        )
        require(
            all(
                not m["RW"]
                for m in inspected["Mounts"]
                if m["Destination"].startswith("/run/")
            ),
            "secret-mount-readonly",
        )
        mounts = []
        for mount in spec["services"]["identity"]["volumes"]:
            mounts.extend(
                [
                    "--mount",
                    f"type=bind,source={mount['source']},target={mount['target']},readonly",
                ]
            )
        for uid, accepted in [("10001:10001", True), ("10002:10002", False)]:
            checked = bounded_run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network=none",
                    "--user",
                    uid,
                    *mounts,
                    self.images["identity"],
                    "--check-config",
                    "/run/config/runtime.json",
                ],
                timeout=30,
                capture_output=True,
            )
            require(
                (checked.returncode == 0) == accepted, "mounted-secret-uid-boundary"
            )

        configuration_digest = digest(json.dumps(profile, sort_keys=True).encode())
        return {
            "tenants": 2,
            "initializationReplayRejected": True,
            "configurationSha256": configuration_digest,
        }

    def events(self):
        self.browser("pg-ready")
        budget_query = (
            "SELECT coalesce(max(count),0) FROM identity_authority.attempts WHERE tenant_id='"
            + TENANTS[0]
            + "' AND key='p:linked' AND expires_at>clock_timestamp();"
        )
        budget_before = int(self.sql(budget_query))
        before = self.snapshot()
        require(
            len(before["accounts"]) >= 6
            and len(before["providers"]) == 2
            and len(before["outbox"]) > 0,
            "durable-security-chain",
        )
        self.sql(
            "CREATE FUNCTION public.t3_reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejection'; END $$; CREATE TRIGGER t3_reject_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.t3_reject_event();"
        )
        try:
            self.browser("rollback")
        finally:
            self.sql(
                "DROP TRIGGER t3_reject_event ON rss_transactional_messaging.outbox; DROP FUNCTION public.t3_reject_event();"
            )
        require(
            self.sql(
                "SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='rolled-back';"
            )
            == "0",
            "rollback-account",
        )
        after = self.snapshot()
        require(
            after["accounts"] == before["accounts"]
            and after["outbox"] == before["outbox"],
            "rollback-state-and-events",
        )
        require(
            int(self.sql(budget_query)) == budget_before + 1,
            "failed-attempt-budget-committed",
        )
        self.browser("response-loss")
        require(
            self.sql(
                "SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='uncertain';"
            )
            == "1",
            "unknown-observed-commit",
        )
        final = self.snapshot()
        require(len(final["outbox"]) == len(after["outbox"]) + 1, "unknown-event-once")
        row = final["outbox"][-1]
        principal = self.sql(
            "SELECT principal_id FROM identity_authority.local_credentials WHERE login_key='uncertain';"
        )
        account = next(a for a in final["accounts"] if a["principal_id"] == principal)
        member = next(a for a in final["memberships"] if a["principal_id"] == principal)
        envelope = row["envelope"]
        payload = json.loads(bytes(envelope["payload"]))
        require(
            row["tenant_id"] == TENANTS[0]
            and row["message_id"] == envelope["id"]
            and row["domain"] == "identity.security"
            and row["status"] == "pending",
            "unknown-event-envelope",
        )
        require(
            envelope["tenant"] == TENANTS[0]
            and envelope["domain"] == "identity.security"
            and envelope["route"] == "account.changed"
            and envelope["contract"] == "identity.account.security"
            and envelope["version"] == "v3"
            and envelope["schema"]
            == "sha256:"
            + file_digest(ROOT / "crates/identity-postgres/src/security-event-v3.json"),
            "unknown-event-contract",
        )
        require(
            payload
            == {
                "action": "account_created",
                "tenant": TENANTS[0],
                "principal": principal,
                "actor": PRINCIPALS[0],
                "epoch": account["auth_epoch"],
                "state": {
                    "enabled": account["enabled"],
                    "member_active": member["active"],
                    "membership_epoch": member["epoch"],
                },
            },
            "unknown-event-state-correlation",
        )
        return {
            "rollbackPreserved": True,
            "failedAttemptBudgetCommitted": True,
            "responseLossObservedCommitted": True,
            "durableEvents": len(final["outbox"]),
            "outboxSha256": digest(
                json.dumps(final["outbox"], sort_keys=True).encode()
            ),
            "eventIds": [row["message_id"] for row in final["outbox"]],
        }

    def availability(self):
        docker("stop", self.keycloak)
        try:
            self.browser("idp-down")
        finally:
            docker("start", self.keycloak)
        # Wait via the actual provider test before the PG fault.
        self.browser("provider-ready")
        self.compose("stop", "postgres")
        try:
            self.browser("pg-down")
        finally:
            self.compose("up", "-d", "--wait", "postgres")
        self.op("verify")
        self.browser("pg-ready")
        return {"localSurvivesIdpFailure": True, "storageFailureClosed": True}

    def credential_rotation(self):
        self.op("close")
        new = {"activeKeyId": "new", "keys": [{"keyId": "new", "path": self.new_key}]}
        bad = copy.deepcopy(self.data)
        bad["runtime"]["oidc"]["credentialKeyring"] = new
        self.render("wrong-key-before-rekey", bad)
        self.op("verify-keys", reject=True)
        self.data["runtime"]["oidc"]["credentialKeyring"] = {
            "activeKeyId": "new",
            "keys": [
                {"keyId": "old", "path": self.old_key},
                {"keyId": "new", "path": self.new_key},
            ],
        }
        self.render("mixed-keys", self.data)
        self.op("rekey")
        retired = copy.deepcopy(self.data)
        retired["runtime"]["oidc"]["credentialKeyring"] = {
            "activeKeyId": "old",
            "keys": [{"keyId": "old", "path": self.old_key}],
        }
        self.render("retired-key-only", retired)
        self.op("verify-keys", reject=True)
        self.data["runtime"]["oidc"]["credentialKeyring"] = new
        self.render("new-key-only", self.data)
        self.op("verify-keys")
        self.op("verify")
        self.op("open")
        self.browser("provider-ready")
        return {
            "oldCiphertextRejectedWithoutKey": True,
            "retiredKeyRejected": True,
            "singleNewKeyVerified": True,
        }

    def state_rotation(self):
        self.browser("begin-old-state")
        self.op("close")
        _, path = self.secret("next-state-key", 32)
        self.data["runtime"]["oidc"]["stateKeyFile"] = path
        self.render("new-state-key", self.data)
        self.op("open")
        self.browser("reject-old-state")
        self.browser("fresh-sso")
        return {"oldStateRejected": True, "newFlowAccepted": True}

    def keycloak_request(self, method, path, data=None, token=None, form=False):
        import ssl, urllib.request, urllib.parse

        context = ssl.create_default_context(cafile=str(self.work / "keycloak-ca.pem"))
        headers = {
            "Content-Type": (
                "application/x-www-form-urlencoded" if form else "application/json"
            )
        }
        if token:
            headers["Authorization"] = "Bearer " + token
        body = (
            urllib.parse.urlencode(data).encode()
            if form
            else json.dumps(data).encode() if data is not None else None
        )
        request = urllib.request.Request(
            self.issuer.split("/realms")[0] + path,
            data=body,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            raw = response.read(1048576)
            return json.loads(raw) if raw else None

    def client_rotation(self):
        token = self.keycloak_request(
            "POST",
            "/realms/master/protocol/openid-connect/token",
            {
                "client_id": "admin-cli",
                "grant_type": "password",
                "username": "operator",
                "password": self.kc_admin,
            },
            form=True,
        )["access_token"]
        self.secrets.append(token)
        clients = self.keycloak_request(
            "GET", "/admin/realms/identity/clients?clientId=reference", token=token
        )
        require(len(clients) == 1, "keycloak-client")
        value = self.keycloak_request(
            "POST",
            "/admin/realms/identity/clients/" + clients[0]["id"] + "/client-secret",
            {},
            token,
        )["value"]
        self.secrets.append(value)
        self.browser("old-client-secret")
        self.browser_config["clientSecret"] = value
        self.browser("update-client-secret")
        self.browser("fresh-sso")
        return {"oldClientSecretRejected": True, "newClientSecretAccepted": True}

    def rejected_runtime_start(self):
        result = bounded_run(
            [
                "docker",
                "compose",
                "--project-name",
                self.source,
                "--file",
                str(self.directories[self.source] / "compose.json"),
                "run",
                "--rm",
                "--no-deps",
                "identity",
            ],
            timeout=45,
            capture_output=True,
        )
        require(result.returncode != 0, "invalid-runtime-material-accepted")
        require(
            b"database" in result.stderr.lower()
            or b"connection" in result.stderr.lower(),
            "unexpected-runtime-rejection",
        )
        operate.require_closed(self.source)

    def database_probe(self, role, password_file, accepted):
        env = self.write(
            "pg-probe.env",
            "PGPASSWORD="
            + Path(password_file).read_text()
            + "\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/ca.pem\n",
        )
        networks = json.loads(
            docker("inspect", self.compose("ps", "-q", "postgres").decode().strip())
        )[0]["NetworkSettings"]["Networks"]
        require(len(networks) == 1, "postgres-probe-network")
        result = bounded_run(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--label",
                "rss.identity.t3=" + self.prefix,
                "--network",
                next(iter(networks)),
                "--env-file",
                env,
                "--mount",
                "type=bind,source="
                + self.data["runtime"]["database"]["caFile"]
                + ",target=/run/ca.pem,readonly",
                "--entrypoint",
                "psql",
                self.images["postgres"],
                "-X",
                "-qAt",
                "-h",
                "postgres",
                "-U",
                role,
                "-d",
                "identity",
                "-c",
                "SELECT current_user",
            ],
            timeout=30,
            capture_output=True,
        )
        passed = (
            result.returncode == 0 and result.stdout.decode().strip() == role
            if accepted
            else result.returncode != 0
            and b"password authentication failed" in result.stderr
        )
        if not passed:
            error = result.stderr.lower()
            kind = (
                "unexpected-acceptance"
                if result.returncode == 0
                else (
                    "certificate"
                    if b"certificate" in error
                    else (
                        "resolve"
                        if b"resolve" in error or b"translate host" in error
                        else (
                            "authentication"
                            if b"authentication failed" in error
                            else (
                                "container"
                                if result.returncode == 125
                                else "connection" if b"connect" in error else "unknown"
                            )
                        )
                    )
                )
            )
            raise ValueError(
                "database-"
                + role.replace("_", "-")
                + ("-current-" if accepted else "-rejected-")
                + kind
            )

    def database_rotation(self):
        self.op("close")
        fields = [
            ("identity_runtime", self.data["runtime"]["database"], "passwordFile"),
            ("identity_maintenance", self.data, "maintenancePasswordFile"),
            ("postgres", self.data, "ownerPasswordFile"),
        ]
        _, wrong = self.secret("wrong-database-password")
        for role, settings, field in fields:
            old = settings[field]
            self.database_probe(role, old, True)
            self.database_probe(role, wrong, False)
            value, path = self.secret("next-" + role + "-password")
            self.sql("ALTER ROLE " + role + " WITH PASSWORD '" + value + "';")
            self.database_probe(role, old, False)
            self.database_probe(role, path, True)
            settings[field] = path
        self.rejected_runtime_start()
        self.op("verify", reject=True)
        admin_file = self.write("db-rotation-admin-password", self.admin_password)
        self.op("recover", TENANTS[0], PRINCIPALS[0], admin_file, reject=True)
        self.render("new-database-passwords", self.data)
        self.op("verify")
        self.op("recover", TENANTS[0], PRINCIPALS[0], admin_file)
        self.op("open")
        self.browser("pg-ready")
        return {
            "roles": [role for role, _, _ in fields],
            "wrongAndRetiredPasswordsRejected": True,
            "newPasswordsAccepted": True,
        }

    def tls_rotation(self):
        self.op("close")
        old_public_ca = self.work / "public-ca.pem"
        ca, cert, key = self.cert("public-next", ["DNS:identity.example.test"])
        self.data.update(tlsCertificateFile=cert, tlsKeyFile=key)
        pg_ca, pg_cert, pg_key = self.cert("postgres-next", ["DNS:postgres"])
        self.data.update(postgresCertificateFile=pg_cert, postgresKeyFile=pg_key)
        self.render("rotated-tls-old-pg-ca", self.data)
        self.compose("up", "-d", "--wait", "--force-recreate", "postgres")
        self.rejected_runtime_start()
        self.data["runtime"]["database"]["caFile"] = pg_ca
        self.render("rotated-tls", self.data)
        self.op("open")
        import ssl, urllib.request, urllib.error

        try:
            urllib.request.urlopen(
                ORIGIN + "/api/identity-host/v1/config.json",
                context=ssl.create_default_context(cafile=str(old_public_ca)),
                timeout=10,
            )
        except (ssl.SSLError, urllib.error.URLError):
            pass
        else:
            raise ValueError("retired-public-ca-accepted")
        self.browser("pg-ready")
        return {"publicAndDatabaseTrustRotated": True, "retiredTrustRejected": True}

    def backup(self):
        self.browser("recovery-state")
        self.op("close")
        self.cut_a = self.snapshot()
        self.backup_a = self.work / "cut-a.dump"
        self.op("backup", self.backup_a)
        self.op("check-backup", self.backup_a)
        tampered = self.work / "tampered.dump"
        tampered.write_bytes(self.backup_a.read_bytes() + b"corrupt")
        tampered.with_suffix(".dump.json").write_bytes(
            self.backup_a.with_suffix(".dump.json").read_bytes()
        )
        self.op("check-backup", tampered, reject=True)
        return {
            "backupBytes": self.backup_a.stat().st_size,
            "dumpSha256": file_digest(self.backup_a),
            "receiptSha256": file_digest(self.backup_a.with_suffix(".dump.json")),
            "tamperRejected": True,
        }

    def restore_data(self, project, subnet, name, backup):
        data = copy.deepcopy(self.data)
        data["backendSubnet"] = subnet
        data["runtime"]["publicGateway"] = subnet.rsplit(".", 1)[0] + ".2"
        self.render(name, data, project)
        self.op("restore", backup, project=project)
        self.op("verify", project=project)
        self.op("verify-keys", project=project)
        operate.require_closed(project)

    def stale_backup(self):
        self.op("open")
        self.admin_password, path = self.secret("recovered-admin-password")
        self.op("recover", TENANTS[0], PRINCIPALS[0], path)
        self.op("close")
        self.cut_b = self.snapshot()
        require(
            self.cut_a["accounts"] != self.cut_b["accounts"]
            and len(self.cut_b["outbox"]) > len(self.cut_a["outbox"]),
            "post-cut-revocation",
        )
        self.restore_data(self.stale, self.subnets[1], "stale-restored", self.backup_a)
        require(self.snapshot(self.stale) == self.cut_a, "stale-cut-correspondence")
        operate.require_closed(self.stale)
        require(
            not {"identity", "gateway"}.intersection(
                self.compose(
                    "ps", "--status", "running", "--services", project=self.stale
                )
                .decode()
                .split()
            ),
            "stale-not-open",
        )
        return {"staleCutIdentified": True, "staleAuthorityRemainsClosed": True}

    def restore(self):
        self.backup_b = self.work / "cut-b.dump"
        self.op("backup", self.backup_b)
        self.op("check-backup", self.backup_b)
        # A live source must be rejected before touching target storage.
        data = copy.deepcopy(self.data)
        data["backendSubnet"] = self.subnets[2]
        data["runtime"]["publicGateway"] = self.subnets[2].rsplit(".", 1)[0] + ".2"
        self.render("current-restored", data, self.restored)
        self.op("open")
        self.op("restore", self.backup_b, project=self.restored, reject=True)
        self.op("close")
        started = time.monotonic()
        self.op("restore", self.backup_b, project=self.restored)
        self.op("verify-keys", project=self.restored)
        operate.require_closed(self.restored)
        restored = self.snapshot(self.restored)
        require(restored == self.cut_b, "restored-security-state")
        self.op("restore", self.backup_b, project=self.restored, reject=True)
        self.op("open", project=self.restored)
        self.browser("restored", recoveredAdminPassword=self.admin_password)
        self.record["measurements"].update(
            restoreSeconds=time.monotonic() - started,
            backupBytes=self.backup_b.stat().st_size,
            lostSecurityChanges=0,
        )
        self.source = self.restored
        return {
            "matchedSafetyCut": True,
            "datasetRows": {name: len(rows) for name, rows in restored.items()},
            "outboxSha256": digest(
                json.dumps(restored["outbox"], sort_keys=True).encode()
            ),
            "sourceAndTargetGuards": True,
            "operatorOpenedAfterVerification": True,
            "dumpSha256": file_digest(self.backup_b),
            "receiptSha256": file_digest(self.backup_b.with_suffix(".dump.json")),
        }

    def capacity(self):
        workload = self.config["subject"]["workload"]
        attempts = self.config["subject"]["policy"]["attempts"]
        # Only fixture workload is seeded. The production request performs the actual bounded cleanup.
        delay = float(
            self.sql(
                "SELECT coalesce(max(extract(epoch FROM expires_at-clock_timestamp())),0) FROM identity_authority.attempts WHERE tenant_id IN ('"
                + "','".join(TENANTS)
                + "') AND (key LIKE 's:%' OR (key='p:operator' AND count>="
                + str(attempts["scopeLimit"])
                + ")) AND expires_at>clock_timestamp();"
            )
        )
        if delay > 0:
            require(
                delay <= max(attempts["sourceSeconds"], attempts["scopeSeconds"]),
                "attempt-window-out-of-policy",
            )
            print("T3 capacity: waiting for existing attempt windows", flush=True)
            time.sleep(delay + 1)
        self.sql(
            "INSERT INTO identity_authority.attempts(tenant_id,key,count,expires_at) SELECT '"
            + TENANTS[0]
            + "'::uuid,'t3-expired-'||i,1,clock_timestamp()-interval '1 hour' FROM generate_series(1,"
            + str(workload["expiredAttempts"])
            + ") i;"
        )
        before = int(
            self.sql(
                "SELECT count(*) FROM identity_authority.attempts WHERE key LIKE 't3-expired-%';"
            )
        )
        ids = self.compose("ps", "--quiet").decode().split()

        def stats():
            return [
                json.loads(row)
                for row in docker(
                    "stats", "--no-stream", "--format", "{{json .}}", *ids
                )
                .decode()
                .splitlines()
            ]

        resources_before = stats()
        account_events = "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE envelope->>'contract'='identity.account.security';"
        event_count = int(self.sql(account_events))
        result = self.browser("capacity", recoveredAdminPassword=self.admin_password)
        resources_after = stats()
        committed_events = int(self.sql(account_events)) - event_count
        require(
            committed_events == result["counts"]["createdAccounts"],
            "capacity-durable-events",
        )
        after = int(
            self.sql(
                "SELECT count(*) FROM identity_authority.attempts WHERE key LIKE 't3-expired-%';"
            )
        )
        require(before > after, "cleanup-not-exercised")
        self.record["measurements"].update(result["measurements"])
        self.record["measurements"]["expiredAttemptsRemoved"] = before - after
        return {
            "datasetRows": {name: len(rows) for name, rows in self.snapshot().items()},
            "resourcesBefore": resources_before,
            "resourcesAfter": resources_after,
            "committedEvents": committed_events,
            "expiredAttemptsBefore": before,
            "expiredAttemptsAfter": after,
            "assertions": result["assertions"],
            **result["counts"],
        }

    def cleanup(self):
        remaining = []
        for project, directory in self.directories.items():
            try:
                self.compose(
                    "down",
                    "--volumes",
                    "--remove-orphans",
                    project=project,
                    directory=directory,
                )
                for command in [
                    ("ps", "--all", "--quiet"),
                    ("volume", "ls", "--quiet"),
                    ("network", "ls", "--quiet"),
                ]:
                    if docker(
                        *command,
                        "--filter",
                        "label=com.docker.compose.project=" + project,
                    ).strip():
                        remaining.append(project)
            except Exception:
                remaining.append(project)
        try:
            ids = (
                docker(
                    "ps",
                    "--all",
                    "--quiet",
                    "--filter",
                    "label=rss.identity.t3=" + self.prefix,
                )
                .decode()
                .split()
            )
            if ids:
                docker("rm", "-f", "-v", *ids)
            if docker(
                "ps",
                "--all",
                "--quiet",
                "--filter",
                "label=rss.identity.t3=" + self.prefix,
            ).strip():
                remaining.append("provider")
        except Exception:
            remaining.append("provider")
        self.record["cleanup"] = {
            "status": "failed" if remaining else "passed",
            "remaining": remaining,
        }

    def execute(self):
        try:
            for name, method, phase in SCENARIOS:
                action = getattr(self, method)
                self.step(name, lambda: action(phase) if phase else action())
        except BaseException as error:
            self.record["failure"] = failure_fact(
                error,
                (
                    self.record["steps"][-1]["name"]
                    if self.record["steps"]
                    else "preflight"
                ),
            )
            # Diagnostic detail remains private, and must never contain a request/response dump.
            self.write("failure-type", type(error).__name__ + ": " + str(error)[:300])
        finally:
            self.cleanup()
            self.record["result"] = (
                "measured" if self.record["targets"] is None else "passed"
            )
            if self.record["failure"] or self.record["cleanup"]["status"] != "passed":
                self.record["result"] = "failed"
            else:
                try:
                    verify_record(
                        self.record,
                        self.config["subject"],
                        (
                            self.config["baseline"].encode()
                            if self.config.get("baseline")
                            else None
                        ),
                    )
                except ValueError:
                    self.record["failure"] = {
                        "stage": "acceptance",
                        "reason": "incomplete-or-target-not-met",
                    }
                    self.record["result"] = "failed"
            save_evidence(self.output, self.record, self.secrets)
        return self.record["result"] != "failed"


def cleanup_operator(prefix, operator, volume):
    remaining = []
    # Stop the operator first: a killed docker-exec client can leave its child alive.
    # Do not let it create resources concurrently with the final sweep.
    try:
        ids = (
            docker("ps", "--all", "--quiet", "--filter", "name=^/" + operator + "$")
            .decode()
            .split()
        )
        if ids:
            docker("rm", "-f", "-v", *ids)
    except BaseException:
        remaining.append("operator")
    for label in [
        "com.docker.compose.project=" + prefix + suffix
        for suffix in ["-source", "-restored", "-stale"]
    ] + ["rss.identity.t3=" + prefix]:
        try:
            ids = (
                docker("ps", "--all", "--quiet", "--filter", "label=" + label)
                .decode()
                .split()
            )
            if ids:
                docker("rm", "-f", "-v", *ids)
            for resource in ["volume", "network"]:
                ids = (
                    docker(resource, "ls", "--quiet", "--filter", "label=" + label)
                    .decode()
                    .split()
                )
                if ids:
                    docker(resource, "rm", *ids)
            require(
                not docker(
                    "ps", "--all", "--quiet", "--filter", "label=" + label
                ).strip(),
                "cleanup-container-remains",
            )
            for resource in ["volume", "network"]:
                require(
                    not docker(
                        resource, "ls", "--quiet", "--filter", "label=" + label
                    ).strip(),
                    "cleanup-resource-remains",
                )
        except BaseException:
            remaining.append(label)
    return remaining


def outside(args):
    require(
        args.record.is_absolute() and not args.record.exists(),
        "fresh-absolute-record-required",
    )
    prefix = "identity-t3-" + secrets.token_hex(5)
    volume, operator = prefix + "-private", prefix + "-operator"
    report = new_record({}, None)
    save(args.record, report)
    phase = "preflight"
    try:
        details, tool, subject, targets, baseline = candidate(args, prefix)
        approval = verify_approval(targets, subject["pullRequest"]) if targets else None
        report = new_record(subject, targets)
        report["approval"] = approval
        save(args.record, report)
        phase = "operator"
        docker("volume", "create", "--label", "rss.identity.t3=" + prefix, volume)
        mount = json.loads(docker("volume", "inspect", volume))[0]["Mountpoint"]
        docker(
            "run",
            "-d",
            "--pull=never",
            "--name",
            operator,
            "--add-host",
            "identity.example.test:"
            + json.loads(docker("network", "inspect", "bridge"))[0]["IPAM"]["Config"][
                0
            ]["Gateway"],
            "--mount",
            f"type=volume,source={volume},target={mount}",
            "--mount",
            "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
            "--entrypoint",
            "sleep",
            tool["Id"],
            "infinity",
        )
        archive = process(
            [
                "/usr/bin/git",
                "-C",
                str(ROOT),
                "archive",
                "HEAD",
                "hack",
                "deployment",
                "crates/identity-postgres/src/schema-signature.sha256",
                "crates/identity-postgres/src/security-event-v3.json",
            ]
        )
        docker("exec", operator, "mkdir", "-p", mount + "/source")
        docker(
            "exec",
            "-i",
            operator,
            "tar",
            "xf",
            "-",
            "-C",
            mount + "/source",
            input=archive,
        )
        config = {
            "work": mount + "/work",
            "output": mount + "/result.json",
            "prefix": prefix,
            "subject": subject,
            "targets": targets,
            "approval": approval,
            "baseline": baseline.decode() if baseline else None,
            "images": {k: v["Id"] for k, v in details.items()},
        }
        docker(
            "exec",
            "-i",
            operator,
            "python3",
            "-c",
            "import sys,pathlib; p=pathlib.Path(sys.argv[1]);p.write_bytes(sys.stdin.buffer.read());p.chmod(0o600)",
            mount + "/input.json",
            input=json.dumps(config).encode(),
        )
        # The child emits only closed phase/status diagnostics, never protocol values.
        status = bounded_run(
            [
                "docker",
                "exec",
                operator,
                "python3",
                mount + "/source/hack/reference_t3.py",
                "--inside",
                mount + "/input.json",
            ],
            timeout=5400,
        )
        raw = docker("exec", operator, "cat", mount + "/result.json")
        returned = json.loads(raw)
        require(
            returned.get("failure", {})
            != {"stage": "redaction", "reason": "secret-in-evidence"},
            "secret-in-evidence",
        )
        require(returned["subject"] == subject, "returned-subject-mismatch")
        report = returned
        if status.returncode and not report["failure"]:
            raise ProcessFailure("operator", status.returncode)
    except BaseException as error:
        report["failure"] = failure_fact(error, phase)
    finally:
        # A copied child result is provisional until its operator and private volume are gone.
        try:
            remaining = cleanup_operator(prefix, operator, volume)
        except BaseException as error:
            if report["failure"] is None:
                report["failure"] = failure_fact(error, "cleanup")
            remaining = ["operator-workspace"]
        report["cleanup"] = {
            "status": "failed" if remaining else "passed",
            "remaining": remaining,
        }
        if report["failure"] or report["cleanup"]["status"] != "passed":
            report["result"] = "failed"
        else:
            try:
                verify_record(report, subject, baseline)
                require(report["approval"] == approval, "returned-approval-mismatch")
                if targets:
                    require(
                        verify_approval(targets, subject["pullRequest"]) == approval,
                        "approval-changed",
                    )
            except BaseException as error:
                report["failure"] = failure_fact(error, "finalize")
                report["result"] = "failed"
        save(args.record, report)
    if report["result"] == "failed":
        print(
            "T3 failed: "
            + (report["failure"] or {"reason": "cleanup-unconfirmed"})["reason"],
            file=sys.stderr,
        )
    return report["result"] in ["measured", "passed"]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--inside", type=Path)
    p.add_argument("--identity-image")
    p.add_argument("--web-image")
    p.add_argument("--tools-image")
    p.add_argument("--web-repo", type=Path)
    p.add_argument("--record", type=Path)
    p.add_argument("--targets", type=Path)
    p.add_argument("--baseline", type=Path)
    p.add_argument("--pull-request", type=int)
    args = p.parse_args()

    def interrupted(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.inside:
            result = Run(json.loads(args.inside.read_text())).execute()
        else:
            require(
                all(
                    [
                        args.identity_image,
                        args.web_image,
                        args.tools_image,
                        args.web_repo,
                        args.record,
                        args.pull_request,
                    ]
                ),
                "required-inputs",
            )
            result = outside(args)
    except BaseException as error:
        if args.record and args.record.is_absolute() and not args.record.exists():
            record = new_record({}, None)
            record.update(
                result="failed",
                failure=failure_fact(error, "preflight-or-operator"),
                cleanup={"status": "unconfirmed", "remaining": []},
            )
            save(args.record, record)
        print(
            "T3 preflight/operator failed; inspect the redacted record", file=sys.stderr
        )
        result = False
    raise SystemExit(0 if result else 1)


if __name__ == "__main__":
    main()
