"""The ordered T31 join hazards; assertions use the candidate's real boundaries."""
import json
import os
import signal
import subprocess
import time

from fixture import eventually
from run import Failure, require


def install(f, observed):
    f.compose("run", "--rm", "--no-deps", "volume-init")
    f.up("postgres")
    eventually(lambda: f.compose("exec", "-T", "postgres", "pg_isready", "-U", "postgres", check=False).returncode == 0)
    described = json.loads(f.compose("run", "--rm", "migrate", "--describe").stdout)
    require(described == f.candidate["migrations"], "embedded_migrations")
    f.compose("run", "--rm", "migrate", timeout=120)
    require(f.sql("SELECT version FROM identity_authority.schema_version;") == "7", "installed_schema")
    f.compose("run", "--rm", "hydra-migrate", timeout=120)
    f.up("hydra", "hydra-admin", "keycloak")
    f.compose("run", "--rm", "hydra-clients", timeout=180)
    f.compose("run", "--rm", "--volume", f.mount + "/input/admin-password:/run/input/new-password:ro",
              "maintenance", "initialize", f.info["principal"], "t31-admin", "/run/input/new-password", timeout=60)
    f.initial = snapshot(f)
    observed.update(schema=7, migrations=described, initial=f.initial)


def snapshot(f):
    return json.loads(f.sql("SELECT json_build_object('deployment', (SELECT row_to_json(d) FROM identity_authority.deployment d), 'storage', (SELECT row_to_json(s) FROM rss_transactional_messaging.storage_lineage s), 'outbox_count', (SELECT count(*) FROM rss_transactional_messaging.outbox), 'outbox_max', (SELECT coalesce(max(seq),0) FROM rss_transactional_messaging.outbox));"))


def healthy(f, observed):
    f.up("identity")
    f.ready()
    f.up("public-gateway", "private-gateway")
    f.connect_helper()
    published = eventually(lambda: f.published(), code="published_gateway_unavailable")
    require(published["status"] == 200 and published["json"] == {"revision": f.candidate["ui"]["revision"]}, "published_ui_identity")
    observed["published_https"] = 200
    eventually(lambda: f.http("/realms/identity/.well-known/openid-configuration", host="sso.t31.test")["status"] == 200,
               timeout=600, code="keycloak_discovery")
    f.login()
    observed["local_login"] = 200
    observed["identity"] = f.state("identity")
    response = validate(f)
    require(response["status"] == 401, "healthy_invalid_credential")
    observed["invalid_credential"] = response["status"]
    settings = {"issuer": "https://sso.t31.test/realms/identity", "client_id": "identity-rp",
                "secret_ref": "identity-rp@1", "jit": False,
                "redirect_uri": "https://identity.t31.test/api/v1/oidc/callback",
                "scopes": ["openid", "email", "profile"], "claims": {"email": "email", "groups": None}}
    response = f.http(base(f) + "/providers", method="POST", body=settings, session=True)
    require(response["status"] == 201, "provider_fixture")
    f.provider = response["json"]["id"]
    response = provider_test(f)
    require(response["status"] == 200 and response["json"]["passed"] is True, "provider_baseline")
    observed["provider_passed"] = True


def base(f):
    return "/api/v1/tenants/" + f.info["tenant"]


def validate(f):
    return f.http("/internal/v1/identity/validate", method="POST", private=True,
                  body={"tenant_id": f.info["tenant"], "audience": "mdm", "credential": "t31-invalid-opaque-credential"})


def provider_test(f):
    return f.http(base(f) + "/providers/" + f.provider + "/test", method="POST", session=True)


def cold_dependencies(f, observed):
    for dependency in ("postgres", "hydra", "keycloak"):
        f.compose("stop", "--timeout", "40", "public-gateway", "private-gateway", "identity", timeout=90)
        if dependency == "hydra":
            # Keep the process unavailable while Compose tries the real dependency graph.
            # A stopped provider would simply be restarted by `up gateway`.
            f.compose("pause", "hydra")
        else:
            f.compose("stop", "--timeout", "40", dependency, timeout=90)
        if dependency == "postgres":
            result = f.compose("run", "--rm", "--no-deps", "identity", check=False, timeout=90)
            require(result.returncode == 1, "cold_pg_must_reject_start")
            observed[dependency] = {"exit_code": result.returncode}
        else:
            f.compose("up", "-d", "--no-deps", "--pull", "never", "identity")
            eventually(lambda: live(f) == 200, code="cold_process_not_live")
            if dependency == "hydra":
                require(not f.probe(), "cold_hydra_must_not_be_ready")
                attempt = f.compose("up", "-d", "--pull", "never", "public-gateway", "private-gateway", check=False, timeout=100)
                require(attempt.returncode != 0 and "unhealthy" in attempt.stderr
                        and f.project + "-identity" in attempt.stderr, "cold_gateway_health_gate_bypassed")
                for gateway in ("public-gateway", "private-gateway"):
                    require(f.state(gateway)["status"] in ("created", "exited"), "cold_gateway_open")
                require(not f.public_port_open(), "cold_gateway_published_port")
                observed[dependency] = {"live": 200, "ready": False, "gateway_start_exit": attempt.returncode, "gateway_open": False}
                f.compose("unpause", "hydra")
            else:
                f.ready()
                f.up("public-gateway", "private-gateway")
                response = provider_test(f)
                require(response["status"] == 200 and response["json"]["passed"] is False, "cold_keycloak_provider_result")
                observed[dependency] = {"ready": True, "provider_passed": False}
        restore(f, dependency)
        f.up("identity")
        f.ready()
        f.up("public-gateway", "private-gateway")
        eventually(lambda: provider_test(f)["json"]["passed"] is True, timeout=300, code="cold_recovery")


def live(f):
    return int(f.helper_python("import http.client,json,sys; c=http.client.HTTPConnection(json.load(sys.stdin),8080,timeout=3); c.request('GET','/livez'); print(c.getresponse().status); c.close()",
                               f.info["backend_ip"], timeout=5).strip())


def restore(f, dependency):
    if dependency == "hydra":
        # These two containers share one network namespace; recreate the pair together.
        f.compose("up", "-d", "--force-recreate", "--pull", "never", "hydra", "hydra-admin", timeout=180)
    else:
        f.up(dependency)
    if dependency == "postgres":
        eventually(lambda: f.compose("exec", "-T", "postgres", "pg_isready", "-U", "postgres", check=False).returncode == 0)


def local_session(f):
    return f.http(base(f) + "/session", session=True)["status"]


def running_dependencies(f, observed):
    for dependency in ("postgres", "hydra", "keycloak"):
        before = f.state("identity")
        stopped = ("hydra-admin", "hydra") if dependency == "hydra" else (dependency,)
        f.compose("stop", "--timeout", "40", *stopped, timeout=90)
        require(live(f) == 200, "running_process_liveness")
        if dependency == "postgres":
            require(not f.probe() and local_session(f) == 503, "pg_outage_fail_closed")
            observed[dependency] = {"ready": False, "session": 503}
        elif dependency == "hydra":
            require(not f.probe(), "hydra_outage_readiness")
            response = validate(f)
            require(response["status"] == 503 and response["json"]["code"] == "identity_unavailable", "hydra_outage_validation")
            f.login()
            observed[dependency] = {"ready": False, "validation": response["json"]["code"], "local_login": 200}
        else:
            f.ready()
            response = provider_test(f)
            require(response["status"] == 200 and response["json"]["passed"] is False, "keycloak_outage_result")
            f.login()
            observed[dependency] = {"ready": True, "provider_passed": False, "local_login": 200}
        require(f.state("identity")["started"] == before["started"], "outage_restarted_identity")
        restore(f, dependency)
        f.ready()
        eventually(lambda: provider_test(f)["json"]["passed"] is True, timeout=300, code="provider_recovery")
        require(validate(f)["status"] == 401 and local_session(f) == 200, "dependency_recovery")
        observed[dependency]["recovered"] = True


def partial_start(f, observed):
    f.compose("stop", "--timeout", "40", "identity", timeout=60)
    eventually(lambda: f.sql("SELECT count(*) FROM pg_stat_activity WHERE usename='identity_runtime';") == "0")
    path = variant(f, "runtime", {"listen": "192.0.2.1:8080"})
    begin = time.monotonic()
    result = f.compose("run", "--rm", "--no-deps", "--volume", path + ":/run/config/runtime.json:ro", "identity", check=False, timeout=40)
    require(result.returncode == 1 and time.monotonic() - begin < 30, "partial_start_exit")
    eventually(lambda: f.sql("SELECT count(*) FROM pg_stat_activity WHERE usename='identity_runtime';") == "0", timeout=10,
               code="partial_start_pool_leak")
    observed.update(exit_code=result.returncode, runtime_connections=0)
    f.up("identity")
    f.ready()


def variant(f, kind, updates):
    path = f.mount + "/" + kind + "-fault.json"
    f.helper_python("import json,pathlib,sys,os; d=json.load(sys.stdin); v=json.loads(pathlib.Path(d['source']).read_text()); v.update(d['updates']); p=pathlib.Path(d['target']); p.write_text(json.dumps(v)); p.chmod(0o600); os.chown(p,10001,10001)",
                    {"source": f.mount + "/rendered/" + kind + ".json", "target": path, "updates": updates})
    return path


def clean_drain(f, observed):
    drain(f, observed, release=True)


def timeout_drain(f, observed):
    drain(f, observed, release=False)


def drain(f, observed, *, release):
    # A retained psql transaction, rather than a timer, controls the actual SQL wait.
    compose = ["docker", "compose", "-p", f.project, "-f", str(f.compose_file)]
    lock = subprocess.Popen([*compose, "exec", "-T", "postgres", "psql", "-X", "-A", "-t", "-U", "postgres", "-d", "identity", "-v", "ON_ERROR_STOP=1"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    request = stop = None
    try:
        lock.stdin.write("SET application_name='identity_t31_lock'; BEGIN; LOCK TABLE identity_authority.attempts IN ACCESS EXCLUSIVE MODE;\n")
        lock.stdin.flush()
        held = "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name='identity_t31_lock' AND l.relation='identity_authority.attempts'::regclass AND l.mode='AccessExclusiveLock' AND l.granted;"
        eventually(lambda: lock.poll() is None and f.sql(held) == "1", timeout=5, code="lock_acquisition_timeout")
        data = {"ca": f.mount + "/input/ca.pem", "address": f.info["public_ip"], "port": 443,
                "path": base(f) + "/login", "method": "POST", "timeout": 35,
                "headers": {"Origin": "https://identity.t31.test", "X-Identity-Request": "1", "Content-Type": "application/json"},
                "body": {"login": "t31-missing-" + str(int(release)), "password": "t31-synthetic-missing-password"}}
        request = subprocess.Popen(["docker", "exec", "-i", f.helper, "python3", "/fixture.py", "http"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        request.stdin.write(json.dumps(data))
        request.stdin.close()
        request.stdin = None
        waiters = "SELECT count(*) FROM pg_stat_activity WHERE usename='identity_runtime' AND wait_event_type='Lock' AND query LIKE '%identity_authority.attempts%';"
        eventually(lambda: f.sql(waiters) == "1", timeout=5, code="request_not_waiting_in_pg")
        begin = time.monotonic()
        stop = subprocess.Popen(["docker", "stop", "--signal", "SIGTERM", "--timeout", "40", f.cid("identity")],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        statuses = []
        def admission_closed():
            status = f.http(base(f) + "/session", session=True, timeout=3)["status"]
            statuses.append(status)
            return status in (502, 503)
        eventually(admission_closed, timeout=5, code="admission_did_not_close")
        # The listener may already have stopped accepting connections (gateway 502),
        # or an existing connection can reach the closed admission gate (503).
        rejected = f.http(base(f) + "/login", method="POST", body=data["body"], timeout=3)
        require(rejected["status"] in (502, 503) and f.sql(waiters) == "1", "shutdown_admitted_new_work")
        observed.update(admission_probe_statuses=statuses, rejected_status=rejected["status"])
        if release:
            lock.stdin.write("ROLLBACK;\n\\q\n")
            lock.stdin.flush()
            response, _ = request.communicate(timeout=12)
            require(request.returncode == 0 and json.loads(response)["status"] == 401, "drained_request_result")
        stop.communicate(timeout=30)
        elapsed = time.monotonic() - begin
        state = f.state("identity")
        require(state["status"] == "exited" and state["exit_code"] == (0 if release else 1)
                and not state["oom"] and elapsed < 30 and (release or elapsed >= 7), "product_drain_outcome")
        observed.update(exit_code=state["exit_code"], elapsed_seconds=round(elapsed, 3),
                        new_admission=False, external_grace_seconds=40, resource_seconds=8, drain_seconds=25)
    finally:
        if lock.poll() is None:
            try:
                lock.communicate("ROLLBACK;\n\\q\n", timeout=5)
            except (subprocess.TimeoutExpired, BrokenPipeError):
                lock.kill()
                lock.communicate(timeout=5)
        for process in (lock, request, stop):
            if process:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.communicate(timeout=5)
    f.up("identity")
    f.ready()


def persistent_restart(f, observed):
    before = snapshot(f)
    f.compose("stop", "--timeout", "40", timeout=180)
    f.up("postgres")
    f.compose("run", "--rm", "migrate", timeout=120)
    f.up("hydra", "hydra-admin", "keycloak")
    f.compose("run", "--rm", "hydra-clients", timeout=180)
    f.up("identity")
    f.ready()
    f.up("public-gateway", "private-gateway")
    eventually(lambda: provider_test(f)["json"]["passed"] is True, timeout=300, code="restart_provider")
    after = snapshot(f)
    require(before["deployment"] == after["deployment"] == f.initial["deployment"]
            and before["storage"] == after["storage"] == f.initial["storage"], "restart_changed_identity")
    retained = int(f.sql("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE seq <= " + str(f.initial["outbox_max"]) + ";"))
    require(retained == f.initial["outbox_count"] and retained > 0, "restart_lost_outbox")
    require(local_session(f) == 200, "restart_lost_session")
    repeated = f.compose("run", "--rm", "--volume", f.mount + "/input/admin-password:/run/input/new-password:ro",
                         "maintenance", "initialize", f.info["principal"], "t31-admin", "/run/input/new-password", check=False)
    require(repeated.returncode == 1, "restart_reinitialized_authority")
    observed.update(deployment_unchanged=True, storage_unchanged=True, retained_outbox=retained,
                    session=200, repeated_initialize=repeated.returncode)


def mismatch(f, observed):
    f.compose("stop", "--timeout", "40", "identity", timeout=60)
    f.sql("DELETE FROM identity_authority.schema_version;")
    for service in ("migrate", "identity"):
        result = f.compose("run", "--rm", "--no-deps", service, check=False, timeout=90)
        require(result.returncode == 1, "missing_schema_version_accepted")
    require(f.sql("SELECT count(*) FROM identity_authority.schema_version;") == "0", "schema_auto_repaired")
    f.sql("INSERT INTO identity_authority.schema_version VALUES(7);")
    identity = dict(f.initial["deployment"])
    # The stored column and public configuration use distinct names.
    wrong = {"environment_id": identity["environment_id"], "config_version": 2,
             "identity_public_origin": identity["identity_public_origin"], "product_public_origin": identity["product_public_origin"]}
    for service, kind in (("migrate", "migration"), ("identity", "runtime")):
        path = variant(f, kind, {"identity_origin": wrong})
        result = f.compose("run", "--rm", "--no-deps", "--volume", path + ":/run/config/" + kind + ".json:ro", service,
                           check=False, timeout=90)
        require(result.returncode == 1, "wrong_identity_version_accepted")
    require(snapshot(f)["deployment"] == f.initial["deployment"], "identity_auto_repaired")
    f.compose("run", "--rm", "migrate", timeout=120)
    f.up("identity")
    f.ready()
    observed.update(schema_mismatch_rejected=True, identity_mismatch_rejected=True, automatic_repair=False, recovered=True)
