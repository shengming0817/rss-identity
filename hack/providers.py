#!/usr/bin/env python3
"""Isolated T2 providers. Loopback HTTP/plaintext is fixture-only, never production config."""
import contextlib
import json
import os
import re
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import uuid
from bounded_process import run as bounded_run

ROOT = Path(__file__).resolve().parent.parent
PG = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929"
KEYCLOAK = "quay.io/keycloak/keycloak:26.7.3@sha256:ff4257d0d64efbe99ed1ddfaf07765cc3c36dc7518bf8324d41961327f441c54"
HYDRA = "oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9"

def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, stderr=subprocess.PIPE, timeout=180).strip()

@contextlib.contextmanager
def container(image, ports, env=(), args=(), mounts=()):
    name = "identity-t2-" + uuid.uuid4().hex
    command = ["run", "-d", "--name", name]
    for port in ports:
        host = ports[port] if isinstance(ports, dict) else ""
        command += ["-p", f"127.0.0.1:{host}:{port}"]
    for key, value in env:
        command += ["-e", f"{key}={value}"]
    for mount in mounts:
        command += ["-v", mount]
    failure = None
    try:
        cid = docker(*command, image, *args)
        mapped = {p: int(docker("port", cid, str(p)).rsplit(":", 1)[1]) for p in ports}
        yield cid, mapped
    except BaseException as error:
        failure = error
        raise
    finally:
        if failure is not None:
            diagnostics(name, image, failure)
        try:
            # Named before startup so even a timed-out run has a cleanup identity.
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, timeout=30, check=True)
        except (subprocess.SubprocessError, OSError) as cleanup_error:
            if failure is None:
                raise RuntimeError(f"fixture cleanup failed: {name}") from cleanup_error
            print(f"fixture cleanup also failed: {name}: {type(cleanup_error).__name__}", file=sys.stderr)

def diagnostics(name, image, failure):
    # Never print raw logs/state/error text: providers can log credentials in arbitrary formats.
    print(f'provider={image.split("@")[0]} failure={type(failure).__name__}', file=sys.stderr)
    for args in [('inspect', '--format', '{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}', name),
                 ('logs', '--tail', '30', name)]:
        try:
            result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=10, check=True)
            if args[0] == 'inspect':
                value = result.stdout.strip()
                safe = value if re.fullmatch(r'(created|running|paused|restarting|removing|exited|dead) [0-9]+ (true|false)', value) else 'unrecognized state'
                print(f'container state: {safe}', file=sys.stderr)
            else:
                lines = (result.stdout + result.stderr)[-8192:].splitlines()[-30:]
                counts = {level: sum(bool(re.search(r'\b' + level + r'\b', line, re.I)) for line in lines) for level in ['error', 'warn', 'fatal']}
                print(f'log tail (content withheld): lines={len(lines)} severity_counts={counts}', file=sys.stderr)
        except (subprocess.SubprocessError, OSError):
            print(f'{args[0]} diagnostics unavailable', file=sys.stderr)

def wait(url):
    deadline = time.monotonic() + 120
    last = 'no response'
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200: return
                last = f'HTTP {r.status}'
        except urllib.error.HTTPError as error:
            last = f'HTTP {error.code}'
        except (OSError, urllib.error.URLError) as error:
            last = type(error).__name__
        time.sleep(0.5)
    raise RuntimeError(f'provider readiness timed out: {last}')

def report_tests(package, test, expected, result):
    # Only canonical names and closed statuses cross the diagnostic boundary.
    statuses = re.findall(r'^test ([a-zA-Z0-9_:]+) \.\.\. (ok|FAILED|ignored)$', result.stdout, re.M)
    for name, status in statuses:
        if name in expected:
            print(f'{package}/{test}: {name}: {status}')
    print(f'{package}/{test}: cargo exit={result.returncode}; raw output withheld')

def cargo(package, test, env, features=()):
    expected = {('rss-identity-http-axum','ui_host'): {'real_identity_ui_management_seam'},('rss-identity-http-axum','management_http'): {'management_accounts_sessions_and_boundaries','management_provider_operations_safe_and_scoped','callback_cancellation_consumes_only_bound_attempts','management_rechecks_inflight_provider_authority'},('rss-identity-postgres','downstream_atomic'): {'downstream_prepare_admission_precedes_invalid_protocol_work','downstream_cleanup_failure_concurrency_and_unknown_settlement','downstream_cleanup_claim_rollback_and_final_unknown','downstream_readonly_rotation_and_revocation','downstream_unknown_commit_and_single_accept','downstream_remote_unknown_never_returns_authority','downstream_accept_rechecks_revocation_and_final_commit','downstream_claim_and_event_roll_back_together','downstream_federated_provider_revocation','downstream_prepare_budget_is_per_client_and_releases_expired'}, ('rss-identity-http-axum','downstream_http'): {'real_downstream_code_pkce_and_online_validation','downstream_body_deadline_and_caller_auth'}, ('rss-identity-http-axum','federated_http'): {'real_provider_management_and_missing_secret','real_federated_login_and_linking','federated_http_rejects_mismatch_and_uncertain_commit','federated_tls_and_egress_policy'}, ('rss-identity-postgres','federated_atomic'): {'federation_concurrent_linking_keeps_one_owner','federation_configuration_authorization_and_versions','federation_state_restart_expiry_and_replay','federation_jit_isolated_subjects_and_membership','federation_config_races_and_provider_revocation','federation_atomic_events_and_unknown_commit','federation_local_and_federated_linking','federation_link_conflict_logout_and_wrong_reauthentication','federation_concurrent_jit_rls_and_schema_drift'}, ('rss-identity-postgres', 'atomic'): {'initialization_and_recovery', 'account_races_and_isolation', 'attempts_are_shared_and_bounded', 'settlement_never_releases_uncertain_success', 'storage_contract_is_checked', 'source_budgets_are_shared', 'maintenance_races_preserve_current_state', 'maintenance_runbook_respects_forced_rls', 'maintenance_permissions_and_schema_are_exact', 'maintenance_deadline_fencing_and_overflow', 'fencing_and_generation_overflow', 'account_transition_matrix_and_events'},
                ('rss-identity-postgres', 'session_atomic'): {'session_rotation_and_revocation', 'session_isolation_replacement_and_restart', 'session_account_changes_fence_racing_credentials', 'session_settlement_and_event_failure_are_atomic', 'session_expiry_deadline_permissions_and_overflow', 'session_logout_rotation_races_and_invalid_storage', 'session_events_match_committed_operations'},
                ('rss-identity-http-axum', 'session_http'): {'session_http_login_cookie_csrf_and_replacement', 'session_http_settlement_never_sets_uncertain_cookie', 'session_http_origin_expiry_and_transport_boundaries', 'session_http_recovery_current_logout_and_deadline', 'session_http_lookup_never_inserts_tenant_guard', 'session_http_pending_commit_preserves_settlement'},
                ('rss-identity-admin', 'operator'): {'maintenance_file_and_settlement'},
                ('rss-identity-oidc', 'provider'): {'real_provider_flows'}}[(package, test)]
    command = ['cargo', 'test', '--locked', '-p', package, '--test', test, *features, '--', '--ignored', '--test-threads=1']
    environment = {**os.environ, **env, 'CARGO_TARGET_DIR': str(ROOT / 'target')}
    listing = bounded_run([*command, '--list'], timeout=900, cwd=ROOT, env=environment, check=True, text=True, stdout=subprocess.PIPE).stdout
    names = re.findall(r'^(.+): test$', listing, re.M)
    if set(names) != expected or len(names) != len(expected):
        raise RuntimeError(f'{package}/{test}: canonical test set missing or changed')
    completed = bounded_run([*command, '--nocapture', '--format', 'pretty'], timeout=max(300 if test == 'ui_host' else 180,len(expected)*180), cwd=ROOT, env=environment, text=True, capture_output=True)
    result = completed.stdout
    report_tests(package, test, expected, completed)
    if completed.returncode:
        raise RuntimeError(f'{package}/{test}: cargo exit={completed.returncode}')
    counts = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', result, re.M)
    executed = re.findall(r'^test (.+) \.\.\. ok$', result, re.M)
    if counts != [(str(len(expected)), '0', '0', '0', '0')] or set(executed) != expected or len(executed) != len(expected):
        raise RuntimeError(f'{package}/{test}: canonical test execution incomplete')

@contextlib.contextmanager
def postgres():
    with container(PG, [5432], [("POSTGRES_PASSWORD", "fixture-only")]) as (cid, ports):
        for _ in range(120):
            p = subprocess.run(["docker", "exec", cid, "pg_isready", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if p.returncode == 0: break
            time.sleep(0.5)
        else: raise RuntimeError(f"PostgreSQL readiness timed out: pg_isready exit={p.returncode}")
        yield cid, ports

def pg():
    with postgres() as (_, ports):
        env = {"IDENTITY_TEST_PG_PORT": str(ports[5432])}
        cargo("rss-identity-postgres", "federated_atomic", env)
        cargo("rss-identity-postgres", "atomic", env)
        cargo("rss-identity-postgres", "session_atomic", env)
        cargo("rss-identity-http-axum", "session_http", env)
        cargo("rss-identity-http-axum", "management_http", env)
        cargo("rss-identity-admin", "operator", env)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def oidc():
    realm = {"realm": "identity", "enabled": True, "sslRequired": "none",
             "clients": [{"clientId": "identity-test", "secret": "fixture-secret", "publicClient": False,
                          "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                          "redirectUris": ["http://127.0.0.1:19999/auth/callback"],
                          "attributes": {"pkce.code.challenge.method": "S256"}}],
             "users": [{"username": "alice", "enabled": True, "email": "alice@example.test", "emailVerified": True,
                        "firstName": "Alice", "lastName": "Fixture",
                        "credentials": [{"type": "password", "value": "fixture-password", "temporary": False}]}]}
    with tempfile.TemporaryDirectory(prefix="identity-oidc-") as tmp, contextlib.ExitStack() as stack:
        realm_file = Path(tmp) / "identity-realm.json"
        realm_file.write_text(json.dumps(realm))
        _, kc_ports = stack.enter_context(container(KEYCLOAK, [8080], args=["start-dev", "--import-realm"], mounts=[f"{realm_file}:/opt/keycloak/data/import/identity-realm.json:ro"]))
        kc = f"http://127.0.0.1:{kc_ports[8080]}/realms/identity"
        wait(kc + "/.well-known/openid-configuration")
        cargo("rss-identity-oidc", "provider", {"IDENTITY_TEST_KEYCLOAK_ISSUER": kc}, ["--features", "test-support"])

def federated():
    realm = {"realm":"identity", "enabled":True, "sslRequired":"all", "duplicateEmailsAllowed":True,
             "loginWithEmailAllowed":False,
             "groups":[{"name":"staff"}],
             "clients":[{"clientId":"identity-test", "secret":"fixture-secret", "publicClient":False,
                         "standardFlowEnabled":True, "directAccessGrantsEnabled":False,
                         "redirectUris":["https://identity.example.test/api/v1/oidc/callback"],
                         "attributes":{"pkce.code.challenge.method":"S256"},
                         "protocolMappers":[{"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper",
                         "config":{"claim.name":"groups","full.path":"false","id.token.claim":"true","access.token.claim":"false"}}]}],
             "users":[{"username":name,"enabled":True,"email":"same@example.test","emailVerified":True,
                       "firstName":name,"lastName":"Fixture","groups":["staff"],
                       "credentials":[{"type":"password","value":"fixture-password","temporary":False}]} for name in ["alice","bob"]]}
    with tempfile.TemporaryDirectory(prefix="identity-federated-") as tmp, contextlib.ExitStack() as stack:
        tmp=Path(tmp);cert=tmp/"tls.crt";key=tmp/"tls.key";realm_file=tmp/"identity-realm.json"
        realm_file.write_text(json.dumps(realm))
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-days","2",
                        "-subj","/CN=identity-t2", "-addext","basicConstraints=critical,CA:FALSE","-addext","keyUsage=critical,digitalSignature,keyEncipherment","-addext","extendedKeyUsage=serverAuth","-addext","subjectAltName=IP:127.0.0.1,DNS:localhost"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        key.chmod(0o644)  # Synthetic disposable fixture key readable by the container's unprivileged uid.
        port=free_port();origin=f"https://127.0.0.1:{port}";issuer=origin+"/realms/identity"
        stack.enter_context(container(KEYCLOAK,{8443:port},args=["start-dev","--import-realm","--http-enabled=false",f"--hostname={origin}",
            "--https-certificate-file=/opt/keycloak/conf/tls.crt","--https-certificate-key-file=/opt/keycloak/conf/tls.key"],
            mounts=[f"{realm_file}:/opt/keycloak/data/import/identity-realm.json:ro",f"{cert}:/opt/keycloak/conf/tls.crt:ro",f"{key}:/opt/keycloak/conf/tls.key:ro"]))
        context=ssl.create_default_context(cafile=str(cert));deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            try:
                with urllib.request.urlopen(issuer+"/.well-known/openid-configuration",context=context,timeout=2) as response:
                    if response.status==200:break
            except (OSError,urllib.error.URLError):time.sleep(.5)
        else:raise RuntimeError("Keycloak TLS readiness timed out")
        _,ports=stack.enter_context(postgres())
        cargo("rss-identity-http-axum","federated_http",{"IDENTITY_TEST_PG_PORT":str(ports[5432]),"IDENTITY_TEST_FEDERATED_ISSUER":issuer,"IDENTITY_TEST_FEDERATED_CA":str(cert)})

if __name__ == "__main__":
    if sys.argv[1:] == ["pg"]: pg()
    elif sys.argv[1:] == ["oidc"]: oidc()
    elif sys.argv[1:] == ["federated"]: federated()
    else: raise SystemExit("usage: providers.py pg|oidc|federated")
