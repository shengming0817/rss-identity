#!/usr/bin/env python3
"""Isolated T2 providers. Loopback HTTP/plaintext is fixture-only, never production config."""
import contextlib
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import uuid

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

def cargo(package, test, env, features=()):
    expected = {('rss-identity-postgres', 'atomic'): {'initialization_and_recovery', 'account_races_and_isolation', 'attempts_are_shared_and_bounded', 'settlement_never_releases_uncertain_success', 'storage_contract_is_checked', 'source_budgets_are_shared', 'maintenance_races_preserve_current_state', 'maintenance_runbook_respects_forced_rls', 'maintenance_permissions_and_schema_are_exact', 'maintenance_deadline_fencing_and_overflow', 'fencing_and_generation_overflow', 'account_transition_matrix_and_events'},
                ('rss-identity-admin', 'operator'): {'maintenance_file_and_settlement'},
                ('rss-identity-oidc', 'provider'): {'real_provider_flows'}}[(package, test)]
    command = ['cargo', 'test', '--locked', '-p', package, '--test', test, *features, '--', '--ignored', '--test-threads=1']
    environment = {**os.environ, **env, 'CARGO_TARGET_DIR': str(ROOT / 'target')}
    listing = subprocess.run([*command, '--list'], cwd=ROOT, env=environment, check=True, text=True, stdout=subprocess.PIPE).stdout
    names = re.findall(r'^(.+): test$', listing, re.M)
    if set(names) != expected or len(names) != len(expected):
        raise RuntimeError(f'{package}/{test}: canonical test set missing or changed')
    result = subprocess.run([*command, '--nocapture', '--format', 'pretty'], cwd=ROOT, env=environment, check=True, text=True, stdout=subprocess.PIPE).stdout
    print(result, end='')
    counts = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', result, re.M)
    executed = re.findall(r'^test (.+) \.\.\. ok$', result, re.M)
    if counts != [(str(len(expected)), '0', '0', '0', '0')] or set(executed) != expected or len(executed) != len(expected):
        raise RuntimeError(f'{package}/{test}: canonical test execution incomplete')

def pg():
    with container(PG, [5432], [("POSTGRES_PASSWORD", "fixture-only")]) as (cid, ports):
        for _ in range(120):
            p = subprocess.run(["docker", "exec", cid, "pg_isready", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if p.returncode == 0: break
            time.sleep(0.5)
        else: raise RuntimeError(f"PostgreSQL readiness timed out: pg_isready exit={p.returncode}")
        env = {"IDENTITY_TEST_PG_PORT": str(ports[5432])}
        cargo("rss-identity-postgres", "atomic", env)
        cargo("rss-identity-admin", "operator", env)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

@contextlib.contextmanager
def hydra():
    # Rebuild the complete self-issuer configuration on each bounded bind collision.
    with contextlib.ExitStack() as stack:
        for attempt in range(3):
            port = free_port()
            issuer = f'http://127.0.0.1:{port}/'
            try:
                _, ports = stack.enter_context(container(HYDRA, {4444: port, 4445: ''},
                    env=[('DSN', 'memory'), ('URLS_SELF_ISSUER', issuer),
                         ('URLS_LOGIN', 'http://127.0.0.1:19998/login'), ('URLS_CONSENT', 'http://127.0.0.1:19998/consent'),
                         ('SECRETS_SYSTEM', 'fixture-only-system-secret-32bytes'), ('LOG_LEVEL', 'error')], args=['serve', 'all', '--dev']))
                break
            except subprocess.CalledProcessError as error:
                collision = any(marker in (error.stderr or '').lower() for marker in ['address already in use', 'port is already allocated'])
                if not collision or attempt == 2:
                    raise
        yield issuer, ports

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
        issuer, hydra_ports = stack.enter_context(hydra())
        admin = f"http://127.0.0.1:{hydra_ports[4445]}"
        wait(issuer + ".well-known/openid-configuration")
        client = {"client_id": "identity-test", "client_secret": "fixture-secret", "grant_types": ["authorization_code"],
                  "response_types": ["code"], "scope": "openid profile", "token_endpoint_auth_method": "client_secret_basic",
                  "redirect_uris": ["http://127.0.0.1:19999/auth/callback"]}
        req = urllib.request.Request(admin + "/admin/clients", data=json.dumps(client).encode(), headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status != 201: raise RuntimeError("Hydra client registration failed")
        cargo("rss-identity-oidc", "provider", {"IDENTITY_TEST_KEYCLOAK_ISSUER": kc, "IDENTITY_TEST_HYDRA_ISSUER": issuer,
              "IDENTITY_TEST_HYDRA_ADMIN": admin}, ["--features", "test-support"])

if __name__ == "__main__":
    if sys.argv[1:] == ["pg"]: pg()
    elif sys.argv[1:] == ["oidc"]: oidc()
    else: raise SystemExit("usage: providers.py pg|oidc")
