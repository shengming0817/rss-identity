#!/usr/bin/env python3
"""Isolated T2 providers. Loopback HTTP/plaintext is fixture-only, never production config."""
import contextlib
from enum import Enum
import json
import ipaddress
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
IMAGES = json.loads((Path(__file__).resolve().parents[1]/"deployment/providers.lock.json").read_text())
PG = IMAGES["postgres"]
KEYCLOAK = IMAGES["keycloak"]

class ContainerState(str, Enum):
    PRECREATE = 'precreate'
    CREATED = 'created'
    REMOVED = 'removed'
    REMOVE_UNKNOWN = 'remove-unknown'

def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, stderr=subprocess.PIPE, timeout=180).strip()

@contextlib.contextmanager
def container(image, ports, env=(), args=(), mounts=(), user=None, sysctls=(), network=None, on_container=None, bind_address="127.0.0.1", address=None):
    name = "identity-t2-" + uuid.uuid4().hex
    command = ["run", "-d", "--name", name]
    if network is not None: command += ["--network", network]
    if address is not None: command += ["--ip", address]
    if user is not None: command += ["--user", user]
    for value in sysctls: command += ["--sysctl", value]
    for port in ports:
        host = ports[port] if isinstance(ports, dict) else ""
        command += ["-p", f"{bind_address}:{host}:{port}"]
    for key, value in env:
        command += ["-e", f"{key}={value}"]
    for mount in mounts:
        command += ["-v", mount]
    failure = None
    try:
        if on_container is not None: on_container(name, ContainerState.PRECREATE)
        cid = docker(*command, image, *args)
        if on_container is not None: on_container(name, ContainerState.CREATED)
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
            subprocess.run(["docker", "rm", "-f", "-v", name], stdout=subprocess.DEVNULL, timeout=30, check=True)
        except (subprocess.SubprocessError, OSError) as cleanup_error:
            if on_container is not None: on_container(name, ContainerState.REMOVE_UNKNOWN)
            if failure is None:
                raise RuntimeError(f"fixture cleanup failed: {name}") from cleanup_error
            print(f"fixture cleanup also failed: {name}: {type(cleanup_error).__name__}", file=sys.stderr)
        else:
            if on_container is not None: on_container(name, ContainerState.REMOVED)

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

SUITES = {('rss-identity-oidc', 'private_provider_tests'): {'real_private_provider_transport'}, ('rss-identity-app', 'ui_host'): {'ui_host_public_components'}, ('rss-identity-http-axum', 'management_http'): {'management_rejects_password_for_federated_only_account', 'callback_cancellation_consumes_only_bound_attempts', 'management_rechecks_inflight_provider_authority', 'provider_capacity_is_atomic_and_keeps_management_available', 'management_accounts_sessions_and_boundaries', 'management_provider_operations_safe_and_scoped'}, ('rss-identity-http-axum', 'federated_http'): {'real_invalid_department_preserves_authenticated_identity', 'department_lifecycle::administrator_snapshot_moves_members_and_keeps_old_observations', 'group_lifecycle::real_group_snapshot_lifecycle', 'federated_http_rejects_mismatch_and_uncertain_commit', 'real_provider_management_and_encrypted_credentials', 'real_federated_login_and_linking', 'real_upstream_client_secret_rotation', 'real_step_up_rotates_only_the_bound_session', 'federated_tls_and_self_service_policy'}, ('rss-identity-postgres', 'federated_atomic'): {'tenant_reencryption_is_atomic_scoped_and_authenticates_every_value', 'session_security_is_subject_bound_and_revocable', 'federation_jit_isolated_subjects_and_membership', 'federation_atomic_events_and_unknown_commit', 'federation_link_conflict_logout_and_wrong_reauthentication', 'federation_assurance_change_revokes_attempts_and_sessions', 'federation_signed_time_skew_preserves_identity', 'federation_state_restart_expiry_and_replay', 'federation_config_races_and_provider_revocation', 'federation_group_snapshot_storage_bounds', 'federation_concurrent_linking_keeps_one_owner', 'federation_concurrent_jit_rls_and_schema_drift', 'federation_configuration_authorization_and_versions', 'federation_step_up_binding_and_settlement', 'federation_local_and_federated_linking', 'federation_step_up_unknown_commit_and_event_rollback'}, ('rss-identity-postgres', 'atomic'): {'maintenance_races_preserve_current_state', 'maintenance_permissions_and_schema_are_exact', 'attempts_are_shared_and_bounded', 'account_transition_matrix_and_events', 'maintenance_runbook_respects_forced_rls', 'storage_contract_is_checked', 'settlement_never_releases_uncertain_success', 'initialization_and_recovery', 'maintenance_deadline_fencing_and_overflow', 'fencing_and_generation_overflow', 'account_races_and_isolation', 'source_budgets_are_shared'}, ('rss-identity-postgres', 'session_atomic'): {'session_isolation_replacement_and_restart', 'session_expiry_deadline_permissions_and_overflow', 'session_logout_rotation_races_and_invalid_storage', 'session_events_match_committed_operations', 'session_settlement_and_event_failure_are_atomic', 'session_rotation_and_revocation', 'session_account_changes_fence_racing_credentials'}, ('rss-identity-http-axum', 'session_http'): {'public_host_requests_enforce_activity_and_revocation', 'session_http_login_cookie_csrf_and_replacement', 'session_http_recovery_current_logout_and_deadline', 'session_http_settlement_never_sets_uncertain_cookie', 'session_http_origin_expiry_and_transport_boundaries', 'session_http_pending_commit_preserves_settlement', 'session_http_lookup_never_inserts_tenant_guard', 'session_http_v2_reauthentication_is_bound_and_has_no_legacy_role_surface'}, ('rss-identity-app', 'operator'): {'maintenance_file_and_settlement'}, ('rss-identity-oidc', 'provider'): {'real_provider_flows'}, ('rss-identity-postgres', 'embedded'): {'department_lifecycle::department_values_absence_expiry_refresh_and_management', 'department_lifecycle::oversized_assertions_withhold_departments_but_corrupt_storage_rejects_identity', 'department_lifecycle::department_configuration_revokes_sessions_and_pending_attempts', 'department_lifecycle::department_source_is_instance_tenant_principal_and_provider_bound', 'department_lifecycle::department_subject_and_provider_revocations_are_current', 'refresh_rejects_expiry_during_writes_without_rotating_or_emitting', 'group_deadline_includes_session_touch_latency', 'own_password_change_requires_current_host_policy', 'construction_verifies_every_declared_tenant_fence', 'trusted_groups_expire_without_extending_identity_or_snapshot', 'host_role_names_and_session_policy_survive_composition', 'local_facade_reauthenticates_and_host_policy_is_current', 'instances_tenants_and_borrowed_pool_are_separate'}, ('rss-identity-app', 'installation'): {'installation_and_reference_host_seams_are_verified'}}

def cargo(package, test, env, features=()):
    expected = SUITES[(package,test)]
    internal = (package=="rss-identity-postgres" and test in {"atomic","session_atomic","federated_atomic"}) or (package=="rss-identity-oidc" and test=="private_provider_tests")
    module = "account_atomic" if test == "atomic" else test
    if internal: expected={f"{module}::{name}" for name in expected}
    filtered = 0
    command = ['cargo', 'test', '--locked', '-p', package, *(['--lib',module+'::'] if internal else ['--test',test]), *features, '--', '--ignored', '--test-threads=1']
    environment = {**os.environ, **env}
    listing = bounded_run([*command, '--list'], timeout=900, cwd=ROOT, env=environment, check=True, text=True, stdout=subprocess.PIPE).stdout
    names = re.findall(r'^(.+): test$', listing, re.M)
    if set(names) != expected or len(names) != len(expected):
        raise RuntimeError(f'{package}/{test}: canonical test set missing or changed')
    if internal:
        all_listing = bounded_run(['cargo','test','--locked','-p',package,'--lib','--','--list'],timeout=900,cwd=ROOT,env=environment,check=True,text=True,stdout=subprocess.PIPE).stdout
        filtered=len(re.findall(r'^(.+): test$',all_listing,re.M))-len(expected)
    completed = bounded_run([*command, '--nocapture', '--format', 'pretty'], timeout=max(180,len(expected)*180), cwd=ROOT, env=environment, text=True, capture_output=True)
    result = completed.stdout
    report_tests(package, test, expected, completed)
    if completed.returncode:
        raise RuntimeError(f'{package}/{test}: cargo exit={completed.returncode}')
    counts = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', result, re.M)
    executed = re.findall(r'^test (.+) \.\.\. ok$', result, re.M)
    if counts != [(str(len(expected)), '0', '0', '0', str(filtered))] or set(executed) != expected or len(executed) != len(expected):
        raise RuntimeError(f'{package}/{test}: canonical test execution incomplete')

@contextlib.contextmanager
def postgres(on_container=None):
    with container(PG, [5432], [("POSTGRES_PASSWORD", "fixture-only")], on_container=on_container) as (cid, ports):
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
        cargo("rss-identity-postgres", "embedded", env)
        cargo("rss-identity-postgres", "session_atomic", env)
        cargo("rss-identity-http-axum", "session_http", env)
        cargo("rss-identity-http-axum", "management_http", env)
        cargo("rss-identity-app", "operator", env)


def free_port(host="127.0.0.1"):
    with socket.socket() as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]

DEPARTMENT_ASSERTION = {"version":1,"sourceRevision":"fixture-r1","nodes":[
    {"id":"root","displayName":"Company","parentId":None},
    {"id":"dept-01","displayName":"Engineering","parentId":"root"},
    {"id":"dept-02","displayName":"Sales","parentId":"root"}],"memberships":["dept-01"]}
DEPARTMENT_MAPPER = {"name":"organization-snapshot", "protocol":"openid-connect", "protocolMapper":"oidc-usermodel-attribute-mapper",
    "config":{"user.attribute":"organization_snapshot", "claim.name":"organization_snapshot", "jsonType.label":"JSON", "multivalued":"false", "aggregate.attrs":"false", "id.token.claim":"true", "access.token.claim":"false", "userinfo.token.claim":"false"}}

def configure_department_profile(issuer, context=None):
    """Only realm administrators can edit the single JSON assertion; built-in mapper only.
    ref: Keycloak 26.7.3 UserAttributeMapper.java / DeclarativeUserProfileProvider.java.
    """
    origin = issuer.removesuffix('/realms/identity')
    credentials = urllib.parse.urlencode({'client_id':'admin-cli','grant_type':'password',
        'username':'fixture-operator','password':'fixture-operator-password'}).encode()
    request=urllib.request.Request(origin+'/realms/master/protocol/openid-connect/token',data=credentials)
    with urllib.request.urlopen(request,context=context,timeout=10) as response: token=json.load(response)['access_token']
    def admin(method, path, value=None):
        request=urllib.request.Request(origin+'/admin/realms/identity'+path,method=method,
            data=json.dumps(value).encode() if value is not None else None,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with urllib.request.urlopen(request,context=context,timeout=10) as response:
            raw=response.read(); return json.loads(raw) if raw else None
    profile=admin('GET','/users/profile')
    profile['attributes']=[a for a in profile['attributes'] if a['name']!='organization_snapshot']
    profile['attributes'].append({'name':'organization_snapshot','displayName':'Organization snapshot',
        'multivalued':False,'permissions':{'view':['admin'],'edit':['admin']},
        'validations':{'length':{'max':32768}}})
    admin('PUT','/users/profile',profile)
    installed=admin('GET','/users/profile')
    attribute=next(a for a in installed['attributes'] if a['name']=='organization_snapshot')
    if attribute['permissions']!={'view':['admin'],'edit':['admin']}: raise RuntimeError('department attribute is not administrator-only')
    user=admin('GET','/users?username=alice&exact=true')[0]
    user.setdefault('attributes',{})['organization_snapshot']=[json.dumps(DEPARTMENT_ASSERTION)]
    admin('PUT','/users/'+user['id'],user)
    if admin('GET','/users/'+user['id'])['attributes']['organization_snapshot']!=[json.dumps(DEPARTMENT_ASSERTION)]:
        raise RuntimeError('department assertion read-back failed')
    # Disposable ordinary-user Account API probe, separate from the product OIDC client.
    admin('POST','/clients',{'clientId':'department-profile-test','publicClient':True,
        'standardFlowEnabled':False,'directAccessGrantsEnabled':True,'fullScopeAllowed':True,
        'defaultClientScopes':['roles','profile','email'],
        'protocolMappers':[{'name':'account-audience','protocol':'openid-connect','protocolMapper':'oidc-audience-mapper',
            'config':{'included.client.audience':'account','id.token.claim':'false','access.token.claim':'true'}}]})
    account=admin('GET','/clients?clientId=account')[0]
    roles=admin('GET','/clients/'+account['id']+'/roles')
    admin('POST','/users/'+user['id']+'/role-mappings/clients/'+account['id'],
        [role for role in roles if role['name'] in {'manage-account','view-profile'}])

def oidc():
    realm = {"realm": "identity", "enabled": True, "sslRequired": "none",
             "clients": [{"clientId": "identity-test", "secret": "fixture-secret", "publicClient": False,
                          "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                          "redirectUris": ["http://127.0.0.1:19999/auth/callback"],
                          "attributes": {"pkce.code.challenge.method": "S256"}, "protocolMappers":[DEPARTMENT_MAPPER]}],
             "users": [{"username": "alice", "enabled": True, "email": "alice@example.test", "emailVerified": True,
                        "firstName": "Alice", "lastName": "Fixture", "attributes":{},
                        "credentials": [{"type": "password", "value": "fixture-password", "temporary": False}]}]}
    with tempfile.TemporaryDirectory(prefix="identity-oidc-") as tmp, contextlib.ExitStack() as stack:
        realm_file = Path(tmp) / "identity-realm.json"
        realm_file.write_text(json.dumps(realm))
        _, kc_ports = stack.enter_context(container(KEYCLOAK, [8080], env=[("KC_BOOTSTRAP_ADMIN_USERNAME","fixture-operator"),("KC_BOOTSTRAP_ADMIN_PASSWORD","fixture-operator-password")], args=["start-dev", "--import-realm"], mounts=[f"{realm_file}:/opt/keycloak/data/import/identity-realm.json:ro"]))
        kc = f"http://127.0.0.1:{kc_ports[8080]}/realms/identity"
        wait(kc + "/.well-known/openid-configuration")
        configure_department_profile(kc)
        cargo("rss-identity-oidc", "provider", {"IDENTITY_TEST_KEYCLOAK_ISSUER": kc}, ["--features", "test-support"])

    private_oidc()

def configure_totp(realm):
    """Keycloak 26.7.3 conditional LoA flow; test credentials, never production defaults.
    ref: Keycloak server_admin Creating a browser login flow with step-up mechanism.
    """
    realm.update(json.loads((ROOT/'deployment/keycloak-totp.json').read_text()))
    for user in realm['users']:
        user['credentials'].append({'type':'otp','userLabel':'fixture-totp','secretData':json.dumps({'value':'fixture-totp-secret-2339'}),'credentialData':json.dumps({'digits':6,'counter':0,'period':30,'algorithm':'HmacSHA1','subType':'totp'})})

@contextlib.contextmanager
def keycloak(redirect_uri="https://identity.example.test/api/v2/oidc/callback", database_env=(), network=None, on_container=None, host="127.0.0.1", hostname=None):
    realm = {"realm":"identity", "enabled":True, "sslRequired":"all", "duplicateEmailsAllowed":True,
             "loginWithEmailAllowed":False,
             "groups":[{"name":"staff"}],
             "clients":[{"clientId":"identity-test", "secret":"fixture-secret", "publicClient":False,
                         "standardFlowEnabled":True, "directAccessGrantsEnabled":False,
                         "redirectUris":[redirect_uri],
                         "attributes":{"pkce.code.challenge.method":"S256"},
                         "protocolMappers":[{"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper",
                         "config":{"claim.name":"groups","full.path":"true","id.token.claim":"true","access.token.claim":"false"}}, DEPARTMENT_MAPPER]}],
             "users":[{"username":name,"enabled":True,"email":"same@example.test","emailVerified":True,
                       "firstName":name,"lastName":"Fixture","groups":["staff"],
                       "attributes":{} if name == "alice" else {},
                       "credentials":[{"type":"password","value":"fixture-password","temporary":False}]} for name in ["alice","bob"]]}
    configure_totp(realm)
    with tempfile.TemporaryDirectory(prefix="identity-federated-") as tmp, contextlib.ExitStack() as stack:
        tmp=Path(tmp);cert=tmp/"tls.crt";key=tmp/"tls.key";realm_file=tmp/"identity-realm.json"
        realm_file.write_text(json.dumps(realm))
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-days","2",
                        "-subj","/CN=identity-t2", "-addext","basicConstraints=critical,CA:FALSE","-addext","keyUsage=critical,digitalSignature,keyEncipherment","-addext","extendedKeyUsage=serverAuth","-addext",f"subjectAltName=IP:{host},DNS:{hostname or 'localhost'}"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        key.chmod(0o644)  # Synthetic disposable fixture key readable by the container's unprivileged uid.
        port=free_port(host);origin=f"https://{hostname or host}:{port}";issuer=origin+"/realms/identity"
        kc_id, _ = stack.enter_context(container(KEYCLOAK,{8443:port},env=[('KC_BOOTSTRAP_ADMIN_USERNAME','fixture-operator'),('KC_BOOTSTRAP_ADMIN_PASSWORD','fixture-operator-password'),*database_env],network=network,args=["start-dev","--import-realm","--http-enabled=false",f"--hostname={origin}",
            "--https-certificate-file=/opt/keycloak/conf/tls.crt","--https-certificate-key-file=/opt/keycloak/conf/tls.key"],
            mounts=[f"{realm_file}:/opt/keycloak/data/import/identity-realm.json:ro",f"{cert}:/opt/keycloak/conf/tls.crt:ro",f"{key}:/opt/keycloak/conf/tls.key:ro"], on_container=on_container, bind_address=host))
        context=ssl.create_default_context(cafile=str(cert));deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            try:
                with urllib.request.urlopen(f"https://{host}:{port}/realms/identity/.well-known/openid-configuration",context=context,timeout=2) as response:
                    if response.status==200:break
            except (OSError,urllib.error.URLError):time.sleep(.5)
        else:raise RuntimeError("Keycloak TLS readiness timed out")
        configure_department_profile(issuer, context)
        yield {"IDENTITY_TEST_FEDERATED_ISSUER":issuer,"IDENTITY_TEST_FEDERATED_CA":str(cert),"IDENTITY_TEST_KEYCLOAK_CONTAINER":kc_id}

def private_host():
    """Use an owned RFC1918 interface, never weaken the production address policy."""
    candidates=[]
    configured=os.environ.get('IDENTITY_TEST_PRIVATE_HOST')
    if configured:
        candidates=[configured]
    else:
        try:candidates.extend(a[4][0] for a in socket.getaddrinfo(socket.gethostname(),None,socket.AF_INET))
        except OSError:pass
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as route:
                route.connect(('10.255.255.255',9));candidates.append(route.getsockname()[0])
        except OSError:pass
    networks=[ipaddress.ip_network(n) for n in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']]
    for value in dict.fromkeys(candidates):
        address=ipaddress.ip_address(value)
        if any(address in network for network in networks):
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:probe.bind((value,0))
                return value
            except OSError:pass
    raise RuntimeError('production private OIDC T2 requires an owned RFC1918 interface; set IDENTITY_TEST_PRIVATE_HOST')

def private_oidc():
    address=private_host()
    with keycloak(host=address, hostname='private-idp.invalid') as env:
        cargo('rss-identity-oidc','private_provider_tests',{**env,'IDENTITY_TEST_PRIVATE_ADDRESS':address})


def federated():
    with keycloak() as env, postgres() as (_, ports):
        cargo("rss-identity-http-axum","federated_http",{**env,"IDENTITY_TEST_PG_PORT":str(ports[5432])})

def assembly():
    # TLS exercises the reference host's actual PG configuration, without a deployed stack.
    with tempfile.TemporaryDirectory(prefix='identity-install-') as tmp, postgres() as (cid, ports):
        root = Path(tmp)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(root/'server.key'),'-out',str(root/'server.crt')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        for name in ['server.key','server.crt']:
            docker('cp',str(root/name),cid+':/tmp/'+name)
        docker('exec','-u','root',cid,'sh','-c','chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key')
        for setting in ["ssl='on'", "ssl_cert_file='/tmp/server.crt'", "ssl_key_file='/tmp/server.key'"]:
            docker('exec',cid,'psql','-X','-U','postgres','-v','ON_ERROR_STOP=1','-c','ALTER SYSTEM SET '+setting)
        docker('exec',cid,'psql','-X','-U','postgres','-v','ON_ERROR_STOP=1','-c','SELECT pg_reload_conf()')
        for name, value in [('owner','fixture-only'),('runtime','fixture-runtime'),('maintenance','fixture-maintenance')]:
            file = root/name
            file.write_text(value)
            file.chmod(0o600)
        cargo('rss-identity-app','installation',{'IDENTITY_TEST_INSTALL_DIR':tmp,'IDENTITY_TEST_PG_PORT':str(ports[5432]),'IDENTITY_TEST_PG_CONTAINER':cid})

if __name__ == "__main__":
    if sys.argv[1:] == ["pg"]: pg()
    elif sys.argv[1:] == ["oidc"]: oidc()
    elif sys.argv[1:] == ["private-oidc"]: private_oidc()
    elif sys.argv[1:] == ["federated"]: federated()
    elif sys.argv[1:] == ["assembly"]: assembly()
    else: raise SystemExit("usage: providers.py pg|oidc|private-oidc|federated|assembly")
