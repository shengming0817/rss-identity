#!/usr/bin/env python3
"""Disposable T2: PG physical restore + persistent Hydra/Keycloak, not a recovery product.

Only generated containers/volumes are touched. The Rust consumer controls the no-write cuts.
ref: PostgreSQL 17 pg_basebackup / pg_verifybackup; Keycloak 26.7.3 prep_migration.adoc.
"""
import contextlib
import http.server
import json
import platform
import hashlib
import ssl
import sys
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid
from pathlib import Path
import providers
import downstream


ACTIONS=('backup-old','backup-current','restore-old','restore-current','corrupt-backup')
STAGES=('begin','prepare-corruption','verify-corruption','stop-providers','base-backup','verify-backup','copy-backup','stop-postgres','create-volume','restore-files','start-postgres','start-providers','readiness')
def safe_failure(action,stage,error):
    category='timeout' if isinstance(error,subprocess.TimeoutExpired) else 'process' if isinstance(error,subprocess.CalledProcessError) else 'io' if isinstance(error,OSError) else 'fixture'
    rc=getattr(error,'returncode',None)
    return dict(action=action if action in ACTIONS else 'unknown',stage=stage if stage in STAGES else 'unknown',error=category,returncode=rc if type(rc) is int and -255<=rc<=255 else None)


def ready_pg(cid):
    for _ in range(120):
        result = subprocess.run(['docker','exec',cid,'pg_isready','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        if result.returncode == 0:return
        time.sleep(.5)
    raise RuntimeError('restored PG readiness failed')


def sql(cid, statement):
    return subprocess.run(['docker','exec','-i',cid,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres'],input=statement,text=True,capture_output=True,timeout=30,check=True).stdout.strip()


class RecoveryGateway(downstream.Gateway):
    def handle_request(self):
        if self.path.startswith('/fixture/recovery/'):
            if self.command!='POST' or self.headers.get('Authorization')!='Bearer '+downstream.SERVICE:
                self.send_error(403);return
            action=self.path.removeprefix('/fixture/recovery/')
            if action not in ACTIONS:
                self.send_error(400);return
            try:
                self.server.recovery(action)
                self.send_response(204);self.send_header('Content-Length','0');self.end_headers()
            except Exception as error:
                self.server.control_error=safe_failure(action,self.server.recovery_stage,error)
                print('recovery failure: '+json.dumps(self.server.control_error,sort_keys=True),file=sys.stderr)
                self.send_error(503)
            return
        super().handle_request()
    do_GET=do_POST=do_PUT=do_DELETE=handle_request


def main():
    with tempfile.TemporaryDirectory(prefix='identity-recovery-t2-') as tmp, contextlib.ExitStack() as stack:
        root=Path(tmp); network='identity-recovery-'+uuid.uuid4().hex
        providers.docker('network','create',network);stack.callback(providers.docker,'network','rm',network)
        port=providers.free_port()
        pg,_=stack.enter_context(providers.container(providers.PG,{5432:port},[('POSTGRES_PASSWORD','fixture-only')]))
        ready_pg(pg);providers.docker('network','connect','--alias','recovery-pg',network,pg)
        sql(pg,'CREATE DATABASE hydra; CREATE DATABASE keycloak;')
        cert=root/'tls.crt';key=root/'tls.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=recovery-t2','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),RecoveryGateway)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key);server.socket=tls.wrap_socket(server.socket,server_side=True)
        issuer=f'https://localhost:{server.server_port}/';server.bridge_port=providers.free_port();server.fail_introspection=False;server.control_error=None
        dsn='postgres://postgres:fixture-only@recovery-pg:5432/hydra?sslmode=disable'
        providers.docker('run','--rm','--network',network,'-e','DSN='+dsn,providers.HYDRA,'migrate','sql','-e','--yes')
        hydra,ports=stack.enter_context(providers.container(providers.HYDRA,{4444:providers.free_port(),4445:providers.free_port()},env=[('DSN',dsn),('URLS_SELF_ISSUER',issuer),('URLS_LOGIN',issuer+'login'),('URLS_CONSENT',issuer+'consent'),('SECRETS_SYSTEM','fixture-only-system-secret-32bytes'),('SECRETS_COOKIE','fixture-only-cookie-secret-32bytes'),('OAUTH2_PKCE_ENFORCED','true'),('STRATEGIES_ACCESS_TOKEN','opaque'),('TTL_LOGIN_CONSENT_REQUEST','5m'),('TTL_AUTH_CODE','1m'),('TTL_ACCESS_TOKEN','5m'),('LOG_LEVEL','error')],args=['serve','all','--dev'],network=network))
        server.public_port=ports[4444];server.admin_port=ports[4445]
        providers.wait(f'http://127.0.0.1:{ports[4445]}/health/ready')
        keycloak=stack.enter_context(providers.keycloak(issuer.rstrip('/')+'/api/v1/oidc/callback',database_env=[('KC_DB','postgres'),('KC_DB_URL','jdbc:postgresql://recovery-pg:5432/keycloak'),('KC_DB_USERNAME','postgres'),('KC_DB_PASSWORD','fixture-only')],network=network))
        kc=keycloak['IDENTITY_TEST_KEYCLOAK_CONTAINER']
        request=urllib.request.Request(f'http://127.0.0.1:{ports[4445]}/admin/clients',data=json.dumps({'client_id':'mdm','client_secret':'fixture-oidc-mdm-secret','grant_types':['authorization_code'],'response_types':['code'],'scope':'openid','audience':['mdm-api'],'token_endpoint_auth_method':'client_secret_basic','redirect_uris':['https://mdm.example.test/auth/callback']}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=5) as response:
            if response.status!=201:raise RuntimeError('Hydra fixture registration failed')
        current=[pg];measurements=[]
        def providers_ready():
            providers.wait(f'http://127.0.0.1:{ports[4445]}/health/ready')
            context=ssl.create_default_context(cafile=keycloak['IDENTITY_TEST_FEDERATED_CA'])
            end=time.monotonic()+120
            while time.monotonic()<end:
                try:
                    with urllib.request.urlopen(keycloak['IDENTITY_TEST_FEDERATED_ISSUER']+'/.well-known/openid-configuration',context=context,timeout=2) as r:
                        if r.status==200:return
                except (OSError,urllib.error.URLError):time.sleep(.5)
            raise RuntimeError('restored Keycloak readiness failed')
        def recovery(action):
            server.recovery_stage='begin'
            started=time.monotonic()
            if action=='corrupt-backup':
                server.recovery_stage='prepare-corruption'
                providers.docker('exec',current[0],'sh','-ec','cp -a /tmp/backup-current /tmp/corrupt; printf corruption >> /tmp/corrupt/PG_VERSION')
                server.recovery_stage='verify-corruption'
                result=subprocess.run(['docker','exec',current[0],'pg_verifybackup','/tmp/corrupt'],capture_output=True,timeout=30)
                if result.returncode==0:raise RuntimeError('corrupt physical backup accepted')
                return
            kind,name=action.split('-')
            server.recovery_stage='stop-providers'
            providers.docker('stop','--time','30',hydra,kc)
            if kind=='backup':
                server.recovery_stage='base-backup'
                providers.docker('exec','--user','postgres',current[0],'pg_basebackup','-U','postgres','-D','/tmp/backup-'+name,'-Fp','-X','stream','-c','fast')
                server.recovery_stage='verify-backup'
                providers.docker('exec',current[0],'pg_verifybackup','/tmp/backup-'+name)
                server.recovery_stage='copy-backup'
                providers.docker('cp',current[0]+':/tmp/backup-'+name,str(root/name))
            else:
                server.recovery_stage='stop-postgres'
                providers.docker('stop','--time','30',current[0]);providers.docker('network','disconnect',network,current[0])
                volume='identity-restore-'+uuid.uuid4().hex
                server.recovery_stage='create-volume'
                providers.docker('volume','create',volume);stack.callback(providers.docker,'volume','rm',volume)
                server.recovery_stage='restore-files'
                providers.docker('run','--rm','-v',str(root/name)+':/backup:ro','-v',volume+':/restore','--entrypoint','sh',providers.PG,'-ec','cp -a /backup/. /restore/; chown -R postgres:postgres /restore; chmod 700 /restore')
                server.recovery_stage='start-postgres'
                restored,_=stack.enter_context(providers.container(providers.PG,{5432:port},mounts=[volume+':/var/lib/postgresql/data']))
                ready_pg(restored);providers.docker('network','connect','--alias','recovery-pg',network,restored);current[0]=restored
            server.recovery_stage='start-providers'
            providers.docker('start',hydra,kc)
            server.recovery_stage='readiness'
            providers_ready()
            measurements.append({'operation':action,'seconds':round(time.monotonic()-started,3)})
        server.recovery=recovery
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            env={'IDENTITY_TEST_PG_PORT':str(port),'IDENTITY_TEST_DOWNSTREAM_ISSUER':issuer,'IDENTITY_TEST_DOWNSTREAM_CA':str(cert),'IDENTITY_TEST_BRIDGE_PORT':str(server.bridge_port),**keycloak}
            providers.cargo('rss-identity-http-axum','recovery_http',env)
            if server.control_error:raise RuntimeError('recovery control failed: '+json.dumps(server.control_error,sort_keys=True))
            print(json.dumps({'proof':'T2 controlled backup point; not production RPO/RTO','host_arch':platform.machine(),'revision':subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=providers.ROOT,text=True).strip(),'dirty':bool(subprocess.check_output(['/usr/bin/git','status','--porcelain'],cwd=providers.ROOT)),'lock_sha256':hashlib.sha256((providers.ROOT/'Cargo.lock').read_bytes()).hexdigest(),'backup_bytes':sum(p.stat().st_size for p in (root/'current').rglob('*') if p.is_file()),'providers':providers.IMAGES,'measurements':measurements},sort_keys=True))
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)

if __name__=='__main__':main()
