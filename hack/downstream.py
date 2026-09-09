"""Real PG + pinned Hydra with a disposable TLS/admin gateway. No production assembly."""
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import urllib.request
import providers

SERVICE = 'fixture-service-identity-admin-32bytes'
VALIDATION = 'fixture-validation-mdm-secret-32bytes'

class Gateway(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def handle_request(self):
        if self.path == '/fixture/introspection':
            if self.headers.get('Authorization') != 'Bearer ' + SERVICE:
                self.send_error(401); return
            size=int(self.headers.get('Content-Length','0'))
            if size>1024:self.send_error(413);return
            value=json.loads(self.rfile.read(size))
            self.server.fail_introspection=value['unavailable']
            self.send_response(204);self.end_headers();return
        if self.path.startswith('/admin/'):
            if self.headers.get('Authorization') != 'Bearer ' + SERVICE:
                self.send_error(401); return
            if self.path.startswith('/admin/oauth2/introspect') and self.server.fail_introspection:
                self.send_error(503);return
            port = self.server.admin_port
        elif self.path.startswith(('/api/', '/internal/')):
            port = self.server.bridge_port
        else:
            port = self.server.public_port
        size = int(self.headers.get('Content-Length', '0'))
        if size > 1048576: self.send_error(413); return
        body = self.rfile.read(size)
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
        try:
            headers = {k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','content-length')}
            headers['Host'] = self.headers['Host']; headers['X-Forwarded-Proto'] = 'https'
            conn.request(self.command, self.path, body=body, headers=headers)
            response = conn.getresponse(); data = response.read(1048577)
            if len(data)>1048576: self.send_error(502); return
            self.send_response(response.status)
            for k,v in response.getheaders():
                if k.lower() not in ('transfer-encoding','connection','content-length'): self.send_header(k,v)
            self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        except (OSError, http.client.HTTPException):
            self.send_error(503)
        finally: conn.close()
    do_GET=do_POST=do_PUT=do_DELETE=handle_request

def run(measure=False):
    with tempfile.TemporaryDirectory(prefix='identity-downstream-') as tmp, contextlib.ExitStack() as stack:
        tmp=Path(tmp); cert=tmp/'tls.crt'; key=tmp/'tls.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=identity-downstream-t2','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature,keyEncipherment','-addext','extendedKeyUsage=serverAuth'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Gateway)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key);server.socket=tls.wrap_socket(server.socket,server_side=True)
        issuer=f'https://localhost:{server.server_port}/'
        server.bridge_port=providers.free_port()
        server.fail_introspection=False
        _, pg=stack.enter_context(providers.postgres())
        _, hydra=stack.enter_context(providers.container(providers.HYDRA,[4444,4445],env=[('DSN','memory'),('URLS_SELF_ISSUER',issuer),('URLS_LOGIN',issuer+'login'),('URLS_CONSENT',issuer+'consent'),('SECRETS_SYSTEM','fixture-only-system-secret-32bytes'),('OAUTH2_PKCE_ENFORCED','true'),('STRATEGIES_ACCESS_TOKEN','opaque'),('TTL_LOGIN_CONSENT_REQUEST','5m'),('TTL_AUTH_CODE','1m'),('TTL_ACCESS_TOKEN','5m'),('LOG_LEVEL','error')],args=['serve','all','--dev']))
        server.admin_port=hydra[4445];server.public_port=hydra[4444]
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            providers.wait(f'http://127.0.0.1:{hydra[4445]}/health/ready')
            for client in ['mdm','other']:
                data={'client_id':client,'client_secret':'fixture-oidc-'+client+'-secret','grant_types':['authorization_code'],'response_types':['code'],'scope':'openid','audience':[client+'-api'],'token_endpoint_auth_method':'client_secret_basic','redirect_uris':['https://'+client+'.example.test/auth/callback']}
                req=urllib.request.Request(f'http://127.0.0.1:{hydra[4445]}/admin/clients',data=json.dumps(data).encode(),headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=5) as r:
                    if r.status!=201:raise RuntimeError('client registration failed')
            env={'IDENTITY_TEST_PG_PORT':str(pg[5432]),'IDENTITY_TEST_DOWNSTREAM_ISSUER':issuer,'IDENTITY_TEST_DOWNSTREAM_CA':str(cert),'IDENTITY_TEST_BRIDGE_PORT':str(server.bridge_port)}
            if measure:
                import platform,hashlib
                source=providers.docker('image','inspect','--format','{{.Architecture}}',providers.HYDRA)
                print(json.dumps({'profile':'one in-process consumer, 1 tenant, 16 accounts, 8 grants; 64 requests per run; existing fixture pool/KDF defaults; latency includes failures; cleanup is one revocation pass, not final deletion','host_arch':platform.machine(),'hydra_arch':source,'revision':subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=providers.ROOT,text=True).strip(),'dirty':bool(subprocess.check_output(['/usr/bin/git','status','--porcelain'],cwd=providers.ROOT)),'lock_sha256':hashlib.sha256((providers.ROOT/'Cargo.lock').read_bytes()).hexdigest(),'providers':{'postgres':providers.PG,'hydra':providers.HYDRA}},sort_keys=True))
                providers.cargo('rss-identity-http-axum','capacity_http',env)
            else:
                env.update(stack.enter_context(providers.keycloak(issuer.rstrip('/')+'/api/v1/oidc/callback')))
                providers.cargo('rss-identity-postgres','downstream_atomic',env)
                providers.cargo('rss-identity-http-axum','downstream_http',env)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)

if __name__=='__main__':
    import sys
    if sys.argv[1:] not in ([],['--measure']):raise SystemExit('usage: downstream.py [--measure]')
    run(measure=bool(sys.argv[1:]))
