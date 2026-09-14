"""Real frontend artifact + public Axum routers + disposable PG. No product assembly."""
import contextlib
import functools
import http.client
import http.server
import os
import json
import signal
import re
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import providers

class Gateway(http.server.SimpleHTTPRequestHandler):
    def log_message(self,*_): pass
    def end_headers(self):
        self.send_header('Cache-Control','no-store')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        super().end_headers()
    def do_GET(self):
        if self.path.startswith('/api/'):
            return self.proxy()
        path=self.translate_path(self.path)
        if not Path(path).is_file():self.path='/index.html'
        super().do_GET()
    def proxy(self):
        size=int(self.headers.get('Content-Length','0'))
        if size>16384:self.send_error(413);return
        connection=http.client.HTTPConnection('127.0.0.1',self.server.backend_port,timeout=35)
        try:
            headers={k:v for k,v in self.headers.items() if k.lower() not in ('connection','content-length')}
            connection.request(self.command,self.path,self.rfile.read(size),headers)
            response=connection.getresponse();data=response.read(1024*1024+1)
            if len(data)>1024*1024:self.send_error(502);return
            self.send_response(response.status)
            for k,v in response.getheaders():
                if k.lower() not in ('connection','content-length','transfer-encoding','cache-control','referrer-policy'):self.send_header(k,v)
            self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        except (OSError,http.client.HTTPException):self.send_error(503)
        finally:connection.close()
    do_POST=do_PUT=proxy

def write_record(path, value):
    if path is None: return
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True))
    temporary.chmod(0o600)
    temporary.replace(path)

def verify_cleanup(resources, volumes=()):
    remaining = []
    for name, state in resources.items():
        try:
            result = subprocess.run(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'],
                                    capture_output=True, text=True, timeout=10)
            absent = result.returncode == 0 and not result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            absent = False
        # An interrupted Docker create may settle later, even if not yet observed.
        if not absent or state != providers.ContainerState.REMOVED: remaining.append(name)
    for volume in volumes:
        try:
            result = subprocess.run(['docker', 'volume', 'ls', '--filter', 'name=' + volume, '--format', '{{.Name}}'],
                                    capture_output=True, text=True, timeout=10)
            absent = result.returncode == 0 and volume not in result.stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            absent = False
        if not absent: remaining.append('volume:' + volume)
    return {'status': 'failed' if remaining else 'passed', 'recovery_targets': remaining}

def main():
    path = Path(os.environ['IDENTITY_UI_FIXTURE_RECORD']) if os.environ.get('IDENTITY_UI_FIXTURE_RECORD') else None
    record = {'format_version': 1, 'result': 'running', 'phase': 'environment', 'failure': None,
              'browser': None, 'cleanup': {'status': 'pending', 'recovery_targets': []}}
    resources = {}
    volumes = set()
    def observe(name, state):
        resources[name] = state
        record['cleanup']['recovery_targets'] = [name for name, state in resources.items() if state != providers.ContainerState.REMOVED] + ['volume:' + v for v in sorted(volumes)]
        write_record(path, record)
        if state == providers.ContainerState.CREATED:
            mounts = json.loads(providers.docker('inspect', '--format', '{{json .Mounts}}', name))
            for mount in mounts:
                if mount['Type'] == 'volume':
                    volume = mount['Name']
                    if not re.fullmatch('[a-f0-9]{64}', volume): raise RuntimeError('unexpected fixture volume')
                    volumes.add(volume)
            record['cleanup']['recovery_targets'] = [name for name, state in resources.items() if state != providers.ContainerState.REMOVED] + ['volume:' + v for v in sorted(volumes)]
            write_record(path, record)
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    def interrupt(signum, _frame): raise SystemExit(128 + signum)
    for sig in previous: signal.signal(sig, interrupt)
    def classify(error):
        if isinstance(error, (KeyboardInterrupt, SystemExit)): return 'interrupted'
        if isinstance(error, subprocess.TimeoutExpired): return 'timeout'
        return 'environment' if record['phase'] in ('environment', 'cleanup') else 'assertion'
    try:
        write_record(path, record)
        dist = Path(os.environ['IDENTITY_UI_DIST']).resolve(strict=True)
        runner = Path(os.environ['IDENTITY_UI_RUNNER']).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix='identity-ui-t2-') as directory:
            tmp = Path(directory)
            browser_record = tmp / 'browser.json'
            with contextlib.ExitStack() as stack:
                try:
                    cert = tmp / 'tls.crt'; key = tmp / 'tls.key'
                    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=identity-ui-t2','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                    _, ports = stack.enter_context(providers.postgres(on_container=observe))
                    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Gateway, directory=str(dist)))
                    stack.callback(server.server_close)
                    server.backend_port = providers.free_port()
                    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert, key)
                    server.socket = tls.wrap_socket(server.socket, server_side=True)
                    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                    def stop_server():
                        server.shutdown(); thread.join(timeout=5)
                        if thread.is_alive(): raise RuntimeError('gateway cleanup failed')
                    stack.callback(stop_server)
                    origin = f'https://localhost:{server.server_port}'
                    upstream = stack.enter_context(providers.keycloak(redirect_uri=origin+'/api/v1/oidc/callback', on_container=observe))
                    record['phase'] = 'backend'; write_record(path, record)
                    env = {**upstream, 'IDENTITY_TEST_PG_PORT': str(ports[5432]),
                           'IDENTITY_TEST_UI_PORT': str(server.backend_port), 'IDENTITY_TEST_UI_ORIGIN': origin,
                           'IDENTITY_UI_RUNNER': str(runner), 'IDENTITY_UI_BROWSER_RECORD': str(browser_record)}
                    providers.cargo('rss-identity-http-axum', 'ui_host', env)
                    record['result'] = 'passed'
                except BaseException as error:
                    record['failure'] = {'phase': record['phase'], 'classification': classify(error)}
                    record['result'] = 'failed'
                    raise
                finally:
                    # Give finally/ExitStack its cleanup budget after a handled interruption.
                    for sig in previous: signal.signal(sig, signal.SIG_IGN)
                    if browser_record.exists():
                        record['browser'] = json.loads(browser_record.read_text())
                        if record['browser'].get('failure') is not None and (record['failure'] is None or record['failure']['classification'] not in ('interrupted', 'timeout')):
                            record['failure'] = {'phase': 'browser', 'classification': record['browser']['failure']}
                    record['phase'] = 'cleanup'
    except BaseException as error:
        record['result'] = 'failed'
        if record['failure'] is None:
            record['failure'] = {'phase': record['phase'], 'classification': classify(error)}
    finally:
        for sig in previous: signal.signal(sig, signal.SIG_IGN)
        record['cleanup'] = verify_cleanup(resources, volumes)
        if record['cleanup']['status'] != 'passed':
            record['result'] = 'failed'
            if record['failure'] is None: record['failure'] = {'phase': 'cleanup', 'classification': 'environment'}
        try: write_record(path, record)
        finally:
            for sig, handler in previous.items(): signal.signal(sig, handler)
    if record['result'] != 'passed':
        print('Identity fixture failed: ' + record['failure']['phase'] + '/' + record['failure']['classification'])
        raise SystemExit(1)
    print('Identity test fixture completed; cleanup verified')

if __name__ == '__main__': main()
