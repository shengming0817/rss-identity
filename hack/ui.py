"""Real frontend artifact + public Axum routers + disposable PG. No product assembly."""
import contextlib
import functools
import http.client
import http.server
import json
import os
from pathlib import Path
import re
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

def main():
    dist=Path(os.environ['IDENTITY_UI_DIST']).resolve(strict=True)
    runner=Path(os.environ['IDENTITY_UI_RUNNER']).resolve(strict=True)
    revision=json.loads((dist/'identity-build.json').read_text())['revision']
    if not re.fullmatch('[0-9a-f]{40}',revision):raise RuntimeError('UI source revision missing')
    with tempfile.TemporaryDirectory(prefix='identity-ui-t2-') as tmp,contextlib.ExitStack() as stack:
        tmp=Path(tmp);cert=tmp/'tls.crt';key=tmp/'tls.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=identity-ui-t2','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        _,ports=stack.enter_context(providers.postgres())
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Gateway,directory=str(dist)))
        server.backend_port=providers.free_port()
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key);server.socket=tls.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            env={'IDENTITY_TEST_PG_PORT':str(ports[5432]),'IDENTITY_TEST_UI_PORT':str(server.backend_port),'IDENTITY_TEST_UI_ORIGIN':f'https://localhost:{server.server_port}','IDENTITY_UI_RUNNER':str(runner)}
            providers.cargo('rss-identity-http-axum','ui_host',env)
            print('Identity UI source:',revision)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)
if __name__=='__main__':main()
