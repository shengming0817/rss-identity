#!/usr/bin/env python3
"""Real CLI -> HTTPS -> Identity router -> PG seam, using disposable fixtures (T2)."""
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import sys
from urllib.parse import urlsplit
import providers

def run():
    subprocess.run(['cargo','build','--locked','-p','rss-identity-platform','--features','test-support'],cwd=providers.ROOT,check=True)
    target=Path(os.environ.get('CARGO_TARGET_DIR',providers.ROOT/'target')).resolve()
    with tempfile.TemporaryDirectory(prefix='identity-platform-t2-') as tmp, providers.postgres() as (_,ports):
        root=Path(tmp); backend=providers.free_port()
        commands=[
            ['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=CLI Fixture CA','-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','basicConstraints=critical,CA:TRUE','-addext','subjectKeyIdentifier=hash','-keyout',str(root/'ca-key.pem'),'-out',str(root/'ca.pem')],
            ['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(root/'key.pem'),'-out',str(root/'server.csr')],
        ]
        for command in commands:subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        (root/'extensions').write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        subprocess.run(['openssl','x509','-req','-in',str(root/'server.csr'),'-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca-key.pem'),'-CAcreateserial','-days','1','-sha256','-extfile',str(root/'extensions'),'-out',str(root/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        browser=root/'browser-fixture'
        browser.write_text('#!'+sys.executable+'\n'+(providers.ROOT/'hack/platform_browser.py').read_text())
        browser.chmod(0o700)
        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self): self.forward()
            def do_POST(self): self.forward()
            def forward(self):
                connection=http.client.HTTPConnection('127.0.0.1',backend,timeout=40)
                try:
                    body=self.rfile.read(int(self.headers.get('content-length','0')))
                    connection.request(self.command,self.path,body,dict(self.headers))
                    response=connection.getresponse();payload=response.read()
                    with (root/'http-events.jsonl').open('a') as log:log.write(json.dumps({'method':self.command,'path':urlsplit(self.path).path,'status':response.status})+'\n')
                    drop=root/'drop-next'
                    if drop.exists() and drop.read_text()==self.path and self.command=='POST':
                        drop.unlink();self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                    self.send_response(response.status)
                    for key,value in response.getheaders():
                        if key.lower() not in ('transfer-encoding','connection','content-length'):self.send_header(key,value)
                    self.send_header('content-length',str(len(payload)));self.send_header('connection','close');self.end_headers();self.wfile.write(payload)
                finally: connection.close()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'cert.pem',root/'key.pem');server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            providers.cargo('rss-identity-http-axum','platform_cli',{'IDENTITY_TEST_PG_PORT':str(ports[5432]),'IDENTITY_PLATFORM_DIR':str(root),'IDENTITY_PLATFORM_BACKEND':str(backend),'IDENTITY_PLATFORM_ORIGIN':f'https://localhost:{server.server_port}','IDENTITY_PLATFORM_BINARY':str(target/'debug/identity-platform')})
        finally: server.shutdown();server.server_close();thread.join(timeout=5)

if __name__=='__main__':run()
