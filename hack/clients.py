#!/usr/bin/env python3
"""Persistent Hydra + local operator seam, including a lost create acknowledgement."""
import contextlib, http.client, http.server, tempfile, threading, uuid
from pathlib import Path
import providers

class LostCreateAck(http.server.BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def request(self):
  size=int(self.headers.get('Content-Length','0'))
  if size>1048576:self.send_error(413);return
  if self.path=='/health/ready':
   self.server.startup_probes+=1
   if self.server.startup_probes<=3:
    self.send_error(503);return
  elif not self.server.ready:
   self.server.premature_requests+=1
   self.send_error(503);return
  connection=http.client.HTTPConnection('127.0.0.1',self.server.upstream,timeout=10)
  try:
   connection.request(self.command,self.path,self.rfile.read(size),{k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','content-length')})
   response=connection.getresponse();body=response.read(1048577)
   if self.path=='/health/ready' and response.status==200:self.server.ready=True
   if self.command=='POST' and self.path=='/admin/clients':
    self.server.creates+=1
    if self.server.creates==1 and response.status==201:
     self.close_connection=True
     return
   if len(body)>1048576:self.send_error(502);return
   self.send_response(response.status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  except (OSError,http.client.HTTPException):self.send_error(503)
  finally:connection.close()
 do_GET=do_POST=do_PUT=request

def main():
 with tempfile.TemporaryDirectory(prefix='identity-clients-') as tmp,contextlib.ExitStack() as stack:
  network='identity-clients-'+uuid.uuid4().hex
  providers.docker('network','create',network);stack.callback(providers.docker,'network','rm',network)
  pg,_=stack.enter_context(providers.postgres());providers.docker('network','connect','--alias','clients-pg',network,pg)
  dsn='postgres://postgres:fixture-only@clients-pg:5432/postgres?sslmode=disable'
  providers.docker('run','--rm','--network',network,'-e','DSN='+dsn,providers.HYDRA,'migrate','sql','-e','--yes')
  env=[('DSN',dsn),('URLS_SELF_ISSUER','http://127.0.0.1:4444/'),('SECRETS_SYSTEM','fixture-only-system-secret-32bytes'),('OAUTH2_PKCE_ENFORCED','true'),('STRATEGIES_ACCESS_TOKEN','opaque'),('LOG_LEVEL','error')]
  cid,ports=stack.enter_context(providers.container(providers.HYDRA,[4444,4445],env=env,args=['serve','all','--dev'],network=network))
  secret=Path(tmp)/'secret';secret.write_text('fixture-local-client-credential-32bytes');secret.chmod(0o600)
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),LostCreateAck);server.upstream=ports[4445];server.creates=0;server.startup_probes=0;server.ready=False;server.premature_requests=0
  thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   variables={'IDENTITY_TEST_CLIENT_ADMIN_PORT':str(server.server_port),'IDENTITY_TEST_CLIENT_PUBLIC_PORT':str(ports[4444]),'IDENTITY_TEST_CLIENT_SECRET':str(secret)}
   providers.cargo('rss-identity-app','clients',variables)
   if server.startup_probes<4 or server.premature_requests:raise RuntimeError('operator did not wait for cold-start readiness')
   providers.docker('exec','--user','10001:10001',cid,'wget','-q','-T','3','-O','/dev/null','http://127.0.0.1:4445/health/ready')
   providers.docker('restart',cid)
   server.startup_probes=0;server.ready=False
   ports={p:int(providers.docker('port',cid,str(p)).rsplit(':',1)[1]) for p in [4444,4445]}
   server.upstream=ports[4445];variables['IDENTITY_TEST_CLIENT_PUBLIC_PORT']=str(ports[4444])
   providers.cargo('rss-identity-app','clients',variables)
   if server.startup_probes<4 or server.premature_requests:raise RuntimeError('operator did not wait for restart readiness')
   if server.creates!=1:raise RuntimeError('registration retried a create or lost persistent client')
  finally:server.shutdown();server.server_close();thread.join(timeout=5)
if __name__=='__main__':main()
