#!/usr/bin/env python3
"""Persistent Hydra + local operator seam, including a lost create acknowledgement."""
import contextlib, http.client, http.server, tempfile, threading, uuid, json, urllib.request, urllib.error
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
  env=[('DSN',dsn),('URLS_SELF_ISSUER','http://127.0.0.1:4444/'),('SECRETS_SYSTEM','fixture-only-system-secret-32bytes'),('SECRETS_COOKIE','fixture-only-cookie-secret-32bytes'),('OAUTH2_PKCE_ENFORCED','true'),('STRATEGIES_ACCESS_TOKEN','opaque'),('LOG_LEVEL','error')]
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
   # Persist a signing key encrypted under the old system secret. The stock CLI owns key creation.
   providers.docker('exec',cid,'hydra','create','jwk','hydra.openid.id-token','fixture-old-key','--endpoint','http://127.0.0.1:4445','--public','--quiet')
   def public_keys(port):
    with urllib.request.urlopen(f'http://127.0.0.1:{port}/.well-known/jwks.json',timeout=5) as response:
     return {k['kid'] for k in json.load(response)['keys']}
   before=public_keys(ports[4444])
   if 'fixture-old-key' not in before:raise RuntimeError('old signing key not persisted')
   providers.docker('stop','--time','30',cid)
   new_system='fixture-new-system-secret-2339-32bytes'
   new_cookie='fixture-new-cookie-secret-2339-32bytes'
   rotated=[(k,new_system+',fixture-only-system-secret-32bytes' if k=='SECRETS_SYSTEM' else new_cookie+',fixture-only-cookie-secret-32bytes' if k=='SECRETS_COOKIE' else v) for k,v in env]
   rotated_id,rotated_ports=stack.enter_context(providers.container(providers.HYDRA,[4444,4445],env=rotated,args=['serve','all','--dev'],network=network))
   providers.wait(f'http://127.0.0.1:{rotated_ports[4445]}/health/ready')
   if not before<=public_keys(rotated_ports[4444]):raise RuntimeError('native keyring lost encrypted signing keys')
   server.upstream=rotated_ports[4445];server.startup_probes=0;server.ready=False
   variables['IDENTITY_TEST_CLIENT_PUBLIC_PORT']=str(rotated_ports[4444])
   providers.cargo('rss-identity-app','clients',variables)
   providers.docker('stop','--time','30',rotated_id)
   new_only=[(k,new_system if k=='SECRETS_SYSTEM' else new_cookie if k=='SECRETS_COOKIE' else v) for k,v in env]
   missing_id,missing_ports=stack.enter_context(providers.container(providers.HYDRA,[4444,4445],env=new_only,args=['serve','all','--dev'],network=network))
   providers.wait(f'http://127.0.0.1:{missing_ports[4445]}/health/ready')
   try:
    readable=before<=public_keys(missing_ports[4444])
   except urllib.error.HTTPError:
    readable=False
   if readable:raise RuntimeError('old encrypted keys unexpectedly readable without the old system key')
   print('Hydra keyring: new-first + retained old key reads persistent keys; premature old-key removal rejected')

  finally:server.shutdown();server.server_close();thread.join(timeout=5)
if __name__=='__main__':main()
