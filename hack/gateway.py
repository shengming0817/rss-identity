#!/usr/bin/env python3
"""Real NGINX TLS/header/path seam, with a local echo upstream, not the Identity product stack."""
import contextlib,http.client,ipaddress,json,ssl,subprocess,tempfile,time,os,socket
from unittest.mock import patch
from pathlib import Path
import deploy,providers
from test_deployment import Deployment

def main():
 with tempfile.TemporaryDirectory(prefix='identity-gateway-') as tmp, contextlib.ExitStack() as cleanup:
  root=Path(tmp);data=Deployment().data(root)
  network=root.name
  providers.docker('network','create',network)
  cleanup.callback(providers.docker,'network','rm',network)
  # Same renderer, loopback-only topology for the isolated protocol fixture.
  data['backend_subnet']='127.0.0.0/24';data['protocol_subnet']='192.0.2.0/24'
  data['runtime']['public_gateway']='127.0.0.2';data['runtime']['private_gateway']='127.0.0.3'
  data['runtime']['hydra']['addresses']=['192.0.2.5/32'];data['runtime']['oidc']['providers'][0]['addresses']=['192.0.2.2/32']
  cert=root/'tls.pem';key=root/'tls.key'
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30);key.chmod(0o600)
  for name in ['tls','hydra_admin','keycloak','postgres']:data[name+'_certificate_file']=str(cert);data[name+'_key_file']=str(key)
  data['runtime']['oidc']['ca_file']=str(cert)
  output=root/'rendered'
  with patch.object(deploy,'DEPLOY_UID',os.getuid()),patch.object(deploy,'DEPLOY_GID',os.getgid()),patch.object(deploy,'KEYCLOAK_UID',os.getuid()),patch.object(deploy,'KEYCLOAK_GID',os.getgid()):deploy.render(data,output,Deployment().candidate())
  compose=json.loads((output/'compose.json').read_text())
  context=ssl.create_default_context(cafile=str(cert))
  def request(port,path,headers):
   conn=http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=5)
   try:
    conn.request('GET',path,headers=headers);r=conn.getresponse();return r.status,r.read().decode()
   finally:conn.close()
  checks=0
  def check(value):
   nonlocal checks
   if not value:raise RuntimeError('gateway behavior mismatch')
   checks+=1
  for kind,service in [('public','public-gateway'),('private','private-gateway'),('hydra-admin','hydra-admin')]:
   conf=output/(kind+'.conf');source=conf.read_text()
   source=source.rsplit('}',1)[0]+'server { listen 127.0.0.4:8080; location / { return 200 "$http_x_forwarded_for|$remote_addr"; } } server { listen 127.0.0.1:4445; location / { return 200 "{}"; } }}'
   conf.write_text(source)
   mounts=[v['source']+':'+v['target']+':ro' for v in compose['services'][service]['volumes']]
   port=8443 if kind=='hydra-admin' else 443
   prepare=f"""mkdir -p /tmp/fixture; cp -R /run/input /tmp/fixture/input; cp /run/config/{kind}.conf /tmp/fixture/nginx.conf; sed -i "s#/run/input/#/tmp/fixture/input/#g" /tmp/fixture/nginx.conf; chown -R 10001:10001 /tmp/fixture; exec setpriv --reuid=10001 --regid=10001 --clear-groups sh -ec 'test "$(id -u)" = 10001; exec nginx -e stderr -c /tmp/fixture/nginx.conf -g "daemon off;"'"""
   with providers.container(deploy.IMAGES['nginx'],[port],args=['sh','-ec',prepare],mounts=mounts,user='0:0',sysctls=['net.ipv4.ip_unprivileged_port_start=0'],network=network) as (_,ports):
    for _ in range(60):
     try:status,_=request(ports[port],'/probe',{});break
     except (OSError,ssl.SSLError):time.sleep(.1)
    else:raise RuntimeError('gateway not ready')
    path='/api/probe' if kind=='public' else '/internal/v1/identity/validate'
    if kind=='hydra-admin':
     check(request(ports[port],'/health/ready',{})[0]==403)
     check(request(ports[port],'/health/ready',{'Authorization':'Bearer '+deploy.secret(data['runtime']['hydra']['service_secret_file'])})[0]==200)
    else:
     status,body=request(ports[port],path,{'X-Forwarded-For':'203.0.113.99','Forwarded':'for=203.0.113.99'})
     check(status==200);client,peer=body.split('|');ipaddress.ip_address(client)
     check(client!='203.0.113.99');check(peer==('127.0.0.2' if kind=='public' else '127.0.0.3'))
     forbidden='/internal/v1/identity/validate' if kind=='public' else '/api/probe'
     check(request(ports[port],forbidden,{})[0]==404)
  settings=json.loads((output/'hydra.json').read_text())
  with providers.container(deploy.IMAGES['hydra'],[4444,4445],env=[('DSN','memory'),('URLS_SELF_ISSUER','https://identity.test/oidc'),('SERVE_ADMIN_HOST',settings['serve']['admin']['host'])],args=['serve','all','--dev']) as (cid,ports):
   for _ in range(30):
    try:
     providers.docker('run','--rm','--network','container:'+cid,deploy.IMAGES['nginx'],'curl','--fail','--silent','--max-time','1','http://127.0.0.1:4445/health/ready');break
    except subprocess.SubprocessError:time.sleep(.1)
   else:raise RuntimeError('Hydra private listener unavailable')
   check(True)
   with socket.create_connection(('127.0.0.1',ports[4444]),timeout=2):check(True)
   outsider=http.client.HTTPConnection('127.0.0.1',ports[4445],timeout=2)
   try:
    outsider.request('GET','/health/ready');outsider.getresponse()
   except (OSError,http.client.HTTPException):check(True)
   else:raise RuntimeError('raw Hydra admin reachable outside its namespace')
   finally:outsider.close()
  if checks!=13:raise RuntimeError('gateway canonical checks incomplete')
  print('gateway T2: TLS, source overwrite, private paths and Hydra service authentication passed')
if __name__=='__main__':main()
