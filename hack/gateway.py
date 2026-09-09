#!/usr/bin/env python3
"""Real NGINX TLS/header/path seam, with a local echo upstream, not the Identity product stack."""
import contextlib,http.client,ipaddress,json,ssl,subprocess,tempfile,time
from pathlib import Path
import deploy,providers
from test_deployment import Deployment

def main():
 with tempfile.TemporaryDirectory(prefix='identity-gateway-') as tmp:
  root=Path(tmp);data=Deployment().data(root)
  # Same renderer, loopback-only topology for the isolated protocol fixture.
  data['backend_subnet']='127.0.0.0/24';data['protocol_subnet']='192.0.2.0/24'
  data['runtime']['public_gateway']='127.0.0.2';data['runtime']['private_gateway']='127.0.0.3'
  data['runtime']['hydra']['addresses']=['192.0.2.5/32'];data['runtime']['oidc']['providers'][0]['addresses']=['192.0.2.2/32']
  cert=root/'tls.pem';key=root/'tls.key'
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30);key.chmod(0o600)
  for name in ['tls','hydra_admin','keycloak','postgres']:data[name+'_certificate_file']=str(cert);data[name+'_key_file']=str(key)
  data['runtime']['oidc']['ca_file']=str(cert)
  output=root/'rendered';deploy.render(data,output,{'server':'unused','operator':'unused','gateway':'unused'})
  compose=json.loads((output/'compose.json').read_text())
  context=ssl.create_default_context(cafile=str(cert))
  def request(port,path,headers):
   conn=http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=5)
   try:
    conn.request('GET',path,headers=headers);r=conn.getresponse();return r.status,r.read().decode()
   finally:conn.close()
  for kind,service in [('public','public-gateway'),('private','private-gateway'),('hydra-admin','hydra-admin')]:
   conf=output/(kind+'.conf');source=conf.read_text().replace('listen 443 ssl','listen 8443 ssl').replace('http://hydra:4444/','http://127.0.0.1:4444/').replace('http://hydra:4445','http://127.0.0.1:4445').replace('https://keycloak:8443','https://127.0.0.1:8444')
   source=source.rsplit('}',1)[0]+'server { listen 127.0.0.4:8080; location / { return 200 "$http_x_forwarded_for|$remote_addr"; } } server { listen 127.0.0.1:4445; location / { return 200 "{}"; } }}'
   conf.write_text(source)
   mounts=[v['source']+':'+v['target']+':ro' for v in compose['services'][service]['volumes']]
   with providers.container(deploy.IMAGES['nginx'],[8443],args=['nginx','-c','/run/config/'+kind+'.conf','-g','daemon off;'],mounts=mounts) as (_,ports):
    for _ in range(60):
     try:status,_=request(ports[8443],'/probe',{});break
     except (OSError,ssl.SSLError):time.sleep(.1)
    else:raise RuntimeError('gateway not ready')
    path='/api/probe' if kind=='public' else '/internal/v1/identity/validate'
    if kind=='hydra-admin':
     assert request(ports[8443],'/health/ready',{})[0]==403
     assert request(ports[8443],'/health/ready',{'Authorization':'Bearer '+deploy.secret(data['runtime']['hydra']['service_secret_file'])})[0]==200
    else:
     status,body=request(ports[8443],path,{'X-Forwarded-For':'203.0.113.99','Forwarded':'for=203.0.113.99'})
     assert status==200;client,peer=body.split('|');ipaddress.ip_address(client)
     assert client!='203.0.113.99';assert peer==('127.0.0.2' if kind=='public' else '127.0.0.3')
     forbidden='/internal/v1/identity/validate' if kind=='public' else '/api/probe'
     assert request(ports[8443],forbidden,{})[0]==404
  print('gateway T2: TLS, source overwrite, private paths and Hydra service authentication passed')
if __name__=='__main__':main()
