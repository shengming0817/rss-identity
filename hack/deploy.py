#!/usr/bin/env python3
"""Render the one supported Compose topology from a versioned deployment input.
Output contains secrets: use a private runtime directory, never commit or publish it.
"""
import argparse,copy,ipaddress,json,os,re,stat
from pathlib import Path
from urllib.parse import urlsplit,quote
ROOT=Path(__file__).resolve().parents[1] if Path(__file__).resolve().parent.name=='hack' else Path(__file__).resolve().parent
DEPLOY_UID=10001
DEPLOY_GID=10001
KEYCLOAK_UID=1000
KEYCLOAK_GID=0
IMAGES=json.loads((ROOT/'deployment/providers.lock.json').read_text())
class ConfigurationError(ValueError):
 """Messages are code-owned diagnostics, never interpolated input values."""
def require(ok,message):
 if not ok:raise ConfigurationError(message)
def configuration_diagnostic(error):
 if isinstance(error,ConfigurationError):return str(error)
 if isinstance(error,KeyError):return 'missing_required_field'
 if isinstance(error,OSError):return 'file_access_failed'
 return 'invalid_configuration'
def fields(data,expected,scope):
 require(isinstance(data,dict),'invalid '+scope+' object')
 missing=sorted(expected-set(data))
 require(not missing,scope+' missing fields: '+','.join(missing))
 require(not set(data)-expected,scope+' unexpected fields')
def secret(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd) as f:
  m=os.fstat(f.fileno());require(stat.S_ISREG(m.st_mode) and not m.st_mode&0o077 and m.st_size<=4096,'unsafe secret file')
  value=f.read(4097);require(0<len(value)<=4096 and '\x00' not in value,'invalid secret file');return value
def host(origin):
 u=urlsplit(origin);require(u.scheme=='https' and u.hostname and not u.username and not u.password and not u.path and not u.query and not u.fragment and u.port in (None,443),'invalid HTTPS origin')
 require(re.fullmatch(r'[a-z0-9.-]+',u.hostname),'invalid DNS hostname');return u.hostname
def sql_literal(value):return "'"+value.replace("'","''")+"'"
def render(data,out,candidate):
 images=candidate['providers'];artifacts=candidate['images']
 require(set(images)==set(IMAGES) and set(artifacts)=={'server','operator','gateway'},'incomplete candidate images')
 require(all(re.fullmatch(r'[A-Za-z0-9_./:-]+@sha256:[a-f0-9]{64}',v) for v in [*images.values(),*artifacts.values()]),'candidate images must have exact digests')
 require(os.getuid()==0 or (os.getuid()==DEPLOY_UID==KEYCLOAK_UID and os.getgid()==DEPLOY_GID==KEYCLOAK_GID),'render as root to deliver provider-specific ownership')
 require(isinstance(data,dict),'invalid deployment object')
 require(not any(k in data for k in ('hydra_system_secret_file','hydra_cookie_secret_file')),'removed singular Hydra secret fields; use hydra_system_secret_files and hydra_cookie_secret_files')
 fields(data,{'runtime','owner_password_file','maintenance_password_file','hydra_database_password_file','keycloak_database_password_file','hydra_system_secret_files','hydra_cookie_secret_files','tls_certificate_file','tls_key_file','hydra_admin_certificate_file','hydra_admin_key_file','keycloak_certificate_file','keycloak_key_file','postgres_certificate_file','postgres_key_file','backend_subnet','protocol_subnet','consumer_network'},'deployment')
 for provider in data['runtime']['oidc']['providers']:
  require('keycloak_totp' in provider,'provider missing field: keycloak_totp')
  require(type(provider['keycloak_totp']) is bool,'invalid keycloak_totp approval')
 require(not out.exists(),'output directory must be new');out.mkdir(mode=0o700,parents=True);os.chown(out,DEPLOY_UID,DEPLOY_GID)
 c=copy.deepcopy(data['runtime']);origin=c['identity_origin'];ih=host(origin['identity_public_origin']);ph=host(origin['product_public_origin']);require(ih!=ph,'distinct origins required')
 back=ipaddress.ip_network(data['backend_subnet']);proto=ipaddress.ip_network(data['protocol_subnet']);require(back.version==4 and proto.version==4 and back.prefixlen==24 and proto.prefixlen==24 and not back.overlaps(proto),'distinct /24 networks required')
 pub,priv,app=(str(back.network_address+i) for i in (2,3,4))
 require(c['listen']=='0.0.0.0:8080' and c['public_gateway']==pub and c['private_gateway']==priv,'runtime ingress differs from topology')
 require(c['database']['host']=='postgres' and c['database']['database']=='identity' and c['database']['user']=='identity_runtime','unsupported runtime database binding')
 require(c['hydra']['admin_url']=='https://hydra-admin:8443' and c['hydra']['addresses']==[str(proto.network_address+5)+'/32'],'invalid Hydra network binding')
 mounts={};generated={}
 def mounted(path,key,private=False,owner=None):
  path=str(Path(path).resolve());require(Path(path).is_file(),'missing deployment file')
  if private:
   secret(path);m=Path(path).stat();require((m.st_uid,m.st_gid)==(owner or (DEPLOY_UID,DEPLOY_GID)),'secret owner must match service UID/GID')
  target='/run/input/'+key;mounts[key]={'type':'bind','source':path,'target':target,'read_only':True};return target
 def write(name,value,owner=None):
  uid,gid=owner or (DEPLOY_UID,DEPLOY_GID)
  p=out/name;p.write_text(value);p.chmod(0o600);os.chown(p,uid,gid)
  m=p.stat();require((m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode))==(uid,gid,0o600),'generated file ownership mismatch')
  generated[name]={'type':'bind','source':str(p.resolve()),'target':'/run/config/'+name,'read_only':True};return p
 def remap_db(db,prefix):
  v=copy.deepcopy(db);v['password_file']=mounted(db['password_file'],prefix+'-password',True);v['ca_file']=mounted(db['ca_file'],prefix+'-ca');return v
 c['database']=remap_db(c['database'],'runtime');c['oidc']['ca_file']=mounted(c['oidc']['ca_file'],'oidc-ca');c['oidc']['state_key_file']=mounted(c['oidc']['state_key_file'],'state-key',True)
 idp_hosts=set();realms={}
 for n,p in enumerate(c['oidc']['providers']):
  u=urlsplit(p['issuer']);idp_hosts.add(host('https://'+u.netloc));require(re.fullmatch(r'/realms/[A-Za-z0-9_-]+',u.path),'Keycloak realm issuer required')
  require(p['addresses']==[str(proto.network_address+2)+'/32'],'OIDC must use the fixed TLS gateway')
  value=secret(p['secret_file']);p['secret_file']=mounted(p['secret_file'],'idp-'+str(n),True)
  realm=u.path.split('/')[-1];realms.setdefault(realm,{'realm':realm,'enabled':True,'sslRequired':'all','clients':[]})['clients'].append({'clientId':p['client_id'],'secret':value,'publicClient':False,'standardFlowEnabled':True,'directAccessGrantsEnabled':False,'serviceAccountsEnabled':False,'redirectUris':[origin['identity_public_origin']+'/api/v1/oidc/callback'],'attributes':{'pkce.code.challenge.method':'S256'}})
 for p in c['oidc']['providers']:
  if p['keycloak_totp']:realms[urlsplit(p['issuer']).path.split('/')[-1]].update(json.loads((ROOT/'deployment/keycloak-totp.json').read_text()))
 require(len(idp_hosts)==1,'reference profile requires one Keycloak hostname');idph=next(iter(idp_hosts));require(idph not in (ih,ph),'IdP origin must be distinct')
 c['hydra']['ca_file']=mounted(c['hydra']['ca_file'],'hydra-ca');service=secret(c['hydra']['service_secret_file']);require(re.fullmatch(r'[A-Za-z0-9_-]{32,256}',service),'Hydra gateway secret must be base64url')
 c['hydra']['service_secret_file']=mounted(c['hydra']['service_secret_file'],'hydra-service',True)
 for n,client in enumerate(c['hydra']['clients']):
  oidc_secret=secret(client['oidc_secret_file']);require(oidc_secret!=secret(client['validation_secret_file']),'client secret domains overlap')
  client['oidc_secret_file']=mounted(client['oidc_secret_file'],'client-oidc-'+str(n),True);client['validation_secret_file']=mounted(client['validation_secret_file'],'client-validation-'+str(n),True)
 runtime_keys=set(mounts);write('runtime.json',json.dumps(c))
 owner_db=copy.deepcopy(c['database']);owner_db['user']='postgres';owner_db['password_file']=mounted(data['owner_password_file'],'owner-password',True)
 migration={'format_version':1,'identity_origin':origin,'database':owner_db,'storage':c['storage'],'runtime_password_file':c['database']['password_file'],'maintenance_password_file':mounted(data['maintenance_password_file'],'maintenance-password',True)}
 write('migration.json',json.dumps(migration))
 maintenance=copy.deepcopy(data['runtime']['database']);maintenance['user']='identity_maintenance';maintenance['password_file']=mounts['maintenance-password']['target'];maintenance['ca_file']=c['database']['ca_file'];require(len(c['storage']['tenants'])>=1,'missing maintenance tenant')
 maintenance.update(identity_origin=origin,tenant_id=c['storage']['tenants'][0]['tenant_id'],storage_target=c['storage']['target'],storage_lineage=c['storage']['lineage'],storage_tenant_epoch=c['storage']['tenants'][0]['epoch']);write('maintenance.json',json.dumps(maintenance))
 hp=secret(data['hydra_database_password_file']);kp=secret(data['keycloak_database_password_file']);require(hp!=kp and re.fullmatch(r'[A-Za-z0-9_-]{32,256}',kp),'invalid provider passwords')
 write('00-databases.sql',f"SET standard_conforming_strings=on;\nCREATE USER hydra WITH PASSWORD {sql_literal(hp)};\nCREATE DATABASE hydra OWNER hydra;\nCREATE USER keycloak WITH PASSWORD {sql_literal(kp)};\nCREATE DATABASE keycloak OWNER keycloak;\n")
 def keyring(paths):
  require(isinstance(paths,list) and 1<=len(paths)<=8 and all(isinstance(p,str) for p in paths),'invalid Hydra key file list')
  values=[secret(p) for p in paths]
  require(all(len(v)>=32 and not any(ch in v for ch in '\r\n') for v in values) and len(set(values))==len(values),'invalid or duplicate Hydra keys')
  for p in paths:
   m=Path(p).stat();require((m.st_uid,m.st_gid)==(DEPLOY_UID,DEPLOY_GID),'Hydra secret owner must match service')
  return values
 system_keys=keyring(data['hydra_system_secret_files']);cookie_keys=keyring(data['hydra_cookie_secret_files'])
 require(not set(system_keys)&set(cookie_keys),'Hydra key domains overlap')
 hydra={'serve':{'admin':{'host':'127.0.0.1','port':4445},'public':{'host':'0.0.0.0','port':4444}},'dsn':'postgres://hydra:'+quote(hp,safe='')+'@postgres:5432/hydra?sslmode=verify-full&sslrootcert=/run/input/runtime-ca','urls':{'self':{'issuer':origin['identity_public_origin']+'/oidc'},'login':origin['identity_public_origin']+'/login','consent':origin['identity_public_origin']+'/consent'},'secrets':{'system':system_keys,'cookie':cookie_keys},'oauth2':{'pkce':{'enforced':True}},'strategies':{'access_token':'opaque'},'ttl':{'login_consent_request':str(c['hydra']['request_seconds'])+'s','auth_code':str(c['hydra']['code_seconds'])+'s','access_token':str(c['hydra']['access_token_seconds'])+'s'},'log':{'level':'error'}}
 write('hydra.json',json.dumps(hydra))
 for realm,v in realms.items():write('realm-'+realm+'.json',json.dumps(v),(KEYCLOAK_UID,KEYCLOAK_GID))
 cert=mounted(data['tls_certificate_file'],'public-cert');key=mounted(data['tls_key_file'],'public-key',True)
 hc=mounted(data['hydra_admin_certificate_file'],'hydra-cert');hk=mounted(data['hydra_admin_key_file'],'hydra-key',True)
 pc=mounted(data['postgres_certificate_file'],'postgres-cert');pk=mounted(data['postgres_key_file'],'postgres-key',True)
 kc=mounted(data['keycloak_certificate_file'],'keycloak-cert');kk=mounted(data['keycloak_key_file'],'keycloak-key',True,(KEYCLOAK_UID,KEYCLOAK_GID))
 write('keycloak.conf',f'db=postgres\ndb-url=jdbc:postgresql://postgres:5432/keycloak?sslmode=verify-full&sslrootcert=/run/input/runtime-ca\ndb-username=keycloak\ndb-password={kp}\nhostname=https://{idph}\nhttps-certificate-file={kc}\nhttps-certificate-key-file={kk}\nhttp-enabled=false\nhealth-enabled=true\n',(KEYCLOAK_UID,KEYCLOAK_GID))
 def nginx(servers):return 'pid /tmp/nginx.pid;\nerror_log stderr crit;\nevents {}\nhttp { access_log off; error_log stderr crit; client_body_temp_path /tmp/client; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; proxy_temp_path /tmp/proxy; include /etc/nginx/mime.types; proxy_next_upstream off; proxy_read_timeout 70s; proxy_send_timeout 70s; client_max_body_size 32k; '+servers+'}\n'
 tls=f'ssl_certificate {cert}; ssl_certificate_key {key}; ssl_protocols TLSv1.2 TLSv1.3;'
 proxy=f'proxy_bind {pub}; proxy_http_version 1.1; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header Forwarded ""; proxy_set_header Host {ih}; proxy_ignore_client_abort on;'
 write('public.conf',nginx(f'server {{ listen 8443 ssl; server_name {ih}; {tls} location ^~ /internal/ {{ return 404; }} location = /livez {{ return 404; }} location = /readyz {{ return 404; }} location ^~ /api/ {{ {proxy} proxy_pass http://{app}:8080; }} location /oidc/ {{ proxy_set_header Host {ih}; proxy_set_header X-Forwarded-Proto https; proxy_pass http://hydra:4444/; }} location / {{ root /usr/share/nginx/html; try_files $uri $uri/ /index.html; add_header Referrer-Policy no-referrer always; }} }} server {{ listen 8443 ssl; server_name {idph}; {tls} location / {{ proxy_ssl_verify on; proxy_ssl_trusted_certificate /run/input/oidc-ca; proxy_ssl_server_name on; proxy_ssl_name keycloak; proxy_set_header Host {idph}; proxy_pass https://keycloak:8443; }} }}'))
 write('private.conf',nginx(f'server {{ listen 443 ssl; server_name {ih}; {tls} location = /internal/v1/identity/validate {{ proxy_bind {priv}; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header Forwarded ""; proxy_http_version 1.1; proxy_pass http://{app}:8080; }} location / {{ return 404; }} }}'))
 write('hydra-admin.conf',nginx(f'server {{ listen 8443 ssl; server_name hydra-admin; ssl_certificate {hc}; ssl_certificate_key {hk}; if ($http_authorization != "Bearer {service}") {{ return 403; }} location / {{ proxy_set_header Authorization ""; proxy_pass http://127.0.0.1:4445; }} }}'))
 def service(image,files,nets,command=None):
  v={'image':image,'user':str(DEPLOY_UID)+':'+str(DEPLOY_GID),'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'tmpfs':['/tmp:rw,noexec,nosuid,size=64m'],'networks':nets,'volumes':[mounts[x] if x in mounts else generated[x] for x in files]}
  if command:v['command']=command
  return v
 sv={}
 sv['postgres']={'image':images['postgres'],'user':str(DEPLOY_UID)+':'+str(DEPLOY_GID),'environment':{'POSTGRES_USER':'postgres','POSTGRES_DB':'identity','POSTGRES_PASSWORD_FILE':mounts['owner-password']['target']},'volumes':[mounts['owner-password'],mounts['runtime-ca'],mounts['postgres-cert'],mounts['postgres-key'],{**generated['00-databases.sql'],'target':'/docker-entrypoint-initdb.d/00-databases.sql'},{'type':'volume','source':'pg','target':'/var/lib/postgresql/data','volume':{'nocopy':True}}],'command':['postgres','-c','ssl=on','-c','ssl_cert_file='+pc,'-c','ssl_key_file='+pk],'networks':['protocol'],'healthcheck':{'test':['CMD','pg_isready','-U','postgres'],'interval':'5s','timeout':'3s','retries':12}}
 sv['migrate']=service(artifacts['operator'],['migration.json','owner-password','runtime-ca','runtime-password','maintenance-password'],['protocol'],['--config','/run/config/migration.json']);sv['migrate']['profiles']=['install'];sv['migrate']['depends_on']={'postgres':{'condition':'service_healthy'}}
 sv['maintenance']=service(artifacts['operator'],['maintenance.json','runtime-ca','maintenance-password'],['protocol']);sv['maintenance']['entrypoint']=['/usr/local/bin/identity-admin','/run/config/maintenance.json'];sv['maintenance']['profiles']=['maintenance']
 sv['identity']=service(artifacts['server'],sorted(runtime_keys)+['runtime.json'],{'backend':{'ipv4_address':app},'protocol':{}},['--config','/run/config/runtime.json']);sv['identity'].update(restart='unless-stopped',stop_grace_period=str(c['budgets']['drain_seconds']+15)+'s',depends_on={'postgres':{'condition':'service_healthy'},'hydra':{'condition':'service_started'}})
 common=['hydra.json','runtime-ca']
 sv['hydra-migrate']=service(images['hydra'],common,['protocol'],['migrate','sql','-e','--yes','--config','/run/config/hydra.json']);sv['hydra-migrate']['profiles']=['install'];sv['hydra-migrate']['depends_on']={'postgres':{'condition':'service_healthy'}}
 sv['hydra']=service(images['hydra'],common,{'protocol':{'ipv4_address':str(proto.network_address+5),'aliases':['hydra-admin']}},['serve','all','--config','/run/config/hydra.json']);sv['hydra']['restart']='unless-stopped';sv['hydra']['healthcheck']={'test':['CMD','wget','-q','-T','3','-O','/dev/null','http://127.0.0.1:4445/health/ready'],'interval':'2s','timeout':'4s','start_period':'10s','retries':30}
 sv['hydra-clients']=service(artifacts['operator'],['runtime.json']+['client-oidc-'+str(n) for n in range(len(c['hydra']['clients']))],[],['--config','/run/config/runtime.json']);sv['hydra-clients'].pop('networks');sv['hydra-clients'].update(entrypoint=['identity-clients'],network_mode='service:hydra',profiles=['install'],depends_on={'hydra':{'condition':'service_healthy'}})
 kfiles=['keycloak.conf','keycloak-cert','keycloak-key','runtime-ca']+['realm-'+r+'.json' for r in realms]
 sv['keycloak']=service(images['keycloak'],kfiles,['protocol'],['--config-file=/run/config/keycloak.conf','start','--import-realm']);sv['keycloak']['user']=str(KEYCLOAK_UID)+':'+str(KEYCLOAK_GID);sv['keycloak']['read_only']=False;sv['keycloak']['volumes'] += [{'type':'volume','source':'keycloak','target':'/opt/keycloak/data','volume':{'nocopy':True}}];sv['keycloak']['restart']='unless-stopped'
 for mount in sv['keycloak']['volumes']:
  if isinstance(mount,dict) and Path(mount['source']).name.startswith('realm-'):mount['target']='/opt/keycloak/data/import/'+Path(mount['source']).name
 sv['public-gateway']=service(artifacts['gateway'],['public.conf','public-cert','public-key','oidc-ca'],{'backend':{'ipv4_address':pub},'protocol':{'ipv4_address':str(proto.network_address+2),'aliases':[ih,idph]}},['-c','/run/config/public.conf']);sv['public-gateway']['ports']=['443:8443']
 sv['private-gateway']=service(artifacts['gateway'],['private.conf','public-cert','public-key'],{'backend':{'ipv4_address':priv},'consumer':{'aliases':[ih]}},['-c','/run/config/private.conf'])
 sv['private-gateway']['sysctls']={'net.ipv4.ip_unprivileged_port_start':'0'}
 sv['hydra-admin']=service(images['nginx'],['hydra-admin.conf','hydra-cert','hydra-key'],{'protocol':{'ipv4_address':str(proto.network_address+5)}},['nginx','-e','stderr','-c','/run/config/hydra-admin.conf','-g','daemon off;']);sv['hydra-admin']['entrypoint']=[]
 sv['identity']['healthcheck']={'test':['CMD','identity-server','--probe','127.0.0.1:8080'],'interval':'10s','timeout':'15s','start_period':'15s','retries':3}
 sv['public-gateway']['depends_on']={'identity':{'condition':'service_healthy'}}
 sv['private-gateway']['depends_on']={'identity':{'condition':'service_healthy'}}
 sv['hydra-admin'].pop('networks');sv['hydra-admin']['network_mode']='service:hydra';sv['hydra-admin']['depends_on']=['hydra']
 sv['volume-init']={'image':images['runtime'],'user':'0:0','network_mode':'none','profiles':['install'],'entrypoint':['sh','-ec'],'command':['for spec in /volumes/pg:10001:10001 /volumes/keycloak:1000:0; do d="${spec%%:*}"; owner="${spec#*:}"; if [ -n "$(find "$d" -mindepth 1 -maxdepth 1 -print -quit)" ]; then test "$(stat -c %u:%g "$d")" = "$owner" || exit 1; else chown "$owner" "$d"; chmod 700 "$d"; fi; done'.replace('$','$$')],'volumes':[{'type':'volume','source':n,'target':'/volumes/'+n,'volume':{'nocopy':True}} for n in ['pg','keycloak']]}

 networks={'backend':{'internal':True,'ipam':{'config':[{'subnet':str(back)}]}},'protocol':{'internal':True,'ipam':{'config':[{'subnet':str(proto)}]}},'consumer':{'external':True,'name':data['consumer_network']}}
 write('compose.json',json.dumps({'name':'rss-identity','services':sv,'networks':networks,'volumes':{'pg':{},'keycloak':{}}},indent=2))
 return out/'compose.json'
def main():
 p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);a=p.parse_args()
 try:render(json.loads(a.input.read_text()),a.output,json.loads(a.candidate.read_text()))
 except (ValueError,KeyError,OSError,TypeError) as e:raise SystemExit('deployment rendering refused: '+configuration_diagnostic(e))
if __name__=='__main__':main()
