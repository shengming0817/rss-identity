#!/usr/bin/env python3
"""Private reference deployment, derived from the pre-component deploy.py mechanism.
One input generates runtime, maintenance, migration and static UI configuration.
"""
import argparse, copy, ipaddress, json, os, re, stat, subprocess, tempfile
from pathlib import Path
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parents[1]
IMAGES=json.loads((ROOT/'deployment/providers.lock.json').read_text())
UID=10001

def require(ok,message):
    if not ok: raise ValueError(message)
def fields(value,expected,scope):
    require(isinstance(value,dict) and set(value)==expected,'invalid '+scope+' fields')
def compose_literals(value):
    # Compose interpolates all string values, including bind paths and SQL passwords.
    if isinstance(value,str): return value.replace('$','$$')
    if isinstance(value,list): return [compose_literals(v) for v in value]
    if isinstance(value,dict): return {k:compose_literals(v) for k,v in value.items()}
    return value
def read(path,secret=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno()); limit=4096 if secret else 1048576
        require(stat.S_ISREG(info.st_mode) and info.st_size<=limit,'unsafe input file')
        require(not secret or not info.st_mode&0o077,'unsafe secret permissions')
        value=f.read(limit+1);require(0<len(value)<=limit,'invalid input length');return value

def inspect_image(reference, product=False):
    require(isinstance(reference,str) and reference and not reference.startswith('-'),'image required')
    def inspect(*args):
        result=subprocess.run(['docker','image','inspect',*args],check=True,capture_output=True,timeout=30)
        values=json.loads(result.stdout);require(len(values)==1,'ambiguous image')
        return values[0]
    # Containerd may return an unaddressable child manifest ID with --platform.
    # Keep the daemon's addressable image/index ID and validate its selected platform.
    identity=inspect(reference)['Id']
    require(re.fullmatch(r'sha256:[a-f0-9]{64}',identity),'invalid image ID')
    image=inspect('--platform','linux/amd64',identity)
    image['Id']=identity
    require(image['Os']=='linux' and image['Architecture']=='amd64','image platform must be linux/amd64')
    if product:
        require(image['Config']['User']=='10001:10001','image user must be 10001:10001')
        revision=(image['Config'].get('Labels') or {}).get('org.opencontainers.image.revision','')
        require(re.fullmatch('[a-f0-9]{40}',revision),'image revision required')
    return image

def resolve_images(identity_image,web_image):
    # Inspect only: the deployment owner explicitly builds or pulls beforehand.
    return {name:inspect_image(ref,name in ['identity','web'])['Id'] for name,ref in
            [('identity',identity_image),('web',web_image),('postgres',IMAGES['postgres']),('runtime',IMAGES['runtime'])]}

def stage(data,out,images,final):
    fields(data,{'runtime','ownerPasswordFile','maintenancePasswordFile','tlsCertificateFile','tlsKeyFile','postgresCertificateFile','postgresKeyFile','backendSubnet'},'deployment')
    require(os.geteuid()==0,'render as root for fixed service ownership')
    fields(images,{'identity','web','postgres','runtime'},'images')
    require(all(re.fullmatch(r'sha256:[a-f0-9]{64}',v) for v in images.values()),'immutable image IDs required')
    c=copy.deepcopy(data['runtime'])
    fields(c,{'formatVersion','instanceId','publicOrigin','bootstrapAccounts','database','storage','listen','publicGateway','budgets','oidc'},'runtime')
    require(c['formatVersion']==3,'unsupported runtime config')
    origin=c['publicOrigin'];u=urlsplit(origin)
    require(u.scheme=='https' and u.hostname and not u.username and not u.password and not u.path and not u.query and not u.fragment and u.port is None and re.fullmatch(r'[a-z0-9.-]+',u.hostname),'canonical HTTPS origin required')
    network=ipaddress.ip_network(data['backendSubnet']);require(network.version==4 and network.prefixlen==24 and network.is_private,'private /24 required')
    gateway,identity,postgres=(str(network.network_address+i) for i in (2,3,4))
    require(c['listen']=='0.0.0.0:8080' and c['publicGateway']==gateway,'ingress mismatch')
    require(c['database']['host']=='postgres' and c['database']['database']=='identity' and c['database']['user']=='identity_runtime' and c['database']['port']==5432,'database identity mismatch')
    tenants=c['storage']['tenants'];accounts=c['bootstrapAccounts']
    require(len(tenants)==len(set(tenants)) and 1<=len(tenants)<=128 and len(accounts)==len(tenants) and all(sum(a['tenantId']==t for a in accounts)==1 for t in tenants),'one bootstrap account per tenant required')
    os.chown(out,UID,UID)
    inputs=out/'input';inputs.mkdir(mode=0o700);os.chown(inputs,UID,UID)
    mounts={}
    def write(name,value):
        p=out/name;p.write_text(value);p.chmod(0o600);os.chown(p,UID,UID);return '/run/config/'+name
    def mount(path,name,secret=False):
        p=inputs/name;p.write_bytes(read(path,secret));p.chmod(0o600);os.chown(p,UID,UID)
        mounts[name]={'type':'bind','source':str(final/'input'/name),'target':'/run/input/'+name,'read_only':True}
        return mounts[name]['target']
    c['database']['passwordFile']=mount(c['database']['passwordFile'],'runtime-password',True)
    c['database']['caFile']=mount(c['database']['caFile'],'database-ca')
    runtime_files=['runtime-password','database-ca'];key_files=[]
    if c['oidc'] is not None:
        oidc=c['oidc'];oidc['stateKeyFile']=mount(oidc['stateKeyFile'],'state-key',True);runtime_files.append('state-key')
        require(oidc['returnTargets']=={'resume':origin+'/auth/resume'},'return target mismatch')
        for n,k in enumerate(oidc['credentialKeyring']['keys']):
            name='credential-key-'+str(n);k['path']=mount(k['path'],name,True);key_files.append(name)
        runtime_files+=key_files
        write('keyring.json',json.dumps(oidc['credentialKeyring']))
    write('runtime.json',json.dumps(c))
    maintenance_db={**c['database'],'user':'identity_maintenance','passwordFile':mount(data['maintenancePasswordFile'],'maintenance-password',True)}
    owner_db={**c['database'],'user':'postgres','passwordFile':mount(data['ownerPasswordFile'],'owner-password',True)}
    common={k:c[k] for k in ['formatVersion','instanceId','storage']}
    write('maintenance.json',json.dumps({**common,'bootstrapAccounts':c['bootstrapAccounts'],'database':maintenance_db}))
    write('migration.json',json.dumps({**common,'database':owner_db,'runtimeRole':'identity_runtime','maintenanceRole':'identity_maintenance'}))
    write('ui.json',json.dumps({'canonicalOrigin':origin,'oidcEnabled':c['oidc'] is not None}))
    def literal(value):return "'"+value.replace("'","''")+"'"
    sql='SET standard_conforming_strings=on;\nCREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS;\n'
    for role,name in [('identity_runtime','runtime-password'),('identity_maintenance','maintenance-password')]:
        value=(inputs/name).read_text();require('\x00' not in value,'invalid password')
        sql+=f'CREATE ROLE {role} LOGIN NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD {literal(value)};\n'
    sql+='REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n'
    write('00-roles.sql',sql)
    cert=mount(data['tlsCertificateFile'],'public-cert');key=mount(data['tlsKeyFile'],'public-key',True)
    pgcert=mount(data['postgresCertificateFile'],'postgres-cert');pgkey=mount(data['postgresKeyFile'],'postgres-key',True)
    # PostgreSQL loopback is operator-only; every remote connection requires TLS and SCRAM.
    write('pg_hba.conf','local all all trust\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::/0 scram-sha-256\nhostnossl all all 0.0.0.0/0 reject\nhostnossl all all ::/0 reject\n')
    proxy=f'proxy_bind {gateway}; proxy_http_version 1.1; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header Forwarded ""; proxy_set_header X-Real-IP ""; proxy_set_header X-Forwarded-Host ""; proxy_set_header X-Forwarded-Proto ""; proxy_set_header Host {u.hostname}; proxy_ignore_client_abort on; proxy_pass http://{identity}:8080;'
    write('gateway.conf',f'''pid /tmp/nginx.pid;
error_log stderr crit;
events {{}}
http {{
 access_log off; include /etc/nginx/mime.types;
 client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;
 proxy_next_upstream off; proxy_read_timeout 70s; proxy_send_timeout 70s; client_max_body_size 32k;
 server {{
  listen 8443 ssl; server_name {u.hostname};
  ssl_certificate {cert}; ssl_certificate_key {key}; ssl_protocols TLSv1.2 TLSv1.3;
  add_header Strict-Transport-Security "max-age=31536000" always;
  add_header X-Content-Type-Options nosniff always;
  add_header Referrer-Policy no-referrer always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
  add_header Cache-Control no-store always;
  location = /api/identity-host/v1/config.json {{ alias /run/config/ui.json; default_type application/json; }}
  location ^~ /api/v2/ {{ {proxy} }}
  location ~ "^/api/identity-host/v1/tenants/[0-9a-f-]{{36}}/context$" {{ {proxy} }}
  location ^~ /internal/ {{ return 404; }}
  location = /livez {{ return 404; }}
  location = /readyz {{ return 404; }}
  location /api/ {{ return 404; }}
  location / {{ root /usr/share/nginx/html; try_files $uri $uri/ /index.html; }}
 }}
}}
''')
    def files(names):
        return [mounts[n] if n in mounts else {'type':'bind','source':str(final/n),'target':'/run/config/'+n,'read_only':True} for n in names]
    def service(image,names,command=None):
        v={'image':image,'pull_policy':'never','platform':'linux/amd64','user':'10001:10001','read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'tmpfs':['/tmp:rw,noexec,nosuid,size=64m'],'networks':['backend'],'volumes':files(names)}
        if command:v['command']=command
        return v
    services={}
    services['postgres']=service(images['postgres'],['owner-password','postgres-cert','postgres-key','00-roles.sql','pg_hba.conf'],['postgres','-c','ssl=on','-c','ssl_cert_file='+pgcert,'-c','ssl_key_file='+pgkey,'-c','hba_file=/run/config/pg_hba.conf'])
    pg=services['postgres'];pg['read_only']=False;pg['environment']={'POSTGRES_USER':'postgres','POSTGRES_DB':'identity','POSTGRES_PASSWORD_FILE':'/run/input/owner-password','PGDATA':'/var/lib/postgresql/data/pgdata'}
    pg['volumes'][-2]['target']='/docker-entrypoint-initdb.d/00-roles.sql'
    pg['volumes'].append({'type':'volume','source':'pg','target':'/var/lib/postgresql/data','volume':{'nocopy':True}})
    # The entrypoint's temporary initialization server accepts Unix sockets only.
    # Require final TCP readiness before installation or pg_restore can start.
    pg['networks']={'backend':{'ipv4_address':postgres}};pg['healthcheck']={'test':['CMD','pg_isready','-h','127.0.0.1','-U','postgres'],'interval':'5s','timeout':'3s','retries':12}
    services['migrate']=service(images['identity'],['migration.json','owner-password','database-ca']+key_files+(['keyring.json'] if key_files else []),['--config','/run/config/migration.json'])
    services['migrate']['entrypoint']=['identity-migrate'];services['migrate']['profiles']=['operator'];services['migrate']['depends_on']={'postgres':{'condition':'service_healthy'}}
    services['maintenance']=service(images['identity'],['maintenance.json','maintenance-password','database-ca'])
    services['maintenance'].update(profiles=['operator'],entrypoint=['identity-admin','/run/config/maintenance.json'])
    services['identity']=service(images['identity'],runtime_files+['runtime.json'],['--config','/run/config/runtime.json'])
    app=services['identity'];app.update(restart='unless-stopped',stop_grace_period=str(c['budgets']['drainSeconds']+15)+'s',depends_on={'postgres':{'condition':'service_healthy'}})
    app['networks']={'backend':{'ipv4_address':identity}}
    if c['oidc'] is not None:app['networks']['egress']={}
    app['healthcheck']={'test':['CMD','identity-server','--probe','127.0.0.1:8080'],'interval':'10s','timeout':'15s','start_period':'15s','retries':3}
    services['gateway']=service(images['web'],['gateway.conf','ui.json','public-cert','public-key'],['-c','/run/config/gateway.conf'])
    services['gateway'].update(ports=['443:8443'],networks={'backend':{'ipv4_address':gateway},'public':{}},depends_on={'identity':{'condition':'service_healthy'}})
    services['volume-init']={'image':images['runtime'],'pull_policy':'never','platform':'linux/amd64','user':'0:0','network_mode':'none','profiles':['operator'],'entrypoint':['sh','-ec'],'command':['if [ -z "$(ls -A /volume)" ]; then chown 10001:10001 /volume; chmod 700 /volume; else test "$(stat -c %u:%g /volume)" = 10001:10001; fi'],'volumes':[{'type':'volume','source':'pg','target':'/volume','volume':{'nocopy':True}}]}
    for name in ['identity','gateway','migrate','maintenance']:services[name]['platform']='linux/amd64'
    networks={'backend':{'internal':True,'ipam':{'config':[{'subnet':str(network)}]}},'public':{}}
    if c['oidc'] is not None:networks['egress']={}
    write('compose.json',json.dumps(compose_literals({'services':services,'networks':networks,'volumes':{'pg':{}}}),indent=2))

def preflight(out,images):
    services=json.loads((out/'compose.json').read_text())['services']
    for binary,service,config in [('identity-server','identity','runtime'),('identity-admin','maintenance','maintenance'),('identity-migrate','migrate','migration')]:
        volumes=[]
        for mount in services[service]['volumes']:
            target=mount['target']
            source=out/('input/' if target.startswith('/run/input/') else '')/Path(target).name
            volumes+=['--volume',str(source)+':'+target+':ro']
        result=subprocess.run(['docker','run','--pull=never','--rm','--network','none','--platform','linux/amd64','--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',*volumes,'--entrypoint',binary,images['identity'],'--check-config','/run/config/'+config+'.json'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=60)
        require(result.returncode==0,'image configuration rejected')


def render(data,out,images):
    require(not out.exists() and not out.is_symlink(),'output must be new')
    # Same parent/filesystem for atomic publication; final Compose binds already name out.
    with tempfile.TemporaryDirectory(prefix='.'+out.name+'-',dir=out.parent) as temp:
        staged=Path(temp)
        stage(data,staged,images,out)
        preflight(staged,images)
        require(not out.exists() and not out.is_symlink(),'output must be new')
        staged.rename(out)


def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--identity-image',required=True);p.add_argument('--web-image',required=True);a=p.parse_args()
    try:render(json.loads(read(a.input)),a.output.resolve(),resolve_images(a.identity_image,a.web_image))
    except (ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError):raise SystemExit('deployment configuration rejected; no services started')
if __name__=='__main__':main()
