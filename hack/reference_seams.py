#!/usr/bin/env python3
"""Reproducible fixed-candidate/operator seams; does not assert product T3 acceptance."""
import argparse, copy, ipaddress, json, os, secrets, signal, subprocess, sys, tempfile, time
from pathlib import Path
import deploy
import operate

STEPS=['candidate','render','install','initialize','open','tls-ui-context','seed-credential','close','reject-new-key-before-rekey','render-rotation','rekey','render-new-key','verify-keys','verify','open-after-rekey','login-after-rekey','close-after-rekey','backup','check-backup','render-restore','restore','verify-restored-keys','open-restored','restored-login','close-restored']

def save(path,record):
    fd,name=tempfile.mkstemp(prefix='.'+path.name,dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(record,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def verify_record(path,candidate,runner):
    record=json.loads(path.read_text());subject=json.loads((candidate/'candidate.json').read_text())
    expected={'candidateSha256':operate.sha(candidate/'candidate.json'),'identityRevision':subject['revision'],'webRevision':subject['ui']['revision'],'runnerSha256':operate.sha(runner)}
    if set(record)!={'formatVersion','scope','subject','steps','result','failure','cleanup'} or type(record['formatVersion']) is not int or record['formatVersion']!=1:raise ValueError('record schema')
    if record['scope']!='candidate-operator-seams' or record['subject']!=expected:raise ValueError('record subject')
    if record['result']!='passed' or record['failure'] is not None or record['cleanup']!={'status':'passed','remaining':[]}:raise ValueError('record not successful')
    if not isinstance(record['steps'],list) or len(record['steps'])!=len(STEPS):raise ValueError('record steps')
    for entry,name in zip(record['steps'],STEPS):
        if set(entry)!={'name','status','elapsedMs'} or entry['name']!=name or entry['status']!='passed' or type(entry['elapsedMs']) is not int or entry['elapsedMs']<0:raise ValueError('record step')
    return record

def process(argv,**kwargs):
    result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,**kwargs)
    if result.returncode:raise RuntimeError('fixture process failed')
    return result.stdout

def free_subnets():
    ids=process(['docker','network','ls','--quiet']).decode().split()
    networks=json.loads(process(['docker','network','inspect',*ids])) if ids else []
    occupied=[ipaddress.ip_network(entry['Subnet']) for network in networks for entry in (network.get('IPAM',{}).get('Config') or []) if entry.get('Subnet')]
    selected=[]
    for subnet in ipaddress.ip_network('10.243.0.0/16').subnets(new_prefix=24):
        if not any(subnet.overlaps(existing) for existing in occupied):selected.append(str(subnet))
        if len(selected)==2:return selected
    raise ValueError('no isolated fixture subnets available')


HTTP='''import http.client,json,ssl,sys
v=json.load(sys.stdin)
c=http.client.HTTPSConnection('gateway',8443,context=ssl.create_default_context(cafile='/fixture-ca'),timeout=30)
c.request(v['method'],v['path'],json.dumps(v['body']) if v['body'] is not None else None,v['headers'])
r=c.getresponse();data=r.read(1048577)
assert len(data)<=1048576
print(json.dumps({'status':r.status,'headers':{k.lower():v for k,v in r.getheaders()},'body':data.decode()}))
c.close()
'''

def run(candidate,output,work):
    if os.geteuid()!=0:raise ValueError('reference runner requires Linux deployment owner root')
    if output.exists() or work.exists():raise ValueError('fresh record and work directory required')
    c=operate.candidate(candidate)
    if operate.sha(Path(__file__))!=c['tools']['reference_seams.py']:raise ValueError('runner candidate mismatch')
    record={'formatVersion':1,'scope':'candidate-operator-seams','subject':{'candidateSha256':operate.sha(candidate/'candidate.json'),'identityRevision':c['revision'],'webRevision':c['ui']['revision'],'runnerSha256':operate.sha(Path(__file__))},'steps':[],'result':'running','failure':None,'cleanup':{'status':'pending','remaining':[]}}
    save(output,record)
    work.mkdir(mode=0o700)
    prefix='identity-seam-'+secrets.token_hex(5);source=prefix+'-source';target=prefix+'-restored'
    projects={source:work/'old',target:work/'restored'}
    def step(name,action):
        entry={'name':name,'status':'running','elapsedMs':0};record['steps'].append(entry);save(output,record)
        start=time.monotonic()
        try:result=action()
        except BaseException:
            entry['status']='failed';raise
        else:entry['status']='passed';return result
        finally:entry['elapsedMs']=int((time.monotonic()-start)*1000);save(output,record)
    def op(project,directory,command,*args,expect_failure=False):
        result=subprocess.run([sys.executable,str(candidate/'operate.py'),'--candidate',str(candidate),'--deployment',str(directory),'--project',project,command,*map(str,args)],capture_output=True,timeout=240)
        if expect_failure:
            if result.returncode==0:raise AssertionError('new key unexpectedly decrypted old credentials')
            status=json.loads(result.stdout)
            if status['stage']!='verify-keys' or status['reason']!='process-failed' or not status['outcomeKnown']:raise AssertionError('wrong rejection')
        elif result.returncode:raise RuntimeError('operator '+command+' failed')
    def write(name,value):
        path=work/name;path.write_text(value);path.chmod(0o600);os.chown(path,10001,10001);return str(path)
    def http(project,path,body=None,headers=None):
        request={'method':'POST' if body is not None else 'GET','path':path,'body':body,'headers':{'Host':'identity.example.test','Origin':'https://identity.example.test','X-Identity-Request':'1','Content-Type':'application/json',**(headers or {})}}
        raw=process(['docker','run','--rm','--interactive','--network',project+'_public','--volume',str(work/'cert')+':/fixture-ca:ro','--entrypoint','python3',c['providers']['rust'],'-c',HTTP],input=json.dumps(request).encode())
        return json.loads(raw)
    previous={sig:signal.getsignal(sig) for sig in [signal.SIGINT,signal.SIGTERM]}
    def interrupted(signum,frame):raise SystemExit(128+signum)
    for sig in previous:signal.signal(sig,interrupted)
    try:
        step('candidate',lambda:op(source,work/'old','candidate'))
        process(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(work/'cert-key'),'-out',str(work/'cert'),'-days','2','-subj','/CN=identity-reference-fixture','-addext','subjectAltName=DNS:identity.example.test,DNS:gateway,DNS:postgres'])
        (work/'cert-key').chmod(0o600)
        data=json.loads((candidate/'deployment/deploy.example.json').read_text())
        runtime=data['runtime'];tenant=runtime['storage']['tenants'][0]
        password=secrets.token_hex(24);password_file=write('user-password',password)
        runtime['database'].update(passwordFile=write('runtime-password',secrets.token_hex(24)),caFile=str(work/'cert'))
        data.update(ownerPasswordFile=write('owner-password',secrets.token_hex(24)),maintenancePasswordFile=write('maintenance-password',secrets.token_hex(24)),tlsCertificateFile=str(work/'cert'),tlsKeyFile=str(work/'cert-key'),postgresCertificateFile=str(work/'cert'),postgresKeyFile=str(work/'cert-key'))
        old=write('old-key',secrets.token_hex(32));new=write('new-key',secrets.token_hex(32))
        runtime['oidc']={'groupFactsMaxAgeSeconds':300,'assuranceProfiles':[],'stateKeyFile':write('state-key',secrets.token_hex(32)),'credentialKeyring':{'activeKeyId':'old','keys':[{'keyId':'old','path':old}]},'returnTargets':{'resume':'https://identity.example.test/auth/resume'}}
        def render(name,ring,subnet):
            value=copy.deepcopy(data);value['backendSubnet']=subnet;value['runtime']['publicGateway']=subnet.rsplit('.',1)[0]+'.2';value['runtime']['oidc']['credentialKeyring']=ring
            deploy.render(value,work/name,c)
        source_subnet,target_subnet=free_subnets()
        ring=runtime['oidc']['credentialKeyring']
        step('render',lambda:render('old',ring,source_subnet))
        step('install',lambda:op(source,work/'old','install'))
        step('initialize',lambda:op(source,work/'old','initialize',tenant,'operator',password_file))
        step('open',lambda:op(source,work/'old','open'))
        def login(project):
            result=http(project,'/api/v2/tenants/'+tenant+'/login',{'login':'operator','password':password})
            if result['status']!=200:raise AssertionError('login failed')
            return {'Cookie':result['headers']['set-cookie'].split(';')[0],'X-CSRF-Token':json.loads(result['body'])['csrfToken']}
        session=login(source)
        def surfaces():
            for path in ['/tenants/'+tenant+'/login','/api/identity-host/v1/config.json','/api/identity-host/v1/tenants/'+tenant+'/context']:
                response=http(source,path,headers=session)
                if response['status']!=200:raise AssertionError('reference surface failed')
            if http(source,'/api/v1/health')['status']!=404:raise AssertionError('legacy path accepted')
        step('tls-ui-context',surfaces)
        def seed():
            result=http(source,'/api/v2/tenants/'+tenant+'/providers',{'settings':{'issuer':'https://idp.example.test','clientId':'fixture','redirectUri':'https://identity.example.test/api/v2/oidc/callback','scopes':['openid'],'claims':{'email':None,'groups':None},'jit':False},'clientSecret':secrets.token_hex(24),'caPem':None},session)
            if result['status']!=201:raise AssertionError('credential not created')
        step('seed-credential',seed)
        step('close',lambda:op(source,work/'old','close'))
        new_ring={'activeKeyId':'new','keys':[{'keyId':'new','path':new}]}
        # A real encrypted provider makes the negative check non-vacuous.
        def reject_new():
            render('negative',new_ring,source_subnet)
            op(source,work/'negative','verify-keys',expect_failure=True)
        step('reject-new-key-before-rekey',reject_new)
        mixed={'activeKeyId':'new','keys':[{'keyId':'old','path':old},{'keyId':'new','path':new}]}
        step('render-rotation',lambda:render('rotation',mixed,source_subnet))
        step('rekey',lambda:op(source,work/'rotation','rekey'))
        step('render-new-key',lambda:render('new',new_ring,source_subnet))
        step('verify-keys',lambda:op(source,work/'new','verify-keys'))
        step('verify',lambda:op(source,work/'new','verify'))
        step('open-after-rekey',lambda:op(source,work/'new','open'))
        step('login-after-rekey',lambda:login(source))
        step('close-after-rekey',lambda:op(source,work/'new','close'))
        backup=work/'backup.dump'
        step('backup',lambda:op(source,work/'new','backup',backup))
        step('check-backup',lambda:op(source,work/'new','check-backup',backup))
        step('render-restore',lambda:render('restored',new_ring,target_subnet))
        step('restore',lambda:op(target,work/'restored','restore',backup))
        step('verify-restored-keys',lambda:op(target,work/'restored','verify-keys'))
        step('open-restored',lambda:op(target,work/'restored','open'))
        step('restored-login',lambda:login(target))
        step('close-restored',lambda:op(target,work/'restored','close'))
        record['result']='passed'
    except BaseException as error:
        record['result']='failed';record['failure']={'stage':record['steps'][-1]['name'] if record['steps'] else 'environment','reason':'interrupted' if isinstance(error,(KeyboardInterrupt,SystemExit)) else 'execution-or-assertion'}
    finally:
        for sig in previous:signal.signal(sig,signal.SIG_IGN)
        remaining=[]
        for project,directory in projects.items():
            try:
                if (directory/'compose.json').exists():process(['docker','compose','--project-name',project,'--file',str(directory/'compose.json'),'down','--volumes','--remove-orphans'])
                for kind,fmt in [('ps','{{.ID}}'),('volume','{{.Name}}'),('network','{{.ID}}')]:
                    argv=['docker',kind]+(['--all'] if kind=='ps' else ['ls'])+['--filter','label=com.docker.compose.project='+project,'--format',fmt]
                    if process(argv).strip():remaining.append(project+':'+kind)
            except BaseException:remaining.append(project)
        record['cleanup']={'status':'failed' if remaining else 'passed','remaining':remaining}
        if remaining:record['result']='failed';record['failure']=record['failure'] or {'stage':'cleanup','reason':'unconfirmed'}
        save(output,record)
        for sig,handler in previous.items():signal.signal(sig,handler)
    verify_record(output,candidate,Path(__file__))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--candidate',type=Path,required=True);parser.add_argument('--record',type=Path,required=True);parser.add_argument('--work',type=Path);parser.add_argument('--verify-record',action='store_true');args=parser.parse_args()
    if args.verify_record:verify_record(args.record,args.candidate,Path(__file__))
    else:
        if args.work is None:parser.error('--work required for execution')
        run(args.candidate.resolve(),args.record.resolve(),args.work.resolve())
if __name__=='__main__':main()
