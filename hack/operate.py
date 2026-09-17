#!/usr/bin/env python3
"""Bounded reference operations. No retries, implicit initialization, or restore into a live volume."""
import argparse, contextlib, fcntl, hashlib, json, os, re, stat, subprocess, tarfile, uuid
from pathlib import Path

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def tree(path):
    h=hashlib.sha256()
    for p in sorted(path.rglob('*')):
        if p.is_symlink():raise Rejection('artifact-symlink')
        if p.is_file():h.update(p.relative_to(path).as_posix().encode()+b'\0'+p.read_bytes()+b'\0')
    return h.hexdigest()
def candidate(root):
    c=json.loads((root/'candidate.json').read_text())
    if c['identity_schema']!=9 or c['config_version']!=3:raise Rejection('candidate-contract')
    for name,entry in c['archives'].items():
        if name not in ['server','operator','gateway'] or entry['file']!=name+'.oci.tar':raise Rejection('archive-identity')
        path=root/entry['file']
        if sha(path)!=entry['sha256']:raise Rejection('archive-digest')
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if m.name.startswith('blobs/sha256/') and m.isfile():
                    if hashlib.sha256(t.extractfile(m).read()).hexdigest()!=m.name.split('/')[-1]:raise Rejection('oci-blob-digest')
    if set(c['archives'])!={'server','operator','gateway'} or set(c['binaries'])!={'identity-server','identity-admin','identity-migrate'}:raise Rejection('incomplete-artifacts')
    for name,digest in c['binaries'].items():
        if sha(root/'binaries'/name)!=digest:raise Rejection('binary-digest')
    for name in ['deploy.py','operate.py','reference_seams.py']:
        if sha(root/name)!=c['tools'][name]:raise Rejection('operator-digest')
    if tree(root/'deployment')!=c['deployment_sha256']:raise Rejection('deployment-digest')
    return c

class OperationError(RuntimeError):
    def __init__(self,stage,reason,outcome_known):
        self.stage=stage;self.reason=reason;self.outcome_known=outcome_known
        super().__init__('operation outcome unknown' if not outcome_known else reason)

class Rejection(OperationError,ValueError):
    def __init__(self,reason):super().__init__('precondition',reason,True)

def command(args,stage='inspect',mutating=False,**kwargs):
    # Never include subprocess arguments, stdout or stderr in public diagnostics.
    try:result=subprocess.run(args,timeout=180,stderr=subprocess.PIPE,**kwargs)
    except (OSError,subprocess.SubprocessError):
        raise OperationError(stage,'process-unconfirmed',not mutating) from None
    if result.returncode:raise OperationError(stage,'process-failed',not mutating)
    return result

def project_name(value):
    return isinstance(value,str) and re.fullmatch('[a-z][a-z0-9_-]{2,47}',value)

def check_backup(path,c=None,config=None):
    record=json.loads(path.with_suffix(path.suffix+'.json').read_text())
    if not isinstance(record,dict) or set(record)!={'schema','instanceId','storage','candidate','project','sha256'}:raise Rejection('backup-receipt-fields')
    if type(record['schema']) is not int or record['schema']!=9:raise Rejection('backup-schema')
    if not project_name(record['project']):raise Rejection('backup-project')
    for key,size in [('candidate',40),('sha256',64)]:
        if not isinstance(record[key],str) or not re.fullmatch('[a-f0-9]{'+str(size)+'}',record[key]):raise Rejection('backup-digest-identity')
    def identity(value):
        if not isinstance(value,str) or str(uuid.UUID(value))!=value or uuid.UUID(value).int==0:raise Rejection('backup-uuid')
    identity(record['instanceId'])
    storage=record['storage']
    if not isinstance(storage,dict) or set(storage)!={'target','lineage','tenants','generation'}:raise Rejection('backup-storage-fields')
    for name in ['target','lineage']:
        v=storage[name]
        if not isinstance(v,list) or len(v)!=16 or any(type(b) is not int or not 0<=b<=255 for b in v) or not any(v):raise Rejection('backup-storage-identity')
    if type(storage['generation']) is not int or not 0<storage['generation']<=2**63-1:raise Rejection('backup-epoch')
    tenants=storage['tenants']
    if not isinstance(tenants,list) or not 1<=len(tenants)<=128:raise Rejection('backup-tenants')
    for tenant in tenants:identity(tenant)
    if len(set(tenants))!=len(tenants):raise Rejection('backup-tenants')
    if record['sha256']!=sha(path):raise Rejection('backup-digest')
    if c is not None and record['candidate']!=c['revision']:raise Rejection('backup-candidate-mismatch')
    if config is not None and (record['instanceId'],storage)!=(config['instanceId'],config['storage']):raise Rejection('restore-binding-mismatch')
    return record

@contextlib.contextmanager
def project_locks(endpoint,projects,root=Path('/var/tmp/rss-identity-operations')):
    # One deployment owner per Docker host. Other users fail closed instead of getting a second lock namespace.
    root.mkdir(mode=0o700,exist_ok=True)
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise Rejection('unsafe-lock-directory')
    with contextlib.ExitStack() as held:
        for project in sorted(set(projects)):
            if not project_name(project):raise Rejection('project-identity')
            name=hashlib.sha256((endpoint+'\0'+project).encode()).hexdigest()
            fd=os.open(root/name,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            stream=held.enter_context(os.fdopen(fd,'a+b'))
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise Rejection('unsafe-lock-file')
            try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise OperationError('lock','project-busy',True) from None
        yield

def authority_states(project):
    rows=command(['docker','ps','--all','--filter','label=com.docker.compose.project='+project,'--format','{{.ID}} {{.Label "com.docker.compose.service"}}'],stdout=subprocess.PIPE).stdout.decode().splitlines()
    states={}
    for row in rows:
        parts=row.split()
        if len(parts)!=2:raise Rejection('container-identity-unknown')
        container,service=parts
        if service not in ['identity','gateway']:continue
        if not re.fullmatch('[a-f0-9]{12,64}',container):raise Rejection('container-identity-unknown')
        state=json.loads(command(['docker','inspect','--format','{{json .State}}',container],stdout=subprocess.PIPE).stdout)
        states[container]=(service,state)
    return states

def require_closed(project,drained=False,expected=None):
    states=authority_states(project)
    if expected is not None and set(states)!=set(expected):raise Rejection('container-identity-changed-during-close')
    for service,state in states.values():
        if state['Status'] not in ['created','exited'] or any(state[k] for k in ['Running','Paused','Restarting']):raise Rejection('close-ingress-and-identity-first')
        if drained and service=='identity' and state['Status']=='exited' and (state['ExitCode']!=0 or state['OOMKilled']):raise Rejection('identity-drain-not-confirmed')
    return states

def operate(args):
    c=candidate(args.candidate.resolve())
    if args.command=='candidate':return
    if not re.fullmatch('[a-z][a-z0-9_-]{2,47}',args.project or ''):raise Rejection('project-identity')
    if args.deployment is None:raise Rejection('deployment-required')
    directory=args.deployment.resolve()
    compose=['docker','compose','--project-name',args.project,'--project-directory',str(directory),'--file',str(directory/'compose.json')]
    spec=json.loads((directory/'compose.json').read_text())
    expected={s:c['images'][i] for s,i in [('identity','server'),('gateway','gateway'),('migrate','operator'),('maintenance','operator')]}
    expected.update(postgres=c['providers']['postgres'],**{'volume-init':c['providers']['runtime']})
    if set(spec['services'])!=set(expected) or any(spec['services'][n]['image']!=image for n,image in expected.items()):raise Rejection('deployment-candidate-mismatch')
    record=None
    if args.command in ['check-backup','restore']:
        record=check_backup(args.backup,c,json.loads((directory/'migration.json').read_text()))
    if args.command=='check-backup':
        with args.backup.open('rb') as stream:command(['docker','run','--rm','--network','none','--user','10001:10001','--interactive','--entrypoint','pg_restore',c['providers']['postgres'],'--list'],stage='check-backup',stdin=stream,stdout=subprocess.DEVNULL)
        return
    projects=[args.project]
    if args.command=='restore':
        if record['project']==args.project:raise Rejection('restore-requires-a-distinct-isolated-project')
        projects.append(record['project'])
    # Daemon ID canonicalizes Docker context/endpoint aliases to the same lock key.
    endpoint=command(['docker','info','--format','{{.ID}}'],stdout=subprocess.PIPE).stdout.decode().strip()
    if not endpoint:raise Rejection('unknown-docker-endpoint')
    with project_locks(endpoint,projects):
        execute(args,c,compose,directory,record)

def execute(args,c,compose,directory,record):
    def run(*words,**kwargs):return command(compose+list(words),stage=kwargs.pop('stage',args.command),mutating=kwargs.pop('mutating',True),stdout=kwargs.pop('stdout',subprocess.DEVNULL),**kwargs)
    def migration(*words):run('run','--rm','migrate','--config','/run/config/migration.json',*words,stage=words[0].lstrip('-') if words else 'install',mutating=not words or words[0] not in ['--verify','--verify-keys'])
    def closed():return require_closed(args.project)
    if args.command=='install':
        closed();run('run','--rm','volume-init');run('up','-d','--wait','postgres');migration()
    elif args.command=='verify':migration('--verify')
    elif args.command=='close':
        before=authority_states(args.project)
        run('stop','gateway');run('stop','identity')
        try:require_closed(args.project,drained=True,expected=before)
        except Rejection as error:raise OperationError('close',error.reason,False) from None
    elif args.command=='open':
        migration('--verify');run('up','-d','--wait','identity');run('up','-d','--wait','gateway')
    elif args.command in ['initialize','recover']:
        path=args.password.resolve(strict=True)
        # A caller-selected private input is mounted once; it never becomes a CLI argument value.
        if path.stat().st_mode&0o077 or path.stat().st_uid!=10001:raise Rejection('password-file-ownership')
        run('run','--rm','--volume',str(path)+':/run/password:ro','maintenance',args.command,args.tenant,args.account,'/run/password')
    elif args.command in ['rekey','verify-keys']:
        closed()
        # --verify-keys requires the generated keyring to contain only the new key.
        migration('--'+args.command,'/run/config/keyring.json')
    elif args.command=='backup':
        closed();migration('--verify')
        path=args.backup.resolve()
        if path.with_suffix(path.suffix+'.json').exists():raise Rejection('backup-receipt-exists')
        with path.open('xb') as stream:
            os.chmod(path,0o600)
            run('exec','-T','postgres','pg_dump','-U','postgres','-d','identity','-Fc',stdout=stream)
        config=json.loads((directory/'migration.json').read_text())
        record={'schema':9,'instanceId':config['instanceId'],'storage':config['storage'],'candidate':c['revision'],'project':args.project,'sha256':sha(path)}
        receipt=path.with_suffix(path.suffix+'.json');receipt.write_text(json.dumps(record));receipt.chmod(0o600)
    elif args.command=='restore':
        require_closed(record['project'])
        existing=run('ps','--all','--quiet',mutating=False,stdout=subprocess.PIPE).stdout
        volumes=command(['docker','volume','ls','--filter','label=com.docker.compose.project='+args.project,'--format','{{.Name}}'],stdout=subprocess.PIPE).stdout
        if existing.strip() or volumes.strip():raise Rejection('restore-target-must-be-empty')
        run('run','--rm','volume-init');run('up','-d','--wait','postgres')
        with args.backup.open('rb') as stream:run('exec','-T','postgres','pg_restore','-U','postgres','-d','identity','--exit-on-error','--single-transaction',stdin=stream)
        migration('--verify')
        # Deliberately remains closed. Operator validates restore point before explicit open.
    else:raise Rejection('unknown-operation')

def main():
    p=argparse.ArgumentParser();p.add_argument('--candidate',type=Path,required=True);p.add_argument('--deployment',type=Path);p.add_argument('--project')
    sub=p.add_subparsers(dest='command',required=True)
    for name in ['candidate','install','verify','open','close','rekey','verify-keys']:sub.add_parser(name)
    for name in ['backup','check-backup','restore']:sub.add_parser(name).add_argument('backup',type=Path)
    for name in ['initialize','recover']:
        command=sub.add_parser(name);command.add_argument('tenant');command.add_argument('account',help='login for initialize; principal UUID for recover');command.add_argument('password',type=Path)
    args=p.parse_args()
    try:operate(args)
    except OperationError as error:
        print(json.dumps({'operation':args.command,'stage':error.stage,'reason':error.reason,'outcomeKnown':error.outcome_known,'status':'failed','inspect':'verify / verify-keys / docker inspect; do not repeat writes'}))
        raise SystemExit(1)
    except (ValueError,TypeError,KeyError,OSError,RuntimeError,subprocess.SubprocessError):
        print(json.dumps({'operation':args.command,'stage':'precondition','reason':'input-or-state-rejected','outcomeKnown':True,'status':'rejected'}))
        raise SystemExit(1)
    print(json.dumps({'operation':args.command,'stage':'complete','reason':'confirmed','outcomeKnown':True,'status':'passed'}))
if __name__=='__main__':main()
