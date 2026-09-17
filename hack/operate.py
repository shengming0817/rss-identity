#!/usr/bin/env python3
"""Bounded reference operations. No retries, implicit initialization, or restore into a live volume."""
import argparse, hashlib, json, os, re, subprocess, tarfile
from pathlib import Path

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def tree(path):
    h=hashlib.sha256()
    for p in sorted(path.rglob('*')):
        if p.is_symlink():raise ValueError('artifact symlink')
        if p.is_file():h.update(p.relative_to(path).as_posix().encode()+b'\0'+p.read_bytes()+b'\0')
    return h.hexdigest()
def candidate(root):
    c=json.loads((root/'candidate.json').read_text())
    if c['identity_schema']!=9 or c['config_version']!=3:raise ValueError('candidate contract')
    for name,entry in c['archives'].items():
        if name not in ['server','operator','gateway'] or entry['file']!=name+'.oci.tar':raise ValueError('archive identity')
        path=root/entry['file']
        if sha(path)!=entry['sha256']:raise ValueError('archive digest')
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if m.name.startswith('blobs/sha256/') and m.isfile():
                    if hashlib.sha256(t.extractfile(m).read()).hexdigest()!=m.name.split('/')[-1]:raise ValueError('OCI blob digest')
    if set(c['archives'])!={'server','operator','gateway'} or set(c['binaries'])!={'identity-server','identity-admin','identity-migrate'}:raise ValueError('incomplete artifacts')
    for name,digest in c['binaries'].items():
        if sha(root/'binaries'/name)!=digest:raise ValueError('binary digest')
    for name in ['deploy.py','operate.py']:
        if sha(root/name)!=c['tools'][name]:raise ValueError('operator digest')
    if tree(root/'deployment')!=c['deployment_sha256']:raise ValueError('deployment digest')
    return c

def command(args,**kwargs):
    # Caller sees only fixed status; PG/provider text and database payload never enter diagnostics.
    result=subprocess.run(args,timeout=180,stderr=subprocess.PIPE,**kwargs)
    if result.returncode:raise RuntimeError('operation failed or outcome unknown')
    return result

def check_backup(path):
    record=json.loads(path.with_suffix(path.suffix+'.json').read_text())
    if record['sha256']!=sha(path) or record['schema']!=9:raise ValueError('backup identity')
    return record

def authority_states(project):
    rows=command(['docker','ps','--all','--filter','label=com.docker.compose.project='+project,'--format','{{.ID}} {{.Label "com.docker.compose.service"}}'],stdout=subprocess.PIPE).stdout.decode().splitlines()
    states={}
    for row in rows:
        parts=row.split()
        if len(parts)!=2:raise ValueError('container identity unknown')
        container,service=parts
        if service not in ['identity','gateway']:continue
        if not re.fullmatch('[a-f0-9]{12,64}',container):raise ValueError('container identity unknown')
        state=json.loads(command(['docker','inspect','--format','{{json .State}}',container],stdout=subprocess.PIPE).stdout)
        states[container]=(service,state)
    return states

def require_closed(project,drained=False,expected=None):
    states=authority_states(project)
    if expected is not None and set(states)!=set(expected):raise ValueError('container identity changed during close')
    for service,state in states.values():
        if state['Status'] not in ['created','exited'] or any(state[k] for k in ['Running','Paused','Restarting']):raise ValueError('close ingress and identity first')
        if drained and service=='identity' and state['Status']=='exited' and (state['ExitCode']!=0 or state['OOMKilled']):raise ValueError('identity drain not confirmed')
    return states

def operate(args):
    c=candidate(args.candidate.resolve())
    if args.command=='candidate':return
    if not re.fullmatch('[a-z][a-z0-9_-]{2,47}',args.project or ''):raise ValueError('project identity')
    if args.deployment is None:raise ValueError('deployment required')
    directory=args.deployment.resolve()
    compose=['docker','compose','--project-name',args.project,'--project-directory',str(directory),'--file',str(directory/'compose.json')]
    spec=json.loads((directory/'compose.json').read_text())
    for name,image in [('identity','server'),('gateway','gateway'),('migrate','operator'),('maintenance','operator')]:
        if spec['services'][name]['image']!=c['images'][image]:raise ValueError('deployment candidate mismatch')
    def run(*words,**kwargs):return command(compose+list(words),stdout=kwargs.pop('stdout',subprocess.DEVNULL),**kwargs)
    def migration(*words):run('run','--rm','migrate','--config','/run/config/migration.json',*words)
    def closed():return require_closed(args.project)
    if args.command=='install':
        closed();run('run','--rm','volume-init');run('up','-d','--wait','postgres');migration()
    elif args.command=='verify':migration('--verify')
    elif args.command=='close':
        before=authority_states(args.project)
        run('stop','gateway');run('stop','identity')
        require_closed(args.project,drained=True,expected=before)
    elif args.command=='open':
        migration('--verify');run('up','-d','--wait','identity');run('up','-d','--wait','gateway')
    elif args.command in ['initialize','recover']:
        path=args.password.resolve(strict=True)
        # A caller-selected private input is mounted once; it never becomes a CLI argument value.
        if path.stat().st_mode&0o077 or path.stat().st_uid!=10001:raise ValueError('password file ownership')
        run('run','--rm','--volume',str(path)+':/run/password:ro','maintenance',args.command,args.tenant,args.account,'/run/password')
    elif args.command in ['rekey','verify-keys']:
        closed()
        # --verify-keys requires the generated keyring to contain only the new key.
        migration('--'+args.command,'/run/config/keyring.json')
    elif args.command=='backup':
        closed();migration('--verify')
        path=args.backup.resolve()
        with path.open('xb') as stream:
            os.chmod(path,0o600)
            run('exec','-T','postgres','pg_dump','-U','postgres','-d','identity','-Fc',stdout=stream)
        config=json.loads((directory/'migration.json').read_text())
        record={'schema':9,'instanceId':config['instanceId'],'storage':config['storage'],'candidate':c['revision'],'project':args.project,'sha256':sha(path)}
        receipt=path.with_suffix(path.suffix+'.json');receipt.write_text(json.dumps(record));receipt.chmod(0o600)
    elif args.command=='check-backup':
        check_backup(args.backup)
        with args.backup.open('rb') as stream:run('run','--rm','-T','--no-deps','--entrypoint','pg_restore','postgres','--list',stdin=stream)
    elif args.command=='restore':
        record=check_backup(args.backup)
        if record['project']==args.project:raise ValueError('restore requires a distinct isolated project')
        source=record['project']
        if not re.fullmatch('[a-z][a-z0-9_-]{2,47}',source):raise ValueError('source project identity')
        require_closed(source)
        config=json.loads((directory/'migration.json').read_text())
        if (config['instanceId'],config['storage'])!=(record['instanceId'],record['storage']):raise ValueError('restore binding mismatch')
        existing=run('ps','--all','--quiet',stdout=subprocess.PIPE).stdout
        volumes=command(['docker','volume','ls','--filter','label=com.docker.compose.project='+args.project,'--format','{{.Name}}'],stdout=subprocess.PIPE).stdout
        if existing.strip() or volumes.strip():raise ValueError('restore target must be empty')
        run('run','--rm','volume-init');run('up','-d','--wait','postgres')
        with args.backup.open('rb') as stream:run('exec','-T','postgres','pg_restore','-U','postgres','-d','identity','--exit-on-error','--single-transaction',stdin=stream)
        migration('--verify')
        # Deliberately remains closed. Operator validates restore point before explicit open.
    else:raise ValueError('unknown operation')

def main():
    p=argparse.ArgumentParser();p.add_argument('--candidate',type=Path,required=True);p.add_argument('--deployment',type=Path);p.add_argument('--project')
    sub=p.add_subparsers(dest='command',required=True)
    for name in ['candidate','install','verify','open','close','rekey','verify-keys']:sub.add_parser(name)
    for name in ['backup','check-backup','restore']:sub.add_parser(name).add_argument('backup',type=Path)
    for name in ['initialize','recover']:
        command=sub.add_parser(name);command.add_argument('tenant');command.add_argument('account',help='login for initialize; principal UUID for recover');command.add_argument('password',type=Path)
    args=p.parse_args()
    try:operate(args)
    except (ValueError,TypeError,KeyError,OSError,RuntimeError,subprocess.SubprocessError):raise SystemExit('operation not confirmed; inspect state before another command')
    print('operation confirmed')
if __name__=='__main__':main()
