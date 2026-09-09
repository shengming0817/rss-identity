#!/usr/bin/env python3
"""Build immutable candidate archives from clean, fixed Identity and UI source identities."""
import argparse,hashlib,json,os,shutil,subprocess,tarfile,tempfile,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run(args,**kwargs):return subprocess.check_output(args,text=True,**kwargs).strip()
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
def tree(path):
 h=hashlib.sha256()
 for p in sorted(path.rglob('*')):
  if p.is_symlink():raise ValueError('symlink in artifact')
  if p.is_file():h.update(p.relative_to(path).as_posix().encode()+b'\0'+p.read_bytes()+b'\0')
 return h.hexdigest()
def validate_ui(source,dist):
 revision=run(['/usr/bin/git','-C',str(source),'rev-parse','HEAD'])
 if run(['/usr/bin/git','-C',str(source),'status','--porcelain']):raise ValueError('dirty UI source')
 if json.loads((dist/'identity-build.json').read_text())!={'revision':revision}:raise ValueError('UI source mismatch')
 if not (dist/'index.html').is_file() or list(dist.rglob('*.map')):raise ValueError('incomplete UI artifact')
 return {'repository':run(['/usr/bin/git','-C',str(source),'remote','get-url','origin']),'revision':revision,'lock_sha256':sha(source/'pnpm-lock.yaml'),'dist_sha256':tree(dist)}
def oci_identity(path):
 with tarfile.open(path) as t:
  index=json.load(t.extractfile('index.json'));descriptor=index['manifests'][0]
  # OCI output with attestations can wrap the platform manifest in an index.
  while 'index' in descriptor['mediaType']:
   index=json.load(t.extractfile('blobs/sha256/'+descriptor['digest'].split(':')[1]));descriptor=next(v for v in index['manifests'] if v.get('platform',{}).get('architecture')=='amd64')
  manifest=json.load(t.extractfile('blobs/sha256/'+descriptor['digest'].split(':')[1]));config=json.load(t.extractfile('blobs/sha256/'+manifest['config']['digest'].split(':')[1]))
  if config.get('architecture')!='amd64' or config.get('os')!='linux' or config['config'].get('User')!='10001:10001':raise ValueError('candidate platform/user mismatch')
  return descriptor['digest'],config

def build(out,ui_source,ui_dist):
 if out.exists():raise ValueError('candidate output must be new')
 if run(['/usr/bin/git','status','--porcelain'],cwd=ROOT):raise ValueError('candidate requires clean final HEAD')
 revision=run(['/usr/bin/git','rev-parse','HEAD'],cwd=ROOT);ui=validate_ui(ui_source,ui_dist)
 images=json.loads((ROOT/'deployment/providers.lock.json').read_text())
 if any('@sha256:' not in v for v in images.values()):raise ValueError('unlocked provider')
 subprocess.run(['python3','hack/check_dependencies.py'],cwd=ROOT,check=True)
 out.mkdir(parents=True)
 with tempfile.TemporaryDirectory(prefix='identity-candidate-') as temp:
  context=Path(temp);(context/'source').mkdir()
  archive=subprocess.check_output(['/usr/bin/git','archive','HEAD'],cwd=ROOT)
  archive_path=context/'source.tar';archive_path.write_bytes(archive)
  with tarfile.open(archive_path) as t:t.extractall(context/'source',filter='data')
  shutil.copytree(ui_dist,context/'ui');shutil.copy(ROOT/'deployment/Dockerfile',context/'Dockerfile')
  result={'format_version':1,'revision':revision,'version':tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']['package']['version'],'platform':'linux/amd64','cargo_lock_sha256':sha(ROOT/'Cargo.lock'),'rust':'1.96.0','ui':ui,'providers':images,'identity_schema':6,'migration_sha256':sha(ROOT/'crates/identity-postgres/migrations/0001_authority.sql'),'images':{},'archives':{}}
  metadata=json.loads(run(['cargo','metadata','--locked','--format-version','1'],cwd=ROOT))
  result['rss']=[{'package':p['name'],'version':p['version'],'source':p['source']} for p in metadata['packages'] if p['name'].startswith('rss-') and p['source']]
  for target in ['server','operator','gateway']:
   output=out/(target+'.oci.tar');name='rss-identity/'+target+':'+revision
   command=['docker','buildx','build','--platform','linux/amd64','--target',target,'--tag',name,'--provenance=false','--build-arg','RUST_IMAGE='+images['rust'],'--build-arg','RUNTIME_IMAGE='+images['runtime'],'--build-arg','NGINX_IMAGE='+images['nginx'],'--build-arg','IDENTITY_REVISION='+revision,'--output','type=oci,dest='+str(output.resolve()),str(context)]
   if os.environ.get('SYSTEM_ACCESSTOKEN'):command[3:3]=['--secret','id=azure_token,env=SYSTEM_ACCESSTOKEN']
   # Pin source identity; no build credential reaches the binary compilation RUN.
   subprocess.run(command,check=True)
   digest,config=oci_identity(output)
   if config['config'].get('Labels',{}).get('org.opencontainers.image.revision')!=revision:raise ValueError('candidate revision mismatch')
   subprocess.run(['docker','load','--input',str(output)],check=True,stdout=subprocess.DEVNULL)
   if target=='server':
    subprocess.run(['docker','run','--rm','--network','none','--platform','linux/amd64',name,'--version'],check=True)
   elif target=='operator':
    result['migrations']=json.loads(run(['docker','run','--rm','--network','none','--platform','linux/amd64',name,'--describe']))
    if result['migrations']['identity_sql_sha256']!=result['migration_sha256'] or result['migrations']['schema_version']!=6:raise ValueError('embedded migration identity mismatch')
   result['images'][target]=name+'@'+digest;result['archives'][target]={'file':output.name,'sha256':sha(output),'manifest_digest':digest}
  command=['docker','buildx','build','--platform','linux/amd64','--target','evidence','--build-arg','RUST_IMAGE='+images['rust'],'--build-arg','RUNTIME_IMAGE='+images['runtime'],'--build-arg','NGINX_IMAGE='+images['nginx'],'--output','type=local,dest='+str((out/'binaries').resolve()),str(context)]
  if os.environ.get('SYSTEM_ACCESSTOKEN'):command[3:3]=['--secret','id=azure_token,env=SYSTEM_ACCESSTOKEN']
  subprocess.run(command,check=True)
  built=json.loads((out/'binaries/metadata.json').read_text());packages={p['id']:p for p in built['packages']};features={}
  for line in (out/'binaries/artifacts.json').read_text().splitlines():
   message=json.loads(line)
   if message.get('reason')=='compiler-artifact':
    p=packages[message['package_id']]
    if p['source'] and p['name'].startswith('rss-'):features[p['name']]=set(message['features'])
  import check_dependencies
  check_dependencies.check_features(features,'production')
  result['production_features']={k:sorted(v) for k,v in features.items()}
  result['binaries']={p.name:sha(p) for p in (out/'binaries').glob('identity-*')}
  (out/'binaries/metadata.json').unlink();(out/'binaries/artifacts.json').unlink()
  (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
  shutil.copytree(ROOT/'deployment',out/'deployment');shutil.copy(ROOT/'hack/deploy.py',out/'deploy.py')
  if run(['/usr/bin/git','rev-parse','HEAD'],cwd=ROOT)!=revision or run(['/usr/bin/git','status','--porcelain'],cwd=ROOT):raise ValueError('source changed during candidate build')
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--ui-source',type=Path,required=True);p.add_argument('--ui-dist',type=Path,required=True);a=p.parse_args()
 build(a.output.resolve(),a.ui_source.resolve(),a.ui_dist.resolve())
if __name__=='__main__':main()
