"""Run the isolated public-client consumer while the T2 bridge is serving."""
from pathlib import Path
import os,re,subprocess
from bounded_process import run as bounded_run
ROOT=Path(__file__).resolve().parents[1]
NAME='tests::product_code_pkce_online_identity_and_logout'
def run():
    env={**os.environ,'CARGO_TARGET_DIR':str(ROOT/'target/consumer')}
    command=['cargo','test','--locked','--manifest-path',str(ROOT/'tests/consumer/Cargo.toml'),'--','--ignored','--test-threads=1']
    listing=bounded_run([*command,'--list'],timeout=900,env=env,cwd=ROOT,text=True,capture_output=True,check=True)
    names=re.findall(r'^(.+): test$',listing.stdout,re.M)
    if names!=[NAME]:raise RuntimeError('consumer canonical tests differ')
    result=bounded_run(command,timeout=180,env=env,cwd=ROOT,text=True,capture_output=True)
    if result.returncode or not re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out',result.stdout):
        # Only safe stage labels from this controlled test cross the diagnostic boundary.
        for line in (result.stdout+result.stderr).splitlines():
            if line.startswith('Error:') and 'http' not in line: print(line[:160])
        raise RuntimeError('independent consumer failed')
    print('independent consumer: 1 passed')
if __name__=='__main__':run()
