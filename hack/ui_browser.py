"""Bounded browser child selected by the consumer-owned joint test entrypoint."""
import os
import json
from pathlib import Path
import shutil
import tempfile
from bounded_process import run

def main():
    runner=Path(os.environ['IDENTITY_UI_RUNNER']).resolve(strict=True)
    node=shutil.which('node')
    if node is None or not runner.is_file():
        raise RuntimeError('Identity browser environment unavailable')
    with tempfile.TemporaryDirectory(prefix='identity-browser-') as home:
        env={'PATH':os.environ['PATH'],'HOME':home,'TMPDIR':home,
             'IDENTITY_UI_DIAGNOSTIC':str(Path(home)/'result.json'),
             'IDENTITY_TEST_UI_ORIGIN':os.environ['IDENTITY_TEST_UI_ORIGIN'],
             'PLAYWRIGHT_BROWSERS_PATH':os.environ.get('PLAYWRIGHT_BROWSERS_PATH', str(Path.home() / ('Library/Caches/ms-playwright' if __import__('sys').platform == 'darwin' else '.cache/ms-playwright')))}
        result=run([node,str(runner)],cwd=runner.parent,env=env,timeout=180,termination_grace=1,capture_output=True,text=True)
        if result.returncode:
            diagnostic = Path(home)/'result.json'
            try:
                value=json.loads(diagnostic.read_text())
                stage=value.get('stage')
                failure=value.get('failure')
                if stage not in ('environment','login','create','disable','reset','enable','providers','signout','member-negative') or failure not in ('environment','timeout','assertion'):
                    raise ValueError('unknown diagnostic')
                print(f'Identity browser failure: {stage}/{failure}',flush=True)
            except (OSError,ValueError,TypeError):
                print('Identity browser failure: unavailable diagnostic',flush=True)
            raise SystemExit(1)
if __name__ == '__main__':main()
