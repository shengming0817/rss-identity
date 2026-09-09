"""Bounded browser child selected by the consumer-owned joint test entrypoint."""
import os
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
             'IDENTITY_TEST_UI_ORIGIN':os.environ['IDENTITY_TEST_UI_ORIGIN'],
             'PLAYWRIGHT_BROWSERS_PATH':os.environ.get('PLAYWRIGHT_BROWSERS_PATH', str(Path.home() / ('Library/Caches/ms-playwright' if __import__('sys').platform == 'darwin' else '.cache/ms-playwright')))}
        result=run([node,str(runner)],cwd=runner.parent,env=env,timeout=180,termination_grace=1,capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError('Identity browser seam failed; raw child output withheld')
if __name__ == '__main__':main()
