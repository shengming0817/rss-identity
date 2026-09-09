"""Bounded browser child, supplied by the exact frontend source under test."""
import os
from pathlib import Path
import shutil
from bounded_process import run
runner=Path(os.environ['IDENTITY_UI_RUNNER']).resolve(strict=True)
node=shutil.which('node')
if node is None or not runner.is_file():
    raise RuntimeError('Identity browser runner/runtime missing')
result=run([node,str(runner)],cwd=runner.parent,env=os.environ,timeout=180,capture_output=True,text=True)
if result.returncode:
    # The browser runner prints only a closed stage and failure name.
    print(result.stdout[-1000:])
    raise RuntimeError('Identity browser seam failed')
