#!/usr/bin/env python3
"""Fetch with the job credential, then build offline without Git authentication config."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

def main():
    env = dict(os.environ)
    env['PATH'] = '/usr/bin:' + env.get('PATH', '')
    token = env.pop('SYSTEM_ACCESSTOKEN', '')
    fetch_env = dict(env)
    if token:
        count = int(fetch_env.get('GIT_CONFIG_COUNT', '0'))
        fetch_env[f'GIT_CONFIG_KEY_{count}'] = 'http.https://dev.azure.com/shengming0923/rss/_git/rss.extraheader'
        fetch_env[f'GIT_CONFIG_VALUE_{count}'] = 'AUTHORIZATION: bearer ' + token
        fetch_env['GIT_CONFIG_COUNT'] = str(count + 1)
    subprocess.run(['cargo', 'fetch', '--locked'], cwd=ROOT, env=fetch_env, check=True)
    # Also remove inherited runtime Git config: build scripts have no need for it.
    env = {k: v for k, v in env.items() if not k.startswith('GIT_CONFIG_')}
    env['CARGO_NET_OFFLINE'] = 'true'
    subprocess.run(['make', 'ci', 'PYTHON=' + sys.executable], cwd=ROOT, env=env, check=True)

if __name__ == '__main__':
    main()
