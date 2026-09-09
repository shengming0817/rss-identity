import concurrent.futures
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / '.cargo/rustc-cache-wrapper.sh'

class CacheWrapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cache-test-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / 'repo'
        (self.repo / '.cargo').mkdir(parents=True)
        self.wrapper = self.repo / '.cargo/rustc-cache-wrapper.sh'
        shutil.copy2(SOURCE, self.wrapper)
        subprocess.run(['/usr/bin/git', 'init', '-q', str(self.repo)], check=True)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.cache = self.bin / 'sccache'
        self.cache.write_text('#!/bin/sh\nif [ "$CACHE_TEST_FAIL" = 1 ]; then exit 2; fi\nexec "$@"\n')
        self.cache.chmod(0o755)
        self.env = {k: v for k,v in os.environ.items() if not k.startswith(('SCCACHE_', 'GIT_'))}
        self.env.update(PATH=str(self.bin)+':/usr/bin:/bin', CACHE_TEST_FAIL='0')

    def invoke(self, *args):
        return subprocess.run([str(self.wrapper), *args], cwd=self.repo, env=self.env,
                              text=True, capture_output=True, timeout=15)

    def test_archive_without_git_runs_compiler(self):
        shutil.rmtree(self.repo / '.git')
        result = self.invoke('/bin/echo', 'argument with spaces')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'argument with spaces\n')

    def test_failed_cache_runs_compiler(self):
        self.env['CACHE_TEST_FAIL'] = '1'
        result = self.invoke('/bin/echo', 'argument with spaces')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'argument with spaces\n')

    def test_compiler_failure_remains_failure(self):
        for fail in ('0', '1'):
            self.env['CACHE_TEST_FAIL'] = fail
            self.assertEqual(self.invoke('/bin/sh', '-c', 'exit 7').returncode, 7)

    def test_missing_cache_runs_compiler(self):
        self.cache.unlink()
        self.assertEqual(self.invoke('/usr/bin/true').returncode, 0)

    def test_unwritable_cache_runs_compiler(self):
        (self.repo / '.cache').write_text('not a directory')
        self.assertEqual(self.invoke('/usr/bin/true').returncode, 0)

    def test_override_selects_own_server(self):
        self.env['SCCACHE_DIR'] = str(self.root / 'custom-cache')
        result = self.invoke('/usr/bin/env')
        self.assertEqual(result.returncode, 0, result.stderr)
        values = dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        self.assertEqual(values['SCCACHE_DIR'], self.env['SCCACHE_DIR'])
        self.assertEqual(values['SCCACHE_SERVER_UDS'], self.env['SCCACHE_DIR']+'/server.sock')
        self.env['SCCACHE_SERVER_UDS'] = str(self.root / 'explicit.sock')
        self.assertIn('SCCACHE_SERVER_UDS='+self.env['SCCACHE_SERVER_UDS'], self.invoke('/usr/bin/env').stdout)

    def test_parallel_cache_failure_preserves_each_command(self):
        self.env['CACHE_TEST_FAIL'] = '1'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda i: self.invoke('/bin/echo', str(i)), range(16)))
        self.assertEqual([(r.returncode,r.stdout) for r in results], [(0,str(i)+'\n') for i in range(16)])

if __name__ == '__main__':
    unittest.main()
