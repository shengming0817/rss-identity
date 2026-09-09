import json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import release

class Release(unittest.TestCase):
 def test_ui_repository_rejects_credentials_without_echoing_them(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);dist=root/'dist';dist.mkdir();revision='a'*40
   (dist/'identity-build.json').write_text(json.dumps({'revision':revision}));(dist/'index.html').write_text('ui');(root/'pnpm-lock.yaml').write_text('lock')
   with patch.object(release,'run',side_effect=[revision,'','https://synthetic-secret@github.com/shengming0817/rss-web.git']):
    with self.assertRaises(ValueError) as error:release.validate_ui(root,dist)
    self.assertNotIn('synthetic-secret',str(error.exception))
   with patch.object(release,'run',side_effect=[revision,'','https://github.com/shengming0817/rss-web.git']):
    result=release.validate_ui(root,dist)
    self.assertEqual(result['repository'],'https://github.com/shengming0817/rss-web.git')
 def test_host_dependency_check_cannot_inherit_build_credentials(self):
  class Stop(Exception):pass
  with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{'SYSTEM_ACCESSTOKEN':'synthetic-token','IDENTITY_GIT_AUTH_HEADER_FILE':'/private/header','GIT_CONFIG_COUNT':'1','GIT_CONFIG_VALUE_0':'synthetic-header'}):
   with patch.object(release,'run',side_effect=['','a'*40]),patch.object(release,'validate_ui',return_value={}),patch.object(release.subprocess,'run',side_effect=Stop) as child:
    with self.assertRaises(Stop):release.build(Path(tmp)/'candidate',Path(tmp),Path(tmp))
    self.assertEqual(child.call_args.args[0][0],sys.executable)
    env=child.call_args.kwargs['env']
    self.assertEqual(env['CARGO_NET_OFFLINE'],'true')
    self.assertFalse(any(k in env for k in ['SYSTEM_ACCESSTOKEN','IDENTITY_GIT_AUTH_HEADER_FILE','GIT_CONFIG_COUNT','GIT_CONFIG_VALUE_0']))
