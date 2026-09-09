#!/usr/bin/env python3
"""Isolated TLS PG installation seam. Does not run the product stack or candidate image."""
import contextlib, os, subprocess, tempfile
from pathlib import Path
import providers

def main():
 with tempfile.TemporaryDirectory(prefix='identity-install-') as tmp, providers.postgres() as (cid,ports):
  root=Path(tmp)
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(root/'server.key'),'-out',str(root/'server.crt')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  for name in ['server.key','server.crt']:providers.docker('cp',str(root/name),cid+':/tmp/'+name)
  providers.docker('exec','-u','root',cid,'sh','-c','chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key')
  for setting in ["ssl='on'","ssl_cert_file='/tmp/server.crt'","ssl_key_file='/tmp/server.key'"]:
   providers.docker('exec',cid,'psql','-X','-U','postgres','-v','ON_ERROR_STOP=1','-c','ALTER SYSTEM SET '+setting)
  providers.docker('exec',cid,'psql','-X','-U','postgres','-c','SELECT pg_reload_conf()')
  for name,value in [('state-key','42'*32),('owner','fixture-only'),('runtime',"runtime-unique-32bytes-secret-with-'quote\\slash"),('maintenance','maintenance-unique-32bytes-secret')]:
   p=root/name;p.write_text(value);p.chmod(0o600)
  providers.cargo('rss-identity-app','installation',{'IDENTITY_TEST_INSTALL_DIR':tmp,'IDENTITY_TEST_PG_PORT':str(ports[5432])})
if __name__=='__main__':main()
