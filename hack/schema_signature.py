#!/usr/bin/env python3
"""Print the structural digest of a fresh installation on the pinned PG fixture; no application data."""
from pathlib import Path
import sys,subprocess,time
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'hack'));import providers
with providers.container(providers.PG,[5432],[("POSTGRES_PASSWORD","fixture-only")]) as (cid,ports):
 for _ in range(120):
  p=subprocess.run(['docker','exec',cid,'pg_isready','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
  if p.returncode==0:break
  time.sleep(.5)
 else:raise RuntimeError('PG unavailable')
 def sql(text):
  return subprocess.run(['docker','exec','-i',cid,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-qAt'],input=text,text=True,capture_output=True,check=True,timeout=30).stdout.strip()
 sql((root/'crates/identity-postgres/migrations/0001_authority.sql').read_text())
 result=sql((root/'crates/identity-postgres/src/schema-signature.sql').read_text())
 print(result)
