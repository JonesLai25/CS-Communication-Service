"""Authenticated command submission and result retrieval; never retries a command."""
import argparse,json,os,pathlib,stat,sys,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from client import AuthenticatedClient,CSError

def signing_key(directory):
 d=pathlib.Path(directory); st=os.lstat(d)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or os.path.realpath(d)!=os.path.abspath(d): raise ValueError('unsafe credential directory')
 fd=os.open(d/'ed25519.key',os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe signing key')
  raw=f.read(33)
 if len(raw)!=32: raise ValueError('invalid signing key')
 return Ed25519PrivateKey.from_private_bytes(raw)

def main():
 p=argparse.ArgumentParser(); p.add_argument('--host',default='localhost'); p.add_argument('--port',type=int,required=True); p.add_argument('--ca',required=True); p.add_argument('--owner',required=True); p.add_argument('--device',required=True); p.add_argument('--credential-dir',required=True)
 sub=p.add_subparsers(dest='op',required=True)
 for name in ('submit','run'):
  s=sub.add_parser(name); s.add_argument('--request-id'); s.add_argument('--timeout',type=int,default=120); s.add_argument('argv',nargs=argparse.REMAINDER)
 for name in ('status','wait','cancel'):
  s=sub.add_parser(name); s.add_argument('request_id')
 a=p.parse_args(); c=AuthenticatedClient(a.host,a.port,a.ca,a.owner,a.device,signing_key(a.credential_dir))
 try:
  c.authenticate()
  if a.op in ('submit','run'):
   args=a.argv[1:] if a.argv and a.argv[0]=='--' else a.argv
   if not args: raise ValueError('command required')
   rid=a.request_id or str(uuid.uuid4()); print(json.dumps({'request_id':rid}),flush=True)
   value=c.exec_submit(rid,a.owner,args,a.timeout)
   if a.op=='run': value=c.exec_wait(rid,min(a.timeout+15,305))
  elif a.op=='status': value=c.exec_result(a.request_id)
  elif a.op=='wait': value=c.exec_wait(a.request_id)
  else: value=c.exec_cancel(a.request_id)
  if isinstance(value,dict) and 'stdout' in value:
   value={**value,'stdout':value['stdout'].decode('utf-8','replace'),'stderr':value['stderr'].decode('utf-8','replace')}
  print(json.dumps(value,ensure_ascii=True))
  if a.op in ('run','wait') and (value is None or value.get('state')!='succeeded'): return 1
  return 0
 finally: c.close()
if __name__=='__main__':
 try: sys.exit(main())
 except (CSError,OSError,ValueError) as e: print(type(e).__name__+': '+str(e),file=sys.stderr); sys.exit(1)
