"""Linux Client file-transfer CLI; private keys and OTPs never appear in argv."""
import argparse,json,os,pathlib,stat,sys,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from client import AuthenticatedClient,CSError
from transfer_client import authorize,upload_tree,download_tree

def keys(directory):
 d=pathlib.Path(directory); st=os.lstat(d)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or os.path.realpath(str(d))!=os.path.abspath(str(d)): raise ValueError('unsafe credential directory')
 result=[]
 for name,kind in (('ed25519.key',Ed25519PrivateKey),('x25519.key',X25519PrivateKey)):
  fd=os.open(d/name,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'rb') as f:
   st=os.fstat(f.fileno())
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe key file')
   raw=f.read(33)
  if len(raw)!=32: raise ValueError('invalid key file')
  result.append(kind.from_private_bytes(raw))
 return result

def main():
 p=argparse.ArgumentParser(); p.add_argument('--host',default='localhost'); p.add_argument('--port',type=int,required=True); p.add_argument('--ca',required=True); p.add_argument('--owner',required=True); p.add_argument('--device',required=True); p.add_argument('--credential-dir',required=True); p.add_argument('--staging-dir'); p.add_argument('--staging-capacity-mib',type=int)
 sub=p.add_subparsers(dest='operation',required=True)
 upload=sub.add_parser('upload'); upload.add_argument('source')
 create=sub.add_parser('package-create'); create.add_argument('source_id')
 download=sub.add_parser('download'); download.add_argument('package_id'); download.add_argument('destination_root')
 listing=sub.add_parser('package-list')
 retire=sub.add_parser('package-retire'); retire.add_argument('package_id')
 result=sub.add_parser('upload-result'); result.add_argument('transfer_id')
 transfer_result=sub.add_parser('transfer-result'); transfer_result.add_argument('request_id')
 cancel=sub.add_parser('cancel'); cancel.add_argument('transfer_id')
 package_result=sub.add_parser('package-result'); package_result.add_argument('request_id')
 a=p.parse_args()
 if a.operation in ('upload','download'):
  if not a.staging_dir or a.staging_capacity_mib is None: raise ValueError('bounded private staging directory and capacity are required')
  from storage_guard import verify_bounded_filesystem
  paths=[os.path.abspath(a.staging_dir)]
  if a.operation=='download': paths.append(os.path.abspath(a.destination_root))
  verify_bounded_filesystem(paths,a.staging_capacity_mib,512*1024*1024)
 ed,x=keys(a.credential_dir); c=AuthenticatedClient(a.host,a.port,a.ca,a.owner,a.device,ed)
 try:
  c.authenticate()
  if a.operation=='upload':
   rid=str(uuid.uuid4()); print(json.dumps({'request_id':rid}),flush=True); handle=authorize(c,x,rid,'upload'); print(json.dumps({'transfer_id':handle.transfer_id}),flush=True)
   value=upload_tree(c,handle,a.source,a.staging_dir)
  elif a.operation=='package-create':
   rid=str(uuid.uuid4()); print(json.dumps({'request_id':rid}),flush=True); value=c.package_create(a.source_id,rid)
  elif a.operation=='download':
   rid=str(uuid.uuid4()); print(json.dumps({'request_id':rid}),flush=True); handle=authorize(c,x,rid,'download',a.package_id); print(json.dumps({'transfer_id':handle.transfer_id}),flush=True)
   value=download_tree(c,handle,a.destination_root,a.staging_dir)
  elif a.operation=='package-list': value={'packages':c.packages_list()}
  elif a.operation=='package-retire': value={'retired':c.package_retire(a.package_id)}
  elif a.operation=='upload-result': value=c.transfer_upload_result(a.transfer_id)
  elif a.operation=='transfer-result':
   value=c.transfer_result(a.request_id)
   if value is not None: value={k:v for k,v in value.items() if k not in ('enc','wrapped')}
  elif a.operation=='cancel': value={'cancelled':c.transfer_cancel(a.transfer_id)}
  else: value=c.package_result(a.request_id)
  print(json.dumps(value))
 finally: c.close()
if __name__=='__main__':
 try: main()
 except (CSError,OSError,ValueError) as e:
  print(type(e).__name__+': '+str(e),file=sys.stderr); sys.exit(1)
