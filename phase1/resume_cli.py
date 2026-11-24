"""Resumable upload CLI; no key or OTP is written to argv or logs."""
import argparse,json,os,pathlib,sys,uuid
from client import AuthenticatedClient,CSError
from transfer_cli import keys
from transfer_client import authorize
from resume_client import ResumeFailure,prepare_upload,recover_handle,upload,cleanup_local,load_request_id
from resume_download_client import download

def main():
 p=argparse.ArgumentParser(); p.add_argument('--host',default='localhost'); p.add_argument('--port',type=int,required=True); p.add_argument('--ca',required=True); p.add_argument('--owner',required=True); p.add_argument('--device',required=True); p.add_argument('--credential-dir',required=True); p.add_argument('--staging-capacity-mib',type=int)
 sub=p.add_subparsers(dest='operation',required=True)
 begin=sub.add_parser('upload'); begin.add_argument('source'); begin.add_argument('resume_directory')
 resume=sub.add_parser('resume'); resume.add_argument('resume_directory'); resume.add_argument('--request-id'); resume.add_argument('--auto',action='store_true')
 down=sub.add_parser('download'); down.add_argument('package_id'); down.add_argument('resume_directory'); down.add_argument('destination_root')
 down_resume=sub.add_parser('resume-download'); down_resume.add_argument('resume_directory'); down_resume.add_argument('destination_root'); down_resume.add_argument('--request-id'); down_resume.add_argument('--auto',action='store_true')
 status=sub.add_parser('status'); status.add_argument('transfer_id'); status.add_argument('--cursor',type=int,default=0)
 cancel=sub.add_parser('cancel'); cancel.add_argument('transfer_id'); cancel.add_argument('--resume-directory')
 a=p.parse_args()
 if a.operation in ('upload','resume','download','resume-download'):
  if a.staging_capacity_mib is None: raise ValueError('bounded staging capacity is required')
  from storage_guard import verify_bounded_filesystem
  stage=pathlib.Path(os.path.abspath(a.resume_directory)); existing=stage if stage.exists() else stage.parent
  paths=[str(existing)]
  if a.operation in ('download','resume-download'): paths.append(os.path.abspath(a.destination_root))
  verify_bounded_filesystem(paths,a.staging_capacity_mib,512*1024*1024)
 ed,x=keys(a.credential_dir)
 def connect():
  c=AuthenticatedClient(a.host,a.port,a.ca,a.owner,a.device,ed); c.authenticate(); return c
 if a.operation=='upload':
  rid=str(uuid.uuid4()); print(json.dumps({'request_id':rid}),flush=True); c=connect()
  try: handle=authorize(c,x,rid,'upload')
  finally: c.close()
  print(json.dumps({'transfer_id':handle.transfer_id}),flush=True); prepare_upload(handle,a.source,a.resume_directory); result=upload(connect,handle,a.resume_directory,automatic=True)
 elif a.operation=='resume':
  c=connect()
  try: handle=recover_handle(c,x,a.request_id or load_request_id(a.resume_directory))
  finally: c.close()
  print(json.dumps({'transfer_id':handle.transfer_id}),flush=True); result=upload(connect,handle,a.resume_directory,automatic=a.auto)
 elif a.operation=='download':
  rid=str(uuid.uuid4()); print(json.dumps({'request_id':rid}),flush=True); c=connect()
  try: handle=authorize(c,x,rid,'download',a.package_id)
  finally: c.close()
  print(json.dumps({'transfer_id':handle.transfer_id}),flush=True); result=download(connect,handle,a.resume_directory,a.destination_root,automatic=True)
 elif a.operation=='resume-download':
  c=connect()
  try: handle=recover_handle(c,x,a.request_id or load_request_id(a.resume_directory))
  finally: c.close()
  print(json.dumps({'transfer_id':handle.transfer_id}),flush=True); result=download(connect,handle,a.resume_directory,a.destination_root,automatic=a.auto)
 elif a.operation=='status':
  c=connect()
  try: result=c.resume_status(a.transfer_id,a.cursor)
  finally: c.close()
 else:
  c=connect()
  try: result={'cancelled':c.transfer_cancel(a.transfer_id)}
  finally: c.close()
  if a.resume_directory: cleanup_local(a.resume_directory,a.transfer_id)
 print(json.dumps(result))
if __name__=='__main__':
 try: main()
 except (CSError,ResumeFailure,OSError,ValueError) as e:
  print(type(e).__name__+': '+str(e),file=sys.stderr); sys.exit(1)
