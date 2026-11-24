"""Child-only checkpoints for SIGKILL fault tests."""
import os,pathlib,signal,sys
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'; sys.path.insert(0,str(P))
from registry import Registry
from transfer_store import TransferStore
from transfer_crypto import context
from resume_store import ResumeStore
root=pathlib.Path(sys.argv[1]); tid=sys.argv[2]; mode=sys.argv[3]
reg=Registry(str(root/'db')); transfers=TransferStore(reg,(root/'master').read_bytes(),(root/'identity').read_bytes()); store=ResumeStore(reg,transfers,str(root/'resume'),str(root/'published'))
if mode=='chunk':
 original=os.link
 def pause_link(*args,**kwargs):
  result=original(*args,**kwargs); print('chunk-linked',flush=True); signal.pause(); return result
 os.link=pause_link
 store.put('a','dev',tid,0,(root/'first').read_bytes())
else:
 import transfer_ingest
 original=transfer_ingest.receive
 def wrapped(*args,**kwargs):
  if mode=='before': print('before-publish',flush=True); signal.pause()
  publish=kwargs['publish']
  def intercept(commit):
   def after_rename():
    commit(); print('after-rename',flush=True); signal.pause()
   return publish(after_rename)
  kwargs['publish']=intercept
  return original(*args,**kwargs)
 transfer_ingest.receive=wrapped
 store.finish('a','dev',tid,context(transfers.server_identity,'a','dev',tid,'upload'))
