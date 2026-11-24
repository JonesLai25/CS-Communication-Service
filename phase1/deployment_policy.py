"""Administrator-owned execution resource policy, independent of test budgets."""
import json,os,stat
DEFAULT={'memory_mib':112,'swap_mib':32,'tasks':32,'cpus':1,'workspace_mib':16,'workspace_entries':512,'workspace_depth':16,'output_bytes':2048,'timeout_seconds':300,'retained_per_user':4096,'retained_total':16384}
BOUNDS={'memory_mib':(80,1024),'swap_mib':(0,512),'tasks':(8,256),'cpus':(1,4),'workspace_mib':(1,128),'workspace_entries':(1,4096),'workspace_depth':(1,32),'output_bytes':(1,2048),'timeout_seconds':(1,300),'retained_per_user':(1,4096),'retained_total':(1,16384)}

def validate(value):
 if not isinstance(value,dict) or set(value)-set(DEFAULT): raise ValueError('invalid policy keys')
 result={**DEFAULT,**value}
 for name,(low,high) in BOUNDS.items():
  if type(result[name]) is not int or not low<=result[name]<=high: raise ValueError('invalid policy value: '+name)
 if result['workspace_mib']>result['memory_mib']-64: raise ValueError('workspace limit exceeds memory headroom')
 if result['retained_per_user']>result['retained_total']: raise ValueError('inconsistent retention limits')
 return result

def load(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_size>8192: raise ValueError('unsafe deployment policy')
  raw=os.read(fd,8193)
 finally: os.close(fd)
 def unique(pairs):
  result={}
  for k,v in pairs:
   if k in result: raise ValueError('duplicate policy key')
   result[k]=v
  return result
 return validate(json.loads(raw,object_pairs_hook=unique))
