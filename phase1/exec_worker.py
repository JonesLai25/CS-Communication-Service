"""Dedicated per-request cgroup worker. Only launches through Bubblewrap."""
import base64,ctypes,json,os,pathlib,resource,selectors,signal,subprocess,sys,tempfile,time
from sandbox import spawn,SandboxUnavailable
from workspace_snapshot import copy_tree,publish,remove_stage
from exec_scope import test_slice
from deployment_policy import validate

def scope(policy):
 lines=pathlib.Path('/proc/self/cgroup').read_text().splitlines(); entries=[x.split(':',2)[2] for x in lines if x.startswith('0::')]
 if len(entries)!=1 or '..' in pathlib.PurePosixPath(entries[0]).parts: raise SandboxUnavailable('unverifiable cgroup')
 cg=pathlib.Path('/sys/fs/cgroup')/entries[0].lstrip('/')
 for name,cap in (('memory.max',policy['memory_mib']*1024*1024),('memory.swap.max',policy['swap_mib']*1024*1024),('pids.max',policy['tasks'])):
  v=(cg/name).read_text().strip()
  if not v.isdecimal() or int(v)>cap or (name!='memory.swap.max' and int(v)<=0): raise SandboxUnavailable('cgroup limit unavailable: '+name)
 # Some supported hosts do not delegate the CPU controller to user scopes.
 # Restrict this worker to one allowed CPU; the loaded seccomp filter forbids
 # sandboxed descendants from expanding their own affinity.
 allowed=sorted(os.sched_getaffinity(0)); count=policy['cpus']
 if len(allowed)<count: raise SandboxUnavailable('CPU capacity unavailable')
 cpus=set(allowed[:count]); os.sched_setaffinity(0,cpus)
 if os.sched_getaffinity(0)!=cpus: raise SandboxUnavailable('CPU affinity unavailable')

def main():
 expected=int(sys.argv[1]); libc=ctypes.CDLL(None,use_errno=True)
 if os.getppid()!=expected or libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=expected: raise SandboxUnavailable('server parent unavailable')
 test_slice(); raw=sys.stdin.buffer.read(8193)
 if len(raw)>8192: raise ValueError('worker input too large')
 data=json.loads(raw)
 if not isinstance(data,dict) or set(data) not in ({'workspace','argv','timeout','stage_name'},{'workspace','argv','timeout','stage_name','policy'}): raise ValueError('invalid worker input')
 policy=validate(data.get('policy',{})); scope(policy)
 if type(data['timeout']) is not int or not 1<=data['timeout']<=policy['timeout_seconds']: raise ValueError('invalid worker timeout')
 for kind,limit in ((resource.RLIMIT_NOFILE,64),(resource.RLIMIT_FSIZE,policy['workspace_mib']*1024*1024),(resource.RLIMIT_CORE,0)):
  resource.setrlimit(kind,(limit,limit))
 stop=[False]
 def cancel(_s,_f): stop[0]=True
 signal.signal(signal.SIGTERM,cancel); signal.signal(signal.SIGINT,cancel)
 if stop[0]: raise SandboxUnavailable('cancelled before sandbox')
 mount=subprocess.run(['/usr/bin/findmnt','--noheadings','--output','FSTYPE','--target','/dev/shm'],capture_output=True,text=True,timeout=3,check=True)
 if mount.stdout.strip()!='tmpfs': raise SandboxUnavailable('workspace staging must be tmpfs')
 # The parent can recover exactly this job's private tmpfs directory after SIGKILL.
 stage=data['stage_name']
 import re
 if not isinstance(stage,str) or not re.fullmatch(r'cs-exec-'+str(os.geteuid())+r'-[0-9a-f]{16}-[0-9a-f]{16}-[0-9a-f-]{36}',stage): raise ValueError('invalid stage name')
 workspace=str(pathlib.Path('/dev/shm')/stage); os.mkdir(workspace,0o700)
 try:
  baseline=copy_tree(data['workspace'],workspace,policy=policy)
  p=spawn(workspace,data['argv']); selector=selectors.DefaultSelector(); buffers={'stdout':bytearray(),'stderr':bytearray()}; outcome=None; code=None
  try:
   for name,pipe in (('stdout',p.stdout),('stderr',p.stderr)):
    os.set_blocking(pipe.fileno(),False); selector.register(pipe,selectors.EVENT_READ,name)
   end=time.monotonic()+data['timeout']
   while selector.get_map() or p.poll() is None:
    if stop[0]: outcome='cancelled'; break
    if time.monotonic()>=end: outcome='timed_out'; break
    for key,_ in selector.select(.1):
     chunk=os.read(key.fd,4096)
     if not chunk: selector.unregister(key.fileobj); continue
     available=policy['output_bytes']-sum(map(len,buffers.values()))
     buffers[key.data].extend(chunk[:max(available,0)])
     if len(chunk)>available: outcome='failed'; break
    if outcome: break
   if outcome is None:
    code=p.wait(timeout=3); outcome='succeeded' if code==0 else 'failed'
  finally:
   if p.poll() is None: p.kill()
   try: p.wait(timeout=5)
   except Exception: raise RuntimeError('sandbox process did not exit')
   selector.close(); p.stdout.close(); p.stderr.close()
  if code is not None and not stop[0]:
   changed=copy_tree(workspace,policy=policy)
   if changed!=baseline: publish(workspace,data['workspace'],baseline,stage,policy)
   elif copy_tree(data['workspace'],policy=policy)!=baseline: raise ValueError('workspace changed while command ran')
  elif stop[0] and code is not None: outcome='cancelled'; code=None
 finally: remove_stage(stage)
 result={'state':outcome,'exit_code':code,'stdout':base64.b64encode(buffers['stdout']).decode(),'stderr':base64.b64encode(buffers['stderr']).decode()}
 print(json.dumps(result,separators=(',',':')),flush=True)
if __name__=='__main__':
 try: main()
 except Exception as e:
  print(json.dumps({'error':'sandbox_unavailable','kind':type(e).__name__}),flush=True); sys.exit(1)
