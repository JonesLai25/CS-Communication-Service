"""Authenticated execution controller; sandbox and scope checks fail closed."""
import base64,fcntl,hashlib,json,os,pathlib,re,signal,stat,subprocess,sys,tempfile,threading,time,uuid
from registry import Busy,Denied,StorageError
from exec_journal import ExecJournal
from sandbox import SandboxUnavailable
from workspace_snapshot import stage_name,remove_stage,recover
from exec_scope import test_slice
from deployment_policy import validate

def process_identity(pid):
 try:
  fields=pathlib.Path('/proc/%d/stat'%pid).read_text().split(') ',1)[1].split()
  return fields[0],fields[19]
 except FileNotFoundError: return None

class ExecController:
 def __init__(self,registry,root,policy=None):
  self.policy=validate({} if policy is None else policy); self.registry=registry; self.journal=ExecJournal(registry,self.policy); self.root=pathlib.Path(root).resolve(strict=True); self.lock=threading.Lock(); self.active={}; self.ready=False; self.stop_event=threading.Event(); self.repair_thread=None
  self._root(); fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   self.root_lock=os.open('.cs-exec.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=fd)
   st=os.fstat(self.root_lock)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise SandboxUnavailable('unsafe controller lock')
   fcntl.flock(self.root_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BaseException:
   if hasattr(self,'root_lock'): os.close(self.root_lock)
   raise
  finally: os.close(fd)
  try:
   # Preflight creates only empty private directories. Never recursively
   # delete an unexpected entry in the workspace root.
   for path in self.root.iterdir():
    if path.name.startswith('.cs-check-'):
     st=os.lstat(path)
     if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise SandboxUnavailable('unsafe preflight leftover')
     os.rmdir(path)
   def bind(db):
    db.execute('CREATE TABLE IF NOT EXISTS exec_meta(id INTEGER PRIMARY KEY CHECK(id=1),root_hash BLOB NOT NULL)')
    fingerprint=hashlib.sha256(os.fsencode(self.root)).digest()
    db.execute('INSERT OR IGNORE INTO exec_meta VALUES(1,?)',(fingerprint,))
    if db.execute('SELECT root_hash FROM exec_meta WHERE id=1').fetchone()[0]!=fingerprint: raise SandboxUnavailable('registry belongs to another workspace root')
   self.registry.transaction(bind)
   self._reconcile()
   remove_stage(stage_name(self.root,'preflight','00000000-0000-0000-0000-000000000000'))
  except BaseException:
   os.close(self.root_lock); self.root_lock=None; raise
 def _root(self):
  fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   st=os.fstat(fd)
   if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise SandboxUnavailable('unsafe workspace root')
  finally: os.close(fd)
 def _db(self,operation):
  for attempt in range(8):
   try: return operation()
   except Busy:
    if attempt==7: raise
    time.sleep(min(.025*(attempt+1),.2))
 def _reconcile(self):
  self.journal.initialize()
  stale=self.registry.read(lambda db:list(db.execute("SELECT owner,id,worker_pid,worker_start,worker_boot FROM exec_jobs WHERE state='unknown'")))
  boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  for owner,rid,pid,start,old_boot in stale:
   if pid is not None and old_boot==boot:
    deadline=time.monotonic()+5
    while True:
     identity=process_identity(pid)
     if identity is None or identity[0]=='Z' or identity[1]!=start: break
     if time.monotonic()>=deadline: raise SandboxUnavailable('previous execution worker still alive')
     time.sleep(.05)
   token=stage_name(self.root,owner,rid); remove_stage(token); recover(self.root/owner,token)
 def _disable(self):
  with self.lock:
   self.ready=False
   if self.stop_event.is_set() or self.repair_thread is not None and self.repair_thread.is_alive(): return
   self.repair_thread=threading.Thread(target=self._repair,daemon=True); self.repair_thread.start()
 def _repair(self):
  delay=.25
  while not self.stop_event.wait(delay):
   with self.lock:
    if self.active: continue
   try:
    self._reconcile(); self.preflight()
    return
   except Exception as error:
    print('exec recovery deferred: '+type(error).__name__,file=sys.stderr,flush=True)
    delay=min(delay*2,10)
 def _workspace(self,owner):
  if not isinstance(owner,str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}',owner): raise Denied()
  self._root(); fd=os.open(self.root/owner,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   st=os.fstat(fd)
   if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise Denied()
  finally: os.close(fd)
  return str(self.root/owner)
 def _launch(self,workspace,argv,timeout,stage):
  if os.geteuid()==0: raise SandboxUnavailable('host root forbidden')
  available=next((int(line.split()[1]) for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')),0)
  if available<300000+self.policy['memory_mib']*1024: raise SandboxUnavailable('host memory guard')
  runtime='/run/user/'+str(os.geteuid()); socket=pathlib.Path(runtime)/'bus'
  if not socket.exists(): raise SandboxUnavailable('user service manager unavailable')
  cmd=['/usr/bin/systemd-run','--user','--scope','--quiet','-p','MemoryMax='+str(self.policy['memory_mib'])+'M','-p','MemorySwapMax='+str(self.policy['swap_mib'])+'M','-p','TasksMax='+str(self.policy['tasks']),sys.executable,'-B',str(pathlib.Path(__file__).with_name('exec_worker.py')),str(os.getpid())]
  env={'PATH':'/usr/bin:/bin','LANG':'C','XDG_RUNTIME_DIR':runtime,'DBUS_SESSION_BUS_ADDRESS':'unix:path='+str(socket)}
  slice_name=test_slice()
  if slice_name: cmd.insert(4,'--slice='+slice_name); env['CS_PHASE5_TEST_SLICE']=slice_name
  process=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True,env=env)
  payload=json.dumps({'workspace':workspace,'argv':argv,'timeout':timeout,'stage_name':stage,'policy':self.policy},separators=(',',':')).encode()
  return process,payload
 def preflight(self):
  self._root()
  with tempfile.TemporaryDirectory(prefix='.cs-check-',dir=self.root) as workspace:
   code="import os,sys; s=open('/proc/self/status').read(); ok=os.getuid()!=0 and 'NoNewPrivs:\\t1' in s and 'Seccomp:\\t2' in s and len(os.sched_getaffinity(0))=="+str(self.policy['cpus'])+"; sys.stdout.write('1') if ok else (_ for _ in ()).throw(RuntimeError('sandbox check failed'))"
   stage=stage_name(self.root,'preflight','00000000-0000-0000-0000-000000000000')
   p,payload=self._launch(workspace,['/usr/bin/python3','-c',code],min(5,self.policy['timeout_seconds']),stage)
   try: out,err=p.communicate(payload,timeout=15)
   except subprocess.TimeoutExpired:
    p.kill(); p.communicate(timeout=5); raise SandboxUnavailable('sandbox preflight deadline')
   finally: remove_stage(stage)
   try: data=json.loads(out)
   except (ValueError,UnicodeError) as e: raise SandboxUnavailable('sandbox preflight response') from e
   if p.returncode or data!={'state':'succeeded','exit_code':0,'stdout':base64.b64encode(b'1').decode(),'stderr':''}: raise SandboxUnavailable('sandbox preflight failed')
  with self.lock:
   if self.stop_event.is_set(): raise SandboxUnavailable('execution controller closed')
   self.ready=True
 def submit(self,owner,device,rid,request):
  with self.lock:
   if not self.ready or self.stop_event.is_set(): raise Denied()
   workspace=self._workspace(owner); record=self.journal.submit(owner,device,rid,request)
   if record['new']:
    event=threading.Event(); key=(owner,rid)
    thread=threading.Thread(target=self._run,args=(owner,rid,request,workspace,event),daemon=True)
    self.active[key]=[event,None,thread]; thread.start()
  return record
 def _run(self,owner,rid,request,workspace,event):
  key=(owner,rid); p=None
  try:
   try: claimed=self._db(lambda:self.journal.claim(owner,rid))
   except (Busy,StorageError):
    self._disable()
    return
   if not claimed: return
   if event.is_set():
    try:
     if not self._db(lambda:self.journal.finish(owner,rid,'cancelled',None,b'',b'')): self._disable()
    except (Busy,StorageError):
     self._disable()
    return
   try:
    p,payload=self._launch(workspace,request['argv'],request['timeout_seconds'],stage_name(self.root,owner,rid))
    identity=process_identity(p.pid)
    if identity is None or identity[0]=='Z': raise SandboxUnavailable('worker exited before registration')
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not self._db(lambda:self.journal.attach(owner,rid,p.pid,identity[1],boot)): raise SandboxUnavailable('worker ownership registration failed')
    with self.lock:
     self.active[key][1]=p
     if event.is_set(): p.send_signal(signal.SIGTERM)
    out,err=p.communicate(payload,timeout=request['timeout_seconds']+15)
    data=json.loads(out)
    if p.returncode or not isinstance(data,dict) or set(data)!={'state','exit_code','stdout','stderr'} or data['state'] not in ('succeeded','failed','timed_out','cancelled') or data['exit_code'] is not None and type(data['exit_code']) is not int: raise ValueError('invalid worker response')
    stdout=base64.b64decode(data['stdout'],validate=True); stderr=base64.b64decode(data['stderr'],validate=True)
    if len(stdout)+len(stderr)>2048: raise ValueError('worker output too large')
    if not self._db(lambda:self.journal.finish(owner,rid,data['state'],data['exit_code'],stdout,stderr)): raise SandboxUnavailable('execution state changed unexpectedly')
   except Exception:
    if p is not None and p.poll() is None:
     p.terminate()
     try: p.communicate(timeout=5)
     except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=5)
    try: recover(workspace,stage_name(self.root,owner,rid))
    except Exception:
     # Preserve ambiguous data and prevent subsequent remote execution until
     # restart reconciliation can establish a safe state.
     self._disable()
    try:
     if not self._db(lambda:self.journal.finish(owner,rid,'unknown',None,b'',b'')): self._disable()
    except (Busy,StorageError):
     self._disable()
  finally:
   try: remove_stage(stage_name(self.root,owner,rid))
   except Exception:
    self._disable()
   finally:
    with self.lock: self.active.pop(key,None)
 def cancel(self,owner,device,rid):
  state=self.journal.cancel_queued(owner,device,rid)
  if state=='running':
   with self.lock:
    item=self.active.get((owner,rid))
    if item:
     item[0].set(); p=item[1]
     if p is not None and p.poll() is None: p.send_signal(signal.SIGTERM)
  return state
 def close(self):
  if self.root_lock is None: return
  with self.lock:
   self.ready=False; self.stop_event.set(); items=list(self.active.values())
  for event,p,thread in items:
   event.set()
   if p is not None and p.poll() is None: p.terminate()
   if thread is not None: thread.join(timeout=10)
  with self.lock:
   if self.active: raise RuntimeError('execution workers still active')
  if self.repair_thread is not None:
   self.repair_thread.join(timeout=16)
   if self.repair_thread.is_alive(): raise RuntimeError('execution recovery still active')
  os.close(self.root_lock); self.root_lock=None
