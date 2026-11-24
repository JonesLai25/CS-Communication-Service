import base64,json,os,pathlib,signal,subprocess,sys,tempfile,time,unittest,uuid
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'phase1'))
sys.path.insert(0,str(ROOT/'tools'))
from resource_guard import enforce
enforce(80*1024*1024,96*1024*1024,32,400000)
from workspace_snapshot import stage_name,remove_stage
from exec_scope import test_slice
class Worker(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); workspace=pathlib.Path(self.tmp.name)/'workspace'; workspace.mkdir(mode=0o700); self.workspace=str(workspace)
 def tearDown(self): self.tmp.cleanup()
 def start(self,argv,timeout=5):
  cmd=['systemd-run','--user','--scope','--quiet','-p','MemoryMax=112M','-p','MemorySwapMax=32M','-p','TasksMax=32',sys.executable,str(ROOT/'phase1/exec_worker.py'),str(os.getpid())]
  name=test_slice()
  if name: cmd.insert(4,'--slice='+name)
  p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  p.stage_name=stage_name(self.tmp.name,'alice',str(uuid.uuid4()))
  p.stdin.write(json.dumps({'workspace':self.workspace,'argv':argv,'timeout':timeout,'stage_name':p.stage_name}).encode()); p.stdin.close(); p.stdin=None
  return p
 def finish(self,p,deadline=15):
  try: out,err=p.communicate(timeout=deadline)
  except subprocess.TimeoutExpired:
   p.terminate()
   try: p.communicate(timeout=5)
   except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=5)
   raise
  self.assertEqual(p.returncode,0,err.decode()+out.decode()); return json.loads(out)
 def test_result_and_affinity(self):
  code="import os,errno; a=os.sched_getaffinity(0); print('cpus',len(a));\ntry: os.sched_setaffinity(0,a)\nexcept OSError as e: print('blocked',e.errno)\nelse: raise RuntimeError('affinity escaped')"
  r=self.finish(self.start(['/usr/bin/python3','-c',code])); self.assertEqual(r['state'],'succeeded'); self.assertEqual(base64.b64decode(r['stdout']),b'cpus 1\nblocked 1\n')
 def test_aggregate_guard_rejects_forged_slice(self):
  from sandbox import SandboxUnavailable
  self.assertIsNotNone(test_slice())
  with patch.dict(os.environ,{'CS_PHASE5_TEST_SLICE':'csphase5000000000000.slice'}):
   with self.assertRaises(SandboxUnavailable): test_slice()
 def test_worker_refuses_missing_job_memory_cap(self):
  name=test_slice(); cmd=['systemd-run','--user','--scope','--quiet','--slice='+name,'-p','MemorySwapMax=32M','-p','TasksMax=32',sys.executable,str(ROOT/'phase1/exec_worker.py'),str(os.getpid())]
  stage=stage_name(self.tmp.name,'alice',str(uuid.uuid4())); p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  payload=json.dumps({'workspace':self.workspace,'argv':['/usr/bin/touch','SHOULD_NOT_RUN'],'timeout':5,'stage_name':stage}).encode()
  try:
   out,err=p.communicate(payload,timeout=12); self.assertNotEqual(p.returncode,0); self.assertEqual(json.loads(out)['error'],'sandbox_unavailable'); self.assertFalse((pathlib.Path(self.workspace)/'SHOULD_NOT_RUN').exists())
  finally:
   if p.poll() is None: p.kill(); p.communicate(timeout=5)
   remove_stage(stage)
 def test_timeout(self):
  r=self.finish(self.start(['/usr/bin/python3','-c','import time;time.sleep(20)'],1)); self.assertEqual(r['state'],'timed_out')
 def test_output_limit(self):
  r=self.finish(self.start(['/usr/bin/python3','-c','import sys;sys.stdout.write("x"*10000)'])); self.assertEqual(r['state'],'failed'); self.assertLessEqual(len(base64.b64decode(r['stdout'])),2048)
 def test_workspace_changes_are_atomically_published(self):
  (pathlib.Path(self.workspace)/'old').write_text('before')
  code="from pathlib import Path; Path('old').write_text('after'); Path('new').write_text('new')"
  r=self.finish(self.start(['/usr/bin/python3','-c',code])); self.assertEqual(r['state'],'succeeded')
  self.assertEqual((pathlib.Path(self.workspace)/'old').read_text(),'after'); self.assertEqual((pathlib.Path(self.workspace)/'new').read_text(),'new')
 def test_oversized_workspace_does_not_publish(self):
  p=self.start(['/usr/bin/python3','-c','open("huge","wb").write(b"x"*(17*1024*1024))'])
  try: out,err=p.communicate(timeout=15)
  except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=5); raise
  self.assertNotEqual(p.returncode,0); self.assertEqual(json.loads(out)['error'],'sandbox_unavailable'); self.assertFalse((pathlib.Path(self.workspace)/'huge').exists())
 def test_memory_limit_cannot_publish(self):
  p=self.start(['/usr/bin/python3','-c','x=bytearray(256*1024*1024);open("bad","w").write("bad")'],5)
  try:
   out,err=p.communicate(timeout=15)
   if p.returncode==0: self.assertNotEqual(json.loads(out)['state'],'succeeded')
   self.assertFalse((pathlib.Path(self.workspace)/'bad').exists())
  finally:
   if p.poll() is None: p.kill(); p.communicate(timeout=5)
   remove_stage(p.stage_name)
 def test_daemon_cannot_modify_workspace_after_result(self):
  code="import os,time; p=os.fork();\nif p==0:\n os.setsid(); os.close(1); os.close(2); time.sleep(2); open('late','w').write('bad'); os._exit(0)"
  r=self.finish(self.start(['/usr/bin/python3','-c',code],1)); self.assertIn(r['state'],('succeeded','timed_out')); time.sleep(2.2)
  self.assertFalse((pathlib.Path(self.workspace)/'late').exists())
 def test_process_count_is_limited(self):
  code="import os,time;\nfor i in range(64):\n try: p=os.fork()\n except OSError as e: print('LIMIT',e.errno,flush=True); break\n if p==0: time.sleep(8); os._exit(0)\ntime.sleep(8)"
  r=self.finish(self.start(['/usr/bin/python3','-c',code],2),deadline=12)
  self.assertEqual(r['state'],'timed_out'); self.assertIn(b'LIMIT 11',base64.b64decode(r['stdout']))
 def test_cancel(self):
  p=self.start(['/usr/bin/python3','-c','import time;time.sleep(20)'])
  try:
   # The request process is owned by this test; wait only for its scoped startup.
   end=time.monotonic()+5
   while time.monotonic()<end:
    try:
     if '.scope' in pathlib.Path('/proc/%d/cgroup'%p.pid).read_text(): break
    except FileNotFoundError: self.fail('worker exited early')
    time.sleep(.02)
   else: self.fail('scope startup deadline')
   time.sleep(.3); p.send_signal(signal.SIGTERM); r=self.finish(p); self.assertEqual(r['state'],'cancelled')
  finally:
   if p.poll() is None: p.kill(); p.communicate(timeout=5)
if __name__=='__main__': unittest.main(verbosity=2)
