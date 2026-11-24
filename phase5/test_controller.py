import base64,pathlib,subprocess,sys,tempfile,time,unittest,uuid
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
from resource_guard import enforce
enforce(80*1024*1024,96*1024*1024,32,400000)
from registry import Busy,Registry,Conflict,Denied,Limited
from exec_controller import ExecController
class Controller(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name); self.work=self.root/'work'; self.work.mkdir(mode=0o700); (self.work/'alice').mkdir(mode=0o700); (self.work/'bob').mkdir(mode=0o700)
  self.reg=Registry(str(self.root/'db')); self.reg.initialize(); self.reg.provision('alice','pc',bytes(32)); self.reg.provision('bob','pc',bytes(32)); self.ctl=ExecController(self.reg,self.work); self.ctl.preflight()
 def tearDown(self): self.ctl.close(); self.tmp.cleanup()
 def request(self,argv,timeout=5): return {'operation':'exec','workspace':'alice','argv':argv,'timeout_seconds':timeout}
 def wait(self,rid):
  end=time.monotonic()+12
  while time.monotonic()<end:
   r=self.ctl.journal.result('alice','pc',rid)
   if r['state'] not in ('queued','running'): return r
   time.sleep(.05)
  self.fail('controller deadline')
 def test_preflight_and_persistent_result(self):
  self.ctl.preflight(); rid=str(uuid.uuid4()); request=self.request(['/usr/bin/printf','hello'])
  self.assertTrue(self.ctl.submit('alice','pc',rid,request)['new']); result=self.wait(rid); self.assertEqual(result['state'],'succeeded'); self.assertEqual(base64.b64decode(result['stdout_b64']),b'hello')
  self.assertFalse(self.ctl.submit('alice','pc',rid,request)['new']); self.assertIsNone(self.ctl.journal.result('bob','pc',rid))
  with self.assertRaises(Conflict): self.ctl.submit('alice','pc',rid,self.request(['/usr/bin/false']))
  from exec_journal import ExecJournal
  self.assertEqual(base64.b64decode(ExecJournal(self.reg).result('alice','pc',rid)['stdout_b64']),b'hello')
 def test_failed_preflight_cannot_enable_execution(self):
  from sandbox import SandboxUnavailable
  self.ctl.ready=False
  with patch.object(self.ctl,'_launch',side_effect=SandboxUnavailable('injected')):
   with self.assertRaises(SandboxUnavailable): self.ctl.preflight()
  with self.assertRaises(Denied): self.ctl.submit('alice','pc',str(uuid.uuid4()),self.request(['/usr/bin/true']))
 def test_database_busy_disables_new_execution_without_false_success(self):
  rid=str(uuid.uuid4())
  with patch.object(self.ctl.journal,'claim',side_effect=Busy('injected')):
   self.ctl.submit('alice','pc',rid,self.request(['/usr/bin/true']))
   end=time.monotonic()+5
   while self.ctl.ready and time.monotonic()<end: time.sleep(.05)
   self.assertFalse(self.ctl.ready)
   with self.assertRaises(Denied): self.ctl.submit('alice','pc',str(uuid.uuid4()),self.request(['/usr/bin/true']))
  end=time.monotonic()+10
  while not self.ctl.ready and time.monotonic()<end: time.sleep(.05)
  self.assertTrue(self.ctl.ready); self.assertEqual(self.ctl.journal.result('alice','pc',rid)['state'],'unknown')
  new=str(uuid.uuid4()); self.ctl.submit('alice','pc',new,self.request(['/usr/bin/true'])); self.assertEqual(self.wait(new)['state'],'succeeded')
 def test_lost_result_transition_never_reports_success(self):
  rid=str(uuid.uuid4())
  with patch.object(self.ctl.journal,'finish',return_value=False):
   self.ctl.submit('alice','pc',rid,self.request(['/usr/bin/true']))
   end=time.monotonic()+8
   while self.ctl.ready and time.monotonic()<end: time.sleep(.05)
   self.assertFalse(self.ctl.ready)
  end=time.monotonic()+10
  while not self.ctl.ready and time.monotonic()<end: time.sleep(.05)
  self.assertTrue(self.ctl.ready); self.assertEqual(self.ctl.journal.result('alice','pc',rid)['state'],'unknown')
 def test_administrator_policy_is_enforced_by_real_worker(self):
  self.ctl.close(); self.ctl=ExecController(self.reg,self.work,{'memory_mib':96,'workspace_mib':8,'output_bytes':4,'tasks':16,'timeout_seconds':5,'retained_per_user':1,'retained_total':1}); self.ctl.preflight()
  with self.assertRaises(ValueError): self.ctl.submit('alice','pc',str(uuid.uuid4()),self.request(['/usr/bin/true'],6))
  rid=str(uuid.uuid4()); self.ctl.submit('alice','pc',rid,self.request(['/usr/bin/printf','12345'],5)); value=self.wait(rid)
  self.assertEqual(value['state'],'failed'); self.assertEqual(base64.b64decode(value['stdout_b64']),b'1234')
  with self.assertRaises(Limited): self.ctl.submit('alice','pc',str(uuid.uuid4()),self.request(['/usr/bin/true'],5))
 def test_running_cancellation(self):
  rid=str(uuid.uuid4()); self.ctl.submit('alice','pc',rid,self.request(['/usr/bin/python3','-c','import time; time.sleep(20)'],30))
  end=time.monotonic()+5
  while time.monotonic()<end:
   with self.ctl.lock: item=self.ctl.active.get(('alice',rid)); p=item[1] if item else None
   if p is not None:
    try:
     if '.scope' in pathlib.Path('/proc/%d/cgroup'%p.pid).read_text(): break
    except FileNotFoundError: pass
   time.sleep(.02)
  else: self.fail('worker startup deadline')
  time.sleep(.3); self.ctl.cancel('alice','pc',rid); self.assertEqual(self.wait(rid)['state'],'cancelled')
 def test_crash_reconciliation_cleans_only_known_stage(self):
  from workspace_snapshot import stage_name
  rid=str(uuid.uuid4()); request=self.request(['/usr/bin/true']); self.ctl.journal.submit('alice','pc',rid,request); self.assertTrue(self.ctl.journal.claim('alice',rid))
  stage=pathlib.Path('/dev/shm')/stage_name(self.work,'alice',rid); stage.mkdir(mode=0o700); (stage/'partial').write_text('test only')
  self.ctl.close(); self.ctl=ExecController(self.reg,self.work)
  self.assertFalse(stage.exists()); self.assertEqual(self.ctl.journal.result('alice','pc',rid)['state'],'unknown')
 def test_killed_worker_does_not_publish_partial_workspace(self):
  from workspace_snapshot import stage_name
  rid=str(uuid.uuid4()); code="from pathlib import Path; import time; Path('partial').write_text('test'); time.sleep(20)"
  self.ctl.submit('alice','pc',rid,self.request(['/usr/bin/python3','-c',code],30)); stage=pathlib.Path('/dev/shm')/stage_name(self.work,'alice',rid)
  end=time.monotonic()+8
  while time.monotonic()<end:
   if (stage/'partial').exists(): break
   time.sleep(.02)
  else: self.fail('isolated worker did not start')
  with self.ctl.lock: item=self.ctl.active.get(('alice',rid)); p=item[1]
  p.kill(); self.assertEqual(self.wait(rid)['state'],'unknown'); self.assertFalse(stage.exists()); self.assertFalse((self.work/'alice'/'partial').exists())
 def test_restart_will_not_reconcile_a_live_recorded_worker(self):
  from exec_controller import process_identity
  from sandbox import SandboxUnavailable
  rid=str(uuid.uuid4()); request=self.request(['/usr/bin/true']); self.ctl.journal.submit('alice','pc',rid,request); self.assertTrue(self.ctl.journal.claim('alice',rid))
  p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(15)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   start=process_identity(p.pid)[1]; boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(); self.assertTrue(self.ctl.journal.attach('alice',rid,p.pid,start,boot)); self.ctl.close()
   with self.assertRaisesRegex(SandboxUnavailable,'still alive'): ExecController(self.reg,self.work)
  finally:
   if p.poll() is None: p.kill()
   p.wait(timeout=5)
  self.ctl=ExecController(self.reg,self.work); self.assertEqual(self.ctl.journal.result('alice','pc',rid)['state'],'unknown')
if __name__=='__main__': unittest.main(verbosity=2)
