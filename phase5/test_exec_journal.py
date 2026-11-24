import base64,concurrent.futures,pathlib,sys,tempfile,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from registry import Registry,Conflict,Denied
from exec_journal import ExecJournal,MAX_OUTPUT
class Journal(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.r=Registry(str(pathlib.Path(self.tmp.name)/'db')); self.r.initialize(); self.r.provision('alice','pc',bytes(32)); self.r.provision('bob','pc',bytes(32)); self.j=ExecJournal(self.r); self.j.initialize(); self.rid=str(uuid.uuid4()); self.request={'operation':'exec','workspace':'alice','argv':['/usr/bin/true'],'timeout_seconds':20}
 def tearDown(self): self.tmp.cleanup()
 def test_atomic_request_and_claim(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: out=list(pool.map(lambda _:self.j.submit('alice','pc',self.rid,self.request),range(2)))
  self.assertEqual(sum(x['new'] for x in out),1)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: claims=list(pool.map(lambda _:self.j.claim('alice',self.rid),range(2)))
  self.assertEqual(sum(claims),1)
  with self.assertRaises(Conflict): self.j.submit('alice','pc',self.rid,{**self.request,'argv':['/usr/bin/false']})
 def test_results_persist_and_authorize(self):
  self.j.submit('alice','pc',self.rid,self.request); self.assertTrue(self.j.claim('alice',self.rid)); self.assertTrue(self.j.finish('alice',self.rid,'succeeded',0,b'ok',b''))
  self.assertEqual(base64.b64decode(self.j.result('alice','pc',self.rid)['stdout_b64']),b'ok'); self.assertIsNone(self.j.result('bob','pc',self.rid)); self.assertFalse(self.j.finish('alice',self.rid,'failed',1,b'',b''))
  with self.assertRaises(ValueError): self.j.finish('alice',self.rid,'failed',1,b'x'*(MAX_OUTPUT+1),b'')
 def test_cancel_and_recovery_unknown(self):
  self.j.submit('alice','pc',self.rid,self.request); self.assertEqual(self.j.cancel_queued('alice','pc',self.rid),'cancelled'); self.assertFalse(self.j.claim('alice',self.rid))
  rid=str(uuid.uuid4()); self.j.submit('alice','pc',rid,self.request); self.assertTrue(self.j.claim('alice',rid)); ExecJournal(self.r).initialize(); self.assertEqual(self.j.result('alice','pc',rid)['state'],'unknown'); self.assertFalse(self.j.submit('alice','pc',rid,self.request)['new'])
 def test_workspace_mismatch(self):
  with self.assertRaises(Denied): self.j.submit('alice','pc',self.rid,{**self.request,'workspace':'bob'})
if __name__=='__main__': unittest.main(verbosity=2)
