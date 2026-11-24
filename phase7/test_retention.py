import pathlib,sqlite3,sys,tempfile,unittest,uuid
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from registry import Registry,Conflict
from exec_journal import ExecJournal
from client import AuthenticatedClient
class ResultRetention(unittest.TestCase):
 def test_terminal_payloads_expire_but_ids_cannot_run_twice(self):
  with tempfile.TemporaryDirectory() as d:
   r=Registry(str(pathlib.Path(d)/'db')); r.initialize(); r.provision('alice','pc',bytes(32)); j=ExecJournal(r,{'retained_per_user':1,'retained_total':1}); j.initialize()
   rid=str(uuid.uuid4()); request={'operation':'exec','workspace':'alice','argv':['/usr/bin/true'],'timeout_seconds':1}
   self.assertTrue(j.submit('alice','pc',rid,request)['new']); self.assertTrue(j.claim('alice',rid)); self.assertTrue(j.finish('alice',rid,'succeeded',0,b'secret-result',b''))
   with sqlite3.connect(r.path) as db: db.execute('UPDATE exec_jobs SET updated=? WHERE id=?',(1,rid))
   self.assertEqual(j.prune_results(1,now=200000),1); result=j.result('alice','pc',rid); self.assertEqual(result['state'],'expired'); self.assertEqual(result['stdout_b64'],''); self.assertEqual(result['stderr_b64'],'')
   self.assertEqual(j.submit('alice','pc',rid,request),{'new':False,'state':'expired'})
   with self.assertRaises(Conflict): j.submit('alice','pc',rid,{**request,'argv':['/usr/bin/false']})
   self.assertEqual(j.cancel_queued('alice','pc',rid),'expired')
   other=str(uuid.uuid4()); self.assertTrue(j.submit('alice','pc',other,request)['new']); self.assertTrue(j.claim('alice',other)); self.assertTrue(j.finish('alice',other,'unknown',None,b'',b''))
   with sqlite3.connect(r.path) as db: db.execute('UPDATE exec_jobs SET updated=1 WHERE id=?',(other,))
   self.assertEqual(j.prune_results(1,now=200000),0); self.assertEqual(j.result('alice','pc',other)['state'],'unknown')
   with sqlite3.connect(r.path) as db:
    row=db.execute('SELECT body,stdout,stderr FROM exec_jobs WHERE id=?',(rid,)).fetchone(); self.assertEqual(row,(b'',b'',b'')); self.assertEqual(db.execute('SELECT state FROM requests WHERE id=?',(rid,)).fetchone()[0],'expired')
 def test_client_accepts_expired_state(self):
  c=object.__new__(AuthenticatedClient); rid=str(uuid.uuid4()); payload={'request_id':rid,'state':'expired','exit_code':None,'stdout_b64':'','stderr_b64':''}
  with patch.object(c,'call',return_value=(200,payload)):
   self.assertEqual(c.exec_result(rid)['state'],'expired')
if __name__=='__main__': unittest.main(verbosity=2)
