"""Negative controls alter only disposable copies, never the project server."""
import os, pathlib, shutil, signal, subprocess, sys, tempfile, unittest
P=pathlib.Path(__file__).resolve().parent
class Mutations(unittest.TestCase):
 def run_mutation(self,old,new,test,marker,target='server.py',testfile='test_review003.py'):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)
   for name in ('storage_guard.py','server.py','registry.py','client.py','tls_transport.py','admin.py','enrollment.py','test_review003.py','test_vertical.py'): shutil.copy2(P/name,root/name)
   path=root/target; text=path.read_text(); self.assertIn(old,text); path.write_text(text.replace(old,new,1))
   proc=subprocess.Popen([sys.executable,str(root/testfile),test],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
   try: stdout,stderr=proc.communicate(timeout=70)
   except subprocess.TimeoutExpired:
    # This process group is created solely for this test and contains only its descendants.
    os.killpg(proc.pid,signal.SIGKILL); proc.communicate(timeout=5); self.fail('mutant test exceeded 70 seconds')
   self.assertNotEqual(proc.returncode,0,'mutation unexpectedly passed')
   self.assertIn(marker,stdout+stderr,'failure did not arise from intended check')
 def test_duplicate_header_control(self):
  self.run_mutation("if len(self.headers.get_all(name,[]))>1: raise ValueError()","if False: raise ValueError()",'Fixture.test_http_ambiguous_boundaries','FAIL')
 def test_session_reclamation_control(self):
  self.run_mutation('with self.server.lock: self.server.sessions.pop(self.session_token,None)','with self.server.lock: pass','Fixture.test_session_reclaimed_and_forged_challenges','authentication unavailable')
 def test_plaintext_reconnect_control(self):
  self.run_mutation('raise OSError(\"TLS connection closed; create a new authenticated client\")','return super().connect()','Responses.test_no_plaintext_reconnect','plaintext socket attempted',target='client.py')
 def test_duplicate_execution_control(self):
  self.run_mutation("return {'new':False,'state':row[1],'result':row[2]}","return {'new':True,'state':row[1],'result':row[2]}",'Vertical.test_vertical','FAIL',target='registry.py',testfile='test_vertical.py')
if __name__=='__main__': unittest.main(verbosity=2)
