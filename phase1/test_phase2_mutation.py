"""Controlled mutation in a disposable copy; no product deployment."""
import os,pathlib,shutil,signal,subprocess,sys,tempfile,unittest
P=pathlib.Path(__file__).resolve().parent
class Mutation(unittest.TestCase):
 def test_invalid_key_proof_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)
   for name in ('storage_guard.py','server.py','registry.py','client.py','tls_transport.py','admin.py','enrollment.py','enroll_cli.py','test_phase2.py'): shutil.copy2(P/name,root/name)
   path=root/'server.py'; data=path.read_text(); old='if not verify(edpub,xpub,ephemeral,nonce,msg,signature,mac): raise Denied()'
   self.assertIn(old,data); path.write_text(data.replace(old,'if False: raise Denied()',1))
   proc=subprocess.Popen([sys.executable,str(root/'test_phase2.py'),'Enrollment.test_enrollment_and_management'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
   try: out,err=proc.communicate(timeout=30)
   except subprocess.TimeoutExpired:
    os.killpg(proc.pid,signal.SIGKILL); proc.communicate(timeout=5); self.fail('mutation test timed out')
   self.assertNotEqual(proc.returncode,0,'mutation unexpectedly passed'); self.assertIn('403',out+err)
if __name__=='__main__': unittest.main(verbosity=2)
