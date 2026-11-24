"""Safety negative controls alter only private temporary copies."""
import os,pathlib,shutil,subprocess,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class Mutations(unittest.TestCase):
 def run_mutation(self,old,new,test,marker):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'phase1').mkdir(); (root/'phase4').mkdir()
   for name in ('resume_store.py','registry.py','transfer_store.py','transfer_crypto.py','transfer_stream.py','transfer_ingest.py','transfer_archive.py','transfer_compress.py'): shutil.copy(ROOT/'phase1'/name,root/'phase1'/name)
   f=root/'phase1'/'resume_store.py'; text=f.read_text(); self.assertIn(old,text); f.write_text(text.replace(old,new,1))
   shutil.copy(ROOT/'phase4'/'test_resume_store.py',root/'phase4'/'test_resume_store.py')
   p=subprocess.run([sys.executable,'-O',str(root/'phase4'/'test_resume_store.py'),test],capture_output=True,text=True,cwd=d,env={**os.environ,'TMPDIR':d},timeout=25)
   self.assertNotEqual(p.returncode,0); self.assertIn(marker,p.stderr)
 def test_changed_manifest_control(self):
  self.run_mutation("old[0]!=owner or old[1]!=device or old[2]!=raw","old[0]!=owner or old[1]!=device",'ResumeTests.test_manifest_and_committed_chunk_immutable','Conflict not raised')
 def test_chunk_digest_control(self):
  self.run_mutation("not hmac.compare_digest(h.digest(),digest)","False",'ResumeTests.test_missing_or_damaged_committed_chunk_is_failure','Corrupt not raised')
 def test_wrong_key_control(self):
  self.run_mutation("not hmac.compare_digest(manifest['key_check'],key_check(key,binding))","False",'ResumeTests.test_wrong_key_denied_before_begin','Denied not raised')
if __name__=='__main__': unittest.main(verbosity=2)
