"""Mutate only temporary copies and demand the real tests catch missing binding."""
import pathlib, shutil, subprocess, sys, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class Mutation(unittest.TestCase):
 def test_context_binding_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'phase1').mkdir(); (root/'phase3').mkdir()
   source=(ROOT/'phase1'/'transfer_stream.py').read_text(); original='hashlib.sha256(context).digest()'; mutated='bytes(32)'
   self.assertIn(original,source); (root/'phase1'/'transfer_stream.py').write_text(source.replace(original,mutated))
   shutil.copy(ROOT/'phase3'/'test_transfer_stream.py',root/'phase3'/'test_transfer_stream.py')
   proc=subprocess.run([sys.executable,'-O',str(root/'phase3'/'test_transfer_stream.py')],capture_output=True,text=True,timeout=20)
   self.assertNotEqual(proc.returncode,0); self.assertIn('InvalidEnvelope not raised',proc.stderr)
 def test_traversal_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'phase1').mkdir(); (root/'phase3').mkdir()
   source=(ROOT/'phase1'/'transfer_archive.py').read_text(); original="p in ('.','..')"; mutated='False'
   self.assertIn(original,source); (root/'phase1'/'transfer_archive.py').write_text(source.replace(original,mutated))
   for name in ('transfer_compress.py','transfer_stream.py'): shutil.copy(ROOT/'phase1'/name,root/'phase1'/name)
   shutil.copy(ROOT/'phase3'/'test_transfer_archive.py',root/'phase3'/'test_transfer_archive.py')
   proc=subprocess.run([sys.executable,'-O',str(root/'phase3'/'test_transfer_archive.py')],capture_output=True,text=True,timeout=20,cwd=d,env={**__import__('os').environ,'TMPDIR':d})
   self.assertNotEqual(proc.returncode,0); self.assertIn('InvalidArchive not raised',proc.stderr)
 def test_no_overwrite_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'phase1').mkdir(); (root/'phase3').mkdir()
   source=(ROOT/'phase1'/'transfer_ingest.py').read_text(); original='os.fsencode(transfer_id),1)'; mutated='os.fsencode(transfer_id),0)'
   self.assertIn(original,source); (root/'phase1'/'transfer_ingest.py').write_text(source.replace(original,mutated))
   for name in ('transfer_archive.py','transfer_compress.py','transfer_stream.py'): shutil.copy(ROOT/'phase1'/name,root/'phase1'/name)
   shutil.copy(ROOT/'phase3'/'test_transfer_ingest.py',root/'phase3'/'test_transfer_ingest.py')
   proc=subprocess.run([sys.executable,'-O',str(root/'phase3'/'test_transfer_ingest.py')],capture_output=True,text=True,timeout=20,cwd=d,env={**__import__('os').environ,'TMPDIR':d})
   self.assertNotEqual(proc.returncode,0); self.assertIn('FileExistsError not raised',proc.stderr)
 def test_tar_extension_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'phase1').mkdir(); (root/'phase3').mkdir()
   source=(ROOT/'phase1'/'transfer_archive.py').read_text(); original="if self.type not in (tarfile.DIRTYPE,tarfile.REGTYPE,tarfile.AREGTYPE):"; mutated='if False:'
   self.assertIn(original,source); (root/'phase1'/'transfer_archive.py').write_text(source.replace(original,mutated))
   for name in ('transfer_compress.py','transfer_stream.py'): shutil.copy(ROOT/'phase1'/name,root/'phase1'/name)
   shutil.copy(ROOT/'phase3'/'test_transfer_archive.py',root/'phase3'/'test_transfer_archive.py')
   proc=subprocess.run([sys.executable,'-O',str(root/'phase3'/'test_transfer_archive.py')],capture_output=True,text=True,timeout=20,cwd=d,env={**__import__('os').environ,'TMPDIR':d})
   self.assertNotEqual(proc.returncode,0); self.assertIn('not less than or equal to',proc.stderr)
 def test_deadline_extension_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'phase1').mkdir(); (root/'phase3').mkdir()
   source=(ROOT/'phase1'/'server.py').read_text(); original='if not self.extended: self.extended=True; self._arm(seconds)'; mutated='if True: self.extended=True; self._arm(seconds)'
   self.assertIn(original,source); (root/'phase1'/'server.py').write_text(source.replace(original,mutated))
   for name in ('registry.py','client.py','tls_transport.py','admin.py','enrollment.py'): shutil.copy(ROOT/'phase1'/name,root/'phase1'/name)
   shutil.copy(ROOT/'phase3'/'test_transfer_deadline.py',root/'phase3'/'test_transfer_deadline.py')
   proc=subprocess.run([sys.executable,'-O',str(root/'phase3'/'test_transfer_deadline.py')],capture_output=True,text=True,timeout=20)
   self.assertNotEqual(proc.returncode,0); self.assertIn('False is not true',proc.stderr)
 def test_download_owner_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'phase1').mkdir(); (root/'phase3').mkdir()
   source=(ROOT/'phase1'/'transfer_store.py').read_text(); original="id=? AND owner=? AND state='ready'"; mutated="id=? AND ? IS NOT NULL AND state='ready'"
   self.assertIn(original,source); (root/'phase1'/'transfer_store.py').write_text(source.replace(original,mutated))
   for name in ('registry.py','outgoing.py','transfer_crypto.py','transfer_stream.py','transfer_compress.py','transfer_archive.py'): shutil.copy(ROOT/'phase1'/name,root/'phase1'/name)
   shutil.copy(ROOT/'phase3'/'test_transfer_outgoing.py',root/'phase3'/'test_transfer_outgoing.py')
   proc=subprocess.run([sys.executable,'-O',str(root/'phase3'/'test_transfer_outgoing.py')],capture_output=True,text=True,timeout=20,cwd=d,env={**__import__('os').environ,'TMPDIR':d})
   self.assertNotEqual(proc.returncode,0); self.assertIn('Denied not raised',proc.stderr)
 def test_aead_tag_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'phase1').mkdir(); (root/'phase3').mkdir()
   source=(ROOT/'phase1'/'transfer_stream.py').read_text(); original="  except InvalidTag as e: raise InvalidEnvelope('authentication failed') from e"
   mutated="""  except InvalidTag:
   from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
   raw=Cipher(algorithms.AES(_key(otp,header[len(MAGIC):],context)),modes.GCM(_nonce(index),ct[-16:])).decryptor()
   raw.authenticate_additional_data(_aad(header,context,index,kind,size-16)); part=raw.update(ct[:-16])"""
   self.assertIn(original,source); (root/'phase1'/'transfer_stream.py').write_text(source.replace(original,mutated))
   shutil.copy(ROOT/'phase3'/'test_transfer_stream.py',root/'phase3'/'test_transfer_stream.py')
   proc=subprocess.run([sys.executable,'-O',str(root/'phase3'/'test_transfer_stream.py')],capture_output=True,text=True,timeout=20)
   self.assertNotEqual(proc.returncode,0); self.assertIn('InvalidEnvelope not raised',proc.stderr)
if __name__=='__main__': unittest.main(verbosity=2)
