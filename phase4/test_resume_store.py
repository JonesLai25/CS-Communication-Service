import errno,hashlib,io,os,pathlib,sqlite3,sys,tempfile,unittest,uuid
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry,Denied,Conflict,Limited,StorageError
from transfer_crypto import context
from transfer_store import TransferStore
from transfer_stream import encrypt
from transfer_archive import pack
from transfer_compress import compress
from resume_store import CHUNK,Corrupt,ResumeStore,key_check
class ResumeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); root=pathlib.Path(self.tmp.name); self.path=root; (root/'resume').mkdir(mode=0o700); (root/'published').mkdir(mode=0o700)
  self.r=Registry(str(root/'db')); self.r.initialize(); self.r.add_user('a'); x=X25519PrivateKey.generate(); pub=x.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); self.r.enroll('a','dev',bytes(32),pub,self.r.create_otp('a',300))
  self.ts=TransferStore(self.r,os.urandom(32),os.urandom(32)); self.ts.initialize(); self.entry=self.ts.issue('a','dev',str(uuid.uuid4()),'upload',300); self.tid=self.entry['id']; self.key=self.ts.get_key('a','dev',self.tid); self.binding=context(self.ts.server_identity,'a','dev',self.tid,'upload')
  source=os.urandom(CHUNK*2+123); target=io.BytesIO(); encrypt(io.BytesIO(source),target,self.key,self.binding); self.data=target.getvalue()
  self.manifest={'version':1,'transfer_id':self.tid,'size':len(self.data),'chunks':(len(self.data)+CHUNK-1)//CHUNK,'cipher_sha256':hashlib.sha256(self.data).hexdigest(),'source_sha256':hashlib.sha256(source).hexdigest(),'key_check':key_check(self.key,self.binding),'context_sha256':hashlib.sha256(self.binding).hexdigest()}
  self.store=ResumeStore(self.r,self.ts,str(root/'resume'),str(root/'published')); self.store.initialize()
 def tearDown(self): self.tmp.cleanup()
 def test_wrong_key_denied_before_begin(self):
  with self.assertRaises(Denied): self.store.begin('a','dev',{**self.manifest,'key_check':'0'*64},self.binding)
 def test_client_refuses_when_staging_space_is_low(self):
  from resume_client import prepare_upload
  handle=SimpleNamespace(direction='upload',request_id=str(uuid.uuid4()),transfer_id=str(uuid.uuid4()))
  with patch('resume_client.os.fstatvfs',return_value=SimpleNamespace(f_bavail=1,f_frsize=4096)):
   with self.assertRaisesRegex(OSError,'insufficient staging space'): prepare_upload(handle,str(self.path/'src'),str(self.path/'work'))
  self.assertFalse((self.path/'work'/'request').exists())
 def test_download_cache_crash_reconciliation_fails_closed(self):
  from outgoing import Packages
  from resume_download import ResumeDownload
  packages=self.path/'packages'; packages.mkdir(mode=0o700)
  store=Packages(self.r,str(packages),str(self.path/'published')); store.initialize(); ResumeDownload(self.r,self.ts,store).initialize()
  stale=packages/'.cs-download-test'; stale.mkdir(mode=0o700); (stale/'cipher').write_bytes(b'partial')
  tid=str(uuid.uuid4()); orphan=packages/('download-'+tid); orphan.write_bytes(b'uncommitted')
  store.reconcile_download_staging(); self.assertFalse(stale.exists()); self.assertFalse(orphan.exists())
  orphan.write_bytes(b'inconsistent')
  with sqlite3.connect(self.r.path) as db: db.execute('INSERT INTO resume_downloads VALUES(?,?)',(tid,b'{}'))
  with self.assertRaisesRegex(ValueError,'index without ciphertext'): store.reconcile_download_staging()
  self.assertTrue(orphan.exists())
  orphan.unlink()
  class FakeTransfers:
   def download_info(self,*args): return str(uuid.uuid4())
   def get_key(self,*args): raise AssertionError('must not re-encrypt indexed transfer')
  with self.assertRaisesRegex(ValueError,'index without ciphertext'): store.prepare_download(FakeTransfers(),'a','dev',tid)
 def test_reserved_staging_budget_rejects_before_receiving_data(self):
  with patch('resume_store.MAX_RESERVED',len(self.data)-1):
   with self.assertRaises(Limited): self.store.begin('a','dev',self.manifest,self.binding)
  with sqlite3.connect(self.r.path) as db:
   self.assertEqual(db.execute('SELECT count(*) FROM resume_transfers').fetchone()[0],0)
   self.assertEqual(db.execute('SELECT count(*) FROM resume_chunks').fetchone()[0],0)
 def test_low_disk_blocks_new_and_existing_chunks(self):
  with patch('resume_store.os.fstatvfs',return_value=SimpleNamespace(f_bavail=1,f_frsize=4096)):
   with self.assertRaises(StorageError): self.store.begin('a','dev',self.manifest,self.binding)
  self.store.begin('a','dev',self.manifest,self.binding)
  with patch('resume_store.os.fstatvfs',return_value=SimpleNamespace(f_bavail=1,f_frsize=4096)):
   with self.assertRaises(StorageError): self.store.put('a','dev',self.tid,0,self.data[:CHUNK])
  self.assertEqual(self.store.status('a','dev',self.tid)['chunks'],[])
 def test_manifest_and_committed_chunk_immutable(self):
  s=self.store; s.begin('a','dev',self.manifest,self.binding); s.begin('a','dev',self.manifest,self.binding)
  other={**self.manifest,'source_sha256':hashlib.sha256(b'changed').hexdigest()}
  with self.assertRaises(Conflict): s.begin('a','dev',other,self.binding)
  with self.assertRaises(Denied): s.begin('a','dev',{**self.manifest,'key_check':'0'*64},self.binding)
  first=self.data[:CHUNK]; self.assertTrue(s.put('a','dev',self.tid,0,first)); self.assertFalse(s.put('a','dev',self.tid,0,first))
  with self.assertRaises(Conflict): s.put('a','dev',self.tid,0,bytes(CHUNK))
  self.assertEqual(s.reconcile('a','dev',self.tid)['chunks'][0]['sha256'],hashlib.sha256(first).hexdigest())
 def test_incomplete_write_orphan_reconciliation(self):
  s=self.store; s.begin('a','dev',self.manifest,self.binding)
  with patch('resume_store._sync_dir',side_effect=OSError('injected fsync failure')):
   with self.assertRaises(OSError): s.put('a','dev',self.tid,0,self.data[:CHUNK])
  self.assertEqual(s.reconcile('a','dev',self.tid)['chunks'],[])
  self.assertTrue(s.put('a','dev',self.tid,0,self.data[:CHUNK]))
 def test_partial_write_and_disk_full_do_not_advance(self):
  s=self.store; s.begin('a','dev',self.manifest,self.binding)
  def partial(fd,data): os.write(fd,data[:13]); raise OSError(errno.ENOSPC,'injected test disk full')
  with patch('resume_store._write_all',side_effect=partial):
   with self.assertRaises(OSError) as cm: s.put('a','dev',self.tid,0,self.data[:CHUNK])
  self.assertEqual(cm.exception.errno,errno.ENOSPC); self.assertEqual(s.status('a','dev',self.tid)['chunks'],[])
  self.assertEqual(s.reconcile('a','dev',self.tid)['chunks'],[]); self.assertEqual(list((self.path/'resume'/self.tid).iterdir()),[])
 def test_missing_committed_chunk_is_failure(self):
  s=self.store; s.begin('a','dev',self.manifest,self.binding); s.put('a','dev',self.tid,0,self.data[:CHUNK]); (self.path/'resume'/self.tid/'0').unlink()
  with self.assertRaises(Corrupt): s.reconcile('a','dev',self.tid)
  self.assertEqual(s.status('a','dev',self.tid)['state'],'failed')
  self.assertEqual(s.cleanup_terminal(),1); self.assertFalse((self.path/'resume'/self.tid).exists())
 def test_missing_or_damaged_committed_chunk_is_failure(self):
  s=self.store; s.begin('a','dev',self.manifest,self.binding); s.put('a','dev',self.tid,0,self.data[:CHUNK]); (self.path/'resume'/self.tid/'0').write_bytes(bytes([self.data[0]^1])+self.data[1:CHUNK])
  with self.assertRaises(Corrupt): s.reconcile('a','dev',self.tid)
  self.assertEqual(s.status('a','dev',self.tid)['state'],'failed')
  with self.assertRaises(Denied): s.put('a','dev',self.tid,0,self.data[:CHUNK])
 def test_finish_publishes_once_with_full_manifest(self):
  src=self.path/'src'; src.mkdir(mode=0o700); (src/'f').write_bytes(os.urandom(CHUNK+17))
  tar=io.BytesIO(); pack(str(src),tar); packed=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),packed); source=packed.getvalue(); cipher=io.BytesIO(); encrypt(io.BytesIO(source),cipher,self.key,self.binding); data=cipher.getvalue()
  manifest={**self.manifest,'size':len(data),'chunks':(len(data)+CHUNK-1)//CHUNK,'source_sha256':hashlib.sha256(source).hexdigest(),'cipher_sha256':hashlib.sha256(data).hexdigest()}
  self.store.begin('a','dev',manifest,self.binding)
  with self.assertRaises(Denied): self.store.finish('a','dev',self.tid,self.binding)
  for idx in range(manifest['chunks']): self.store.put('a','dev',self.tid,idx,data[idx*CHUNK:(idx+1)*CHUNK])
  self.assertEqual(self.store.finish('a','dev',self.tid,self.binding),{'status':'received'})
  self.assertEqual((self.path/'published'/self.tid/'f').read_bytes(),(src/'f').read_bytes())
  self.assertEqual(self.store.status('a','dev',self.tid)['state'],'complete')
  self.assertEqual(self.store.finish('a','dev',self.tid,self.binding),{'status':'received'})
  with self.assertRaises(Conflict): self.ts.publish_if_authorized('a','dev',self.tid,lambda:None)
 def test_publication_fsync_failure_can_retry(self):
  src=self.path/'src'; src.mkdir(mode=0o700); (src/'f').write_bytes(b'fsync test'); tar=io.BytesIO(); pack(str(src),tar); packed=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),packed); source=packed.getvalue(); cipher=io.BytesIO(); encrypt(io.BytesIO(source),cipher,self.key,self.binding); data=cipher.getvalue()
  m={**self.manifest,'size':len(data),'chunks':(len(data)+CHUNK-1)//CHUNK,'source_sha256':hashlib.sha256(source).hexdigest(),'cipher_sha256':hashlib.sha256(data).hexdigest()}; self.store.begin('a','dev',m,self.binding)
  for i in range(m['chunks']): self.store.put('a','dev',self.tid,i,data[i*CHUNK:(i+1)*CHUNK])
  original=os.fsync
  def injected(fd):
   if '.cs-incoming-' in os.readlink('/proc/self/fd/'+str(fd)): raise OSError(errno.ENOSPC,'injected staging fsync failure')
   return original(fd)
  with patch('transfer_ingest.os.fsync',side_effect=injected):
   with self.assertRaises(OSError): self.store.finish('a','dev',self.tid,self.binding)
  self.assertEqual(self.store.status('a','dev',self.tid)['state'],'receiving'); self.assertFalse((self.path/'published'/self.tid).exists())
  self.assertEqual(self.store.finish('a','dev',self.tid,self.binding),{'status':'received'})
 def test_manifest_corruption_and_expiration_cleanup(self):
  s=self.store; s.begin('a','dev',self.manifest,self.binding); s.put('a','dev',self.tid,0,self.data[:CHUNK])
  with sqlite3.connect(self.r.path) as db: db.execute("UPDATE resume_transfers SET manifest=? WHERE id=?",(b'{}',self.tid))
  with self.assertRaises(Corrupt): s.reconcile('a','dev',self.tid)
  s.reconcile_all()
  with sqlite3.connect(self.r.path) as db: self.assertEqual(db.execute('SELECT state FROM resume_transfers WHERE id=?',(self.tid,)).fetchone()[0],'failed')
 def test_expiry_and_empty_cancel_cleanup(self):
  s=self.store; s.begin('a','dev',self.manifest,self.binding)
  with sqlite3.connect(self.r.path) as db: db.execute('UPDATE transfer_keys SET expires=0 WHERE id=?',(self.tid,))
  self.assertEqual(s.status('a','dev',self.tid)['state'],'expired'); self.assertEqual(s.cleanup_terminal(),1); self.assertFalse((self.path/'resume'/self.tid).exists())
 def test_reordered_ciphertext_does_not_publish(self):
  from transfer_stream import InvalidEnvelope
  src=self.path/'src'; src.mkdir(mode=0o700); (src/'f').write_bytes(os.urandom(CHUNK*2+10)); tar=io.BytesIO(); pack(str(src),tar); packed=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),packed); plain=packed.getvalue(); target=io.BytesIO(); encrypt(io.BytesIO(plain),target,self.key,self.binding); data=target.getvalue()
  m={**self.manifest,'size':len(data),'chunks':(len(data)+CHUNK-1)//CHUNK,'source_sha256':hashlib.sha256(plain).hexdigest(),'cipher_sha256':hashlib.sha256(data).hexdigest()}; self.store.begin('a','dev',m,self.binding)
  parts=[data[i*CHUNK:(i+1)*CHUNK] for i in range(m['chunks'])]; parts[0],parts[1]=parts[1],parts[0]
  for i,part in enumerate(parts): self.store.put('a','dev',self.tid,i,part)
  with self.assertRaises((Corrupt,InvalidEnvelope)): self.store.finish('a','dev',self.tid,self.binding)
  self.assertFalse((self.path/'published'/self.tid).exists()); self.assertEqual(self.store.status('a','dev',self.tid)['state'],'failed')
 def test_cancel_and_disable_reject(self):
  s=self.store; s.begin('a','dev',self.manifest,self.binding); self.ts.cancel('a','dev',self.tid)
  with self.assertRaises(Denied): s.put('a','dev',self.tid,0,self.data[:CHUNK])
  self.assertEqual(s.status('a','dev',self.tid)['state'],'cancelled'); self.assertEqual(s.cleanup_terminal(),1); self.assertFalse((self.path/'resume'/self.tid).exists())
if __name__=='__main__': unittest.main(verbosity=2)
