import fcntl,json,os,pathlib,sqlite3,sys,tempfile,unittest,uuid
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from resume_client import cleanup_local,ResumeFailure,_locked_upload
from storage_guard import verify_bounded_filesystem
from registry import StorageError
from server import BoundedServer
class Lifecycle(unittest.TestCase):
 def test_cleanup_is_explicit_locked_and_preserves_other_files(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); tid=str(uuid.uuid4()); (p/'manifest').write_text(json.dumps({'transfer_id':tid})); (p/'cipher').write_bytes(b'cipher'); (p/'request').write_text('preserve'); (p/'other').write_text('preserve')
   for x in p.iterdir(): x.chmod(0o600)
   with self.assertRaises(ResumeFailure): cleanup_local(p,str(uuid.uuid4()))
   self.assertTrue((p/'cipher').exists())
   lock=os.open(p/'.lock',os.O_CREAT|os.O_RDWR,0o600)
   try:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    with self.assertRaises(BlockingIOError): cleanup_local(p,tid)
   finally: os.close(lock)
   cleanup_local(p,tid); self.assertFalse((p/'cipher').exists()); self.assertEqual((p/'other').read_text(),'preserve'); self.assertTrue((p/'request').exists())
 def test_cleanup_rejects_unsafe_entry_before_deleting_anything(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); tid=str(uuid.uuid4()); (p/'manifest').write_text(json.dumps({'transfer_id':tid})); (p/'manifest').chmod(0o600); (p/'cipher').write_bytes(b'keep'); (p/'cipher').chmod(0o600); (p/'0').symlink_to(p/'cipher')
   with self.assertRaises(ResumeFailure): cleanup_local(p,tid)
   self.assertEqual((p/'cipher').read_bytes(),b'keep')
 def test_upload_holds_cleanup_lock(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); tid=str(uuid.uuid4()); (p/'manifest').write_text(json.dumps({'transfer_id':tid})); (p/'manifest').chmod(0o600)
   @_locked_upload
   def during(connector,handle,directory):
    with self.assertRaises(BlockingIOError): cleanup_local(directory,tid)
    return True
   self.assertTrue(during(None,None,p))
 def test_incomplete_preparation_can_be_cleaned_by_identity(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); tid=str(uuid.uuid4()); (p/'transfer').write_text(tid); (p/'transfer').chmod(0o600); (p/'cipher.partial').write_bytes(b'partial'); (p/'cipher.partial').chmod(0o600)
   cleanup_local(p,tid); self.assertFalse((p/'cipher.partial').exists()); self.assertEqual((p/'transfer').read_text(),tid)
 def test_runtime_storage_failure_is_fail_closed(self):
  s=object.__new__(BoundedServer); s.storage_paths=['/unused']; s.storage_capacity_mib=1024
  with patch('storage_guard.verify_bounded_filesystem',side_effect=ValueError('reserve')):
   with self.assertRaises(StorageError): s.check_storage()
  s.storage_paths=None
  with self.assertRaises(StorageError): s.check_storage()
 def test_expiry_cleanup_is_bounded_and_erases_key_fields(self):
  from registry import Registry
  from transfer_store import TransferStore
  with tempfile.TemporaryDirectory() as d:
   r=Registry(str(pathlib.Path(d)/'db')); r.initialize(); store=TransferStore(r,bytes(32),bytes(32)); store.initialize()
   with sqlite3.connect(r.path) as db:
    db.executemany("INSERT INTO transfer_keys VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", [('a','d',str(uuid.uuid4()),str(uuid.uuid4()),'upload',1,b'e',b'w',b'n',b'key',300,'active') for _ in range(513)])
   self.assertEqual(store.cleanup(),512); self.assertEqual(store.cleanup(),1); self.assertEqual(store.cleanup(),0)
   with sqlite3.connect(r.path) as db: self.assertEqual(db.execute("SELECT count(*) FROM transfer_keys WHERE state='expired' AND length(key_cipher)=0 AND length(nonce)=0").fetchone()[0],513)
if __name__=='__main__': unittest.main(verbosity=2)
