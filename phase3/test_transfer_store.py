import concurrent.futures, os, pathlib, sqlite3, sys, tempfile, unittest, uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry, Conflict, Denied, StorageError
from transfer_crypto import open_envelope
from transfer_store import TransferStore
class Store(unittest.TestCase):
 def test_issue_recovery_and_cancellation(self):
  with tempfile.TemporaryDirectory() as d:
   r=Registry(d+'/db'); r.initialize(); r.add_user('alice'); key=X25519PrivateKey.generate(); pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   enrollment=r.create_otp('alice',300); r.enroll('alice','pc',bytes(32),pub,enrollment)
   identity=os.urandom(32); master=os.urandom(32); store=TransferStore(r,master,identity); store.initialize(); rid=str(uuid.uuid4())
   def issue(_): return store.issue('alice','pc',rid,'upload',300)
   with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: first,second=list(pool.map(issue,range(2),timeout=5))
   self.assertEqual(first,second)
   otp=open_envelope(first['enc'],first['wrapped'],key,identity,'alice','pc',first['id'],'upload')
   self.assertEqual(TransferStore(r,master,identity).get_key('alice','pc',first['id']),otp)
   with self.assertRaises(ValueError): TransferStore(r,os.urandom(32),identity).initialize()
   with self.assertRaises(ValueError): TransferStore(r,master,os.urandom(32)).initialize()
   self.assertEqual(store.lookup('alice','pc',rid),first)
   self.assertIsNone(store.lookup('bob','pc',rid))
   with sqlite3.connect(d+'/db') as db:
    row=db.execute('SELECT key_cipher FROM transfer_keys').fetchone(); self.assertNotIn(otp,row[0]); self.assertNotIn(enrollment,row[0].hex())
   with sqlite3.connect(d+'/db') as db:
    saved=db.execute('SELECT key_cipher FROM transfer_keys').fetchone()[0]
    db.execute('UPDATE transfer_keys SET key_cipher=?',(saved[:-1]+bytes([saved[-1]^1]),))
   with self.assertRaises(StorageError): store.get_key('alice','pc',first['id'])
   with sqlite3.connect(d+'/db') as db: db.execute('UPDATE transfer_keys SET key_cipher=?',(saved,))
   with self.assertRaises(Conflict): store.issue('alice','pc',rid,'upload',301)
   with self.assertRaises(Denied): store.get_key('bob','pc',first['id'])
   store.cancel('alice','pc',first['id'])
   with self.assertRaises(Denied): store.get_key('alice','pc',first['id'])
   with self.assertRaises(Denied): issue(0)
   with sqlite3.connect(d+'/db') as db: self.assertEqual(db.execute('SELECT key_cipher FROM transfer_keys').fetchone()[0],b'')
   rid2=str(uuid.uuid4()); second=store.issue('alice','pc',rid2,'upload',30)
   with sqlite3.connect(d+'/db') as db: db.execute('UPDATE transfer_keys SET expires=0 WHERE id=?',(second['id'],))
   self.assertEqual(store.cleanup(),1)
   with self.assertRaises(Denied): store.issue('alice','pc',rid2,'upload',30)
   active=store.issue('alice','pc',str(uuid.uuid4()),'upload',30); published=[]
   r.revoke_device('alice','pc')
   with self.assertRaises(Denied): store.publish_if_authorized('alice','pc',active['id'],lambda:published.append(True))
   self.assertEqual(published,[])
   with self.assertRaises(Denied): store.issue('alice','pc',str(uuid.uuid4()),'upload',30)
 def test_legacy_key_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   r=Registry(d+'/db'); r.initialize(); r.provision('alice','legacy',bytes(32)); s=TransferStore(r,os.urandom(32),os.urandom(32)); s.initialize()
   with self.assertRaises(Denied): s.issue('alice','legacy',str(uuid.uuid4()),'upload')
if __name__=='__main__': unittest.main(verbosity=2)
