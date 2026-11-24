import concurrent.futures,io,os,pathlib,sys,tempfile,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from outgoing import Packages
from registry import Registry,Denied,Conflict
from transfer_store import TransferStore
from transfer_crypto import open_envelope
from pyhpke import OpenError
from transfer_compress import decompress
from transfer_archive import unpack
from transfer_stream import decrypt
from transfer_crypto import context
class Outgoing(unittest.TestCase):
 def test_lifecycle_and_authorization(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); received=p/'received'; root=p/'packages'; target=p/'unpack'; received.mkdir(mode=0o700); root.mkdir(mode=0o700); target.mkdir(mode=0o700)
   r=Registry(str(p/'db')); r.initialize(); r.add_user('alice'); r.add_user('bob'); x=X25519PrivateKey.generate(); pub=x.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); otp=r.create_otp('alice',300); r.enroll('alice','laptop',bytes(32),pub,otp)
   bkey=X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); otp=r.create_otp('bob',300); r.enroll('bob','other',bytes(32),bkey,otp)
   extra=X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); r.enroll('alice','second',bytes(32),extra,r.create_otp('alice',300))
   transfers=TransferStore(r,os.urandom(32),os.urandom(32)); transfers.initialize(); upload=transfers.issue('alice','laptop',str(uuid.uuid4()),'upload',300)
   source=received/upload['id']; source.mkdir(mode=0o700); (source/'hello').write_text('package data')
   packages=Packages(r,str(root),str(received)); packages.initialize(); request_id=str(uuid.uuid4())
   with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(lambda _:packages.create('alice','laptop',upload['id'],request_id),range(2),timeout=10))
   self.assertEqual(results[0],results[1]); package=results[0]; self.assertEqual(packages.create('alice','second',upload['id'],request_id),package);
   with self.assertRaises(Conflict): packages.create('alice','laptop',str(uuid.uuid4()),request_id)
   (source/'hello').write_text('changed after package creation'); self.assertNotEqual(package['package_id'],upload['id']); self.assertEqual(packages.list('alice','laptop'),[package]); self.assertEqual(packages.list('bob','other'),[])
   with self.assertRaises(Denied): packages.open_verified('bob','other',package['package_id'])
   fd,size=packages.open_verified('alice','laptop',package['package_id'])
   with os.fdopen(fd,'rb') as f:
    archive=io.BytesIO(); decompress(f,archive)
   unpack(io.BytesIO(archive.getvalue()),str(target)); self.assertEqual((target/'hello').read_text(),'package data')
   blob=root/package['package_id']; self.assertEqual(blob.stat().st_mode & 0o777,0o600); blob.chmod(0o644)
   with self.assertRaises(ValueError): packages.open_verified('alice','laptop',package['package_id'])
   blob.chmod(0o600); original=blob.read_bytes(); blob.write_bytes(original[:-1]+bytes([original[-1]^1]))
   with self.assertRaises(ValueError): packages.open_verified('alice','laptop',package['package_id'])
   blob.write_bytes(original)
   download_request=str(uuid.uuid4()); active=transfers.issue_download('alice','laptop',download_request,package['package_id'],30)
   self.assertEqual(transfers.issue_download('alice','laptop',download_request,package['package_id'],30),active)
   key=open_envelope(active['enc'],active['wrapped'],x,transfers.server_identity,'alice','laptop',active['id'],'download',package['package_id'])
   self.assertEqual(transfers.get_key('alice','laptop',active['id'],'download'),key)
   with self.assertRaises(OpenError): open_envelope(active['enc'],active['wrapped'],x,transfers.server_identity,'alice','laptop',active['id'],'download',str(uuid.uuid4()))
   with self.assertRaises(Denied): transfers.issue_download('bob','other',str(uuid.uuid4()),package['package_id'],30)
   fd,n,pid=packages.prepare_download(transfers,'alice','laptop',active['id'])
   with os.fdopen(fd,'rb') as f: ciphertext=f.read()
   fd,n2,pid2=packages.prepare_download(transfers,'alice','laptop',active['id'])
   with os.fdopen(fd,'rb') as f: self.assertEqual(f.read(),ciphertext)
   self.assertEqual((n,pid),(n2,pid2))
   stored=root/('download-'+active['id']); self.assertEqual(stored.stat().st_mode & 0o777,0o600); stored.write_bytes(ciphertext[:-1]+bytes([ciphertext[-1]^1]))
   with self.assertRaises(ValueError): packages.open_download(transfers,'alice','laptop',active['id'])
   stored.write_bytes(ciphertext)
   decoded=io.BytesIO(); decrypt(io.BytesIO(ciphertext),decoded,key,context(transfers.server_identity,'alice','laptop',active['id'],'download',package['package_id']))
   restored=io.BytesIO(); decompress(io.BytesIO(decoded.getvalue()),restored)
   target2=p/'unpack2'; target2.mkdir(mode=0o700); unpack(io.BytesIO(restored.getvalue()),str(target2)); self.assertEqual((target2/'hello').read_text(),'package data')
   with self.assertRaises(Conflict): packages.retire('alice','laptop',package['package_id'])
   transfers.cancel('alice','laptop',active['id']); packages.cleanup_download(active['id']); self.assertFalse((root/('download-'+active['id'])).exists()); packages.retire('alice','laptop',package['package_id']); self.assertEqual(packages.list('alice','laptop'),[]); self.assertFalse(blob.exists())
   with self.assertRaises(Denied): packages.open_verified('alice','laptop',package['package_id'])
 def test_expiry_revokes_transfer_and_cleans_files(self):
  with tempfile.TemporaryDirectory() as d:
   import sqlite3
   p=pathlib.Path(d); received=p/'received'; root=p/'packages'; received.mkdir(mode=0o700); root.mkdir(mode=0o700)
   r=Registry(str(p/'db')); r.initialize(); r.add_user('a'); x=X25519PrivateKey.generate(); pub=x.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); r.enroll('a','d',bytes(32),pub,r.create_otp('a',300))
   transfers=TransferStore(r,os.urandom(32),os.urandom(32)); transfers.initialize(); upload=transfers.issue('a','d',str(uuid.uuid4()),'upload',300); source=received/upload['id']; source.mkdir(mode=0o700); (source/'file').write_text('x')
   packages=Packages(r,str(root),str(received)); packages.initialize(); package=packages.create('a','d',upload['id'],str(uuid.uuid4())); down=transfers.issue_download('a','d',str(uuid.uuid4()),package['package_id'],300)
   fd,_,_=packages.prepare_download(transfers,'a','d',down['id']); os.close(fd)
   with sqlite3.connect(p/'db') as db: db.execute('UPDATE outgoing_packages SET created=0 WHERE id=?',(package['package_id'],))
   with self.assertRaises(Denied): transfers.download_info('a','d',down['id'])
   self.assertEqual(packages.cleanup_expired(transfers),(1,1)); self.assertEqual(list(root.iterdir()),[])
   with self.assertRaises(Denied): transfers.get_key('a','d',down['id'])
 def test_unindexed_source_and_disabled_device_denied(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); root=p/'root'; recv=p/'recv'; root.mkdir(mode=0o700); recv.mkdir(mode=0o700); r=Registry(str(p/'db')); r.initialize(); r.provision('alice','legacy',bytes(32)); TransferStore(r,os.urandom(32),os.urandom(32)).initialize(); packages=Packages(r,str(root),str(recv)); packages.initialize()
   with self.assertRaises(Denied): packages.create('alice','legacy',str(uuid.uuid4()),str(uuid.uuid4()))
   r.revoke_device('alice','legacy')
   with self.assertRaises(Denied): packages.list('alice','legacy')
if __name__=='__main__': unittest.main(verbosity=2)
