import io,os,pathlib,sys,tarfile,tempfile,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from transfer_archive import InvalidArchive,pack
from transfer_compress import compress
from transfer_stream import encrypt,InvalidEnvelope
from transfer_ingest import receive
class Ingest(unittest.TestCase):
 def test_private_staging_and_no_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); src=p/'src'; root=p/'recv'; src.mkdir(mode=0o700); root.mkdir(mode=0o700); (src/'hello').write_text('hello')
   tar=io.BytesIO(); pack(str(src),tar); z=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),z); key=os.urandom(32); encrypted=io.BytesIO(); encrypt(io.BytesIO(z.getvalue()),encrypted,key,b'ctx'); data=encrypted.getvalue(); tid=str(uuid.uuid4())
   with self.assertRaises(InvalidEnvelope): receive(io.BytesIO(data),str(root),tid,os.urandom(32),b'ctx')
   self.assertEqual(list(root.iterdir()),[])
   receive(io.BytesIO(data),str(root),tid,key,b'ctx'); self.assertEqual((root/tid/'hello').read_text(),'hello')
   with self.assertRaises(FileExistsError): receive(io.BytesIO(data),str(root),tid,key,b'ctx')
   self.assertEqual((root/tid/'hello').read_text(),'hello'); self.assertEqual(sorted(x.name for x in root.iterdir()),[tid])
 def test_empty_existing_directory_is_not_replaced(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)/'recv'; root.mkdir(mode=0o700); tid=str(uuid.uuid4()); (root/tid).mkdir(); before=(root/tid).stat().st_ino
   tar=io.BytesIO()
   with tarfile.open(fileobj=tar,mode='w'): pass
   packed=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),packed); key=os.urandom(32); encrypted=io.BytesIO(); encrypt(io.BytesIO(packed.getvalue()),encrypted,key,b'ctx')
   with self.assertRaises(FileExistsError): receive(io.BytesIO(encrypted.getvalue()),str(root),tid,key,b'ctx')
   self.assertEqual((root/tid).stat().st_ino,before)
 def test_unsafe_archive_never_published(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)/'recv'; root.mkdir(mode=0o700); tar=io.BytesIO()
   with tarfile.open(fileobj=tar,mode='w') as t: t.addfile(tarfile.TarInfo('../escape'))
   z=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),z); key=os.urandom(32); encrypted=io.BytesIO(); encrypt(io.BytesIO(z.getvalue()),encrypted,key,b'ctx')
   with self.assertRaises(InvalidArchive): receive(io.BytesIO(encrypted.getvalue()),str(root),str(uuid.uuid4()),key,b'ctx')
   self.assertEqual(list(root.iterdir()),[])
if __name__=='__main__': unittest.main(verbosity=2)
