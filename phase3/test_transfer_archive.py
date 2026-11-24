import io, os, pathlib, sys, tarfile, tempfile, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from transfer_archive import InvalidArchive, pack, unpack
from transfer_compress import compress,decompress
from transfer_stream import encrypt,decrypt
class ArchiveTest(unittest.TestCase):
 def test_tree_secure_roundtrip(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)/'source'; dest=pathlib.Path(d)/'destination'; root.mkdir(mode=0o700); dest.mkdir(mode=0o700); (root/'dir').mkdir(); (root/'dir'/'file').write_bytes(os.urandom(8000))
   archive=io.BytesIO(); p=pack(str(root),archive); compressed=io.BytesIO(); compress(io.BytesIO(archive.getvalue()),compressed)
   ciphertext=io.BytesIO(); key=os.urandom(32); encrypt(io.BytesIO(compressed.getvalue()),ciphertext,key,b'context'); compressed2=io.BytesIO(); decrypt(io.BytesIO(ciphertext.getvalue()),compressed2,key,b'context')
   extracted=io.BytesIO(); decompress(io.BytesIO(compressed2.getvalue()),extracted); self.assertEqual(unpack(io.BytesIO(extracted.getvalue()),str(dest)),p); self.assertEqual((dest/'dir'/'file').read_bytes(),(root/'dir'/'file').read_bytes())
 def test_reject_unsafe_members(self):
  for name,kind in (('../escape','file'),('/absolute','file'),('link','symlink'),('hard','hardlink'),('sparse','sparse'),('bad/../../out','file')):
   with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
    dest=pathlib.Path(d)/'staging'; dest.mkdir(mode=0o700); b=io.BytesIO()
    with tarfile.open(fileobj=b,mode='w') as t:
     info=tarfile.TarInfo(name)
     if kind=='symlink': info.type=tarfile.SYMTYPE; info.linkname='/etc/passwd'
     if kind=='hardlink': info.type=tarfile.LNKTYPE; info.linkname='/etc/passwd'
     if kind=='sparse': info.type=tarfile.GNUTYPE_SPARSE
     t.addfile(info)
    with self.assertRaises(InvalidArchive): unpack(io.BytesIO(b.getvalue()),str(dest))
 def test_large_extension_rejected_before_processing(self):
  header=tarfile.TarInfo('extension'); header.type=tarfile.GNUTYPE_LONGNAME; header.size=512*1024*1024
  class Counting(io.BytesIO):
   def __init__(self,b): super().__init__(b); self.consumed=0
   def read(self,n=-1):
    data=super().read(n); self.consumed+=len(data); return data
  source=Counting(header.tobuf(format=tarfile.USTAR_FORMAT)+bytes(1024*1024))
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(InvalidArchive): unpack(source,d)
  self.assertLessEqual(source.consumed,10240)
 def test_duplicate_and_nonempty_staging_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   dest=pathlib.Path(d)/'staging'; dest.mkdir(mode=0o700); b=io.BytesIO()
   with tarfile.open(fileobj=b,mode='w') as t:
    for _ in range(2):
     item=tarfile.TarInfo('same'); item.size=1; t.addfile(item,io.BytesIO(b'x'))
   with self.assertRaises(InvalidArchive): unpack(io.BytesIO(b.getvalue()),str(dest))
   with self.assertRaises(InvalidArchive): unpack(io.BytesIO(b.getvalue()),str(dest))
 def test_symlink_and_hardlink_source_denied(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'real').write_text('x'); (root/'link').symlink_to('/etc/passwd')
   with self.assertRaises(InvalidArchive): pack(str(root),io.BytesIO())
   (root/'link').unlink(); os.link(root/'real',root/'hard')
   with self.assertRaises(InvalidArchive): pack(str(root),io.BytesIO())
if __name__=='__main__': unittest.main(verbosity=2)
