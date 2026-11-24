import io, os, pathlib, sys, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from transfer_stream import CHUNK, InvalidEnvelope, encrypt, decrypt

class Bounded(io.BytesIO):
 def read(self,n=-1):
  if n<0 or n>CHUNK+64: raise AssertionError('unbounded read')
  return super().read(n)
class StreamTests(unittest.TestCase):
 def test_roundtrip_and_corruption(self):
  data=os.urandom(CHUNK*2+41); key=os.urandom(32); context=b'upload and transfer id'; encrypted=io.BytesIO()
  stats=encrypt(Bounded(data),encrypted,key,context); ct=encrypted.getvalue(); out=io.BytesIO()
  self.assertEqual(decrypt(Bounded(ct),out,key,context),stats); self.assertEqual(out.getvalue(),data)
  start=38; frame=5+CHUNK+16
  reordered=ct[:start]+ct[start+frame:start+2*frame]+ct[start:start+frame]+ct[start+2*frame:]
  for corrupted in (ct[:-1],ct+b'x',ct[:100]+bytes([ct[100]^1])+ct[101:],ct[:-1]+bytes([ct[-1]^1]),reordered):
   with self.assertRaises(InvalidEnvelope): decrypt(Bounded(corrupted),io.BytesIO(),key,context)
  with self.assertRaises(InvalidEnvelope): decrypt(Bounded(ct),io.BytesIO(),os.urandom(32),context)
  with self.assertRaises(InvalidEnvelope): decrypt(Bounded(ct),io.BytesIO(),key,b'other')
 def test_empty_and_randomized_keys(self):
  key=os.urandom(32); one=io.BytesIO(); two=io.BytesIO(); encrypt(io.BytesIO(b''),one,key,b'context'); encrypt(io.BytesIO(b''),two,key,b'context')
  self.assertNotEqual(one.getvalue(),two.getvalue()); self.assertEqual(decrypt(Bounded(one.getvalue()),io.BytesIO(),key,b'context')['size'],0)
if __name__=='__main__': unittest.main(verbosity=2)
