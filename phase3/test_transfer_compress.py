import io, os, pathlib, sys, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from transfer_compress import CHUNK,compress,decompress,InvalidCompressed
from transfer_stream import InvalidEnvelope,encrypt,decrypt
class StreamTests(unittest.TestCase):
 def test_roundtrip_and_limits(self):
  for data in (b'',os.urandom(CHUNK*2+37),b'\x00'*(CHUNK*3)):
   out=io.BytesIO(); stats=compress(io.BytesIO(data),out); encoded=out.getvalue(); decoded=io.BytesIO()
   self.assertEqual(decompress(io.BytesIO(encoded),decoded),stats); self.assertEqual(decoded.getvalue(),data)
   if data:
    with self.assertRaises(InvalidCompressed): decompress(io.BytesIO(encoded),io.BytesIO(),len(data)-1)
   for bad in (encoded[:-1],encoded+b'junk',encoded[:15]+bytes([encoded[15]^1])+encoded[16:]):
    with self.assertRaises((InvalidCompressed,InvalidEnvelope)): decompress(io.BytesIO(bad),io.BytesIO())
 def test_encrypt_compressed_roundtrip(self):
  original=os.urandom(CHUNK+100); otp=os.urandom(32); context=b'transfer scope'; packed=io.BytesIO(); compress(io.BytesIO(original),packed)
  cipher=io.BytesIO(); encrypt(io.BytesIO(packed.getvalue()),cipher,otp,context)
  verified=io.BytesIO(); decrypt(io.BytesIO(cipher.getvalue()),verified,otp,context)
  restored=io.BytesIO(); decompress(io.BytesIO(verified.getvalue()),restored)
  self.assertEqual(restored.getvalue(),original)
if __name__=='__main__': unittest.main(verbosity=2)
