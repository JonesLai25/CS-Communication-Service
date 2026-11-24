"""Measure streaming RSS using generated input larger than the configured cap."""
import hashlib, os, pathlib, resource, sys, tempfile, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from transfer_stream import CHUNK, encrypt, decrypt
from transfer_compress import compress, decompress
SIZE=128*1024*1024
CAP_KIB=96*1024
class Generated:
 def __init__(self): self.left=SIZE
 def read(self,n):
  if n<0 or n>CHUNK: raise AssertionError('unbounded input')
  n=min(n,self.left); self.left-=n; return bytes(n)
class HashSink:
 def __init__(self): self.hash=hashlib.sha256(); self.size=0
 def write(self,data): self.hash.update(data); self.size+=len(data); return len(data)
class MemoryTest(unittest.TestCase):
 def test_large_stream(self):
  key=os.urandom(32)
  with tempfile.TemporaryFile() as f:
   result=encrypt(Generated(),f,key,b'memory test'); f.seek(0); sink=HashSink(); self.assertEqual(decrypt(f,sink,key,b'memory test'),result)
  self.assertEqual(sink.size,SIZE); self.assertEqual(sink.hash.hexdigest(),result['sha256'])
  rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
  print('data_bytes=%d peak_rss_kib=%d limit_kib=%d'%(SIZE,rss,CAP_KIB),flush=True)
  self.assertLess(rss,CAP_KIB)
 def test_compress_encrypt_pipeline(self):
  key=os.urandom(32)
  with tempfile.TemporaryFile() as packed, tempfile.TemporaryFile() as encrypted, tempfile.TemporaryFile() as verified:
   expected=compress(Generated(),packed); packed.seek(0); encrypt(packed,encrypted,key,b'memory test'); encrypted.seek(0); decrypt(encrypted,verified,key,b'memory test'); verified.seek(0)
   sink=HashSink(); self.assertEqual(decompress(verified,sink),expected); self.assertEqual(sink.size,SIZE); self.assertEqual(sink.hash.hexdigest(),expected['sha256'])
  rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss; print('pipeline_bytes=%d peak_rss_kib=%d limit_kib=%d'%(SIZE,rss,CAP_KIB),flush=True); self.assertLess(rss,CAP_KIB)
if __name__=='__main__': unittest.main(verbosity=2)
