import io,pathlib,sys,threading,time,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from server import ConnectionDeadline
from registry import Denied
from client import _BoundedSource
class DeadlineTests(unittest.TestCase):
 def test_single_extension_and_cancel(self):
  class Transport:
   def __init__(self): self.expired=threading.Event()
   def shutdown(self,how): self.expired.set()
  first=Transport(); deadline=ConnectionDeadline(first,.05); deadline.extend_once(.18); deadline.extend_once(1)
  self.assertFalse(first.expired.wait(.10)); self.assertTrue(first.expired.wait(.30))
  with self.assertRaises(Denied): deadline.extend_once(.1)
  deadline.cancel()
  second=Transport(); deadline=ConnectionDeadline(second,.05); deadline.cancel(); self.assertFalse(second.expired.wait(.10))
 def test_upload_source_absolute_deadline(self):
  with self.assertRaises(TimeoutError): _BoundedSource(io.BytesIO(b'x'),1,time.monotonic()-1).read(1)
  source=_BoundedSource(io.BytesIO(b'abc'),2,time.monotonic()+1)
  self.assertEqual(source.read(4),b'ab'); self.assertEqual(source.read(4),b'')
if __name__=='__main__': unittest.main(verbosity=2)
