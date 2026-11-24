"""Local-only tests of lock, stale socket recovery and non-socket refusal."""
import pathlib,socket,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from admin import Server
from registry import Registry
class Recovery(unittest.TestCase):
 def test_lock_stale_and_unsafe_path(self):
  with tempfile.TemporaryDirectory() as d:
   reg=Registry(d+'/db'); reg.initialize(); path=d+'/admin.sock'
   first=Server(path,reg)
   try:
    with self.assertRaises(BlockingIOError): Server(path,reg)
   finally: first.server_close()
   with socket.socket(socket.AF_UNIX) as sock: sock.bind(path)
   recovered=Server(path,reg); recovered.server_close()
   pathlib.Path(path).write_text('test canary')
   with self.assertRaises(ValueError): Server(path,reg)
   self.assertEqual(pathlib.Path(path).read_text(),'test canary')
if __name__=='__main__': unittest.main(verbosity=2)
