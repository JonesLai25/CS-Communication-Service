import pathlib,select,subprocess,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from workspace_snapshot import recover
HERE=pathlib.Path(__file__).resolve().parent
class Crash(unittest.TestCase):
 def test_owned_sigkill_at_atomic_boundary(self):
  for checkpoint,expected in (('before','before'),('after','after')):
   with self.subTest(checkpoint=checkpoint),tempfile.TemporaryDirectory() as d:
    root=pathlib.Path(d); (root/'workspace').mkdir(mode=0o700); (root/'stage').mkdir(mode=0o700); (root/'workspace'/'item').write_text('before')
    p=subprocess.Popen([sys.executable,str(HERE/'workspace_crash_worker.py'),d,checkpoint],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
     if not select.select([p.stdout],[],[],8)[0] or p.stdout.readline().strip()!='AT_CHECKPOINT': self.fail('owned crash worker startup deadline')
     p.kill(); self.assertEqual(p.wait(timeout=5),-9)
    finally:
     if p.poll() is None: p.kill(); p.wait(timeout=5)
     p.stdout.close(); p.stderr.close()
    recover(root/'workspace','crashtest'); self.assertEqual((root/'workspace'/'item').read_text(),expected); self.assertEqual(list(root.glob('.cs-exec-*')),[])
if __name__=='__main__': unittest.main(verbosity=2)
