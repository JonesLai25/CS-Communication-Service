import os,pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from workspace_snapshot import InvalidWorkspace,copy_tree,publish,recover
class Workspace(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name); self.original=self.root/'alice'; self.scratch=self.root/'scratch'; self.original.mkdir(mode=0o700); self.scratch.mkdir(mode=0o700); (self.original/'file').write_bytes(b'before')
 def tearDown(self): self.tmp.cleanup()
 def test_snapshot_atomic_publish(self):
  digest=copy_tree(self.original,self.scratch); (self.scratch/'file').write_bytes(b'after'); publish(self.scratch,self.original,digest,'testtoken')
  self.assertEqual((self.original/'file').read_bytes(),b'after'); self.assertEqual(list(self.root.glob('.cs-exec-stage-*')),[])
 def test_changed_original_does_not_publish(self):
  digest=copy_tree(self.original,self.scratch); (self.original/'file').write_bytes(b'changed'); (self.scratch/'file').write_bytes(b'after')
  with self.assertRaises(InvalidWorkspace): publish(self.scratch,self.original,digest,'testtoken')
  self.assertEqual((self.original/'file').read_bytes(),b'changed')
 def test_symlink_and_hardlink_rejected(self):
  (self.scratch/'bad').symlink_to('/etc/passwd')
  with self.assertRaises(InvalidWorkspace): copy_tree(self.scratch)
  (self.scratch/'bad').unlink(); os.link(self.original/'file',self.scratch/'link')
  with self.assertRaises(InvalidWorkspace): copy_tree(self.scratch)
 def test_workspace_size_is_bounded(self):
  with patch('workspace_snapshot.MAX_BYTES',3):
   with self.assertRaisesRegex(InvalidWorkspace,'too large'): copy_tree(self.original)
 def test_recovery_before_and_after_atomic_exchange(self):
  digest=copy_tree(self.original,self.scratch); (self.scratch/'file').write_bytes(b'after')
  class FailedRename:
   def renameat2(self,*args): return -1
  with patch('workspace_snapshot.ctypes.CDLL',return_value=FailedRename()):
   with self.assertRaises(OSError): publish(self.scratch,self.original,digest,'before')
  recover(self.original,'before'); self.assertEqual((self.original/'file').read_bytes(),b'before')
  import workspace_snapshot
  marker=workspace_snapshot._marker; calls=[]
  def fail_after(fd,name,record):
   calls.append(record['state'])
   if record['state']=='committed': raise OSError('injected crash after exchange')
   return marker(fd,name,record)
  with patch('workspace_snapshot._marker',side_effect=fail_after):
   with self.assertRaises(OSError): publish(self.scratch,self.original,digest,'after')
  self.assertEqual(calls,['prepared','committed']); recover(self.original,'after'); self.assertEqual((self.original/'file').read_bytes(),b'after'); self.assertEqual(list(self.root.glob('.cs-exec-*')),[])
if __name__=='__main__': unittest.main(verbosity=2)
