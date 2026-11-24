import json,os,pathlib,stat,sys,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'phase1'))
from storage_guard import verify_bounded_filesystem
from service_cli import load_config
class StorageGuard(unittest.TestCase):
 def test_kernel_capacity_check_and_rejections(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); a=p/'a'; b=p/'b'; a.mkdir(mode=0o700); b.mkdir(mode=0o700)
   class V: f_blocks=16384; f_frsize=1024; f_bavail=8192
   with patch('storage_guard.os.fstatvfs',return_value=V()):
    self.assertEqual(verify_bounded_filesystem([a,b],16),16*1024*1024)
    with self.assertRaisesRegex(ValueError,'reserve'): verify_bounded_filesystem([a],16,9*1024*1024)
    with self.assertRaisesRegex(ValueError,'limit'): verify_bounded_filesystem([a],15)
    link=p/'link'; link.symlink_to(a,target_is_directory=True)
    with self.assertRaisesRegex(ValueError,'symlinks'): verify_bounded_filesystem([link],16)
    b.chmod(0o755)
    with self.assertRaisesRegex(ValueError,'private'): verify_bounded_filesystem([b],16)
   class Large: f_blocks=16385; f_frsize=1024
   with patch('storage_guard.os.fstatvfs',return_value=Large()):
    with self.assertRaisesRegex(ValueError,'exceeds'): verify_bounded_filesystem([a],16)
   first=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=os.geteuid(),st_dev=1)
   second=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=os.geteuid(),st_dev=2)
   with patch('storage_guard.os.fstatvfs',return_value=V()),patch('storage_guard.os.fstat',side_effect=[first,second]):
    with self.assertRaisesRegex(ValueError,'different filesystems'): verify_bounded_filesystem([a,b],16)
 def test_listen_configuration_requires_ipv4(self):
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d)/'server.json'; base={'cert':'/cert','key':'/key','db':'/db','port':18443}
   for value in ('0.0.0.0','192.0.2.20','127.0.0.1'):
    path.write_text(json.dumps({**base,'listen':value})); path.chmod(0o600); self.assertEqual(load_config(path)['listen'],value)
   for value in ('localhost','::1','300.1.1.1',True):
    path.write_text(json.dumps({**base,'listen':value})); path.chmod(0o600)
    with self.assertRaises(ValueError): load_config(path)
 def test_reject_invalid_limit(self):
  for value in (True,0,15,1048577,'16'):
   with self.assertRaises(ValueError): verify_bounded_filesystem(['/tmp'],value)
if __name__=='__main__': unittest.main(verbosity=2)
