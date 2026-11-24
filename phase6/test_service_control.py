import pathlib,sys,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'phase1'))
import service_control as sc
class Units(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name)/'product'; self.root.mkdir(mode=0o700); (self.root/'.cs-install-root').write_bytes(b'CS-INSTALL-v1\n'); (self.root/'.cs-install-root').chmod(0o600); self.units=pathlib.Path(self.tmp.name)/'units'; self.units.mkdir(mode=0o700)
 def tearDown(self): self.tmp.cleanup()
 def test_idempotent_safe_install_and_remove(self):
  unit=sc.install_unit(self.root,self.units,'user'); self.assertEqual(sc.install_unit(self.root,self.units,'user'),unit); self.assertTrue((self.root/'.unit-user-registered').exists())
  def fake(args,**kw):
   return type('R',(),{'returncode':3 if 'is-active' in args else 1,'stdout':'inactive\n' if 'is-active' in args else 'disabled\n','stderr':''})()
  with patch.object(sc.subprocess,'run',side_effect=fake): sc.remove_unit(self.root,self.units,'user')
  self.assertFalse(unit.exists()); self.assertFalse((self.root/'.unit-user-registered').exists())
 def test_unmanaged_collision_and_wrong_fragment_fail(self):
  path=self.units/sc.unit_name(self.root); path.write_text('other service'); path.chmod(0o600)
  with self.assertRaises(sc.ServiceError): sc.install_unit(self.root,self.units,'user')
  self.assertEqual(path.read_text(),'other service'); self.assertFalse((self.root/'.unit-user-registered').exists()); path.unlink()
  sc.install_unit(self.root,self.units,'user')
  with patch.object(sc.subprocess,'run',return_value=type('R',(),{'returncode':0,'stdout':'/other/unit\n','stderr':''})()) as run:
   with self.assertRaises(sc.ServiceError): sc.systemctl(self.root,self.units,'user','stop')
   self.assertEqual(run.call_count,1)
 def test_system_install_requires_real_administrator(self):
  with self.assertRaises(sc.ServiceError): sc.install_unit(self.root,self.units,'system')
if __name__=='__main__': unittest.main(verbosity=2)
