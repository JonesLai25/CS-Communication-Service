import hashlib,json,os,pathlib,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'phase1'))
from initialize_service import initialize
from service_cli import load_config
class Initialize(unittest.TestCase):
 def test_identity_is_not_replaced(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp); data=root/'data'; config=root/'config'; data.mkdir(mode=0o700); config.mkdir(mode=0o700)
   result=initialize(data,config,0,True); self.assertEqual(result['status'],'initialized'); instance=data/'instance'
   fields=('tls.key','tls.crt','master.key','registry.db'); before={n:hashlib.sha256((instance/n).read_bytes()).digest() for n in fields}
   value=load_config(config/'server.json'); self.assertEqual(value['exec_root'],str(instance/'workspaces')); self.assertEqual(value['port'],0)
   self.assertEqual(initialize(data,config,12345,False)['status'],'unchanged')
   self.assertEqual(before,{n:hashlib.sha256((instance/n).read_bytes()).digest() for n in fields}); self.assertEqual(load_config(config/'server.json')['port'],0)
 def test_unsafe_configuration_and_incomplete_identity_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp); data=root/'data'; config=root/'config'; data.mkdir(mode=0o700); config.mkdir(mode=0o700); instance=data/'instance'; instance.mkdir(mode=0o700)
   with self.assertRaises(ValueError): initialize(data,config,0,False)
   f=config/'wrong'; f.write_text('{"port":0,"port":1}'); f.chmod(0o600)
   with self.assertRaises(ValueError): load_config(f)
   f.chmod(0o644)
   with self.assertRaises(ValueError): load_config(f)
if __name__=='__main__': unittest.main(verbosity=2)
