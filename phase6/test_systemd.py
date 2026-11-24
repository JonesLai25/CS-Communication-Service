import pathlib,subprocess,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'phase1'))
from systemd_unit import render,sysusers
class Units(unittest.TestCase):
 def test_unit_permissions_and_syntax(self):
  with tempfile.TemporaryDirectory(prefix='cs phase6 ') as tmp:
   root=pathlib.Path(tmp); (root/'bin').mkdir(); launcher=root/'bin/cs-server'; launcher.write_text('#!/bin/sh\nexit 0\n'); launcher.chmod(0o700)
   (root/'config').mkdir(); config=root/'config/server.json'; config.write_text('{}')
   for mode in ('user','system'):
    text=render(root,config,mode); self.assertIn('NoNewPrivileges=yes',text)
    if mode=='system': self.assertIn('User=csservice',text); self.assertNotIn('User=root',text)
    else: self.assertNotIn('User=',text)
    unit=root/('cs-'+mode+'.service'); unit.write_text(text)
    p=subprocess.run(['systemd-analyze','verify',str(unit)],capture_output=True,text=True,timeout=15)
    self.assertEqual(p.returncode,0,p.stderr)
  self.assertIn('csservice',sysusers())
  with self.assertRaises(ValueError): render('/tmp','/tmp/config/server.json','system','root')
if __name__=='__main__': unittest.main(verbosity=2)
