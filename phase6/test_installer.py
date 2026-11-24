import hashlib,json,os,pathlib,sqlite3,subprocess,sys,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools')); sys.path.insert(0,str(ROOT/'phase6')); sys.path.insert(0,str(ROOT/'phase1'))
from resource_guard import enforce
enforce(144*1024*1024,128*1024*1024,64,400000)
import installer
PYTHON=ROOT/'.local-test/python312/bin/python3'; WHEELS=ROOT/'.local-test/ubuntu20-py312-wheels'; LOCK=ROOT/'phase3/requirements-ubuntu20-py312.lock'
class Installation(unittest.TestCase):
 def test_real_offline_install_upgrade_rollback_and_uninstall(self):
  with tempfile.TemporaryDirectory(prefix='cs-phase6-install-') as tmp:
   root=pathlib.Path(tmp)/'product'; result=installer.install(root,PYTHON,WHEELS,LOCK); self.assertEqual(result['status'],'installed'); original=os.readlink(root/'current')
   self.assertEqual(installer.install(root,PYTHON,WHEELS,LOCK)['status'],'unchanged'); data=root/'data'; (data/'identity').write_bytes(b'identity'); (data/'database').write_bytes(b'persisted-result'); (data/'workspace').mkdir(mode=0o700); (data/'workspace'/'file').write_bytes(b'workspace')
   (data/'.schema-epoch').write_text('2\n')
   with self.assertRaisesRegex(installer.InstallError,'incompatible data schema'): installer.install(root,PYTHON,WHEELS,LOCK)
   self.assertEqual(os.readlink(root/'current'),original); (data/'.schema-epoch').write_text('1\n')
   init=subprocess.run([str(root/'bin/cs-server'),'initialize','--port','0','--enable-exec'],capture_output=True,text=True,timeout=20)
   self.assertEqual(init.returncode,0,init.stderr); self.assertEqual(json.loads(init.stdout)['status'],'initialized'); instance=data/'instance'
   identities={n:hashlib.sha256((instance/n).read_bytes()).digest() for n in ('tls.key','tls.crt','master.key')}
   with sqlite3.connect(instance/'registry.db') as db: db.execute("INSERT INTO users(owner) VALUES('retained-user')")
   (instance/'workspaces'/'retained-user').mkdir(mode=0o700); (instance/'workspaces'/'retained-user'/'content').write_bytes(b'preserved')
   with patch.object(installer,'_version',return_value='b'*64),patch.object(installer,'_run',side_effect=installer.InstallError('injected dependency failure')):
    with self.assertRaises(installer.InstallError): installer.install(root,PYTHON,WHEELS,LOCK)
   self.assertEqual(os.readlink(root/'current'),original); self.assertEqual((data/'database').read_bytes(),b'persisted-result')
   with patch.object(installer,'_version',return_value='c'*64): result=installer.install(root,PYTHON,WHEELS,LOCK)
   self.assertEqual(result['status'],'upgraded'); upgraded=os.readlink(root/'current'); self.assertNotEqual(upgraded,original)
   self.assertEqual((data/'identity').read_bytes(),b'identity'); self.assertEqual((data/'workspace'/'file').read_bytes(),b'workspace')
   self.assertEqual(identities,{n:hashlib.sha256((instance/n).read_bytes()).digest() for n in identities})
   with sqlite3.connect(instance/'registry.db') as db: self.assertEqual(db.execute("SELECT count(*) FROM users WHERE owner='retained-user'").fetchone()[0],1)
   self.assertEqual((instance/'workspaces'/'retained-user'/'content').read_bytes(),b'preserved')
   app=root/upgraded/'app/client.py'; clean=app.read_bytes(); app.write_bytes(clean+b'\n# tampered\n')
   try:
    with self.assertRaisesRegex(installer.InstallError,'modified'): installer.install(root,PYTHON,WHEELS,LOCK)
    self.assertEqual(os.readlink(root/'current'),upgraded)
   finally: app.write_bytes(clean)
   link=installer._atomic_link; calls=[]
   def after_publish(path,target):
    link(path,target); calls.append(target)
    if len(calls)==1: raise OSError('injected post-publication failure')
   with patch.object(installer,'_version',return_value='d'*64),patch.object(installer,'_atomic_link',side_effect=after_publish):
    with self.assertRaisesRegex(OSError,'post-publication'): installer.install(root,PYTHON,WHEELS,LOCK)
   self.assertEqual(os.readlink(root/'current'),upgraded); self.assertEqual(len(calls),2)
   self.assertEqual((instance/'workspaces'/'retained-user'/'content').read_bytes(),b'preserved')
   from install_runtime import hold
   fd=hold(root)
   try:
    with self.assertRaisesRegex(installer.InstallError,'stop CS processes'): installer.uninstall(root)
    self.assertTrue((root/'current').is_symlink())
   finally: os.close(fd)
   self.assertEqual(installer.uninstall(root),{'status':'uninstalled','data_retained':True}); self.assertFalse((root/'current').exists()); self.assertEqual((data/'database').read_bytes(),b'persisted-result')
   self.assertEqual(list((root/'releases').iterdir()),[])
 def test_unmarked_or_symlink_prefix_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp); unknown=root/'unknown'; unknown.mkdir(mode=0o700); (unknown/'user-data').write_text('keep')
   with self.assertRaises(installer.InstallError): installer.install(unknown,PYTHON,WHEELS,LOCK)
   self.assertEqual((unknown/'user-data').read_text(),'keep')
   link=root/'link'; link.symlink_to(unknown,target_is_directory=True)
   with self.assertRaises(installer.InstallError): installer.install(link,PYTHON,WHEELS,LOCK)
if __name__=='__main__': unittest.main(verbosity=2)
