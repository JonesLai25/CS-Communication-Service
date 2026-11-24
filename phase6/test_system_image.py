"""System installation exercise, only in a rootless isolated container."""
import os,pathlib,pwd,select,signal,stat,subprocess,sys,unittest,uuid
from unittest.mock import patch
if os.environ.get('CS_PHASE6_ISOLATED')!='1' or os.geteuid()!=0 or not pathlib.Path('/run/.containerenv').exists(): raise SystemExit('isolated container required')
rows=[list(map(int,x.split())) for x in pathlib.Path('/proc/self/uid_map').read_text().splitlines()]
if not any(a==0 and b!=0 for a,b,n in rows): raise SystemExit('host root namespace forbidden')
sys.path[:0]=['/work/phase6','/work/phase1']
import installer,system_installer,service_control
class SystemInstall(unittest.TestCase):
 def test_system_identity_install_and_preserved_data(self):
  name='cstest'+uuid.uuid4().hex[:10]; prefix=pathlib.Path('/work-tmp/product'); units=pathlib.Path('/tmp/units'); units.mkdir(mode=0o755)
  out=system_installer.install_system(prefix,'/opt/python/bin/python3','/wheels','/work/phase3/requirements-ubuntu20-py312.lock',name,0,False,str(units))
  user=pwd.getpwnam(name); self.assertGreater(user.pw_uid,0); self.assertEqual(out['service_uid'],user.pw_uid)
  for part in ('bin/cs-server','bin/cs-client','releases'):
   st=(prefix/part).stat(); self.assertEqual(st.st_uid,0); self.assertEqual(st.st_mode&0o022,0)
  for part in ('data','config','data/instance/tls.key'):
   st=(prefix/part).stat(); self.assertEqual(st.st_uid,user.pw_uid); self.assertEqual(st.st_mode&0o077,0)
  unit=pathlib.Path(out['unit']); text=unit.read_text(); self.assertIn('User='+name,text); self.assertIn('NoNewPrivileges=yes',text)
  def client_identity():
   os.setgroups([]); os.setgid(1000); os.setuid(1000)
  client=subprocess.run([str(prefix/'bin/cs-client')],capture_output=True,text=True,timeout=10,preexec_fn=client_identity)
  self.assertIn('usage: cs-client',client.stderr)
  cfg=prefix/'config/server.json'; settings=__import__('json').loads(cfg.read_text()); fs=os.statvfs(prefix/'data'); settings['storage_capacity_mib']=(fs.f_blocks*fs.f_frsize+1048575)//1048576; cfg.write_text(__import__('json').dumps(settings)); cfg.chmod(0o600)
  denied=subprocess.run([str(prefix/'bin/cs-server'),'serve'],capture_output=True,text=True,timeout=10)
  self.assertNotEqual(denied.returncode,0)
  def drop():
   os.setgroups([]); os.setgid(user.pw_gid); os.setuid(user.pw_uid)
  proc=subprocess.Popen([str(prefix/'bin/cs-server'),'serve'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True,preexec_fn=drop)
  try:
   ready,_,_=select.select([proc.stdout],[],[],20)
   self.assertTrue(ready,'non-root service startup deadline')
   line=proc.stdout.readline().strip(); self.assertTrue(line.isdecimal(),'non-root service failed to start: '+line)
   self.assertGreater(int(line),0); self.assertIsNone(proc.poll())
  finally:
   if proc.poll() is None: os.killpg(proc.pid,signal.SIGTERM)
   try: proc.communicate(timeout=10)
   except subprocess.TimeoutExpired:
    os.killpg(proc.pid,signal.SIGKILL); proc.communicate(timeout=5)
  with self.assertRaises(installer.InstallError): installer.uninstall(prefix,'system',user.pw_uid,user.pw_gid)
  class Result:
   returncode=0; stdout='inactive\n'; stderr=''
  def fake_run(args,**kwargs):
   r=Result(); r.stdout='disabled\n' if 'is-enabled' in args else 'inactive\n'; r.returncode=1 if 'is-enabled' in args else 3; return r
  with patch.object(service_control.subprocess,'run',side_effect=fake_run): service_control.remove_unit(prefix,units,'system',name)
  self.assertEqual(installer.uninstall(prefix,'system',user.pw_uid,user.pw_gid)['status'],'uninstalled')
  self.assertTrue((prefix/'data/instance/tls.key').is_file()); self.assertTrue((prefix/'config/server.json').is_file())
if __name__=='__main__': unittest.main(verbosity=2)
