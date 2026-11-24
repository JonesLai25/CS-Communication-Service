"""Install and exercise the actual artifact in an Ubuntu 20 user space."""
import errno,json,os,pathlib,select,socket,sqlite3,ssl,subprocess,sys,tempfile,unittest
if os.environ.get('CS_PHASE7_CONTAINER')!='1' or os.geteuid()==0 or not pathlib.Path('/run/.containerenv').exists(): raise SystemExit('non-root isolated container required')
if 'VERSION_ID="20.04"' not in pathlib.Path('/etc/os-release').read_text(): raise SystemExit('Ubuntu 20.04 user space required')
sys.path.insert(0,'/work/phase7')
from release import extract
class ReleaseContainer(unittest.TestCase):
 def test_install_start_tls_and_uninstall(self):
  root=pathlib.Path('/work-tmp'); package=root/'release'; package.mkdir(mode=0o700); meta=extract('/release.zip',package); self.assertEqual(len(meta['git_commit']),40)
  prefix=root/'product'; python='/opt/python/bin/python3'
  def run(args,timeout=30):
   p=subprocess.run([str(a) for a in args],capture_output=True,text=True,timeout=timeout)
   self.assertEqual(p.returncode,0,p.stderr[-3000:]); return p.stdout
  install=[python,'-B',package/'phase6/installer.py']; run(install+['install','--prefix',prefix,'--python',python,'--wheelhouse',package/'wheels','--lock',package/'phase3/requirements-ubuntu20-py312.lock'],120)
  with socket.socket() as s: s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
  server=prefix/'bin/cs-server'; run([server,'initialize','--port',port],30)
  refused=subprocess.run([str(server),'serve'],capture_output=True,text=True,timeout=10); self.assertNotEqual(refused.returncode,0); self.assertIn('storage_capacity_mib is required',refused.stderr)
  cfg=prefix/'config/server.json'; settings=json.loads(cfg.read_text()); fs=os.statvfs(prefix/'data'); settings['storage_capacity_mib']=(fs.f_blocks*fs.f_frsize+1048575)//1048576; cfg.write_text(json.dumps(settings)); cfg.chmod(0o600)
  p=subprocess.Popen([str(server),'serve'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  try:
   ready,_,_=select.select([p.stdout],[],[],20); self.assertTrue(ready,'startup deadline'); self.assertEqual(p.stdout.readline().strip(),str(port)); self.assertEqual(json.loads(run([server,'health']))['status'],'ok')
  finally:
   if p.poll() is None: p.terminate()
   try: p.communicate(timeout=10)
   except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=5)
  # A capacity smaller than the actual persistent filesystem fails closed.
  cfg=prefix/'config/server.json'; original=json.loads(cfg.read_text()); cfg.write_text(json.dumps({**original,'storage_capacity_mib':16})); cfg.chmod(0o600)
  refused=subprocess.run([str(server),'serve'],capture_output=True,text=True,timeout=15)
  self.assertNotEqual(refused.returncode,0); self.assertIn('filesystem capacity exceeds',refused.stderr)
  cfg.write_text(json.dumps(original)); cfg.chmod(0o600)
  # The actual tmpfs capacity is kernel-enforced; exercise the real Server on it.
  with tempfile.TemporaryDirectory(prefix='cs-guard-',dir='/tmp') as temp:
   base=pathlib.Path(temp); data=base/'data'; config=base/'config'; data.mkdir(mode=0o700); config.mkdir(mode=0o700)
   with socket.socket() as sock: sock.bind(('127.0.0.1',0)); guarded_port=sock.getsockname()[1]
   py=prefix/'current/venv/bin/python'; app=prefix/'current/app'
   run([py,'-B',app/'initialize_service.py','--data',data,'--config',config,'--port',guarded_port])
   conf=config/'server.json'; obj=json.loads(conf.read_text()); obj['storage_capacity_mib']=16; obj['listen']='127.0.0.2'; conf.write_text(json.dumps(obj)); conf.chmod(0o600)
   guarded=subprocess.Popen([str(py),'-B',str(app/'service_cli.py'),'--config',str(conf)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
   try:
    ready,_,_=select.select([guarded.stdout],[],[],20); self.assertTrue(ready); self.assertEqual(guarded.stdout.readline().strip(),str(guarded_port))
    context=ssl.create_default_context(cafile=str(data/'instance/tls.crt'))
    with socket.create_connection(('127.0.0.2',guarded_port),timeout=5) as raw:
     with context.wrap_socket(raw,server_hostname='localhost') as stream:
      stream.sendall(b'GET /v1/health HTTP/1.1\r\nHost: localhost\r\nX-Request-ID: 11111111-1111-4111-8111-111111111111\r\nConnection: close\r\n\r\n'); self.assertIn(b'503',stream.recv(4096))
    with self.assertRaises(OSError): socket.create_connection(('127.0.0.1',guarded_port),timeout=3)
    # Fill only this container's 16 MiB tmpfs and require a real ENOSPC.
    testdb=base/'isolated-full-test.db'; db=sqlite3.connect(testdb); db.execute('PRAGMA journal_mode=WAL'); db.execute('CREATE TABLE records(value BLOB)'); db.execute('INSERT INTO records VALUES(?)',(b'committed',)); db.commit()
    filler=base/'test-only-fill'; received_full=False
    try:
     with filler.open('wb',buffering=0) as f:
      for _ in range(20):
       try: f.write(b'x'*(1024*1024))
       except OSError as error:
        self.assertEqual(error.errno,errno.ENOSPC); received_full=True; break
     self.assertTrue(received_full,'bounded tmpfs did not enforce capacity')
     self.assertTrue((data/'instance/registry.db').is_file()); self.assertTrue((data/'instance/tls.key').is_file())
     with self.assertRaises(sqlite3.OperationalError) as full:
      db.execute('INSERT INTO records VALUES(?)',(b'z'*(2*1024*1024),)); db.commit()
     self.assertIn('full',str(full.exception).lower()); db.rollback()
    finally: filler.unlink(missing_ok=True)
    self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok'); self.assertEqual(db.execute('SELECT value FROM records').fetchall(),[(b'committed',)]); db.close()

   finally:
    if guarded.poll() is None: guarded.terminate()
    try: guarded.communicate(timeout=10)
    except subprocess.TimeoutExpired: guarded.kill(); guarded.communicate(timeout=5)
  run(install+['uninstall','--prefix',prefix]); self.assertTrue((prefix/'data/instance/tls.key').is_file())
if __name__=='__main__': unittest.main(verbosity=2)
