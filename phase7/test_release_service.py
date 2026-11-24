"""Real installed User Mode service in a uniquely owned transient systemd unit."""
import hashlib,json,os,pathlib,shutil,socket,sqlite3,subprocess,sys,time,unittest,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'phase1')); sys.path.insert(0,str(ROOT/'tools'))
from resource_guard import enforce
from exec_scope import test_slice
from client import health,NetworkError,TLSError
enforce(80*1024*1024,96*1024*1024,32,400000)
class InstalledService(unittest.TestCase):
 def test_installed_service_auth_transfer_exec_and_live_upgrade(self):
  root=pathlib.Path(os.environ['CS_PHASE7_TEST_ROOT']); case=root.parent
  if root.name!='product' or case.parent!=pathlib.Path('/tmp') or not case.name.startswith('cs-phase7-e2e.'): self.fail('invalid isolated test root')
  slice_name=test_slice(); self.assertIsNotNone(slice_name)
  with socket.socket() as sock: sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
  def run(args,timeout=30,input_data=None):
   p=subprocess.run([str(x) for x in args],input=input_data,capture_output=True,text=True,timeout=timeout)
   if p.returncode: self.fail('owned test command failed: '+p.stderr[-1000:])
   return p.stdout
  server=root/'bin/cs-server'; client=root/'bin/cs-client'; initialized=json.loads(run([server,'initialize','--port',str(port),'--enable-exec'],timeout=30)); self.assertEqual(initialized['status'],'initialized')
  instance=root/'data/instance'; cert=instance/'tls.crt'; workspace=instance/'workspaces/alice'; workspace.mkdir(mode=0o700)
  cfg=root/'config/server.json'; settings=json.loads(cfg.read_text()); fs=os.statvfs(instance); settings['storage_capacity_mib']=(fs.f_blocks*fs.f_frsize+1048575)//1048576; cfg.write_text(json.dumps(settings)); cfg.chmod(0o600)
  identities={name:hashlib.sha256((instance/name).read_bytes()).hexdigest() for name in ('tls.key','tls.crt','master.key')}; old=os.readlink(root/'current')
  unit='csphase7'+uuid.uuid4().hex[:12]+'.service'; self.assertRegex(unit,r'^csphase7[0-9a-f]{12}\.service$')
  cpu=min(os.sched_getaffinity(0)); systemctl=['/usr/bin/systemctl','--user']
  launch=['/usr/bin/systemd-run','--user','--quiet','--unit='+unit,'--slice='+slice_name,'--service-type=exec','--property=MemoryMax=64M','--property=MemorySwapMax=32M','--property=TasksMax=20','--property=NoNewPrivileges=yes','--property=CPUAffinity='+str(cpu),'--setenv=CS_PHASE5_TEST_SLICE='+slice_name,str(server),'serve']
  started=False
  def server_pid():
   output=run(systemctl+['show',unit,'--property=MainPID','--value'],timeout=10).strip()
   if not output.isdecimal(): self.fail('invalid service pid')
   return int(output)
  def wait_ready():
   end=time.monotonic()+20
   while time.monotonic()<end:
    try:
     if health('localhost',port,str(cert))['status']=='ok': return
    except (NetworkError,TLSError,OSError): time.sleep(.1)
   self.fail('service readiness deadline')
  try:
   run(launch,timeout=15); started=True; wait_ready(); pid=server_pid(); self.assertGreater(pid,1)
   status=pathlib.Path('/proc/%d/status'%pid).read_text(); uidline=next(x for x in status.splitlines() if x.startswith('Uid:')); self.assertEqual(int(uidline.split()[1]),os.geteuid()); self.assertNotEqual(os.geteuid(),0)
   self.assertIn(old.encode(),pathlib.Path('/proc/%d/cmdline'%pid).read_bytes())
   self.assertTrue(json.loads(run([server,'admin','user_add','--owner','alice']))['ok'])
   otp=json.loads(run([server,'admin','otp_create','--owner','alice','--ttl','300']))['otp']; cred=case/'credentials'
   enroll=[client,'enroll','--port',port,'--ca',cert,'--owner','alice','--device','pc','--credential-dir',cred]
   run(enroll,timeout=20,input_data=otp+'\n')
   source=case/'source'; source.mkdir(mode=0o700); (source/'sample').write_bytes(b'phase6 installed transfer')
   dest=case/'dest'; dest.mkdir(mode=0o700)
   transfer=[client,'transfer','--port',port,'--ca',cert,'--owner','alice','--device','pc','--credential-dir',cred,'--staging-dir',case,'--staging-capacity-mib','1048576']
   upload=[json.loads(x) for x in run(transfer+['upload',source],timeout=30).splitlines()]; tid=upload[1]['transfer_id']
   package=[json.loads(x) for x in run(transfer+['package-create',tid],timeout=30).splitlines()][-1]['package_id']
   downloaded=[json.loads(x) for x in run(transfer+['download',package,dest],timeout=30).splitlines()]; down=downloaded[1]['transfer_id']; self.assertEqual((dest/down/'sample').read_bytes(),b'phase6 installed transfer')
   execute=[client,'exec','--port',port,'--ca',cert,'--owner','alice','--device','pc','--credential-dir',cred]
   command=[json.loads(x) for x in run(execute+['run','--timeout','5','--','/usr/bin/python3','-c',"from pathlib import Path; Path('result').write_text('persisted'); print('ok')"],timeout=30).splitlines()]; rid=command[0]['request_id']; self.assertEqual(command[-1]['state'],'succeeded'); self.assertEqual((workspace/'result').read_text(),'persisted')
   # Commit one encrypted chunk, drop the test connection, restart only our service,
   # then use the installed CLI to recover the original immutable transfer.
   from transfer_cli import keys
   from transfer_client import authorize
   from client import AuthenticatedClient
   from resume_client import prepare_upload
   from resume_store import CHUNK
   (source/'random').write_bytes(os.urandom(CHUNK*3+111))
   ed,x=keys(str(cred)); conn=AuthenticatedClient('localhost',port,str(cert),'alice','pc',ed); conn.authenticate()
   try: handle=authorize(conn,x,str(uuid.uuid4()),'upload')
   finally: conn.close()
   resumework=case/'resume-upload'; manifest=prepare_upload(handle,str(source),str(resumework)); self.assertGreater(manifest['chunks'],1)
   conn=AuthenticatedClient('localhost',port,str(cert),'alice','pc',ed); conn.authenticate()
   try:
    conn.resume_begin(manifest)
    with (resumework/'cipher').open('rb') as f: self.assertTrue(conn.resume_chunk(handle.transfer_id,0,f.read(CHUNK)))
   finally: conn.close()
   run(systemctl+['restart',unit],timeout=20); wait_ready(); pid=server_pid()
   resumeclient=[client,'resume','--port',port,'--ca',cert,'--owner','alice','--device','pc','--credential-dir',cred,'--staging-capacity-mib','1048576']
   resumelines=[json.loads(x) for x in run(resumeclient+['resume',resumework,'--auto'],timeout=30).splitlines()]; resumed_id=handle.transfer_id
   self.assertEqual(resumelines[-1]['status'],'received'); self.assertEqual(json.loads(run(resumeclient+['status',resumed_id]))['state'],'complete')
   self.assertEqual((instance/'incoming'/resumed_id/'random').read_bytes(),(source/'random').read_bytes())
   self.assertEqual(json.loads(run([client,'cleanup','--directory',resumework,'--transfer-id',resumed_id]))['status'],'staging_cleaned')
   self.assertFalse((resumework/'cipher').exists()); self.assertTrue((resumework/'request').exists()); self.assertTrue((instance/'incoming'/resumed_id/'random').is_file())
   # A separate transfer is issued then cancelled, without affecting the completed one.
   from transfer_cli import keys
   from transfer_client import authorize
   from client import AuthenticatedClient
   ed,x=keys(str(cred)); conn=AuthenticatedClient('localhost',port,str(cert),'alice','pc',ed); conn.authenticate()
   try: to_cancel=authorize(conn,x,str(uuid.uuid4()),'upload')
   finally: conn.close()
   self.assertTrue(json.loads(run(resumeclient+['cancel',to_cancel.transfer_id]))['cancelled'])
   # The service must terminate the isolated command and retain its queryable result.
   submitted=[json.loads(x) for x in run(execute+['submit','--timeout','30','--','/usr/bin/python3','-c','import time; time.sleep(20)'],timeout=20).splitlines()]; cancel_id=submitted[0]['request_id']
   run(execute+['cancel',cancel_id],timeout=20)
   deadline=time.monotonic()+15; cancelled=None
   while time.monotonic()<deadline:
    cancelled=json.loads(run(execute+['status',cancel_id],timeout=10))
    if cancelled and cancelled.get('state') in ('cancelled','failed','succeeded','unknown'): break
    time.sleep(.1)
   self.assertEqual(cancelled['state'],'cancelled')
   build=case/'build'; build.mkdir(mode=0o700); shutil.copytree(ROOT/'phase1',build/'phase1',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
   with (build/'phase1/client.py').open('a') as f: f.write('\n# Isolated upgrade fixture.\n')
   code="import pathlib,sys; sys.path.insert(0,sys.argv[1]); import installer; installer.SOURCE=pathlib.Path(sys.argv[2]); installer.install(*sys.argv[3:])"
   upgrade=['/usr/bin/systemd-run','--user','--scope','--quiet','--slice='+slice_name,'-p','MemoryMax=112M','-p','MemorySwapMax=32M','-p','TasksMax=32','taskset','-c',str(cpu),str(ROOT/'.venv/bin/python'),'-B','-c',code,str(ROOT/'phase6'),str(build),str(root),str(ROOT/'.local-test/python312/bin/python3'),str(ROOT/'.local-test/ubuntu20-py312-wheels'),str(ROOT/'phase3/requirements-ubuntu20-py312.lock')]
   run(upgrade,timeout=120); new=os.readlink(root/'current'); self.assertNotEqual(new,old); self.assertEqual(server_pid(),pid); self.assertIn(old.encode(),pathlib.Path('/proc/%d/cmdline'%pid).read_bytes())
   self.assertEqual(json.loads(run(execute+['status',rid]))['state'],'succeeded')
   run(systemctl+['restart',unit],timeout=20); wait_ready(); newpid=server_pid(); self.assertIn(new.encode(),pathlib.Path('/proc/%d/cmdline'%newpid).read_bytes())
   self.assertEqual(identities,{name:hashlib.sha256((instance/name).read_bytes()).hexdigest() for name in identities}); self.assertEqual((workspace/'result').read_text(),'persisted'); self.assertEqual(json.loads(run(execute+['status',rid]))['state'],'succeeded')
   self.assertTrue(any(x['owner']=='alice' for x in json.loads(run([server,'admin','user_list']))['users']))
   self.assertEqual(json.loads(run(execute+['status',cancel_id]))['state'],'cancelled')
   # Expire old terminal payloads without allowing the same Request ID to run again.
   with sqlite3.connect(instance/'registry.db') as db: db.execute('UPDATE exec_jobs SET updated=1 WHERE owner=? AND id=?',('alice',rid))
   from registry import Registry
   from exec_journal import ExecJournal
   self.assertEqual(ExecJournal(Registry(str(instance/'registry.db'))).prune_results(90),1)
   self.assertEqual(json.loads(run(execute+['status',rid]))['state'],'expired')
   again=[json.loads(x) for x in run(execute+['submit','--request-id',rid,'--timeout','5','--','/usr/bin/python3','-c',"from pathlib import Path; Path('result').write_text('persisted'); print('ok')"]).splitlines()]
   self.assertFalse(again[-1]['new']); self.assertEqual(again[-1]['state'],'expired'); self.assertEqual((workspace/'result').read_text(),'persisted')
   total=sum(os.lstat(pathlib.Path(base)/name).st_blocks*512 for base,dirs,files in os.walk(case) for name in files if not (pathlib.Path(base)/name).is_symlink())
   print('sampled test allocated bytes:',total,'limit:',512*1024*1024,flush=True); self.assertLessEqual(total,512*1024*1024)
  finally:
   if started:
    stopped=subprocess.run(systemctl+['stop',unit],capture_output=True,text=True,timeout=20)
    if stopped.returncode: self.fail('test-owned transient service cleanup failed: '+stopped.stderr[-500:])
  run([ROOT/'.local-test/python312/bin/python3',case/'release/phase6/installer.py','uninstall','--prefix',root],timeout=30)
  self.assertFalse((root/'current').exists()); self.assertTrue((instance/'registry.db').is_file()); self.assertTrue((instance/'tls.key').is_file()); self.assertEqual((workspace/'result').read_text(),'persisted')
if __name__=='__main__': unittest.main(verbosity=2)
