"""Real TLS tests use only disposable credentials, workspaces and owned processes."""
import concurrent.futures,json,os,pathlib,select,subprocess,sys,tempfile,time,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
from resource_guard import enforce
enforce(80*1024*1024,96*1024*1024,32,400000)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from registry import Registry
from client import AuthenticatedClient,AuthorizationError,ProtocolError
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'
class TLSExec(unittest.TestCase):
 def test_unsafe_workspace_configuration_disables_exec_only(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); cert=root/'cert'; key=root/'key'; reg=Registry(str(root/'db')); reg.initialize(); ed=Ed25519PrivateKey.generate(); raw=ed.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); reg.provision('alice','pc',raw)
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   p=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',str(cert),'--key',str(key),'--db',reg.path,'--exec-root',str(root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   try:
    if not select.select([p.stdout],[],[],8)[0]: self.fail('server startup deadline')
    port=int(p.stdout.readline()); c=AuthenticatedClient('localhost',port,str(cert),'alice','pc',ed)
    try:
     c.authenticate()
     with self.assertRaises(AuthorizationError): c.exec_submit(str(uuid.uuid4()),'alice',['/usr/bin/true'],5)
    finally: c.close()
   finally:
    if p.poll() is None: p.terminate()
    try: out,err=p.communicate(timeout=5)
    except subprocess.TimeoutExpired: p.kill(); out,err=p.communicate(timeout=5)
   self.assertIn('exec disabled:',err)
   workspace=root/'work'; workspace.mkdir(mode=0o700); (workspace/'alice').mkdir(mode=0o700)
   wrapper=root/'injected_server.py'
   wrapper.write_text("import sys; sys.path.insert(0,"+repr(str(P))+"); import exec_controller,server; from sandbox import SandboxUnavailable; exec_controller.ExecController.preflight=lambda self: (_ for _ in ()).throw(SandboxUnavailable('test')); sys.argv=['server','--cert',"+repr(str(cert))+",'--key',"+repr(str(key))+",'--db',"+repr(reg.path)+",'--exec-root',"+repr(str(workspace))+"]; server.main()")
   p=subprocess.Popen([sys.executable,str(wrapper)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   try:
    if not select.select([p.stdout],[],[],8)[0]: self.fail('mutant startup deadline')
    port=int(p.stdout.readline()); c=AuthenticatedClient('localhost',port,str(cert),'alice','pc',ed)
    try:
     c.authenticate()
     with self.assertRaises(AuthorizationError): c.exec_submit(str(uuid.uuid4()),'alice',['/usr/bin/true'],5)
    finally: c.close()
   finally:
    if p.poll() is None: p.terminate()
    try: out,err=p.communicate(timeout=5)
    except subprocess.TimeoutExpired: p.kill(); out,err=p.communicate(timeout=5)
   self.assertIn('exec disabled: SandboxUnavailable',err)
 def test_authenticated_reconnect_and_kill(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); work=root/'work'; work.mkdir(mode=0o700); (work/'alice').mkdir(mode=0o700); (work/'bob').mkdir(mode=0o700)
   cert=root/'cert'; tlskey=root/'tlskey'; reg=Registry(str(root/'db')); reg.initialize()
   alice=Ed25519PrivateKey.generate(); bob=Ed25519PrivateKey.generate(); raw=lambda k:k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   reg.provision('alice','pc',raw(alice)); reg.provision('bob','pc',raw(bob))
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tlskey),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   cmd=[sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',str(cert),'--key',str(tlskey),'--db',reg.path,'--exec-root',str(work)]
   def start():
    p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if not select.select([p.stdout],[],[],12)[0]: p.kill(); p.communicate(timeout=5); self.fail('server startup timeout')
    line=p.stdout.readline().strip()
    if not line.isdecimal(): p.kill(); _,err=p.communicate(timeout=5); self.fail('invalid server startup: '+line+err)
    return p,int(line)
   proc,port=start()
   try:
    def connect(owner='alice'):
     c=AuthenticatedClient('localhost',port,str(cert),owner,'pc',alice if owner=='alice' else bob); c.authenticate(); return c
    c=AuthenticatedClient('localhost',port,str(cert),'alice','pc',alice)
    try:
     with self.assertRaises(AuthorizationError): c.exec_submit(str(uuid.uuid4()),'alice',['/usr/bin/true'],5)
    finally: c.close()
    c=connect(); rid=str(uuid.uuid4()); code="from pathlib import Path; Path('out').write_text('success'); print('hello')"
    try:
     with self.assertRaises(AuthorizationError): c.exec_submit(str(uuid.uuid4()),'bob',['/usr/bin/true'],5)
     self.assertTrue(c.exec_submit(rid,'alice',['/usr/bin/python3','-c',code],5)['new'])
    finally: c.close()
    end=time.monotonic()+12
    while time.monotonic()<end:
     c=connect()
     try: result=c.exec_result(rid)
     finally: c.close()
     if result['state'] not in ('queued','running'): break
     time.sleep(.1)
    else: self.fail('execution deadline')
    self.assertEqual(result['state'],'succeeded'); self.assertEqual(result['stdout'],b'hello\n'); self.assertEqual((work/'alice'/'out').read_text(),'success')
    c=connect(); c._authenticated_at-=46
    try: self.assertEqual(c.exec_wait(rid,10)['state'],'succeeded')
    finally: c.close()
    credentials=root/'credentials'; credentials.mkdir(mode=0o700)
    rawkey=alice.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()); (credentials/'ed25519.key').write_bytes(rawkey); (credentials/'ed25519.key').chmod(0o600)
    cli=[sys.executable,str(P/'exec_cli.py'),'--port',str(port),'--ca',str(cert),'--owner','alice','--device','pc','--credential-dir',str(credentials),'run','--timeout','5','--','/usr/bin/printf','cli-ok']
    ran=subprocess.run(cli,text=True,capture_output=True,timeout=20); self.assertEqual(ran.returncode,0,ran.stderr); messages=[json.loads(line) for line in ran.stdout.splitlines()]; self.assertEqual(messages[-1]['state'],'succeeded'); self.assertEqual(messages[-1]['stdout'],'cli-ok')
    failed=subprocess.run(cli[:-2]+['/usr/bin/false'],text=True,capture_output=True,timeout=20); self.assertNotEqual(failed.returncode,0); self.assertEqual(json.loads(failed.stdout.splitlines()[-1])['state'],'failed')
    same_id=str(uuid.uuid4()); same_code="from pathlib import Path; p=Path('count'); p.write_text(str(int(p.read_text())+1) if p.exists() else '1')"
    def submit_same(_):
     client=connect()
     try: return client.exec_submit(same_id,'alice',['/usr/bin/python3','-c',same_code],5)
     finally: client.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(submit_same,range(2)))
    self.assertEqual(sum(r['new'] for r in results),1)
    c=connect()
    try: self.assertEqual(c.exec_wait(same_id,10)['state'],'succeeded')
    finally: c.close()
    self.assertEqual((work/'alice'/'count').read_text(),'1')
    c=connect('bob')
    try: self.assertIsNone(c.exec_result(rid))
    finally: c.close()
    c=connect()
    try:
     self.assertFalse(c.exec_submit(rid,'alice',['/usr/bin/python3','-c',code],5)['new'])
     with self.assertRaises(ProtocolError): c.exec_submit(rid,'alice',['/usr/bin/false'],5)
     cancel_id=str(uuid.uuid4()); cancel_code="from pathlib import Path; import time; Path('cancelled').write_text('temporary'); time.sleep(20)"
     c.exec_submit(cancel_id,'alice',['/usr/bin/python3','-c',cancel_code],30)
     from workspace_snapshot import stage_name
     cancel_stage=pathlib.Path('/dev/shm')/stage_name(work,'alice',cancel_id); end=time.monotonic()+8
     while time.monotonic()<end:
      if (cancel_stage/'cancelled').exists(): break
      time.sleep(.05)
     else: self.fail('cancellation worker startup deadline')
     c.exec_cancel(cancel_id); cancelled=c.exec_wait(cancel_id,10); self.assertEqual(cancelled['state'],'cancelled'); self.assertFalse((work/'alice'/'cancelled').exists())
     rid2=str(uuid.uuid4()); code2="from pathlib import Path; import time; Path('partial').write_text('temporary'); time.sleep(20)"
     c.exec_submit(rid2,'alice',['/usr/bin/python3','-c',code2],30)
    finally: c.close()
    from workspace_snapshot import stage_name
    stage=pathlib.Path('/dev/shm')/stage_name(work,'alice',rid2); end=time.monotonic()+8
    while time.monotonic()<end:
     if (stage/'partial').exists(): break
     time.sleep(.05)
    else: self.fail('isolated command startup deadline')
    proc.kill(); proc.wait(timeout=5); proc.stdout.close(); proc.stderr.close(); proc,port=start()
    c=connect()
    try: self.assertEqual(c.exec_result(rid2)['state'],'unknown'); self.assertEqual(c.exec_result(rid)['state'],'succeeded')
    finally: c.close()
    self.assertFalse(stage.exists()); self.assertFalse((work/'alice'/'partial').exists())
    proc.terminate(); proc.wait(timeout=5); proc.stdout.close(); proc.stderr.close(); cmd=cmd[:-2]; proc,port=start()
    c=connect()
    try:
     self.assertEqual(c.exec_result(rid)['state'],'succeeded')
     with self.assertRaises(AuthorizationError): c.exec_submit(str(uuid.uuid4()),'alice',['/usr/bin/true'],5)
    finally: c.close()
   finally:
    if proc.poll() is None: proc.terminate()
    try: proc.wait(timeout=6)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close(); proc.stderr.close()
if __name__=='__main__': unittest.main(verbosity=2)
