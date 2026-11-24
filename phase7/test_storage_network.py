"""Inject low free space only into an isolated test Server."""
import pathlib,select,sqlite3,subprocess,sys,tempfile,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from client import AuthenticatedClient,health,RemoteOperationError
from registry import Registry
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'
class StorageNetwork(unittest.TestCase):
 def test_low_reserve_rejects_writes_but_allows_authenticated_read(self):
  with tempfile.TemporaryDirectory(prefix='cs-low-space-') as d:
   root=pathlib.Path(d); cert=root/'cert'; key=root/'tlskey'; r=Registry(str(root/'db')); r.initialize(); ed=Ed25519PrivateKey.generate(); r.provision('alice','pc',ed.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   refused=subprocess.run([sys.executable,'-B',str(P/'server.py'),'--cert',str(cert),'--key',str(key),'--db',r.path],capture_output=True,text=True,timeout=10)
   self.assertNotEqual(refused.returncode,0); self.assertIn('storage_capacity_mib is required',refused.stderr)
   code="""import runpy,storage_guard,sys
original=storage_guard.verify_bounded_filesystem
def checked(paths,cap,minimum_free=0):
 if minimum_free: raise ValueError('injected low free space')
 return original(paths,cap,minimum_free)
storage_guard.verify_bounded_filesystem=checked
sys.argv=[sys.argv[1]]+sys.argv[2:]
runpy.run_path(sys.argv[0],run_name='__main__')
"""
   proc=subprocess.Popen([sys.executable,'-B','-c',code,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',str(cert),'--key',str(key),'--db',r.path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(P)})
   try:
    ready,_,_=select.select([proc.stdout],[],[],10); self.assertTrue(ready); line=proc.stdout.readline().strip(); self.assertTrue(line.isdecimal(),proc.stderr.read() if proc.poll() is not None else line); port=int(line)
    with self.assertRaises(RemoteOperationError): health('localhost',port,str(cert))
    c=AuthenticatedClient('localhost',port,str(cert),'alice','pc',ed)
    try:
     c.authenticate(); rid=str(uuid.uuid4()); status,body=c.call('POST','/v1/exec',{'request_id':rid,'workspace':'alice','argv':['/bin/true'],'timeout_seconds':1}); self.assertEqual(status,503); self.assertEqual(body,{'error':'storage_unavailable'})
    finally: c.close()
    with sqlite3.connect(r.path) as db: self.assertEqual(db.execute('SELECT count(*) FROM requests').fetchone()[0],0)
    with self.assertRaises(RemoteOperationError): health('localhost',port,str(cert))
   finally:
    if proc.poll() is None: proc.terminate()
    try: proc.communicate(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.communicate(timeout=5)
if __name__=='__main__': unittest.main(verbosity=2)
