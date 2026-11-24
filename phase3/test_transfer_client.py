import json,os,pathlib,select,subprocess,sys,tempfile,unittest,uuid
from unittest.mock import patch
from pyhpke import OpenError
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from client import AuthenticatedClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry
from transfer_client import authorize,upload_tree,download_tree
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'
class ClientFlow(unittest.TestCase):
 def test_unexpected_hpke_exception_is_not_auth_failure(self):
  class Sock:
   def getpeercert(self,binary_form=False): return b'test server'
  class Conn: sock=Sock()
  class Fake:
   token='token'; conn=Conn(); owner='a'; device='d'
   def transfer_issue(self,*args,**kwargs): return {'id':str(uuid.uuid4()),'enc':bytes(32),'wrapped':bytes(48)}
  def bug(*args,**kwargs):
   try: raise RuntimeError('programming error')
   except RuntimeError as e: raise OpenError('unexpected') from e
  with patch('transfer_client.open_envelope',side_effect=bug):
   with self.assertRaises(OpenError) as cm: authorize(Fake(),None,str(uuid.uuid4()),'upload')
   self.assertIsInstance(cm.exception.__cause__,RuntimeError)
 def test_automatic_upload_download(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); received=root/'received'; packages=root/'packages'; dest=root/'dest'; source=root/'source'
   for p in (received,packages,dest,source): p.mkdir(mode=0o700)
   payload=os.urandom(1024*1024); (source/'data').write_bytes(payload)
   cert=str(root/'cert'); tlskey=str(root/'tlskey'); master=root/'master'; master.write_bytes(os.urandom(32)); master.chmod(0o600)
   r=Registry(str(root/'db')); r.initialize(); r.add_user('a'); ed=Ed25519PrivateKey.generate(); x=X25519PrivateKey.generate(); raw=lambda k:k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   r.enroll('a','d',raw(ed.public_key()),raw(x.public_key()),r.create_otp('a',300))
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',tlskey,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   proc=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',cert,'--key',tlskey,'--db',r.path,'--transfer-master',str(master),'--transfer-root',str(received),'--package-root',str(packages)],stdout=subprocess.PIPE,text=True)
   try:
    if not select.select([proc.stdout],[],[],5)[0]: self.fail('startup timeout')
    port=int(proc.stdout.readline())
    def connect():
     c=AuthenticatedClient('localhost',port,cert,'a','d',ed); c.authenticate(); return c
    c=connect()
    try:
     upload=authorize(c,x,str(uuid.uuid4()),'upload'); self.assertNotIn(repr(upload.key),repr(upload)); result=upload_tree(c,upload,str(source),d); self.assertEqual(result['bytes'],len(payload))
    finally: c.close()
    c=connect()
    try:
     pkg=c.package_create(upload.transfer_id,str(uuid.uuid4())); download=authorize(c,x,str(uuid.uuid4()),'download',pkg['package_id']); self.assertNotEqual(download.transfer_id,pkg['package_id']); result=download_tree(c,download,str(dest),d)
     self.assertEqual(result['bytes'],len(payload)); self.assertEqual((dest/download.transfer_id/'data').read_bytes(),payload)
    finally: c.close()
    self.assertFalse(any(p.name.startswith('.cs-client-') for p in root.iterdir()))
    creds=root/'credentials'; creds.mkdir(mode=0o700)
    for name,key in (('ed25519.key',ed),('x25519.key',x)):
     data=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()); path=creds/name; path.write_bytes(data); path.chmod(0o600)
    argv=[sys.executable,str(P/'transfer_cli.py'),'--port',str(port),'--ca',cert,'--owner','a','--device','d','--credential-dir',str(creds),'--staging-dir',d,'--staging-capacity-mib','1048576']
    def run(*args):
     proc2=subprocess.run(argv+list(args),capture_output=True,text=True,timeout=25); self.assertEqual(proc2.returncode,0,proc2.stderr); self.assertNotIn(x.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex(),proc2.stdout+proc2.stderr); return [json.loads(line) for line in proc2.stdout.splitlines()]
    cli_upload=run('upload',str(source)); cli_package=run('package-create',cli_upload[1]['transfer_id']); cli_download=run('download',cli_package[-1]['package_id'],str(dest))
    self.assertEqual((dest/cli_download[1]['transfer_id']/'data').read_bytes(),payload)
    self.assertTrue(run('package-list')[-1]['packages'])
   finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close()
if __name__=='__main__': unittest.main(verbosity=2)
