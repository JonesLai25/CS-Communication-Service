import hashlib,io,os,pathlib,select,signal,subprocess,sys,tempfile,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry,Conflict
from transfer_store import TransferStore
from transfer_crypto import context
from transfer_archive import pack
from transfer_compress import compress
from transfer_stream import encrypt
from resume_store import CHUNK,ResumeStore,key_check
P=pathlib.Path(__file__).resolve().parent
class Crash(unittest.TestCase):
 def test_kill_before_and_after_publication(self):
  for mode in ('chunk','before','after'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
    root=pathlib.Path(d)
    for p in ('resume','published','src'): (root/p).mkdir(mode=0o700)
    payload=os.urandom(CHUNK+55); (root/'src'/'f').write_bytes(payload)
    r=Registry(str(root/'db')); r.initialize(); r.add_user('a'); x=X25519PrivateKey.generate(); pub=x.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); r.enroll('a','dev',bytes(32),pub,r.create_otp('a',300))
    master=os.urandom(32); identity=os.urandom(32)
    for name,data in (('master',master),('identity',identity)): p=root/name; p.write_bytes(data); p.chmod(0o600)
    ts=TransferStore(r,master,identity); ts.initialize(); tid=ts.issue('a','dev',str(uuid.uuid4()),'upload',300)['id']; key=ts.get_key('a','dev',tid); binding=context(identity,'a','dev',tid,'upload')
    tar=io.BytesIO(); pack(str(root/'src'),tar); compressed=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),compressed); source=compressed.getvalue(); cipher=io.BytesIO(); encrypt(io.BytesIO(source),cipher,key,binding); data=cipher.getvalue()
    m={'version':1,'transfer_id':tid,'size':len(data),'chunks':(len(data)+CHUNK-1)//CHUNK,'cipher_sha256':hashlib.sha256(data).hexdigest(),'source_sha256':hashlib.sha256(source).hexdigest(),'key_check':key_check(key,binding),'context_sha256':hashlib.sha256(binding).hexdigest()}
    store=ResumeStore(r,ts,str(root/'resume'),str(root/'published')); store.initialize(); store.begin('a','dev',m,binding); (root/'first').write_bytes(data[:CHUNK]); (root/'first').chmod(0o600)
    if mode!='chunk':
     for i in range(m['chunks']): store.put('a','dev',tid,i,data[i*CHUNK:(i+1)*CHUNK])
    proc=subprocess.Popen([sys.executable,str(P/'fault_worker.py'),str(root),tid,mode],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
     if not select.select([proc.stdout],[],[],8)[0]: self.fail('fault worker did not reach checkpoint')
     self.assertEqual(proc.stdout.readline().strip(),{'chunk':'chunk-linked','before':'before-publish','after':'after-rename'}[mode]); proc.kill(); self.assertEqual(proc.wait(timeout=5),-signal.SIGKILL)
    finally:
     if proc.poll() is None: proc.kill(); proc.wait(timeout=5)
     proc.stdout.close(); proc.stderr.close()
    store.reconcile_all(); state=store.status('a','dev',tid)['state']
    if mode=='after':
     self.assertEqual(state,'complete'); self.assertEqual((root/'published'/tid/'f').read_bytes(),payload)
     with self.assertRaises(Conflict): ts.cancel('a','dev',tid)
    else:
     self.assertEqual(state,'receiving'); self.assertFalse((root/'published'/tid).exists())
     if mode=='chunk':
      for i in range(m['chunks']): store.put('a','dev',tid,i,data[i*CHUNK:(i+1)*CHUNK])
     self.assertEqual(store.finish('a','dev',tid,binding),{'status':'received'}); self.assertEqual((root/'published'/tid/'f').read_bytes(),payload)
    self.assertFalse(any(p.name.startswith('.cs-incoming-') for p in (root/'published').iterdir()))
if __name__=='__main__': unittest.main(verbosity=2)
