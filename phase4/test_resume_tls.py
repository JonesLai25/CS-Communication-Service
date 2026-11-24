import os,pathlib,select,sqlite3,subprocess,sys,tempfile,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from client import AuthenticatedClient,UnknownOutcome
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry
from transfer_client import authorize
from resume_client import prepare_upload,recover_handle,upload,ResumeFailure
from resume_store import CHUNK
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'
class ResumeTLS(unittest.TestCase):
 def test_disconnect_recovery_and_no_duplicate_chunks(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); received=root/'received'; resumedir=root/'server-resume'; source=root/'source'
   for p in (received,resumedir,source): p.mkdir(mode=0o700)
   payload=os.urandom(CHUNK*3+123); (source/'data').write_bytes(payload)
   cert=root/'cert'; keyfile=root/'tlskey'; master=root/'master'; master.write_bytes(os.urandom(32)); master.chmod(0o600)
   reg=Registry(str(root/'db')); reg.initialize(); reg.add_user('a'); ed=Ed25519PrivateKey.generate(); x=X25519PrivateKey.generate(); raw=lambda k:k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   reg.enroll('a','dev',raw(ed.public_key()),raw(x.public_key()),reg.create_otp('a',300))
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(keyfile),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   command=[sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',str(cert),'--key',str(keyfile),'--db',reg.path,'--transfer-master',str(master),'--transfer-root',str(received),'--resume-root',str(resumedir)]
   def start():
    p=subprocess.Popen(command,stdout=subprocess.PIPE,text=True)
    if not select.select([p.stdout],[],[],5)[0]: p.kill(); p.wait(timeout=5); self.fail('startup timeout')
    return p,int(p.stdout.readline())
   proc,port=start()
   try:
    def connect():
     c=AuthenticatedClient('localhost',port,str(cert),'a','dev',ed); c.authenticate(); return c
    request_id=str(uuid.uuid4()); c=connect()
    try: handle=authorize(c,x,request_id,'upload')
    finally: c.close()
    work=root/'client-resume'; manifest=prepare_upload(handle,str(source),str(work)); self.assertGreater(manifest['chunks'],2)
    c=connect()
    try:
     c.resume_begin(manifest)
     with open(work/'cipher','rb') as f: first=f.read(CHUNK)
     self.assertTrue(c.resume_chunk(handle.transfer_id,0,first))
    finally: c.close()
    # Kill only this test's identified server, restart it and reconcile persisted chunks.
    proc.kill(); self.assertIsNotNone(proc.wait(timeout=5)); proc.stdout.close(); proc,port=start()
    # Re-authenticate and recover the exact same protected Transfer OTP.
    c=connect()
    try: recovered=recover_handle(c,x,request_id); self.assertEqual(recovered.key,handle.key)
    finally: c.close()
    fault=[True]
    def flaky_connect():
     c=connect(); original=c.resume_chunk
     def chunk(*args):
      result=original(*args)
      if fault[0]: fault[0]=False; raise UnknownOutcome('simulated lost response after commit')
      return result
     c.resume_chunk=chunk; return c
    self.assertEqual(upload(flaky_connect,recovered,str(work)),{'status':'received'}); self.assertFalse(fault[0]); self.assertEqual((received/handle.transfer_id/'data').read_bytes(),payload)
    with sqlite3.connect(reg.path) as db: self.assertEqual(db.execute('SELECT count(*) FROM resume_chunks WHERE id=?',(handle.transfer_id,)).fetchone()[0],manifest['chunks'])
    c=connect()
    try: self.assertEqual(c.resume_status(handle.transfer_id)['state'],'complete')
    finally: c.close()
    with open(work/'cipher','r+b') as f: f.seek(0); f.write(b'X')
    with self.assertRaises(ResumeFailure): upload(connect,recovered,str(work))
   finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close()
if __name__=='__main__': unittest.main(verbosity=2)
