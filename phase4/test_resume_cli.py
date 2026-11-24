import json,os,pathlib,select,subprocess,sys,tempfile,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from client import AuthenticatedClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry
from transfer_client import authorize
from resume_client import prepare_upload
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'
class CLI(unittest.TestCase):
 def test_cli_upload_download_manual_and_cancel(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); received=root/'received'; server_resume=root/'server-resume'; packages=root/'packages'; source=root/'source'; dest=root/'dest'; creds=root/'creds'
   for p in (received,server_resume,packages,source,dest,creds): p.mkdir(mode=0o700)
   payload=os.urandom(400000); (source/'data').write_bytes(payload); master=root/'master'; master.write_bytes(os.urandom(32)); master.chmod(0o600); cert=root/'cert'; tlskey=root/'tlskey'
   r=Registry(str(root/'db')); r.initialize(); r.add_user('a'); ed=Ed25519PrivateKey.generate(); x=X25519PrivateKey.generate(); raw=lambda k:k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   r.enroll('a','dev',raw(ed.public_key()),raw(x.public_key()),r.create_otp('a',300))
   for name,key in (('ed25519.key',ed),('x25519.key',x)):
    f=creds/name; f.write_bytes(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())); f.chmod(0o600)
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tlskey),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   proc=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',str(cert),'--key',str(tlskey),'--db',r.path,'--transfer-master',str(master),'--transfer-root',str(received),'--resume-root',str(server_resume),'--package-root',str(packages)],stdout=subprocess.PIPE,text=True)
   try:
    if not select.select([proc.stdout],[],[],5)[0]: self.fail('startup timeout')
    port=int(proc.stdout.readline()); argv=[sys.executable,str(P/'resume_cli.py'),'--port',str(port),'--ca',str(cert),'--owner','a','--device','dev','--credential-dir',str(creds),'--staging-capacity-mib','1048576']
    def run(*args):
     result=subprocess.run(argv+list(args),capture_output=True,text=True,timeout=40); self.assertEqual(result.returncode,0,result.stderr); return [json.loads(line) for line in result.stdout.splitlines()]
    work=root/'upwork'; uploaded=run('upload',str(source),str(work)); tid=uploaded[1]['transfer_id']; self.assertEqual(uploaded[-1],{'status':'received'}); self.assertEqual((received/tid/'data').read_bytes(),payload)
    self.assertEqual(run('resume',str(work))[-1],{'status':'received'})
    def connect():
     c=AuthenticatedClient('localhost',port,str(cert),'a','dev',ed); c.authenticate(); return c
    c=connect()
    try: package=c.package_create(tid,str(uuid.uuid4()))
    finally: c.close()
    downwork=root/'downwork'; downloaded=run('download',package['package_id'],str(downwork),str(dest)); downid=downloaded[1]['transfer_id']; self.assertEqual((dest/downid/'data').read_bytes(),payload); self.assertEqual(run('resume-download',str(downwork),str(dest))[-1],{'status':'received'})
    c=connect()
    try: handle=authorize(c,x,str(uuid.uuid4()),'upload')
    finally: c.close()
    cancelled=root/'cancelled'; m=prepare_upload(handle,str(source),str(cancelled)); (cancelled/'unrelated').write_text('keep')
    c=connect()
    try: c.resume_begin(m)
    finally: c.close()
    self.assertEqual(run('cancel',handle.transfer_id,'--resume-directory',str(cancelled))[-1],{'cancelled':True}); self.assertFalse((cancelled/'cipher').exists()); self.assertEqual((cancelled/'unrelated').read_text(),'keep')
    self.assertEqual(run('status',handle.transfer_id)[-1]['state'],'cancelled')
   finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close()
if __name__=='__main__': unittest.main(verbosity=2)
