import os,pathlib,select,sqlite3,subprocess,sys,tempfile,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from client import AuthenticatedClient,NetworkError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry
from transfer_client import authorize,upload_tree
from resume_client import recover_handle
from resume_download_client import download
from resume_store import CHUNK
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'
class DownloadTLS(unittest.TestCase):
 def test_manual_resume_after_server_restart(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); received=root/'received'; resume_root=root/'server-resume'; packages=root/'packages'; source=root/'source'; dest=root/'dest'; work=root/'work'
   for p in (received,resume_root,packages,source,dest): p.mkdir(mode=0o700)
   payload=os.urandom(CHUNK*3+19); (source/'data').write_bytes(payload)
   cert=root/'cert'; tlskey=root/'tlskey'; master=root/'master'; master.write_bytes(os.urandom(32)); master.chmod(0o600)
   reg=Registry(str(root/'db')); reg.initialize(); reg.add_user('a'); ed=Ed25519PrivateKey.generate(); x=X25519PrivateKey.generate(); raw=lambda k:k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   reg.enroll('a','dev',raw(ed.public_key()),raw(x.public_key()),reg.create_otp('a',300))
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tlskey),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   command=[sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',str(cert),'--key',str(tlskey),'--db',reg.path,'--transfer-master',str(master),'--transfer-root',str(received),'--resume-root',str(resume_root),'--package-root',str(packages)]
   def start():
    p=subprocess.Popen(command,stdout=subprocess.PIPE,text=True)
    if not select.select([p.stdout],[],[],5)[0]: p.kill(); p.wait(timeout=5); self.fail('startup timeout')
    return p,int(p.stdout.readline())
   proc,port=start()
   try:
    duplicate=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
    self.assertNotEqual(duplicate.returncode,0); self.assertIn('BlockingIOError',duplicate.stderr)
    def connect():
     c=AuthenticatedClient('localhost',port,str(cert),'a','dev',ed); c.authenticate(); return c
    c=connect()
    try: up=authorize(c,x,str(uuid.uuid4()),'upload'); upload_tree(c,up,str(source),d)
    finally: c.close()
    rid=str(uuid.uuid4()); c=connect()
    try: pkg=c.package_create(up.transfer_id,str(uuid.uuid4())); handle=authorize(c,x,rid,'download',pkg['package_id'])
    finally: c.close()
    calls=[]
    def failing():
     c=connect(); old=c.resume_download_chunk
     def chunk(tid,index):
      calls.append(index)
      if index==1: raise NetworkError('isolated test interruption')
      return old(tid,index)
     c.resume_download_chunk=chunk; return c
    with self.assertRaises(NetworkError): download(failing,handle,str(work),str(dest),automatic=False)
    self.assertTrue((work/'0').exists()); self.assertFalse((dest/handle.transfer_id).exists())
    # A damaged incomplete chunk is discarded and retrieved from the verified server index.
    (work/'1').write_bytes(b'damaged'); (work/'1').chmod(0o600)
    (work/'.partial-test').write_bytes(b'uncommitted'); (work/'.partial-test').chmod(0o600)
    (work/'state').write_bytes(b'publishing'); orphan=dest/('.cs-incoming-'+handle.transfer_id+'-orphan'); orphan.mkdir(mode=0o700); (orphan/'stale').write_bytes(b'partial')
    proc.kill(); self.assertIsNotNone(proc.wait(timeout=5)); proc.stdout.close(); proc,port=start()
    c=connect()
    try: recovered=recover_handle(c,x,rid); self.assertEqual(recovered.key,handle.key)
    finally: c.close()
    retried=[]
    def recording():
     c=connect(); old=c.resume_download_chunk
     def chunk(tid,index): retried.append(index); return old(tid,index)
     c.resume_download_chunk=chunk; return c
    self.assertEqual(download(recording,recovered,str(work),str(dest)),{'status':'received'}); self.assertNotIn(0,retried); self.assertIn(1,retried); self.assertEqual((dest/handle.transfer_id/'data').read_bytes(),payload)
    self.assertFalse((work/'.partial-test').exists())
    self.assertFalse(orphan.exists())
    (work/'state').write_bytes(b'publishing'); orphan.mkdir(mode=0o700); (orphan/'stale').write_bytes(b'partial')
    self.assertEqual(download(connect,recovered,str(work),str(dest)),{'status':'received'}); self.assertFalse(orphan.exists())
    self.assertEqual(download(connect,recovered,str(work),str(dest)),{'status':'received'})
    c=connect()
    try: c.transfer_cancel(handle.transfer_id)
    finally: c.close()
    from resume_download import ResumeDownload
    self.assertEqual(ResumeDownload(reg,None,None).cleanup_terminal(),1)
    with sqlite3.connect(reg.path) as db: self.assertEqual(db.execute('SELECT count(*) FROM resume_download_chunks WHERE id=?',(handle.transfer_id,)).fetchone()[0],0)
    def forbidden(): raise AssertionError('completed local result must not need server')
    self.assertEqual(download(forbidden,recovered,str(work),str(dest)),{'status':'received'})
    # Automatic recovery retries only after re-querying the immutable index.
    c=connect()
    try: auto=authorize(c,x,str(uuid.uuid4()),'download',pkg['package_id'])
    finally: c.close()
    auto_work=root/'auto-work'; auto_dest=root/'auto-dest'; auto_dest.mkdir(mode=0o700); failures=[True]; fetched=[]
    def flaky():
     c=connect(); old=c.resume_download_chunk
     def chunk(tid,index):
      fetched.append(index)
      if index==1 and failures[0]: failures[0]=False; raise NetworkError('transient test disconnect')
      return old(tid,index)
     c.resume_download_chunk=chunk; return c
    self.assertEqual(download(flaky,auto,str(auto_work),str(auto_dest),automatic=True),{'status':'received'})
    self.assertFalse(failures[0]); self.assertEqual(fetched.count(0),1); self.assertEqual((auto_dest/auto.transfer_id/'data').read_bytes(),payload)
   finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close()
if __name__=='__main__': unittest.main(verbosity=2)
