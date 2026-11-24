"""Resource-capped real TLS large-file integration; uses disposable files only."""
import hashlib,os,pathlib,resource,select,subprocess,sys,tempfile,threading,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from client import AuthenticatedClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry
from transfer_client import authorize,upload_tree,download_tree
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'
SIZE=110*1024*1024
RSS_LIMIT_KIB=96*1024
class LargeEndToEnd(unittest.TestCase):
 def test_large_file(self):
  with tempfile.TemporaryDirectory(prefix='cs-phase3-large-') as d:
   root=pathlib.Path(d); src=root/'src'; received=root/'received'; packages=root/'packages'; dest=root/'dest'
   for p in (src,received,packages,dest): p.mkdir(mode=0o700)
   with open(src/'large','wb') as f: f.truncate(SIZE)
   cert=root/'cert'; tlskey=root/'tlskey'; master=root/'master'; master.write_bytes(os.urandom(32)); master.chmod(0o600)
   r=Registry(str(root/'db')); r.initialize(); r.add_user('alice'); ed=Ed25519PrivateKey.generate(); x=X25519PrivateKey.generate(); raw=lambda k:k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   r.enroll('alice','pc',raw(ed.public_key()),raw(x.public_key()),r.create_otp('alice',300))
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tlskey),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   stop=threading.Event(); peak=[0]; logical=[0]
   def sample_disk():
    while not stop.is_set():
     total=0; logical_total=0
     for base,dirs,files in os.walk(d):
      for name in files:
       try:
        st=os.stat(os.path.join(base,name),follow_symlinks=False); total+=st.st_blocks*512; logical_total+=st.st_size
       except FileNotFoundError: pass
     peak[0]=max(peak[0],total); logical[0]=max(logical[0],logical_total); stop.wait(.1)
   monitor=threading.Thread(target=sample_disk,daemon=True); monitor.start()
   proc=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',str(cert),'--key',str(tlskey),'--db',r.path,'--transfer-master',str(master),'--transfer-root',str(received),'--package-root',str(packages)],stdout=subprocess.PIPE,text=True)
   try:
    if not select.select([proc.stdout],[],[],8)[0]: self.fail('server startup timeout')
    port=int(proc.stdout.readline())
    def conn():
     c=AuthenticatedClient('localhost',port,str(cert),'alice','pc',ed); c.authenticate(); return c
    c=conn()
    try: up=authorize(c,x,str(uuid.uuid4()),'upload'); self.assertEqual(upload_tree(c,up,str(src),d)['bytes'],SIZE)
    finally: c.close()
    c=conn()
    try:
     package=c.package_create(up.transfer_id,str(uuid.uuid4())); down=authorize(c,x,str(uuid.uuid4()),'download',package['package_id']); self.assertEqual(download_tree(c,down,str(dest),d)['bytes'],SIZE)
    finally: c.close()
    target=dest/down.transfer_id/'large'; self.assertEqual(target.stat().st_size,SIZE)
    def digest(path):
     h=hashlib.sha256()
     with open(path,'rb') as f:
      for b in iter(lambda:f.read(262144),b''): h.update(b)
     return h.digest()
    self.assertEqual(digest(src/'large'),digest(target))
   finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close(); stop.set(); monitor.join(timeout=2)
   print('sampled_peak_allocated_bytes=%d sampled_peak_logical_bytes=%d limit_bytes=%d'%(peak[0],logical[0],512*1024*1024),flush=True); self.assertLessEqual(peak[0],512*1024*1024); self.assertLessEqual(logical[0],512*1024*1024)
   own=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss; child=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
   print('file_bytes=%d client_peak_rss_kib=%d child_peak_rss_kib=%d limit_kib=%d'%(SIZE,own,child,RSS_LIMIT_KIB),flush=True)
   self.assertLess(own,RSS_LIMIT_KIB); self.assertLess(child,RSS_LIMIT_KIB)
if __name__=='__main__': unittest.main(verbosity=2)
