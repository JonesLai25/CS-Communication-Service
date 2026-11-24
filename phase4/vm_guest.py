"""CS resume core inside a disposable VM; uid is dropped before touching CS state."""
import hashlib,io,json,os,pathlib,signal,sys,uuid
sys.path.insert(0,'/mnt/env/phase1')
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry,Conflict
from transfer_store import TransferStore
from transfer_crypto import context
from transfer_archive import pack
from transfer_compress import compress
from transfer_stream import encrypt
from resume_store import CHUNK,ResumeStore,key_check
os.setgid(1000); os.setuid(1000)
if os.geteuid()==0: raise RuntimeError('CS test must run non-root')
root=pathlib.Path('/mnt/work'); mode=sys.argv[1]
if mode=='setup':
 for name in ('resume','published','src'): (root/name).mkdir(mode=0o700)
 payload=b'isolated-vm-resume-test'*1024; (root/'src'/'f').write_bytes(payload)
 r=Registry(str(root/'db')); r.initialize(); r.add_user('a'); x=X25519PrivateKey.generate(); pub=x.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); r.enroll('a','dev',bytes(32),pub,r.create_otp('a',300))
 master=os.urandom(32); identity=os.urandom(32)
 for name,data in (('master',master),('identity',identity)):
  fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
 ts=TransferStore(r,master,identity); ts.initialize(); tid=ts.issue('a','dev',str(uuid.uuid4()),'upload',300)['id']; key=ts.get_key('a','dev',tid); binding=context(identity,'a','dev',tid,'upload')
 tar=io.BytesIO(); pack(str(root/'src'),tar); z=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),z); plain=z.getvalue(); cipher=io.BytesIO(); encrypt(io.BytesIO(plain),cipher,key,binding); data=cipher.getvalue()
 m={'version':1,'transfer_id':tid,'size':len(data),'chunks':(len(data)+CHUNK-1)//CHUNK,'cipher_sha256':hashlib.sha256(data).hexdigest(),'source_sha256':hashlib.sha256(plain).hexdigest(),'key_check':key_check(key,binding),'context_sha256':hashlib.sha256(binding).hexdigest()}
 store=ResumeStore(r,ts,str(root/'resume'),str(root/'published')); store.initialize(); store.begin('a','dev',m,binding)
 for i in range(m['chunks']): store.put('a','dev',tid,i,data[i*CHUNK:(i+1)*CHUNK])
 fd=os.open(root/'checkpoint',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f: json.dump({'tid':tid,'payload_sha':hashlib.sha256(payload).hexdigest()},f); f.flush(); os.fsync(f.fileno())
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
 print('CS_VM_PREPARED_NONROOT',flush=True); signal.pause()
else:
 meta=json.loads((root/'checkpoint').read_text()); tid=meta['tid']; r=Registry(str(root/'db')); ts=TransferStore(r,(root/'master').read_bytes(),(root/'identity').read_bytes()); store=ResumeStore(r,ts,str(root/'resume'),str(root/'published')); store.initialize(); store.reconcile_all(); binding=context(ts.server_identity,'a','dev',tid,'upload')
 if mode in ('before','after'):
  if store.status('a','dev',tid)['state']!='receiving': raise RuntimeError('unexpected state before finish')
  import transfer_ingest
  original=transfer_ingest.receive
  def wrapped(*args,**kwargs):
   if mode=='before': print('CS_VM_BEFORE_PUBLISH',flush=True); signal.pause()
   publish=kwargs['publish']
   def intercept(commit):
    def after_rename(): commit(); print('CS_VM_AFTER_RENAME',flush=True); signal.pause()
    return publish(after_rename)
   kwargs['publish']=intercept; return original(*args,**kwargs)
  transfer_ingest.receive=wrapped; store.finish('a','dev',tid,binding)
 elif mode=='verify':
  if store.status('a','dev',tid)['state']!='complete': raise RuntimeError('reconciliation did not complete')
  if hashlib.sha256((root/'published'/tid/'f').read_bytes()).hexdigest()!=meta['payload_sha']: raise RuntimeError('published content mismatch')
  try: ts.cancel('a','dev',tid)
  except Conflict: pass
  else: raise RuntimeError('completed transfer was cancelled')
  if any(p.name.startswith('.cs-incoming-') for p in (root/'published').iterdir()): raise RuntimeError('orphan staging remains')
  print('CS_VM_RECOVERY_OK_NONROOT',flush=True); signal.pause()
