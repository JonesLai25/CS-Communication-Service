"""Immutable upload preparation and manual/limited automatic retry orchestration."""
import fcntl,functools,hashlib,hmac,json,os,pathlib,re,stat,tempfile,time,uuid
from client import AuthorizationError,NetworkError,ProtocolError,RemoteOperationError,TLSError,TemporaryUnavailable,UnknownOutcome
from transfer_archive import pack
from transfer_compress import compress
from transfer_stream import encrypt
from transfer_client import _CappedWriter
from resume_store import CHUNK, key_check, manifest_bytes

class ResumeFailure(Exception): pass

def _hash(stream):
 h=hashlib.sha256()
 while True:
  b=stream.read(CHUNK)
  if not b: break
  h.update(b)
 return h.hexdigest()
def _open_private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); st=os.fstat(fd)
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: os.close(fd); raise ValueError('unsafe resume file')
 return os.fdopen(fd,'rb')
def _dir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); st=os.fstat(fd)
 if st.st_uid!=os.geteuid() or st.st_mode&0o077: os.close(fd); raise ValueError('unsafe resume directory')
 return fd

def _mkdir_private(directory,exist_ok=False):
 d=pathlib.Path(directory); parent=os.open(d.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  try: os.mkdir(d.name,0o700,dir_fd=parent); os.fsync(parent)
  except FileExistsError:
   if not exist_ok: raise
 finally: os.close(parent)
 return d

def load_request_id(directory):
 with _open_private(pathlib.Path(directory)/'request') as f: raw=f.read(37)
 try: value=raw.decode('ascii')
 except UnicodeError as e: raise ResumeFailure('invalid request id') from e
 if len(value)!=36 or str(uuid.UUID(value))!=value: raise ResumeFailure('invalid request id')
 return value

def prepare_upload(handle,source,directory):
 if handle.direction!='upload' or not isinstance(handle.request_id,str) or str(uuid.UUID(handle.request_id))!=handle.request_id or not isinstance(handle.transfer_id,str) or str(uuid.UUID(handle.transfer_id))!=handle.transfer_id: raise ValueError('invalid upload handle')
 d=_mkdir_private(directory); dirfd=_dir(d)
 try: lock=os.open('.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
 except BaseException: os.close(dirfd); raise
 try:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  identity=os.open('transfer',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
  with os.fdopen(identity,'wb') as f: f.write(handle.transfer_id.encode('ascii')); f.flush(); os.fsync(f.fileno())
  os.fsync(dirfd)
  space=os.fstatvfs(dirfd)
  if space.f_bavail*space.f_frsize<512*1024*1024: raise OSError('insufficient staging space')
  req=os.open('request',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
  with os.fdopen(req,'wb') as f: f.write(handle.request_id.encode('ascii')); f.flush(); os.fsync(f.fileno())
  os.fsync(dirfd)
  with tempfile.TemporaryFile(dir=d) as compressed:
   with tempfile.TemporaryFile(dir=d) as archive:
    pack(source,_CappedWriter(archive,128*1024*1024)); archive.seek(0); compress(archive,_CappedWriter(compressed,160*1024*1024))
   compressed.seek(0); source_sha=_hash(compressed); compressed.seek(0)
   fd=os.open('cipher.partial',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
   with os.fdopen(fd,'wb') as cipher:
    encrypt(compressed,_CappedWriter(cipher,160*1024*1024),handle.key,handle.context); cipher.flush(); os.fsync(cipher.fileno())
  os.link('cipher.partial','cipher',src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False); os.unlink('cipher.partial',dir_fd=dirfd); os.fsync(dirfd)
  with _open_private(d/'cipher') as cipher: size=os.fstat(cipher.fileno()).st_size; cipher_sha=_hash(cipher)
  manifest={'version':1,'transfer_id':handle.transfer_id,'size':size,'chunks':(size+CHUNK-1)//CHUNK,'cipher_sha256':cipher_sha,'source_sha256':source_sha,'key_check':key_check(handle.key,handle.context),'context_sha256':hashlib.sha256(handle.context).hexdigest()}
  raw=manifest_bytes(manifest); fd=os.open('manifest.partial',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
  with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
  os.link('manifest.partial','manifest',src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False); os.unlink('manifest.partial',dir_fd=dirfd); os.fsync(dirfd)
  return manifest
 finally: os.close(lock); os.close(dirfd)

def load_upload(handle,directory):
 d=pathlib.Path(directory); fd=_dir(d); os.close(fd)
 if load_request_id(d)!=handle.request_id: raise ResumeFailure('request id mismatch')
 with _open_private(d/'manifest') as f:
  raw=f.read(4097)
  if len(raw)>4096: raise ResumeFailure('manifest too large')
 try: manifest=json.loads(raw)
 except (ValueError,UnicodeError) as e: raise ResumeFailure('invalid manifest') from e
 if manifest_bytes(manifest)!=raw or manifest['transfer_id']!=handle.transfer_id or not hmac.compare_digest(manifest['key_check'],key_check(handle.key,handle.context)) or manifest['context_sha256']!=hashlib.sha256(handle.context).hexdigest(): raise ResumeFailure('manifest identity or key mismatch')
 with _open_private(d/'cipher') as f:
  if os.fstat(f.fileno()).st_size!=manifest['size'] or not hmac.compare_digest(_hash(f),manifest['cipher_sha256']): raise ResumeFailure('immutable ciphertext modified')
 return manifest

def recover_handle(client,x25519_key,request_id):
 import hashlib
 from transfer_client import TransferHandle
 from transfer_crypto import context,open_envelope
 if client.token is None: raise ValueError('authenticate first')
 entry=client.transfer_result(request_id)
 if entry is None or entry['direction'] not in ('upload','download'): raise ResumeFailure('transfer unavailable')
 identity=hashlib.sha256(client.conn.sock.getpeercert(binary_form=True)).digest()
 direction=entry['direction']; package_id=entry.get('package_id')
 key=open_envelope(entry['enc'],entry['wrapped'],x25519_key,identity,client.owner,client.device,entry['id'],direction,package_id)
 return TransferHandle(entry['id'],package_id,key,context(identity,client.owner,client.device,entry['id'],direction,package_id),direction,request_id)

def _status(connector,manifest):
 chunks={}; cursor=0; first_state=None
 while True:
  c=connector()
  try: page=c.resume_status(manifest['transfer_id'],cursor)
  finally: c.close()
  if page is None: return None,{}
  if page['manifest']!=manifest: raise ResumeFailure('server manifest mismatch')
  state=page['state']
  if first_state is None: first_state=state
  elif state!=first_state: raise ResumeFailure('server state changed during pagination')
  if state not in ('receiving','complete'): raise ResumeFailure('transfer is '+state)
  for item in page['chunks']:
   if not isinstance(item,dict) or set(item)!={'index','size','sha256'} or type(item['index']) is not int or type(item['size']) is not int or not 0<=item['index']<manifest['chunks'] or item['index'] in chunks or not isinstance(item['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',item['sha256']): raise ResumeFailure('invalid server progress')
   expected=CHUNK if item['index']<manifest['chunks']-1 else manifest['size']-item['index']*CHUNK
   if item['size']!=expected: raise ResumeFailure('invalid chunk size')
   chunks[item['index']]=item['sha256']
  if page['next'] is None: return state,chunks
  if page['next']<=cursor or page['next']>manifest['chunks']: raise ResumeFailure('invalid progress cursor')
  cursor=page['next']

def _locked_upload(fn):
 @functools.wraps(fn)
 def wrapped(connector,handle,directory,*args,**kwargs):
  root=_dir(directory)
  try: lock=os.open('.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=root)
  except BaseException: os.close(root); raise
  try:
   st=os.fstat(lock)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ResumeFailure('unsafe local lock')
   fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   return fn(connector,handle,directory,*args,**kwargs)
  finally: os.close(lock); os.close(root)
 return wrapped

@_locked_upload
def upload(connector,handle,directory,automatic=True,max_retries=3):
 if type(max_retries) is not int or not 0<=max_retries<=3: raise ValueError('invalid retry budget')
 m=load_upload(handle,directory); attempts=0
 while True:
  try:
   state,committed=_status(connector,m)
   if state=='complete': return {'status':'received'}
   if state is None:
    c=connector()
    try: c.resume_begin(m)
    finally: c.close()
    state,committed=_status(connector,m)
    if state!='receiving': raise ResumeFailure('unexpected state after begin')
   with _open_private(pathlib.Path(directory)/'cipher') as f:
    for index in range(m['chunks']):
     part=f.read(CHUNK); digest=hashlib.sha256(part).hexdigest()
     if index in committed:
      if not hmac.compare_digest(committed[index],digest): raise ResumeFailure('server chunk mismatch')
      continue
     c=connector()
     try: c.resume_chunk(m['transfer_id'],index,part)
     finally: c.close()
   c=connector()
   try: return c.resume_finish(m['transfer_id'])
   finally: c.close()
  except (NetworkError,TemporaryUnavailable,UnknownOutcome):
   if not automatic or attempts>=max_retries: raise
   attempts+=1; time.sleep(min(.1*(2**(attempts-1)),.4))

def cleanup_local(directory,transfer_id):
 """Remove only recognized owned encrypted staging after explicit cancellation."""
 d=pathlib.Path(directory); root=_dir(d)
 try: lock=os.open('.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=root)
 except BaseException: os.close(root); raise
 try:
  st=os.fstat(lock)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ResumeFailure('unsafe local lock')
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if not isinstance(transfer_id,str) or str(uuid.UUID(transfer_id))!=transfer_id: raise ResumeFailure('invalid transfer id')
  try:
   with _open_private(d/'manifest') as f: raw=f.read(4097)
  except FileNotFoundError:
   with _open_private(d/'transfer') as f: rawid=f.read(37)
   if rawid!=transfer_id.encode('ascii'): raise ResumeFailure('transfer id mismatch')
  else:
   if len(raw)>4096: raise ResumeFailure('invalid local manifest')
   try: record=json.loads(raw)
   except (ValueError,UnicodeError) as e: raise ResumeFailure('invalid local manifest') from e
   if not isinstance(record,dict) or record.get('transfer_id')!=transfer_id: raise ResumeFailure('transfer id mismatch')
   try:
    with _open_private(d/'transfer') as f: rawid=f.read(37)
   except FileNotFoundError: pass  # Older staged transfers predate the marker.
   else:
    if rawid!=transfer_id.encode('ascii'): raise ResumeFailure('transfer id mismatch')
  selected=[]
  for name in os.listdir(root):
   if name in ('cipher','cipher.partial','manifest.partial') or name.isascii() and name.isdigit() or name.startswith('.partial-'):
    st=os.stat(name,dir_fd=root,follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_nlink!=1: raise ResumeFailure('unsafe local staging entry')
    selected.append(name)
  for name in selected: os.unlink(name,dir_fd=root)
  os.fsync(root)
 finally: os.close(lock); os.close(root)
