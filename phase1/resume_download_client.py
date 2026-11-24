"""Download already-encrypted immutable chunks into private durable staging."""
import fcntl,hashlib,hmac,json,os,pathlib,re,stat,time,uuid
from client import NetworkError,TemporaryUnavailable,UnknownOutcome
from resume_store import CHUNK,MAX_SIZE,key_check,ResumeStore
from resume_client import ResumeFailure,_dir,_open_private,_mkdir_private,load_request_id
from transfer_ingest import receive

def _canonical(handle,m):
 if not isinstance(m,dict) or set(m)!={'version','transfer_id','package_id','size','chunks','cipher_sha256','source_sha256','key_check','context_sha256'}: raise ResumeFailure('invalid download manifest')
 if type(m['version']) is not int or m['version']!=1 or m['transfer_id']!=handle.transfer_id or m['package_id']!=handle.package_id: raise ResumeFailure('download identity mismatch')
 if type(m['size']) is not int or not 1<=m['size']<=MAX_SIZE or type(m['chunks']) is not int or m['chunks']!=(m['size']+CHUNK-1)//CHUNK: raise ResumeFailure('invalid download size')
 for name in ('cipher_sha256','source_sha256','key_check','context_sha256'):
  if not isinstance(m[name],str) or not re.fullmatch('[0-9a-f]{64}',m[name]): raise ResumeFailure('invalid download digest')
 if not hmac.compare_digest(m['key_check'],key_check(handle.key,handle.context)) or not hmac.compare_digest(m['context_sha256'],hashlib.sha256(handle.context).hexdigest()): raise ResumeFailure('download key or context mismatch')
 return json.dumps(m,sort_keys=True,separators=(',',':')).encode('ascii')

def _atomic(fd,name,data,replace=False):
 temp='.partial-'+uuid.uuid4().hex
 f=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
 try:
  with os.fdopen(f,'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
  if replace: os.replace(temp,name,src_dir_fd=fd,dst_dir_fd=fd)
  else: os.link(temp,name,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False); os.unlink(temp,dir_fd=fd)
  os.fsync(fd)
 finally:
  try: os.unlink(temp,dir_fd=fd)
  except FileNotFoundError: pass

def _meta(connector,handle):
 c=connector()
 try: m=c.resume_download_meta(handle.transfer_id)
 finally: c.close()
 return m,_canonical(handle,m)
def _indices(connector,handle,m):
 result={}; cursor=0
 while True:
  c=connector()
  try: page=c.resume_download_index(handle.transfer_id,cursor)
  finally: c.close()
  for item in page['chunks']:
   if not isinstance(item,dict) or set(item)!={'index','size','sha256'} or type(item['index']) is not int or type(item['size']) is not int or item['index'] in result or not 0<=item['index']<m['chunks'] or not isinstance(item['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',item['sha256']): raise ResumeFailure('invalid download index')
   expected=CHUNK if item['index']<m['chunks']-1 else m['size']-item['index']*CHUNK
   if item['size']!=expected: raise ResumeFailure('invalid download chunk size')
   result[item['index']]=item
  if page['next'] is None: break
  if page['next']<=cursor or page['next']>m['chunks']: raise ResumeFailure('invalid download cursor')
  cursor=page['next']
 if set(result)!=set(range(m['chunks'])): raise ResumeFailure('incomplete download index')
 return result

def _private_bytes(path,limit):
 with _open_private(path) as f:
  data=f.read(limit+1)
  if len(data)>limit: raise ResumeFailure('oversized local record')
  return data

def download(connector,handle,directory,destination,automatic=True,max_retries=3):
 if handle.direction!='download' or not handle.package_id or type(max_retries) is not int or not 0<=max_retries<=3: raise ValueError('invalid download')
 if not isinstance(handle.transfer_id,str) or str(uuid.UUID(handle.transfer_id))!=handle.transfer_id: raise ValueError('invalid transfer id')
 if not isinstance(handle.request_id,str) or str(uuid.UUID(handle.request_id))!=handle.request_id: raise ValueError('invalid request id')
 d=_mkdir_private(directory,exist_ok=True)
 root=_dir(d)
 space=os.fstatvfs(root)
 if space.f_bavail*space.f_frsize<512*1024*1024: os.close(root); raise OSError('insufficient staging space')
 try: lock=os.open('.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=root)
 except BaseException: os.close(root); raise
 try:
  st=os.fstat(lock)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ResumeFailure('unsafe local lock')
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if (d/'transfer').exists():
   if _private_bytes(d/'transfer',36)!=handle.transfer_id.encode('ascii'): raise ResumeFailure('transfer id mismatch')
  else: _atomic(root,'transfer',handle.transfer_id.encode('ascii'))
  # A kill during _atomic can leave only these private, uncommitted files.
  for name in os.listdir(root):
   if name.startswith('.partial-'):
    st=os.stat(name,dir_fd=root,follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ResumeFailure('unsafe local staging entry')
    os.unlink(name,dir_fd=root)
  os.fsync(root)
  if (d/'request').exists():
   if load_request_id(d)!=handle.request_id: raise ResumeFailure('request id mismatch')
  else: _atomic(root,'request',handle.request_id.encode('ascii'))
  # A previously published local result remains complete even after server expiry.
  if (d/'manifest').exists() and (d/'state').exists():
   local_raw=_private_bytes(d/'manifest',4096)
   try: local_manifest=json.loads(local_raw)
   except (ValueError,UnicodeError) as e: raise ResumeFailure('invalid local manifest') from e
   if _canonical(handle,local_manifest)!=local_raw: raise ResumeFailure('local manifest mismatch')
   local_state=_private_bytes(d/'state',32).decode('ascii')
   if local_state in ('publishing','complete'):
    pub=_dir(destination)
    try:
     try: entry=os.stat(handle.transfer_id,dir_fd=pub,follow_symlinks=False); exists=True
     except FileNotFoundError: exists=False
     if exists and (not stat.S_ISDIR(entry.st_mode) or entry.st_uid!=os.geteuid()): raise ResumeFailure('unsafe destination')
     if local_state=='complete' and not exists: raise ResumeFailure('published destination missing')
     if exists:
      helper=ResumeStore.__new__(ResumeStore); helper.published_root=str(destination); helper._cleanup_partial(handle.transfer_id)
      if local_state!='complete': _atomic(root,'state',b'complete',True)
      return {'status':'received'}
    finally: os.close(pub)
  attempts=0
  while True:
   try:
    m,raw=_meta(connector,handle)
    if (d/'manifest').exists():
     if _private_bytes(d/'manifest',4096)!=raw: raise ResumeFailure('local manifest mismatch')
    else: _atomic(root,'manifest',raw)
    if (d/'state').exists(): state=_private_bytes(d/'state',32).decode('ascii')
    else: state='receiving'; _atomic(root,'state',state.encode())
    if state not in ('receiving','publishing','complete'): raise ResumeFailure('invalid local state')
    pub=_dir(destination)
    try:
     try: entry=os.stat(handle.transfer_id,dir_fd=pub,follow_symlinks=False); exists=True
     except FileNotFoundError: exists=False
     if exists and (not stat.S_ISDIR(entry.st_mode) or entry.st_uid!=os.geteuid()): raise ResumeFailure('unsafe destination')
     if state=='complete':
      if not exists: raise ResumeFailure('published destination missing')
      return {'status':'received'}
     if state=='publishing':
      helper=ResumeStore.__new__(ResumeStore); helper.published_root=str(destination); helper._cleanup_partial(handle.transfer_id)
      if exists: _atomic(root,'state',b'complete',True); return {'status':'received'}
      state='receiving'; _atomic(root,'state',b'receiving',True)
     if exists: raise ResumeFailure('destination already exists')
    finally: os.close(pub)
    indices=_indices(connector,handle,m)
    for i in range(m['chunks']):
     name=str(i); item=indices[i]; path=d/name; valid=False
     try:
      with _open_private(path) as f:
       data=f.read(CHUNK+1); valid=len(data)==item['size'] and hmac.compare_digest(hashlib.sha256(data).hexdigest(),item['sha256'])
     except FileNotFoundError: pass
     if valid: continue
     if path.exists(): os.unlink(name,dir_fd=root); os.fsync(root)
     c=connector()
     try: data,digest=c.resume_download_chunk(handle.transfer_id,i)
     finally: c.close()
     if len(data)!=item['size'] or not hmac.compare_digest(digest,item['sha256']): raise ResumeFailure('server chunk mismatch')
     _atomic(root,name,data)
    class Reader:
     def __init__(self): self.index=0; self.f=None; self.hash=hashlib.sha256(); self.total=0
     def read(self,n):
      if n<0: raise ValueError('unbounded read')
      out=bytearray()
      while len(out)<n and self.index<m['chunks']:
       if self.f is None: self.f=_open_private(d/str(self.index))
       part=self.f.read(n-len(out))
       if not part: self.f.close(); self.f=None; self.index+=1; continue
       out.extend(part); self.hash.update(part); self.total+=len(part)
      return bytes(out)
     def close(self):
      if self.f: self.f.close()
    reader=Reader(); _atomic(root,'state',b'publishing',True)
    try:
     def validate(summary):
      if reader.total!=m['size'] or not hmac.compare_digest(reader.hash.hexdigest(),m['cipher_sha256']) or not hmac.compare_digest(summary['sha256'],m['source_sha256']): raise ResumeFailure('download source digest mismatch')
     def publish(commit):
      fresh,fresh_raw=_meta(connector,handle)
      if fresh_raw!=raw: raise ResumeFailure('download authorization changed')
      commit()
     receive(reader,str(destination),handle.transfer_id,handle.key,handle.context,publish=publish,archive_limit=128*1024*1024,validate=validate,durable=True)
     _atomic(root,'state',b'complete',True); return {'status':'received'}
    finally: reader.close()
   except (NetworkError,TemporaryUnavailable,UnknownOutcome):
    if not automatic or attempts>=max_retries: raise
    attempts+=1; time.sleep(min(.1*(2**(attempts-1)),.4))
 finally: os.close(lock); os.close(root)
