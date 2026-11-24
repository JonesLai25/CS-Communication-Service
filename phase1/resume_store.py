"""Durable upload chunk journal. Chunks are pre-existing ciphertext, never re-encrypted.

This module owns only its private test/service directory. SQLite metadata is the
publication authority; callers must reconcile before accepting network traffic.
"""
import fcntl,functools,hashlib,hmac,json,os,re,stat,time,uuid
from registry import Busy,Conflict,Denied,Limited,StorageError

CHUNK=256*1024
MAX_SIZE=160*1024*1024
# Bound aggregate receiving ciphertext, including reservations for chunks that
# have not yet arrived. This is separate from the publication/package quota.
MAX_RESERVED=384*1024*1024
HEX=re.compile(r'[0-9a-f]{64}\Z')
class Corrupt(Exception): pass
class NotFound(Exception): pass

def manifest_bytes(manifest):
 if not isinstance(manifest,dict) or set(manifest)!={'version','transfer_id','size','chunks','cipher_sha256','source_sha256','key_check','context_sha256'}: raise ValueError('invalid manifest')
 if type(manifest['version']) is not int or manifest['version']!=1: raise ValueError('invalid version')
 tid=manifest['transfer_id']
 if not isinstance(tid,str) or str(uuid.UUID(tid))!=tid: raise ValueError('invalid transfer id')
 size=manifest['size']; count=manifest['chunks']
 if type(size) is not int or not 1<=size<=MAX_SIZE or type(count) is not int or count!=(size+CHUNK-1)//CHUNK: raise ValueError('invalid size or count')
 for field in ('cipher_sha256','source_sha256','key_check','context_sha256'):
  if not isinstance(manifest[field],str) or not HEX.fullmatch(manifest[field]): raise ValueError('invalid digest')
 return json.dumps(manifest,sort_keys=True,separators=(',',':')).encode('ascii')

def parse_manifest(raw,digest):
 if not isinstance(raw,bytes) or not isinstance(digest,bytes) or not hmac.compare_digest(hashlib.sha256(raw).digest(),digest): raise Corrupt('manifest digest mismatch')
 try:
  parsed=json.loads(raw)
  if manifest_bytes(parsed)!=raw: raise ValueError('noncanonical manifest')
  return parsed
 except (ValueError,TypeError,UnicodeError) as e: raise Corrupt('invalid manifest') from e

def key_check(key,binding): return hmac.new(key,b'CS-RESUME-KEY-v1\0'+hashlib.sha256(binding).digest(),hashlib.sha256).hexdigest()
def _sync_dir(fd): os.fsync(fd)
def _write_all(fd,data):
 view=memoryview(data)
 while view:
  n=os.write(fd,view)
  if n<=0: raise OSError('short write')
  view=view[n:]
def exclusive(method):
 @functools.wraps(method)
 def guarded(self,*args,**kwargs):
  root=self._root()
  try:
   fd=os.open('.journal.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=root)
   try:
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe journal lock')
    try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError as e: raise Busy('resume journal busy') from e
    return method(self,*args,**kwargs)
   finally: os.close(fd)
  finally: os.close(root)
 return guarded
class ResumeStore:
 def __init__(self,registry,transfers,root,published_root,max_reserved=None):
  if max_reserved is not None and (type(max_reserved) is not int or not 1024*1024<=max_reserved<=4096*1024*1024): raise ValueError('invalid upload reservation limit')
  self.registry=registry; self.transfers=transfers; self.root=root; self.published_root=published_root; self.max_reserved=max_reserved
 def _root(self):
  fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); st=os.fstat(fd)
  if st.st_uid!=os.geteuid() or st.st_mode&0o077: os.close(fd); raise ValueError('unsafe resume root')
  return fd
 def initialize(self):
  def op(db):
   db.execute("CREATE TABLE IF NOT EXISTS resume_transfers(id TEXT PRIMARY KEY,owner TEXT NOT NULL,device TEXT NOT NULL,manifest BLOB NOT NULL,digest BLOB NOT NULL,state TEXT NOT NULL)")
   db.execute('CREATE TABLE IF NOT EXISTS resume_chunks(id TEXT NOT NULL,idx INTEGER NOT NULL,size INTEGER NOT NULL,digest BLOB NOT NULL,PRIMARY KEY(id,idx))')
   if 'cleaned' not in [r[1] for r in db.execute('PRAGMA table_info(resume_transfers)')]: db.execute('ALTER TABLE resume_transfers ADD COLUMN cleaned INTEGER NOT NULL DEFAULT 0')
  self.registry.transaction(op)
 def _active(self,db,owner,device,tid):
  row=db.execute("SELECT 1 FROM transfer_keys t JOIN devices d ON d.owner=t.owner AND d.device=t.device JOIN users u ON u.owner=d.owner WHERE t.id=? AND t.owner=? AND t.device=? AND t.direction='upload' AND t.state='active' AND t.expires>? AND d.enabled=1 AND u.enabled=1",(tid,owner,device,int(time.time()))).fetchone()
  if not row: raise Denied()
 @exclusive
 def begin(self,owner,device,manifest,binding):
  raw=manifest_bytes(manifest); tid=manifest['transfer_id']; key=self.transfers.get_key(owner,device,tid,'upload')
  if not hmac.compare_digest(manifest['key_check'],key_check(key,binding)) or not hmac.compare_digest(manifest['context_sha256'],hashlib.sha256(binding).hexdigest()): raise Denied()
  root=self._root()
  try:
   space=os.fstatvfs(root); free=space.f_bavail*space.f_frsize
   created=False
   try: os.mkdir(tid,0o700,dir_fd=root); created=True; _sync_dir(root)
   except FileExistsError: pass
   folder=os.open(tid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
   try:
    st=os.fstat(folder)
    if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe transfer directory')
   finally: os.close(folder)
   def op(db):
    self._active(db,owner,device,tid)
    old=db.execute('SELECT owner,device,manifest,state FROM resume_transfers WHERE id=?',(tid,)).fetchone()
    if old:
     if old[0]!=owner or old[1]!=device or old[2]!=raw: raise Conflict()
     if old[3]!='receiving': raise Denied()
     return
    pub=os.open(self.published_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
     try: os.stat(tid,dir_fd=pub,follow_symlinks=False)
     except FileNotFoundError: pass
     else: raise Conflict()
    finally: os.close(pub)
    if db.execute("SELECT count(*) FROM resume_transfers WHERE owner=? AND state='receiving'",(owner,)).fetchone()[0]>=4: raise Limited()
    reserved=sum(parse_manifest(m,d)['size'] for m,d in db.execute("SELECT manifest,digest FROM resume_transfers WHERE state IN ('receiving','publishing')"))
    if reserved+manifest['size']>(MAX_RESERVED if self.max_reserved is None else self.max_reserved): raise Limited()
    if free<512*1024*1024+reserved+manifest['size']: raise StorageError('insufficient staging space')
    db.execute("INSERT INTO resume_transfers(id,owner,device,manifest,digest,state) VALUES(?,?,?,?,?,'receiving')",(tid,owner,device,raw,hashlib.sha256(raw).digest()))
   try: self.registry.transaction(op)
   except BaseException:
    if created:
     try: os.rmdir(tid,dir_fd=root); _sync_dir(root)
     except OSError: pass
    raise
  finally: os.close(root)
 @exclusive
 def put(self,owner,device,tid,index,data):
  if not isinstance(tid,str) or str(uuid.UUID(tid))!=tid or type(index) is not int or not isinstance(data,bytes): raise ValueError('invalid chunk')
  def metadata(db):
   self._active(db,owner,device,tid); row=db.execute("SELECT manifest,digest FROM resume_transfers WHERE id=? AND owner=? AND device=? AND state='receiving'",(tid,owner,device)).fetchone()
   if not row: raise Denied()
   return parse_manifest(row[0],row[1])
  m=self.registry.transaction(metadata)
  if not 0<=index<m['chunks'] or len(data)!=(CHUNK if index<m['chunks']-1 else m['size']-index*CHUNK): raise ValueError('invalid chunk length')
  digest=hashlib.sha256(data).digest(); root=self._root()
  try:
   space=os.fstatvfs(root)
   if space.f_bavail*space.f_frsize<512*1024*1024+len(data): raise StorageError('insufficient staging space')
   folder=os.open(tid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
   try:
    name=str(index); temp='.partial-'+uuid.uuid4().hex
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=folder)
    try: _write_all(fd,data); os.fsync(fd)
    finally: os.close(fd)
    try:
     def commit(db):
      self._active(db,owner,device,tid)
      if not db.execute("SELECT 1 FROM resume_transfers WHERE id=? AND owner=? AND device=? AND state='receiving'",(tid,owner,device)).fetchone(): raise Denied()
      old=db.execute('SELECT size,digest FROM resume_chunks WHERE id=? AND idx=?',(tid,index)).fetchone()
      if old:
       if old!=(len(data),digest): raise Conflict()
       self._verify(folder,name,len(data),digest); return False
      try: os.link(temp,name,src_dir_fd=folder,dst_dir_fd=folder,follow_symlinks=False)
      except FileExistsError: raise Corrupt('unreconciled chunk')
      _sync_dir(folder); db.execute('INSERT INTO resume_chunks VALUES(?,?,?,?)',(tid,index,len(data),digest)); return True
     return self.registry.transaction(commit)
    finally:
     try: os.unlink(temp,dir_fd=folder); _sync_dir(folder)
     except FileNotFoundError: pass
   finally: os.close(folder)
  finally: os.close(root)
 def _verify(self,folder,name,size,digest):
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=folder)
  try:
   st=os.fstat(fd)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_size!=size: raise Corrupt('invalid committed chunk')
   h=hashlib.sha256()
   while True:
    block=os.read(fd,65536)
    if not block: break
    h.update(block)
   if not hmac.compare_digest(h.digest(),digest): raise Corrupt('corrupt committed chunk')
  finally: os.close(fd)
 def status(self,owner,device,tid):
  def op(db):
   if not db.execute('SELECT 1 FROM devices d JOIN users u ON u.owner=d.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone(): raise Denied()
   row=db.execute('SELECT r.manifest,r.state,t.state,t.expires,r.digest FROM resume_transfers r JOIN transfer_keys t ON t.id=r.id WHERE r.id=? AND r.owner=? AND r.device=?',(tid,owner,device)).fetchone()
   if not row: raise NotFound()
   state=row[1]
   if state not in ('complete','failed','publishing') and (row[2]!='active' or row[3]<=int(time.time())):
    state='expired' if row[2]=='expired' or row[3]<=int(time.time()) else 'cancelled'
    db.execute('UPDATE resume_transfers SET state=? WHERE id=?',(state,tid))
   chunks=[{'index':i,'size':n,'sha256':h.hex()} for i,n,h in db.execute('SELECT idx,size,digest FROM resume_chunks WHERE id=? ORDER BY idx',(tid,))]
   parsed=parse_manifest(row[0],row[4])
   if parsed['transfer_id']!=tid: raise Corrupt('manifest transfer mismatch')
   return {'manifest':parsed,'state':state,'chunks':chunks}
  return self.registry.transaction(op)
 @exclusive
 def reconcile(self,owner,device,tid):
  state=self.status(owner,device,tid)
  if state['state']=='publishing':
   published=self._published(tid)
   self._cleanup_partial(tid)
   self.registry.transaction(lambda db:db.execute("UPDATE resume_transfers SET state=? WHERE id=? AND state='publishing'",('complete' if published else 'receiving',tid)))
   state=self.status(owner,device,tid)
  if state['state'] in ('complete','failed','cancelled','expired'): return state
  root=self._root()
  try:
   folder=os.open(tid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
   try:
    committed={str(c['index']):c for c in state['chunks']}
    for name in os.listdir(folder):
     if name not in committed:
      st=os.stat(name,dir_fd=folder,follow_symlinks=False)
      if not stat.S_ISREG(st.st_mode): raise Corrupt('unexpected staging entry')
      os.unlink(name,dir_fd=folder)
    _sync_dir(folder)
    for name,item in committed.items():
     try: self._verify(folder,name,item['size'],bytes.fromhex(item['sha256']))
     except (OSError,Corrupt) as e:
      self.registry.transaction(lambda db:db.execute("UPDATE resume_transfers SET state='failed' WHERE id=? AND state='receiving'",(tid,)))
      raise Corrupt('journal mismatch') from e
   finally: os.close(folder)
  finally: os.close(root)
  return self.status(owner,device,tid)
 def _cleanup_partial(self,tid):
  root=os.open(self.published_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  def remove(parent,name):
   fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   try:
    st=os.fstat(fd)
    if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise Corrupt('unsafe staging directory')
    for child in os.listdir(fd):
     entry=os.stat(child,dir_fd=fd,follow_symlinks=False)
     if entry.st_uid!=os.geteuid(): raise Corrupt('unsafe staging owner')
     if stat.S_ISDIR(entry.st_mode): remove(fd,child)
     elif stat.S_ISREG(entry.st_mode): os.unlink(child,dir_fd=fd)
     else: raise Corrupt('unsafe staging entry')
    os.fsync(fd)
   finally: os.close(fd)
   os.rmdir(name,dir_fd=parent)
  try:
   st=os.fstat(root)
   if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe publication root')
   prefix='.cs-incoming-'+tid+'-'
   for name in os.listdir(root):
    if name.startswith(prefix): remove(root,name)
   os.fsync(root)
  finally: os.close(root)
 def _published(self,tid):
  fd=os.open(self.published_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   st=os.fstat(fd)
   if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe publication root')
   try: entry=os.stat(tid,dir_fd=fd,follow_symlinks=False)
   except FileNotFoundError: return False
   if not stat.S_ISDIR(entry.st_mode) or entry.st_uid!=os.geteuid(): raise Corrupt('unsafe publication entry')
   os.fsync(fd); return True
  finally: os.close(fd)
 @exclusive
 def finish(self,owner,device,tid,binding):
  from transfer_ingest import receive
  from transfer_stream import InvalidEnvelope
  from transfer_compress import InvalidCompressed
  from transfer_archive import InvalidArchive
  state=ResumeStore.reconcile.__wrapped__(self,owner,device,tid); manifest=state['manifest']; chunks=state['chunks']
  if state['state']=='complete': return {'status':'received'}
  if state['state']!='receiving' or len(chunks)!=manifest['chunks'] or [c['index'] for c in chunks]!=list(range(manifest['chunks'])): raise Denied()
  key=self.transfers.get_key(owner,device,tid,'upload')
  if not hmac.compare_digest(key_check(key,binding),manifest['key_check']) or hashlib.sha256(binding).hexdigest()!=manifest['context_sha256']: raise Denied()
  self.registry.transaction(lambda db:db.execute("UPDATE resume_transfers SET state='publishing' WHERE id=? AND state='receiving'",(tid,)))
  root=self._root(); folder=os.open(tid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root); os.close(root)
  class Reader:
   def __init__(self): self.index=0; self.fd=None; self.hash=hashlib.sha256(); self.total=0
   def read(self,n):
    if n<0: raise ValueError('unbounded read')
    out=bytearray()
    while len(out)<n and self.index<manifest['chunks']:
     if self.fd is None: self.fd=os.open(str(self.index),os.O_RDONLY|os.O_NOFOLLOW,dir_fd=folder)
     part=os.read(self.fd,n-len(out))
     if not part: os.close(self.fd); self.fd=None; self.index+=1; continue
     out.extend(part); self.hash.update(part); self.total+=len(part)
    return bytes(out)
   def close(self):
    if self.fd is not None: os.close(self.fd); self.fd=None
  reader=Reader()
  try:
   def validate(summary):
    if reader.total!=manifest['size'] or not hmac.compare_digest(reader.hash.hexdigest(),manifest['cipher_sha256']) or not hmac.compare_digest(summary['sha256'],manifest['source_sha256']): raise Corrupt('source manifest mismatch')
   receive(reader,self.published_root,tid,key,binding,publish=lambda commit:self.transfers.publish_if_authorized(owner,device,tid,commit,expected_resume=True),archive_limit=128*1024*1024,validate=validate,durable=True)
   self.registry.transaction(lambda db:db.execute("UPDATE resume_transfers SET state='complete' WHERE id=? AND state='publishing'",(tid,)))
   return {'status':'received'}
  except (Corrupt,InvalidEnvelope,InvalidCompressed,InvalidArchive):
   self.registry.transaction(lambda db:db.execute("UPDATE resume_transfers SET state='failed' WHERE id=? AND state='publishing'",(tid,)))
   raise
  except BaseException:
   if not self._published(tid): self.registry.transaction(lambda db:db.execute("UPDATE resume_transfers SET state='receiving' WHERE id=? AND state='publishing'",(tid,)))
   raise
  finally: reader.close(); os.close(folder)
 @exclusive
 def cleanup_terminal(self):
  now=int(time.time())
  def mark(db):
   db.execute("UPDATE resume_transfers SET state='expired' WHERE id IN (SELECT r.id FROM resume_transfers r JOIN transfer_keys t ON t.id=r.id WHERE r.state='receiving' AND (t.state='expired' OR t.expires<=?) LIMIT 512)",(now,))
   return [r[0] for r in db.execute("SELECT id FROM resume_transfers WHERE state IN ('complete','cancelled','expired','failed') AND cleaned=0 LIMIT 64")]
  ids=self.registry.transaction(mark); root=self._root()
  try:
   for tid in ids:
    if str(uuid.UUID(tid))!=tid: raise Corrupt('invalid journal id')
    try: folder=os.open(tid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
    except FileNotFoundError: folder=None
    if folder is not None:
     try:
      for name in os.listdir(folder):
       st=os.stat(name,dir_fd=folder,follow_symlinks=False)
       if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid(): raise Corrupt('unsafe journal entry')
       os.unlink(name,dir_fd=folder)
      os.fsync(folder)
     finally: os.close(folder)
     os.rmdir(tid,dir_fd=root); os.fsync(root)
    def clear(db):
     db.execute('DELETE FROM resume_chunks WHERE id=?',(tid,))
     db.execute('UPDATE resume_transfers SET cleaned=1 WHERE id=?',(tid,))
    self.registry.transaction(clear)
  finally: os.close(root)
  return len(ids)
 def reconcile_all(self):
  rows=self.registry.read(lambda db:list(db.execute("SELECT id,owner,device,state FROM resume_transfers WHERE state IN ('receiving','publishing')")))
  for tid,owner,device,state in rows:
   if state=='publishing':
    published=self._published(tid)
    self._cleanup_partial(tid)
    self.registry.transaction(lambda db:db.execute("UPDATE resume_transfers SET state=? WHERE id=? AND state='publishing'",('complete' if published else 'receiving',tid)))
   try: self.reconcile(owner,device,tid)
   except Denied:
    def revoke(db):
     db.execute("UPDATE transfer_keys SET state='cancelled',key_cipher=x'',nonce=x'' WHERE id=? AND state='active'",(tid,))
     db.execute("UPDATE resume_transfers SET state='cancelled' WHERE id=? AND state='receiving'",(tid,))
    self.registry.transaction(revoke)
   except Corrupt: self.registry.transaction(lambda db:db.execute("UPDATE resume_transfers SET state='failed' WHERE id=? AND state='receiving'",(tid,)))
  self.cleanup_terminal()
