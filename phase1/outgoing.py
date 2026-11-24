"""Locally indexed immutable outgoing packages. No arbitrary remote paths."""
import hashlib, os, stat, tempfile, time, uuid
from transfer_archive import pack
from transfer_compress import compress
from registry import Conflict, Denied, Limited

MAX_PACKAGE=128*1024*1024
class _LimitWriter:
 def __init__(self,inner,limit): self.inner=inner; self.limit=limit; self.count=0
 def write(self,data):
  if self.count+len(data)>self.limit: raise ValueError('package size limit')
  n=self.inner.write(data); self.count+=n; return n
 def flush(self): return self.inner.flush()
 def tell(self): return self.count
def _private_root(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 st=os.fstat(fd)
 if st.st_uid!=os.geteuid() or st.st_mode & 0o077:
  os.close(fd); raise ValueError('package root must be private and owned')
 return fd
class Packages:
 def __init__(self,registry,root,received): self.registry=registry; self.root=root; self.received=received
 def initialize(self):
  def op(db):
   if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='transfer_keys'").fetchone(): raise ValueError('transfer store is not initialized')
   db.execute('CREATE TABLE IF NOT EXISTS outgoing_packages(id TEXT PRIMARY KEY,owner TEXT NOT NULL,source_id TEXT NOT NULL,digest BLOB NOT NULL,size INTEGER NOT NULL,created INTEGER NOT NULL,state TEXT NOT NULL)')
   db.execute('CREATE TABLE IF NOT EXISTS outgoing_requests(owner TEXT NOT NULL,request_id TEXT NOT NULL,source_id TEXT NOT NULL,package_id TEXT NOT NULL,PRIMARY KEY(owner,request_id))')
   db.execute('CREATE TABLE IF NOT EXISTS download_links(transfer_id TEXT PRIMARY KEY,package_id TEXT NOT NULL)')
   db.execute('CREATE TABLE IF NOT EXISTS outgoing_ciphertexts(transfer_id TEXT PRIMARY KEY,package_id TEXT NOT NULL,size INTEGER NOT NULL,digest BLOB NOT NULL,state TEXT NOT NULL)')
  self.registry.transaction(op)
 def reconcile_download_staging(self):
  """Called before serving requests, when no download writer can be active."""
  def snapshot(db):
   return ({r[0] for r in db.execute('SELECT transfer_id FROM outgoing_ciphertexts')},
           {r[0] for r in db.execute('SELECT id FROM resume_downloads')})
  known,indexed=self.registry.read(snapshot); root=_private_root(self.root)
  try:
   for name in os.listdir(root):
    if name.startswith('.cs-download-'):
     fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
     try:
      st=os.fstat(fd)
      if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe download staging')
      for child in os.listdir(fd):
       st=os.stat(child,dir_fd=fd,follow_symlinks=False)
       if child!='cipher' or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid(): raise ValueError('unsafe download staging entry')
       os.unlink(child,dir_fd=fd)
      os.fsync(fd)
     finally: os.close(fd)
     os.rmdir(name,dir_fd=root)
    elif name.startswith('download-'):
     tid=name[len('download-'):]
     try:
      if str(uuid.UUID(tid))!=tid: raise ValueError()
     except ValueError: raise ValueError('invalid download cache name')
     if tid not in known:
      if tid in indexed: raise ValueError('download index without ciphertext record')
      st=os.stat(name,dir_fd=root,follow_symlinks=False)
      if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid(): raise ValueError('unsafe orphan download cache')
      os.unlink(name,dir_fd=root)
   os.fsync(root)
  finally: os.close(root)
 def authorize(self,db,owner,device,source_id):
  row=db.execute("SELECT 1 FROM transfer_keys t JOIN devices d ON d.owner=t.owner JOIN users u ON u.owner=d.owner WHERE t.owner=? AND t.id=? AND t.direction='upload' AND t.state='active' AND t.expires>? AND d.device=? AND d.enabled=1 AND u.enabled=1",(owner,source_id,int(time.time()),device)).fetchone()
  if not row: raise Denied()
 def create(self,owner,device,source_id,request_id):
  if not isinstance(source_id,str) or str(uuid.UUID(source_id))!=source_id: raise ValueError('invalid source')
  if not isinstance(request_id,str) or str(uuid.UUID(request_id))!=request_id: raise ValueError('invalid request id')
  def existing(db):
   if not db.execute('SELECT 1 FROM devices d JOIN users u ON d.owner=u.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone(): raise Denied()
   row=db.execute('SELECT r.source_id,p.id,p.size,p.digest,p.state,p.created FROM outgoing_requests r JOIN outgoing_packages p ON p.id=r.package_id WHERE r.owner=? AND r.request_id=?',(owner,request_id)).fetchone()
   if row:
    if row[0]!=source_id: raise Conflict()
    if row[4]!='ready' or row[5]+86400<=int(time.time()): raise Denied()
    return {'package_id':row[1],'size':row[2],'sha256':row[3].hex()}
   self.authorize(db,owner,device,source_id)
   return None
  old=self.registry.transaction(existing)
  if old is not None: return old
  rootfd=_private_root(self.root)
  try: recvfd=_private_root(self.received)
  except BaseException: os.close(rootfd); raise
  try:
   for fd in (rootfd,recvfd):
    st=os.fstat(fd)
    if st.st_uid!=os.geteuid() or st.st_mode & 0o077: raise ValueError('package roots must be private and owned')
   if os.statvfs(self.root).f_bavail*os.statvfs(self.root).f_frsize < 512*1024*1024: raise OSError('insufficient storage')
   source=os.open(source_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=recvfd)
   try:
    base='/proc/self/fd/'+str(rootfd); source_path='/proc/self/fd/'+str(source)+'/.'
    with tempfile.TemporaryDirectory(prefix='.cs-package-',dir=base) as temp:
     archive_path=os.path.join(temp,'tree.tar'); package_path=os.path.join(temp,'package')
     with open(archive_path,'w+b') as archive:
      os.fchmod(archive.fileno(),0o600)
      pack(source_path,_LimitWriter(archive,MAX_PACKAGE)); archive.flush(); archive.seek(0)
      with open(package_path,'w+b') as package:
       os.fchmod(package.fileno(),0o600)
       compress(archive,_LimitWriter(package,MAX_PACKAGE)); package.flush(); os.fsync(package.fileno()); size=package.tell(); package.seek(0); h=hashlib.sha256()
       while True:
        data=package.read(262144)
        if not data: break
        h.update(data)
       digest=h.digest()
     package_id=str(uuid.uuid4()); relative=os.path.relpath(package_path,base)
     def commit(db):
      old=existing(db)
      if old is not None: return old
      if db.execute("SELECT count(*) FROM outgoing_packages WHERE owner=? AND state='ready'",(owner,)).fetchone()[0]>=4: raise Limited()
      # Hard link provides no-replace publishing on one filesystem; source is removed by temporary-directory cleanup.
      os.link(relative,package_id,src_dir_fd=rootfd,dst_dir_fd=rootfd,follow_symlinks=False); os.fsync(rootfd)
      db.execute("INSERT INTO outgoing_packages VALUES(?,?,?,?,?,?, 'ready')",(package_id,owner,source_id,digest,size,int(time.time())))
      db.execute('INSERT INTO outgoing_requests VALUES(?,?,?,?)',(owner,request_id,source_id,package_id))
      return {'package_id':package_id,'size':size,'sha256':digest.hex()}
     return self.registry.transaction(commit)
   finally: os.close(source)
  finally: os.close(recvfd); os.close(rootfd)
 def lookup_request(self,owner,device,request_id):
  if not isinstance(request_id,str) or str(uuid.UUID(request_id))!=request_id: raise ValueError('invalid request id')
  def op(db):
   if not db.execute('SELECT 1 FROM devices d JOIN users u ON d.owner=u.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone(): raise Denied()
   row=db.execute("SELECT p.id,p.size,p.digest FROM outgoing_requests r JOIN outgoing_packages p ON p.id=r.package_id WHERE r.owner=? AND r.request_id=? AND p.state='ready' AND p.created+86400>?",(owner,request_id,int(time.time()))).fetchone()
   return None if row is None else {'package_id':row[0],'size':row[1],'sha256':row[2].hex()}
  return self.registry.transaction(op)
 def list(self,owner,device):
  def op(db):
   if not db.execute('SELECT 1 FROM devices d JOIN users u ON d.owner=u.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone(): raise Denied()
   return [{'package_id':r[0],'size':r[1],'sha256':r[2].hex()} for r in db.execute("SELECT id,size,digest FROM outgoing_packages WHERE owner=? AND state='ready' AND created+86400>? ORDER BY created,id",(owner,int(time.time())))]
  return self.registry.transaction(op)
 def open_verified(self,owner,device,package_id):
  if not isinstance(package_id,str) or str(uuid.UUID(package_id))!=package_id: raise ValueError('invalid package')
  def op(db):
   row=db.execute("SELECT p.size,p.digest FROM outgoing_packages p JOIN devices d ON d.owner=p.owner JOIN users u ON u.owner=d.owner WHERE p.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1 AND p.id=? AND p.state='ready' AND p.created+86400>?",(owner,device,package_id,int(time.time()))).fetchone()
   if not row: raise Denied()
   return row
  size,digest=self.registry.transaction(op)
  if type(size) is not int or not 0<size<=MAX_PACKAGE or not isinstance(digest,bytes) or len(digest)!=32: raise ValueError('invalid package metadata')
  rootfd=_private_root(self.root)
  try: fd=os.open(package_id,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rootfd)
  finally: os.close(rootfd)
  try:
   st=os.fstat(fd)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_nlink!=1 or st.st_size!=size: raise ValueError('invalid package blob')
   h=hashlib.sha256()
   while True:
    chunk=os.read(fd,262144)
    if not chunk: break
    h.update(chunk)
   end=os.fstat(fd)
   if h.digest()!=digest or (st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=(end.st_size,end.st_mtime_ns,end.st_ctime_ns): raise ValueError('package blob changed')
   os.lseek(fd,0,os.SEEK_SET); return fd,size
  except BaseException: os.close(fd); raise
 def retire(self,owner,device,package_id):
  if not isinstance(package_id,str) or str(uuid.UUID(package_id))!=package_id: raise ValueError('invalid package')
  def retire_db(db):
   if not db.execute('SELECT 1 FROM devices d JOIN users u ON d.owner=u.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone(): raise Denied()
   if db.execute("SELECT 1 FROM download_links l JOIN transfer_keys t ON t.id=l.transfer_id WHERE l.package_id=? AND t.state='active' AND t.expires>? LIMIT 1",(package_id,int(time.time()))).fetchone(): raise Conflict()
   if db.execute("UPDATE outgoing_packages SET state='retiring' WHERE owner=? AND id=? AND state='ready'",(owner,package_id)).rowcount!=1: raise Denied()
  self.registry.transaction(retire_db)
  rootfd=_private_root(self.root)
  try:
   try: os.unlink(package_id,dir_fd=rootfd)
   except FileNotFoundError: pass
   os.fsync(rootfd)
  finally: os.close(rootfd)
  self.registry.transaction(lambda db:db.execute("UPDATE outgoing_packages SET state='deleted' WHERE owner=? AND id=? AND state='retiring'",(owner,package_id)))
 def prepare_download(self,transfers,owner,device,transfer_id):
  from transfer_crypto import context
  from transfer_stream import encrypt
  package_id=transfers.download_info(owner,device,transfer_id)
  def existing(db): return db.execute("SELECT size,digest FROM outgoing_ciphertexts WHERE transfer_id=? AND package_id=? AND state='ready'",(transfer_id,package_id)).fetchone()
  if self.registry.transaction(existing) is None:
   def has_resume_index(db):
    table=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='resume_downloads'").fetchone()
    return bool(table and db.execute('SELECT 1 FROM resume_downloads WHERE id=?',(transfer_id,)).fetchone())
   if self.registry.read(has_resume_index): raise ValueError('download index without ciphertext record')
   key=transfers.get_key(owner,device,transfer_id,'download'); source,size=self.open_verified(owner,device,package_id)
   try: rootfd=_private_root(self.root)
   except BaseException: os.close(source); raise
   try:
    space=os.fstatvfs(rootfd)
    if space.f_bavail*space.f_frsize<512*1024*1024: raise OSError('insufficient download storage')
    expected=self.registry.transaction(lambda db:db.execute("SELECT digest FROM outgoing_packages WHERE id=? AND owner=? AND state='ready' AND created+86400>?",(package_id,owner,int(time.time()))).fetchone())
    if not expected: raise Denied()
    with os.fdopen(source,'rb') as inp:
     source=None
     class Reader:
      def __init__(self,stream): self.stream=stream; self.hash=hashlib.sha256(); self.size=0
      def read(self,n):
       data=self.stream.read(n); self.hash.update(data); self.size+=len(data); return data
     reader=Reader(inp); base='/proc/self/fd/'+str(rootfd)
     with tempfile.TemporaryDirectory(prefix='.cs-download-',dir=base) as temp:
      path=os.path.join(temp,'cipher')
      with open(path,'w+b') as cipher:
       os.fchmod(cipher.fileno(),0o600)
       encrypt(reader,_LimitWriter(cipher,160*1024*1024),key,context(transfers.server_identity,owner,device,transfer_id,'download',package_id))
       if reader.size!=size or reader.hash.digest()!=expected[0]: raise ValueError('package changed while encrypting')
       cipher.flush(); os.fsync(cipher.fileno()); cipher_size=cipher.tell(); cipher.seek(0); h=hashlib.sha256()
       while True:
        data=cipher.read(262144)
        if not data: break
        h.update(data)
       digest=h.digest()
      relative=os.path.relpath(path,base); filename='download-'+transfer_id
      def commit(db):
       if not db.execute("SELECT 1 FROM transfer_keys t JOIN download_links l ON l.transfer_id=t.id JOIN outgoing_packages p ON p.id=l.package_id JOIN devices d ON d.owner=t.owner AND d.device=t.device JOIN users u ON u.owner=d.owner WHERE t.id=? AND t.owner=? AND t.device=? AND t.state='active' AND t.expires>? AND l.package_id=? AND p.owner=t.owner AND p.state='ready' AND p.created+86400>CAST(strftime('%s','now') AS INTEGER) AND d.enabled=1 AND u.enabled=1",(transfer_id,owner,device,int(time.time()),package_id)).fetchone(): raise Denied()
       if existing(db) is not None: return
       os.link(relative,filename,src_dir_fd=rootfd,dst_dir_fd=rootfd,follow_symlinks=False); os.fsync(rootfd)
       db.execute("INSERT INTO outgoing_ciphertexts VALUES(?,?,?,?,'ready')",(transfer_id,package_id,cipher_size,digest))
      self.registry.transaction(commit)
   finally:
    if source is not None: os.close(source)
    os.close(rootfd)
  return self.open_download(transfers,owner,device,transfer_id)
 def open_download(self,transfers,owner,device,transfer_id):
  package_id=transfers.download_info(owner,device,transfer_id)
  row=self.registry.transaction(lambda db:db.execute("SELECT size,digest FROM outgoing_ciphertexts WHERE transfer_id=? AND package_id=? AND state='ready'",(transfer_id,package_id)).fetchone())
  if not row: raise Denied()
  if type(row[0]) is not int or not 0<row[0]<=160*1024*1024 or not isinstance(row[1],bytes) or len(row[1])!=32: raise ValueError('invalid ciphertext metadata')
  rootfd=_private_root(self.root)
  try: fd=os.open('download-'+transfer_id,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rootfd)
  finally: os.close(rootfd)
  try:
   st=os.fstat(fd)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_nlink!=1 or st.st_size!=row[0]: raise ValueError('invalid download ciphertext')
   h=hashlib.sha256()
   while True:
    part=os.read(fd,262144)
    if not part: break
    h.update(part)
   end=os.fstat(fd)
   if h.digest()!=row[1] or (st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=(end.st_size,end.st_mtime_ns,end.st_ctime_ns): raise ValueError('download ciphertext changed')
   transfers.download_info(owner,device,transfer_id); os.lseek(fd,0,os.SEEK_SET); return fd,row[0],package_id
  except BaseException: os.close(fd); raise
 def cleanup_download(self,transfer_id):
  if not isinstance(transfer_id,str) or str(uuid.UUID(transfer_id))!=transfer_id: raise ValueError('invalid transfer id')
  def mark(db):
   row=db.execute('SELECT state,expires FROM transfer_keys WHERE id=?',(transfer_id,)).fetchone()
   if not row or (row[0]=='active' and row[1]>int(time.time())): raise Denied()
   return db.execute("UPDATE outgoing_ciphertexts SET state='retiring' WHERE transfer_id=? AND state IN ('ready','retiring')",(transfer_id,)).rowcount
  if not self.registry.transaction(mark): return
  rootfd=_private_root(self.root)
  try:
   try: os.unlink('download-'+transfer_id,dir_fd=rootfd)
   except FileNotFoundError: pass
   os.fsync(rootfd)
  finally: os.close(rootfd)
  self.registry.transaction(lambda db:db.execute("UPDATE outgoing_ciphertexts SET state='deleted' WHERE transfer_id=? AND state='retiring'",(transfer_id,)))
 def cleanup_expired(self,transfers):
  """Bounded maintenance; retry tombstones on future calls after interruption."""
  now=int(time.time()); transfers.cleanup()
  def mark(db):
   db.execute("UPDATE outgoing_packages SET state='retiring' WHERE id IN (SELECT id FROM outgoing_packages WHERE state='ready' AND created+86400<=? LIMIT 512)",(now,))
   db.execute("UPDATE transfer_keys SET state='expired',nonce=x'',key_cipher=x'' WHERE state='active' AND id IN (SELECT l.transfer_id FROM download_links l JOIN outgoing_packages p ON p.id=l.package_id WHERE p.state='retiring')")
   ciphers=[r[0] for r in db.execute("SELECT c.transfer_id FROM outgoing_ciphertexts c JOIN transfer_keys t ON t.id=c.transfer_id WHERE c.state IN ('ready','retiring') AND (t.state!='active' OR t.expires<=?) LIMIT 64",(now,))]
   packages=[r[0] for r in db.execute("SELECT id FROM outgoing_packages WHERE state='retiring' LIMIT 64")]
   return ciphers,packages
  ciphers,packages=self.registry.transaction(mark)
  for tid in ciphers: self.cleanup_download(tid)
  rootfd=_private_root(self.root)
  try:
   for package_id in packages:
    if str(uuid.UUID(package_id))!=package_id: raise ValueError('invalid package id in index')
    try: os.unlink(package_id,dir_fd=rootfd)
    except FileNotFoundError: pass
   if packages: os.fsync(rootfd)
  finally: os.close(rootfd)
  for package_id in packages: self.registry.transaction(lambda db:db.execute("UPDATE outgoing_packages SET state='deleted' WHERE id=? AND state='retiring'",(package_id,)))
  return len(ciphers),len(packages)
