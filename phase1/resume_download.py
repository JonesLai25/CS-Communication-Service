"""Stable per-chunk download manifest over Phase 3 retained ciphertext."""
import hashlib,hmac,json,os,re,stat,uuid
from registry import Denied
from resume_store import CHUNK,MAX_SIZE,Corrupt,key_check
from transfer_crypto import context

class ResumeDownload:
 def __init__(self,registry,transfers,packages): self.registry=registry; self.transfers=transfers; self.packages=packages
 def initialize(self):
  def op(db):
   db.execute('CREATE TABLE IF NOT EXISTS resume_downloads(id TEXT PRIMARY KEY,manifest BLOB NOT NULL)')
   db.execute('CREATE TABLE IF NOT EXISTS resume_download_chunks(id TEXT NOT NULL,idx INTEGER NOT NULL,size INTEGER NOT NULL,digest BLOB NOT NULL,PRIMARY KEY(id,idx))')
  self.registry.transaction(op)
 def cleanup_terminal(self):
  def op(db):
   ids=[row[0] for row in db.execute("SELECT r.id FROM resume_downloads r JOIN transfer_keys t ON t.id=r.id WHERE t.state!='active' OR t.expires<=CAST(strftime('%s','now') AS INTEGER) LIMIT 64")]
   for tid in ids:
    db.execute('DELETE FROM resume_download_chunks WHERE id=?',(tid,))
    db.execute('DELETE FROM resume_downloads WHERE id=?',(tid,))
   return len(ids)
  return self.registry.transaction(op)
 def meta(self,owner,device,tid):
  package_id=self.transfers.download_info(owner,device,tid); key=self.transfers.get_key(owner,device,tid,'download')
  source=self.registry.transaction(lambda db:db.execute("SELECT digest FROM outgoing_packages WHERE id=? AND owner=? AND state='ready'",(package_id,owner)).fetchone())
  if not source or not isinstance(source[0],bytes) or len(source[0])!=32: raise Denied()
  fd,size,verified_package=self.packages.prepare_download(self.transfers,owner,device,tid)
  try:
   if verified_package!=package_id or not 1<=size<=MAX_SIZE: raise Corrupt('invalid download cache')
   h=hashlib.sha256(); chunks=[]
   while True:
    parts=bytearray()
    while len(parts)<CHUNK:
     part=os.read(fd,CHUNK-len(parts))
     if not part: break
     parts.extend(part)
    if not parts: break
    b=bytes(parts); h.update(b); chunks.append((len(b),hashlib.sha256(b).digest()))
   if sum(n for n,_ in chunks)!=size: raise Corrupt('download length changed')
  finally: os.close(fd)
  binding=context(self.transfers.server_identity,owner,device,tid,'download',package_id)
  m={'version':1,'transfer_id':tid,'package_id':package_id,'size':size,'chunks':len(chunks),'cipher_sha256':h.hexdigest(),'source_sha256':source[0].hex(),'key_check':key_check(key,binding),'context_sha256':hashlib.sha256(binding).hexdigest()}
  raw=json.dumps(m,sort_keys=True,separators=(',',':')).encode('ascii')
  def op(db):
   self.transfers_check(db,owner,device,tid,package_id)
   old=db.execute('SELECT manifest FROM resume_downloads WHERE id=?',(tid,)).fetchone()
   if old and old[0]!=raw: raise Corrupt('download manifest changed')
   if not old:
    db.execute('INSERT INTO resume_downloads VALUES(?,?)',(tid,raw))
    db.executemany('INSERT INTO resume_download_chunks VALUES(?,?,?,?)',[(tid,i,n,d) for i,(n,d) in enumerate(chunks)])
   else:
    rows=list(db.execute('SELECT idx,size,digest FROM resume_download_chunks WHERE id=? ORDER BY idx',(tid,)))
    if rows!=[(i,n,d) for i,(n,d) in enumerate(chunks)]: raise Corrupt('download chunk index changed')
  self.registry.transaction(op); return m
 def transfers_check(self,db,owner,device,tid,package_id):
  row=db.execute("SELECT 1 FROM transfer_keys t JOIN download_links l ON l.transfer_id=t.id JOIN outgoing_packages p ON p.id=l.package_id JOIN devices d ON d.owner=t.owner AND d.device=t.device JOIN users u ON u.owner=d.owner WHERE t.owner=? AND t.device=? AND t.id=? AND t.direction='download' AND t.state='active' AND t.expires>CAST(strftime('%s','now') AS INTEGER) AND l.package_id=? AND p.owner=t.owner AND p.state='ready' AND p.created+86400>CAST(strftime('%s','now') AS INTEGER) AND d.enabled=1 AND u.enabled=1",(owner,device,tid,package_id)).fetchone()
  if not row: raise Denied()
 def index(self,owner,device,tid,cursor):
  if not isinstance(tid,str) or str(uuid.UUID(tid))!=tid or type(cursor) is not int or cursor<0: raise ValueError('invalid cursor')
  def op(db):
   row=db.execute('SELECT manifest FROM resume_downloads WHERE id=?',(tid,)).fetchone()
   if not row: raise Denied()
   m=json.loads(row[0]); self.transfers_check(db,owner,device,tid,m['package_id'])
   rows=list(db.execute('SELECT idx,size,digest FROM resume_download_chunks WHERE id=? AND idx>=? ORDER BY idx LIMIT 16',(tid,cursor)))
   entries=[{'index':i,'size':size,'sha256':digest.hex()} for i,size,digest in rows]
   return {'chunks':entries,'next':entries[-1]['index']+1 if len(entries)==16 else None}
  return self.registry.transaction(op)
 def chunk(self,owner,device,tid,index):
  if not isinstance(tid,str) or str(uuid.UUID(tid))!=tid or type(index) is not int or index<0: raise ValueError('invalid chunk')
  def metadata(db):
   row=db.execute('SELECT manifest FROM resume_downloads WHERE id=?',(tid,)).fetchone()
   if not row: raise Denied()
   m=json.loads(row[0]); self.transfers_check(db,owner,device,tid,m['package_id'])
   item=db.execute('SELECT size,digest FROM resume_download_chunks WHERE id=? AND idx=?',(tid,index)).fetchone()
   if not item: raise Denied()
   return m,item
  m,item=self.registry.transaction(metadata); root=self.packages.root
  rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   st=os.fstat(rootfd)
   if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe download root')
   fd=os.open('download-'+tid,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rootfd)
   try:
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_size!=m['size']: raise Corrupt('invalid ciphertext file')
    data=os.pread(fd,item[0],index*CHUNK)
   finally: os.close(fd)
  finally: os.close(rootfd)
  if len(data)!=item[0] or not hmac.compare_digest(hashlib.sha256(data).digest(),item[1]): raise Corrupt('download chunk corruption')
  self.registry.transaction(lambda db:self.transfers_check(db,owner,device,tid,m['package_id']))
  return data,item[1].hex()
