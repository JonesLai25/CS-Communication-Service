"""Transfer OTP issuance and protected storage; not a file transfer endpoint."""
import hashlib, os, time, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from registry import Conflict, Denied, Limited, StorageError
from transfer_crypto import context, seal

class TransferStore:
 def __init__(self,registry,master,server_identity):
  if not isinstance(master,bytes) or len(master)!=32 or not isinstance(server_identity,bytes) or len(server_identity)!=32: raise ValueError('invalid server key or identity')
  self.registry=registry; self.master=master; self.server_identity=server_identity
 def initialize(self):
  def op(db):
   db.execute('CREATE TABLE IF NOT EXISTS transfer_keys(owner TEXT NOT NULL, device TEXT NOT NULL, request_id TEXT NOT NULL, id TEXT NOT NULL UNIQUE, direction TEXT NOT NULL, expires INTEGER NOT NULL, enc BLOB NOT NULL, wrapped BLOB NOT NULL, nonce BLOB NOT NULL, key_cipher BLOB NOT NULL, lifetime INTEGER NOT NULL, state TEXT NOT NULL, PRIMARY KEY(owner,request_id))')
   db.execute('CREATE TABLE IF NOT EXISTS download_links(transfer_id TEXT PRIMARY KEY,package_id TEXT NOT NULL)')
   db.execute('CREATE TABLE IF NOT EXISTS transfer_meta(id INTEGER PRIMARY KEY CHECK(id=1), fingerprint BLOB NOT NULL)')
   fingerprint=hashlib.sha256(b'CS-TRANSFER-MASTER-v1'+self.master+self.server_identity).digest()
   db.execute('INSERT OR IGNORE INTO transfer_meta VALUES(1,?)',(fingerprint,))
   if db.execute('SELECT fingerprint FROM transfer_meta WHERE id=1').fetchone()[0]!=fingerprint: raise ValueError('wrong transfer master or server identity')
  self.registry.transaction(op)
 def cleanup(self):
  now=int(time.time())
  return self.registry.transaction(lambda db: db.execute("UPDATE transfer_keys SET state='expired',key_cipher=x'',nonce=x'' WHERE id IN (SELECT id FROM transfer_keys WHERE state='active' AND expires<=? LIMIT 512)",(now,)).rowcount)
 def issue(self,owner,device,request_id,direction,ttl=3600):
  if not isinstance(request_id,str) or str(uuid.UUID(request_id))!=request_id or direction!='upload' or type(ttl) is not int or not 30<=ttl<=3600: raise ValueError('invalid transfer request')
  now=int(time.time())
  def op(db):
   row=db.execute('SELECT d.xpub FROM devices d JOIN users u ON d.owner=u.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone()
   if not row or not isinstance(row[0],bytes) or len(row[0])!=32 or row[0]==bytes(32): raise Denied()
   old=db.execute('SELECT device,id,direction,expires,enc,wrapped,lifetime,state FROM transfer_keys WHERE owner=? AND request_id=?',(owner,request_id)).fetchone()
   if old:
    if old[0]!=device or old[2]!=direction or old[6]!=ttl: raise Conflict()
    if old[3]<=now or old[7]!='active': raise Denied()
    return {'id':old[1],'direction':old[2],'expires':old[3],'enc':old[4],'wrapped':old[5]}
   if db.execute("SELECT count(*) FROM transfer_keys WHERE owner=? AND state='active' AND expires>?",(owner,now)).fetchone()[0]>=4: raise Limited()
   if db.execute('SELECT count(*) FROM transfer_keys WHERE owner=?',(owner,)).fetchone()[0]>=4096: raise Limited()
   tid=str(uuid.uuid4()); aad=context(self.server_identity,owner,device,tid,direction); otp=os.urandom(32)
   enc,wrapped=seal(otp,row[0],self.server_identity,owner,device,tid,direction)
   nonce=os.urandom(12); protected=AESGCM(self.master).encrypt(nonce,otp,aad)
   db.execute('INSERT INTO transfer_keys VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(owner,device,request_id,tid,direction,now+ttl,enc,wrapped,nonce,protected,ttl,'active'))
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(now,owner,device,'transfer_key_issued'))
   return {'id':tid,'direction':direction,'expires':now+ttl,'enc':enc,'wrapped':wrapped}
  return self.registry.transaction(op)
 def lookup(self,owner,device,request_id):
  if not isinstance(request_id,str) or str(uuid.UUID(request_id))!=request_id: raise ValueError('invalid request id')
  now=int(time.time())
  def op(db):
   row=db.execute("SELECT t.id,t.direction,t.expires,t.enc,t.wrapped,(SELECT package_id FROM download_links WHERE transfer_id=t.id) FROM transfer_keys t JOIN devices d ON d.owner=t.owner AND d.device=t.device JOIN users u ON u.owner=d.owner WHERE t.owner=? AND t.device=? AND t.request_id=? AND t.expires>? AND t.state='active' AND d.enabled=1 AND u.enabled=1",(owner,device,request_id,now)).fetchone()
   if row is None: return None
   result={'id':row[0],'direction':row[1],'expires':row[2],'enc':row[3],'wrapped':row[4]}
   if row[1]=='download': result['package_id']=row[5]
   return result
  return self.registry.transaction(op)
 def issue_download(self,owner,device,request_id,package_id,ttl=3600):
  if not isinstance(request_id,str) or str(uuid.UUID(request_id))!=request_id or not isinstance(package_id,str) or str(uuid.UUID(package_id))!=package_id or type(ttl) is not int or not 30<=ttl<=3600: raise ValueError('invalid download request')
  now=int(time.time())
  def op(db):
   row=db.execute('SELECT d.xpub FROM devices d JOIN users u ON d.owner=u.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone()
   if not row or not isinstance(row[0],bytes) or len(row[0])!=32 or row[0]==bytes(32): raise Denied()
   pkg=db.execute("SELECT 1 FROM outgoing_packages WHERE id=? AND owner=? AND state='ready' AND created+86400>?",(package_id,owner,now)).fetchone()
   if not pkg: raise Denied()
   old=db.execute('SELECT t.device,t.id,t.direction,t.expires,t.enc,t.wrapped,t.lifetime,t.state,l.package_id FROM transfer_keys t LEFT JOIN download_links l ON l.transfer_id=t.id WHERE t.owner=? AND t.request_id=?',(owner,request_id)).fetchone()
   if old:
    if old[0]!=device or old[2]!='download' or old[6]!=ttl or old[8]!=package_id: raise Conflict()
    if old[3]<=now or old[7]!='active': raise Denied()
    return {'id':old[1],'direction':'download','expires':old[3],'enc':old[4],'wrapped':old[5],'package_id':package_id}
   if db.execute("SELECT count(*) FROM transfer_keys WHERE owner=? AND state='active' AND expires>?",(owner,now)).fetchone()[0]>=4 or db.execute('SELECT count(*) FROM transfer_keys WHERE owner=?',(owner,)).fetchone()[0]>=4096: raise Limited()
   tid=str(uuid.uuid4()); otp=os.urandom(32); aad=context(self.server_identity,owner,device,tid,'download',package_id)
   enc,wrapped=seal(otp,row[0],self.server_identity,owner,device,tid,'download',package_id)
   nonce=os.urandom(12); protected=AESGCM(self.master).encrypt(nonce,otp,aad)
   db.execute('INSERT INTO transfer_keys VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(owner,device,request_id,tid,'download',now+ttl,enc,wrapped,nonce,protected,ttl,'active'))
   db.execute('INSERT INTO download_links VALUES(?,?)',(tid,package_id))
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(now,owner,device,'transfer_key_issued'))
   return {'id':tid,'direction':'download','expires':now+ttl,'enc':enc,'wrapped':wrapped,'package_id':package_id}
  return self.registry.transaction(op)
 def download_info(self,owner,device,tid):
  if not isinstance(tid,str) or str(uuid.UUID(tid))!=tid: raise ValueError('invalid transfer id')
  def op(db):
   row=db.execute("SELECT l.package_id FROM transfer_keys t JOIN download_links l ON l.transfer_id=t.id JOIN outgoing_packages p ON p.id=l.package_id AND p.owner=t.owner JOIN devices d ON d.owner=t.owner AND d.device=t.device JOIN users u ON u.owner=d.owner WHERE t.owner=? AND t.device=? AND t.id=? AND t.direction='download' AND t.state='active' AND t.expires>? AND p.state='ready' AND p.created+86400>CAST(strftime('%s','now') AS INTEGER) AND d.enabled=1 AND u.enabled=1",(owner,device,tid,int(time.time()))).fetchone()
   if not row: raise Denied()
   return row[0]
  return self.registry.transaction(op)
 def get_key(self,owner,device,tid,direction=None):
  if not isinstance(tid,str) or str(uuid.UUID(tid))!=tid: raise ValueError('invalid transfer id')
  now=int(time.time())
  def op(db):
   row=db.execute('SELECT t.direction,t.nonce,t.key_cipher,(SELECT package_id FROM download_links WHERE transfer_id=t.id) FROM transfer_keys t JOIN devices d ON d.owner=t.owner AND d.device=t.device JOIN users u ON u.owner=d.owner WHERE t.owner=? AND t.device=? AND t.id=? AND t.expires>? AND t.state="active" AND d.enabled=1 AND u.enabled=1',(owner,device,tid,now)).fetchone()
   if not row or (direction is not None and row[0]!=direction): raise Denied()
   try: return AESGCM(self.master).decrypt(row[1],row[2],context(self.server_identity,owner,device,tid,row[0],row[3]))
   except InvalidTag as e: raise StorageError('transfer key integrity failure') from e
  return self.registry.transaction(op)
 def publish_if_authorized(self,owner,device,tid,commit,expected_resume=False):
  def op(db):
   now=int(time.time())
   row=db.execute("SELECT 1 FROM transfer_keys t JOIN devices d ON d.owner=t.owner AND d.device=t.device JOIN users u ON u.owner=d.owner WHERE t.owner=? AND t.device=? AND t.id=? AND t.direction='upload' AND t.state='active' AND t.expires>? AND d.enabled=1 AND u.enabled=1",(owner,device,tid,now)).fetchone()
   if not row: raise Denied()
   has_table=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='resume_transfers'").fetchone()
   resume=db.execute('SELECT state FROM resume_transfers WHERE id=?',(tid,)).fetchone() if has_table else None
   if expected_resume:
    if not resume or resume[0]!='publishing': raise Denied()
   elif resume is not None: raise Conflict()
   commit()
   if expected_resume: db.execute("UPDATE resume_transfers SET state='complete' WHERE id=? AND state='publishing'",(tid,))
  return self.registry.transaction(op)
 def cancel(self,owner,device,tid):
  if not isinstance(tid,str) or str(uuid.UUID(tid))!=tid: raise ValueError('invalid transfer id')
  def op(db):
   active=db.execute('SELECT 1 FROM devices d JOIN users u ON u.owner=d.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone()
   table=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='resume_transfers'").fetchone()
   resume=db.execute('SELECT state FROM resume_transfers WHERE id=? AND owner=? AND device=?',(tid,owner,device)).fetchone() if table else None
   if resume and resume[0]=='complete': raise Conflict()
   if not active or db.execute("UPDATE transfer_keys SET state='cancelled',key_cipher=x'',nonce=x'' WHERE owner=? AND device=? AND id=? AND state='active'",(owner,device,tid)).rowcount!=1: raise Denied()
   if resume: db.execute("UPDATE resume_transfers SET state='cancelled' WHERE id=? AND state!='complete'",(tid,))
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(int(time.time()),owner,device,'transfer_key_cancelled'))
  self.registry.transaction(op)
