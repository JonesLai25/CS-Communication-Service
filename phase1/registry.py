"""Phase 1 SQLite registry: each transaction owns its connection."""
import hashlib, os, secrets, sqlite3, time
from contextlib import closing
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class Denied(Exception): pass
class Conflict(Exception): pass
class Busy(Exception): pass
class Limited(Exception): pass
class StorageError(Exception): pass

def message(server, channel, challenge, owner, device):
    fields=(b'cs/1',b'client-auth',server,channel,challenge,owner.encode('utf-8'),device.encode('utf-8'))
    return b'CS-AUTH-v1\x00'+b''.join(len(x).to_bytes(4,'big')+x for x in fields)

class Registry:
 def __init__(self,path): self.path=path
 def connect(self):
  try:
   db=sqlite3.connect(self.path,timeout=0.25,isolation_level=None)
   try:
    db.execute('PRAGMA busy_timeout=250')
    db.execute('PRAGMA secure_delete=ON')
   except BaseException: db.close(); raise
   return db
  except sqlite3.Error as e: self.classify(e)
 @staticmethod
 def classify(e):
  if (isinstance(getattr(e,'sqlite_errorcode',None),int) and (e.sqlite_errorcode & 255) in (getattr(sqlite3,'SQLITE_BUSY',5),getattr(sqlite3,'SQLITE_LOCKED',6))) or 'locked' in str(e).lower() or 'busy' in str(e).lower(): raise Busy('database busy') from e
  raise StorageError('database unavailable') from e
 def read(self,fun):
  try:
   with closing(self.connect()) as db: return fun(db)
  except sqlite3.Error as e: self.classify(e)
 def initialize(self):
  fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)
  with closing(self.connect()) as db:
   db.executescript('''PRAGMA journal_mode=WAL; CREATE TABLE devices(owner TEXT NOT NULL,device TEXT NOT NULL,pub BLOB NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(owner,device)); CREATE TABLE challenges(id BLOB PRIMARY KEY,owner TEXT NOT NULL,device TEXT NOT NULL,channel BLOB NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0); CREATE INDEX challenges_device ON challenges(owner,device,expires); CREATE TABLE issued(owner TEXT NOT NULL,device TEXT NOT NULL,at INTEGER NOT NULL); CREATE TABLE requests(owner TEXT NOT NULL,id TEXT NOT NULL,digest BLOB NOT NULL,state TEXT NOT NULL,result TEXT NOT NULL,PRIMARY KEY(owner,id)); CREATE TABLE effects(owner TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(owner,id)); CREATE TABLE audit(at INTEGER NOT NULL,owner TEXT NOT NULL,device TEXT NOT NULL,event TEXT NOT NULL);''')
  self.upgrade()
 def transaction(self,fun):
  db=self.connect()
  try:
   db.execute('BEGIN IMMEDIATE'); out=fun(db); db.execute('COMMIT'); return out
  except sqlite3.Error as e:
   if db.in_transaction:
    try: db.execute('ROLLBACK')
    except sqlite3.Error: pass
   self.classify(e)
  except BaseException:
   if db.in_transaction: db.execute('ROLLBACK')
   raise
  finally: db.close()
 def upgrade(self):
  def op(db):
   db.execute('CREATE TABLE IF NOT EXISTS users(owner TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1)')
   if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit'").fetchone(): db.execute('CREATE INDEX IF NOT EXISTS audit_at ON audit(at)')
   db.execute('CREATE TABLE IF NOT EXISTS enrollment_otps(digest BLOB PRIMARY KEY, owner TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)')
   if 'xpub' not in [r[1] for r in db.execute('PRAGMA table_info(devices)')]: db.execute('ALTER TABLE devices ADD COLUMN xpub BLOB')
   db.execute('INSERT OR IGNORE INTO users(owner) SELECT DISTINCT owner FROM devices')
  self.transaction(op)
 def prune_audit(self,retention_days,max_records,now=None):
  if type(retention_days) is not int or not 1<=retention_days<=3650 or type(max_records) is not int or not 100<=max_records<=1000000: raise ValueError('invalid audit retention policy')
  now=int(time.time()) if now is None else now
  if type(now) is not int: raise ValueError('invalid clock')
  def op(db):
   first=db.execute('DELETE FROM audit WHERE rowid IN (SELECT rowid FROM audit WHERE at<? ORDER BY at,rowid LIMIT 1000)',(now-retention_days*86400,)).rowcount
   excess=max(0,db.execute('SELECT count(*) FROM audit').fetchone()[0]-max_records)
   second=db.execute('DELETE FROM audit WHERE rowid IN (SELECT rowid FROM audit ORDER BY at,rowid LIMIT ?)',(min(excess,1000),)).rowcount
   return first+second
  return self.transaction(op)
 def provision(self,owner,device,pub):
  def op(db):
   db.execute('INSERT OR IGNORE INTO users(owner) VALUES(?)',(owner,))
   db.execute('INSERT INTO devices(owner,device,pub) VALUES(?,?,?)',(owner,device,pub))
  self.transaction(op)
 def add_user(self,owner):
  def op(db):
   if db.execute('SELECT 1 FROM users WHERE owner=?',(owner,)).fetchone(): raise Conflict()
   db.execute('INSERT INTO users(owner) VALUES(?)',(owner,))
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(int(time.time()),owner,'','user_created'))
  self.transaction(op)
 def list_users(self):
  return self.read(lambda db: [{'owner':r[0],'enabled':bool(r[1])} for r in db.execute('SELECT owner,enabled FROM users ORDER BY owner')])
 def disable_user(self,owner):
  def op(db):
   if db.execute('UPDATE users SET enabled=0 WHERE owner=?',(owner,)).rowcount!=1: raise Denied()
   db.execute('UPDATE enrollment_otps SET used=1 WHERE owner=?',(owner,))
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(int(time.time()),owner,'','user_disabled'))
  self.transaction(op)
 def create_otp(self,owner,ttl):
  if type(ttl) is not int or not 30<=ttl<=3600: raise ValueError('invalid ttl')
  token=secrets.token_urlsafe(32); digest=hashlib.sha256(token.encode('ascii')).digest(); now=int(time.time())
  def op(db):
   if not db.execute('SELECT 1 FROM users WHERE owner=? AND enabled=1',(owner,)).fetchone(): raise Denied()
   db.execute('DELETE FROM enrollment_otps WHERE rowid IN (SELECT rowid FROM enrollment_otps WHERE expires<=? LIMIT 1000)',(now,))
   if db.execute('SELECT count(*) FROM enrollment_otps WHERE owner=? AND used=0',(owner,)).fetchone()[0]>=4: raise Limited()
   db.execute('INSERT INTO enrollment_otps VALUES(?,?,?,0)',(digest,owner,now+ttl))
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(now,owner,'','enrollment_otp_created'))
  self.transaction(op); return token
 def revoke_otps(self,owner):
  def op(db):
   if not db.execute('SELECT 1 FROM users WHERE owner=?',(owner,)).fetchone(): raise Denied()
   db.execute('UPDATE enrollment_otps SET used=1 WHERE owner=?',(owner,))
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(int(time.time()),owner,'','enrollment_otp_revoked'))
  self.transaction(op)
 def list_devices(self,owner):
  return self.read(lambda db: [{'device':r[0],'enabled':bool(r[1]),'signing_sha256':hashlib.sha256(r[2]).hexdigest(),'encryption_sha256':hashlib.sha256(r[3]).hexdigest() if r[3] is not None else None} for r in db.execute('SELECT device,enabled,pub,xpub FROM devices WHERE owner=? ORDER BY device',(owner,))])
 def revoke_device(self,owner,device):
  def op(db):
   if db.execute('UPDATE devices SET enabled=0 WHERE owner=? AND device=?',(owner,device)).rowcount!=1: raise Denied()
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(int(time.time()),owner,device,'device_revoked'))
  self.transaction(op)
 def enroll(self,owner,device,edpub,xpub,token):
  if not isinstance(token,str) or len(token)!=43 or not token.isascii(): raise Denied()
  digest=hashlib.sha256(token.encode('ascii')).digest(); now=int(time.time())
  def op(db):
   if not db.execute('SELECT 1 FROM users WHERE owner=? AND enabled=1',(owner,)).fetchone(): raise Denied()
   if not db.execute('SELECT 1 FROM enrollment_otps WHERE digest=? AND owner=? AND expires>? AND used=0',(digest,owner,now)).fetchone(): raise Denied()
   if db.execute('SELECT 1 FROM devices WHERE owner=? AND device=?',(owner,device)).fetchone(): raise Conflict()
   db.execute('INSERT INTO devices(owner,device,pub,xpub) VALUES(?,?,?,?)',(owner,device,edpub,xpub))
   if db.execute('UPDATE enrollment_otps SET used=1 WHERE digest=? AND used=0',(digest,)).rowcount!=1: raise Denied()
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(now,owner,device,'device_enrolled'))
  self.transaction(op)

 def transfer_recipient(self,owner,device):
  """Resolve only an enabled registered device with a usable encryption key."""
  def op(db):
   row=db.execute('SELECT d.xpub FROM devices d JOIN users u ON u.owner=d.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone()
   if not row or not isinstance(row[0],bytes) or len(row[0])!=32 or row[0]==bytes(32): raise Denied()
   return row[0]
  return self.transaction(op)

 def enabled(self,owner,device):
  return self.read(lambda db: bool(db.execute('SELECT 1 FROM devices JOIN users USING(owner) WHERE devices.owner=? AND device=? AND devices.enabled=1 AND users.enabled=1',(owner,device)).fetchone()))
 def issue(self,owner,device,channel):
  now=int(time.time())
  def op(db):
   db.execute('DELETE FROM challenges WHERE expires<=?',(now,))
   if not db.execute('SELECT 1 FROM devices JOIN users USING(owner) WHERE devices.owner=? AND device=? AND devices.enabled=1 AND users.enabled=1',(owner,device)).fetchone(): raise Denied()
   db.execute('DELETE FROM challenges WHERE channel=?',(channel,))
   if db.execute('SELECT count(*) FROM challenges').fetchone()[0]>=256: raise Limited()
   challenge=secrets.token_bytes(32); db.execute('INSERT INTO challenges VALUES(?,?,?,?,?,0)',(challenge,owner,device,channel,now+60)); return challenge
  return self.transaction(op)
 def release(self,channel):
  self.transaction(lambda db: db.execute('DELETE FROM challenges WHERE channel=?',(channel,)))
 def authenticate(self,owner,device,channel,challenge,server,signature):
  now=int(time.time())
  def op(db):
   row=db.execute('SELECT d.pub FROM challenges c JOIN devices d ON d.owner=c.owner AND d.device=c.device JOIN users u ON u.owner=d.owner WHERE u.enabled=1 AND c.id=? AND c.owner=? AND c.device=? AND c.channel=? AND c.expires>? AND c.used=0 AND d.enabled=1',(challenge,owner,device,channel,now)).fetchone()
   if not row: raise Denied()
   try: Ed25519PublicKey.from_public_bytes(row[0]).verify(signature,message(server,channel,challenge,owner,device))
   except (InvalidSignature,ValueError) as e: raise Denied() from e
   if db.execute('UPDATE challenges SET used=1 WHERE id=? AND used=0',(challenge,)).rowcount!=1: raise Denied()
   db.execute('INSERT INTO audit VALUES(?,?,?,?)',(now,owner,device,'authentication_succeeded'))
  self.transaction(op)
 def execute(self,owner,rid,body,device):
  digest=hashlib.sha256(body).digest()
  def op(db):
   if not db.execute('SELECT 1 FROM devices JOIN users USING(owner) WHERE devices.owner=? AND device=? AND devices.enabled=1 AND users.enabled=1',(owner,device)).fetchone(): raise Denied()
   row=db.execute('SELECT digest,state,result FROM requests WHERE owner=? AND id=?',(owner,rid)).fetchone()
   if row:
    if row[0]!=digest: raise Conflict()
    return {'new':False,'state':row[1],'result':row[2]}
   db.execute('INSERT INTO requests VALUES(?,?,?,?,?)',(owner,rid,digest,'running',''))
   # Entire harmless test effect and final result share the same SQLite transaction.
   db.execute('INSERT INTO effects VALUES(?,?)',(owner,rid))
   db.execute("UPDATE requests SET state='succeeded', result='recorded' WHERE owner=? AND id=?",(owner,rid))
   return {'new':True,'state':'succeeded','result':'recorded'}
  return self.transaction(op)
 def result(self,owner,rid,device):
  def op(db):
   if not db.execute('SELECT 1 FROM devices JOIN users USING(owner) WHERE devices.owner=? AND device=? AND devices.enabled=1 AND users.enabled=1',(owner,device)).fetchone(): raise Denied()
   row=db.execute('SELECT state,result FROM requests WHERE owner=? AND id=?',(owner,rid)).fetchone()
   return None if row is None else {'state':row[0],'result':row[1]}
  return self.transaction(op)
