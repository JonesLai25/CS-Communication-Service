"""Archived CR-001 prototype: NOT used by Phase 1, no security support or migration."""
import hashlib, os, sqlite3, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

class AuthError(Exception): pass
class Conflict(Exception): pass
class Store:
 def __init__(self,path):
  self.db=sqlite3.connect(path, timeout=5, isolation_level=None)
  self.db.execute('PRAGMA journal_mode=WAL')
  self.db.executescript('''CREATE TABLE IF NOT EXISTS keys(owner TEXT NOT NULL,device TEXT PRIMARY KEY,pub BLOB NOT NULL,enabled INTEGER NOT NULL DEFAULT 1); CREATE TABLE IF NOT EXISTS challenges(nonce BLOB PRIMARY KEY,owner TEXT NOT NULL,device TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS requests(owner TEXT NOT NULL,id TEXT NOT NULL,digest BLOB NOT NULL,state TEXT NOT NULL,PRIMARY KEY(owner,id));''')
 def close(self): self.db.close()
 def provision(self,owner,device,pub): self.db.execute('INSERT INTO keys(owner,device,pub) VALUES(?,?,?)',(owner,device,pub))
 def challenge(self,owner,device):
  if not self.db.execute('SELECT 1 FROM keys WHERE owner=? AND device=? AND enabled=1',(owner,device)).fetchone(): raise AuthError('unavailable')
  nonce=os.urandom(32); self.db.execute('INSERT INTO challenges(nonce,owner,device,expires) VALUES(?,?,?,?)',(nonce,owner,device,int(time.time())+60)); return nonce
 @staticmethod
 def message(owner,device,nonce):
  # Length-prefix fields prevent ambiguous encodings; bind domain and identity.
  fields=[owner.encode(),device.encode(),nonce]
  return b'CS-AUTH-EXPERIMENT-v1'+b''.join(len(x).to_bytes(4,'big')+x for x in fields)
 def authenticate(self,owner,device,nonce,signature):
  self.db.execute('BEGIN IMMEDIATE')
  try:
   row=self.db.execute('SELECT k.pub FROM keys k JOIN challenges c ON c.owner=k.owner AND c.device=k.device WHERE k.owner=? AND k.device=? AND k.enabled=1 AND c.nonce=? AND c.used=0 AND c.expires>?',(owner,device,nonce,int(time.time()))).fetchone()
   if row is None: raise AuthError('invalid challenge')
   try: Ed25519PublicKey.from_public_bytes(row[0]).verify(signature,self.message(owner,device,nonce))
   except InvalidSignature as e: raise AuthError('invalid signature') from e
   self.db.execute('UPDATE challenges SET used=1 WHERE nonce=?',(nonce,)); self.db.execute('COMMIT')
  except BaseException: self.db.execute('ROLLBACK'); raise
 def request(self,owner,rid,body):
  digest=hashlib.sha256(body).digest(); self.db.execute('BEGIN IMMEDIATE')
  try:
   row=self.db.execute('SELECT digest,state FROM requests WHERE owner=? AND id=?',(owner,rid)).fetchone()
   if row and row[0]!=digest: raise Conflict('request ID reused with different content')
   if row is None: self.db.execute('INSERT INTO requests VALUES(?,?,?,?)',(owner,rid,digest,'created')); state='created'
   else: state=row[1]
   self.db.execute('COMMIT'); return state
  except BaseException: self.db.execute('ROLLBACK'); raise
