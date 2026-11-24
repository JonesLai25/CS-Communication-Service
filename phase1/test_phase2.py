import base64,concurrent.futures,hashlib,json,os,pathlib,select,socket,sqlite3,stat,struct,subprocess,sys,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from client import AuthenticatedClient, AuthorizationError, UnknownOutcome
from enrollment import raw_public, transcript, proof, verify
from registry import Registry, Denied
from admin import Server as AdminServer, peer_allowed
P=pathlib.Path(__file__).resolve().parent
class Enrollment(unittest.TestCase):
 def test_enrollment_and_management(self):
  with tempfile.TemporaryDirectory() as d:
   cert=d+'/cert'; tlskey=d+'/tlskey'; db=d+'/db'; sock=d+'/admin.sock'; Registry(db).initialize()
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',tlskey,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   proc=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',cert,'--key',tlskey,'--db',db,'--admin-socket',sock],stdout=subprocess.PIPE,text=True)
   try:
    if not select.select([proc.stdout],[],[],5)[0]: self.fail('server startup timeout')
    port=int(proc.stdout.readline()); self.assertEqual(stat.S_IMODE(os.stat(sock).st_mode),0o600)
    def admin(**kw):
     with socket.socket(socket.AF_UNIX) as s:
      s.settimeout(3); s.connect(sock); s.sendall(json.dumps(kw).encode()+b'\n'); return json.loads(s.makefile('rb').readline(4097))
    def connect(owner,device,key): return AuthenticatedClient('localhost',port,cert,owner,device,key)
    self.assertEqual(admin(op='user_add',owner='alice'),{'ok':True})
    self.assertEqual(admin(op='user_add',owner='alice'),{'error':'conflict'})
    with socket.socket(socket.AF_UNIX) as raw_socket:
     raw_socket.settimeout(3); raw_socket.connect(sock); raw_socket.sendall(b'{\"op\":\"user_list\",\"op\":\"user_list\"}\n'); self.assertEqual(json.loads(raw_socket.makefile('rb').readline()),{'error':'bad_request'})
    self.assertEqual(admin(op='user_list'),{'users':[{'owner':'alice','enabled':True}]})
    self.assertEqual(admin(op='user_add',owner='bob'),{'ok':True})
    otp=admin(op='otp_create',owner='alice',ttl=300)['otp']; ed=Ed25519PrivateKey.generate(); x=X25519PrivateKey.generate()
    wrong=connect('alice','wrong',ed)
    try:
     with self.assertRaises(AuthorizationError): wrong.enroll('x'*43,x)
    finally: wrong.close()
    # Invalid X25519 proof must not consume the correct OTP.
    bad=connect('alice','device',ed)
    try:
     status,challenge=bad.call('POST','/v1/enroll/challenge',{'owner':'alice','device':'device','edpub':base64.b64encode(raw_public(ed.public_key())).decode(),'xpub':base64.b64encode(raw_public(x.public_key())).decode()}); self.assertEqual(status,200)
     nonce=base64.b64decode(challenge['nonce']); epub=base64.b64decode(challenge['epub']); channel=hashlib.sha256(bad.conn.sock.exporter()).digest(); server=hashlib.sha256(bad.conn.sock.getpeercert(binary_form=True)).digest()
     message=transcript(server,channel,nonce,'alice','device',raw_public(ed.public_key()),raw_public(x.public_key()),epub,otp)
     # A valid enrollment response is bound to its originating TLS connection.
     cross=connect('alice','device',ed)
     try:
      valid_mac=proof(x.exchange(X25519PublicKey.from_public_bytes(epub)),nonce,message)
      status,_=cross.call('POST','/v1/enroll/complete',{'otp':otp,'signature':base64.b64encode(ed.sign(message)).decode(),'proof':base64.b64encode(valid_mac).decode()}); self.assertEqual(status,403)
     finally: cross.close()
     wrong_x=X25519PrivateKey.generate(); wrong_mac=proof(wrong_x.exchange(X25519PublicKey.from_public_bytes(epub)),nonce,message)
     status,_=bad.call('POST','/v1/enroll/complete',{'otp':otp,'signature':base64.b64encode(ed.sign(message)).decode(),'proof':base64.b64encode(wrong_mac).decode()}); self.assertEqual(status,403)
    finally: bad.close()
    other=connect('bob','other',Ed25519PrivateKey.generate())
    try:
     with self.assertRaises(AuthorizationError): other.enroll(otp,X25519PrivateKey.generate())
    finally: other.close()
    c=connect('alice','device',ed)
    try:
     self.assertTrue(c.enroll(otp,x))
     self.assertEqual(c.call('POST','/v1/challenge',{'owner':'alice','device':'device'})[0],403)
    finally: c.close()
    self.assertEqual(admin(op='device_list',owner='alice'),{'devices':[{'device':'device','enabled':True,'signing_sha256':hashlib.sha256(raw_public(ed.public_key())).hexdigest(),'encryption_sha256':hashlib.sha256(raw_public(x.public_key())).hexdigest()}]})
    c=connect('alice','device',ed)
    try: c.authenticate()
    finally: c.close()
    replay=connect('alice','second',Ed25519PrivateKey.generate())
    try:
     with self.assertRaises(AuthorizationError): replay.enroll(otp,X25519PrivateKey.generate())
    finally: replay.close()
    raceotp=admin(op='otp_create',owner='alice',ttl=300)['otp']
    def race(i):
     connection=connect('alice','race'+str(i),Ed25519PrivateKey.generate())
     try:
      try: connection.enroll(raceotp,X25519PrivateKey.generate()); return True
      except AuthorizationError: return False
     finally: connection.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: self.assertEqual(sorted(pool.map(race,[1,2],timeout=10)),[False,True])
    # Lose the enrollment response after server commit; retain keys and query by authentication.
    lostotp=admin(op='otp_create',owner='alice',ttl=300)['otp']; lostkey=Ed25519PrivateKey.generate(); lost=connect('alice','lost',lostkey); original=lost.conn.getresponse; calls=[0]
    def drop_response():
     calls[0]+=1; response=original()
     if calls[0]==2:
      response.read(); raise ConnectionResetError('simulated lost enrollment response')
     return response
    lost.conn.getresponse=drop_response
    try:
     with self.assertRaises(UnknownOutcome): lost.enroll(lostotp,X25519PrivateKey.generate())
    finally: lost.close()
    recovered=connect('alice','lost',lostkey)
    try: recovered.authenticate()
    finally: recovered.close()
    self.assertEqual(admin(op='device_revoke',owner='alice',device='device'),{'ok':True})
    c=connect('alice','device',ed)
    try:
     with self.assertRaises(AuthorizationError): c.authenticate()
    finally: c.close()
    revoked=admin(op='otp_create',owner='alice',ttl=300)['otp']; self.assertEqual(admin(op='otp_revoke',owner='alice'),{'ok':True})
    c=connect('alice','revoked',Ed25519PrivateKey.generate())
    try:
     with self.assertRaises(AuthorizationError): c.enroll(revoked,X25519PrivateKey.generate())
    finally: c.close()
    cliotp=admin(op='otp_create',owner='alice',ttl=300)['otp']; cred=d+'/credentials'
    argv=[sys.executable,str(P/'enroll_cli.py'),'--port',str(port),'--ca',cert,'--owner','alice','--device','cli','--credential-dir',cred]
    cli=subprocess.run(argv,input=cliotp+'\n',text=True,capture_output=True,timeout=12)
    self.assertEqual(cli.returncode,0,cli.stderr); self.assertNotIn(cliotp,cli.stdout+cli.stderr)
    for filename in ('ed25519.key','x25519.key'): self.assertEqual(stat.S_IMODE(os.stat(cred+'/'+filename).st_mode),0o600)
    resumed=subprocess.run(argv+['--resume'],input='',text=True,capture_output=True,timeout=12)
    self.assertEqual(resumed.returncode,0,resumed.stderr); self.assertIn('already registered',resumed.stdout)
    livekey=Ed25519PrivateKey.generate(); liveotp=admin(op='otp_create',owner='alice',ttl=300)['otp']
    c=connect('alice','live',livekey)
    try: self.assertTrue(c.enroll(liveotp,X25519PrivateKey.generate()))
    finally: c.close()
    live=connect('alice','live',livekey); live.authenticate()
    otp2=admin(op='otp_create',owner='alice',ttl=300)['otp']; self.assertEqual(admin(op='user_disable',owner='alice'),{'ok':True})
    try: self.assertEqual(live.call('GET','/v1/result?id=00000000-0000-0000-0000-000000000000')[0],403)
    finally: live.close()
    c=connect('alice','third',Ed25519PrivateKey.generate())
    try:
     with self.assertRaises(AuthorizationError): c.enroll(otp2,X25519PrivateKey.generate())
    finally: c.close()
    with sqlite3.connect(db) as dbh:
     raw=' '.join(str(row) for row in dbh.execute('SELECT * FROM audit'))
     self.assertNotIn(otp,raw); self.assertIn('user_disabled',raw); self.assertIn('device_revoked',raw); self.assertIn('enrollment_otp_revoked',raw); self.assertEqual(dbh.execute('SELECT length(xpub) FROM devices WHERE device=?',('device',)).fetchone()[0],32)
   finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close()
 def test_signing_and_encryption_key_proofs(self):
  ed=Ed25519PrivateKey.generate(); wrong=Ed25519PrivateKey.generate(); x=X25519PrivateKey.generate(); eph=X25519PrivateKey.generate(); nonce=os.urandom(32); message=b'test transcript'
  mac=proof(x.exchange(eph.public_key()),nonce,message)
  self.assertTrue(verify(raw_public(ed.public_key()),raw_public(x.public_key()),eph,nonce,message,ed.sign(message),mac))
  self.assertFalse(verify(raw_public(ed.public_key()),raw_public(x.public_key()),eph,nonce,message,wrong.sign(message),mac))
  self.assertFalse(verify(raw_public(ed.public_key()),raw_public(x.public_key()),eph,nonce,b'changed',ed.sign(message),mac))
 def test_phase1_registry_migration(self):
  with tempfile.TemporaryDirectory() as d:
   path=d+'/old.db'
   with sqlite3.connect(path) as db:
    db.execute('CREATE TABLE devices(owner TEXT,device TEXT,pub BLOB,enabled INTEGER DEFAULT 1,PRIMARY KEY(owner,device))')
    db.execute('INSERT INTO devices(owner,device,pub) VALUES(?,?,?)',('legacy','old',bytes(32)))
   reg=Registry(path); reg.upgrade(); reg.upgrade()
   self.assertTrue(reg.enabled('legacy','old'))
   self.assertEqual(reg.list_users(),[{'owner':'legacy','enabled':True}])
   with sqlite3.connect(path) as db: self.assertIsNone(db.execute('SELECT xpub FROM devices').fetchone()[0])
 def test_admin_peer_and_directory(self):
  self.assertTrue(peer_allowed(struct.pack('3i',123,os.geteuid(),1),os.geteuid()))
  self.assertFalse(peer_allowed(struct.pack('3i',123,os.geteuid()+1,1),os.geteuid()))
  self.assertFalse(peer_allowed(b'invalid',os.geteuid()))
  with tempfile.TemporaryDirectory() as d:
   db=d+'/db'; Registry(db).initialize(); os.chmod(d,0o755)
   try:
    with self.assertRaises(ValueError): AdminServer(d+'/admin.sock',Registry(db))
   finally: os.chmod(d,0o700)
 def test_revocation_inside_operation_transaction(self):
  with tempfile.TemporaryDirectory() as d:
   r=Registry(d+'/db'); r.initialize(); r.provision('alice','device',bytes(32))
   self.assertTrue(r.execute('alice','before',b'x','device')['new'])
   r.revoke_device('alice','device')
   with self.assertRaises(Denied): r.execute('alice','after',b'x','device')
   with self.assertRaises(Denied): r.result('alice','before','device')
   with sqlite3.connect(d+'/db') as db: self.assertEqual(db.execute("SELECT count(*) FROM effects WHERE id='after'").fetchone()[0],0)
 def test_atomic_one_time_otp(self):
  with tempfile.TemporaryDirectory() as d:
   r=Registry(d+'/db'); r.initialize(); r.add_user('a'); otp=r.create_otp('a',300)
   def enroll(i):
    try: r.enroll('a','d'+str(i),bytes([i])*32,bytes([i+1])*32,otp); return True
    except Denied: return False
   with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: self.assertEqual(sorted(pool.map(enroll,[1,2],timeout=5)),[False,True])
   token=r.create_otp('a',30)
   with sqlite3.connect(d+'/db') as db: db.execute('UPDATE enrollment_otps SET expires=0 WHERE used=0')
   with self.assertRaises(Denied): r.enroll('a','expired',bytes(32),bytes(32),token)
if __name__=='__main__': unittest.main(verbosity=2)
