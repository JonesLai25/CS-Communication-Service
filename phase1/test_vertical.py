import base64, concurrent.futures, hashlib, pathlib, select, socket, sqlite3, ssl, subprocess, sys, tempfile, time, unittest, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from client import AuthenticatedClient, UnknownOutcome, TLSError, TLSOnlyHTTPConnection
from registry import Registry, Denied, Busy, Limited, message
P=pathlib.Path(__file__).resolve().parent

def pub(k): return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def b64(x): return base64.b64encode(x).decode()
class Vertical(unittest.TestCase):
 def test_vertical(self):
  with tempfile.TemporaryDirectory() as d:
   cert=d+'/cert.pem'; keyfile=d+'/key.pem'; path=d+'/db'; reg=Registry(path); reg.initialize(); alice=Ed25519PrivateKey.generate(); bob=Ed25519PrivateKey.generate(); wrong=Ed25519PrivateKey.generate(); reg.provision('alice','a',pub(alice)); reg.provision('bob','b',pub(bob))
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyfile,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],timeout=15,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   othercert=d+'/other.pem'; otherkey=d+'/other-key.pem'
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',otherkey,'-out',othercert,'-days','1','-subj','/CN=other'],timeout=15,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   proc=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',cert,'--key',keyfile,'--db',path],stdout=subprocess.PIPE,text=True)
   clients=[]
   try:
    if not select.select([proc.stdout],[],[],5)[0]: self.fail('startup timeout')
    port=int(proc.stdout.readline())
    def connect(owner,dev,key):
     c=AuthenticatedClient('localhost',port,cert,owner,dev,key); clients.append(c); return c
    with self.assertRaises(TLSError):
     AuthenticatedClient('localhost',port,othercert,'alice','a',alice)
    with self.assertRaises(TLSError):
     AuthenticatedClient('127.0.0.1',port,cert,'alice','a',alice)
    bad=connect('alice','a',alice); self.assertEqual(bad.call('POST','/v1/challenge',{'owner':'alice','device':'a','extra':1})[0],400); bad.close()
    a=connect('alice','a',alice); x=connect('alice','a',alice); b=connect('bob','b',bob)
    self.assertIsInstance(a.conn,TLSOnlyHTTPConnection)
    rid=str(uuid.uuid4()); self.assertEqual(a.call('POST','/v1/test',{'request_id':rid,'payload':'safe'})[0],403)
    status,ch=a.call('POST','/v1/challenge',{'owner':'alice','device':'a'}); self.assertEqual(status,200); challenge=base64.b64decode(ch['challenge']); chan=hashlib.sha256(a.conn.sock.exporter()).digest(); server=hashlib.sha256(a.conn.sock.getpeercert(binary_form=True)).digest(); msg=message(server,chan,challenge,'alice','a')
    def auth(c,owner,dev,sig): return c.call('POST','/v1/auth',{'owner':owner,'device':dev,'challenge':ch['challenge'],'signature':b64(sig)})[0]
    self.assertEqual(auth(a,'alice','a',wrong.sign(msg)),403)
    self.assertEqual(auth(x,'alice','a',alice.sign(msg)),403)
    self.assertEqual(auth(a,'bob','b',bob.sign(message(server,chan,challenge,'bob','b'))),403)
    self.assertEqual(auth(a,'alice','a',alice.sign(message(bytes(32),chan,challenge,'alice','a'))),403)
    self.assertEqual(auth(a,'alice','a',alice.sign(msg)),200)
    self.assertEqual(auth(a,'alice','a',alice.sign(msg)),403)
    self.assertEqual(a.call('POST','/v1/challenge',{'owner':'alice','device':'a'})[0],403)
    a.close(); a=connect('alice','a',alice); a.authenticate(); x.authenticate(); b.authenticate()
    # A session token captured from one TLS connection is unusable on another.
    # A bare token must not be accepted without the Bearer scheme.
    x.conn.request('GET','/v1/result?id='+rid,headers={'Authorization':a.token}); raw=x.conn.getresponse(); raw.read(); self.assertEqual(raw.status,403)
    saved=x.token; x.token=a.token; self.assertEqual(x.call('GET','/v1/result?id='+rid)[0],403); x.token=saved
    def submit(c): return c.call('POST','/v1/test',{'request_id':rid,'payload':'safe'})
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(submit,[a,x],timeout=8))
    self.assertEqual([v[0] for v in results],[200,200]); self.assertEqual(sorted(v[1]['new'] for v in results),[False,True])
    self.assertEqual(a.call('POST','/v1/test',{'request_id':rid,'payload':'changed'})[0],409)
    self.assertEqual(b.call('GET','/v1/result?id='+rid)[0],404)
    a.close(); renewed=connect('alice','a',alice); renewed.authenticate(); result=renewed.result(rid); self.assertEqual(result['state'],'succeeded')
    # Send a harmless request and deliberately close this test connection before reading.
    import json
    rid2=str(uuid.uuid4()); wire=json.dumps({'request_id':rid2,'payload':'disconnect'}).encode(); renewed.conn.request('POST','/v1/test',wire,{'Authorization':'Bearer '+renewed.token,'Content-Type':'application/json'}); renewed.close()
    renewed=connect('alice','a',alice); renewed.authenticate(); result=None
    for _ in range(20):
     result=renewed.result(rid2)
     if result is not None: break
     time.sleep(.05)
    self.assertIsNotNone(result); self.assertEqual(result['state'],'succeeded')
    with sqlite3.connect(path) as db: self.assertEqual(db.execute('SELECT count(*) FROM effects WHERE id=?',(rid,)).fetchone()[0],1)
    with sqlite3.connect(path) as db: db.execute("UPDATE devices SET enabled=0 WHERE owner='alice' AND device='a'")
    self.assertEqual(renewed.call('GET','/v1/result?id='+rid)[0],403)
   finally:
    for c in clients: c.close()
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close()
 def test_ip_san(self):
  with tempfile.TemporaryDirectory() as d:
   cert=d+'/cert.pem'; keyfile=d+'/key.pem'; path=d+'/db'; Registry(path).initialize()
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyfile,'-out',cert,'-days','1','-subj','/CN=example','-addext','subjectAltName=IP:127.0.0.1'],timeout=15,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   proc=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',cert,'--key',keyfile,'--db',path],stdout=subprocess.PIPE,text=True)
   try:
    if not select.select([proc.stdout],[],[],5)[0]: self.fail('startup timeout')
    port=int(proc.stdout.readline()); c=AuthenticatedClient('127.0.0.1',port,cert,'u','d',Ed25519PrivateKey.generate()); c.close()
   finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close()
 def test_duplicate_json(self):
  import json
  from server import unique_object
  with self.assertRaises(ValueError): json.loads('{\"owner\":\"a\",\"owner\":\"b\"}',object_pairs_hook=unique_object)
 def test_unknown_does_not_retry(self):
  class Broken:
   calls=0
   def request(self,*args,**kw): self.calls+=1; raise ConnectionResetError('simulated')
   def close(self): pass
  c=AuthenticatedClient.__new__(AuthenticatedClient); c.conn=Broken(); c.token='test'; rid=str(uuid.uuid4())
  with self.assertRaises(UnknownOutcome): c.submit(rid,'safe')
  self.assertEqual(c.conn.calls,1)
 def test_registry_contention(self):
  with tempfile.TemporaryDirectory() as d:
   path=d+'/db'; reg=Registry(path); reg.initialize(); key=Ed25519PrivateKey.generate(); reg.provision('u','d',pub(key)); channel=b'c'*32; server=b's'*32; ch=reg.issue('u','d',channel); sig=key.sign(message(server,channel,ch,'u','d'))
   def consume(_):
    try: reg.authenticate('u','d',channel,ch,server,sig); return True
    except Denied: return False
   with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: self.assertEqual(sorted(pool.map(consume,range(2),timeout=5)),[False,True])
   with sqlite3.connect(path,isolation_level=None) as db:
    db.execute('BEGIN IMMEDIATE')
    with self.assertRaises(Busy): reg.execute('u','locked',b'payload','d')
    db.execute('ROLLBACK')
   self.assertTrue(reg.execute('u','locked',b'payload','d')['new'])
   with sqlite3.connect(path) as db: db.execute('UPDATE challenges SET expires=0')
   expired=reg.issue('u','d',channel)
   with sqlite3.connect(path) as db:
    self.assertEqual(db.execute('SELECT count(*) FROM challenges WHERE id=?',(ch,)).fetchone()[0],0)
    db.execute('UPDATE challenges SET expires=0 WHERE id=?',(expired,))
   with self.assertRaises(Denied): reg.authenticate('u','d',channel,expired,server,key.sign(message(server,channel,expired,'u','d')))
   # Forged challenges on other TLS channels cannot consume a device quota.
   for i in range(20):
    other=i.to_bytes(32,'big'); reg.issue('u','d',other); reg.release(other)
   token=reg.issue('u','d',channel); reg.authenticate('u','d',channel,token,server,key.sign(message(server,channel,token,'u','d')))
   with sqlite3.connect(path) as db: db.execute('UPDATE devices SET enabled=0')
   with self.assertRaises(Denied): reg.issue('u','d',channel)
   with sqlite3.connect(path) as db:
    events=db.execute('SELECT event FROM audit').fetchall()
    self.assertIn(('authentication_succeeded',),events)
    self.assertNotIn(ch.hex(),str(events))
if __name__=='__main__': unittest.main(verbosity=2)
