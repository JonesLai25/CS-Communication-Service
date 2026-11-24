import concurrent.futures, email.message, http.client, json, pathlib, select, socket, sqlite3, ssl, subprocess, sys, tempfile, time, unittest, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from client import AuthenticatedClient, ProtocolError, UnknownOutcome, TLSOnlyHTTPConnection, NetworkError, TLSError
from registry import Registry, Busy, StorageError, Limited
P=pathlib.Path(__file__).resolve().parent
class Fixture(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); d=self.tmp.name; self.cert=d+'/cert'; keyfile=d+'/key'; self.path=d+'/db'; self.reg=Registry(self.path); self.reg.initialize(); self.key=Ed25519PrivateKey.generate(); pub=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); self.reg.provision('alice','a',pub)
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyfile,'-out',self.cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  self.proc=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',self.cert,'--key',keyfile,'--db',self.path],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
  if not select.select([self.proc.stdout],[],[],5)[0]: self.tearDown(); self.fail('server startup timeout')
  self.port=int(self.proc.stdout.readline())
 def tearDown(self):
  if hasattr(self,'proc'):
   self.proc.terminate()
   try: self.proc.wait(timeout=5)
   except subprocess.TimeoutExpired: self.proc.kill(); self.proc.wait(timeout=5)
   self.proc.stdout.close()
  self.tmp.cleanup()
 def conn(self): return AuthenticatedClient('localhost',self.port,self.cert,'alice','a',self.key)
 def test_session_reclaimed_and_forged_challenges(self):
  pending=[]
  try:
   for _ in range(12):
    c=self.conn(); pending.append(c); self.assertEqual(c.call('POST','/v1/challenge',{'owner':'alice','device':'a'})[0],200)
   legitimate=self.conn()
   try: legitimate.authenticate()
   finally: legitimate.close()
  finally:
   for c in pending: c.close()
  deadline=time.monotonic()+6
  while True:
   with sqlite3.connect(self.path) as db: count=db.execute('SELECT count(*) FROM challenges').fetchone()[0]
   if count==0 or time.monotonic()>=deadline: break
   time.sleep(.02)
  self.assertEqual(count,0)
  for _ in range(135):
   c=self.conn()
   try: c.authenticate()
   finally: c.close()
 def test_bad_signatures_bounded_per_connection(self):
  import base64
  c=self.conn()
  try:
   status,data=c.call('POST','/v1/challenge',{'owner':'alice','device':'a'}); self.assertEqual(status,200)
   for _ in range(4):
    status,_=c.call('POST','/v1/auth',{'owner':'alice','device':'a','challenge':data['challenge'],'signature':base64.b64encode(bytes(64)).decode()})
    self.assertEqual(status,403)
   with self.assertRaises((NetworkError,TLSError)):
    c.call('POST','/v1/challenge',{'owner':'alice','device':'a'})
  finally: c.close()
  fresh=self.conn()
  try: fresh.authenticate()
  finally: fresh.close()
 def test_http_ambiguous_boundaries(self):
  requests=[b'GET /v1/health HTTP/1.1\r\nHost: localhost\r\nHost: evil\r\n\r\n',b'GET /v1/health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx',b'POST /v1/challenge HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}',b'POST /v1/challenge HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}',b'GET /v1/result?id=x HTTP/1.1\r\nHost: localhost\r\nAuthorization: x\r\nAuthorization: y\r\n\r\n',b'POST /v1/challenge HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n{}',b'GET /v1/health HTTP/1.1\r\nHost: localhost\r\nX-Big: '+b'a'*17000+b'\r\n\r\n']
  ctx=ssl.create_default_context(cafile=self.cert)
  for req in requests:
   with self.subTest(req=req):
    with ctx.wrap_socket(socket.create_connection(('127.0.0.1',self.port),timeout=3),server_hostname='localhost') as s:
     s.settimeout(3); s.sendall(req); data=s.recv(4096); self.assertTrue(data.startswith((b'HTTP/1.1 400 ',b'HTTP/1.1 417 ',b'HTTP/1.1 431 ')),data[:100])
 def test_parallel_authenticated_clients(self):
  def run(_):
   c=self.conn()
   try:
    c.authenticate(); rid=str(uuid.uuid4()); result=c.submit(rid,'parallel'); return rid,result['state']
   finally: c.close()
  with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(run,range(8),timeout=15))
  self.assertEqual(len({x[0] for x in results}),8)
  self.assertTrue(all(state=='succeeded' for _,state in results))
 def test_global_challenge_cap(self):
  for i in range(256): self.reg.issue('alice','a',i.to_bytes(32,'big'))
  with self.assertRaises(Limited): self.reg.issue('alice','a',(256).to_bytes(32,'big'))
  self.reg.release((1).to_bytes(32,'big'))
  self.assertEqual(len(self.reg.issue('alice','a',(256).to_bytes(32,'big'))),32)
 def test_storage_classification(self):
  with self.assertRaises(Busy): self.reg.read(lambda db: (_ for _ in ()).throw(sqlite3.OperationalError('database is locked')))
  c=self.conn(); c.authenticate()
  with sqlite3.connect(self.path) as db: db.execute('DROP TABLE requests')
  self.assertEqual(c.call('GET','/v1/result?id='+str(uuid.uuid4()))[0],503)
  self.assertEqual(c.call('POST','/v1/test',{'request_id':str(uuid.uuid4()),'payload':'x'})[0],503)
  c.close()
  with self.assertRaises(StorageError): self.reg.result('alice','x','a')
  with self.assertRaises(StorageError): self.reg.execute('alice','x',b'test','a')

class Responses(unittest.TestCase):
 class FakeResponse:
  def __init__(self,headers,body,status=200):
   self.headers=email.message.Message()
   for k,v in headers: self.headers.add_header(k,v)
   self.body=body; self.status=status
  def read(self,n): return self.body[:n]
 class FakeConnection:
  def __init__(self,response): self.response=response; self.closed=False
  def request(self,*a,**kw): pass
  def getresponse(self): return self.response
  def close(self): self.closed=True
 def make(self,headers,body):
  c=AuthenticatedClient.__new__(AuthenticatedClient); c.conn=self.FakeConnection(self.FakeResponse(headers,body)); c.token='token'; return c
 def test_bad_headers_and_duplicate_json(self):
  for headers,body in [([('Content-Length','2'),('Content-Length','2'),('Content-Type','application/json')],b'{}'),([('Content-Length','2'),('Content-Type','text/plain')],b'{}'),([('Content-Length','2'),('Content-Type','application/json'),('Transfer-Encoding','chunked')],b'{}'),([('Content-Length','20'),('Content-Type','application/json')],b'{}'),([('Content-Length','13'),('Content-Type','application/json')],b'{"a":1,"a":2}')]:
   with self.subTest(headers=headers,body=body):
    c=self.make(headers,body)
    with self.assertRaises(ProtocolError): c.call('GET','/v1/result?id=x')
    self.assertTrue(c.conn.closed)
 def test_no_plaintext_reconnect(self):
  from unittest.mock import patch
  c=AuthenticatedClient.__new__(AuthenticatedClient); c.conn=TLSOnlyHTTPConnection('localhost',12345); c.token='fake'
  with patch.object(c.conn,'_create_connection',side_effect=AssertionError('plaintext socket attempted')):
   with self.assertRaises(UnknownOutcome): c.submit(str(uuid.uuid4()),'x')
 def test_http_parser_error_classification(self):
  c=self.make([('Content-Length','2'),('Content-Type','application/json')],b'{}')
  def fail(): raise http.client.BadStatusLine('bad')
  c.conn.getresponse=fail
  with self.assertRaises(ProtocolError): c.call('GET','/v1/result?id=x')
  self.assertTrue(c.conn.closed)
 def test_malformed_404_is_not_absence(self):
  c=self.make([('Content-Length','2'),('Content-Type','application/json')],b'{}'); c.conn.response.status=404
  with self.assertRaises(ProtocolError): c.result(str(uuid.uuid4()))
 def test_ambiguous_response_is_unknown_for_mutation(self):
  c=self.make([('Content-Length','2'),('Content-Type','text/plain')],b'{}')
  with self.assertRaises(UnknownOutcome): c.submit(str(uuid.uuid4()),'x')
if __name__=='__main__': unittest.main(verbosity=2)
