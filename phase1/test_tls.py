import pathlib, select, socket, ssl, subprocess, sys, tempfile, time, unittest
from registry import Registry
from client import health, validate_response, TLSError, ProtocolError, AuthorizationError, RemoteOperationError, NetworkError
P=pathlib.Path(__file__).resolve().parent
class TLS(unittest.TestCase):
 def test_real_process_tls(self):
  with tempfile.TemporaryDirectory() as d:
   cert=d+'/cert.pem'; key=d+'/key.pem'; db=d+'/registry.db'; Registry(db).initialize()
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   p=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',cert,'--key',key,'--db',db],stdout=subprocess.PIPE,text=True)
   try:
    if not select.select([p.stdout],[],[],5)[0]: self.fail('server startup timeout')
    port=int(p.stdout.readline()); self.assertEqual(health('localhost',port,cert)['status'],'ok')
    for host,ca in [('localhost',None),('127.0.0.1',cert)]:
     with self.assertRaises(TLSError): health(host,port,ca)
    old=ssl.create_default_context(cafile=cert); old.maximum_version=ssl.TLSVersion.TLSv1_2
    with self.assertRaises(ssl.SSLError):
     with socket.create_connection(('127.0.0.1',port),timeout=3) as sock: old.wrap_socket(sock,server_hostname='localhost')
    raw=socket.create_connection(('127.0.0.1',port),timeout=3)
    ctx=ssl.create_default_context(cafile=cert); slow=ctx.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname='localhost')
    try:
     slow.sendall(b'GET /v1/health HTTP/1.1\r\nHost: localhost\r\nX-Partial:')
     self.assertEqual(health('localhost',port,cert)['status'],'ok')
     time.sleep(3.5)
     self.assertEqual(raw.recv(1),b'')
    finally: slow.close(); raw.close()
    stalled=[socket.create_connection(('127.0.0.1',port),timeout=3) for _ in range(16)]
    try:
     time.sleep(0.2)
     with self.assertRaises((TLSError, NetworkError)): health('localhost',port,cert)
     time.sleep(3.3)
     self.assertEqual(health('localhost',port,cert)['status'],'ok')
    finally:
     for item in stalled: item.close()
   finally:
    p.terminate()
    try: p.wait(timeout=5)
    except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
    p.stdout.close()
 def test_response_schema(self):
  body=b'{"request_id":"id","status":"ok","protocol":"cs/1"}'
  self.assertEqual(validate_response(200,'application/json',body,'id')['status'],'ok')
  for status,typ,data,exc in [(200,'application/json',body+b' '*4096,ProtocolError),(200,'application/json',b'{}',ProtocolError),(403,'application/json',b'{}',AuthorizationError),(500,'application/json',b'{}',RemoteOperationError)]:
   with self.assertRaises(exc): validate_response(status,typ,data,'id')
if __name__=='__main__': unittest.main(verbosity=2)
