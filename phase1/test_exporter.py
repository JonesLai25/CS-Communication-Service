"""Feasibility check only: RFC 9266 exporter over a real TLS 1.3 socketpair."""
import concurrent.futures, select, socket, subprocess, tempfile, time, unittest
from OpenSSL import SSL

def handshake(conn):
 deadline=time.monotonic()+5
 while True:
  try: conn.do_handshake(); return
  except (SSL.WantReadError,SSL.WantWriteError) as error:
   left=deadline-time.monotonic()
   if left<=0: raise TimeoutError('TLS handshake')
   r=[conn] if isinstance(error,SSL.WantReadError) else []; w=[conn] if isinstance(error,SSL.WantWriteError) else []
   if not any(select.select(r,w,[],left)[:2]): raise TimeoutError('TLS handshake')
class Exporter(unittest.TestCase):
 def test_exporter(self):
  with tempfile.TemporaryDirectory() as d:
   cert=d+'/cert.pem'; key=d+'/key.pem'
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   server=SSL.Context(SSL.TLS_SERVER_METHOD); server.set_min_proto_version(SSL.TLS1_3_VERSION); server.use_certificate_file(cert); server.use_privatekey_file(key)
   client=SSL.Context(SSL.TLS_CLIENT_METHOD); client.set_min_proto_version(SSL.TLS1_3_VERSION); client.load_verify_locations(cert); client.set_verify(SSL.VERIFY_PEER,lambda connection,certificate,errno,depth,ok: ok)
   a,b=socket.socketpair(); a.setblocking(False); b.setblocking(False); s=SSL.Connection(server,a); c=SSL.Connection(client,b); s.set_accept_state(); c.set_connect_state(); c.set_tlsext_host_name(b'localhost')
   try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
     f1=pool.submit(handshake,s); f2=pool.submit(handshake,c); f1.result(timeout=7); f2.result(timeout=7)
    self.assertEqual(c.get_protocol_version_name(),'TLSv1.3')
    self.assertEqual(s.export_keying_material(b'EXPORTER-Channel-Binding',32,b''),c.export_keying_material(b'EXPORTER-Channel-Binding',32,b''))
    self.assertNotEqual(s.export_keying_material(b'EXPORTER-Channel-Binding',32,b''),s.export_keying_material(b'other-label',32,b''))
   finally: s.close(); c.close()
if __name__=='__main__': unittest.main(verbosity=2)
