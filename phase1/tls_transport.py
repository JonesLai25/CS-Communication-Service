"""Bounded pyOpenSSL transport with RFC 9266 TLS exporter (TLS 1.3 only)."""
import io, ipaddress, select, socket, time
from OpenSSL import SSL, crypto
from service_identity import pyopenssl as service_identity
from service_identity.exceptions import VerificationError, CertificateError

class TLSFailure(OSError): pass
class Reader(io.RawIOBase):
 def __init__(self,transport): self.transport=transport
 def readable(self): return True
 def readinto(self,b):
  data=self.transport.recv(len(b)); b[:len(data)]=data; return len(data)
class Transport:
 def __init__(self,conn,raw,timeout=3): self.conn=conn; self.raw=raw; self.timeout=timeout
 def _call(self,fn,*args):
  deadline=time.monotonic()+self.timeout
  while True:
   try: return fn(*args)
   except (SSL.WantReadError,SSL.WantWriteError) as e:
    remain=deadline-time.monotonic()
    if remain<=0: raise TimeoutError('TLS I/O deadline') from e
    ready=select.select([self.raw] if isinstance(e,SSL.WantReadError) else [],[self.raw] if isinstance(e,SSL.WantWriteError) else [],[],remain)
    if not ready[0] and not ready[1]: raise TimeoutError('TLS I/O deadline') from e
   except SSL.ZeroReturnError: return b''
   except SSL.Error as e: raise TLSFailure('TLS operation failed') from e
 def handshake(self): self._call(self.conn.do_handshake)
 def recv(self,n): return self._call(self.conn.recv,n)
 def sendall(self,data):
  view=memoryview(data)
  while view:
   sent=self._call(self.conn.send,bytes(view))
   if not isinstance(sent,int) or sent<=0: raise TLSFailure('TLS write failed')
   view=view[sent:]
 def makefile(self,mode,buffering=None):
  if mode!='rb': raise ValueError('unsupported mode')
  return io.BufferedReader(Reader(self))
 def exporter(self): return self.conn.export_keying_material(b'EXPORTER-Channel-Binding',32,b'')
 def getpeercert(self,binary_form=False):
  cert=self.conn.get_peer_certificate()
  if binary_form: return crypto.dump_certificate(crypto.FILETYPE_ASN1,cert)
  raise ValueError('only DER supported')
 def shutdown(self,how): self.raw.shutdown(how)
 def close(self): self.conn.close()

def server_context(cert,key):
 ctx=SSL.Context(SSL.TLS_SERVER_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION); ctx.use_certificate_file(cert); ctx.use_privatekey_file(key); ctx.check_privatekey(); return ctx

def server_wrap(ctx,raw):
 raw.setblocking(False); conn=SSL.Connection(ctx,raw); conn.set_accept_state(); return Transport(conn,raw)

def client_wrap(raw,host,ca):
 ctx=SSL.Context(SSL.TLS_CLIENT_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION); ctx.load_verify_locations(ca); ctx.set_verify(SSL.VERIFY_PEER,lambda connection,cert,err,depth,ok: ok)
 raw.setblocking(False); conn=SSL.Connection(ctx,raw); conn.set_connect_state(); conn.set_tlsext_host_name(host.encode('idna')); wrapped=Transport(conn,raw,5)
 try:
  wrapped.handshake()
  try:
   try: ipaddress.ip_address(host)
   except ValueError: service_identity.verify_hostname(conn,host)
   else: service_identity.verify_ip_address(conn,host)
  except (VerificationError,CertificateError) as e: raise TLSFailure('certificate hostname mismatch') from e
  return wrapped
 except BaseException:
  wrapped.close(); raise
