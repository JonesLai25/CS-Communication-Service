"""Client on private network node A through two TCP proxies."""
import pathlib,sys,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root=pathlib.Path(sys.argv[1]); sys.path.insert(0,str(root/'phase1'))
from client import AuthenticatedClient, AuthorizationError, ProtocolError, TLSError
try: (root/'server/key.pem').read_bytes()
except PermissionError: pass
else: raise RuntimeError('server private key accessible to client node')
key=Ed25519PrivateKey.from_private_bytes((root/'client/key.bin').read_bytes()); rid=str(uuid.uuid4())
def conn(private=key,owner='alice'): return AuthenticatedClient('localhost',18443,str(root/'client/cert.pem'),owner,'local-test',private)
try: AuthenticatedClient('127.0.0.1',18443,str(root/'client/cert.pem'),'alice','local-test',key)
except TLSError: pass
else: raise RuntimeError('wrong TLS hostname accepted')
a=conn()
try:
 if a.call('GET','/v1/result?id='+rid)[0]!=403: raise RuntimeError('unauthenticated accepted')
 a.authenticate(); result=a.submit(rid,'two-hop-proxy')
 if not result['new']: raise RuntimeError('new request not granted')
finally: a.close()
wrong=conn(Ed25519PrivateKey.generate())
try:
 try: wrong.authenticate()
 except AuthorizationError: pass
 else: raise RuntimeError('wrong key accepted')
finally: wrong.close()
b=conn()
try:
 b.authenticate()
 if b.result(rid)['state']!='succeeded': raise RuntimeError('reconnect query failed')
 if b.submit(rid,'two-hop-proxy')['new']: raise RuntimeError('duplicate granted')
 try: b.submit(rid,'changed')
 except ProtocolError: pass
 else: raise RuntimeError('conflicting request accepted')
finally: b.close()
print('two network namespaces, veth, two TCP proxies, TLS authentication and reconnect: PASS')
