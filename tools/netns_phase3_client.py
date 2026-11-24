"""Authenticated encrypted transfer across two private nodes and TCP proxies."""
import hashlib,pathlib,sys,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
root=pathlib.Path(sys.argv[1]); sys.path.insert(0,str(root/'phase1'))
from client import AuthenticatedClient
from transfer_client import authorize,upload_tree,download_tree
try: (root/'server/master.bin').read_bytes()
except PermissionError: pass
else: raise RuntimeError('server master key accessible to client node')
ed=Ed25519PrivateKey.from_private_bytes((root/'client/key.bin').read_bytes()); x=X25519PrivateKey.from_private_bytes((root/'client/xkey.bin').read_bytes())
def connect():
 c=AuthenticatedClient('localhost',18443,str(root/'client/cert.pem'),'alice','local-test',ed); c.authenticate(); return c
c=connect()
try:
 up=authorize(c,x,str(uuid.uuid4()),'upload'); upload_tree(c,up,str(root/'client/source'),str(root/'client'))
finally: c.close()
c=connect()
try:
 package=c.package_create(up.transfer_id,str(uuid.uuid4())); down=authorize(c,x,str(uuid.uuid4()),'download',package['package_id']); download_tree(c,down,str(root/'client/dest'),str(root/'client'))
finally: c.close()
a=(root/'client/source/sample.bin').read_bytes(); b=(root/'client/dest'/down.transfer_id/'sample.bin').read_bytes()
if hashlib.sha256(a).digest()!=hashlib.sha256(b).digest(): raise RuntimeError('end-to-end digest mismatch')
print('two private network namespaces, two proxies, TLS encrypted upload/download and digest: PASS')
