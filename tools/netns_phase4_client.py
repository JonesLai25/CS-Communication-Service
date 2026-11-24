"""Resume encrypted transfers through two private network namespaces and proxies."""
import hashlib,pathlib,sys,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
root=pathlib.Path(sys.argv[1]); sys.path.insert(0,str(root/'phase1'))
from client import AuthenticatedClient,NetworkError
from transfer_client import authorize
from resume_client import prepare_upload,upload
from resume_download_client import download
try: (root/'server/master.bin').read_bytes()
except PermissionError: pass
else: raise RuntimeError('server master key accessible to client node')
ed=Ed25519PrivateKey.from_private_bytes((root/'client/key.bin').read_bytes()); x=X25519PrivateKey.from_private_bytes((root/'client/xkey.bin').read_bytes())
def connect():
 c=AuthenticatedClient('localhost',18443,str(root/'client/cert.pem'),'alice','local-test',ed); c.authenticate(); return c
c=connect()
try: up=authorize(c,x,str(uuid.uuid4()),'upload')
finally: c.close()
prepare_upload(up,str(root/'client/source'),str(root/'client/up-work'))
seen=[False]
def interrupted():
 c=connect(); old=c.resume_chunk
 def chunk(*args):
  if not seen[0]: seen[0]=True; old(*args); raise NetworkError('simulated lost response')
  return old(*args)
 c.resume_chunk=chunk; return c
upload(interrupted,up,str(root/'client/up-work'))
if not seen[0]: raise RuntimeError('fault injection did not run')
c=connect()
try:
 package=c.package_create(up.transfer_id,str(uuid.uuid4())); down=authorize(c,x,str(uuid.uuid4()),'download',package['package_id'])
finally: c.close()
download(connect,down,str(root/'client/down-work'),str(root/'client/dest'))
a=(root/'client/source/sample.bin').read_bytes(); b=(root/'client/dest'/down.transfer_id/'sample.bin').read_bytes()
if hashlib.sha256(a).digest()!=hashlib.sha256(b).digest(): raise RuntimeError('end-to-end digest mismatch')
print('two isolated network namespaces, two proxies, interrupted resumable encrypted upload/download: PASS')
