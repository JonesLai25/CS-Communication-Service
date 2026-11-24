"""Linux enrollment CLI; private keys are persisted before network enrollment."""
import argparse,getpass,os,pathlib,stat,sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from client import AuthenticatedClient, AuthorizationError
p=argparse.ArgumentParser(); p.add_argument('--host',default='localhost'); p.add_argument('--port',required=True,type=int); p.add_argument('--ca',required=True); p.add_argument('--owner',required=True); p.add_argument('--device',required=True); p.add_argument('--credential-dir',required=True); p.add_argument('--resume',action='store_true'); a=p.parse_args()
d=pathlib.Path(a.credential_dir)
if not a.resume: d.mkdir(mode=0o700)
st=os.lstat(d)
if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or os.path.realpath(str(d))!=os.path.abspath(str(d)): raise SystemExit('unsafe credential directory')
def load_or_create(filename,kind):
 path=d/filename
 if a.resume:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: os.close(fd); raise SystemExit('unsafe key file')
  with os.fdopen(fd,'rb') as f: raw=f.read(33)
  if len(raw)!=32: raise SystemExit('invalid key file')
  return kind.from_private_bytes(raw)
 key=kind.generate(); raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
 return key
ed=load_or_create('ed25519.key',Ed25519PrivateKey); x=load_or_create('x25519.key',X25519PrivateKey)
fd=os.open(str(d),os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
if a.resume:
 c=AuthenticatedClient(a.host,a.port,a.ca,a.owner,a.device,ed)
 try:
  try: c.authenticate()
  except AuthorizationError: pass
  else: print('Device is already registered'); sys.exit(0)
 finally: c.close()
otp=getpass.getpass('Enrollment OTP: ')
c=AuthenticatedClient(a.host,a.port,a.ca,a.owner,a.device,ed)
try: c.enroll(otp,x); print('Enrollment complete')
finally: c.close()
