"""Add only disposable Phase 3 resources to the existing isolated fixture."""
import os,pathlib,sqlite3,sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
root=pathlib.Path(sys.argv[1]); server=root/'server'; client=root/'client'
x=X25519PrivateKey.generate(); pub=x.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); raw=x.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
fd=os.open(client/'xkey.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f: f.write(raw)
with sqlite3.connect(server/'registry.db') as db: db.execute("UPDATE devices SET xpub=? WHERE owner='alice' AND device='local-test'",(pub,))
fd=os.open(server/'master.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f: f.write(os.urandom(32))
for path in (server/'received',server/'packages',client/'source',client/'dest'): path.mkdir(mode=0o700)
(client/'source'/'sample.bin').write_bytes(os.urandom(256*1024))
