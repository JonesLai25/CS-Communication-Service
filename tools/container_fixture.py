"""Create disposable test-only keys, TLS certificate and registry in a provided empty directory."""
import os, pathlib, subprocess, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
project=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(project/'phase1'))
from registry import Registry
root=pathlib.Path(sys.argv[1]); server=root/'server'; client=root/'client'
server.mkdir(mode=0o700); client.mkdir(mode=0o700)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(server/'key.pem'),'-out',str(server/'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
(client/'cert.pem').write_bytes((server/'cert.pem').read_bytes())
key=Ed25519PrivateKey.generate(); raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()); fd=os.open(client/'key.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f: f.write(raw)
pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); reg=Registry(str(server/'registry.db')); reg.initialize(); reg.provision('alice','local-test',pub)
