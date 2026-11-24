"""TLS-bound Phase 2 enrollment proof; uses standard Ed25519, X25519, HKDF and HMAC."""
import hashlib, hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def raw_public(key): return key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def transcript(server,channel,nonce,owner,device,edpub,xpub,epub,otp):
 fields=(b'cs/1',b'enrollment',server,channel,nonce,owner.encode(),device.encode(),edpub,xpub,epub,hashlib.sha256(otp.encode('ascii')).digest())
 return b'CS-ENROLL-v1\x00'+b''.join(len(x).to_bytes(4,'big')+x for x in fields)
def proof(shared,nonce,message):
 key=HKDF(algorithm=hashes.SHA256(),length=32,salt=nonce,info=b'CS-X25519-POP-v1'+hashlib.sha256(message).digest()).derive(shared)
 return hmac.new(key,message,hashlib.sha256).digest()
def verify(edpub,xpub,ephemeral,nonce,message,signature,mac):
 try:
  Ed25519PublicKey.from_public_bytes(edpub).verify(signature,message)
  shared=ephemeral.exchange(X25519PublicKey.from_public_bytes(xpub))
  return hmac.compare_digest(proof(shared,nonce,message),mac)
 except (InvalidSignature,ValueError): return False
