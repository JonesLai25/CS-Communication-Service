"""Experimental HPKE checks, not product code."""
if not __debug__: raise RuntimeError('security checks require Python without -O')
import json, os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from pyhpke import CipherSuite, KEMId, KDFId, AEADId, OpenError
v=json.loads((Path(__file__).parent/'hpke_vectors.json').read_text())
b=lambda s: bytes.fromhex(s)
s=CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256,KDFId.HKDF_SHA256,AEADId.AES256_GCM)
r=s.kem.derive_key_pair(b(v['ikmR'])); e=s.kem.derive_key_pair(b(v['ikmE']))
enc, sender=s.create_sender_context(r.public_key,b(v['info']),eks=e)
assert enc==b(v['enc'])
receiver=s.create_recipient_context(enc,r.private_key,b(v['info']))
for x in v['encryptions']:
    ct=sender.seal(b(x['pt']),b(x['aad'])); assert ct==b(x['ct']); assert receiver.open(ct,b(x['aad']))==b(x['pt'])
print('RFC 9180 X25519/AES-256-GCM vector: %d ciphertexts PASS'%len(v['encryptions']))
r=s.kem.derive_key_pair(os.urandom(32)); wrong=s.kem.derive_key_pair(os.urandom(32)); otp=os.urandom(32); info=b'cs-prototype'; aad=b'transfer-test'
enc,ctx=s.create_sender_context(r.public_key,info); ct=ctx.seal(otp,aad)
assert s.create_recipient_context(enc,r.private_key,info).open(ct,aad)==otp

def require_auth_failure(fn):
    try: fn()
    except OpenError as e:
        if not isinstance(e.__cause__,InvalidTag): raise
        return
    raise AssertionError('expected AEAD authentication failure')
for key,assoc in [(r.private_key,b'wrong-aad'),(wrong.private_key,aad),(r.private_key,b'wrong-transfer-id')]:
    require_auth_failure(lambda: s.create_recipient_context(enc,key,info).open(ct,assoc))
# HPKE itself does not prevent replay across new contexts; this is only a local application-ledger demonstration.
seen=set()
def consume(token):
    if token in seen: raise ValueError('replay')
    value=s.create_recipient_context(enc,r.private_key,info).open(ct,aad); seen.add(token); return value
assert consume(b'transfer-test')==otp
try: consume(b'transfer-test')
except ValueError: pass
else: raise AssertionError('replay accepted')
def wrapped_bug():
    try: raise RuntimeError('unexpected')
    except RuntimeError as e: raise OpenError('wrapped bug') from e
try: require_auth_failure(wrapped_bug)
except OpenError as e:
    if not isinstance(e.__cause__, RuntimeError): raise
else: raise AssertionError('unexpected exception classified as authentication failure')
print('OTP, wrong key/AAD/transfer ID, replay ledger and unexpected exception negative control: PASS')
