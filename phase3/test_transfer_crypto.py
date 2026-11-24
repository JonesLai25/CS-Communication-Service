"""HPKE interoperability and contextual authorization checks, isolated local files."""
import hashlib, json, os, pathlib, sys, tempfile, unittest, uuid
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'phase1'))
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyhpke import OpenError
from registry import Registry, Denied
from transfer_crypto import SUITE, seal, open_envelope

class TransferCrypto(unittest.TestCase):
 def test_rfc9180_vector(self):
  v=json.loads((pathlib.Path(__file__).resolve().parents[1]/'prototypes/hpke_vectors.json').read_text())
  b=bytes.fromhex
  r=SUITE.kem.derive_key_pair(b(v['ikmR'])); e=SUITE.kem.derive_key_pair(b(v['ikmE']))
  enc,sender=SUITE.create_sender_context(r.public_key,b(v['info']),eks=e)
  self.assertEqual(enc,b(v['enc']))
  receiver=SUITE.create_recipient_context(enc,r.private_key,b(v['info']))
  for case in v['encryptions']:
   ct=sender.seal(b(case['pt']),b(case['aad'])); self.assertEqual(ct,b(case['ct'])); self.assertEqual(receiver.open(ct,b(case['aad'])),b(case['pt']))
 def test_context_and_rejection(self):
  sk=X25519PrivateKey.generate(); wrong=X25519PrivateKey.generate(); pk=sk.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
  otp=os.urandom(32); server=os.urandom(32); tid=str(uuid.uuid4()); context=(server,'alice','laptop',tid,'upload')
  enc,ct=seal(otp,pk,*context); self.assertEqual(open_envelope(enc,ct,sk,*context),otp)
  contexts=[(os.urandom(32),'alice','laptop',tid,'upload'),(server,'bob','laptop',tid,'upload'),(server,'alice','other',tid,'upload'),(server,'alice','laptop',str(uuid.uuid4()),'upload'),(server,'alice','laptop',tid,'download',str(uuid.uuid4()))]
  for ctx in contexts:
   with self.subTest(context=ctx):
    with self.assertRaises(OpenError) as cm: open_envelope(enc,ct,sk,*ctx)
    self.assertIsInstance(cm.exception.__cause__,InvalidTag)
  with self.assertRaises(OpenError) as cm: open_envelope(enc,ct,wrong,*context)
  self.assertIsInstance(cm.exception.__cause__,InvalidTag)
  bad=ct[:-1]+bytes([ct[-1]^1])
  with self.assertRaises(OpenError) as cm: open_envelope(enc,bad,sk,*context)
  self.assertIsInstance(cm.exception.__cause__,InvalidTag)
  with self.assertRaises(ValueError): seal(b'short',pk,*context)
 def test_registered_device_authorization(self):
  with tempfile.TemporaryDirectory() as d:
   r=Registry(d+'/registry'); r.initialize(); r.provision('alice','legacy',bytes(32))
   with self.assertRaises(Denied): r.transfer_recipient('alice','legacy')
   token=r.create_otp('alice',300); key=X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   r.enroll('alice','new',bytes(32),key,token); self.assertEqual(r.transfer_recipient('alice','new'),key)
   with self.assertRaises(Denied): r.transfer_recipient('bob','new')
   r.revoke_device('alice','new')
   with self.assertRaises(Denied): r.transfer_recipient('alice','new')

if __name__ == '__main__': unittest.main(verbosity=2)
