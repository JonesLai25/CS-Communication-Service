import pathlib, tempfile, unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from legacy_auth_store import Store, AuthError, Conflict
class Checks(unittest.TestCase):
 def test_auth_and_persistence(self):
  with tempfile.TemporaryDirectory() as d:
   path=str(pathlib.Path(d)/'db'); s=Store(path); key=Ed25519PrivateKey.generate(); wrong=Ed25519PrivateKey.generate(); pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); s.provision('alice','device',pub)
   nonce=s.challenge('alice','device'); msg=s.message('alice','device',nonce)
   with self.assertRaises(AuthError): s.authenticate('alice','device',nonce,wrong.sign(msg))
   s.authenticate('alice','device',nonce,key.sign(msg))
   with self.assertRaises(AuthError): s.authenticate('alice','device',nonce,key.sign(msg))
   self.assertEqual(s.request('alice','one',b'data'),'created'); s.close(); s=Store(path)
   self.assertEqual(s.request('alice','one',b'data'),'created')
   with self.assertRaises(Conflict): s.request('alice','one',b'changed')
   with self.assertRaises(AuthError): s.challenge('bob','device')
   s.close()
if __name__=='__main__': unittest.main(verbosity=2)
