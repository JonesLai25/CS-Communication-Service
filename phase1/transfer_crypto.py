"""RFC 9180 Transfer OTP envelopes; transport authorization is separate.

An envelope authenticates its complete transfer context. Callers must independently
check authorization and maintain the transfer lifecycle and replay state.
"""
import uuid
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

INFO = b'CS-TRANSFER-OTP-v1\x00'
SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)


def context(server_identity, owner, device, transfer_id, direction, package_id=None):
    if not isinstance(server_identity, bytes) or len(server_identity) != 32:
        raise ValueError('invalid server identity')
    for name in (owner, device):
        if not isinstance(name, str) or not (1 <= len(name) <= 64) or not name.isascii() or not all(c.isalnum() or c in '_-' for c in name):
            raise ValueError('invalid identity')
    if not isinstance(transfer_id, str) or str(uuid.UUID(transfer_id)) != transfer_id:
        raise ValueError('invalid transfer id')
    if direction not in ('upload', 'download'):
        raise ValueError('invalid direction')
    if direction == 'download':
        if not isinstance(package_id,str) or str(uuid.UUID(package_id))!=package_id: raise ValueError('invalid package id')
    elif package_id is not None: raise ValueError('unexpected package id')
    fields = (server_identity, owner.encode('ascii'), device.encode('ascii'), transfer_id.encode('ascii'), direction.encode('ascii'))
    if package_id is not None: fields += (package_id.encode('ascii'),)
    return INFO + b''.join(len(field).to_bytes(4, 'big') + field for field in fields)


def seal(otp, public_key, server_identity, owner, device, transfer_id, direction, package_id=None):
    if not isinstance(otp, bytes) or len(otp) != 32:
        raise ValueError('invalid Transfer OTP')
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError('invalid X25519 key')
    aad = context(server_identity, owner, device, transfer_id, direction, package_id)
    recipient = KEMKey.from_pyca_cryptography_key(X25519PublicKey.from_public_bytes(public_key))
    encapsulated, sender = SUITE.create_sender_context(recipient, INFO)
    return encapsulated, sender.seal(otp, aad)


def open_envelope(encapsulated, ciphertext, private_key, server_identity, owner, device, transfer_id, direction, package_id=None):
    if not isinstance(encapsulated, bytes) or len(encapsulated) != 32 or not isinstance(ciphertext, bytes) or len(ciphertext) != 48:
        raise ValueError('invalid envelope')
    aad = context(server_identity, owner, device, transfer_id, direction, package_id)
    recipient = KEMKey.from_pyca_cryptography_key(private_key)
    result = SUITE.create_recipient_context(encapsulated, recipient, INFO).open(ciphertext, aad)
    if len(result) != 32:
        raise ValueError('invalid Transfer OTP length')
    return result
