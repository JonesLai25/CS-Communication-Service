"""Non-destructive test inside an isolated peer container; no host network."""
import os, pathlib, socket, sys, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,'/work/phase1')
from client import AuthenticatedClient, AuthorizationError, ProtocolError
if {name for _,name in socket.if_nameindex()} != {'lo'}: raise RuntimeError('unexpected network interface')
if pathlib.Path('/case/key.pem').exists() or pathlib.Path('/case/registry.db').exists(): raise RuntimeError('server private fixture exposed')
print('client network namespace:',os.readlink('/proc/self/ns/net'))
print('private loopback and separate server secrets: PASS')
key=Ed25519PrivateKey.from_private_bytes(pathlib.Path('/case/key.bin').read_bytes())
def connection(owner='alice',device='local-test',private=key): return AuthenticatedClient('localhost',18443,'/case/cert.pem',owner,device,private)
request_id=str(uuid.uuid4()); client=connection()
try:
 status,_=client.call('GET','/v1/result?id='+request_id)
 if status!=403: raise RuntimeError('unauthenticated query was accepted')
 client.authenticate(); reply=client.submit(request_id,'container-pair')
 if reply['state']!='succeeded' or not reply['new']: raise RuntimeError('submit failed')
 probe=connection()
 try:
  probe.token=client.token; status,_=probe.call('GET','/v1/result?id='+request_id)
  if status!=403: raise RuntimeError('cross-session token accepted')
 finally: probe.close()
finally: client.close()
wrong=connection(private=Ed25519PrivateKey.generate())
try:
 try: wrong.authenticate()
 except AuthorizationError: pass
 else: raise RuntimeError('wrong signing key was accepted')
finally: wrong.close()
other=connection(owner='bob')
try:
 try: other.authenticate()
 except AuthorizationError: pass
 else: raise RuntimeError('unregistered user was accepted')
finally: other.close()
client=connection()
try:
 client.authenticate(); reply=client.result(request_id)
 if reply is None or reply['state']!='succeeded': raise RuntimeError('reconnect query failed')
 reply=client.submit(request_id,'container-pair')
 if reply['new']: raise RuntimeError('duplicate execution right granted')
 try: client.submit(request_id,'different')
 except ProtocolError: pass
 else: raise RuntimeError('request ID content conflict accepted')
finally: client.close()
print('distinct containers: TLS auth, unauthenticated/wrong-key/cross-user/cross-session rejection, idempotency and reconnect query PASS')
