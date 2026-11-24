"""Bounded-memory authenticated framing for already-compressed transfer data.

Decrypt only to a private staging file; a caller must not publish it until this
function has returned successfully and the archive has been safely validated.
The caller must enforce authorization and transfer lifecycle separately.
"""
import hashlib, os, struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

MAGIC=b'CSF3\x00\x01'
CHUNK=256*1024
MAX_CHUNKS=4096  # 1 GiB per envelope at the maximum chunk size
class InvalidEnvelope(Exception): pass

def _key(otp,salt,context):
 if not isinstance(otp,bytes) or len(otp)!=32 or not isinstance(context,bytes) or len(context)>4096: raise ValueError('invalid key or context')
 return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=b'CS-FILE-KEY-v1\x00'+hashlib.sha256(context).digest()).derive(otp)
def _read_exact(source,size):
 out=bytearray()
 while len(out)<size:
  part=source.read(size-len(out))
  if not part: raise InvalidEnvelope('truncated frame')
  out.extend(part)
 return bytes(out)
def _write_all(target,data):
 view=memoryview(data)
 while view:
  n=target.write(view)
  if not isinstance(n,int) or n<=0 or n>len(view): raise OSError('incomplete write')
  view=view[n:]
def _aad(header,context,index,kind,length):
 return header+hashlib.sha256(context).digest()+struct.pack('>QBI',index,kind,length)
def _nonce(index): return b'CSF3'+struct.pack('>Q',index)

def encrypt(source,target,otp,context):
 salt=os.urandom(32); header=MAGIC+salt; a=AESGCM(_key(otp,salt,context)); _write_all(target,header); digest=hashlib.sha256(); index=0; total=0
 while True:
  part=source.read(CHUNK)
  if not part: break
  if not isinstance(part,bytes) or len(part)>CHUNK: raise ValueError('invalid input stream')
  if index>=MAX_CHUNKS: raise ValueError('transfer too large')
  digest.update(part); total+=len(part); aad=_aad(header,context,index,0,len(part)); ct=a.encrypt(_nonce(index),part,aad)
  _write_all(target,struct.pack('>BI',0,len(ct))); _write_all(target,ct); index+=1
 final=struct.pack('>QQ',index,total)+digest.digest(); aad=_aad(header,context,index,1,len(final)); ct=a.encrypt(_nonce(index),final,aad)
 _write_all(target,struct.pack('>BI',1,len(ct))); _write_all(target,ct)
 return {'chunks':index,'size':total,'sha256':digest.hexdigest()}

def decrypt(source,target,otp,context):
 header=_read_exact(source,len(MAGIC)+32)
 if not header.startswith(MAGIC): raise InvalidEnvelope('invalid format')
 a=AESGCM(_key(otp,header[len(MAGIC):],context)); digest=hashlib.sha256(); index=0; total=0
 while True:
  kind,size=struct.unpack('>BI',_read_exact(source,5))
  if kind not in (0,1) or size<16 or (kind==0 and not 16<size<=CHUNK+16) or (kind==1 and size!=64) or index>MAX_CHUNKS: raise InvalidEnvelope('invalid frame')
  ct=_read_exact(source,size)
  try: part=a.decrypt(_nonce(index),ct,_aad(header,context,index,kind,size-16))
  except InvalidTag as e: raise InvalidEnvelope('authentication failed') from e
  if kind==1:
   count,expected=struct.unpack('>QQ',part[:16])
   if count!=index or expected!=total or part[16:]!=digest.digest() or source.read(1): raise InvalidEnvelope('incomplete or trailing data')
   return {'chunks':index,'size':total,'sha256':digest.hexdigest()}
  if index>=MAX_CHUNKS: raise InvalidEnvelope('too many chunks')
  _write_all(target,part); digest.update(part); total+=len(part); index+=1
