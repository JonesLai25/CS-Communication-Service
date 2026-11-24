"""Phase 3 client orchestration. Resume/reconciliation belongs to Phase 4."""
import hashlib, os, tempfile
from dataclasses import dataclass,field
from pyhpke import OpenError
from cryptography.exceptions import InvalidTag
from client import ProtocolError
from transfer_crypto import context, open_envelope
from transfer_archive import pack
from transfer_compress import compress
from transfer_stream import encrypt
from transfer_ingest import receive

@dataclass(frozen=True)
class TransferHandle:
 transfer_id: str
 package_id: object
 key: bytes=field(repr=False)
 context: bytes=field(repr=False)
 direction: str='upload'
 request_id: object=None

class _CappedWriter:
 def __init__(self,stream,limit): self.stream=stream; self.limit=limit; self.size=0
 def write(self,data):
  if self.size+len(data)>self.limit: raise ValueError('staging limit exceeded')
  n=self.stream.write(data); self.size+=n; return n
 def flush(self): return self.stream.flush()
 def tell(self): return self.size

def authorize(client,x25519_key,request_id,direction,package_id=None,ttl=3600):
 if client.token is None: raise ValueError('authenticate first')
 identity=hashlib.sha256(client.conn.sock.getpeercert(binary_form=True)).digest()
 entry=client.transfer_issue(request_id,direction,ttl,package_id=package_id)
 try: key=open_envelope(entry['enc'],entry['wrapped'],x25519_key,identity,client.owner,client.device,entry['id'],direction,package_id)
 except OpenError as e:
  if not isinstance(e.__cause__,InvalidTag): raise
  raise ProtocolError('Transfer OTP envelope rejected') from e
 binding=context(identity,client.owner,client.device,entry['id'],direction,package_id)
 return TransferHandle(entry['id'],package_id,key,binding,direction,request_id)

def upload_tree(client,handle,source,staging_dir=None):
 if handle.direction!='upload': raise ValueError('not an upload')
 with tempfile.TemporaryDirectory(prefix='.cs-client-',dir=staging_dir) as work:
  if os.statvfs(work).f_bavail*os.statvfs(work).f_frsize<512*1024*1024: raise OSError('insufficient client staging space')
  with tempfile.TemporaryFile(dir=work) as cipher:
   with tempfile.TemporaryFile(dir=work) as compressed:
    with tempfile.TemporaryFile(dir=work) as archive:
     pack(source,_CappedWriter(archive,128*1024*1024)); archive.seek(0)
     compress(archive,_CappedWriter(compressed,160*1024*1024))
    compressed.seek(0); encrypt(compressed,_CappedWriter(cipher,160*1024*1024),handle.key,handle.context)
   length=cipher.tell(); cipher.seek(0)
   return client.transfer_upload_stream(handle.transfer_id,cipher,length)

def download_tree(client,handle,root,staging_dir=None):
 if handle.direction!='download' or not handle.package_id: raise ValueError('not a download')
 with tempfile.TemporaryDirectory(prefix='.cs-client-',dir=staging_dir) as work:
  if os.statvfs(work).f_bavail*os.statvfs(work).f_frsize<512*1024*1024: raise OSError('insufficient client staging space')
  with tempfile.TemporaryFile(dir=work) as cipher:
   client.transfer_download_stream(handle.transfer_id,handle.package_id,cipher); cipher.seek(0)
   return receive(cipher,root,handle.transfer_id,handle.key,handle.context,archive_limit=128*1024*1024)
