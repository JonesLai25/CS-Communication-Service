"""Bounded Zstandard framing for a byte stream; filesystem extraction is separate."""
import hashlib, struct
import zstandard as zstd
from transfer_stream import CHUNK, InvalidEnvelope, _read_exact, _write_all
MAGIC=b'CSZ3\x00\x01'
MAX_BYTES=1024*1024*1024
MAX_COMPRESSED=CHUNK+65536
MAX_FRAMES=4096
class InvalidCompressed(Exception): pass

def compress(source,target):
 _write_all(target,MAGIC); compressor=zstd.ZstdCompressor(level=3,write_content_size=True,write_checksum=True); digest=hashlib.sha256(); total=0; count=0
 while True:
  data=source.read(CHUNK)
  if not data: break
  if not isinstance(data,bytes) or len(data)>CHUNK or total+len(data)>MAX_BYTES or count>=MAX_FRAMES: raise ValueError('input exceeds limit')
  compressed=compressor.compress(data)
  if len(compressed)>MAX_COMPRESSED: raise ValueError('compressed frame exceeds limit')
  _write_all(target,struct.pack('>II',len(data),len(compressed))); _write_all(target,compressed); digest.update(data); total+=len(data); count+=1
 _write_all(target,struct.pack('>IIQQ',0,0,count,total)+digest.digest())
 return {'size':total,'chunks':count,'sha256':digest.hexdigest()}

def decompress(source,target,max_output=MAX_BYTES):
 if type(max_output) is not int or not 0<=max_output<=MAX_BYTES: raise ValueError('invalid output limit')
 try:
  if _read_exact(source,len(MAGIC))!=MAGIC: raise InvalidCompressed('invalid format')
  digest=hashlib.sha256(); total=0; count=0; decompressor=zstd.ZstdDecompressor(max_window_size=1024)
  while True:
   length,size=struct.unpack('>II',_read_exact(source,8))
   if length==0 and size==0:
    expected_count,expected_total=struct.unpack('>QQ',_read_exact(source,16)); expected_hash=_read_exact(source,32)
    if count!=expected_count or total!=expected_total or digest.digest()!=expected_hash or source.read(1): raise InvalidCompressed('incomplete, altered or trailing stream')
    return {'size':total,'chunks':count,'sha256':digest.hexdigest()}
   if not 0<length<=CHUNK or not 0<size<=MAX_COMPRESSED or total+length>max_output or count>=MAX_FRAMES: raise InvalidCompressed('decompression limit')
   frame=_read_exact(source,size)
   if zstd.frame_content_size(frame)!=length: raise InvalidCompressed('frame length mismatch')
   data=decompressor.decompress(frame,max_output_size=CHUNK,allow_extra_data=False)
   if len(data)!=length: raise InvalidCompressed('frame length mismatch')
   _write_all(target,data); digest.update(data); total+=length; count+=1
 except (zstd.ZstdError,InvalidEnvelope,EOFError) as e: raise InvalidCompressed('invalid compressed frame') from e
