"""Authenticated, bounded local receive into an isolated staging area.

The caller must authorize the transfer and provide the correct key and context.
This helper is not a network endpoint or a crash-recovery journal.
"""
import ctypes, errno, os, stat, tempfile, uuid
from transfer_stream import decrypt
from transfer_compress import decompress
from transfer_archive import unpack

_libc=ctypes.CDLL(None,use_errno=True)
try:
 _renameat2=_libc.renameat2
 _renameat2.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
 _renameat2.restype=ctypes.c_int
except AttributeError: _renameat2=None

def receive(encrypted,root,transfer_id,key,context,publish=None,archive_limit=1024*1024*1024,validate=None,durable=False):
 if not isinstance(transfer_id,str) or str(uuid.UUID(transfer_id))!=transfer_id: raise ValueError('invalid transfer id')
 if _renameat2 is None: raise OSError(errno.ENOSYS,'renameat2 unavailable')
 rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  st=os.fstat(rootfd)
  if st.st_uid!=os.geteuid() or st.st_mode & 0o077: raise ValueError('receive root must be private and owned')
  # Operate via the verified open directory, not a path that can be replaced.
  verified_root='/proc/self/fd/'+str(rootfd)
  with tempfile.TemporaryDirectory(prefix='.cs-incoming-'+transfer_id+'-',dir=verified_root) as work:
   staging=os.path.join(work,'tree'); os.mkdir(staging,0o700)
   with tempfile.TemporaryFile(dir=work) as archive:
    with tempfile.TemporaryFile(dir=work) as compressed:
     summary=decrypt(encrypted,compressed,key,context)
     if validate is not None: validate(summary)
     compressed.seek(0)
     decompress(compressed,archive,max_output=archive_limit)
    archive.seek(0); result=unpack(archive,staging)
   if durable:
    for base,dirs,files in os.walk(staging,topdown=False,followlinks=False):
     for name in files:
      fd=os.open(os.path.join(base,name),os.O_RDONLY|os.O_NOFOLLOW)
      try: os.fsync(fd)
      finally: os.close(fd)
     fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
     try: os.fsync(fd)
     finally: os.close(fd)
   # Source and destination share the same verified filesystem. No replacement.
   relative=os.path.relpath(staging,verified_root)
   def commit():
    if _renameat2(rootfd,os.fsencode(relative),rootfd,os.fsencode(transfer_id),1)!=0:
     code=ctypes.get_errno(); raise OSError(code,os.strerror(code))
    if durable: os.fsync(rootfd)
   if publish is None: commit()
   else: publish(commit)
   return result
 finally: os.close(rootfd)
