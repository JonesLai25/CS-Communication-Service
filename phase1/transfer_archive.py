"""Restricted tar file tree format; extraction target must be private staging."""
import os, stat, tarfile, unicodedata
MAX_FILES=4096
MAX_DEPTH=16
MAX_BYTES=1024*1024*1024
class InvalidArchive(Exception): pass

class _StrictTarInfo(tarfile.TarInfo):
 # Reject extension headers before tarfile allocates or parses their content.
 def _proc_member(self,archive):
  if self.type not in (tarfile.DIRTYPE,tarfile.REGTYPE,tarfile.AREGTYPE): raise InvalidArchive('unsupported archive member')
  return super()._proc_member(archive)

def components(path):
 if not isinstance(path,str) or not path or len(path.encode('utf-8'))>4096 or path.startswith('/') or '\\' in path or unicodedata.normalize('NFC',path)!=path: raise InvalidArchive('invalid path')
 parts=path.split('/')
 if len(parts)>MAX_DEPTH or any(not p or p in ('.','..') or len(p.encode('utf-8'))>255 or any(ord(c)<32 or ord(c)==127 for c in p) for p in parts): raise InvalidArchive('invalid path')
 return parts

def _dir(root,parts):
 fd=os.dup(root)
 try:
  for part in parts:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd); os.close(fd); fd=nxt
  return fd
 except BaseException: os.close(fd); raise

def unpack(source,staging):
 root=os.open(staging,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); total=0; count=0
 try:
  st=os.fstat(root)
  if st.st_uid!=os.geteuid() or st.st_mode & 0o077 or os.listdir(root): raise InvalidArchive('staging must be private, owned and empty')
  with tarfile.open(fileobj=source,mode='r|',tarinfo=_StrictTarInfo) as archive:
   for member in archive:
    count+=1
    if count>MAX_FILES or member.pax_headers or member.type not in (tarfile.DIRTYPE,tarfile.REGTYPE,tarfile.AREGTYPE): raise InvalidArchive('unsupported archive member')
    parts=components(member.name.rstrip('/') if member.isdir() else member.name)
    if member.size<0 or total+member.size>MAX_BYTES or (member.isdir() and member.size): raise InvalidArchive('archive size limit')
    parent=_dir(root,parts[:-1])
    try:
     if member.isdir(): os.mkdir(parts[-1],0o700,dir_fd=parent)
     else:
      target=os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
      with os.fdopen(target,'wb') as out:
       data=archive.extractfile(member)
       if data is None: raise InvalidArchive('missing content')
       remaining=member.size
       while remaining:
        block=data.read(min(262144,remaining))
        if not block: raise InvalidArchive('truncated content')
        out.write(block); remaining-=len(block)
      total+=member.size
    finally: os.close(parent)
  return {'files_and_directories':count,'bytes':total}
 except (tarfile.TarError,OSError,UnicodeError) as e: raise InvalidArchive('invalid or unsafe archive') from e
 finally: os.close(root)

def pack(path,target):
 root=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); rootdev=os.fstat(root).st_dev; total=0; count=0
 try:
  with tarfile.open(fileobj=target,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
   def walk(fd,prefix):
    nonlocal count,total
    for name in sorted(os.listdir(fd)):
     rel=prefix+'/'+name if prefix else name; components(rel); count+=1
     if count>MAX_FILES: raise InvalidArchive('too many files')
     st=os.stat(name,dir_fd=fd,follow_symlinks=False)
     if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)) or (stat.S_ISREG(st.st_mode) and st.st_nlink!=1): raise InvalidArchive('unsupported filesystem object')
     child=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|(os.O_DIRECTORY if stat.S_ISDIR(st.st_mode) else 0),dir_fd=fd)
     try:
      actual=os.fstat(child)
      if actual.st_dev!=rootdev or (actual.st_dev,actual.st_ino)!=(st.st_dev,st.st_ino) or (stat.S_ISREG(actual.st_mode) and actual.st_nlink!=1) or stat.S_IFMT(actual.st_mode)!=stat.S_IFMT(st.st_mode): raise InvalidArchive('source changed')
      info=tarfile.TarInfo(rel); info.uid=info.gid=0; info.uname=info.gname=''; info.mtime=0
      if stat.S_ISDIR(actual.st_mode):
       info.type=tarfile.DIRTYPE; info.mode=0o700; archive.addfile(info); walk(child,rel)
      else:
       total+=actual.st_size
       if total>MAX_BYTES: raise InvalidArchive('source too large')
       info.size=actual.st_size; info.mode=0o600
       with os.fdopen(os.dup(child),'rb') as src: archive.addfile(info,src)
       after=os.fstat(child)
       if (after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(actual.st_size,actual.st_mtime_ns,actual.st_ctime_ns): raise InvalidArchive('source changed')
     finally: os.close(child)
   walk(root,'')
  return {'files_and_directories':count,'bytes':total}
 except (tarfile.TarError,OSError,UnicodeError,ValueError) as e: raise InvalidArchive('unsafe source tree') from e
 finally: os.close(root)
