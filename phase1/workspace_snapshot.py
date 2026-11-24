"""Bounded ordinary-file workspace snapshots; fail closed on special entries."""
import ctypes,hashlib,json,os,pathlib,re,shutil,stat,tempfile
MAX_BYTES=16*1024*1024
MAX_FILES=512
MAX_DEPTH=16
class InvalidWorkspace(Exception): pass

def stage_name(root,owner,rid):
 rootid=hashlib.sha256(os.fsencode(pathlib.Path(root).resolve())).hexdigest()[:16]
 user=hashlib.sha256(owner.encode('ascii')).hexdigest()[:16]
 import uuid
 if str(uuid.UUID(rid))!=rid: raise ValueError('invalid stage id')
 return 'cs-exec-'+str(os.geteuid())+'-'+rootid+'-'+user+'-'+rid

def remove_stage(name):
 if not isinstance(name,str) or not re.fullmatch(r'cs-exec-'+str(os.geteuid())+r'-[0-9a-f]{16}-[0-9a-f]{16}-[0-9a-f-]{36}',name): raise InvalidWorkspace('invalid stage name')
 parent=os.open('/dev/shm',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  try: st=os.stat(name,dir_fd=parent,follow_symlinks=False)
  except FileNotFoundError: return
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise InvalidWorkspace('unsafe staging directory')
  shutil.rmtree(pathlib.Path('/dev/shm')/name)
 finally: os.close(parent)

def copy_tree(source,destination=None,durable=False,policy=None):
 root=pathlib.Path(source); st=os.lstat(root)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise InvalidWorkspace('unsafe workspace root')
 device=st.st_dev; count=0; total=0; digest=hashlib.sha256()
 max_bytes=MAX_BYTES if policy is None else policy['workspace_mib']*1024*1024
 max_files=MAX_FILES if policy is None else policy['workspace_entries']
 max_depth=MAX_DEPTH if policy is None else policy['workspace_depth']
 def add(raw): digest.update(len(raw).to_bytes(4,'big')); digest.update(raw)
 def walk(src,dst,relative,depth):
  nonlocal count,total
  if depth>max_depth: raise InvalidWorkspace('workspace too deep')
  with os.scandir(src) as entries: ordered=sorted(entries,key=lambda x:os.fsencode(x.name))
  for item in ordered:
   count+=1
   if count>max_files: raise InvalidWorkspace('too many workspace entries')
   info=item.stat(follow_symlinks=False); name=os.fsencode(item.name); rel=relative+b'/'+name; path=pathlib.Path(src)/item.name
   if info.st_dev!=device or info.st_uid!=os.geteuid(): raise InvalidWorkspace('foreign workspace entry')
   if stat.S_ISDIR(info.st_mode):
    add(b'd'); add(rel)
    target=None if dst is None else pathlib.Path(dst)/item.name
    if target is not None: os.mkdir(target,0o700)
    walk(path,target,rel,depth+1)
   elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
    total+=info.st_size
    if total>max_bytes: raise InvalidWorkspace('workspace too large')
    add(b'f'); add(rel); add(b'x' if info.st_mode&0o111 else b'-'); add(str(info.st_size).encode())
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); out=None
    try:
     current=os.fstat(fd)
     if (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns)!=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns): raise InvalidWorkspace('workspace changed during snapshot')
     if dst is not None: out=os.open(pathlib.Path(dst)/item.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700 if info.st_mode&0o111 else 0o600)
     remaining=info.st_size
     while remaining:
      chunk=os.read(fd,min(65536,remaining))
      if not chunk: raise InvalidWorkspace('workspace file truncated')
      digest.update(chunk); remaining-=len(chunk)
      if out is not None:
       view=memoryview(chunk)
       while view:
        n=os.write(out,view)
        if n<=0: raise OSError('short workspace write')
        view=view[n:]
     end=os.fstat(fd)
     if (end.st_size,end.st_mtime_ns,end.st_ctime_ns)!=(info.st_size,info.st_mtime_ns,info.st_ctime_ns): raise InvalidWorkspace('workspace changed during snapshot')
     if out is not None and durable: os.fsync(out)
    finally:
     os.close(fd)
     if out is not None: os.close(out)
   else: raise InvalidWorkspace('workspace entry must be regular file or directory')
  if dst is not None and durable:
   fd=os.open(dst,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   try: os.fsync(fd)
   finally: os.close(fd)
 walk(root,destination,b'',0)
 return digest.digest()

def _marker(parentfd,name,record):
 raw=json.dumps(record,sort_keys=True,separators=(',',':')).encode('ascii'); temporary='.'+name+'.tmp'
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parentfd)
 try:
  with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
  os.replace(temporary,name,src_dir_fd=parentfd,dst_dir_fd=parentfd); os.fsync(parentfd)
 finally:
  try: os.unlink(temporary,dir_fd=parentfd)
  except FileNotFoundError: pass

def recover(workspace,token,policy=None):
 if not isinstance(token,str) or not re.fullmatch('[A-Za-z0-9_-]{1,160}',token): raise ValueError('invalid publication token')
 if policy is None: policy={'workspace_mib':128,'workspace_entries':4096,'workspace_depth':32}
 workspace=pathlib.Path(workspace); parent=workspace.parent; stage=parent/('.cs-exec-stage-'+token); marker=parent/('.cs-exec-publish-'+token)
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise InvalidWorkspace('unsafe workspace parent')
  temp='.'+marker.name+'.tmp'
  try: item=os.stat(temp,dir_fd=fd,follow_symlinks=False)
  except FileNotFoundError: pass
  else:
   if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.geteuid() or item.st_mode&0o077: raise InvalidWorkspace('unsafe temporary marker')
   os.unlink(temp,dir_fd=fd); os.fsync(fd)
  try: markfd=os.open(marker.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
  except FileNotFoundError:
   if stage.exists():
    st=os.lstat(stage)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise InvalidWorkspace('unsafe publication stage')
    shutil.rmtree(stage); os.fsync(fd)
   return
  try:
   st=os.fstat(markfd)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_size>2048: raise InvalidWorkspace('unsafe publication marker')
   record=json.loads(os.read(markfd,2049))
  finally: os.close(markfd)
  if not isinstance(record,dict) or set(record)!={'workspace','before','after','state'} or record['workspace']!=workspace.name or record['state'] not in ('prepared','committed') or any(not isinstance(record[k],str) or not re.fullmatch('[0-9a-f]{64}',record[k]) for k in ('before','after')): raise InvalidWorkspace('invalid publication marker')
  current=copy_tree(workspace,policy=policy).hex()
  if record['state']=='committed':
   if current!=record['after']: raise InvalidWorkspace('published workspace changed')
  elif stage.exists():
   other=copy_tree(stage,policy=policy).hex()
   if (current,other) not in ((record['before'],record['after']),(record['after'],record['before'])): raise InvalidWorkspace('ambiguous workspace recovery')
  elif current not in (record['before'],record['after']): raise InvalidWorkspace('ambiguous workspace recovery')
  if stage.exists():
   st=os.lstat(stage)
   if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise InvalidWorkspace('unsafe publication stage')
   shutil.rmtree(stage); os.fsync(fd)
  os.unlink(marker.name,dir_fd=fd); os.fsync(fd)
 finally: os.close(fd)

def publish(source,workspace,expected,token,policy=None):
 if not isinstance(token,str) or not re.fullmatch('[A-Za-z0-9_-]{1,160}',token): raise ValueError('invalid publication token')
 workspace=pathlib.Path(workspace); parent=workspace.parent; parentfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 stage=parent/('.cs-exec-stage-'+token); marker='.cs-exec-publish-'+token; marked=False
 try:
  st=os.fstat(parentfd)
  if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise InvalidWorkspace('unsafe workspace parent')
  if copy_tree(workspace,policy=policy)!=expected: raise InvalidWorkspace('workspace changed while command ran')
  info=os.fstatvfs(parentfd)
  if info.f_bavail*info.f_frsize<512*1024*1024: raise OSError('insufficient workspace storage')
  os.mkdir(stage,0o700); after=copy_tree(source,stage,True,policy)
  if copy_tree(workspace,policy=policy)!=expected: raise InvalidWorkspace('workspace changed before publish')
  record={'workspace':workspace.name,'before':expected.hex(),'after':after.hex(),'state':'prepared'}
  _marker(parentfd,marker,record); marked=True
  libc=ctypes.CDLL(None,use_errno=True)
  if not hasattr(libc,'renameat2'): raise InvalidWorkspace('atomic exchange unavailable')
  if libc.renameat2(parentfd,os.fsencode(stage.name),parentfd,os.fsencode(workspace.name),2): raise OSError(ctypes.get_errno(),'atomic workspace exchange failed')
  os.fsync(parentfd); record['state']='committed'; _marker(parentfd,marker,record)
  shutil.rmtree(stage); os.fsync(parentfd); os.unlink(marker,dir_fd=parentfd); os.fsync(parentfd)
 finally:
  if not marked and stage.exists(): shutil.rmtree(stage); os.fsync(parentfd)
  os.close(parentfd)
