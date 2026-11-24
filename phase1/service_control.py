"""Manage only the uniquely named CS unit belonging to one installation."""
import hashlib,os,pathlib,re,stat,subprocess,uuid
from systemd_unit import render

class ServiceError(Exception): pass

def unit_name(prefix):
 return 'cs-communication-'+hashlib.sha256(os.fsencode(pathlib.Path(prefix).resolve())).hexdigest()[:12]+'.service'

def _directory(path,mode):
 p=pathlib.Path(path)
 if not p.is_absolute() or os.path.realpath(p)!=os.path.abspath(p): raise ServiceError('unsafe unit directory')
 if mode=='user':
  if os.geteuid()==0: raise ServiceError('user service requires non-root')
  p.mkdir(mode=0o700,parents=True,exist_ok=True)
 else:
  if os.geteuid()!=0: raise ServiceError('system service requires administrator')
  p.mkdir(mode=0o755,parents=True,exist_ok=True)
 st=os.lstat(p)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o022: raise ServiceError('unsafe unit directory permissions')
 return p

def _sync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)

def _prefix(prefix):
 root=pathlib.Path(prefix).resolve(strict=True); fd=os.open(root/'.cs-install-root',os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or f.read(64)!=b'CS-INSTALL-v1\n': raise ServiceError('invalid installation marker')
 return root

def install_unit(prefix,directory,mode,user='csservice'):
 root=_prefix(prefix); directory=_directory(directory,mode)
 data=('# CS managed unit v1\n'+render(root,root/'config/server.json',mode,user)).encode(); target=directory/unit_name(root)
 exists=False
 try: fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
 except FileNotFoundError: pass
 else:
  with os.fdopen(fd,'rb') as f:
   st=os.fstat(f.fileno())
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o022 or f.read(len(data)+1)!=data: raise ServiceError('refusing to replace an unmanaged unit')
  exists=True
 marker=root/('.unit-'+mode+'-registered'); marker_data=(str(target)+'\n').encode(); created=False
 try: mfd=os.open(marker,os.O_RDONLY|os.O_NOFOLLOW)
 except FileNotFoundError:
  mfd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); created=True
  with os.fdopen(mfd,'wb') as f: f.write(marker_data); f.flush(); os.fsync(f.fileno())
  _sync(root)
 else:
  with os.fdopen(mfd,'rb') as f:
   st=os.fstat(f.fileno())
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or f.read(len(marker_data)+1)!=marker_data: raise ServiceError('unsafe unit registration')
 if exists: return target
 temp=directory/('.cs-unit-'+uuid.uuid4().hex)
 try:
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644 if mode=='system' else 0o600)
  with os.fdopen(fd,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
  os.link(temp,target,follow_symlinks=False); _sync(directory)
 except BaseException:
  if created: marker.unlink(missing_ok=True); _sync(root)
  raise
 finally:
  try: temp.unlink(); _sync(directory)
  except FileNotFoundError: pass
 return target

def _managed(prefix,directory,mode,user):
 root=_prefix(prefix); directory=_directory(directory,mode); path=directory/unit_name(root)
 expected=('# CS managed unit v1\n'+render(root,root/'config/server.json',mode,user)).encode(); fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o022 or f.read(len(expected)+1)!=expected: raise ServiceError('unit ownership or content mismatch')
 return path

def systemctl(prefix,directory,mode,action,user='csservice'):
 if action not in ('start','stop','restart','status','enable','disable'): raise ValueError('invalid service action')
 unit=_managed(prefix,directory,mode,user)
 base=['/usr/bin/systemctl','--user' if mode=='user' else '--system']
 # Reject name collisions or a manager resolving a different unit file.
 check=subprocess.run(base+['show',unit.name,'--property=FragmentPath','--value'],capture_output=True,text=True,timeout=10)
 if check.returncode or pathlib.Path(check.stdout.strip())!=unit: raise ServiceError('systemd resolved an unexpected unit')
 result=subprocess.run(base+[action,unit.name],capture_output=True,text=True,timeout=30)
 if result.returncode: raise ServiceError('systemd action failed: '+result.stderr[-500:])
 return result.stdout

def remove_unit(prefix,directory,mode,user='csservice'):
 root=_prefix(prefix); marker=root/('.unit-'+mode+'-registered'); path=_managed(prefix,directory,mode,user); base=['/usr/bin/systemctl','--user' if mode=='user' else '--system']
 fd=os.open(marker,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno()); expected=(str(path)+'\n').encode()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or f.read(len(expected)+1)!=expected: raise ServiceError('unsafe unit registration')
 active=subprocess.run(base+['is-active',path.name],capture_output=True,text=True,timeout=10)
 if active.returncode not in (3,4) or active.stdout.strip() not in ('inactive','unknown'): raise ServiceError('stop the owned service before removing its unit')
 enabled=subprocess.run(base+['is-enabled',path.name],capture_output=True,text=True,timeout=10)
 if enabled.stdout.strip() not in ('disabled','static','not-found'): raise ServiceError('disable the owned service before removing its unit')
 path.unlink(); _sync(path.parent); marker.unlink(); _sync(root)
