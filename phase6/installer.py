"""Versioned CS installation under an explicitly selected private prefix.

No service is started, enabled, stopped or deployed by installation. Privileged
system integration requires an explicit administrator action, never sudo here.
"""
import argparse,fcntl,hashlib,json,os,pathlib,re,shlex,shutil,stat,subprocess,sys,uuid

SOURCE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE/'phase1'))
from systemd_unit import render
FILES=tuple(sorted(p.name for p in (SOURCE/'phase1').glob('*.py') if not p.name.startswith('test_')))
SCHEMA_EPOCH=1
class InstallError(Exception): pass

def _fsync_dir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)

def _private(path,create=False,system=False):
 p=pathlib.Path(path)
 if system and os.geteuid()!=0: raise InstallError('system installation requires an administrator')
 if not system and os.geteuid()==0: raise InstallError('user installation requires a non-root user')
 if not p.is_absolute() or os.path.realpath(p)!=os.path.abspath(p): raise InstallError('prefix must be an absolute path without symlinks')
 if create:
  try: p.mkdir(mode=0o755 if system else 0o700); os.chmod(p,0o755 if system else 0o700)
  except FileExistsError: pass
 st=os.lstat(p)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&(0o022 if system else 0o077): raise InstallError('installation prefix must be protected and owned')
 return p

def _mkdir(path,owner=None,group=None,public=False):
 owner=os.geteuid() if owner is None else owner; group=os.getegid() if group is None else group
 try:
  path.mkdir(mode=0o755 if public else 0o700); os.chown(path,owner,group); os.chmod(path,0o755 if public else 0o700)
 except FileExistsError: pass
 st=os.lstat(path)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=owner or st.st_mode&(0o022 if public else 0o077): raise InstallError('unsafe installation directory')

def _run(args,timeout=120):
 env={'PATH':'/usr/bin:/bin','LANG':'C','PIP_DISABLE_PIP_VERSION_CHECK':'1','PIP_NO_CACHE_DIR':'1','PYTHONNOUSERSITE':'1'}
 result=subprocess.run(args,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
 if result.returncode: raise InstallError('dependency setup failed: '+result.stdout[-3000:])
 return result.stdout

def _version(lock,python):
 h=hashlib.sha256(b'CS-INSTALL-v1\0'); h.update(lock.read_bytes())
 h.update(os.fsencode(python)+b'\0')
 h.update(_run([str(python),'-c','import platform,ssl,sys;print(sys.version);print(platform.machine());print(ssl.OPENSSL_VERSION)'],timeout=10).encode())
 for name in FILES:
  p=SOURCE/'phase1'/name
  if p.is_symlink() or not p.is_file(): raise InstallError('source file missing or symlink')
  h.update(name.encode()+b'\0'); h.update(p.read_bytes())
 return h.hexdigest()

def _verify_release(release):
 if release.is_symlink() or not release.is_dir(): raise InstallError('invalid release')
 manifest=release/'manifest.json'
 if manifest.is_symlink() or not manifest.is_file(): raise InstallError('missing active manifest')
 data=json.loads(manifest.read_text())
 if not isinstance(data,dict) or set(data)!={'source_sha256','previous','python','files','lock_sha256','schema_epoch'} or data['schema_epoch']!=SCHEMA_EPOCH or not isinstance(data['files'],dict) or not data['files'] or any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py',n) or n.startswith('test_') or not isinstance(d,str) or not re.fullmatch(r'[0-9a-f]{64}',d) for n,d in data['files'].items()): raise InstallError('invalid active manifest or incompatible schema')
 app=release/'app'
 if app.is_symlink() or not app.is_dir() or {p.name for p in app.iterdir()}!=set(data['files']): raise InstallError('active application inventory changed')
 for name,digest in data['files'].items():
  path=app/name
  if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest: raise InstallError('active application modified')
 lock=release/'requirements.lock'
 if lock.is_symlink() or not lock.is_file() or hashlib.sha256(lock.read_bytes()).hexdigest()!=data['lock_sha256']: raise InstallError('active dependency lock modified')
 return data

def _sync_tree(root):
 for directory,subdirs,files in os.walk(root,topdown=False,followlinks=False):
  for name in files:
   path=pathlib.Path(directory)/name
   if path.is_symlink(): continue
   fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
   try:
    if not stat.S_ISREG(os.fstat(fd).st_mode): raise InstallError('unexpected release entry')
    os.fsync(fd)
   finally: os.close(fd)
  _fsync_dir(directory)

def _atomic_link(root,target):
 temp=root/('.current-'+uuid.uuid4().hex)
 os.symlink(target,temp)
 try: os.replace(temp,root/'current'); _fsync_dir(root)
 finally:
  try: temp.unlink()
  except FileNotFoundError: pass

def _wrapper(root,name):
 target={'cs-server':'server_launcher.py','cs-client':'client_launcher.py'}[name]
 quoted=shlex.quote(str(root)); suffix=(' --prefix '+quoted) if name=='cs-server' else ''
 return ('#!/bin/sh\nset -eu\nroot='+quoted+'\ntarget=$(/usr/bin/readlink -- "$root/current")\nprintf "%s\\n" "$target" | /usr/bin/grep -Eq "^releases/[0-9a-f]{64}-[0-9a-f]{12}$" || exit 1\nexec "$root/$target/venv/bin/python" -B "$root/$target/app/'+target+'"'+suffix+' "$@"\n').encode()

def _ensure_wrappers(root,system=False):
 created=[]
 try:
  for name in ('cs-server','cs-client'):
   path=root/'bin'/name; wanted=_wrapper(root,name)
   try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
   except FileNotFoundError:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755 if system else 0o700); created.append(path)
    if system: os.fchmod(fd,0o755)
    with os.fdopen(fd,'wb') as f: f.write(wanted); f.flush(); os.fsync(f.fileno())
   else:
    with os.fdopen(fd,'rb') as f:
     st=os.fstat(f.fileno())
     if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&(0o022 if system else 0o077) or f.read(len(wanted)+1)!=wanted: raise InstallError('existing launcher is not managed')
  _fsync_dir(root/'bin'); return created
 except BaseException:
  for path in created: path.unlink(missing_ok=True)
  raise

def _ensure_unit(root):
 unit=root/'config'/('cs-communication-'+hashlib.sha256(os.fsencode(root)).hexdigest()[:12]+'.service')
 wanted=('# CS managed unit v1\n'+render(root,root/'config/server.json','user')).encode()
 try: fd=os.open(unit,os.O_RDONLY|os.O_NOFOLLOW)
 except FileNotFoundError:
  fd=os.open(unit,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f: f.write(wanted); f.flush(); os.fsync(f.fileno())
  _fsync_dir(root/'config'); return unit,True
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or f.read(len(wanted)+1)!=wanted: raise InstallError('existing unit is not managed')
 return unit,False

def install(prefix,python,wheelhouse,lock,mode='user',service_uid=None,service_gid=None):
 if mode not in ('user','system'): raise InstallError('invalid installation mode')
 system=mode=='system'
 if system and (type(service_uid) is not int or type(service_gid) is not int or service_uid<=0 or service_gid<=0): raise InstallError('dedicated non-root service identity required')
 root=_private(prefix,True,system); marker=root/'.cs-install-root'
 if not marker.exists():
  if any(root.iterdir()): raise InstallError('refusing nonempty unmarked prefix')
  fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as f: f.write('CS-INSTALL-v1\n'); f.flush(); os.fsync(f.fileno())
  _fsync_dir(root)
 elif marker.is_symlink() or marker.read_text()!='CS-INSTALL-v1\n': raise InstallError('invalid installation marker')
 modefile=root/'.install-mode'; expected_mode={'mode':mode,'uid':service_uid if system else os.geteuid(),'gid':service_gid if system else os.getegid()}
 if not os.path.lexists(modefile):
  fd=os.open(modefile,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as f: json.dump(expected_mode,f,sort_keys=True); f.flush(); os.fsync(f.fileno())
  _fsync_dir(root)
 else:
  fd=os.open(modefile,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'r') as f:
   st=os.fstat(f.fileno())
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or json.load(f)!=expected_mode: raise InstallError('installation mode or identity mismatch')
 for name in ('releases','bin'): _mkdir(root/name,public=system)
 for name in ('data','config'): _mkdir(root/name,service_uid if system else None,service_gid if system else None)
 runtime_path=root/'bin/.runtime.lock'
 try:
  runtime_fd=os.open(runtime_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644 if system else 0o600)
  if system: os.fchmod(runtime_fd,0o644)
  os.fsync(runtime_fd); os.close(runtime_fd); _fsync_dir(root/'bin')
 except FileExistsError:
  runtime_fd=os.open(runtime_path,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   st=os.fstat(runtime_fd)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&(0o022 if system else 0o077): raise InstallError('unsafe runtime lock')
  finally: os.close(runtime_fd)
 lfd=os.open(root/'.install.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  st=os.fstat(lfd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise InstallError('unsafe install lock')
  fcntl.flock(lfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  schema=root/'data/.schema-epoch'
  if not os.path.lexists(schema):
   if any((root/'data').iterdir()): raise InstallError('existing data has no schema compatibility marker')
   fd=os.open(schema,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'w') as f: f.write(str(SCHEMA_EPOCH)+'\n'); f.flush(); os.fsync(f.fileno())
   _fsync_dir(root/'data')
  else:
   fd=os.open(schema,os.O_RDONLY|os.O_NOFOLLOW)
   with os.fdopen(fd,'rb') as f:
    st=os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or f.read(32)!=(str(SCHEMA_EPOCH)+'\n').encode(): raise InstallError('incompatible data schema')
  lock=pathlib.Path(lock).resolve(strict=True); wheels=pathlib.Path(wheelhouse).resolve(strict=True); python=pathlib.Path(python).resolve(strict=True)
  if not wheels.is_dir() or not python.is_file(): raise InstallError('dependency source unavailable')
  version=_version(lock,python); current=root/'current'
  if current.is_symlink():
   old=os.readlink(current)
   if not re.fullmatch(r'releases/[0-9a-f]{64}-[0-9a-f]{12}',old): raise InstallError('invalid current release')
   data=_verify_release(root/old)
   if data.get('source_sha256')==version:
    _ensure_wrappers(root,system)
    if not system: _ensure_unit(root)
    return {'status':'unchanged','version':version,'release':old}
  elif current.exists(): raise InstallError('invalid current pointer')
  else: old=None
  release_name=version+'-'+uuid.uuid4().hex[:12]; release=root/'releases'/release_name; release.mkdir(mode=0o700); created_wrappers=[]; created_unit=None
  try:
   app=release/'app'; app.mkdir(mode=0o700)
   for name in FILES: shutil.copyfile(SOURCE/'phase1'/name,app/name)
   shutil.copyfile(lock,release/'requirements.lock')
   _run([str(python),'-m','venv',str(release/'venv')])
   py=release/'venv/bin/python'
   _run([str(py),'-m','pip','install','--no-index','--find-links',str(wheels),'--require-hashes','-r',str(release/'requirements.lock')])
   _run([str(py),'-B','-c','import OpenSSL,cryptography,pyhpke,zstandard; print("dependencies-ok")'])
   meta={'source_sha256':version,'previous':old,'python':str(python),'files':{name:hashlib.sha256((app/name).read_bytes()).hexdigest() for name in FILES},'lock_sha256':hashlib.sha256((release/'requirements.lock').read_bytes()).hexdigest(),'schema_epoch':SCHEMA_EPOCH}
   fd=os.open(release/'manifest.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'w') as f: json.dump(meta,f,sort_keys=True); f.flush(); os.fsync(f.fileno())
   if system:
    for directory,subdirs,files in os.walk(release,followlinks=False):
     os.chmod(directory,0o755)
     for name in files:
      path=pathlib.Path(directory)/name
      if not path.is_symlink():
       st=os.lstat(path); os.chmod(path,0o755 if st.st_mode&0o111 else 0o644)
   _sync_tree(release); _fsync_dir(root/'releases'); created_wrappers=_ensure_wrappers(root,system)
   if not system:
    unit,unit_new=_ensure_unit(root)
    if unit_new: created_unit=unit
   _atomic_link(root,'releases/'+release_name)
   return {'status':'installed' if old is None else 'upgraded','version':version,'release':'releases/'+release_name,'previous':old}
  except BaseException as error:
   # Only an unactivated release allocated by this invocation may be removed.
   if current.is_symlink() and os.readlink(current)=='releases/'+release_name:
    try:
     if old is not None: _atomic_link(root,old)
     else: current.unlink(); _fsync_dir(root)
    except BaseException as rollback: raise InstallError('activation failed; rollback not confirmed') from rollback
   if not current.is_symlink() or os.readlink(current)!='releases/'+release_name:
    shutil.rmtree(release)
    for path in created_wrappers: path.unlink(missing_ok=True)
    if created_wrappers: _fsync_dir(root/'bin')
    if created_unit is not None: created_unit.unlink(missing_ok=True); _fsync_dir(root/'config')
   raise
 finally: os.close(lfd)

def uninstall(prefix,mode='user',service_uid=None,service_gid=None):
 if mode not in ('user','system'): raise InstallError('invalid installation mode')
 system=mode=='system'
 if system and (type(service_uid) is not int or type(service_gid) is not int or service_uid<=0 or service_gid<=0): raise InstallError('dedicated service identity required')
 root=_private(prefix,system=system); marker=root/'.cs-install-root'
 if marker.is_symlink() or not marker.is_file() or marker.read_text()!='CS-INSTALL-v1\n': raise InstallError('invalid installation marker')
 modefile=root/'.install-mode'; mfd=os.open(modefile,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(mfd,'r') as f:
  st=os.fstat(f.fileno()); expected={'mode':mode,'uid':service_uid if system else os.geteuid(),'gid':service_gid if system else os.getegid()}
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or json.load(f)!=expected: raise InstallError('installation mode or identity mismatch')
 fd=os.open(root/'.install.lock',os.O_RDWR|os.O_NOFOLLOW); runtime=None
 try:
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); current=root/'current'
  runtime=os.open(root/'bin/.runtime.lock',os.O_RDONLY|os.O_NOFOLLOW)
  st=os.fstat(runtime)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&(0o022 if system else 0o077): raise InstallError('unsafe runtime lock')
  try: fcntl.flock(runtime,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError as e: raise InstallError('stop CS processes before uninstall') from e
  if any(os.path.lexists(root/('.unit-'+mode+'-registered')) for mode in ('user','system')): raise InstallError('remove the managed systemd unit before uninstall')
  releases=root/'releases'
  _mkdir(releases,public=system)
  paths=list(releases.iterdir())
  for path in paths:
   st=os.lstat(path)
   if not re.fullmatch(r'[0-9a-f]{64}-[0-9a-f]{12}',path.name) or not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid(): raise InstallError('unsafe release entry')
  wrappers=[]
  for name in ('cs-server','cs-client'):
   path=root/'bin'/name
   try: wfd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
   except FileNotFoundError: continue
   with os.fdopen(wfd,'rb') as f:
    st=os.fstat(f.fileno())
    wanted=_wrapper(root,name)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&(0o022 if system else 0o077) or f.read(len(wanted)+1)!=wanted: raise InstallError('refusing to delete unmanaged launcher')
   wrappers.append(path)
  template=root/'config'/('cs-communication-'+hashlib.sha256(os.fsencode(root)).hexdigest()[:12]+'.service')
  if not system and os.path.lexists(template):
   tfd=os.open(template,os.O_RDONLY|os.O_NOFOLLOW); expected=('# CS managed unit v1\n'+render(root,root/'config/server.json','user')).encode()
   with os.fdopen(tfd,'rb') as f:
    st=os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or f.read(len(expected)+1)!=expected: raise InstallError('refusing to delete unmanaged unit template')
  else: template=None
  if current.is_symlink(): current.unlink(); _fsync_dir(root)
  elif current.exists(): raise InstallError('invalid current pointer')
  for path in paths: shutil.rmtree(path)
  _fsync_dir(releases)
  for path in wrappers: path.unlink()
  _fsync_dir(root/'bin')
  if template is not None: template.unlink(); _fsync_dir(root/'config')
  # Data, configuration, keys and results are deliberately retained.
  return {'status':'uninstalled','data_retained':True}
 finally:
  if runtime is not None: os.close(runtime)
  os.close(fd)

def main():
 p=argparse.ArgumentParser(); p.add_argument('action',choices=['install','uninstall']); p.add_argument('--prefix',required=True); p.add_argument('--python',default=sys.executable); p.add_argument('--wheelhouse'); p.add_argument('--lock'); a=p.parse_args()
 if a.action=='install':
  if not a.wheelhouse or not a.lock: p.error('install requires --wheelhouse and --lock')
  result=install(a.prefix,a.python,a.wheelhouse,a.lock)
 else: result=uninstall(a.prefix)
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try: main()
 except (OSError,ValueError,InstallError,subprocess.TimeoutExpired) as e: print(type(e).__name__+': '+str(e),file=sys.stderr); sys.exit(1)
