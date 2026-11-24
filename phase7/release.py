"""Build and verify an offline Linux release, with no private data or venv."""
import argparse,hashlib,json,os,pathlib,re,stat,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
MANIFEST='SHA256_MANIFEST.json'

def digest(data): return hashlib.sha256(data).hexdigest()
def git(*args): return subprocess.run(['git',*args],cwd=ROOT,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15).stdout

def build(output,wheels):
 head=git('rev-parse','HEAD').decode().strip()
 if not re.fullmatch('[0-9a-f]{40}',head) or git('status','--porcelain','--untracked-files=all'): raise ValueError('clean committed source required')
 files=[p for p in sorted((ROOT/'phase1').glob('*.py')) if not p.name.startswith('test_')]
 files += [ROOT/x for x in ('phase6/installer.py','phase6/system_installer.py','phase3/requirements-ubuntu20-py312.lock','phase7/release.py','phase7/INSTALL_GUIDE.md','phase7/ADMIN_GUIDE.md','phase7/USER_GUIDE.md')]
 content={}
 for path in files:
  name=path.relative_to(ROOT).as_posix()
  if path.is_symlink() or not path.is_file(): raise ValueError('invalid release source '+name)
  data=path.read_bytes()
  if git('show',head+':'+name)!=data: raise ValueError('source differs from committed version '+name)
  content[name]=data
 lock=content['phase3/requirements-ubuntu20-py312.lock'].decode()
 expected=re.findall(r'--hash=sha256:([a-f0-9]{64})',lock)
 if not expected or len(expected)!=len(set(expected)): raise ValueError('invalid dependency lock')
 wheelpaths=sorted(pathlib.Path(wheels).glob('*.whl'))
 if len(wheelpaths)!=len(expected): raise ValueError('wheel inventory mismatch')
 found=[]
 for p in wheelpaths:
  if p.is_symlink() or not p.is_file() or p.stat().st_size>32*1024*1024: raise ValueError('invalid wheel')
  data=p.read_bytes(); found.append(digest(data)); content['wheels/'+p.name]=data
 if sorted(found)!=sorted(expected): raise ValueError('wheel hash mismatch')
 content['RELEASE.json']=(json.dumps({'git_commit':head,'format':1,'platform':'linux-x86_64-python3.12','offline':True},sort_keys=True,indent=2)+'\n').encode()
 content[MANIFEST]=(json.dumps({n:digest(b) for n,b in sorted(content.items())},sort_keys=True,indent=2)+'\n').encode()
 output=pathlib.Path(output)
 if not output.is_absolute() or output.parent.resolve()!=ROOT.parent.resolve(): raise ValueError('release must be in persistent project parent')
 with output.open('xb') as f:
  with zipfile.ZipFile(f,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
   for name,data in sorted(content.items()):
    info=zipfile.ZipInfo(name,(2020,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED; info.external_attr=0o100644<<16; z.writestr(info,data)
  f.flush(); os.fsync(f.fileno())
 try: verify(output,head)
 except BaseException: output.unlink(missing_ok=True); raise
 fd=os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)
 return head

def verify(path,expected=None):
 path=pathlib.Path(path)
 if path.is_symlink() or not path.is_file() or path.stat().st_size>64*1024*1024: raise ValueError('invalid release archive')
 with zipfile.ZipFile(path) as z:
  entries=z.infolist(); names=[i.filename for i in entries]
  if len(names)!=len(set(names)) or len(names)>256 or sum(i.file_size for i in entries)>96*1024*1024: raise ValueError('invalid release inventory')
  for i in entries:
   parts=pathlib.PurePosixPath(i.filename).parts
   if not parts or i.filename!=pathlib.PurePosixPath(i.filename).as_posix() or i.filename.startswith('/') or any(p in ('.','..') for p in parts) or '\\' in i.filename or not stat.S_ISREG(i.external_attr>>16): raise ValueError('unsafe archive entry')
  manifest=json.loads(z.read(MANIFEST));
  if not isinstance(manifest,dict) or set(manifest)!=(set(names)-{MANIFEST}): raise ValueError('manifest mismatch')
  required={'RELEASE.json','phase6/installer.py','phase6/system_installer.py','phase3/requirements-ubuntu20-py312.lock','phase7/release.py','phase7/INSTALL_GUIDE.md','phase7/ADMIN_GUIDE.md','phase7/USER_GUIDE.md'}
  if not required<=set(manifest) or not any(n.startswith('wheels/') and n.endswith('.whl') for n in manifest) or not any(n.startswith('phase1/') and n.endswith('.py') for n in manifest): raise ValueError('release content missing')
  for name,hash_value in manifest.items():
   if not isinstance(hash_value,str) or not re.fullmatch('[0-9a-f]{64}',hash_value) or digest(z.read(name))!=hash_value: raise ValueError('digest mismatch: '+name)
  meta=json.loads(z.read('RELEASE.json'))
  if set(meta)!={'git_commit','format','platform','offline'} or meta['format']!=1 or meta['platform']!='linux-x86_64-python3.12' or meta['offline'] is not True or not re.fullmatch('[0-9a-f]{40}',meta['git_commit']): raise ValueError('invalid release metadata')
  if expected is not None and meta['git_commit']!=expected: raise ValueError('wrong Git version')
 return meta

def extract(path,destination,expected=None):
 meta=verify(path,expected); target=pathlib.Path(destination)
 if not target.is_absolute() or target.is_symlink() or not target.is_dir() or any(target.iterdir()) or target.stat().st_uid!=os.geteuid() or target.stat().st_mode&0o077: raise ValueError('destination must be an empty private owned directory')
 with zipfile.ZipFile(path) as z:
  for info in z.infolist():
   p=target.joinpath(*pathlib.PurePosixPath(info.filename).parts); p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as f: f.write(z.read(info)); f.flush(); os.fsync(f.fileno())
 return meta

def main():
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='op',required=True)
 b=sub.add_parser('build'); b.add_argument('output'); b.add_argument('--wheels',required=True)
 v=sub.add_parser('verify'); v.add_argument('archive'); v.add_argument('--commit')
 e=sub.add_parser('extract'); e.add_argument('archive'); e.add_argument('destination'); e.add_argument('--commit')
 a=p.parse_args()
 result=build(a.output,a.wheels) if a.op=='build' else verify(a.archive,a.commit) if a.op=='verify' else extract(a.archive,a.destination,a.commit)
 print(json.dumps({'result':result},sort_keys=True))
if __name__=='__main__':
 try: main()
 except (OSError,ValueError,KeyError,zipfile.BadZipFile,subprocess.SubprocessError) as e: print(type(e).__name__+': '+str(e),file=sys.stderr); sys.exit(1)
