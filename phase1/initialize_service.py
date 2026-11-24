"""Create a private local Server identity once; never replace existing keys."""
import argparse,ctypes,datetime,json,os,pathlib,re,shutil,stat,tempfile,uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from registry import Registry
from service_cli import load_config
from deployment_policy import DEFAULT,load

def private_dir(value):
 p=pathlib.Path(value)
 if not p.is_absolute() or os.path.realpath(p)!=os.path.abspath(p): raise ValueError('unsafe directory path')
 st=os.lstat(p)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('directory must be private and owned')
 return p

def sync_dir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)

def write_new(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())

def initialize(data,config,port,enable_exec):
 import fcntl
 if os.geteuid()==0: raise ValueError('service identity must be initialized as non-root')
 data=private_dir(data); config=private_dir(config)
 if type(port) is not int or not 0<=port<=65535 or type(enable_exec) is not bool: raise ValueError('invalid configuration')
 lock=os.open(data/'.initialize.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  st=os.fstat(lock)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe initializer lock')
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  for path in data.iterdir():
   if path.name.startswith('.cs-init-'):
    st=os.lstat(path)
    if not re.fullmatch(r'\.cs-init-[A-Za-z0-9_-]{8}',path.name) or not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe initializer staging')
    shutil.rmtree(path); sync_dir(data)
  instance=data/'instance'
  if not instance.exists():
   temp=pathlib.Path(tempfile.mkdtemp(prefix='.cs-init-',dir=data))
   try:
    for name in ('incoming','packages','resume','workspaces','admin'): (temp/name).mkdir(mode=0o700)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048); subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]); now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).sign(key,hashes.SHA256()))
    write_new(temp/'tls.key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    write_new(temp/'tls.crt',cert.public_bytes(serialization.Encoding.PEM)); write_new(temp/'master.key',os.urandom(32)); Registry(str(temp/'registry.db')).initialize(); write_new(temp/'.cs-instance',b'CS-INSTANCE-v1\n')
    fd=os.open(temp/'registry.db',os.O_RDONLY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    for path in (temp/'incoming',temp/'packages',temp/'resume',temp/'workspaces',temp/'admin',temp): sync_dir(path)
    parent=os.open(data,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
     libc=ctypes.CDLL(None,use_errno=True)
     if not hasattr(libc,'renameat2') or libc.renameat2(parent,os.fsencode(temp.name),parent,b'instance',1): raise OSError(ctypes.get_errno(),'atomic instance publication failed')
     os.fsync(parent)
    finally: os.close(parent)
   finally:
    if temp.exists(): shutil.rmtree(temp)
  private_dir(instance)
  marker=instance/'.cs-instance'
  if marker.is_symlink() or not marker.is_file() or marker.read_bytes()!=b'CS-INSTANCE-v1\n': raise ValueError('invalid existing instance')
  for name in ('tls.key','tls.crt','master.key','registry.db'):
   fd=os.open(instance/name,os.O_RDONLY|os.O_NOFOLLOW)
   try:
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe existing identity')
   finally: os.close(fd)
  for name in ('incoming','packages','resume','workspaces','admin'): private_dir(instance/name)
  config_file=config/'server.json'
  if config_file.exists(): load_config(config_file); return {'status':'unchanged','config':str(config_file)}
  policy=config/'execution-policy.json'
  if policy.exists(): load(policy)
  else: write_new(policy,(json.dumps(DEFAULT,sort_keys=True,indent=2)+'\n').encode()); sync_dir(config)
  value={'cert':str(instance/'tls.crt'),'key':str(instance/'tls.key'),'db':str(instance/'registry.db'),'port':port,'admin_socket':str(instance/'admin/admin.sock'),'transfer_master':str(instance/'master.key'),'transfer_root':str(instance/'incoming'),'package_root':str(instance/'packages'),'resume_root':str(instance/'resume'),'pending_upload_mib':384,'audit_retention_days':90,'audit_max_records':100000}
  if enable_exec: value['exec_root']=str(instance/'workspaces'); value['exec_policy']=str(policy)
  raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode(); temp=config/('.server-'+uuid.uuid4().hex)
  try:
   write_new(temp,raw); os.link(temp,config_file,follow_symlinks=False); sync_dir(config)
  finally:
   try: temp.unlink(); sync_dir(config)
   except FileNotFoundError: pass
  return {'status':'initialized','config':str(config_file)}
 finally: os.close(lock)

def main():
 p=argparse.ArgumentParser(); p.add_argument('--data',required=True); p.add_argument('--config',required=True); p.add_argument('--port',type=int,default=18443); p.add_argument('--enable-exec',action='store_true'); a=p.parse_args(); print(json.dumps(initialize(a.data,a.config,a.port,a.enable_exec)))
if __name__=='__main__': main()
