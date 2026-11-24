"""Owner-authorized local Unix socket management, not a network endpoint."""
import fcntl,json,os,re,socket,socketserver,stat,struct,threading
from registry import Denied, Busy, Limited, StorageError, Conflict

def name(value):
 if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',value): raise ValueError('invalid name')
 return value
def unique_object(pairs):
 result={}
 for key,value in pairs:
  if key in result: raise ValueError('duplicate JSON key')
  result[key]=value
 return result
def peer_allowed(credentials,expected_uid):
 if len(credentials)!=12: return False
 return struct.unpack('3i',credentials)[1]==expected_uid
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  self.request.settimeout(3)
  try:
   if not peer_allowed(self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12),os.geteuid()): return
   raw=self.rfile.readline(4097)
   if not raw.endswith(b'\n') or len(raw)>4096: return
   data=json.loads(raw,object_pairs_hook=unique_object); op=data['op']; reg=self.server.registry
   if self.server.storage_check is not None: self.server.storage_check()
   if op=='user_add' and set(data)=={'op','owner'}: reg.add_user(name(data['owner'])); result={'ok':True}
   elif op=='user_list' and set(data)=={'op'}: result={'users':reg.list_users()}
   elif op=='user_disable' and set(data)=={'op','owner'}: reg.disable_user(name(data['owner'])); result={'ok':True}
   elif op=='otp_create' and set(data)=={'op','owner','ttl'}: result={'otp':reg.create_otp(name(data['owner']),data['ttl'])}
   elif op=='otp_revoke' and set(data)=={'op','owner'}: reg.revoke_otps(name(data['owner'])); result={'ok':True}
   elif op=='device_list' and set(data)=={'op','owner'}: result={'devices':reg.list_devices(name(data['owner']))}
   elif op=='device_revoke' and set(data)=={'op','owner','device'}: reg.revoke_device(name(data['owner']),name(data['device'])); result={'ok':True}
   else: raise ValueError('bad request')
  except (ValueError,KeyError,TypeError,json.JSONDecodeError): result={'error':'bad_request'}
  except Denied: result={'error':'denied'}
  except Conflict: result={'error':'conflict'}
  except Limited: result={'error':'limited'}
  except Busy: result={'error':'busy'}
  except StorageError: result={'error':'storage'}
  self.wfile.write(json.dumps(result,separators=(',',':')).encode()+b'\n')
class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
 daemon_threads=True; request_queue_size=4
 def __init__(self,path,registry,storage_check=None):
  self.lockfd=None; self.bound=False
  parent=os.path.dirname(os.path.abspath(path)); st=os.lstat(parent)
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077 or os.path.realpath(parent)!=parent: raise ValueError('admin directory must be private and owned')
  lock=os.path.join(parent,'.cs-admin.lock'); self.lockfd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
  lockst=os.fstat(self.lockfd)
  if not stat.S_ISREG(lockst.st_mode) or lockst.st_uid!=os.geteuid() or lockst.st_mode & 0o077: os.close(self.lockfd); self.lockfd=None; raise ValueError('invalid lock')
  try:
   fcntl.flock(self.lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   if os.path.lexists(path):
    old=os.lstat(path)
    if not stat.S_ISSOCK(old.st_mode) or old.st_uid!=os.geteuid(): raise ValueError('unsafe existing admin path')
    os.unlink(path)
   self.registry=registry; self.storage_check=storage_check; self.slots=threading.BoundedSemaphore(4); super().__init__(path,Handler); self.bound=True; os.chmod(path,0o600)
  except BaseException:
   if self.lockfd is not None: os.close(self.lockfd); self.lockfd=None
   raise
 def process_request(self,request,addr):
  if not self.slots.acquire(False): self.shutdown_request(request); return
  try: super().process_request(request,addr)
  except BaseException: self.slots.release(); raise
 def process_request_thread(self,request,addr):
  try: super().process_request_thread(request,addr)
  finally: self.slots.release()
 def server_close(self):
  super().server_close()
  if self.bound:
   try: os.unlink(self.server_address)
   except FileNotFoundError: pass
   self.bound=False
  if self.lockfd is not None: os.close(self.lockfd); self.lockfd=None
