"""Fail-closed Bubblewrap building blocks for the execution worker."""
import ctypes,errno,os,pathlib,stat,subprocess,tempfile

DENIED=('mount','umount2','pivot_root','unshare','setns','ptrace','bpf','keyctl','add_key','request_key','open_by_handle_at','process_vm_readv','process_vm_writev','io_uring_setup','perf_event_open','userfaultfd','clone3','sched_setaffinity','connect')
class SandboxUnavailable(Exception): pass

def filter_file():
 """Build a libseccomp filter; absence or any unrecognized syscall fails closed."""
 try: lib=ctypes.CDLL('libseccomp.so.2',use_errno=True)
 except OSError as e: raise SandboxUnavailable('libseccomp unavailable') from e
 lib.seccomp_init.argtypes=[ctypes.c_uint32]; lib.seccomp_init.restype=ctypes.c_void_p
 lib.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint]; lib.seccomp_rule_add.restype=ctypes.c_int
 lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]; lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
 lib.seccomp_export_bpf.argtypes=[ctypes.c_void_p,ctypes.c_int]; lib.seccomp_export_bpf.restype=ctypes.c_int
 lib.seccomp_release.argtypes=[ctypes.c_void_p]
 ctx=lib.seccomp_init(0x7fff0000)
 if not ctx: raise SandboxUnavailable('seccomp init failed')
 output=None
 try:
  for name in DENIED:
   nr=lib.seccomp_syscall_resolve_name(name.encode('ascii'))
   if nr<0 or lib.seccomp_rule_add(ctx,0x00050000|errno.EPERM,nr,0)!=0: raise SandboxUnavailable('seccomp rule unavailable: '+name)
  output=tempfile.TemporaryFile()
  if lib.seccomp_export_bpf(ctx,output.fileno())!=0: raise SandboxUnavailable('seccomp export failed')
  output.seek(0); return output
 except BaseException:
  if output: output.close()
  raise
 finally: lib.seccomp_release(ctx)

def spawn(workspace,argv):
 """Launch only through Bubblewrap; never fall back to direct execution."""
 if os.geteuid()==0: raise SandboxUnavailable('host root is forbidden')
 if not isinstance(argv,list) or not 1<=len(argv)<=64 or any(not isinstance(s,str) or not s or '\0' in s or len(s.encode())>4096 for s in argv): raise ValueError('invalid argv')
 if sum(len(s.encode()) for s in argv)>16384: raise ValueError('argv too large')
 fd=os.open(workspace,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if st.st_uid!=os.geteuid() or st.st_mode&0o077: raise SandboxUnavailable('unsafe workspace')
  with filter_file() as filt:
   cmd=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--uid',str(os.geteuid()),'--gid',str(os.getegid()),'--cap-drop','ALL','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/workspace','--setenv','TMPDIR','/tmp','--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--bind-fd',str(fd),'/workspace','--chdir','/workspace','--seccomp',str(filt.fileno()),'--',*argv]
   return subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=(fd,filt.fileno()),start_new_session=True,env={'PATH':'/usr/bin:/bin'})
 finally: os.close(fd)
