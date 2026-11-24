"""Keep a shared lock while installed programs are using a release."""
import fcntl,os,pathlib,stat

def hold(prefix):
 root=pathlib.Path(prefix); fd=os.open(root/'bin/.runtime.lock',os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0,os.geteuid()) or st.st_mode&0o022 or (st.st_uid!=0 and st.st_mode&0o077): raise ValueError('unsafe runtime lock')
  fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB); os.set_inheritable(fd,True); return fd
 except BaseException: os.close(fd); raise
