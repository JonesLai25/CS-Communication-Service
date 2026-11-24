"""Verify an administrator-provisioned bounded filesystem for server state.

This checks a kernel filesystem capacity, not a directory size estimate or a
per-user quota. It does not configure filesystems or govern external journals.
"""
import os,pathlib,stat

def verify_bounded_filesystem(paths,maximum_mib,minimum_free=0):
 if type(maximum_mib) is not int or not 16<=maximum_mib<=1048576: raise ValueError('invalid storage capacity limit')
 if type(minimum_free) is not int or minimum_free<0: raise ValueError('invalid free space reserve')
 if not paths: raise ValueError('no storage paths')
 expected=None; capacity=None
 for value in paths:
  path=pathlib.Path(value)
  if not path.is_absolute() or os.path.realpath(path)!=os.path.abspath(path): raise ValueError('storage path must be absolute and without symlinks')
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   st=os.fstat(fd); fs=os.fstatvfs(fd)
   if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('storage directory must be private and owned')
   total=fs.f_blocks*fs.f_frsize
   if fs.f_blocks<=0 or fs.f_frsize<=0 or total>maximum_mib*1024*1024: raise ValueError('filesystem capacity exceeds configured limit')
   if minimum_free and fs.f_bavail*fs.f_frsize<minimum_free: raise ValueError('filesystem free space reserve unavailable')
   if expected is not None and (st.st_dev!=expected or total!=capacity): raise ValueError('server data spans different filesystems')
   expected=st.st_dev; capacity=total
  finally: os.close(fd)
 return capacity
