"""Fail closed when a test's actual cgroup or CPU budget is not enforced."""
import os,pathlib

def enforce(memory,swap,pids,min_available_kib):
 if os.geteuid()==0: raise RuntimeError('test must not run as host root')
 lines=pathlib.Path('/proc/self/cgroup').read_text().splitlines()
 entries=[line.split(':',2)[2] for line in lines if line.startswith('0::')]
 if len(entries)!=1 or '..' in pathlib.PurePosixPath(entries[0]).parts: raise RuntimeError('unverifiable cgroup')
 group=pathlib.Path('/sys/fs/cgroup')/entries[0].lstrip('/')
 for name,ceiling in (('memory.max',memory),('memory.swap.max',swap),('pids.max',pids)):
  value=(group/name).read_text().strip()
  if not value.isdecimal() or not 0<int(value)<=ceiling: raise RuntimeError('resource limit missing or exceeded: '+name)
 if len(os.sched_getaffinity(0))!=1: raise RuntimeError('test CPU affinity exceeds one core')
 mem={}
 for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
  key,_,value=line.partition(':')
  if key=='MemAvailable': mem[key]=int(value.split()[0])
 if mem.get('MemAvailable',0)<min_available_kib: raise RuntimeError('host memory guard refused test')
