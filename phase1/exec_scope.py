"""Validate a test-only aggregate cgroup; production does not require it."""
import os,pathlib,re
from sandbox import SandboxUnavailable

def test_slice():
 name=os.environ.get('CS_PHASE5_TEST_SLICE')
 if not name: return None
 if not re.fullmatch(r'csphase5[0-9a-f]{12}\.slice',name): raise SandboxUnavailable('invalid test slice')
 lines=pathlib.Path('/proc/self/cgroup').read_text().splitlines(); entries=[x.split(':',2)[2] for x in lines if x.startswith('0::')]
 if len(entries)!=1: raise SandboxUnavailable('unverifiable test slice')
 parts=pathlib.PurePosixPath(entries[0]).parts
 if '..' in parts or parts.count(name)!=1: raise SandboxUnavailable('process outside test slice')
 group=pathlib.Path('/sys/fs/cgroup').joinpath(*parts[1:parts.index(name)+1])
 for file,cap in (('memory.max',192*1024*1024),('memory.swap.max',128*1024*1024),('pids.max',64)):
  value=(group/file).read_text().strip()
  if not value.isdecimal() or not 0<int(value)<=cap: raise SandboxUnavailable('test aggregate limit unavailable: '+file)
 return name
