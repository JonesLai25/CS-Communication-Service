import pathlib,unittest
from unittest.mock import patch
import resource_guard
class Limits(unittest.TestCase):
 def check(self,changed=None,cpus={0},available=500000):
  values={'/proc/self/cgroup':'0::/test\n','/sys/fs/cgroup/test/memory.max':'150994944','/sys/fs/cgroup/test/memory.swap.max':'134217728','/sys/fs/cgroup/test/pids.max':'64','/proc/meminfo':'MemAvailable: '+str(available)+' kB\n'}
  if changed: values.update(changed)
  def read(path,*args,**kwargs): return values[str(path)]
  with patch.object(pathlib.Path,'read_text',read),patch('resource_guard.os.geteuid',return_value=1000),patch('resource_guard.os.sched_getaffinity',return_value=cpus): resource_guard.enforce(150994944,134217728,64,300000)
 def test_valid_limits(self): self.check()
 def test_unbounded_or_excess_rejected(self):
  for key,value in (('memory.max','max'),('memory.max','150994945'),('memory.swap.max','134217729'),('pids.max','65')):
   with self.subTest(key=key,value=value),self.assertRaises(RuntimeError): self.check({'/sys/fs/cgroup/test/'+key:value})
 def test_cpu_and_host_memory_rejected(self):
  with self.assertRaises(RuntimeError): self.check(cpus={0,1})
  with self.assertRaises(RuntimeError): self.check(available=299999)
if __name__=='__main__': unittest.main(verbosity=2)
