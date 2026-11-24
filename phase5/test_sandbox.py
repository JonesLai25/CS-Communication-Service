"""Host-isolated, fake-resource security tests; explicit exceptions survive -O."""
import os,pathlib,select,socket,subprocess,sys,tempfile,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
from resource_guard import enforce
enforce(144*1024*1024,128*1024*1024,64,300000)
import sandbox
class Sandbox(unittest.TestCase):
 def test_boundaries_and_negative_control(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); private=root/'private'; alice=root/'alice'; bob=root/'bob'
   for p in (private,alice,bob): p.mkdir(mode=0o700)
   secret=private/'secret'; secret.write_text('dummy secret'); (alice/'marker').write_text('alice'); (bob/'marker').write_text('bob')
   with socket.socket(socket.AF_UNIX) as admin, socket.socket() as listener, secret.open('rb') as leaked:
    admin.bind(str(private/'admin.sock')); admin.listen(); listener.bind(('127.0.0.1',0)); listener.listen()
    code='''import ctypes,errno,os,socket,sys\nsecret,bob,sock,port,hostpid,fd=sys.argv[1:]\ndef check(v,m):\n if not v: raise RuntimeError(m)\ncheck(os.getuid()!=0,'root uid')\ncheck(open('/workspace/marker').read()=='alice','workspace')\nfor p in (secret,bob):\n try: open(p).read()\n except OSError: pass\n else: raise RuntimeError('HOST_DATA_EXPOSED '+p)\ntry: open(bob,'w').write('tamper')\nexcept OSError: pass\nelse: raise RuntimeError('other workspace writable')\ns=socket.socket(socket.AF_UNIX); s.settimeout(1)\ntry: s.connect(sock)\nexcept OSError: pass\nelse: raise RuntimeError('admin socket reachable')\ns=socket.socket(); s.settimeout(1); check(s.connect_ex(('127.0.0.1',int(port)))!=0,'network reachable')\ncheck('CS_FAKE_SECRET' not in os.environ,'secret environment')\ntry: os.read(int(fd),1)\nexcept OSError: pass\nelse: raise RuntimeError('secret FD inherited')\ncheck(not os.path.exists('/proc/'+hostpid),'host process exposed')\nstatus=open('/proc/self/status').read(); check('NoNewPrivs:\\t1' in status,'no-new-privs missing'); check('Seccomp:\\t2' in status,'seccomp missing')\nlib=ctypes.CDLL(None,use_errno=True); rc=lib.unshare(0); check(rc==-1 and ctypes.get_errno()==errno.EPERM,'unshare not blocked')\nprint('BOUNDARY_OK')'''
    argv=['/usr/bin/python3','-c',code,str(secret),str(bob/'marker'),str(private/'admin.sock'),str(listener.getsockname()[1]),str(os.getpid()),str(leaked.fileno())]
    def run(mutant=False):
     real=sandbox.subprocess.Popen
     def injected(cmd,*a,**kw):
      if mutant: cmd=cmd[:-len(argv)-1]+['--ro-bind',str(private),str(private),'--']+cmd[-len(argv):]
      return real(cmd,*a,**kw)
     with patch.object(sandbox.subprocess,'Popen',side_effect=injected): p=sandbox.spawn(alice,argv)
     try: return p.communicate(timeout=12)+(p.returncode,)
     except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=5); raise
    os.environ['CS_FAKE_SECRET']='not-a-secret'
    try: out,err,rc=run(); self.assertEqual(rc,0,err.decode()); self.assertIn(b'BOUNDARY_OK',out)
    finally: os.environ.pop('CS_FAKE_SECRET',None)
    out,err,rc=run(True); self.assertNotEqual(rc,0); self.assertIn(b'HOST_DATA_EXPOSED',err)
    self.assertEqual((bob/'marker').read_text(),'bob')
 def test_filter_missing_fails_closed(self):
  with tempfile.TemporaryDirectory() as d, patch.object(sandbox,'filter_file',side_effect=sandbox.SandboxUnavailable('injected')):
   with self.assertRaises(sandbox.SandboxUnavailable): sandbox.spawn(d,['/usr/bin/true'])
 def test_seccomp_negative_control_detects_missing_affinity_rule(self):
  with tempfile.TemporaryDirectory() as d:
   code="import os,errno;\ntry: os.sched_setaffinity(0,os.sched_getaffinity(0))\nexcept OSError as e:\n if e.errno!=errno.EPERM: raise\n print('BLOCKED')\nelse: raise RuntimeError('AFFINITY_FILTER_MISSING')"
   def run():
    p=sandbox.spawn(d,['/usr/bin/python3','-c',code])
    try: out,err=p.communicate(timeout=10); return p.returncode,out,err
    except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=5); raise
   rc,out,err=run(); self.assertEqual(rc,0,err.decode()); self.assertIn(b'BLOCKED',out)
   with patch.object(sandbox,'DENIED',tuple(x for x in sandbox.DENIED if x!='sched_setaffinity')):
    rc,out,err=run()
   self.assertNotEqual(rc,0); self.assertIn(b'AFFINITY_FILTER_MISSING',err)
 def test_socket_connect_negative_control(self):
  with tempfile.TemporaryDirectory() as d, socket.socket(socket.AF_UNIX) as listener:
   listener.bind(str(pathlib.Path(d)/'fake.sock')); listener.listen()
   code="import errno,socket; s=socket.socket(socket.AF_UNIX);\ntry: s.connect('/workspace/fake.sock')\nexcept OSError as e:\n if e.errno!=errno.EPERM: raise\n print('CONNECT_BLOCKED')\nelse: raise RuntimeError('CONNECT_FILTER_MISSING')"
   def run():
    p=sandbox.spawn(d,['/usr/bin/python3','-c',code])
    try: out,err=p.communicate(timeout=10); return p.returncode,out,err
    except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=5); raise
   rc,out,err=run(); self.assertEqual(rc,0,err.decode()); self.assertIn(b'CONNECT_BLOCKED',out)
   with patch.object(sandbox,'DENIED',tuple(x for x in sandbox.DENIED if x!='connect')):
    rc,out,err=run()
   self.assertNotEqual(rc,0); self.assertIn(b'CONNECT_FILTER_MISSING',err)
 def test_owned_process_tree_is_reaped(self):
  with tempfile.TemporaryDirectory() as d:
   code="import os,time; pid=os.fork(); (os.setsid() if pid==0 else None); print('READY',flush=True) if pid else None; time.sleep(120)"
   p=sandbox.spawn(d,['/usr/bin/python3','-c',code]); observed={}
   try:
    if not select.select([p.stdout],[],[],10)[0] or p.stdout.readline().strip()!=b'READY': self.fail('startup deadline')
    def children(pid):
     try: return [int(x) for x in pathlib.Path('/proc/%d/task/%d/children'%(pid,pid)).read_text().split()]
     except FileNotFoundError: return []
    def collect(pid):
     for child in children(pid):
      try: observed[child]=pathlib.Path('/proc/%d/stat'%child).read_text().split(') ',1)[1].split()[19]
      except FileNotFoundError: continue
      collect(child)
    collect(p.pid); self.assertGreaterEqual(len(observed),2)
   finally:
    if p.poll() is None: p.kill()
    p.communicate(timeout=5)
   end=time.monotonic()+5
   while time.monotonic()<end:
    live=[]
    for pid,start in observed.items():
     try:
      fields=pathlib.Path('/proc/%d/stat'%pid).read_text().split(') ',1)[1].split()
      if fields[19]==start and fields[0]!='Z': live.append(pid)
     except FileNotFoundError: pass
    if not live: break
    time.sleep(.05)
   self.assertEqual(live,[],'isolated descendants survived')
if __name__=='__main__': unittest.main(verbosity=2)
