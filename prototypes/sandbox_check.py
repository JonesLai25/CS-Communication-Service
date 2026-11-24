"""Bubblewrap isolation experiment with disposable resources; not production sandbox."""
if not __debug__: raise RuntimeError('security checks require Python without -O')
import os, pathlib, resource, socket, subprocess, tempfile
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d)
 for x in ('private','alice','bob'): (p/x).mkdir()
 secret=p/'private'/'secret'; secret.write_text('fake-private'); (p/'alice'/'data').write_text('alice'); bob=p/'bob'/'data'; bob.write_text('fake-bob')
 with socket.socket(socket.AF_UNIX) as admin, socket.socket() as listener, open(secret,'rb') as fd:
  admin.bind(str(p/'private'/'admin.sock')); admin.listen(); listener.bind(('127.0.0.1',0)); listener.listen(); port=listener.getsockname()[1]
  code='''import os,socket,resource\nassert open('/workspace/data').read()=='alice'\nfor path in PATHS:\n try:\n  with open(path,'rb') as f: f.read()\n except (OSError,PermissionError): pass\n else: raise AssertionError('host file exposed: '+path)\ntry:\n with open(BOB,'w') as f: f.write('changed')\nexcept OSError: pass\nelse: raise AssertionError('host workspace writable')\ns=socket.socket(socket.AF_UNIX); s.settimeout(1)\ntry: s.connect(SOCK)\nexcept OSError: pass\nelse: raise AssertionError('admin socket reachable')\ns=socket.socket(); s.settimeout(1); assert s.connect_ex(('127.0.0.1',PORT)) != 0\nassert 'CS_FAKE_SECRET' not in os.environ\ntry: os.read(FD,1)\nexcept OSError: pass\nelse: raise AssertionError('secret fd leaked')\nassert os.getpid()==2 and not os.path.exists('/proc/'+str(HOSTPID))\nassert resource.getrlimit(resource.RLIMIT_NOFILE)[0]<=64\nprint('paths, socket, fd, environment, network, proc and rlimit: PASS')'''
  code=code.replace('PATHS',repr([str(secret),str(bob)])).replace('BOB',repr(str(bob))).replace('SOCK',repr(str(p/'private'/'admin.sock'))).replace('PORT',str(port)).replace('HOSTPID',str(os.getpid())).replace('FD',str(fd.fileno()))
  cmd=['bwrap','--die-with-parent','--unshare-all','--new-session','--clearenv','--setenv','PATH','/usr/bin:/bin','--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--bind',str(p/'alice'),'/workspace','--chdir','/workspace']
  def limits(): resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
  def run(extra): return subprocess.run(cmd+extra+['/usr/bin/python3','-c',code],env={'PATH':'/usr/bin:/bin','CS_FAKE_SECRET':'dummy'},preexec_fn=limits,timeout=10,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  ok=run([])
  if ok.returncode: raise RuntimeError('sandbox test failed: '+ok.stderr)
  print(ok.stdout.strip())
  mutant=run(['--ro-bind',str(p/'private'),str(p/'private')])
  if mutant.returncode==0 or 'host file exposed:' not in mutant.stderr: raise AssertionError('negative control did not detect exposed secret: '+mutant.stderr)
  print('negative control exposed fake secret: correctly detected')
