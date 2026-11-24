"""Actual non-owner Unix-socket denial; all files and processes are test-owned."""
import os,pathlib,socket,subprocess,sys,tempfile,threading
project=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(project/'phase1'))
from admin import Server
from registry import Registry
with tempfile.TemporaryDirectory(prefix='cs-admin-uid-') as d:
 r=Registry(d+'/db'); r.initialize(); server=Server(d+'/admin.sock',r); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
 try:
  runtime='/tmp/cs-podman-%d'%os.geteuid()
  code="import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(2);\ntry: s.connect(sys.argv[1])\nexcept PermissionError: print('non-owner socket access denied: PASS')\nelse: raise RuntimeError('non-owner connected')"
  args=['podman','--root',str(project/'.local-test/abs-graph'),'--runroot',runtime+'/run','--tmpdir',runtime+'/tmp','--storage-driver','overlay','--storage-opt','overlay.mount_program=/usr/bin/fuse-overlayfs','--cgroup-manager','cgroupfs','--events-backend','file','unshare','setpriv','--reuid=1000','--regid=1000','--clear-groups','/usr/bin/python3','-c',code,d+'/admin.sock']
  p=subprocess.run(args,check=True,capture_output=True,text=True,timeout=15); print(p.stdout.strip())
 finally: server.shutdown(); server.server_close(); thread.join(timeout=5)
