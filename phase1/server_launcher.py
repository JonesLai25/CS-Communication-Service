"""Route non-root Server initialization, foreground launch and local administration."""
import argparse,json,os,pathlib,sys
from service_cli import load_config
from install_runtime import hold

def main():
 p=argparse.ArgumentParser(); p.add_argument('--prefix',required=True); p.add_argument('action',choices=('initialize','serve','admin','health','unit')); p.add_argument('args',nargs=argparse.REMAINDER); a=p.parse_args()
 root=pathlib.Path(a.prefix)
 if not root.is_absolute(): raise ValueError('invalid install prefix')
 if a.action=='unit':
  import subprocess
  from service_control import install_unit,remove_unit,systemctl
  q=argparse.ArgumentParser(); q.add_argument('operation',choices=('install','remove','start','stop','restart','status','enable','disable')); q.add_argument('--mode',choices=('user','system'),default='user'); q.add_argument('--service-user',default='csservice'); b=q.parse_args(a.args)
  directory=pathlib.Path(os.environ.get('XDG_CONFIG_HOME',str(pathlib.Path.home()/'.config')))/'systemd/user' if b.mode=='user' else pathlib.Path('/etc/systemd/system')
  if b.operation=='install':
   result=install_unit(root,directory,b.mode,b.service_user)
   subprocess.run(['/usr/bin/systemctl','--user' if b.mode=='user' else '--system','daemon-reload'],check=True,timeout=30); print(result); return
  if b.operation=='remove':
   remove_unit(root,directory,b.mode,b.service_user)
   subprocess.run(['/usr/bin/systemctl','--user' if b.mode=='user' else '--system','daemon-reload'],check=True,timeout=30); print('removed'); return
  print(systemctl(root,directory,b.mode,b.operation,b.service_user),end=''); return
 if os.geteuid()==0: raise SystemExit('Server must run as non-root')
 hold(root); here=pathlib.Path(__file__).resolve().parent; config=root/'config/server.json'
 if a.action=='initialize': target='initialize_service.py'; args=['--data',str(root/'data'),'--config',str(root/'config'),*a.args]
 elif a.action=='serve': target='service_cli.py'; args=['--config',str(config)]
 elif a.action=='admin':
  settings=load_config(config)
  if 'admin_socket' not in settings: raise ValueError('admin socket is not configured')
  target='admin_cli.py'; args=['--socket',settings['admin_socket'],*a.args]
 else:
  if a.args: raise ValueError('health takes no arguments')
  from client import health
  settings=load_config(config)
  if not settings['port']: raise ValueError('health requires a fixed configured port')
  print(json.dumps(health('localhost',settings['port'],settings['cert']))); return
 os.execv(sys.executable,[sys.executable,'-B',str(here/target),*args])
if __name__=='__main__': main()
