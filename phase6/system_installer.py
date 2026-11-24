"""Administrator-only System Mode installer. Does not invoke sudo or start a service."""
import argparse,grp,json,os,pathlib,pwd,re,subprocess,sys
from installer import InstallError,install,uninstall
from service_control import install_unit,remove_unit

def account(name, create=True):
 if os.geteuid()!=0: raise InstallError('system mode requires an administrator')
 if not isinstance(name,str) or not re.fullmatch('[a-z_][a-z0-9_-]{0,30}',name) or name=='root': raise InstallError('invalid service account')
 try: entry=pwd.getpwnam(name)
 except KeyError:
  if not create: raise InstallError('service account does not exist')
  cmd=['/usr/sbin/useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',name]
  result=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
  if result.returncode: raise InstallError('dedicated account creation failed: '+result.stderr[-500:])
  entry=pwd.getpwnam(name)
 if entry.pw_uid<=0 or entry.pw_gid<=0 or entry.pw_dir!='/nonexistent' or entry.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin','/bin/false') or grp.getgrgid(entry.pw_gid).gr_name!=name: raise InstallError('existing service account is not an isolated non-root identity with its own group')
 return entry

def install_system(prefix,python,wheelhouse,lock,name='csservice',port=18443,enable_exec=False,unit_directory='/etc/systemd/system'):
 entry=account(name)
 result=install(prefix,python,wheelhouse,lock,'system',entry.pw_uid,entry.pw_gid)
 args=['/usr/sbin/runuser','-u',name,'--',str(pathlib.Path(prefix)/'bin/cs-server'),'initialize','--port',str(port)]
 if enable_exec: args.append('--enable-exec')
 setup=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
 if setup.returncode: raise InstallError('non-root identity initialization failed: '+setup.stderr[-1000:])
 unit=install_unit(prefix,unit_directory,'system',name)
 return {'status':result['status'],'unit':str(unit),'service_uid':entry.pw_uid,'service_started':False,'note':'administrator must reload systemd and arrange a user manager for sandbox execution'}

def main():
 p=argparse.ArgumentParser(); p.add_argument('action',choices=('install','uninstall')); p.add_argument('--prefix',required=True); p.add_argument('--python',default=sys.executable); p.add_argument('--wheelhouse'); p.add_argument('--lock'); p.add_argument('--service-user',default='csservice'); p.add_argument('--port',type=int,default=18443); p.add_argument('--enable-exec',action='store_true'); a=p.parse_args()
 if a.action=='install':
  if not a.wheelhouse or not a.lock: p.error('install requires --wheelhouse and --lock')
  result=install_system(a.prefix,a.python,a.wheelhouse,a.lock,a.service_user,a.port,a.enable_exec)
 else:
  entry=account(a.service_user,False); result=uninstall(a.prefix,'system',entry.pw_uid,entry.pw_gid)
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try: main()
 except (OSError,ValueError,InstallError,subprocess.TimeoutExpired) as e: print(type(e).__name__+': '+str(e),file=sys.stderr); sys.exit(1)
