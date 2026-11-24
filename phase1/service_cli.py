"""Launch a configured CS server without elevating its runtime identity."""
import argparse,ipaddress,json,os,pathlib,stat,sys

REQUIRED={'cert','key','db','port'}
OPTIONAL={'admin_socket','transfer_master','transfer_root','package_root','resume_root','exec_root','exec_policy','pending_upload_mib','audit_retention_days','audit_max_records','storage_capacity_mib','listen','exec_result_retention_days'}

def load_config(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_size>16384: raise ValueError('unsafe server configuration')
  raw=os.read(fd,16385)
 finally: os.close(fd)
 def unique(pairs):
  out={}
  for key,value in pairs:
   if key in out: raise ValueError('duplicate configuration key')
   out[key]=value
  return out
 data=json.loads(raw,object_pairs_hook=unique)
 if not isinstance(data,dict) or not REQUIRED<=set(data) or set(data)-REQUIRED-OPTIONAL: raise ValueError('invalid server configuration')
 if type(data['port']) is not int or not 0<=data['port']<=65535: raise ValueError('invalid port')
 if 'pending_upload_mib' in data and (type(data['pending_upload_mib']) is not int or not 1<=data['pending_upload_mib']<=4096): raise ValueError('invalid upload reservation limit')
 if 'audit_retention_days' in data and (type(data['audit_retention_days']) is not int or not 1<=data['audit_retention_days']<=3650): raise ValueError('invalid audit retention')
 if 'listen' in data:
  if not isinstance(data['listen'],str): raise ValueError('invalid IPv4 listen address')
  try: ipaddress.IPv4Address(data['listen'])
  except ipaddress.AddressValueError as e: raise ValueError('invalid IPv4 listen address') from e
 if 'exec_result_retention_days' in data and (type(data['exec_result_retention_days']) is not int or not 1<=data['exec_result_retention_days']<=3650): raise ValueError('invalid execution retention')
 if 'storage_capacity_mib' in data and (type(data['storage_capacity_mib']) is not int or not 16<=data['storage_capacity_mib']<=1048576): raise ValueError('invalid storage capacity limit')
 if 'audit_max_records' in data and (type(data['audit_max_records']) is not int or not 100<=data['audit_max_records']<=1000000): raise ValueError('invalid audit limit')
 for name,value in data.items():
  if name in ('port','pending_upload_mib','audit_retention_days','audit_max_records','storage_capacity_mib','listen','exec_result_retention_days'): continue
  if not isinstance(value,str) or not pathlib.Path(value).is_absolute() or '\0' in value or len(value)>4096: raise ValueError('invalid configuration path')
 return data

def main():
 p=argparse.ArgumentParser(); p.add_argument('--config',required=True); a=p.parse_args()
 if os.geteuid()==0: raise SystemExit('server must run as non-root')
 data=load_config(a.config); command=[sys.executable,'-B',str(pathlib.Path(__file__).resolve().with_name('server.py'))]
 if 'storage_capacity_mib' not in data: raise SystemExit('storage_capacity_mib is required: configure an administrator-provisioned bounded filesystem')
 for name,value in data.items(): command.extend(['--'+name.replace('_','-'),str(value)])
 os.execv(sys.executable,command)
if __name__=='__main__': main()
