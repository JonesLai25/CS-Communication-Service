"""Render explicit User/System units; never invokes systemctl itself."""
import os,pathlib,re

def _arg(value):
 value=str(value)
 if not value or any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError('invalid systemd argument')
 return '"'+value.replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('$','$$')+'"'

def render(prefix,config,mode,service_user='csservice'):
 prefix=pathlib.Path(prefix); config=pathlib.Path(config)
 if not prefix.is_absolute() or not config.is_absolute() or mode not in ('user','system'): raise ValueError('invalid unit parameters')
 if config!=prefix/'config/server.json': raise ValueError('configuration must belong to the installation')
 if mode=='system' and (not re.fullmatch('[a-z_][a-z0-9_-]{0,30}',service_user) or service_user=='root'): raise ValueError('invalid service account')
 cmd=' '.join(map(_arg,(prefix/'bin/cs-server','serve')))
 service=['[Unit]','Description=CS Communication Service','After=network.target','','[Service]','Type=simple']
 if mode=='system': service.extend(['User='+service_user,'Group='+service_user])
 service+=['ExecStart='+cmd,'Restart=on-failure','RestartSec=2','NoNewPrivileges=yes','UMask=0077','TimeoutStopSec=30','','[Install]', 'WantedBy='+('default.target' if mode=='user' else 'multi-user.target'),'']
 return '\n'.join(service)

def sysusers(service_user='csservice'):
 if not re.fullmatch('[a-z_][a-z0-9_-]{0,30}',service_user) or service_user=='root': raise ValueError('invalid service account')
 return 'u '+service_user+' - "CS Communication Service" /nonexistent /usr/sbin/nologin\n'
