"""Local administrator client; OTP output must be transferred over a trusted channel."""
import argparse,json,socket
p=argparse.ArgumentParser(); p.add_argument('--socket',required=True); p.add_argument('op',choices=['user_add','user_list','user_disable','otp_create','otp_revoke','device_list','device_revoke']); p.add_argument('--owner'); p.add_argument('--device'); p.add_argument('--ttl',type=int,default=300); a=p.parse_args()
data={'op':a.op}
if a.owner is not None: data['owner']=a.owner
if a.device is not None: data['device']=a.device
if a.op=='otp_create': data['ttl']=a.ttl
with socket.socket(socket.AF_UNIX) as s:
 s.settimeout(3); s.connect(a.socket); s.sendall(json.dumps(data).encode()+b'\n'); stream=s.makefile('rb'); raw=stream.readline(4097)
 if not raw.endswith(b'\n') or len(raw)>4096: raise SystemExit('invalid admin response')
 result=json.loads(raw)
 if 'error' in result: raise SystemExit('admin operation failed: '+result['error'])
 print(json.dumps(result))
