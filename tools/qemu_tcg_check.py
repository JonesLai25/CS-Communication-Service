"""Isolated QEMU TCG boot; kill only the child started here, no disk/network."""
from resource_guard import enforce
enforce(144*1024*1024,32*1024*1024,24,204800)
import hashlib, os, pathlib, select, subprocess, time
root=pathlib.Path(__file__).resolve().parents[1]; data=root/'.local-test/qemu'
if hashlib.sha256((data/'vmlinuz-virt').read_bytes()).hexdigest()!='be523954ad673a78c9cdfd3d473a8d39609f5901adfcc68402c67dc037a64c7e': raise SystemExit('kernel SHA-256 mismatch')
mem={}
for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
 k,_,v=line.partition(':'); mem[k]=int(v.strip().split()[0])
if mem['MemAvailable'] < 200*1024: raise SystemExit('BLOCKED: host MemAvailable below 200 MiB; no VM launched')
cmd=['qemu-system-x86_64','-machine','accel=tcg','-m','64M','-smp','1','-no-reboot','-no-shutdown','-nographic','-monitor','none','-nic','none','-kernel',str(data/'vmlinuz-virt'),'-initrd',str(data/'initramfs.gz'),'-append','console=ttyS0 init=/init panic=-1']
print('host MemAvailable KiB:',mem['MemAvailable'],flush=True); print('qemu: TCG 1 vCPU, 64 MiB guest, no disk/network',flush=True)
p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
try:
 end=time.monotonic()+65; output=b''
 while time.monotonic()<end:
  if select.select([p.stdout],[],[],min(1,end-time.monotonic()))[0]:
   chunk=os.read(p.stdout.fileno(),65536)
   if not chunk: break
   output+=chunk
   if len(output)>2_000_000: raise RuntimeError('guest output exceeds limit')
   if b'CS_QEMU_TCG_GUEST_READY' in output:
    print('guest boot marker: CS_QEMU_TCG_GUEST_READY'); print('TCG boot: PASS'); break
  if p.poll() is not None: break
 else: raise TimeoutError('VM boot deadline')
 if b'CS_QEMU_TCG_GUEST_READY' not in output:
  print('qemu exit status:',p.poll()); cg=pathlib.Path('/sys/fs/cgroup')/pathlib.Path(pathlib.Path('/proc/self/cgroup').read_text().strip().split(':')[-1].lstrip('/')); print('memory.events:',(cg/'memory.events').read_text()); print(output[-12000:].decode(errors='replace')); raise RuntimeError('guest did not boot')
finally:
 if p.poll() is None:
  p.terminate()
  try: p.wait(timeout=5)
  except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
 p.stdout.close(); p.stdin.close()
