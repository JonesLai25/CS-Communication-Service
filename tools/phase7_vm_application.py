"""Real CS journal code in an isolated VM with abrupt virtual power interruption.

A 384 MiB disposable ext4 image is populated with mkfs; no host mount,
network, service stop or host power operation is performed. The guest drops to
UID 1000 before invoking CS code. This does not prove physical power-loss safety.
"""
from resource_guard import enforce
enforce(192*1024*1024,32*1024*1024,24,400000)
import gzip,hashlib,os,pathlib,re,select,shutil,subprocess,tarfile,tempfile,time,zipfile
root=pathlib.Path(__file__).resolve().parents[1]; base=root/'.local-test/qemu-phase4/modules'; kernel=base/'boot/vmlinuz-virt'
if hashlib.sha256(kernel.read_bytes()).hexdigest()!='d341acf38aca9f9af67641e3241ef1075c0368a59774485fa076f271182e8c00': raise SystemExit('unexpected VM kernel')
module_base=base/'lib/modules/6.6.142-0-virt/kernel'
modules=[('virtio_blk','drivers/block/virtio_blk.ko.gz','e96740ec5ba167b6b00e239c6e91f727f711411681924f7128dde65537c05cbc'),('crc32c_generic','crypto/crc32c_generic.ko.gz','4f260bb6df2f45d1d865738fbab8d83bc02b7ea029b11ee9b1b661eb1301204e'),('crc16','lib/crc16.ko.gz','afa278249dc0708f30eb2894f54676010bf96565d7a665a742358ef1ff20602d'),('mbcache','fs/mbcache.ko.gz','278f2c8107cf337726e940ac78a0bc21dbde60856bb38b3de0e7f3579d6a5dae'),('jbd2','fs/jbd2/jbd2.ko.gz','48f5bfc4e545d81c27c90ff92b91f3f491ce72b6e987086a2b84e58945fc0236'),('ext4','fs/ext4/ext4.ko.gz','e0761f3b57cd4a0c64ee6e787623afe413f8b8c98e2f9d66f26ea5b4fe05af4c')]
with tempfile.TemporaryDirectory(prefix='cs-phase7-app-vm-') as d:
 p=pathlib.Path(d); stage=p/'stage'; env=stage/'env'; env.mkdir(parents=True)
 shutil.copytree(root/'.local-test/python312',env/'python',symlinks=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc','test','tests','ensurepip','pip','pip-*','include','share'))
 site=env/'python/lib/python3.12/site-packages'; site.mkdir(parents=True,exist_ok=True)
 lock=(root/'phase3/requirements-ubuntu20-py312.lock').read_text().splitlines(); expected={}
 for line in lock:
  a,b=line.split(' --hash=sha256:'); expected[a.lower().replace('_','-')]=b
 for wheel in sorted((root/'.local-test/ubuntu20-py312-wheels').glob('*.whl')):
  bits=wheel.name.split('-'); name=(bits[0]+'=='+bits[1]).lower().replace('_','-'); digest=hashlib.sha256(wheel.read_bytes()).hexdigest()
  if expected.get(name)!=digest: raise RuntimeError('wheel lock mismatch: '+wheel.name)
  with zipfile.ZipFile(wheel) as z:
   for item in z.infolist():
    path=pathlib.PurePosixPath(item.filename)
    if path.is_absolute() or '..' in path.parts or ((item.external_attr>>16)&0o170000)==0o120000: raise RuntimeError('unsafe wheel entry')
   z.extractall(site)
  del expected[name]
 if expected: raise RuntimeError('missing locked wheels')
 shutil.copytree(root/'phase1',env/'phase1',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
 shutil.copy2(root/'phase4/vm_guest.py',env/'vm_guest.py')
 swap=p/'swap.img'
 with open(swap,'wb') as f: f.truncate(64*1024*1024)
 os.chmod(swap,0o600)
 subprocess.run(['/usr/sbin/mkswap',str(swap)],check=True,timeout=20)
 disk=p/'disk.img'
 with open(disk,'wb') as f: f.truncate(384*1024*1024)
 # Populate only the newly created image without mounting it on the host.
 subprocess.run(['/usr/sbin/mkfs.ext4','-q','-F','-d',str(stage),str(disk)],check=True,timeout=60)
 with open(disk,'rb') as f: os.posix_fadvise(f.fileno(),0,0,os.POSIX_FADV_DONTNEED)
 def initramfs(mode):
  init=p/('init-'+mode); (init/'bin').mkdir(parents=True)
  for name in ('dev','proc','sys','mnt','tmp','lib/x86_64-linux-gnu','lib64'): (init/name).mkdir(parents=True,exist_ok=True)
  shutil.copy2('/usr/bin/busybox',init/'bin/busybox')
  for name,relative,digest in modules:
   compressed=(module_base/relative).read_bytes()
   if hashlib.sha256(compressed).hexdigest()!=digest: raise RuntimeError('unexpected module: '+name)
   (init/'bin'/(name+'.ko')).write_bytes(gzip.decompress(compressed))
  libs=['libc.so.6','libm.so.6','libdl.so.2','libpthread.so.0','librt.so.1','libutil.so.1','libgcc_s.so.1','libcrypt.so.1']
  for name in libs: shutil.copyfile('/lib/x86_64-linux-gnu/'+name,init/'lib/x86_64-linux-gnu'/name)
  shutil.copyfile('/lib64/ld-linux-x86-64.so.2',init/'lib64/ld-linux-x86-64.so.2')
  (init/'lib64/ld-linux-x86-64.so.2').chmod(0o755)
  script='''#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox insmod /bin/virtio_blk.ko
/bin/busybox swapon /dev/vdb || { /bin/busybox echo CS_VM_SWAP_FAILED; exec /bin/busybox sh; }
/bin/busybox echo CS_VM_PRIVATE_SWAP_OK
/bin/busybox insmod /bin/crc32c_generic.ko
/bin/busybox insmod /bin/crc16.ko
/bin/busybox insmod /bin/mbcache.ko
/bin/busybox insmod /bin/jbd2.ko
/bin/busybox insmod /bin/ext4.ko
/bin/busybox mount -t ext4 /dev/vda /mnt || { /bin/busybox echo CS_VM_MOUNT_FAIL; exec /bin/busybox sh; }
if [ ! -d /mnt/env ]; then /bin/busybox echo CS_VM_UNPACK_FAIL; exec /bin/busybox sh; fi
if [ ! -d /mnt/work ]; then /bin/busybox mkdir -m 700 /mnt/work; /bin/busybox chown 1000:1000 /mnt/work; /bin/busybox sync; fi
export TMPDIR=/mnt/work
/mnt/env/python/bin/python3 /mnt/env/vm_guest.py MODE
/bin/busybox echo CS_VM_PYTHON_FAILED
exec /bin/busybox sh
'''.replace(' MODE\n',' '+mode+'\n')
  (init/'init').write_text(script); (init/'init').chmod(0o755); path=p/('initrd-'+mode)
  with open(path,'wb') as archive:
   cpio=subprocess.Popen(['cpio','-o','--format=newc'],cwd=str(init),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
   gz=subprocess.Popen(['gzip','-1'],stdin=cpio.stdout,stdout=archive); cpio.stdout.close()
   names=['.']+['./'+str(x.relative_to(init)) for x in sorted(init.rglob('*'))]
   cpio.communicate(('\n'.join(names)+'\n').encode(),timeout=30)
   if cpio.returncode or gz.wait(timeout=30): raise RuntimeError('initramfs build failed')
  return path
 def boot(mode,marker):
  args=['qemu-system-x86_64','-machine','pc','-accel','tcg,tb-size=16','-m','80M','-smp','1','-no-reboot','-no-shutdown','-nographic','-monitor','none','-nic','none','-kernel',str(kernel),'-initrd',str(initramfs(mode)),'-drive','file='+str(disk)+',format=raw,if=virtio,cache=none','-drive','file='+str(swap)+',format=raw,if=virtio,cache=none','-append','console=ttyS0 init=/init panic=-1']
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
  try:
   output=bytearray(); end=time.monotonic()+150
   while time.monotonic()<end:
    if select.select([proc.stdout],[],[],1)[0]:
     part=os.read(proc.stdout.fileno(),65536)
     if not part: break
     output.extend(part)
     if len(output)>2_000_000: raise RuntimeError('guest output too large')
     if marker.encode() in output or b'CS_VM_PYTHON_FAILED' in output or b'CS_VM_MOUNT_FAIL' in output or b'CS_VM_UNPACK_FAIL' in output or b'CS_VM_SWAP_FAILED' in output: break
    if proc.poll() is not None: break
   if marker.encode() not in output:
    print(output[-10000:].decode(errors='replace'),flush=True)
    print('QEMU exit status:',proc.poll(),flush=True)
    cg=pathlib.Path('/sys/fs/cgroup')/pathlib.Path(open('/proc/self/cgroup').read().strip().split(':')[-1].lstrip('/'))
    print('scope memory.events:',(cg/'memory.events').read_text(),flush=True)
    raise RuntimeError('guest marker missing: '+marker)
   print(mode+': '+marker,flush=True)
  finally:
   if proc.poll() is None: proc.kill(); proc.wait(timeout=5)
   proc.stdin.close(); proc.stdout.close()
  if proc.returncode!=-9: raise RuntimeError('unexpected QEMU termination')
  print('terminated only test-owned QEMU: SIGKILL',flush=True)
 for mode,marker in [('setup','CS_VM_PREPARED_NONROOT'),('before','CS_VM_BEFORE_PUBLISH'),('after','CS_VM_AFTER_RENAME'),('verify','CS_VM_RECOVERY_OK_NONROOT')]: boot(mode,marker)
 print('CS core isolated VM abrupt power model: PASS; physical power loss and production deployment: UNVERIFIED',flush=True)
