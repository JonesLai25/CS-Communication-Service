"""Abruptly terminate only disposable QEMU guests; filesystem model, not CS application power acceptance."""
from resource_guard import enforce
enforce(144*1024*1024,32*1024*1024,24,400000)
import gzip,hashlib,os,pathlib,select,shutil,subprocess,tempfile,time
root=pathlib.Path(__file__).resolve().parents[1]; base=root/'.local-test/qemu-phase4/modules'; kernel=base/'boot/vmlinuz-virt'
if hashlib.sha256(kernel.read_bytes()).hexdigest()!='d341acf38aca9f9af67641e3241ef1075c0368a59774485fa076f271182e8c00': raise SystemExit('unexpected kernel')
module_base=base/'lib/modules/6.6.142-0-virt/kernel'
modules=[('virtio_blk','drivers/block/virtio_blk.ko.gz','e96740ec5ba167b6b00e239c6e91f727f711411681924f7128dde65537c05cbc'),('crc32c_generic','crypto/crc32c_generic.ko.gz','4f260bb6df2f45d1d865738fbab8d83bc02b7ea029b11ee9b1b661eb1301204e'),('crc16','lib/crc16.ko.gz','afa278249dc0708f30eb2894f54676010bf96565d7a665a742358ef1ff20602d'),('mbcache','fs/mbcache.ko.gz','278f2c8107cf337726e940ac78a0bc21dbde60856bb38b3de0e7f3579d6a5dae'),('jbd2','fs/jbd2/jbd2.ko.gz','48f5bfc4e545d81c27c90ff92b91f3f491ce72b6e987086a2b84e58945fc0236'),('ext4','fs/ext4/ext4.ko.gz','e0761f3b57cd4a0c64ee6e787623afe413f8b8c98e2f9d66f26ea5b4fe05af4c')]
with tempfile.TemporaryDirectory(prefix='cs-phase4-power-vm-') as d:
 p=pathlib.Path(d); disk=p/'disk.img'
 with open(disk,'wb') as f: f.truncate(32*1024*1024)
 subprocess.run(['/usr/sbin/mkfs.ext4','-q','-F',str(disk)],check=True,timeout=20)
 def initramfs(mode):
  init=p/('init-'+mode); (init/'bin').mkdir(parents=True)
  for name in ('dev','proc','sys','mnt'): (init/name).mkdir()
  shutil.copy2('/usr/bin/busybox',init/'bin/busybox')
  for name,relative,digest in modules:
   compressed=(module_base/relative).read_bytes()
   if hashlib.sha256(compressed).hexdigest()!=digest: raise RuntimeError('unexpected module: '+name)
   (init/'bin'/(name+'.ko')).write_bytes(gzip.decompress(compressed))
  setup="""#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox insmod /bin/virtio_blk.ko
/bin/busybox insmod /bin/crc32c_generic.ko
/bin/busybox insmod /bin/crc16.ko
/bin/busybox insmod /bin/mbcache.ko
/bin/busybox insmod /bin/jbd2.ko
/bin/busybox insmod /bin/ext4.ko
/bin/busybox mount -t ext4 /dev/vda /mnt || { /bin/busybox echo VM_FAIL_MOUNT; exec /bin/busybox sh; }
"""
  scripts={
   'before':"/bin/busybox printf 'partial' > /mnt/pending\n/bin/busybox sync\n/bin/busybox echo VM_BEFORE_PUBLISH\n",
   'recover-before':"if [ -f /mnt/pending ] && [ ! -e /mnt/final ]; then /bin/busybox rm /mnt/pending; /bin/busybox sync; /bin/busybox echo VM_RECOVER_BEFORE_OK; else /bin/busybox echo VM_FAIL_RECOVER_BEFORE; fi\n",
   'after':"/bin/busybox printf 'complete-test-data' > /mnt/pending\n/bin/busybox sync\n/bin/busybox mv /mnt/pending /mnt/final\n/bin/busybox sync\n/bin/busybox echo VM_AFTER_PUBLISH\n",
   'recover-after':"if [ \"$(/bin/busybox cat /mnt/final)\" = 'complete-test-data' ] && [ ! -e /mnt/pending ]; then /bin/busybox echo VM_RECOVER_AFTER_OK; else /bin/busybox echo VM_FAIL_RECOVER_AFTER; fi\n"}
  (init/'init').write_text(setup+scripts[mode]+'exec /bin/busybox sh\n'); (init/'init').chmod(0o755)
  path=p/('initramfs-'+mode)
  with open(path,'wb') as archive:
   cpio=subprocess.Popen(['cpio','-o','--format=newc'],cwd=str(init),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
   gz=subprocess.Popen(['gzip','-1'],stdin=cpio.stdout,stdout=archive); cpio.stdout.close()
   listing=['.','./bin','./bin/busybox']+['./bin/'+name+'.ko' for name,_,_ in modules]+['./dev','./proc','./sys','./mnt','./init']
   cpio.communicate(('\n'.join(listing)+'\n').encode(),timeout=20)
   if cpio.returncode or gz.wait(timeout=20): raise RuntimeError('initramfs build failed')
  return path
 def boot(mode,marker):
  args=['qemu-system-x86_64','-machine','accel=tcg','-m','64M','-smp','1','-no-reboot','-no-shutdown','-nographic','-monitor','none','-nic','none','-kernel',str(kernel),'-initrd',str(initramfs(mode)),'-drive','file='+str(disk)+',format=raw,if=virtio,cache=writeback','-append','console=ttyS0 init=/init panic=-1']
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
  try:
   output=bytearray(); end=time.monotonic()+65
   while time.monotonic()<end:
    if select.select([proc.stdout],[],[],1)[0]:
     part=os.read(proc.stdout.fileno(),65536)
     if not part: break
     output.extend(part)
     if len(output)>2_000_000: raise RuntimeError('guest output exceeds limit')
     if marker.encode() in output: break
    if proc.poll() is not None: break
   if marker.encode() not in output:
    print(output[-5000:].decode(errors='replace'),flush=True); raise RuntimeError('guest marker missing: '+marker)
   print(mode+': '+marker,flush=True)
  finally:
   if proc.poll() is None:
    proc.kill()
    proc.wait(timeout=5)
   proc.stdin.close(); proc.stdout.close()
  if proc.returncode!=-9: raise RuntimeError('unexpected QEMU termination')
  print('terminated only test-owned QEMU process: SIGKILL',flush=True)
 boot('before','VM_BEFORE_PUBLISH'); boot('recover-before','VM_RECOVER_BEFORE_OK')
 boot('after','VM_AFTER_PUBLISH'); boot('recover-after','VM_RECOVER_AFTER_OK')
 print('isolated VM abrupt termination filesystem model: PASS; physical power loss and CS application acceptance: UNVERIFIED')
