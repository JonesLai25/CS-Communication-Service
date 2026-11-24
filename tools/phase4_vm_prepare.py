"""Extract only pinned Alpine kernel artifacts into this project's ignored test area.

Pass the official linux-virt-6.6.142-r0.apk obtained separately. No system
packages are installed and no pre-existing host files are overwritten.
"""
import hashlib,pathlib,sys,tarfile,tempfile,os
root=pathlib.Path(__file__).resolve().parents[1]; source=pathlib.Path(sys.argv[1]); target=root/'.local-test/qemu-phase4/modules'
if hashlib.sha256(source.read_bytes()).hexdigest()!='0d84e30c04c52426b0bf10b01616c45f7d0c5384a59552e4c4a6caeb13a3f6e7': raise SystemExit('unexpected APK hash')
wanted=['boot/vmlinuz-virt']+['lib/modules/6.6.142-0-virt/kernel/'+x for x in ('drivers/block/virtio_blk.ko.gz','crypto/crc32c_generic.ko.gz','lib/crc16.ko.gz','fs/mbcache/mbcache.ko.gz','fs/jbd2/jbd2.ko.gz','fs/ext4/ext4.ko.gz')]
# mbcache resides under fs/mbcache on some packages; match the validated probe path.
wanted[4]='lib/modules/6.6.142-0-virt/kernel/fs/mbcache.ko.gz'
with tarfile.open(source,'r:gz') as tar:
 for name in wanted:
  entry=tar.getmember(name)
  if not entry.isfile() or entry.size>40*1024*1024: raise SystemExit('invalid kernel artifact')
  data=tar.extractfile(entry).read(); path=target/name; path.parent.mkdir(parents=True,exist_ok=True)
  if path.exists():
   if path.read_bytes()!=data: raise SystemExit('refusing to overwrite different artifact')
  else:
   with open(path,'xb') as out: out.write(data)
print('pinned VM kernel artifacts prepared; per-file hashes are verified by the VM runner')
