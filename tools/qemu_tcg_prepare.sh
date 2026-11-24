#!/bin/sh
# Prepare an isolated tiny TCG boot fixture; no host service changes.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
base="$project/.local-test/qemu"
mkdir -p "$base/init/bin" "$base/init/dev" "$base/init/proc" "$base/init/sys"
if [ ! -f "$base/vmlinuz-virt" ]; then
 timeout --kill-after=2s 60s python3 - "$base/vmlinuz-virt.part" <<'PYCODE'
import sys, urllib.request
url='https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/netboot/vmlinuz-virt'
with urllib.request.urlopen(url,timeout=20) as response, open(sys.argv[1],'wb') as out:
 total=0
 while True:
  chunk=response.read(65536)
  if not chunk: break
  total+=len(chunk)
  if total>32*1024*1024: raise RuntimeError('kernel download exceeds 32 MiB')
  out.write(chunk)
PYCODE
 mv "$base/vmlinuz-virt.part" "$base/vmlinuz-virt"
fi
printf '%s  %s\n' be523954ad673a78c9cdfd3d473a8d39609f5901adfcc68402c67dc037a64c7e "$base/vmlinuz-virt" | sha256sum -c -
cp /usr/bin/busybox "$base/init/bin/busybox"
printf '#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc\n/bin/busybox echo CS_QEMU_TCG_GUEST_READY\nexec /bin/busybox sh\n' > "$base/init/init"
chmod 755 "$base/init/init"
(cd "$base/init" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 > "$base/initramfs.gz")
printf 'TCG fixture prepared: '; sha256sum "$base/initramfs.gz"
