#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ -n "$available" ] && [ "$available" -ge 400000 ] || { echo 'host memory guard refused VM' >&2; exit 1; }
[ "$(df -Pk /tmp | awk 'NR==2 {print $4}')" -ge 524288 ] || exit 1
if [ "${CS_VM_SCOPE:-}" != 1 ]; then
 exec systemd-run --user --scope --quiet -p MemoryMax=192M -p MemorySwapMax=32M -p TasksMax=24 env CS_VM_SCOPE=1 "$0"
fi
cg=$(awk -F: '$1=="0" {print $3}' /proc/self/cgroup)
[ "$(cat "/sys/fs/cgroup$cg/memory.max")" = 201326592 ] && [ "$(cat "/sys/fs/cgroup$cg/memory.swap.max")" = 33554432 ] && [ "$(cat "/sys/fs/cgroup$cg/pids.max")" = 24 ] || exit 1
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
printf 'VM scope memory.max=201326592 swap.max=33554432 pids.max=24 CPU=%s; guest=80MiB; network=none; disposable disk=384MiB + private swap=64MiB\n' "$cpu"
exec python3 "$project/tools/phase7_vm_application.py"
