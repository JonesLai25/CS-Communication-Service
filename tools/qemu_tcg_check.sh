#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
if [ "${CS_QEMU_SCOPE:-}" != 1 ]; then
 exec systemd-run --user --scope --quiet -p MemoryMax=144M -p MemorySwapMax=32M -p TasksMax=24 -p Delegate=yes env CS_QEMU_SCOPE=1 "$0"
fi
cg=$(awk -F: '$1=="0" {print $3}' /proc/self/cgroup)
mem=$(cat "/sys/fs/cgroup$cg/memory.max"); swap=$(cat "/sys/fs/cgroup$cg/memory.swap.max"); pids=$(cat "/sys/fs/cgroup$cg/pids.max")
case "$mem:$swap:$pids" in *[!0-9:]*|:*) echo 'unbounded cgroup' >&2; exit 1;; esac
[ "$mem" -le 150994944 ] && [ "$swap" -le 33554432 ] && [ "$pids" -le 24 ] || { echo 'budget check failed' >&2; exit 1; }
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
printf 'scope memory.max=%s swap.max=%s pids.max=%s CPU=%s\n' "$mem" "$swap" "$pids" "$cpu"
exec python3 "$project/tools/qemu_tcg_check.py"
