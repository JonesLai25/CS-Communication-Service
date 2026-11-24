#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
case "${1:-compressible}" in compressible|incompressible) mode=${1:-compressible};; *) exit 2;; esac
[ "$#" -le 1 ] || exit 2
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ -n "$available" ] && [ "$available" -ge 300000 ] || { echo 'host memory guard refused test' >&2; exit 1; }
[ "$(df -Pk /tmp | awk 'NR==2 {print $4}')" -ge 524288 ] || { echo 'insufficient test storage' >&2; exit 1; }
if [ "${CS_LARGE_SCOPE:-}" != 1 ]; then
 exec systemd-run --user --scope --quiet -p MemoryMax=144M -p MemorySwapMax=128M -p TasksMax=64 env CS_LARGE_SCOPE=1 "$0" "$mode"
fi
cg=$(awk -F: '$1=="0" {print $3}' /proc/self/cgroup)
[ "$(cat "/sys/fs/cgroup$cg/memory.max")" = 150994944 ] && [ "$(cat "/sys/fs/cgroup$cg/memory.swap.max")" = 134217728 ] && [ "$(cat "/sys/fs/cgroup$cg/pids.max")" = 64 ] || { echo 'scope limits not verified' >&2; exit 1; }
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
printf 'scope memory.max=150994944 swap.max=134217728 pids.max=64 CPU=%s\n' "$cpu"
"$project/.venv/bin/python" "$project/tools/run_phase3_large.py" "$mode"
