#!/bin/sh
# Prepare only this project's rootless image storage; never alter global Podman config.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
uid=$(id -u)
[ "$uid" -ne 0 ] || { echo 'refusing root' >&2; exit 1; }
[ "$#" -eq 0 ] || { echo 'no arguments expected' >&2; exit 2; }
case "$project" in *,*) echo 'project path containing comma is unsupported' >&2; exit 1;; esac
if [ "${CS_LOCAL_TEST_SCOPE:-}" != 1 ]; then
 exec systemd-run --user --scope --quiet -p MemoryMax=192M -p MemorySwapMax=128M -p TasksMax=64 -p Delegate=yes env CS_LOCAL_TEST_SCOPE=1 "$0"
fi
cg=$(awk -F: '$1=="0" {print $3}' /proc/self/cgroup)
[ -n "$cg" ] && [ -r "/sys/fs/cgroup$cg/memory.max" ] && [ -r "/sys/fs/cgroup$cg/pids.max" ] || { echo 'cannot verify cgroup budget' >&2; exit 1; }
mem=$(cat "/sys/fs/cgroup$cg/memory.max"); swap=$(cat "/sys/fs/cgroup$cg/memory.swap.max"); pids=$(cat "/sys/fs/cgroup$cg/pids.max")
case "$mem:$swap:$pids" in *[!0-9:]*|:*) echo 'unbounded cgroup; refusing setup' >&2; exit 1;; esac
[ "$mem" -le 201326592 ] && [ "$swap" -le 134217728 ] && [ "$pids" -le 64 ] || { echo 'cgroup budget exceeds limits' >&2; exit 1; }
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')
taskset -pc "$cpu" "$$" >/dev/null
[ "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)" = "$cpu" ] || { echo 'cannot verify CPU affinity' >&2; exit 1; }
printf 'verified one-CPU affinity=%s, swap.max=%s\n' "$cpu" "$swap"
runtime="/tmp/cs-podman-$uid"
[ ! -L "$runtime" ] || { echo 'runtime path is a symlink' >&2; exit 1; }
umask 077
mkdir -p "$project/.local-test/abs-graph" "$runtime/run" "$runtime/tmp"
[ "$(stat -c %u "$runtime")" = "$uid" ] || { echo 'runtime path has wrong owner' >&2; exit 1; }
chmod 700 "$runtime" "$runtime/run" "$runtime/tmp" "$project/.local-test" "$project/.local-test/abs-graph"
if ! graph_report=$(timeout --kill-after=2s 15s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file unshare du -sk "$project/.local-test/abs-graph"); then
 echo 'cannot verify project image store size' >&2; exit 1
fi
graph_kib=$(printf '%s\n' "$graph_report" | awk '{print $1}')
case "$graph_kib" in *[!0-9]*|'') echo 'invalid store size' >&2; exit 1;; esac
[ "$graph_kib" -le 524288 ] || { echo 'project image store exceeds 512 MiB budget' >&2; exit 1; }
available_kib=$(df -Pk "$project/.local-test/abs-graph" | awk 'NR==2 {print $4}')
[ "$available_kib" -ge 524288 ] || { echo 'less than 512 MiB free; refusing test' >&2; exit 1; }
podman_cs() { timeout --kill-after=5s 120s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file "$@"; }
image=bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731
if podman_cs image exists "$image"; then :; else
 rc=$?
 [ "$rc" -eq 1 ] || { echo 'image inventory failed; refusing pull' >&2; exit "$rc"; }
 podman_cs pull docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
fi
actual=$(podman_cs image inspect --format '{{.Id}}' "$image")
[ "$actual" = "$image" ] || { echo 'image ID mismatch' >&2; exit 1; }
printf 'isolated image verified: %s\n' "$actual"
