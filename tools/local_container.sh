#!/bin/sh
# Project-only rootless Podman test runner; no network, no host modifications.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
uid=$(id -u)
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ -n "$available" ] && [ "$available" -ge 300000 ] || { echo 'host available memory below 300000 KiB; refusing test' >&2; exit 1; }
[ "$uid" -ne 0 ] || { echo 'refusing to run as root' >&2; exit 1; }
[ -x "$project/.venv/bin/python" ] || { echo 'project .venv is missing; install pinned dependencies first' >&2; exit 1; }
case "$project" in *,*) echo 'project path containing comma is unsupported' >&2; exit 1;; esac
# Rootless Podman can silently ignore container limits without delegated controllers.
# Enforce the budget on a dedicated temporary user scope and verify it before running.
if [ "${CS_LOCAL_TEST_SCOPE:-}" != 1 ]; then
 exec systemd-run --user --scope --quiet -p MemoryMax=144M -p MemorySwapMax=128M -p TasksMax=64 -p Delegate=yes env CS_LOCAL_TEST_SCOPE=1 "$0" "$@"
fi
cg=$(awk -F: '$1=="0" {print $3}' /proc/self/cgroup)
[ -n "$cg" ] && [ -r "/sys/fs/cgroup$cg/memory.max" ] && [ -r "/sys/fs/cgroup$cg/pids.max" ] || { echo 'cannot verify cgroup budget' >&2; exit 1; }
mem=$(cat "/sys/fs/cgroup$cg/memory.max"); swap=$(cat "/sys/fs/cgroup$cg/memory.swap.max"); pids=$(cat "/sys/fs/cgroup$cg/pids.max")
case "$mem:$swap:$pids" in *[!0-9:]*|:*) echo 'unbounded cgroup; refusing test' >&2; exit 1;; esac
[ "$mem" -le 201326592 ] && [ "$swap" -le 134217728 ] && [ "$pids" -le 64 ] || { echo 'cgroup budget exceeds limits' >&2; exit 1; }
printf 'verified scope memory.max=%s pids.max=%s\n' "$mem" "$pids"
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
case "${1:-}" in
 smoke) shift; [ "$#" -eq 0 ] || exit 2; set -- /work/.venv/bin/python -B -c 'import sys,ssl,OpenSSL,service_identity; print(sys.version); print(ssl.OPENSSL_VERSION); print(OpenSSL.__version__); print("isolated-python-ok")'; limit=30 ;;
 phase4-mutations) shift; [ "$#" -eq 0 ] || exit 2; set -- /work/.venv/bin/python -B -O /work/phase4/test_mutation.py; limit=120 ;;
 phase4) shift; [ "$#" -eq 0 ] || exit 2; set -- /work/.venv/bin/python -B -O -m unittest discover -s phase4 -p 'test_resume*.py' -v; limit=240 ;;
 phase3-mutations) shift; [ "$#" -eq 0 ] || exit 2; set -- /work/.venv/bin/python -B -O /work/phase3/test_mutation.py; limit=120 ;;
 phase3) shift; [ "$#" -eq 0 ] || exit 2; set -- /work/.venv/bin/python -B -O -m unittest discover -s phase3 -p 'test_transfer*.py' -v; limit=240 ;;
 phase1) shift; [ "$#" -eq 0 ] || exit 2; set -- /work/.venv/bin/python -B -O -m unittest discover -s phase1 -p 'test*.py' -v; limit=240 ;;
 *) echo 'usage: local_container.sh smoke|phase1|phase3|phase3-mutations|phase4|phase4-mutations' >&2; exit 2 ;;
esac
test_dir=$(mktemp -d "$runtime/cs-test.XXXXXX")
cidfile="$test_dir/container.id"
remove_owned() {
 cid=$1
 [ "${#cid}" -eq 64 ] || { echo 'invalid test container ID length' >&2; return 1; }
 case "$cid" in *[!0-9a-f]*) echo 'invalid test container ID' >&2; return 1;; esac
 for attempt in 1 2 3; do
  if timeout --kill-after=2s 8s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file rm --force "$cid" >/dev/null 2>&1; then return 0; fi
  if timeout --kill-after=2s 8s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file container exists "$cid" >/dev/null 2>&1; then :; else
   rc=$?; [ "$rc" -eq 1 ] && return 0
   echo 'unable to verify container cleanup' >&2; return 1
  fi
 done
 echo 'test container remains; preserve its ID for diagnosis:' "$cid" >&2; return 1
}
cleanup_fuse_helpers() {
 # Only helpers in this unique test scope and pointing at this project's graph root.
 for helper_pid in $(cat "/sys/fs/cgroup$cg/cgroup.procs"); do
  [ -r "/proc/$helper_pid/comm" ] && [ "$(cat "/proc/$helper_pid/comm")" = fuse-overlayfs ] || continue
  if tr '\000' ' ' 2>/dev/null < "/proc/$helper_pid/cmdline" | grep -Fq "$project/.local-test/abs-graph/overlay/"; then
   kill -TERM "$helper_pid" 2>/dev/null || :
  fi
 done
 for attempt in 1 2 3 4 5 6 7 8 9 10; do
  left=0
  for helper_pid in $(cat "/sys/fs/cgroup$cg/cgroup.procs"); do
   [ -r "/proc/$helper_pid/comm" ] && [ "$(cat "/proc/$helper_pid/comm")" = fuse-overlayfs ] || continue
   if tr '\000' ' ' 2>/dev/null < "/proc/$helper_pid/cmdline" | grep -Fq "$project/.local-test/abs-graph/overlay/"; then left=1; fi
  done
  [ "$left" -eq 0 ] && return 0
  sleep 0.2
 done
 echo 'project test FUSE helper did not exit' >&2; return 1
}
cleanup() {
 if [ -s "$cidfile" ]; then
  cid=$(cat "$cidfile")
  remove_owned "$cid" || return 1
 fi
 cleanup_fuse_helpers || return 1
 rm -rf -- "$test_dir"
}
on_exit() { result=$?; trap - EXIT; cleanup || result=1; exit "$result"; }
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --kill-after=5s "$limit" podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file run --rm --cidfile "$cidfile" --pull=never --network=none --memory=144m --pids-limit=64 --cap-drop=all --security-opt=no-new-privileges --read-only --userns=keep-id --user "$uid:$uid" --tmpfs /tmp:rw,size=64m,mode=1777 --mount type=bind,src=/usr,dst=/usr,ro --mount type=bind,src=/usr/lib,dst=/lib,ro --mount type=bind,src=/usr/lib64,dst=/lib64,ro --mount "type=bind,src=$project/.venv,dst=/work/.venv,ro" --mount "type=bind,src=$project/phase1,dst=/work/phase1,ro" --mount "type=bind,src=$project/phase3,dst=/work/phase3,ro" --mount "type=bind,src=$project/phase4,dst=/work/phase4,ro" --mount "type=bind,src=$project/prototypes,dst=/work/prototypes,ro" --mount "type=bind,src=$test_dir,dst=/work-tmp,rw" --env TMPDIR=/work-tmp --workdir /work bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731 "$@"
