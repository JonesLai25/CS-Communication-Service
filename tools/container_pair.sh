#!/bin/sh
# Two disposable rootless containers, sharing only a private network namespace.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
uid=$(id -u)
[ "$uid" -ne 0 ] || { echo 'refusing root' >&2; exit 1; }
# Rootless Podman can silently ignore container limits without delegated controllers.
# Enforce the budget on a dedicated temporary user scope and verify it before running.
if [ "${CS_LOCAL_TEST_SCOPE:-}" != 1 ]; then
 exec systemd-run --user --scope --quiet -p MemoryMax=192M -p MemorySwapMax=128M -p TasksMax=64 -p Delegate=yes env CS_LOCAL_TEST_SCOPE=1 "$0" "$@"
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
[ -d "$runtime" ] && [ ! -L "$runtime" ] && [ "$(stat -c %u "$runtime")" = "$uid" ] || { echo 'run local_container.sh smoke first' >&2; exit 1; }
umask 077
if ! graph_report=$(timeout --kill-after=2s 15s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file unshare du -sk "$project/.local-test/abs-graph"); then
 echo 'cannot verify project image store size' >&2; exit 1
fi
graph_kib=$(printf '%s\n' "$graph_report" | awk '{print $1}')
case "$graph_kib" in *[!0-9]*|'') echo 'invalid store size' >&2; exit 1;; esac
[ "$graph_kib" -le 524288 ] || { echo 'project image store exceeds 512 MiB budget' >&2; exit 1; }
available_kib=$(df -Pk "$project/.local-test/abs-graph" | awk 'NR==2 {print $4}')
[ "$available_kib" -ge 524288 ] || { echo 'less than 512 MiB free; refusing test' >&2; exit 1; }
case_dir=$(mktemp -d "$runtime/pair.XXXXXX")
server_cid="$case_dir/server.id"
client_cid="$case_dir/client.id"
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
  if tr '\000' ' ' < "/proc/$helper_pid/cmdline" | grep -Fq "$project/.local-test/abs-graph/overlay/"; then
   kill -TERM "$helper_pid" 2>/dev/null || :
  fi
 done
 for attempt in 1 2 3 4 5 6 7 8 9 10; do
  left=0
  for helper_pid in $(cat "/sys/fs/cgroup$cg/cgroup.procs"); do
   [ -r "/proc/$helper_pid/comm" ] && [ "$(cat "/proc/$helper_pid/comm")" = fuse-overlayfs ] || continue
   if tr '\000' ' ' < "/proc/$helper_pid/cmdline" | grep -Fq "$project/.local-test/abs-graph/overlay/"; then left=1; fi
  done
  [ "$left" -eq 0 ] && return 0
  sleep 0.2
 done
 echo 'project test FUSE helper did not exit' >&2; return 1
}
cleanup() {
 for idfile in "$client_cid" "$server_cid"; do
  [ -s "$idfile" ] || continue
  cid=$(cat "$idfile")
  remove_owned "$cid" || return 1
 done
 cleanup_fuse_helpers || return 1
 /usr/bin/python3 -c 'import pathlib,shutil,sys; p=pathlib.Path(sys.argv[1]); (p.name.startswith("pair.") and p.parent==pathlib.Path(sys.argv[2])) or sys.exit("invalid test path"); shutil.rmtree(p)' "$case_dir" "$runtime"
}
on_exit() { result=$?; trap - EXIT; cleanup || result=1; exit "$result"; }
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$project/.venv/bin/python" "$project/tools/container_fixture.py" "$case_dir"
podman_cs() { timeout --kill-after=2s 10s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file "$@"; }
# Server and client receive separate test key directories; neither sees host network.
timeout --kill-after=5s 20s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file run -d --cidfile "$server_cid" --pull=never --network=none --memory=128m --pids-limit=48 --cap-drop=all --security-opt=no-new-privileges --read-only --userns=keep-id --user "$uid:$uid" --log-driver=k8s-file --tmpfs /tmp:rw,size=32m,mode=1777 --mount type=bind,src=/usr,dst=/usr,ro --mount type=bind,src=/usr/lib,dst=/lib,ro --mount type=bind,src=/usr/lib64,dst=/lib64,ro --mount "type=bind,src=$project/.venv,dst=/work/.venv,ro" --mount "type=bind,src=$project/phase1,dst=/work/phase1,ro" --mount "type=bind,src=$case_dir/server,dst=/case,rw" --workdir /work bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731 /work/.venv/bin/python -B phase1/server.py --storage-capacity-mib 1048576 --cert /case/cert.pem --key /case/key.pem --db /case/registry.db --port 18443 > "$case_dir/started"
cid=$(cat "$server_cid")
server_pid=$(podman_cs inspect --format '{{.State.Pid}}' "$cid")
server_cg=$(awk -F: '$1=="0" {print $3}' "/proc/$server_pid/cgroup")
[ "$(awk '/^Cpus_allowed_list:/ {print $2}' "/proc/$server_pid/status")" = "$cpu" ] || { echo 'server CPU affinity mismatch' >&2; exit 1; }
case "$server_cg" in "$cg"|"$cg"/*) printf 'server cgroup is inside verified scope: PASS\n';; *) echo 'server escaped budget scope' >&2; exit 1;; esac
ready=0
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
 if podman_cs logs "$cid" 2>/dev/null | grep -q '^18443$'; then ready=1; break; fi
 sleep 0.25
done
[ "$ready" -eq 1 ] || { echo 'test server did not start' >&2; podman_cs logs "$cid" >&2 || :; exit 1; }
host_net=$(readlink /proc/self/ns/net)
server_net=$(podman_cs exec "$cid" /usr/bin/readlink /proc/self/ns/net)
[ "$host_net" != "$server_net" ] || { echo 'server shares host network namespace' >&2; exit 1; }
printf 'host network namespace: %s\nserver network namespace: %s\n' "$host_net" "$server_net"
timeout --kill-after=5s 30s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file run -d --cidfile "$client_cid" --pull=never --network "container:$cid" --memory=128m --pids-limit=48 --cap-drop=all --security-opt=no-new-privileges --read-only --userns=keep-id --user "$uid:$uid" --tmpfs /tmp:rw,size=32m,mode=1777 --mount type=bind,src=/usr,dst=/usr,ro --mount type=bind,src=/usr/lib,dst=/lib,ro --mount type=bind,src=/usr/lib64,dst=/lib64,ro --mount "type=bind,src=$project/.venv,dst=/work/.venv,ro" --mount "type=bind,src=$project/phase1,dst=/work/phase1,ro" --mount "type=bind,src=$project/tools/container_pair_client.py,dst=/work/client.py,ro" --mount "type=bind,src=$case_dir/client,dst=/case,ro" --workdir /work bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731 /work/.venv/bin/python -B -c 'import time; time.sleep(45)' > "$case_dir/client-started"
client_id=$(cat "$client_cid")
client_pid=$(podman_cs inspect --format '{{.State.Pid}}' "$client_id")
client_cg=$(awk -F: '$1=="0" {print $3}' "/proc/$client_pid/cgroup")
[ "$(awk '/^Cpus_allowed_list:/ {print $2}' "/proc/$client_pid/status")" = "$cpu" ] || { echo 'client CPU affinity mismatch' >&2; exit 1; }
case "$client_cg" in "$cg"|"$cg"/*) printf 'client cgroup is inside verified scope: PASS\n';; *) echo 'client escaped budget scope' >&2; exit 1;; esac
timeout --kill-after=5s 30s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file exec "$client_id" /work/.venv/bin/python -B /work/client.py > "$case_dir/client-result"
cat "$case_dir/client-result"
grep -Fx "client network namespace: $server_net" "$case_dir/client-result" >/dev/null || { echo 'client and server network namespaces differ' >&2; exit 1; }
