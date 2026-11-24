#!/bin/sh
# Private rootless namespaces only: never touches host interfaces or existing services.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ -n "$available" ] && [ "$available" -ge 300000 ] || { echo 'host memory guard refused test' >&2; exit 1; }
if [ "${CS_NETNS_SCOPE:-}" != 1 ]; then
 exec systemd-run --user --scope --quiet -p MemoryMax=144M -p MemorySwapMax=128M -p TasksMax=64 -p Delegate=yes env CS_NETNS_SCOPE=1 "$0"
fi
cg=$(awk -F: '$1=="0" {print $3}' /proc/self/cgroup)
mem=$(cat "/sys/fs/cgroup$cg/memory.max"); swap=$(cat "/sys/fs/cgroup$cg/memory.swap.max"); pids=$(cat "/sys/fs/cgroup$cg/pids.max")
case "$mem:$swap:$pids" in *[!0-9:]*|:*) echo 'unbounded cgroup' >&2; exit 1;; esac
[ "$mem" -le 201326592 ] && [ "$swap" -le 134217728 ] && [ "$pids" -le 64 ] || exit 1
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
printf 'scope memory.max=%s swap.max=%s pids.max=%s CPU=%s\n' "$mem" "$swap" "$pids" "$cpu"
runtime="/tmp/cs-podman-$(id -u)"
[ -d "$runtime" ] && [ ! -L "$runtime" ] && [ "$(stat -c %u "$runtime")" = "$(id -u)" ] || exit 1
[ -x "$project/.venv/bin/python" ] || { echo 'project venv missing' >&2; exit 1; }
if ! venv_report=$(du -sk "$project/.venv"); then echo 'cannot check venv disk size' >&2; exit 1; fi
venv_kib=$(printf '%s\n' "$venv_report" | awk '{print $1}')
[ "$venv_kib" -le 131072 ] || { echo 'venv exceeds 128 MiB test budget' >&2; exit 1; }
available_kib=$(df -Pk /tmp | awk 'NR==2 {print $4}')
[ "$available_kib" -ge 524288 ] || { echo 'less than 512 MiB free' >&2; exit 1; }
case_dir=$(mktemp -d /tmp/cs-netns.XXXXXX)
restore() {
 # Files are created solely by this test; restore their UID mapping for cleanup.
 timeout --kill-after=2s 10s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file unshare chown -R 0:0 "$case_dir" || return 1
 /usr/bin/python3 -c 'import pathlib,shutil,sys; p=pathlib.Path(sys.argv[1]); (p.name.startswith("cs-netns.") and p.parent==pathlib.Path("/tmp")) or sys.exit("invalid test path"); shutil.rmtree(p)' "$case_dir" "$runtime"
}
on_exit() { result=$?; trap - EXIT; restore || result=1; exit "$result"; }
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$project/.venv/bin/python" "$project/tools/container_fixture.py" "$case_dir"
"$project/.venv/bin/python" "$project/tools/netns_phase4_fixture.py" "$case_dir"
"$project/.venv/bin/python" -c 'import pathlib,shutil,sys; src=pathlib.Path(sys.argv[1]); dst=pathlib.Path(sys.argv[2]); shutil.copytree(src/"phase1",dst/"phase1",ignore=shutil.ignore_patterns("__pycache__","*.pyc")); shutil.copytree(src/".venv",dst/"venv",symlinks=True,ignore=shutil.ignore_patterns("__pycache__","*.pyc")); [shutil.copy2(src/"tools"/n,dst/n) for n in ("netns_forwarder.py","netns_phase4_client.py","netns_phase4_orchestrator.py")]' "$project" "$case_dir"
# Root below means UID 0 *inside the rootless Podman user namespace*, never host root.
podman_cs() { timeout --kill-after=5s 90s podman --root "$project/.local-test/abs-graph" --runroot "$runtime/run" --tmpdir "$runtime/tmp" --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs --cgroup-manager cgroupfs --events-backend file "$@"; }
host_ns=$(readlink /proc/self/ns/net)
ip -brief link | grep -Eq '^csa0(@|[[:space:]])|^csb0(@|[[:space:]])' && { echo 'test interface names already exist on host' >&2; exit 1; }
podman_cs unshare sh -c 'set -eu; d=$1; chmod 755 "$d"; chown -R 1000:1000 "$d/server"; chown -R 1001:1001 "$d/client"; exec unshare --net /usr/bin/python3 "$d/netns_phase4_orchestrator.py" "$d" "$2"' _ "$case_dir" "$host_ns"
ip -brief link | grep -Eq '^csa0(@|[[:space:]])|^csb0(@|[[:space:]])' && { echo 'unexpected host test interface' >&2; exit 1; }
exit 0
