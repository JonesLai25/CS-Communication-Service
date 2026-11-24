#!/bin/sh
# Creates only a unique project test slice and removes only that slice.
set -eu
[ "$#" -eq 1 ] || exit 2
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
case "$1" in "$project"/tools/phase5_worker_test.sh|"$project"/tools/phase5_controller_test.sh|"$project"/tools/phase5_tls_test.sh|"$project"/tools/phase6_e2e_inner.sh|"$project"/tools/phase7_e2e_inner.sh) ;; *) exit 2;; esac
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ -n "$available" ] && [ "$available" -ge 400000 ] || exit 1
slice="csphase5$(python3 -c 'import secrets;print(secrets.token_hex(6))').slice"
case "$slice" in csphase5????????????.slice) ;; *) exit 1;; esac
created=0
cleanup() {
 [ "$created" -eq 1 ] || return 0
 timeout --kill-after=2s 10s systemctl --user stop "$slice" >/dev/null 2>&1 || { echo 'test slice stop failed' >&2; return 1; }
 timeout --kill-after=2s 10s systemctl --user revert "$slice" >/dev/null 2>&1 || { echo 'test slice property cleanup failed' >&2; return 1; }
 [ ! -e "/run/user/$(id -u)/systemd/user.control/$slice.d" ] || { echo 'test slice properties remain' >&2; return 1; }
 printf 'test slice and properties removed: %s\n' "$slice"
}
on_exit() { result=$?; trap - EXIT; cleanup || result=1; exit "$result"; }
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --kill-after=2s 10s systemctl --user start "$slice"
created=1
timeout --kill-after=2s 10s systemctl --user set-property --runtime "$slice" MemoryMax=192M MemorySwapMax=128M TasksMax=64
printf 'requested aggregate slice %s: memory.max=201326592 swap.max=134217728 pids.max=64\n' "$slice"
timeout --kill-after=5s 240s systemd-run --user --scope --quiet --slice="$slice" -p MemoryMax=80M -p MemorySwapMax=96M -p TasksMax=32 env CS_PHASE5_SCOPE=1 CS_PHASE5_TEST_SLICE="$slice" "$1"
