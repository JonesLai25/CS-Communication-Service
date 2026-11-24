#!/bin/sh
set -eu
[ "$#" -eq 1 ] || { echo "release archive required" >&2; exit 2; }
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ -n "$available" ] && [ "$available" -ge 400000 ] || exit 1
[ "$(df -Pk /tmp | awk 'NR==2 {print $4}')" -ge 524288 ] || exit 1
case_dir=$(mktemp -d /tmp/cs-phase7-e2e.XXXXXX)
cleanup() { /usr/bin/python3 -c 'import pathlib,shutil,sys; p=pathlib.Path(sys.argv[1]); (p.parent==pathlib.Path("/tmp") and p.name.startswith("cs-phase7-e2e.")) or sys.exit("invalid test directory"); shutil.rmtree(p)' "$case_dir"; }
on_exit() { result=$?; trap - EXIT; cleanup || result=1; exit "$result"; }
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')
timeout --kill-after=5s 180s systemd-run --user --scope --quiet -p MemoryMax=144M -p MemorySwapMax=128M -p TasksMax=64 taskset -c "$cpu" "$project/.venv/bin/python" -B -O "$project/phase7/build_fixture.py" "$case_dir/product" "$1"
export CS_PHASE7_TEST_ROOT="$case_dir/product"
"$project/tools/phase5_scope.sh" "$project/tools/phase7_e2e_inner.sh"
