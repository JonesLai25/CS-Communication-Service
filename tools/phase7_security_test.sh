#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
if [ "${CS_PHASE7_SECURITY_SCOPE:-}" != 1 ]; then exec systemd-run --user --scope --quiet -p MemoryMax=144M -p MemorySwapMax=128M -p TasksMax=64 env CS_PHASE7_SECURITY_SCOPE=1 "$0"; fi
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
PYTHONPATH="$project/tools" "$project/.venv/bin/python" -B -O -c 'from resource_guard import enforce; enforce(144*1024*1024,128*1024*1024,64,400000)'
for test in phase7/test_storage_guard.py phase7/test_retention.py phase7/test_release.py phase1/test_tls.py phase1/test_mutations003.py phase3/test_mutation.py phase4/test_mutation.py; do "$project/.venv/bin/python" -B -O "$project/$test"; done
