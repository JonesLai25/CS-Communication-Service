#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
if [ "${CS_PHASE6_UNIT_SCOPE:-}" != 1 ]; then exec systemd-run --user --scope --quiet -p MemoryMax=96M -p MemorySwapMax=96M -p TasksMax=32 env CS_PHASE6_UNIT_SCOPE=1 "$0"; fi
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
PYTHONPATH="$project/tools" "$project/.venv/bin/python" -B -O -c 'from resource_guard import enforce; enforce(96*1024*1024,96*1024*1024,32,400000)'
for test in test_policy.py test_initialize.py test_systemd.py test_service_control.py test_retention.py; do "$project/.venv/bin/python" -B -O "$project/phase6/$test"; done
for test in test_export.py test_delivery.py; do "$project/.venv/bin/python" -B -O "$project/tools/$test"; done
