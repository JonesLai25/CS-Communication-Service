#!/bin/sh
# Reproducible project-local Python for Ubuntu 20.04; no host installation.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || { echo 'refusing root' >&2; exit 1; }
[ "$#" -eq 0 ] || exit 2
if [ "${CS_PHASE3_SCOPE:-}" != 1 ]; then
 exec systemd-run --user --scope --quiet -p MemoryMax=192M -p MemorySwapMax=128M -p TasksMax=64 env CS_PHASE3_SCOPE=1 "$0"
fi
cg=$(awk -F: '$1=="0" {print $3}' /proc/self/cgroup)
[ -r "/sys/fs/cgroup$cg/memory.max" ] && [ "$(cat "/sys/fs/cgroup$cg/memory.max")" = 201326592 ] || { echo 'memory limit missing' >&2; exit 1; }
[ "$(cat "/sys/fs/cgroup$cg/memory.swap.max")" = 134217728 ] && [ "$(cat "/sys/fs/cgroup$cg/pids.max")" = 64 ] || { echo 'scope limits missing' >&2; exit 1; }
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
[ "$(df -Pk "$project" | awk 'NR==2 {print $4}')" -ge 524288 ] || { echo 'insufficient disk space' >&2; exit 1; }
umask 077
mkdir -p "$project/.local-test/python312-download" "$project/.local-test/ubuntu20-py312-wheels"
archive="$project/.local-test/python312-download/python.tar.gz"
sha=c85811d35971d06612585a057db3b71806378df6ea8476275fb16aa5c9fe56a0
url='https://github.com/astral-sh/python-build-standalone/releases/download/20261123/cpython-3.12.16%2B20261123-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz'
if [ ! -f "$archive" ]; then wget -q -T 60 -O "$archive.part" "$url"; mv "$archive.part" "$archive"; fi
printf '%s  %s\n' "$sha" "$archive" | sha256sum -c -
if [ ! -x "$project/.local-test/python312/bin/python3" ]; then
 mkdir -p "$project/.local-test/python312"
 tar -xzf "$archive" -C "$project/.local-test/python312" --strip-components=1
fi
[ "$("$project/.local-test/python312/bin/python3" --version)" = 'Python 3.12.16' ] || { echo 'unexpected Python' >&2; exit 1; }
wheels="$project/.local-test/ubuntu20-py312-wheels"
if "$project/.venv/bin/python" -m pip download --no-index --find-links "$wheels" --only-binary=:all: --platform manylinux2014_x86_64 --python-version 312 --implementation cp --abi cp312 --require-hashes -r "$project/phase3/requirements-ubuntu20-py312.lock" --dest "$wheels"; then :; else
 "$project/.venv/bin/python" -m pip download --only-binary=:all: --platform manylinux2014_x86_64 --python-version 312 --implementation cp --abi cp312 --require-hashes -r "$project/phase3/requirements-ubuntu20-py312.lock" --dest "$wheels"
fi
