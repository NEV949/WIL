#!/usr/bin/env bash
# Phase 1.2 / 1.3: build the sandbox image and run the hardening verification.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-oracle-sandbox:1.0}"

# Git Bash on Windows rewrites container paths like /opt/... into Windows paths.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

echo "== build =="
docker build -t "$IMAGE" "$ROOT/sandbox/"

echo "== verify (restricted run) =="
docker run --rm \
  --network none \
  --memory 512m \
  --memory-swap 512m \
  --cpus 0.5 \
  --pids-limit 64 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /workspace:rw,exec,size=128m,uid=1000,gid=1000,mode=0750 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 1000:1000 \
  "$IMAGE" \
  bash -lc "/opt/venv/bin/python /opt/verify/check_sandbox.py"
