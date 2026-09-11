#!/usr/bin/env bash
# Build the maven-demo image and run it. Host needs docker + /dev/fuse.
set -euo pipefail
CTX="$(cd "$(dirname "$0")/../.." && pwd)"     # fusefs/
IMG=fusefs-mvn
BASE="${BASE:-ubuntu:22.04}"                    # override where Docker Hub is blocked

echo "== build $IMG (base: $BASE) — installs JDK+Maven, populates ~/.m2 (online) =="
docker build --build-arg BASE="$BASE" -f "$CTX/docker/maven-demo/Dockerfile" -t "$IMG" "$CTX"

echo "== run: encrypt all repo jars, rerun mvn test through fusefs =="
docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined "$IMG"
