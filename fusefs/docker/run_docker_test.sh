#!/usr/bin/env bash
# run_docker_test.sh — host-side driver: build the image and run the in-container
# decrypt/gate test.  Run from anywhere; resolves the fusefs/ build context itself.
#
#   bash fusefs/docker/run_docker_test.sh
#
# Needs: docker, and a host kernel with /dev/fuse (stock 'fuse' module).
set -euo pipefail
CTX="$(cd "$(dirname "$0")/.." && pwd)"          # fusefs/
IMG=fusefs-test
BASE="${BASE:-ubuntu:22.04}"                     # override where Docker Hub is blocked

echo "== building $IMG (context: $CTX, base: $BASE) =="
docker build --build-arg BASE="$BASE" -f "$CTX/docker/Dockerfile" -t "$IMG" "$CTX"

echo "== running in-container test =="
# --device /dev/fuse + CAP_SYS_ADMIN are what a FUSE mount needs in a container;
# apparmor:unconfined is a no-op where apparmor is absent (e.g. many WSL setups).
docker run --rm \
	--device /dev/fuse \
	--cap-add SYS_ADMIN \
	--security-opt apparmor=unconfined \
	"$IMG"
