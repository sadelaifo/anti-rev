#!/bin/sh
# entrypoint.sh — mount the decrypting view in place over /app/bin, then run the
# app (the CMD).  vcachefsd holds the AES key (compiled in); /app/bin/dose.jar on
# disk is keyless ciphertext and appears decrypted only through this mount.
set -e

MP=/app/bin

# In-place mount (lower == mountpoint): vcachefsd pins an fd to /app/bin before
# it mounts, so the shadowed ciphertext stays reachable.  --passdata serves any
# non-encrypted files in bin/ verbatim.  Add gate enforcement (only the JVM may
# decrypt) by uncommenting the --gate line.
vcachefsd "$MP" "$MP" --passdata
# vcachefsd "$MP" "$MP" --passdata --gate --authz /etc/fusefs.allow   # echo java > /etc/fusefs.allow

# wait for the mount to be live before starting the app
i=0
while ! mountpoint -q "$MP"; do
	i=$((i + 1)); [ "$i" -gt 100 ] && { echo "vcachefsd: mount did not come up" >&2; exit 1; }
	sleep 0.1
done

exec "$@"
