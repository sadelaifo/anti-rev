#!/bin/sh
# fusefs-entrypoint.sh — mount the decrypting view, then exec the product.
#
# Two modes (FUSEFS_WRITABLE):
#   1 (default): writable view — vcachefsd (RO, decrypt) as the lower, with a
#     stock overlayfs writable upper stacked on top at $FUSEFS_MNT.  Decrypted
#     reads fall through to the fusefs lower; the app's runtime writes (lock/
#     log/pid next to the binaries) land in the overlay upper and NEVER touch
#     the ciphertext.
#   0: read-only — a bare vcachefsd mount at $FUSEFS_MNT (use only if the app
#     never writes inside its own tree).
#
# Wrap your original command:
#   ENTRYPOINT ["/usr/local/bin/fusefs-entrypoint.sh"]
#   CMD        ["/opt/product/bin/app", "..."]
#
# REQUIRED at `docker run`:  --device /dev/fuse --cap-add SYS_ADMIN
#   (SYS_ADMIN also covers the overlayfs + tmpfs mounts below)
set -eu

LOWER="${FUSEFS_LOWER:-/opt/product.enc}"   # ciphertext tree baked into the image
MNT="${FUSEFS_MNT:-/opt/product}"           # where the app reads/writes its files
OPTS="${FUSEFS_OPTS:---passdata}"           # prod: "--passdata --gate --passthrough-cipher"
WRITABLE="${FUSEFS_WRITABLE:-1}"
# State dir holds the decrypt mountpoint + overlay upper/work.  It is placed on
# a tmpfs (a "real" fs — overlayfs refuses an upperdir that sits on another
# overlayfs, which is what a container rootfs is).  tmpfs => writes are wiped on
# container stop (fine for lock/log/pid).  For persistence, bind a volume here
# and set FUSEFS_STATE_TMPFS=0.
STATE="${FUSEFS_STATE:-/run/fusefs}"
STATE_TMPFS="${FUSEFS_STATE_TMPFS:-1}"

if [ ! -e /dev/fuse ]; then
	echo "fusefs: /dev/fuse not present — run with --device /dev/fuse --cap-add SYS_ADMIN" >&2
	exit 1
fi

wait_mounted() {  # $1 = mountpoint
	i=0
	while ! grep -q " $1 " /proc/self/mountinfo; do
		i=$((i + 1))
		[ "$i" -gt 50 ] && { echo "fusefs: mount did not come up at $1" >&2; exit 1; }
		sleep 0.1
	done
}

mkdir -p "$MNT"

if [ "$WRITABLE" = "1" ]; then
	mkdir -p "$STATE"
	[ "$STATE_TMPFS" = "1" ] && mount -t tmpfs tmpfs "$STATE"
	DEC="$STATE/dec"; UPPER="$STATE/upper"; WORK="$STATE/work"
	mkdir -p "$DEC" "$UPPER" "$WORK"
	# lower: decrypting fusefs (read-only)
	vcachefsd "$LOWER" "$DEC" $OPTS
	wait_mounted "$DEC"
	# writable overlay on top; reads fall through to DEC, writes -> UPPER
	mount -t overlay fusefs_overlay \
		-o "lowerdir=$DEC,upperdir=$UPPER,workdir=$WORK" "$MNT"
	wait_mounted "$MNT"
else
	vcachefsd "$LOWER" "$MNT" $OPTS
	wait_mounted "$MNT"
fi

exec "$@"
