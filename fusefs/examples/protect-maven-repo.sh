#!/usr/bin/env bash
# protect-maven-repo.sh — encrypt every .jar in a Maven local repo, serve a
# decrypting view over it (optionally gated on `java`), and run Maven against
# that view.  Your real ~/.m2 is never modified (we work on a copy).
#
#   protect-maven-repo.sh [options] -- [mvn args...]     (default mvn args: -o -B test)
#
# Options (env var in parens overrides the default):
#   --src DIR      Maven local repo to protect        (SRC,    ~/.m2/repository)
#   --enc DIR      ciphertext copy = the lower tree    (ENC,    /tmp/repo.enc)
#   --mnt DIR      decrypting view Maven reads          (MNT,    /tmp/repo)
#   --state DIR    overlay state (dec/upper/work)       (STATE,  /run/fusefs-repo)
#   --proj DIR     project dir to run mvn in            (PROJ,   $PWD)
#   --fusefs PATH  the vcachefsd binary                 (FUSEFS, ../prebuilt/vcachefsd-x86_64)
#   --pack PATH    pack_jar.py                          (PACK,   ../docker/jar-demo/pack_jar.py)
#   --gate         enforce the gate + whitelist `java`  (default off)
#   --ro           plain read-only mount (no writable overlay; Maven may need writes)
#   --no-run       encrypt + mount only, don't run mvn
#   --down         unmount everything and exit
#
# Needs: fuse3 (fusermount3) + /dev/fuse; root/CAP_SYS_ADMIN for the writable
# overlay + tmpfs.  The decrypting mount is read-only, so the writable overlay
# (default) lets Maven write repo metadata; jar reads fall through and decrypt.
set -euo pipefail

SELF_DIR=$(cd "$(dirname "$0")" && pwd)
SRC="${SRC:-$HOME/.m2/repository}"
ENC="${ENC:-/tmp/repo.enc}"
MNT="${MNT:-/tmp/repo}"
STATE="${STATE:-/run/fusefs-repo}"
PROJ="${PROJ:-$PWD}"
FUSEFS="${FUSEFS:-$SELF_DIR/../prebuilt/vcachefsd-x86_64}"
PACK="${PACK:-$SELF_DIR/../docker/jar-demo/pack_jar.py}"
GATE=0; WRITABLE=1; RUN=1; DOWN=0
MAGIC='\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f'

while [ $# -gt 0 ]; do case "$1" in
	--src) SRC=$2; shift 2;;
	--enc) ENC=$2; shift 2;;
	--mnt) MNT=$2; shift 2;;
	--state) STATE=$2; shift 2;;
	--proj) PROJ=$2; shift 2;;
	--fusefs) FUSEFS=$2; shift 2;;
	--pack) PACK=$2; shift 2;;
	--gate) GATE=1; shift;;
	--ro) WRITABLE=0; shift;;
	--no-run) RUN=0; shift;;
	--down) DOWN=1; shift;;
	--) shift; break;;
	-h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
	*) echo "unknown option: $1" >&2; exit 2;;
esac; done
MVN_ARGS=("$@"); [ ${#MVN_ARGS[@]} -eq 0 ] && MVN_ARGS=(-o -B test)

is_mounted() { grep -q " $1 " /proc/self/mountinfo; }
umnt() { is_mounted "$1" && { fusermount3 -u "$1" 2>/dev/null || umount -l "$1" 2>/dev/null; } || true; }
teardown() { umnt "$MNT"; umnt "$STATE/dec"; is_mounted "$STATE" && umount -l "$STATE" 2>/dev/null || true; }

if [ "$DOWN" = 1 ]; then teardown; echo "[*] unmounted"; exit 0; fi
[ -x "$FUSEFS" ] || { echo "vcachefsd not executable at: $FUSEFS (--fusefs or build it)" >&2; exit 1; }
[ -f "$PACK" ]   || { echo "pack_jar.py not found at: $PACK (--pack)" >&2; exit 1; }

# 1) stage a ciphertext copy (once) so the real repo is never touched
if [ ! -d "$ENC" ]; then
	echo "[*] staging copy: $SRC -> $ENC"
	cp -a "$SRC" "$ENC"
fi

# 2) encrypt every .jar in the copy, in place, idempotently
echo "[*] encrypting .jar files under $ENC ..."
n=0
while IFS= read -r -d '' j; do
	if head -c8 "$j" | cmp -s - <(printf "$MAGIC"); then continue; fi   # already encrypted
	python3 "$PACK" "$j" "$j.__e" >/dev/null && mv "$j.__e" "$j" && n=$((n+1))
done < <(find "$ENC" -name '*.jar' -type f -print0)
echo "[*] newly encrypted: $n    total jars: $(find "$ENC" -name '*.jar' -type f | wc -l)"

# 3) mount the decrypting view
AUTHZ=/tmp/.fusefs-maven.authz; echo java > "$AUTHZ"
GATEOPTS=""; [ "$GATE" = 1 ] && GATEOPTS="--gate --authz $AUTHZ --passthrough-cipher"
teardown
mkdir -p "$MNT"
if [ "$WRITABLE" = 1 ]; then
	mkdir -p "$STATE"; mount -t tmpfs tmpfs "$STATE"
	mkdir -p "$STATE/dec" "$STATE/upper" "$STATE/work"
	# shellcheck disable=SC2086
	"$FUSEFS" "$ENC" "$STATE/dec" --passdata $GATEOPTS
	i=0; until is_mounted "$STATE/dec"; do i=$((i+1)); [ $i -gt 50 ] && { echo "fusefs lower mount failed" >&2; exit 1; }; sleep 0.1; done
	mount -t overlay fusefs_repo -o "lowerdir=$STATE/dec,upperdir=$STATE/upper,workdir=$STATE/work" "$MNT"
else
	# shellcheck disable=SC2086
	"$FUSEFS" "$ENC" "$MNT" --passdata $GATEOPTS
fi
i=0; until is_mounted "$MNT"; do i=$((i+1)); [ $i -gt 50 ] && { echo "mount failed" >&2; exit 1; }; sleep 0.1; done
echo "[*] decrypting repo mounted at $MNT  (writable=$WRITABLE gate=$GATE)"

[ "$RUN" = 0 ] && { echo "[*] --no-run: leaving it mounted; use  mvn -Dmaven.repo.local=$MNT"; exit 0; }

# 4) run Maven against the decrypted repo
echo "[*] cd $PROJ && mvn ${MVN_ARGS[*]} -Dmaven.repo.local=$MNT"
set +e
( cd "$PROJ" && mvn "${MVN_ARGS[@]}" -Dmaven.repo.local="$MNT" )
rc=$?
set -e
echo "[*] mvn exit=$rc"
exit $rc
