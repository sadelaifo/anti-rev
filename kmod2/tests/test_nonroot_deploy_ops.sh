#!/bin/bash
# test_nonroot_deploy_ops.sh — validate what a NON-ROOT deploy script may do on a
# target directory, exercising every filesystem op a typical python unzip/deploy
# script uses: open(), os.remove(), os.path.exists(), os.path.isabs(),
# os.listdir(), mkdir -p, rm -rf, shutil.rmtree(), os.chmod(), chattr, lsattr,
# os.chdir().
#
# WHY: on a vcachefs writable in-place mount, *writes* are ungated by the module,
# but the KERNEL still enforces the normal Unix model — a non-root caller needs
# write+exec on the parent directory, ownership to chmod, and canNOT set/clear
# the immutable/append flags (chattr +/-i,+/-a need CAP_LINUX_IMMUTABLE = root).
# This script shows you exactly which of your deploy ops succeed and which are
# denied (with the errno), so you can fix the script (run chattr as root, own the
# tree, clear +i before rmtree/tar, mount DOWN during deploy, ...).
#
# SAFE: it only ever touches a scratch subdir it creates under TARGET; it never
# modifies your existing files.  It needs NO root and NO kernel module.
#
# Usage:   bash test_nonroot_deploy_ops.sh [TARGET_DIR]       (default: .)
#   TARGET_DIR is the directory your deploy writes into — point it at your mount
#   or a bin/ under it, e.g.:  bash test_nonroot_deploy_ops.sh /home/$USER/proj/bin
#
# Run it AS THE DEPLOY USER.  (If run as root the write/chattr results won't
# reflect what your unprivileged deploy user sees — it warns and continues.)
set -u

TARGET="${1:-.}"

PASS=0; FAIL=0; INFO=0
ok()   { echo "  [OK]    $*"; PASS=$((PASS+1)); }
no()   { echo "  [DENY]  $*"; FAIL=$((FAIL+1)); }    # denied (may be expected)
note() { echo "  [NOTE]  $*"; INFO=$((INFO+1)); }

echo "== non-root deploy-op check =="
echo "target : $TARGET"
echo "user   : $(id -un) (uid=$(id -u))"
if [[ $(id -u) -eq 0 ]]; then
	echo "  !! running as ROOT — results will NOT reflect your non-root deploy user."
	echo "     re-run as the deploy user:  sudo -u <deployuser> bash $0 $TARGET"
fi
[[ -d "$TARGET" ]] || { echo "target is not a directory: $TARGET"; exit 1; }
echo

# Classify a shell command's failure by its stderr text (locale-tolerant-ish).
# Prints a short errno tag for the message.
errno_of() {
	case "$1" in
		*"not permitted"*)              echo "EPERM" ;;
		*"ermission denied"*)           echo "EACCES" ;;
		*"ead-only file system"*)       echo "EROFS" ;;
		*"peration not supported"*|*"nappropriate ioctl"*) echo "ENOTSUP" ;;
		*"evice or resource busy"*)     echo "EBUSY" ;;
		*"o such file"*)                echo "ENOENT" ;;
		*)                              echo "err" ;;
	esac
}

# ---- 1. can we even create a scratch area here? (mkdir + write in TARGET) ----
echo "-- 1. create scratch workspace in TARGET (mkdir -p + write) --"
WORK="$TARGET/.nonroot_optest.$$"
if err=$(mkdir -p "$WORK/sub/deep" 2>&1); then
	ok "mkdir -p '$WORK/sub/deep' (os.mkdir / 'mkdir -p')"
else
	no "mkdir -p in TARGET -> $(errno_of "$err") ($err)"
	echo
	echo "Cannot create files in TARGET as this user — the rest of the WRITE tests"
	echo "would all fail the same way.  Likely: TARGET is root-owned / not writable"
	echo "by $(id -un), or an ancestor dir is immutable.  Read-only tests below still run."
	WORK=""   # disable write tests
fi

cleanup() {
	[[ -n "${WORK:-}" && -d "$WORK" ]] || return 0
	command -v chattr >/dev/null && chattr -R -i -a "$WORK" 2>/dev/null
	rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT
echo

# ---- 2. read-only / traversal ops (expected OK anywhere traversable) ----
echo "-- 2. read-only + traversal ops (os.path.*, os.listdir, os.chdir, lsattr) --"
python3 - "$TARGET" <<'PY' || note "python3 not available — skipped the python read-only block"
import os, sys, errno
t = sys.argv[1]
def r(label, fn):
    try:
        fn(); print(f"  [OK]    {label}")
    except OSError as e:
        print(f"  [DENY]  {label} -> {errno.errorcode.get(e.errno,e.errno)} ({e.strerror})")
    except Exception as e:
        print(f"  [NOTE]  {label} -> {type(e).__name__}: {e}")
print(f"  [OK]    os.path.isabs('{t}') = {os.path.isabs(t)} (pure string, no syscall)")
r("os.path.exists(TARGET)",  lambda: os.path.exists(t))
r("os.listdir(TARGET)",      lambda: os.listdir(t))
r("os.chdir(TARGET)",        lambda: os.chdir(t))
PY
if command -v lsattr >/dev/null; then
	if err=$(lsattr -d "$TARGET" 2>&1); then ok "lsattr -d TARGET ($err)"
	else note "lsattr -d TARGET -> $(errno_of "$err") (fs may not support flags: $err)"; fi
else
	note "lsattr not installed — skipped"
fi
echo

# ---- 3. write / mutate ops in the scratch area (os-level) ----
if [[ -n "${WORK:-}" ]]; then
echo "-- 3. write/mutate ops in scratch (open, os.chmod, os.remove, rm -rf, rmtree) --"
python3 - "$WORK" <<'PY' || note "python3 not available — skipped the python write block"
import os, sys, errno, shutil
w = sys.argv[1]
def r(label, fn):
    try:
        fn(); print(f"  [OK]    {label}")
    except OSError as e:
        print(f"  [DENY]  {label} -> {errno.errorcode.get(e.errno,e.errno)} ({e.strerror})")
    except Exception as e:
        print(f"  [NOTE]  {label} -> {type(e).__name__}: {e}")
f = os.path.join(w, "file.txt")
r("open(f,'w').write()",     lambda: open(f,"w").write("hello"))
r("open(f,'r').read()",      lambda: open(f).read())
r("os.chmod(f,0o600)",       lambda: os.chmod(f, 0o600))   # own file -> should pass
r("os.remove(f)",            lambda: os.remove(f))
# rmtree a throwaway subtree
sd = os.path.join(w, "rmtree_me")
os.makedirs(os.path.join(sd, "a", "b"), exist_ok=True)
open(os.path.join(sd, "a", "b", "x"), "w").write("x")
r("shutil.rmtree(subtree)",  lambda: shutil.rmtree(sd))
PY
# shell equivalents your script also shells out to
d="$WORK/rmrf_me"; mkdir -p "$d/a/b" 2>/dev/null; : > "$d/a/b/x" 2>/dev/null
if err=$(rm -rf "$d" 2>&1); then ok "rm -rf subtree"
else no "rm -rf subtree -> $(errno_of "$err") ($err)"; fi
echo
else
echo "-- 3. write/mutate ops: SKIPPED (could not create scratch in TARGET; see §1) --"
echo
fi

# ---- 4. the privileged ops: chattr +/- i,a  (MUST be denied for non-root) ----
echo "-- 4. chattr immutable/append (NON-ROOT MUST be denied — needs CAP_LINUX_IMMUTABLE) --"
if [[ -z "${WORK:-}" ]]; then
	note "no scratch file to test chattr on (see §1) — skipped"
elif ! command -v chattr >/dev/null; then
	note "chattr not installed — skipped"
else
	cf="$WORK/chattr_target"; : > "$cf" 2>/dev/null
	err=$(chattr +i "$cf" 2>&1); rc=$?
	if [[ $rc -ne 0 ]]; then
		ok "chattr +i denied for non-root (expected) -> $(errno_of "$err")"
	else
		# Unexpected: a non-root user set +i.  We now canNOT clear it ourselves;
		# warn loudly so cleanup/rm doesn't silently fail.
		note "chattr +i UNEXPECTEDLY SUCCEEDED as non-root (fs/cap anomaly)."
		chattr -i "$cf" 2>/dev/null || \
			echo "        !! could not clear it as non-root — run: sudo chattr -i '$cf'"
	fi
	err=$(chattr +a "$cf" 2>&1); rc=$?
	[[ $rc -ne 0 ]] && ok "chattr +a denied for non-root (expected) -> $(errno_of "$err")" \
	               || { note "chattr +a unexpectedly succeeded"; chattr -a "$cf" 2>/dev/null; }
fi
echo

echo "==== non-root deploy ops: $PASS ok, $FAIL denied, $INFO notes ===="
cat <<'LEGEND'

How to read this:
  §1-§3 [OK]   -> this user CAN do that op on TARGET (writable + mutable + owned).
  §1-§3 [DENY] EPERM/EACCES  -> TARGET is root-owned / not writable by you, or a
                 dir/file is immutable (+i) or append-only (+a).  Fix: own the tree
                 as the deploy user, clear +i/+a first (sudo chattr -R -i -a), and
                 mount DOWN during destroy/extract.
  §4    [OK]   -> GOOD: chattr +i/+a is correctly DENIED for non-root.  Your deploy
                 script's chattr calls MUST run under sudo (as you already do).
  §4 unexpectedly succeeded -> investigate (unusual fs/caps).

Reminder: run this as your DEPLOY USER, pointed at the real target (your mount or
its bin/ lib/), with the mount in whatever state your script runs in.
LEGEND
[[ $FAIL -eq 0 ]]
