#!/usr/bin/env bash
# entrypoint_maven.sh — demonstrate: encrypt ALL repo jars, then `mvn test`
# still passes by reading them decrypted through the fusefs mount.
set -u
PASS=0 FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
MAGIC='\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f'

echo "== baseline: mvn test against the plaintext repo (offline) =="
if ( cd /proj && mvn -o -B -q test ); then ok "baseline mvn test passes (plaintext repo)"; else bad "baseline failed"; echo; echo "$PASS passed, $((FAIL)) failed"; exit 1; fi

echo
echo "== protect: encrypt every .jar, mount decrypting view, rerun mvn test =="
/usr/local/bin/protect-maven-repo.sh \
	--src "$HOME/.m2/repository" --enc /tmp/repo.enc --mnt /tmp/repo \
	--fusefs /usr/local/bin/vcachefsd --pack /usr/local/bin/pack_jar.py \
	--proj /proj --gate -- -o -B test
rc=$?
[ $rc -eq 0 ] && ok "mvn test PASSES reading encrypted jars through the mount (gate on: java)" \
              || bad "mvn test failed over encrypted jars (rc=$rc)"

echo
echo "== proof the jars are ciphertext at rest =="
J=$(find /tmp/repo.enc -name 'junit-jupiter-api-*.jar' | head -1)
echo "  sample: $J"
if [ -n "$J" ] && head -c8 "$J" | cmp -s - <(printf "$MAGIC"); then ok "dependency jar on disk is ciphertext (FS_MAGIC)"; else bad "jar on disk not ciphertext"; fi
TOTAL=$(find /tmp/repo.enc -name '*.jar' -type f | wc -l)
ENCN=0
while IFS= read -r -d '' j; do
	if head -c8 "$j" | cmp -s - <(printf "$MAGIC"); then ENCN=$((ENCN+1)); fi
done < <(find /tmp/repo.enc -name '*.jar' -type f -print0)
echo "  $ENCN of $TOTAL jars carry FS_MAGIC"
[ "$ENCN" = "$TOTAL" ] && ok "ALL repo jars encrypted ($ENCN/$TOTAL)" || bad "some jars not encrypted ($ENCN/$TOTAL)"

/usr/local/bin/protect-maven-repo.sh --down --mnt /tmp/repo --state /run/fusefs-repo 2>/dev/null || true
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
