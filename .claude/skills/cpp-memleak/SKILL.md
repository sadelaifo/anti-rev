---
name: cpp-memleak
description: Investigate suspected C++ memory leaks or persistent RSS growth in long-running processes. Use when user reports "memory leak", "RSS keeps growing", "process eats too much memory", "OOM after running N days", especially on resource-constrained targets where heavy profilers (Valgrind full-restart, ASan with 3x memory overhead) are not viable. Walks from raw symptom through constraint-driven diagnosis, multi-hypothesis generation, targeted semantic source review, and cross-verification. Avoid invoking for one-off "where do I add delete" questions or for crashes / OOM-at-startup (those are different problems).
---

# C++ Memory Leak / RSS Growth — Investigation Skill

A structured procedure for diagnosing "the C++ process keeps using more and more memory".
Built from a real case study (an aarch64 program growing 4 GB/day, default glibc ptmalloc,
limited on-board tools). The **methodology** generalizes; the **specific numbers** in the
case study are reference points, not assumptions.

The skill enforces three discipline rules:

1. **Ground truth before theory** — collect hard data before forming hypotheses
2. **Multi-hypothesis** — enumerate competing causes; do not commit to one too early
3. **Cross-verify** — confirm with at least two independent methods before concluding

---

## When to invoke

Trigger when the user describes:

- A long-running C++ process whose memory usage grows over time
- "Memory leak" / "RSS 涨" / "RSS keeps growing" / "OOM after N days"
- Process getting OOM-killed by kernel after running a while
- Specific growth rate observation (e.g., "+4 GB/day", "doubled overnight")

Do **not** trigger for:

- "How do I write `delete` here" — answer directly, no skill needed
- Static code review with no runtime symptoms
- OOM at startup (different: usually misconfiguration or sizing)
- Crashes / segfaults / use-after-free reports (different: ASan / debugger)
- Performance issues that aren't memory growth (CPU, latency)

---

## Process

### Phase 0: Establish ground truth (do NOT skip)

Before any analysis, get hard numbers. Push back if the user only has anecdotes ("it seems slow", "people are saying it leaks"). Without data you can only speculate.

**Required minimum:**

- Process PID
- RSS readings at ≥ 2 timestamps showing the trend (`grep VmRSS /proc/$PID/status`)
- Approximate growth rate (MB/min or GB/day)
- Platform: arch (x86_64/aarch64/…), kernel version, OS
- What tools are available on the target (grep, gdb, pmap is usually a yes; bcc-tools / heaptrack / valgrind often a no)

**Strongly recommended additional snapshot:**

```bash
PID=<…>

# Memory totals
cat /proc/$PID/status | grep -E "VmPeak|VmSize|VmRSS|RssAnon|RssFile|RssShmem"
cat /proc/$PID/smaps_rollup

# Segment breakdown
pmap -x $PID | head -30
pmap -x $PID | sort -k3 -n | tail -20

# Anonymous segment statistics (signals allocator behavior)
pmap -x $PID | grep anon | awk '$2 == 65536' | wc -l       # 64 MB segments (ptmalloc subheaps)
pmap -x $PID | grep anon | awk '$2 > 65536'                 # large blocks

# Threads (run twice, 30 s apart, to detect thread leak)
ls /proc/$PID/task | wc -l ; sleep 30 ; ls /proc/$PID/task | wc -l

# Allocator environment
cat /proc/$PID/environ | tr '\0' '\n' | grep -iE 'MALLOC|LD_PRELOAD|TCMALLOC|MIMALLOC'

# CPU count (sets ptmalloc default arena cap)
grep -c ^processor /proc/cpuinfo
```

**If user is on glibc, also grab `malloc_info`** (it tells you fragmentation vs real-data):

```bash
gdb -batch -p $PID \
    -ex 'set $f = (void *)fopen("/tmp/mi.xml", "w")' \
    -ex 'call (void) malloc_info(0, $f)' \
    -ex 'call (int) fflush($f)' \
    -ex 'call (int) fclose($f)'
# then extract the summary numbers
grep -E '<system|<total type' /tmp/mi.xml
```

**Anti-pattern to avoid in Phase 0:** jumping straight to "run Valgrind" without confirming the platform can run a profiler, or recommending tools the user already said they don't have.

### Phase 1: Translate diagnostics into constraints

This is the highest-leverage step. Each diagnostic number is a **filter** on what the leaking code can look like. Done well, this phase eliminates 90%+ of code from suspicion before any source review.

For each piece of ground truth, derive a constraint:

| Diagnostic input | Derived constraint on suspect code |
|---|---|
| ptmalloc utilization `(system − free_chunks) / system` | > 80% → real data accumulation; < 50% → fragmentation/return issue dominates |
| Average free chunk size = `total_free_bytes / chunk_count` | The likely **size of the leaking object** (32-128 B → tree/list node; 64-256 B → string; KB+ → buffer) |
| Growth rate (bytes/sec) ÷ average chunk size | Estimated **allocation frequency** of the leak source (per second) |
| Thread count stability | Stable → leak is in shared/per-thread steady-state logic; **growing → thread leak** (different bug class) |
| arena count vs thread count (glibc) | ≈ → leak is per-thread balanced; ≪ → leak is in single arena (often main thread) |
| Subheaps per arena (count of 64 MB segments / arena count) | Multiple → arena grew over time (accumulation evidence) |
| Pss ≈ Rss | Private memory; **rules out shared mmap, file cache, copy-on-write** |
| Mmap allocation share (`<total type=mmap>` size / total) | Small (< 5%) → ignore big-block hypothesis; large → suspect 16 MB+ allocations |
| Steady vs spiky growth | Steady → stable business path; spiky → event-driven (reconnect storm, config reload, burst) |

After this phase, you should have a **suspect profile** — a one-sentence picture of what the leaking code must look like. Example from the case study:

> "Long-lived container holding ~512 B objects, written at ~500 ops/sec by all worker threads, on a steady-state business path, no matching cleanup path."

This profile is the input to Phase 2-3.

### Phase 2: Multi-hypothesis generation (anti-overfit)

Enumerate **all plausible causes** before committing to one. Rank by how well each matches the suspect profile from Phase 1, but **do not discard low-ranked ones until cross-verified**.

| # | Hypothesis | Signature to look for |
|---|---|---|
| H1 | Genuine memory leak (`new` / `malloc` without matching free) | High allocator utilization + monotonic data structure |
| H2 | Unbounded design growth (cache, log, metric, history) | Indistinguishable from H1 externally; differentiate by reading code intent |
| H3 | Allocator fragmentation (free chunks plenty, can't pack) | Utilization < 60% + many small free chunks scattered |
| H4 | Allocator not returning memory to OS | Utilization moderate + many subheaps + steady growth even as in-use is stable |
| H5 | Thread / fiber leak (each new thread leaks per-thread state) | Thread count grows over time |
| H6 | Custom memory pool growing | Large `[anon]` segments not 64 MB sized; possibly with reserved/PROT_NONE pattern |
| H7 | Memory-mapped file growth | Visible in `pmap` as file-mapped segments growing |
| H8 | Shared memory growth | Pss ≪ Rss (private smaller than total) |
| H9 | Stack growth (recursive / deep threads) | `[stack]` segments large or numerous |
| H10 | Third-party library leak (protobuf Arena, libcurl, OpenSSL) | Specific to deps in use; check known patterns |

For each, predict what its observable signature would be. Cross against Phase 0 data. Eliminate the ones that genuinely don't match. **Keep at least 2 alive** going into Phase 3.

**Anti-overfit reminder:** the case-study program (aarch64, ptmalloc, 4 GB/day) doesn't mean every leak looks like that. Don't assume:

- The user is on the same arch (could be x86_64, arm32, RISC-V)
- The user uses glibc ptmalloc (could be jemalloc, tcmalloc, mimalloc, musl)
- Default config (user may have set `MALLOC_ARENA_MAX`, custom allocator via LD_PRELOAD)
- C++ specifically (could be C with `new`, or mixed)
- Long-running (could be a batch job with bounded life)
- Linux (could be FreeBSD, embedded RTOS)

Each assumption needs to be verified against Phase 0 data.

### Phase 3: Targeted source review (when applicable)

Skip if no source is available, or if Phase 2 ruled in H3/H4/H5/H7/H8 (those don't need source review; they're config/operations issues).

For H1, H2, H6, H10 — source review with the suspect profile as filter.

**Method (semantic, not grep):**

1. **Find "all-worker-paths"** — main loops, dispatchers, request handlers, message processors. The code where every thread goes through every cycle. This is the haystack.
2. **List "long-lived containers" by form:**
   - `static` class members
   - namespace-level globals (`.cpp` top-of-file containers)
   - Singleton/Manager class members (`Foo::instance().container`)
   - `thread_local` containers
   - Members of objects whose lifetime is process-lifetime
3. **For each long-lived container, locate ALL writes and ALL removes**
   - Writes: `insert`, `emplace`, `push_back`, `operator[]=`, `try_emplace`, `merge`, `[] = ...`
   - Removes: `erase`, `clear`, `pop_*`, `extract`, `reset()`, `swap` with empty
4. **Semantic asymmetry check** — not just counting calls, but reasoning about:
   - Triggering conditions: is the remove path conditional on something rare?
   - Exception paths: does an exception skip the remove?
   - Branch frequencies: is the write in the hot loop, remove in cold cleanup?
   - Lifetime: does the container outlive what it should hold?
5. **Rate sanity check** — estimate: `bytes_per_insert × inserts_per_second` for the suspect. Must match the observed rate within ~one order of magnitude. If 100× off, it's not this one.

**C++ leak pattern library:**

| Pattern | Profile signature | Identification cues |
|---|---|---|
| **A. Monotonic map<K,V>** (most common) | Long-lived + small objects + hot insert | `unordered_map`/`map` member; insert in dispatch, erase rare or missing |
| **B. `vector<T*>` no destructor delete** | Long-lived + small objects | Owns raw pointers; container's destructor doesn't delete them |
| **C. `shared_ptr` cycle** | Many control blocks (small frees) + lifetime confused | A holds `shared_ptr<B>`, B's callback captures `shared_ptr<A>` |
| **D. Subscribe without unsubscribe** | Long-lived broker + small closures | `subscribe`/`register`/`addListener` count > matching unsubscribe count |
| **E. `thread_local` container** | Per-thread balanced growth | `thread_local` declaration + container type, no reset across cycles |
| **F. Third-party library hot spots** | Specific to lib | protobuf Arena no Reset; libcurl handle no cleanup; SSL_CTX session cache no cap; spdlog async buffer; nlohmann::json Parse reuse |

**To invoke source review programmatically** (e.g., paste into an LLM with the source):

```text
context:
  - C++ program, [arch], default allocator [if known]
  - RSS grows at [rate]
  - From diagnostics:
    [paste the Phase 1 constraint table]
  - Suspect profile:
    [paste the one-sentence picture from end of Phase 1]

task:
  Semantic review (NOT grep). For the attached source:

  1. Identify "all-worker-paths" — main loops, dispatchers, handlers
  2. List long-lived containers (static / namespace / Singleton / thread_local)
  3. For each, list all writes and all removes; analyse asymmetry semantically
  4. For each candidate, ESTIMATE byte-rate it contributes; compare to observed rate
  5. Rank top 5 suspects; for each, give:
     - file:line of the smoking gun
     - why it matches the profile
     - byte-rate estimate within an order of magnitude of observed
     - which pattern A-F (or other)
     - suggested fix

Do not produce a grep-style report (list of files with regex hits).
Reason explicitly about lifetime, frequency, and rate.
```

### Phase 4: Cross-verification (anti-overfit)

**Before concluding "X is the cause", confirm with at least two independent methods.** A single line of evidence can be a coincidence; two independent lines converging is signal.

Independent methods:

| Method | What it proves |
|---|---|
| Snapshot diff (pmap + malloc_info over time) | Growth rate, segment-level breakdown |
| Allocator stats diff (`malloc_info` `<system>` vs `<total>` delta) | Distinguishes "real allocation" from "free-but-not-returned" |
| Source semantic review with rate estimate | Identifies specific code + predicts rate |
| Live profiler (bcc memleak, perf uprobe, custom LD_PRELOAD wrapper) | Captures actual leak stack traces |
| Env-var experiment (`MALLOC_ARENA_MAX`, `MALLOC_TRIM_THRESHOLD_`, jemalloc preload) | Changes allocator behavior; if RSS changes, leak hypothesis was wrong |
| Code modification + redeploy | The most definitive: fix → observe → confirm growth stops |

**Convergence rule:** if Phase 3 says "Pattern A in ClassMyCache::add", confirm by at least one of:
- Snapshot diff shows the rate matches estimate (~1 OOM)
- LD_PRELOAD profiler captures `MyCache::add` as the top allocator
- Setting a `clear()` call in the right place reduces RSS growth in test

If only one line of evidence points to a cause, you have a hypothesis, not a conclusion. **Continue to track alternatives.**

---

## Tool selection matrix

When choosing a profiler/analysis tool, match to constraints:

| Constraint | Tool |
|---|---|
| Can restart, lots of RAM, dev env | **ASan** (`-fsanitize=address`) or LSan (`-fsanitize=leak`) |
| Can restart, embedded / limited RAM | **Custom LD_PRELOAD allocator wrapper** (~100 lines, gcc + glibc only) |
| Cannot restart, has bcc-tools | **`bcc memleak -p PID`** (eBPF, no restart) |
| Cannot restart, has perf | **`perf probe + perf record` on malloc uprobe** |
| Cannot restart, none of above | **Snapshot diff** (pmap + malloc_info over time) + **gcore** to a dev machine for offline analysis |
| Can restart, want visual UI | **heaptrack** (records, then GUI analysis) |
| Suspect allocator (not real leak) | **`MALLOC_ARENA_MAX=2` experiment** OR **`LD_PRELOAD=libjemalloc.so` experiment** |

For each tool, document its overhead — Valgrind is 10-50x slowdown (rarely viable in production), ASan is 2-3x CPU and 3x memory, bcc memleak ~negligible, snapshot diff zero.

---

## Knowledge base reference

### Allocator fingerprints

- **ptmalloc (glibc)** subheap size: 64 MB on 64-bit (a `[anon]` mapping of exactly `65536` KB in `pmap` strongly suggests this)
- **ptmalloc** default arena cap: `8 × n_cpu` on 64-bit (`2 × n_cpu` on 32-bit)
- **ptmalloc** mmap threshold: 128 KB by default (allocations ≥ this go to `mmap` directly, bypass arenas)
- **ptmalloc** trim threshold: 128 KB by default (only top-of-heap free chunks above this get sbrk-released)
- **jemalloc** default chunk: 4 MB; manages its own profiling via `MALLOC_CONF`
- **tcmalloc** per-thread cache; very different RSS shape, more aggressive return
- **musl libc** allocator: simpler, less fragmentation but also less optimized
- **Custom mimalloc / snmalloc / hoard**: each has its own segment patterns

### Diagnostic numbers from a real case (calibration reference)

(From an actual investigation, kept here as a sanity-check reference; do not pattern-match user's data to these specifically.)

```
Program:  C++ aarch64 server, default ptmalloc, 8 CPUs
RSS:      21.7 GB, growing ~4 GB/day = ~46 MB/min ≈ 460 KB/sec
Threads:  59 stable
Segments: 309 × 64 MB anon (= 19.3 GB, 89% of RSS) + 3 large + heap + libs

malloc_info summary:
  <system size> 20.17 GB
  <total fast>   73 KB
  <total rest>  469 MB    ← only 2.3% free, utilization 97.7%
  <total mmap>  665 MB    ← 42 large direct-mmap blocks

Suspect profile: long-lived container, ~512 B objects, ~500 ops/sec,
all-workers, steady-state. Most likely pattern A (monotonic map).
```

The point: the rate (460 KB/s) × the chunk size (~512 B) constraint immediately ruled out big-buffer hypotheses and zeroed in on small-object container patterns.

### Common false-positive readings

- "RSS is growing" while `system` stays flat → not allocator-real; check `[stack]`, `[heap]` vs page cache
- ptmalloc per-thread arena residency looks like growth but is reuse
- `top` shows large RSS but `Pss` is small → most memory is shared (libs, page cache)
- OOM-killer victim reporting can differ from `/proc/self/status` due to oom_score adjustments

---

## Anti-overfit checklist

Before concluding "the cause is X":

- [ ] Did Phase 0 ground truth actually constrain to X, or could it match other causes?
- [ ] Have at least 2 hypotheses (H1-H10) been considered and evaluated?
- [ ] Has at least one independent verification method confirmed X (snapshot, profiler, env var, code change)?
- [ ] Does the source-level rate estimate match observed rate within one order of magnitude?
- [ ] If a fix is proposed, is there a measurement plan to confirm RSS growth actually stops post-fix?
- [ ] Could a DIFFERENT leak in the same codebase coexist? (Sometimes you fix one and another shows up.)
- [ ] If symptom was on a niche platform (qemu, embedded, RTOS), did you check that platform's specific gotchas (qemu mmap emulation, embedded fixed heap, etc.)?

If any box is unchecked, you have a partial answer; communicate uncertainty to the user.

---

## Output format expectations

When concluding an investigation, present to the user:

1. **Summary of findings** (one paragraph): what the leak is, the evidence
2. **Confidence level**: how many independent methods converged
3. **Recommended fix** (or fixes, if hypotheses are tied)
4. **Verification plan**: how to confirm the fix worked
5. **Open questions / unverified hypotheses**: what was NOT ruled out

Avoid:
- Listing greps without analysis
- Single-hypothesis conclusions when only one method was used
- Recommending tools the user said are unavailable
- Skipping the rate/constraint sanity check

---

## Skill version

- v1 — Initial extraction from C++ aarch64 case study (2026-06)
- Methodology: constraint-driven, multi-hypothesis, cross-verified
- Tested-against case: aarch64 ptmalloc 21 GB RSS @ 4 GB/day growth

Update version when adding new patterns / tools / platform gotchas.
