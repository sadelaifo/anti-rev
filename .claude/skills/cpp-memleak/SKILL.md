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

## First principles — what every C++ leak is

Before any phase, anchor on the essential model. Every memory leak in C++ satisfies the same equivalent statement:

> **There exists a long-lived holder structure,**
> **an operation that adds references to it,**
> **and a missing or broken operation that should remove them.**

| Holder structure | "Add" operation | Missing "remove" |
|---|---|---|
| `std::vector<T>` member | `push_back` / `emplace_back` | `erase` / `pop_back` / `clear` |
| `std::map / unordered_map` member | `emplace` / `operator[]` / `try_emplace` | `erase` / `clear` |
| Callback / observer registry | `subscribe` / `register` / `addListener` | `unsubscribe` / `remove` |
| `shared_ptr` reference cycle | `make_shared` / capture in lambda | (break with `weak_ptr`) |
| Async queue | producer `push` | consumer can't keep up / not running |
| `thread_local` container | per-thread `push` | no per-thread reset |
| Cross-module boundary (plugin↔platform↔third-party) | API hand-off | symmetric hand-back missing |

Crucially, **these are not seven independent leak types** — they are the same essential mechanism instantiated on seven kinds of structure. Investigation reduces to **find the structure, find the add, find the missing remove**.

Architectural context — "is this a plugin host?", "is this a microservice?", "is this third-party-heavy?" — is **data about where the holder structure might live**. It is **not** a narrowing of the hypothesis. A plugin host can still leak inside one plugin, in the platform, in a third-party library, or at the platform/plugin boundary — the same first-principles model applies to each location.

Use this framing whenever you catch yourself jumping from a contextual label ("it's a plugin host", "it's a gRPC server") to a specific mechanism ("must be cross-plugin interaction", "must be a connection cache"). The label only enlarges your search list of candidate structures; it does not eliminate any.

---

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

**Architectural context — purely as data, NOT as a narrowing.** Ask what the process is — plugin host (`dlopen` of `.so` / `.dll`), microservice, monolith, multi-tenant fabric, game engine, etc. — and which third-party libraries it links against. Record these as context. They tell you **where the holder structure might be located** (one of several candidate code regions), but they do **not** eliminate any of the patterns A-F or any code region.

A plugin host can still leak in:
- a single plugin's internal container
- the platform's plugin-management code
- a third-party library used by one or several plugins
- the platform/plugin API boundary
- initialization-time state held for process lifetime

Don't pre-pick one based on the label. Carry all candidates into Phase 2.

When the leak appears only under a specific configuration / plugin combination / workload, that's a **strong cross-verification signal** (Phase 4) — but it still doesn't tell you the mechanism. It only narrows *where the work runs*. The mechanism could still be any of A-F.

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

**Safety principle: observation must not break the patient.**

The diagnostic target is almost always a production / pre-production process the user cannot afford to crash. Tag every command with a risk level and never blindly issue L2/L3:

| Risk | Definition | Examples |
|---|---|---|
| **L0** | Reads `/proc/PID/*` only | `grep VmRSS`, `pmap`, `cat /proc/PID/maps` |
| **L1** | gdb attach + reads only — no `call`, no `set` | `info threads`, struct field reads (`p main_arena.system_mem`), arena chain walk, `thread apply all bt` |
| **L2** | gdb `call` of a function in the target — hijacks one of its threads | `call malloc_info(0, f)`, `call malloc_stats()` |
| **L3** | Mutates target or freezes it for an extended period | `set var ...`, `gcore` (process frozen 30 s to several minutes) |

Hard rules:

1. **Default to L0/L1.** Only escalate when the data they can't provide is essential. Prefer struct walks over `call` whenever the field is directly readable.
2. **Never `kill -9` a hung gdb attached to a live process.** If gdb was mid-`call`, killing it leaves the hijacked thread in the called function's frame — any glibc mutex (e.g., `malloc_info` takes per-arena locks) acquired but not released will deadlock the rest of the process the next time it allocates. Use `Ctrl-C` first; if that fails, `kill -TERM` (default signal) so gdb can clean up. If it still hangs, accept the hung gdb — the process is in ptrace-stop until it cleans up, but stays alive.
3. **Wrap every gdb invocation in `timeout 60`.** Default `timeout` sends SIGTERM, which gdb handles cleanly.
4. **Every gdb `while` loop must have an iteration cap** (`while $n < 200`), never `while 1`. A bad pointer in an arena chain walk otherwise loops forever.
5. **`gcore` is L3** — coordinate the freeze window with the operator before running. RSS-proportional: a 3 GB process freezes ~30 s; a 21 GB process freezes minutes.
6. **One gdb at a time per PID.** ptrace is mutex-style; a second concurrent attach blocks indefinitely.

The cost of a deadlocked production process from an unsafe diagnostic command is days of incident response. The benefit of one extra data field is rarely worth it.

**Strategic note: a restart is a diagnostic opportunity, not a setback.** If the target process is restarted mid-investigation — OOM-killed, manually restarted, periodic-maintenance restart — do NOT treat it as data loss. The early-growth phase has the highest signal-to-noise ratio for catching the leak:

- At 21 GB steady state, ~100 MB/h of new leak signal is buried under 200× the steady history.
- At 3 GB just after restart, the same 100 MB/h growth is visible as a clean trajectory; the concentration of allocations into a specific arena is **happening, not finished**, so the cause is observable in motion.
- Thread names (`pthread_name`) are still at their initial entry-function values before fork/exec chains overwrite them, making arena → tid mapping (cross-verification step) far more readable.
- A restart also opens a window for **controlled-comparison experiments**: change one `MALLOC_*` env or `LD_PRELOAD` per restart and observe whether RSS behavior changes. Without a restart, these experiments are unavailable.

When a restart occurs:
1. Capture baseline snapshot **immediately** at low RSS (full Phase 0 + Phase 1 data).
2. Run the concentration check + arena→tid mapping **now** — it's far cheaper here than at saturation.
3. Re-sample at multiple time points along the growth curve (1×, 2×, 3× initial RSS) to track which arena grows fastest.
4. Evidence from prior runs (before the restart) remains valid as an **independent observation** to cross-verify the new run's findings.
5. If another restart window is available, run ONE allocator-tuning experiment (e.g., `MALLOC_ARENA_MAX=2`) per window — never combine multiple env changes in the same restart.

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
| **Single-snapshot arena concentration** | A snapshot shows "arena N holds 67% of heap". This describes **historical accumulation up to this moment** — not necessarily where memory is actively growing right now. **Without a T0→T1 per-arena delta**, you cannot distinguish "this arena is actively accumulating now" from "this arena front-loaded long ago and has been static since". Both yield the same concentration signal. |
| **max/avg stability across snapshots** | If `max/avg` is the same in T0 and T1, this has **multiple solutions**: (a) the top arena grew proportionally with everyone; (b) **the top arena's value is locked and growth happens outside per-arena heap entirely** (mmap'd large chunks, business direct mmap, thread stacks); (c) the top arena number changed but the new top happens to match the old ratio. Always look at the top arena's absolute Δ and the per-arena sum's Δ before drawing a conclusion. |

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

> **About "Pattern G" plugin / combo-dependent leaks**: an earlier revision of this skill listed combo-dependent plugin leaks as a separate Pattern G. That was overfit. A combo-dependent leak still falls into A-F — the structure may be a vector in one plugin, a callback registry on the platform side, an async queue between two plugins, etc. The combo-dependence is a clue about *where to look* (which plugin's code, which boundary), not about which mechanism is at work. Always run A-F semantic review at every candidate location the architecture suggests.

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
| **Plugin elimination experiment** (plugin host only) | Load N-1 of N plugins, rotate omission; combo where RSS stays flat identifies the involved plugin(s). Often the cheapest way to localize a combo-dependent leak. Cost: each rotation needs a restart + observation window |
| **Multi-snapshot rate validation** | Once a steady-state rate R is measured at one observation point, predict subsequent snapshots: at time T+Δt, RSS should equal observed-RSS + R·Δt; same for top arena. Match within 20% confirms a stable rate (rules out burst, threshold, and one-off causes). Mismatch tells you which sub-hypothesis to revisit. Cost: a follow-up snapshot run after the chosen Δt. Worth doing whenever you've quoted a rate as if it were stable. |
| **Init-baseline arithmetic** | Compute process uptime (from `/proc/PID/stat` field 22 + `btime`). Implied init-time accumulation = current RSS − (rate × uptime). A small (<1 GB) baseline ⇒ runtime-driven leak; a multi-GB baseline ⇒ init-time accumulation dominates. Cheapest possible discrimination between two very different fix paths. |
| **Rate → call-frequency translation** | Top-arena rate (bytes/sec) divided by typical leaked-object size gives the suspect function's invocation frequency in Hz. The Hz range labels the code pattern: 20-100 Hz ≈ simulator tick / heartbeat; 100-1000 Hz ≈ moderate RPC; 10000+ ≈ epoll callback. Narrows the source-review question from "any function" to "this Hz family of functions". |
| Code modification + redeploy | The most definitive: fix → observe → confirm growth stops |

**Snapshot-delta decision matrix (high-leverage, zero-overhead method for glibc).**

Take two snapshots ≥ 30 min apart (whatever lets you observe a few hundred MB of growth). Extract from each: `VmRSS`, count of 64 MB anon segments (ptmalloc subheaps), and `malloc_info` summary lines (`<system current>`, `<total rest>`, `<total fast>`, `<total mmap>`). Compute deltas, then read off this table:

| Pattern | Interpretation | Action |
|---|---|---|
| Δsystem ≈ Δ(subheap_count) × 64 MB **AND** Δrest ≈ 0 | **100% true accumulation in ptmalloc** — newly OS-allocated memory is all live data, not free pool growth. Fragmentation hypothesis is dead. | Skip allocator tuning; go straight to source review / live profiler |
| Δsystem ≈ Δrest | Allocator pulling pages from OS, but new pages end up in free pool. **Free-but-not-returned** behavior. | Try `MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=131072`; if RSS stabilizes, no source fix needed |
| Δsystem ≪ ΔVmRSS | Growth is **outside ptmalloc** (mmap, stack, shared anon, file mappings). | Diff the `pmap` files (`comm -13 t0.pmap t1.pmap`) to see which non-heap segment is growing |
| Δsubheap_count = 0 but Δrest grows | Heavy churn inside existing arenas; RSS stable. Not a leak. | Stop investigating; this is normal |
| Δmmap (`<total type="mmap">`) grows | Large direct mmap blocks (≥ 128 KB) accumulating. | Suspect big buffers, file mappings, or `posix_memalign` users with large alignments |

The first row is the cleanest possible signal for a true leak — if you see it, source review is justified and tuning is wasted time.

**Per-arena concentration check (high-leverage when glibc, multi-arena).**

When the snapshot-delta matrix points to "100% true accumulation", do NOT yet assume "all workers contribute". The per-arena distribution decides whether the leak is **distributed** or **concentrated** — completely different source-review scopes.

Parse the per-`<heap nr=N>` `<system current>` blocks out of `malloc_info`:

```bash
awk -F'"' '
  /<heap nr=/        { a=$2; in_h=1; s=0; next }
  /<\/heap>/         { if (in_h) printf "%4d %12d\n", a, s; in_h=0; next }
  in_h && /<system type="current"/ { s=$4 }
' mi.xml | sort -k2 -n
```

Compute `max / avg` across all arenas:

| Ratio | Interpretation | Source-review scope |
|---|---|---|
| `< 2×` | Distributed evenly across arenas | "All workers contribute" picture holds — review shared dispatcher / handler code |
| `2× – 10×` | Hot worker(s) | Picture narrows to "a small group of workers" |
| `> 10×` | **Single arena dominant** — one thread is responsible | Map arena → tid (see below); review only that thread's code |
| arena 0 dominant | Main thread | Review `main()`, init code, main-thread Singleton/Manager state |

When `> 10×`, **map the dominant arena to a specific thread** using glibc's `thread_arena` TLS:

```bash
gdb -batch -p $PID \
    -ex 'thread apply all printf "tid=%d arena=%p\n", $_thread, thread_arena' \
    -ex 'detach' 2>&1 | grep ^tid=
```

Match the thread whose `arena=...` matches the top arena's address (get via `main_arena.next` walk; see runbook). The resulting tid + its backtrace's entry function is the **definitive scope** to hand to source review — typically slashes the audit area from "whole codebase" to "single thread's call tree".

This technique transforms a high-arena-concentration finding from a curious data point into an actionable scope cut.

**Simplified identification when arena→tid mapping is unavailable.** Stripped libc (no `main_arena` symbol), gdb without Python, or no debug info can all block the precise arena→tid mapping. Rather than escalating to gcore-and-offline, fall back to three L0 signals that often pin the suspect down to 1-3 candidate tids without any gdb work:

1. **Thread-name uniqueness** — `for tid in /proc/PID/task/*; do cat $tid/comm; done | sort | uniq -c`. Look for "orphan" names (1-2 instances among 50 identical workers); a semantically-named singleton (DataLoader, MetaCache, RouteMgr) is often the suspect.
2. **CPU-time leaderboard** — `/proc/PID/task/*/stat` fields 14+15 (utime+stime). A 10× outlier vs. peers means that thread is consistently busy; on a steady-state leak it correlates with the allocator.
3. **Stack-top frequency** — parse the existing `thread apply all bt`; most threads are in `pthread_cond_wait` / `epoll_wait` / `futex_wait`; the 3-5 that are in business code are the candidates.

When all three signals point to the same small set, hand off those tids to source review. Candidate set of 1-3 (instead of "a single precise tid") is still two orders of magnitude smaller than "whole codebase" — usually good enough. Reserve the precise arena→tid path for cases where the candidate set is still too large (e.g., 50 identically-named workers with no CPU outlier).

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

malloc_info summary at T0:
  <system current> 20.17 GB
  <total fast>     73 KB
  <total rest>     469 MB    ← only 2.3% free, utilization 97.7%
  <total mmap>     665 MB    ← 42 large direct-mmap blocks

T0 → T1 snapshot diff (69 minutes apart):
  ΔVmRSS         = +186 MB
  Δsubheap_count = +3   (3 × 64 MB = 192 MB ≈ ΔVmRSS)
  Δsystem        = +186 MB
  Δrest          = -0.01 MB  (free pool essentially flat)
  Δfast          = -0.003 MB
  Δthreads       = 0   (still 59)
  → Snapshot-delta row 1 hit: 100% true accumulation. Source review justified.

Suspect profile: long-lived container, ~512 B objects, ~900 ops/sec,
all-workers, steady-state. Most likely pattern A (monotonic map).
```

The point: the rate (460 KB/s) × the chunk size (~512 B) constraint immediately ruled out big-buffer hypotheses and zeroed in on small-object container patterns. The snapshot diff then ruled out fragmentation cleanly in one round.

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
- [ ] **Have architectural labels narrowed the hypothesis space?** "It's a plugin host so the leak must be at the plugin boundary" / "It's a gRPC server so it must be connection caching" / "It's a microservice so it must be a stale message queue" — none of these chains of reasoning are valid. Labels enlarge the candidate-location list; they don't shrink it. If you narrowed because of a label, re-open the discarded hypotheses.
- [ ] **Have you confused historical accumulation with active accumulation?** Single-snapshot arena/segment concentration tells you where memory CURRENTLY SITS, not where it is CURRENTLY GROWING. The two can be different if accumulation was front-loaded and then plateaued at that location while later growth lands elsewhere. **Validate every "X is the leak location" claim with an explicit T0 → T1 per-arena (or per-segment) delta showing X is still growing during the observation window.** A constant `max/avg` ratio in particular has multiple solutions — see the Phase 1 row "max/avg stability across snapshots".

If any box is unchecked, you have a partial answer; communicate uncertainty to the user.

---

## Strategic note: when to stop external diagnosis

External (process-not-yet-instrumented) diagnosis — snapshot diffing, `/proc` reads, gdb attach with no business symbols — has a sharp diminishing-returns curve. Recognize when you've hit it. Continuing past the inflection point doesn't fail loudly; it silently wastes the diagnosis driver's energy and accumulates plausible-looking but unverified narrative around real constraints.

Signs you've hit the inflection:

1. **Data self-contradicts under the constraints of the allocator's data model.** (E.g. the global `<system current>` Δ should equal Σ per-arena Δ in glibc's malloc_info; if they disagree, you've reached the limit of external introspection — the next step needs `LD_PRELOAD` allocator wrapping or `gcore` offline, not more snapshots.)
2. **Each new round of snapshots narrows the constraint set by less than half the previous round.** Diminishing returns.
3. **The driver of the diagnosis says they're tired / can't sustain it.** Human attention is the scarce resource; respect it.
4. **Commands are getting more complex but the value-per-command is dropping.** You're now answering meta-questions ("why doesn't my awk add up?") rather than substantive ones ("where is the leak?").
5. **The core hard constraints are tight enough for source review to act on.** Don't keep refining when the next step already has enough.

When any one triggers, package and hand off. The hand-off doc should structure findings into three tiers:

- **A. Confirmed hard constraints** (high confidence, multiple independent observations)
- **B. Single-point observations** (medium confidence, could be coincidence — one snapshot caught the suspect thread mid-`std::string::replace` is NOT the same as confirmed evidence of string-based accumulation)
- **C. Unresolved contradictions / open questions** (explicitly call out what you couldn't resolve; the source-review team should know which mysteries are yours and which are theirs)

Resist the urge to bundle in the speculative narratives you built and discarded along the way. The clean three-tier hand-off is more useful than a chronological story of your investigation.

Acceptable next steps when external diagnosis is exhausted, ranked by cost:

| Next step | Cost | When to choose |
|---|---|---|
| Source review (hand off to whoever has source) | 0 | Default |
| LD_PRELOAD allocator wrapper with backtrace dump | ~hundreds of LOC C + one restart | Source review is 2-3 weeks without result |
| `gcore` + dev-machine offline analysis | ~30 s to several minutes process freeze | Need to confirm actual in-use object distribution / container size |
| `MALLOC_ARENA_MAX=2` experiment | One restart | Suspect your own diagnostic picture is biased |
| jemalloc + heap profiling | One restart + build jemalloc | Need real allocation stack traces; ptmalloc has no built-in profiler |

Stopping external diagnosis is not failure — it's transferring the work to the right tool. The investigation continues; the diagnosis driver just rotates out.

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
- v1.1 — Restart-window technique + per-arena concentration + arena→tid mapping
- v1.2 — Safety rules (L0-L3 risk levels, 6 disciplines, hang ladder); simplified identification (thread name + CPU + bt) when arena→tid unavailable
- **v1.3 — First-principles framing** (every leak = holder structure + add op + missing remove); Pattern G (combo-dependent) **demoted** to a note under A-F because architectural labels (plugin host, microservice, gRPC, etc.) do not narrow the leak mechanism, only enlarge candidate locations; anti-overfit checklist gains an explicit "did labels narrow your hypothesis?" check
- Methodology: constraint-driven, multi-hypothesis, cross-verified, **label-blind to mechanism**
- Tested-against case: aarch64 ptmalloc 21 GB RSS @ 4 GB/day growth on a plugin-host process (`simultor`); successive over-narrowing (single-arena → single-worker → plugin-interaction) was the lesson that drove v1.3

Update version when adding new patterns / tools / platform gotchas. **Resist** adding a new "Pattern X" for each new architectural circumstance encountered — first check if it's an existing A-F mechanism at a new location.
