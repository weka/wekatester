# wekatester Calibrated Sizing (-a cal / -a hybrid) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace guessed queue depths in auto mode with per-client measured knees (`-a cal`), a formula-seeded variant (`-a hybrid`), and retire the falsified DRAM ceiling from `-a max`.

**Architecture:** All code lives in the single-file `wekatester` (bash 3.2 + embedded python3 heredocs), following its existing patterns: probe facts → pure-python derivation → per-host staged variants. Calibration is a new phase between `verify_fio_ports` and `stage_jobfiles`: generated ladder jobfiles run through the same `fio --client` machinery as real jobs, per-client knees are merged into `targets.final` (below CLI/host-file precedence, above the tuner), and the existing `-a` writeback persists them into `hostlist.csv` — which is also the cache that lets later runs skip calibration.

**Tech Stack:** bash 3.2 (macOS-compatible), python3 stdlib heredocs, fio client/server. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-31-wekatester-auto-mode-design.md` — sections "Working-set sizing (max tier) — CORRECTED 2026-08-18" and "Calibrated sizing: -a cal and -a hybrid (2026-08-18)".

## Global Constraints

- bash 3.2 compatible (no associative arrays, no `read -t 0.5` fractions, no `wait -n`).
- NEVER a bare `wait` — the run-log tees are always-alive children; every wait is pid-scoped.
- No stderr suppression (`2>/dev/null` banned); capture to a variable/file when noise is expected.
- Python heredocs own stdin — pass data as arguments or files, never stdin.
- README `# Usage` block must stay byte-identical to `./wekatester -h` (suite-enforced).
- `bash -n` after every edit; the full suite runs ONCE before each commit.
- All staged variants carry `unique_filename=0` + `<host>.` filename prefixes (stamped by `stamp_unique_names`); calibration jobfiles must do the same explicitly.
- Constants live in one place with a comment: `CAL_STEP_RUNTIME=10`, `CAL_RAMP=2`, `CAL_GAIN_PCT=10`, `CAL_BW_QD_CAP=64`, `CAL_IOPS_QD_CAP=128`, `CAL_HYBRID_BW_START=8`, `CAL_HYBRID_IOPS_START=64`.

---

### Task 1: Retire the DRAM ceiling from -a max

**Files:**
- Modify: `wekatester` — `probe_workers` (drop the `_weka_ram` query + login hint), tuner python (drop `cache_bytes`, `CACHE_MULT`, the `_weka_ram.json` parse; `ws = WS_FLOOR`), keep `run_weka_master` (unused, future weka calls).
- Test: `tests/test_wekatester.sh` — delete the `_weka_ram.json` fixture row write, the "failed weka RAM query hints at weka user login" test, the "server-level RAM fallback" test, the exit-127 retry test's *probe* wiring assumptions (the `run_weka_master` unit tests stay — the helper remains).

**Interfaces:**
- Produces: tuner sizes small-file namespaces as `ws = WS_FLOOR` (8 GiB/host); no `weka` CLI runs anywhere under `-a`.

- [ ] **Step 1: Update the tuner-fixture tests** — remove the `_weka_ram.json` printf from `tuner_fixture` (tests/test_wekatester.sh:259) and adjust every nrfiles expectation that was derived from `2 × 24.67GB / 2 hosts` to the 8 GiB floor (`nrfiles(iops) = max(2, ceil(8GiB/(numjobs×1G)))`). Grep: `grep -n '_weka_ram\|12335448064' tests/test_wekatester.sh`.
- [ ] **Step 2: Run the affected tests to see them fail** against current code (floor vs ceiling mismatch).
- [ ] **Step 3: Tuner edit** — in the tuner python: delete the `cache_bytes` block (the `ram_path` parse, COMPUTE filter, both `warn(...)` fallbacks) and `CACHE_MULT`; replace `ws = max(WS_FLOOR, CACHE_MULT * cache_bytes // len(hosts))` with `ws = WS_FLOOR` plus a comment pointing at the corrected spec section (backend DRAM never caches user data; the floor is a spread rule, not a cache bound).
- [ ] **Step 4: Probe edit** — in `probe_workers`, delete the `run_weka_master`-driven `_weka_ram.json` block and both NOTE/WARNING lines; keep `df`. Delete the two RAM-probe tests named above.
- [ ] **Step 5:** `bash -n wekatester tests/test_wekatester.sh`; run the tuner/probe test subset; full suite once; commit `tuner: -a max sizes by the floor -- the DRAM ceiling is gone`.

### Task 2: -a accepts safe|max|cal|hybrid

**Files:**
- Modify: `wekatester` — `parse_args` `-a` validation, usage text; `README.md` Usage block byte-sync + auto-mode prose.
- Test: `tests/test_wekatester.sh` — parse tests.

**Interfaces:**
- Produces: `AUTO_LEVEL` ∈ `safe|max|cal|hybrid`; `[ "$AUTO_LEVEL" = cal ] || [ "$AUTO_LEVEL" = hybrid ]` gates the calibration phase (helper `cal_mode()` returns 0 for cal/hybrid).

- [ ] **Step 1: Write failing parse tests** — `-a cal`, `-Ahybrid`, `--auto=cal` set `AUTO_LEVEL`; `-a bogus` still dies; `cal_mode` true only for cal/hybrid.
- [ ] **Step 2:** Run: fails (validation rejects cal).
- [ ] **Step 3:** Extend the `-a` value check to the four levels; add `cal_mode() { [ "$AUTO_LEVEL" = cal ] || [ "$AUTO_LEVEL" = hybrid ]; }`; update `-h` text (`-a safe|max|cal|hybrid`; one line each: cal = measured iodepth ladders, hybrid = formula-seeded ladder) and regenerate the README Usage block byte-for-byte; extend the README auto-mode section per the spec.
- [ ] **Step 4:** Parse tests pass; full suite once; commit.

### Task 3: Set inspection — which ladders does this set need

**Files:**
- Modify: `wekatester` — new `cal_required <setdir>` (python heredoc).
- Test: `tests/test_wekatester.sh`.

**Interfaces:**
- Produces: `cal_required <setdir>` prints unique lines `bw read`, `bw write`, `iops read`, `iops write` (subset), derived from non-layout `[0-9]*` jobfiles: report type from the `# report` directive (`bandwidth`→bw; `iops`→iops; `latency` contributes nothing — qd=1 by definition); direction from each job's effective `rw=` (`read|randread`→read, `write|randwrite`→write, `rw|randrw|readwrite`→both). Empty output = nothing to calibrate.

- [ ] **Step 1: Failing test** — a set with `# report bandwidth` + `rw=read`, `# report iops` + `rw=randrw`, `# report latency` + `rw=randread` yields exactly `bw read`, `iops read`, `iops write` (sorted); a bw-write-only set yields `bw write`; a latency-only set yields nothing.
- [ ] **Step 2:** Run: fails (function missing).
- [ ] **Step 3:** Implement — python walks jobfiles (skip `is_layout` markers), reads the directive with the same regex as `report_directive`, collects section `rw=` values (global fallback), prints the sorted unique set.
- [ ] **Step 4:** Tests pass; commit.

### Task 4: Ladder step jobfile + knee math

**Files:**
- Modify: `wekatester` — new `stage_cal_step <type> <dir> <qd> <outdir> <host>...` (writes per-host step jobfiles) and `cal_gains <prev.json> <cur.json>` (python: per-client percent gain).
- Test: `tests/test_wekatester.sh`.

**Interfaces:**
- Consumes: `host_dir`, `host_priv`-independent; per-host engine from `$WORK_DIR/targets.final` field 3 (fallback: first proven engine in `$WORK_DIR/engine.results` for that host, else `psync`); per-host cpus from `$AUTH_DIR/$host.cpus`; usable cores from `$WORK_DIR/probe/$host` (`ncpus` − weka single-cpu masks, same rule as the tuner — expose the existing computation as `usable_cores <host>` if not already callable from bash).
- Produces: step jobfile `$WORK_DIR/cal/<host>/cal-<type>-<dir>-qd<qd>.job`; `cal_gains` prints one line per client: `<host> <cur_value> <gain_pct>` where value = bytes/sec (bw) or iops summed over read+write of the LAST section per host (same last-entry rule as the summarizer); prev `-` means first step (gain 100).

- [ ] **Step 1: Failing tests** — (a) staged step file contains: `directory=<host_dir>/.wekatester-cal`, `unique_filename=0`, `filename_format=<host>.cal.$jobnum.$filenum`, `bs=1Mi` (bw) / `bs=4k` (iops), `rw=` mapped (`read`→`read` for bw, `randread` for iops), `iodepth=<qd>`, `numjobs=<usable>`, `nrfiles=2`, `filesize=1G` (bw) / `filesize=256M` (iops), `runtime=10`, `ramp_time=2`, `time_based=1`, `direct=1`, `ioengine=<resolved>`, `cpus_allowed=<recorded>` + `cpus_allowed_policy=split` when cpus exist, `create_on_open=1` for write direction; read-direction step files carry NO create options (files come from the seed pass, Task 5). (b) `cal_gains` on two fabricated JSONs reports per-client gains and flags <10%.
- [ ] **Step 2:** Run: fails.
- [ ] **Step 3:** Implement both. `cal_gains` python: parse both files with the same `client_stats` / skip-`All clients` / last-entry-per-host rules as `check_fio_errors`; value = Σ over read+write of `bw_bytes` (bw mode) or `iops` (iops mode) — mode passed as arg 3.
- [ ] **Step 4:** Tests pass; commit.

### Task 5: The calibrate() orchestrator

**Files:**
- Modify: `wekatester` — new `calibrate()`; constants block.
- Test: `tests/test_wekatester.sh` (run_host stubbed; fabricated per-step JSONs drive the knee).

**Interfaces:**
- Consumes: `cal_required`, `stage_cal_step`, `cal_gains`, `run_host`, `check_fio_errors`.
- Produces: `$WORK_DIR/cal.results` lines: `<host> <bw_qd|-> <iops_qd|-> <nj|->` (nj only when the knee arrived below full cores — the qd ladder at nj=cores hit <10% gain at qd=1, then a descending nj probe found the knee; otherwise `-`). Logs `cal: <host> <type>-<dir> knee qd=<n> (<value human>)`. Fatal on any step's `check_fio_errors` failure.

- [ ] **Step 1: Failing test** — with `cal_required` forced to `bw read`, a run_host stub that returns fabricated JSONs (gains 100%, 40%, 12%, 4% across qd 1,2,4,8) produces `cal.results` with `h1 4 - -` (knee = last ≥10% step) and the log line; a stub whose qd-1 JSON carries a job error dies.
- [ ] **Step 2:** Run: fails.
- [ ] **Step 3:** Implement:
  - Per required ladder: seed pass for read-direction ladders (one un-measured write step, `create_on_open=1`, `runtime=5`) unless a write ladder of the same type already ran (its files persist for the read ladder — same names).
  - qd sequence: cal = `1 2 4 8 16 32 [64 128 iops-only]`; hybrid = `START/2 START START×2 ...` (START from the constants; descend below START/2 only while the lower step is within 10% of the one above it).
  - Per step: `stage_cal_step` per host → single `fio --client` invocation over all hosts (same command shape as `run_jobs`, `--eta=never`, output to `$WORK_DIR/cal/step.json`) → `check_fio_errors ... layout` (zeros allowed only for the seed pass — measured steps use `measured`) → `cal_gains prev cur` → hosts still gaining continue; a host below `CAL_GAIN_PCT` freezes its knee at the previous step. Ladder ends when every host froze or the cap hit.
  - All-hosts-parallel is inherent (one coordinator invocation per step); the per-step wait is on the single `run_host` — no fan-out, no bare wait.
  - Final: `rm -rf` each host's `.wekatester-cal` dir via parallel `run_host` with pid-scoped waits.
- [ ] **Step 4:** Tests pass (knee, freeze-per-host, error-fatal, scratch cleanup command issued); full suite once; commit.

### Task 6: Wire-in — skip cache, merge, writeback, dry-run

**Files:**
- Modify: `wekatester` — main() (call between `verify_fio_ports` and `stage_jobfiles` when `cal_mode`), new `apply_cal_results`, `dry_run_report` addition.
- Test: `tests/test_wekatester.sh`.

**Interfaces:**
- Consumes: `$WORK_DIR/cal.results`, `$WORK_DIR/targets.final` (may be absent when no `-t`).
- Produces: `targets.final` geometry fields filled from cal where they were `-` (bw_qd ← field 9, iops_qd ← field 17, both nj fields ← cal nj when present): CLI > host file > cal > tuner. Hosts whose relevant qd fields are already non-`-` are EXCLUDED from the ladder up front (log: `cal: <host>: hostlist.csv already carries <type> geometry -- reusing (re-measure with -g)`); `REGEN_LAYOUT=1` (-g) ignores the cache. The existing `writeback_targets` fill-mode then persists cal-filled fields into `hostlist.csv` unchanged — verify, don't reimplement.
- `-n`: prints `dry run: -a <level> would calibrate: <ladder list> on <hosts>` (from `cal_required` + the skip logic) without running fio.

- [ ] **Step 1: Failing tests** — (a) `apply_cal_results` fills only `-` fields; a CSV-supplied `iops_qd=64` survives; (b) skip logic excludes a filled host and includes it again under `-g`; (c) `-n -a cal` output names the ladders and executes nothing (no-ssh fixture proves no fio ran).
- [ ] **Step 2:** Run: fails.
- [ ] **Step 3:** Implement; `targets.final` absent (no `-t`) → all fields treated as `-`, results used for this run only (nothing to write back — writeback already requires `-t`/`-C`).
- [ ] **Step 4:** Tests pass; full suite once; commit.

### Task 7: Docs, suite, live sanity

**Files:**
- Modify: `README.md` (auto-mode section: the four tiers, calibration mechanics, cache semantics, the corrected sizing rationale with one sentence on the retired DRAM ceiling), `wekatester -h` already done in Task 2 — re-verify byte-sync.
- Test: full suite.

- [ ] **Step 1:** README prose per spec; byte-sync check.
- [ ] **Step 2:** Full suite once; commit; push on Frank's go (or standing permission).
- [ ] **Step 3:** Live gate (Frank or lab): `-a cal -t -- localhost` on a lab client — expect ladder log lines, knees written to hostlist.csv, second run skipping calibration; `-a hybrid` reaching the same knee in fewer steps; `-a max` running with zero weka CLI calls.

## Self-Review

- Spec coverage: corrected max sizing (Task 1), tiers (Task 2), set inspection (Task 3), ladder+knee (Tasks 4-5), parallel-all-clients (Task 5, single coordinator), persistence/skip/`-g` (Task 6), `-n` (Task 6), docs (Task 7). Latency-never-calibrated is encoded in Task 3 (latency contributes nothing).
- Placeholders: none — every step names exact functions, fields, and expected log lines.
- Type consistency: `cal.results` schema (`host bw_qd iops_qd nj`) is produced in Task 5 and consumed verbatim in Task 6; `cal_required` output grammar is shared by Tasks 3, 5, 6.
