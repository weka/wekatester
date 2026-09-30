# wekatester auto mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `-a/--auto [safe|max]` to wekatester: probe workers, assemble per-client tuned fio jobfiles (ioengine, numjobs, iodepth, nrfiles, cpus_allowed, small-file working set), guard wekafs forcedirect mounts, warn on capacity.

**Architecture:** Single-file bash tool (`wekatester`) with embedded stdlib-only python3 heredocs. Bash orchestrates (ssh probes, staging, run); Python transforms (tuning, capacity math). Per-client jobfile staging becomes unconditional; auto mode inserts a probe phase and a one-shot Python "tuner" that reads all probe facts and emits every per-host variant.

**Tech Stack:** bash (macOS 3.2-compatible on the local side), OpenSSH, python3 ≥3.6 stdlib only, fio jobfile INI format. Spec: `docs/superpowers/specs/2026-07-31-wekatester-auto-mode-design.md`.

## Global Constraints

- No installable dependencies. Remote probes use only: `getconf`, `/proc/<pid>/status`, `fio --enghelp`, `findmnt`, `df -kP`, `weka` CLI (failure tolerated).
- Never suppress stderr (`2>/dev/null` is forbidden in this codebase).
- Local bash must avoid `mapfile`, associative arrays, `${var,,}` (macOS bash 3.2).
- Constants, verbatim from spec: `SMALL_FILESIZE=1G`, `CACHE_MULT=2`, `WS_FLOOR=8GiB`, iops outstanding target `64×cores`, `IODEPTH_CAP=128`, `LAT_NRFILES_CAP=8`, engine order `io_uring > libaio > psync`, small-file namespace `wt-small.$jobnum.$filenum`.
- Latency-report jobfiles: `numjobs`/`iodepth` NEVER modified, at any tier. `filesize`/`nrfiles` of bandwidth files never modified.
- Mount guard and per-client staging apply to ALL runs; probe/tuner/capacity apply to auto runs only.
- All new failure paths follow the collect-all-then-die pattern; capacity and heterogeneity findings WARN and continue.

---

### Task 1: Source-guard and test harness

**Files:**
- Modify: `wekatester` (bottom: the bare `main` call)
- Create: `tests/test_wekatester.sh`

**Interfaces:**
- Produces: sourcing `wekatester` defines all functions but runs nothing. Test harness provides `t_run <name> <fn>` and `t_assert <desc> <expr>`; later tasks append tests to `tests/test_wekatester.sh`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_wekatester.sh`:

```bash
#!/usr/bin/env bash
# wekatester unit tests: source the script (source-guard prevents main), test pure functions.
cd "$(dirname "$0")/.."
PASS=0; FAIL=0

t_assert() {   # t_assert <description> <command...>
    if "${@:2}"; then PASS=$((PASS+1)); echo "ok - $1"
    else FAIL=$((FAIL+1)); echo "FAIL - $1"; fi
}

# --- source-guard: sourcing must not run main (no args → would die) ---
out=$(source ./wekatester 2>&1)
t_assert "sourcing produces no output" test -z "$out"
t_assert "usage function defined after source" bash -c 'source ./wekatester; declare -f usage >/dev/null'

echo; echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `chmod +x tests/test_wekatester.sh && ./tests/test_wekatester.sh`
Expected: FAIL — sourcing currently executes `main`, which prints the usage error and exits.

- [ ] **Step 3: Implement the source-guard**

In `wekatester`, replace the final line `main` with:

```bash
# run only when executed, not when sourced (tests source this file)
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main
fi
```

Note: argument parsing currently runs at top level. Task 2 moves it into `parse_args`; until then the source-guard alone makes sourcing safe because parsing with no args only sets defaults (HOSTS empty is checked inside `main`).

- [ ] **Step 4: Run test to verify it passes**

Run: `./tests/test_wekatester.sh` — Expected: `passed 2, failed 0`.
Also: `bash -n wekatester && ./wekatester -V` still prints the version.

- [ ] **Step 5: Commit**

```bash
git add wekatester tests/test_wekatester.sh
git commit -m "Add source-guard and unit test harness"
```

---

### Task 2: Manual argument parsing with -a/--auto

**Files:**
- Modify: `wekatester` (replace the `getopts` block and `usage`)
- Test: `tests/test_wekatester.sh` (append)

**Interfaces:**
- Produces: `parse_args "$@"` sets globals `DIRECTORY WORKLOAD FIO_BIN VERBOSITY SUMMARIZE_FILE REPORT_ITEMS AUTO_LEVEL HOSTS MASTER`. `AUTO_LEVEL` is `""` (off), `"safe"`, or `"max"`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_wekatester.sh` before the summary lines)

```bash
# --- parse_args ---
p() { (source ./wekatester; parse_args "$@"; echo "$AUTO_LEVEL|$DIRECTORY|${HOSTS[*]-}"); }
t_assert "no -a: auto off"            test "$(p -d /x h1)" = "|/x|h1"
t_assert "bare -a defaults to max"    test "$(p -a h1 h2)" = "max|/mnt/weka|h1 h2"
t_assert "-a safe consumed"           test "$(p -a safe h1)" = "safe|/mnt/weka|h1"
t_assert "--auto bare is max"         test "$(p --auto h1)" = "max|/mnt/weka|h1"
t_assert "--auto=safe"                test "$(p --auto=safe h1)" = "safe|/mnt/weka|h1"
t_assert "-vv still counts" bash -c 'source ./wekatester; parse_args -vv h1; [ "$VERBOSITY" -eq 2 ]'
t_assert "--auto=bogus errors" bash -c '! (source ./wekatester; parse_args --auto=bogus h1) '
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./tests/test_wekatester.sh` — Expected: new tests FAIL (`parse_args` undefined).

- [ ] **Step 3: Replace getopts with parse_args**

Delete the `while getopts ... done; shift; HOSTS=...; MASTER=...` block and add:

```bash
AUTO_LEVEL=""    # "", "safe", or "max"

parse_args() {
    HOSTS=()
    while [ $# -gt 0 ]; do
        case "$1" in
            -d) DIRECTORY=$2; shift 2 ;;
            -w) WORKLOAD=$2; shift 2 ;;
            -f) FIO_BIN=$2; shift 2 ;;
            -s) SUMMARIZE_FILE=$2; shift 2 ;;
            -r) REPORT_ITEMS=$2; shift 2 ;;
            -a|--auto)
                AUTO_LEVEL="max"
                case "${2:-}" in safe|max) AUTO_LEVEL=$2; shift ;; esac
                shift ;;
            --auto=*)
                AUTO_LEVEL=${1#--auto=}
                case "$AUTO_LEVEL" in safe|max) ;; *)
                    usage >&2; die "unknown auto level: $AUTO_LEVEL (safe|max)" ;;
                esac
                shift ;;
            -v)   VERBOSITY=$((VERBOSITY + 1)); shift ;;
            -vv)  VERBOSITY=$((VERBOSITY + 2)); shift ;;
            -vvv) VERBOSITY=$((VERBOSITY + 3)); shift ;;
            -V) echo "${0##*/} version $VERSION"; exit 0 ;;
            -h) usage; exit 0 ;;
            -*) usage >&2; die "unknown option: $1" ;;
            *)  HOSTS+=("$1"); shift ;;
        esac
    done
    MASTER=${HOSTS[0]:-}
}
```

Options `-d/-w/-f/-s/-r` with a missing value: `$2` unset → `shift 2` fails the function under `set -u`-less bash by shifting 1; add a guard line at the top of each if desired — acceptable v1 is `[ $# -ge 2 ] || { usage >&2; die "option $1 requires an argument"; }` inserted before each `shift 2` group via a helper:

```bash
need_arg() { [ "$2" -ge 2 ] || { usage >&2; die "option $1 requires an argument"; }; }
```

and call `need_arg "$1" $#` as the first statement of each value-taking case arm.

In `main`, call `parse_args` is NOT needed — instead, at the bottom of the file inside the execution guard:

```bash
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    parse_args "$@"
    main
fi
```

Update `usage()` — add these lines to the option list:

```
  -a, --auto [safe|max]   derive system-specific fio options from the workers
                          (default level when omitted: max)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./tests/test_wekatester.sh` — Expected: all pass. Also `./wekatester -V`, `./wekatester -h`, and a fake-host run `./wekatester nosuchhost.invalid` (still dies at preflight).

- [ ] **Step 5: Commit**

```bash
git add wekatester tests/test_wekatester.sh
git commit -m "Replace getopts with manual parse_args; add -a/--auto"
```

---

### Task 3: wekafs forcedirect mount guard

**Files:**
- Modify: `wekatester` (new function + call in `main` between `preflight` and `start_fio_servers`)
- Test: `tests/test_wekatester.sh` (append)

**Interfaces:**
- Produces: `classify_mount_line "<fstype> <options>"` → prints `ok`, `skip`, or `fail <mode>`; `verify_mount_mode()` runs it against `findmnt` output from every host, collect-all, dies on failures.

- [ ] **Step 1: Write the failing tests**

```bash
# --- mount guard classifier ---
c() { (source ./wekatester; classify_mount_line "$1"); }
t_assert "wekafs forcedirect ok"   test "$(c 'wekafs rw,relatime,forcedirect,inode_bits=auto')" = "ok"
t_assert "wekafs writecache fails" test "$(c 'wekafs rw,relatime,writecache,readahead_kb=32768')" = "fail writecache"
t_assert "wekafs readcache fails"  test "$(c 'wekafs rw,readcache')" = "fail readcache"
t_assert "wekafs unknown mode"     test "$(c 'wekafs rw,relatime')" = "fail unknown"
t_assert "nfs skipped"             test "$(c 'nfs4 rw,noatime')" = "skip"
t_assert "empty line skipped"      test "$(c '')" = "skip"
```

- [ ] **Step 2: Run tests to verify they fail** — `./tests/test_wekatester.sh`, new tests FAIL.

- [ ] **Step 3: Implement**

```bash
# Decide whether a "FSTYPE OPTIONS" line from findmnt satisfies the guard.
# wekafs must be mounted forcedirect: fio's direct=1 asks for O_DIRECT per
# file, but only the forcedirect mount mode keeps the wekafs client cache
# out of the IO path entirely. Non-wekafs targets are not our call.
classify_mount_line() {
    set -- $1
    local fstype=${1:-} opts=${2:-} mode
    [ "$fstype" = "wekafs" ] || { echo "skip"; return; }
    case ",$opts," in
        *,forcedirect,*) echo "ok" ;;
        *,writecache,*)  echo "fail writecache" ;;
        *,readcache,*)   echo "fail readcache" ;;
        *)               echo "fail unknown" ;;
    esac
}

# All workers: -d must not be a cached-mode wekafs mount.
verify_mount_mode() {
    log "checking mount mode of $DIRECTORY on ${#HOSTS[@]} host(s)..."
    local host line verdict failed=()
    for host in "${HOSTS[@]}"; do
        line=$(ssh -n $SSH_OPTS "$host" "findmnt -T '$DIRECTORY' -n -o FSTYPE,OPTIONS") \
            || { failed+=("$host: findmnt failed"); continue; }
        verdict=$(classify_mount_line "$line")
        case "$verdict" in
            ok)   ;;
            skip) debug "$host: $DIRECTORY is not wekafs; guard skipped" ;;
            fail*) failed+=("$host: wekafs mounted ${verdict#fail } (need forcedirect)") ;;
        esac
    done
    if [ ${#failed[@]} -gt 0 ]; then
        for line in "${failed[@]}"; do log "ERROR: $line" >&2; done
        die "wekafs at $DIRECTORY must be mounted with forcedirect; remount and re-run"
    fi
    debug "mount mode ok on all hosts"
}
```

Sequential ssh per host is acceptable here (ControlMaster makes each call ~30ms); parallelize only if review demands.

In `main`, after `preflight`, add: `verify_mount_mode`.

- [ ] **Step 4: Run tests to verify they pass** — `./tests/test_wekatester.sh` all green; `bash -n wekatester`.

- [ ] **Step 5: Commit**

```bash
git add wekatester tests/test_wekatester.sh
git commit -m "Guard: wekafs at -d must be mounted forcedirect"
```

---

### Task 4: Probe phase

**Files:**
- Modify: `wekatester` (new `probe_workers`, called from `main` when `AUTO_LEVEL` non-empty, after `verify_fio_ports`)
- Test: `tests/test_wekatester.sh` (append)

**Interfaces:**
- Produces: `$WORK_DIR/probe/<host>` (lines: `ncpus N`, zero+ `weka_allowed <cpulist>`, `engines <name>...`), `$WORK_DIR/probe/_df` (`df -kP` output for `-d` from master), `$WORK_DIR/probe/_weka_ram.json` (raw `weka cluster servers list -J`) or `_weka_ram.err`. Consumed by Task 5's tuner.
- Produces: `probe_remote_cmd()` prints the remote snippet (pure, testable).

- [ ] **Step 1: Write the failing test**

```bash
# --- probe remote snippet runs on a stub PATH and emits the 3 fact lines ---
probe_stub() {
    stub=$(mktemp -d)   # leaked on purpose; tests are short-lived
    printf '#!/bin/sh\necho 8\n' > "$stub/getconf"
    printf '#!/bin/sh\nexit 1\n' > "$stub/pgrep"     # no wekanode procs
    printf '#!/bin/sh\necho " io_uring libaio"\n' > "$stub/fio"
    chmod +x "$stub"/*
    (source ./wekatester; PATH="$stub:$PATH" bash -c "$(probe_remote_cmd)")
}
t_assert "probe snippet emits ncpus"   bash -c 'probe_out=$(probe_stub); case "$probe_out" in *"ncpus 8"*) true;; *) false;; esac' 
t_assert "probe snippet emits engines" bash -c 'probe_out=$(probe_stub); case "$probe_out" in *"engines"*io_uring*) true;; *) false;; esac'
```

(Define `probe_stub` above the asserts in the test file.)

- [ ] **Step 2: Run tests to verify they fail** — `probe_remote_cmd` undefined.

- [ ] **Step 3: Implement**

```bash
# Remote fact-gathering snippet. Dumb by design: emits raw lines, all
# interpretation happens locally in the tuner.
probe_remote_cmd() {
    printf '%s' 'echo "ncpus $(getconf _NPROCESSORS_ONLN)"; \
        for p in $(pgrep -x wekanode || true); do \
            awk "/^Cpus_allowed_list/ {print \"weka_allowed\", \$2}" "/proc/$p/status"; \
        done; \
        echo "engines $(fio --enghelp | tr "\n" " ")"'
}

# Gather per-host facts + master-side extras into $WORK_DIR/probe/.
probe_workers() {
    log "probing ${#HOSTS[@]} worker(s) for auto tuning..."
    mkdir -p "$WORK_DIR/probe"
    local pids=() failed=() host i
    for host in "${HOSTS[@]}"; do
        ssh -n $SSH_OPTS "$host" "$(probe_remote_cmd)" > "$WORK_DIR/probe/$host" &
        pids+=($!)
    done
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}" || failed+=("${HOSTS[$i]}")
    done
    [ ${#failed[@]} -eq 0 ] || die "probe failed on: ${failed[*]}"

    ssh -n $SSH_OPTS "$MASTER" "df -kP '$DIRECTORY'" > "$WORK_DIR/probe/_df" \
        || die "cannot df $DIRECTORY on $MASTER"
    if ! ssh -n $SSH_OPTS "$MASTER" "weka cluster servers list -J" \
            > "$WORK_DIR/probe/_weka_ram.json"; then
        rm -f "$WORK_DIR/probe/_weka_ram.json"
        : > "$WORK_DIR/probe/_weka_ram.err"
        log "WARNING: could not query weka backend RAM; using ${WS_FLOOR_GIB}GiB/host working-set floor" >&2
    fi
}
```

Add constant near the top of the script: `WS_FLOOR_GIB=8`.

In `main`, after `verify_fio_ports`: `[ -n "$AUTO_LEVEL" ] && probe_workers`.
(`fio --enghelp` in the probe requires the fio servers check to have passed; probe placement after `verify_fio_ports` also means ControlMasters are warm.)

- [ ] **Step 4: Run tests to verify they pass** — `./tests/test_wekatester.sh`; `bash -n wekatester`.

- [ ] **Step 5: Commit**

```bash
git add wekatester tests/test_wekatester.sh
git commit -m "Add auto-mode probe phase (cores, weka pinning, engines, df, weka RAM)"
```

---

### Task 5: Tuner — probe aggregation, warnings, helpers

**Files:**
- Modify: `wekatester` (new `auto_tune()` bash function wrapping one python3 heredoc; not yet wired into staging)
- Test: `tests/test_wekatester.sh` (append)

**Interfaces:**
- Consumes: `$WORK_DIR/probe/*` from Task 4.
- Produces: `auto_tune <jobfile_src_dir> <work_dir> <tier> <directory> <host>...` — python reads probe dir + all `[0-9]*` jobfiles in src dir, writes `<work_dir>/jobs/<host>/<basename>` for every host×jobfile, prints one `auto:` summary line per jobfile and `WARNING:` lines to stderr; exits nonzero on error. This task implements parsing/warnings/helpers plus pass-through variant writing (directory override only); Task 6 adds tier rules.

- [ ] **Step 1: Write the failing tests**

```bash
# --- tuner: fabricate probe dir + jobfile, run auto_tune ---
tuner_fixture() {   # $1 = extra probe content variant
    FIX=$(mktemp -d)
    mkdir -p "$FIX/probe" "$FIX/jobs" "$FIX/src"
    printf 'ncpus 8\nweka_allowed 0-2\nengines io_uring libaio psync \n' > "$FIX/probe/h1"
    printf 'ncpus 8\nweka_allowed 0-2\nengines io_uring libaio psync \n' > "$FIX/probe/h2"
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 1073741824 0 1073741824 1%% /mnt/weka\n' > "$FIX/probe/_df"
    printf '[{"memory": 12335448064}, {"memory": 12335448064}]\n' > "$FIX/probe/_weka_ram.json"
    printf '# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\ndirectory=/orig\nioengine=libaio\n[create]\ncreate_only=1\n[bw]\nstonewall\nrw=read\niodepth=1\n' > "$FIX/src/011-bw.job"
}
t_assert "tuner writes per-host variants" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka h1 h2) >/dev/null
    test -f "$FIX/jobs/h1/011-bw.job" && test -f "$FIX/jobs/h2/011-bw.job"'
t_assert "directory override applied" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka h1 h2) >/dev/null
    grep -q "^directory=/mnt/weka$" "$FIX/jobs/h1/011-bw.job"'
t_assert "cpus_allowed excludes weka cores" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka h1 h2) >/dev/null
    grep -q "^cpus_allowed=3-7$" "$FIX/jobs/h1/011-bw.job"'
t_assert "core mismatch warns" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 16\nweka_allowed 0-2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka h1 h2) 2>&1 >/dev/null )
    case "$err" in *WARNING*"core counts differ"*) true;; *) false;; esac'
```

Move `tuner_fixture` (and `probe_stub` from Task 4) into a new `tests/helpers.sh`, sourced at the top of `tests/test_wekatester.sh`.

- [ ] **Step 2: Run tests to verify they fail** — `auto_tune` undefined.

- [ ] **Step 3: Implement `auto_tune`**

```bash
# One-shot tuner: reads all probe facts and all jobfiles, writes every
# per-host variant. Python because the rules are per-section, per-type,
# per-tier -- data transformation, not orchestration.
auto_tune() {
    python3 - "$@" <<'PYEOF' || return 1
import json, math, os, re, sys

src, work, tier, directory = sys.argv[1:5]
hosts = sys.argv[5:]

SMALL_FILESIZE = "1G"; SMALL_BYTES = 2**30
CACHE_MULT = 2; WS_FLOOR = 8 * 2**30
IODEPTH_CAP = 128; OUTSTANDING_PER_CORE = 64; LAT_NRFILES_CAP = 8
ENGINE_ORDER = ["io_uring", "libaio", "psync"]
SMALL_FORMAT = "wt-small.$jobnum.$filenum"

def warn(msg): print(f"WARNING: {msg}", file=sys.stderr)

def parse_cpulist(s):
    cpus = set()
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-"); cpus.update(range(int(a), int(b) + 1))
        elif part:
            cpus.add(int(part))
    return cpus

def fmt_cpulist(cpus):
    out, run = [], []
    for c in sorted(cpus):
        if run and c == run[-1] + 1: run.append(c)
        else:
            if run: out.append(run)
            run = [c]
    if run: out.append(run)
    return ",".join(f"{r[0]}-{r[-1]}" if len(r) > 1 else f"{r[0]}" for r in out)

def parse_size(s):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([kKmMgGtT]?)i?[bB]?", s.strip())
    if not m: raise ValueError(f"bad size: {s}")
    mult = {"": 1, "k": 2**10, "m": 2**20, "g": 2**30, "t": 2**40}[m.group(2).lower()]
    return int(float(m.group(1)) * mult)

# --- probe facts ---
facts = {}
for h in hosts:
    ncpus, weka, engines = 0, set(), []
    for line in open(os.path.join(work, "probe", h)):
        f = line.split()
        if not f: continue
        if f[0] == "ncpus": ncpus = int(f[1])
        elif f[0] == "weka_allowed": weka |= parse_cpulist(f[1])
        elif f[0] == "engines": engines = f[1:]
    usable = sorted(set(range(ncpus)) - weka) or list(range(ncpus))
    facts[h] = {"ncpus": ncpus, "weka": weka, "usable": usable, "engines": engines}

if len({f["ncpus"] for f in facts.values()}) > 1:
    warn("system core counts differ between hosts: "
         + ", ".join(f"{h}={facts[h]['ncpus']}" for h in hosts))
if len({len(f["weka"]) for f in facts.values()}) > 1:
    warn("weka core counts differ between hosts: "
         + ", ".join(f"{h}={len(facts[h]['weka'])}" for h in hosts))

common_engines = [e for e in ENGINE_ORDER
                  if all(e in f["engines"] for f in facts.values())]
min_usable = min(len(f["usable"]) for f in facts.values())

# --- jobfiles ---
def report_items(path):
    items = []
    for line in open(path):
        m = re.match(r"^#\s*report\s+(.*)", line)
        if m: items += m.group(1).split()
    return items or ["bandwidth", "latency", "iops"]

def override(lines, key, value):
    """Replace key= wherever it appears; else insert after [global]."""
    out, found = [], False
    for line in lines:
        if re.match(rf"^{key}=", line):
            out.append(f"{key}={value}"); found = True
        else:
            out.append(line)
    if not found:
        ins = []
        for line in out:
            ins.append(line)
            if line.strip() == "[global]":
                ins.append(f"{key}={value}")
        out = ins
    return out

jobs = sorted(f for f in os.listdir(src) if re.match(r"^[0-9]", f))
for h in hosts:
    os.makedirs(os.path.join(work, "jobs", h), exist_ok=True)

for job in jobs:
    lines = open(os.path.join(src, job)).read().splitlines()
    items = report_items(os.path.join(src, job))
    for h in hosts:
        out = override(lines, "directory", directory)
        out = override(out, "cpus_allowed", fmt_cpulist(facts[h]["usable"]))
        # Task 6 inserts tier rules here.
        header = [f"# generated by wekatester auto[{tier}] for {h}",
                  f"# usable cores: {fmt_cpulist(facts[h]['usable'])} "
                  f"(of {facts[h]['ncpus']}, weka: {fmt_cpulist(facts[h]['weka']) or 'none'})"]
        with open(os.path.join(work, "jobs", h, job), "w") as fp:
            fp.write("\n".join(header + out) + "\n")
    print(f"auto[{tier}]: {job}: staged for {len(hosts)} host(s)")
PYEOF
}
```

- [ ] **Step 4: Run tests to verify they pass** — `./tests/test_wekatester.sh` all green.

- [ ] **Step 5: Commit**

```bash
git add wekatester tests/test_wekatester.sh tests/helpers.sh
git commit -m "Auto tuner skeleton: probe aggregation, warnings, per-host variants"
```

---

### Task 6: Tuner — tier rules

**Files:**
- Modify: `wekatester` (inside the `auto_tune` heredoc, at the `# Task 6` marker)
- Test: `tests/test_wekatester.sh` (append)

**Interfaces:**
- Consumes: `facts`, `common_engines`, `min_usable`, `override`, `report_items` from Task 5.
- Produces: staged variants honor the spec's tier table; summary line becomes `auto[<tier>]: <job> type=<bw|iops|latency> numjobs=... iodepth=... nrfiles=...`.

- [ ] **Step 1: Write the failing tests**

```bash
t_assert "safe: numjobs = min usable cores" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 6\nweka_allowed 0-2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=3$" "$FIX/jobs/h1/011-bw.job"'   # h2 usable=3 is the min
t_assert "max: numjobs per host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 6\nweka_allowed 0-2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=5$" "$FIX/jobs/h1/011-bw.job" && grep -q "^numjobs=3$" "$FIX/jobs/h2/011-bw.job"'
t_assert "max: bw ioengine upgraded to io_uring" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=io_uring$" "$FIX/jobs/h1/011-bw.job"'
t_assert "safe: engine untouched when available" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=libaio$" "$FIX/jobs/h1/011-bw.job"'
t_assert "safe: engine fixed when missing on one host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nioengine=io_uring\nnumjobs=2\nfilesize=1G\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    printf "ncpus 8\nweka_allowed 0-2\nengines libaio psync \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=libaio$" "$FIX/jobs/h1/011-bw.job"'
t_assert "latency: numjobs/iodepth untouched, small files applied at max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report latency\n[global]\nfilesize=10G\nnumjobs=1\nioengine=libaio\n[lat]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/021-lat.job"
    grep -q "^numjobs=1$" "$v" && grep -q "^iodepth=1$" "$v" &&
    grep -q "^filesize=1G$" "$v" && grep -q "wt-small" "$v" &&
    grep -q "^file_service_type=random$" "$v"'
t_assert "mixed report treats file as latency" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops latency\n[global]\nnumjobs=4\nioengine=libaio\nfilesize=1G\n[j]\nrw=randwrite\niodepth=8\n" > "$FIX/src/022-mixed.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=4$" "$FIX/jobs/h1/022-mixed.job"'
t_assert "max: iops iodepth and nrfiles derived" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/031-iops.job"
    grep -q "^iodepth=64$" "$v" && grep -q "^filesize=1G$" "$v" && grep -q "^nrfiles=5$" "$v"'
```

nrfiles expectation math: the fixture's `_weka_ram.json` sums to 24,670,896,128 B (~23 GiB); `ws = max(8GiB, 2 × 23GiB / 2 hosts) ≈ 23GiB`; h1 has 5 usable cores, so `nrfiles = max(2, ceil(23GiB / (5 × 1GiB))) = 5`. Recompute if you change the fixture.

- [ ] **Step 2: Run tests to verify they fail** — current tuner writes pass-through variants.

- [ ] **Step 3: Implement tier rules** (replace the `# Task 6 inserts tier rules here.` comment)

```python
        is_latency = "latency" in items
        is_bw = "bandwidth" in items and not is_latency
        is_iops = "iops" in items and not is_latency
        usable_n = len(facts[h]["usable"])
        best = common_engines[0] if common_engines else None

        cur_engines = {m.group(1) for l in lines
                       for m in [re.match(r"^ioengine=(\S+)", l)] if m}
        missing = any(e not in f["engines"]
                      for e in cur_engines for f in facts.values())
        if best and (tier == "max" or missing):
            out = override(out, "ioengine", best)

        if not is_latency:
            if tier == "safe":
                out = override(out, "numjobs", str(min_usable))
            else:  # max
                out = override(out, "numjobs", str(usable_n))
                cur_depth = max([int(m.group(1)) for l in lines
                                 for m in [re.match(r"^iodepth=(\d+)", l)] if m] or [1])
                if is_bw:
                    out = override(out, "iodepth", str(max(cur_depth, 8)))
                if is_iops:
                    depth = max(cur_depth,
                                min(IODEPTH_CAP,
                                    math.ceil(OUTSTANDING_PER_CORE * usable_n / usable_n)))
                    out = override(out, "iodepth", str(max(cur_depth, min(IODEPTH_CAP, 64))))

        if tier == "max" and (is_iops or is_latency):
            out = override(out, "filesize", SMALL_FILESIZE)
            out = override(out, "filename_format", SMALL_FORMAT)
            ws = max(WS_FLOOR, CACHE_MULT * cache_bytes // len(hosts))
            eff_jobs = usable_n if is_iops else 1
            nr = max(2, math.ceil(ws / (max(eff_jobs, 1) * SMALL_BYTES)))
            if is_latency:
                out = override(out, "nrfiles", str(min(LAT_NRFILES_CAP, nr)))
                out = override(out, "file_service_type", "random")
            else:
                out = override(out, "nrfiles", str(nr))
```

Above the jobfile loop, load the cache ceiling once:

```python
cache_bytes = 0
ram_path = os.path.join(work, "probe", "_weka_ram.json")
if os.path.exists(ram_path):
    try:
        cache_bytes = sum(s.get("memory", 0) for s in json.load(open(ram_path)))
    except (ValueError, KeyError) as exc:
        warn(f"could not parse weka RAM listing ({exc}); using working-set floor")
if cache_bytes == 0:
    warn(f"weka backend RAM unknown; small-file working set floors at {WS_FLOOR // 2**30}GiB/host")
```

And extend the per-job summary print:

```python
    kind = "latency" if is_latency else ("bandwidth" if is_bw else "iops" if is_iops else "all")
    print(f"auto[{tier}]: {job} type={kind}")
```

Simplify the iops iodepth expression during implementation: `OUTSTANDING_PER_CORE × usable_n / numjobs` with `numjobs = usable_n` reduces to `OUTSTANDING_PER_CORE` (=64) capped by `IODEPTH_CAP` and floored by the jobfile's current value — write it as that reduction with a comment, don't ship the redundant formula.

- [ ] **Step 4: Run tests to verify they pass** — `./tests/test_wekatester.sh` all green (recheck the nrfiles arithmetic against the fixture before trusting a failure).

- [ ] **Step 5: Commit**

```bash
git add wekatester tests/test_wekatester.sh
git commit -m "Auto tuner: safe/max tier rules, small-file working set"
```

---

### Task 7: Capacity warning

**Files:**
- Modify: `wekatester` (inside `auto_tune` heredoc, after the jobfile loop)
- Test: `tests/test_wekatester.sh` (append)

**Interfaces:**
- Consumes: staged variants (re-read from `work/jobs/`), `parse_size`, `_df` probe file.
- Produces: `WARNING: workload needs ~<X>GiB but <dir> has <Y>GiB available` on stderr when over; always prints `auto: capacity required ~<X>GiB, available <Y>GiB` at the end of the summary.

- [ ] **Step 1: Write the failing test**

```bash
t_assert "capacity warning fires when oversized" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"   # 20 GiB avail
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka h1 h2) 2>&1 >/dev/null )
    case "$err" in *WARNING*"available"*) true;; *) false;; esac'
t_assert "no capacity warning when it fits" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka h1 h2) 2>&1 >/dev/null )
    case "$err" in *WARNING*available*) false;; *) true;; esac'
```

- [ ] **Step 2: Run tests to verify they fail.**

- [ ] **Step 3: Implement** (after the jobfile loop in the heredoc)

```python
# Capacity: per host, group staged jobs by filename_format namespace; each
# namespace's footprint is the max over its jobfiles of numjobs*filesize*nrfiles
# (files are shared within a namespace); host total = sum over namespaces.
def job_value(path, key, default):
    for line in open(path):
        m = re.match(rf"^{key}=(\S+)", line)
        if m: return m.group(1)
    return default

required = 0
for h in hosts:
    namespaces = {}
    for job in jobs:
        p = os.path.join(work, "jobs", h, job)
        ns = job_value(p, "filename_format", "$jobname.$jobnum.$filenum")
        need = (int(job_value(p, "numjobs", "1"))
                * parse_size(job_value(p, "filesize", "0"))
                * int(job_value(p, "nrfiles", "1")))
        namespaces[ns] = max(namespaces.get(ns, 0), need)
    required += sum(namespaces.values())

avail = 0
df_path = os.path.join(work, "probe", "_df")
if os.path.exists(df_path):
    df_lines = open(df_path).read().splitlines()
    if len(df_lines) >= 2:
        avail = int(df_lines[1].split()[3]) * 1024

gib = lambda n: f"{n / 2**30:.1f}"
print(f"auto: capacity required ~{gib(required)}GiB, available {gib(avail)}GiB")
if avail and required > avail:
    warn(f"workload needs ~{gib(required)}GiB but {directory} has "
         f"{gib(avail)}GiB available")
```

Note: this namespace-aware formula supersedes the spec's simpler
`max over jobfiles`; the spec predates the split into big/small namespaces.
Update the spec's Capacity paragraph in this commit to match.

- [ ] **Step 4: Run tests to verify they pass.**

- [ ] **Step 5: Commit**

```bash
git add wekatester tests/test_wekatester.sh docs/superpowers/specs/2026-07-31-wekatester-auto-mode-design.md
git commit -m "Auto tuner: namespace-aware capacity warning; spec formula updated"
```

---

### Task 8: Staging and run integration

**Files:**
- Modify: `wekatester` (`stage_jobfiles`, `run_jobs`, `main`)
- Test: `tests/test_wekatester.sh` (append) + fake-host smoke

**Interfaces:**
- Consumes: `auto_tune` (Task 5-7), `probe_workers` (Task 4).
- Produces: `$WORK_DIR/jobs/<host>/<job>` staged for every run (auto and non-auto); `run_jobs` pairs `--client=<host> '$TARGET_DIR/<host>/<job>'`; `JOBFILES` array unchanged (basenames).

- [ ] **Step 1: Write the failing test**

```bash
t_assert "non-auto staging produces per-host variants" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester
     WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2); AUTO_LEVEL=""
     stage_variants "$FIX/src")
    test -f "$FIX/jobs/h1/011-bw.job" && test -f "$FIX/jobs/h2/011-bw.job" &&
    grep -q "^directory=/mnt/weka$" "$FIX/jobs/h2/011-bw.job"'
```

- [ ] **Step 2: Run test to verify it fails** — `stage_variants` undefined.

- [ ] **Step 3: Implement**

Extract the variant-generation part of `stage_jobfiles` into `stage_variants <srcdir>`:

```bash
# Build $WORK_DIR/jobs/<host>/<job> for every host. Auto mode delegates to
# the tuner; plain mode copies with the directory override (variants are
# identical across hosts, but one layout = one code path).
stage_variants() {
    local srcdir=$1 job base host
    if [ -n "$AUTO_LEVEL" ]; then
        auto_tune "$srcdir" "$WORK_DIR" "$AUTO_LEVEL" "$DIRECTORY" "${HOSTS[@]}" \
            || die "auto tuning failed"
        return
    fi
    for host in "${HOSTS[@]}"; do
        mkdir -p "$WORK_DIR/jobs/$host"
        for job in "$srcdir"/[0-9]*; do
            base=${job##*/}
            if grep -q '^directory=' "$job"; then
                awk -v dir="$DIRECTORY" \
                    '/^directory=/ { print "directory=" dir; next } { print }' \
                    "$job" > "$WORK_DIR/jobs/$host/$base"
            else
                awk -v dir="$DIRECTORY" \
                    '{ print } /^\[global\]/ && !ins { print "directory=" dir; ins = 1 }' \
                    "$job" > "$WORK_DIR/jobs/$host/$base"
            fi
        done
    done
}
```

Rework `stage_jobfiles` to: discover `JOBFILE_SRC` and `JOBFILES` (unchanged logic), call `stage_variants "$JOBFILE_SRC"`, then ship the whole tree:

```bash
    ssh -n $SSH_OPTS "$MASTER" "rm -rf '$TARGET_DIR' && mkdir -p '$TARGET_DIR'" \
        || die "cannot create $TARGET_DIR on $MASTER"
    scp $SSH_OPTS -q -r "$WORK_DIR"/jobs/* "$MASTER:$TARGET_DIR/" \
        || die "failed to copy jobfiles to $MASTER"
```

In `run_jobs`, change the client pairing line to:

```bash
            cmd="$cmd --client=$host '$TARGET_DIR/$host/$job'"
```

and read the `# report` directive from `$JOBFILE_SRC/$job` (unchanged — source files, not variants).

In `main`, the auto call order is: `preflight` → `verify_mount_mode` → `start_fio_servers` → `verify_fio_ports` → `[ -n "$AUTO_LEVEL" ] && probe_workers` → `stage_jobfiles` → `run_jobs`.

- [ ] **Step 4: Run tests + smoke** — `./tests/test_wekatester.sh` all green; `bash -n wekatester`; `./wekatester -s <old results json>` regression; `./wekatester nosuchhost.invalid` fails cleanly at preflight.

- [ ] **Step 5: Commit**

```bash
git add wekatester tests/test_wekatester.sh
git commit -m "Per-host variant staging for all runs; auto mode wired end-to-end"
```

---

### Task 9: README and usage documentation

**Files:**
- Modify: `README.md` (Usage block, new "Auto mode" section, Caveats)

**Interfaces:** none (docs).

- [ ] **Step 1: Update README**

- Regenerate the Usage code block from actual `./wekatester -h` output.
- New section after Workloads:

```markdown
# Auto mode
`-a` / `--auto` derives system-specific fio options from the workers instead
of trusting the jobfiles' static values. Two levels:

- `-a safe` — uniform and conservative: `numjobs` = the smallest usable core
  count across workers, ioengine fixed only if a worker lacks the one in the
  jobfile, and fio pinned away from weka's cores (`cpus_allowed`). Hosts stay
  directly comparable.
- `-a max` (default when the level is omitted) — each worker is tuned to its
  own capability: `numjobs` = that host's usable cores, deeper iodepth,
  and iops/latency tests move to a shared small-file namespace sized from
  the cluster's backend RAM (cache-defeat working set). Highest numbers;
  hosts with different hardware run different settings.

Every staged jobfile records what auto derived for that host in header
comments. Auto also warns when workers differ (core counts, weka cores),
when the backend RAM query fails, and when the workload's required capacity
exceeds what's available at `-d`.
```

- Caveats section: add the forcedirect guard —

```markdown
- If `-d` is a wekafs mount it must be mounted with `forcedirect`; wekatester
  refuses to run otherwise. fio's `direct=1` alone does not keep the wekafs
  client cache fully out of the IO path.
```

- [ ] **Step 2: Verify** — README renders (visual check), usage block matches `./wekatester -h` exactly.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Document auto mode and forcedirect guard"
```

---

### Task 10: Lab validation (integration, manual checklist)

**Files:** none (validation on ubuntu@158.101.121.27; deploy dir `~/wekatester-smoke`).

- [ ] **Step 1: Deploy** — `scp -q wekatester ubuntu@158.101.121.27:wekatester-smoke/` (plus `fio-jobfiles` if changed).

- [ ] **Step 2: Mount guard negative test** — `./wekatester -w smoke -d /mnt/weka backend-1 ... backend-6` with the current `writecache` mount. Expected: dies listing all six hosts as `wekafs mounted writecache (need forcedirect)`; no daemons left.

- [ ] **Step 3: Remount forcedirect** (needs sudo on each backend; the permission classifier may require the user to run this):
`for i in 1..6: ssh backend-$i "sudo umount /mnt/weka && sudo mount -t wekafs -o forcedirect default /mnt/weka"`

- [ ] **Step 4: Positive runs** — `-w smoke` without `-a` (regression), with `-a safe`, with `-a max`. Expected: green EXIT=0; auto summary lines; per-host staged files visible at debug.

- [ ] **Step 5: Verify derived values on master** — `ssh backend-1 'head -20 /dev/shm/fio-jobfiles/backend-2/*.job'`: header comments, `cpus_allowed` excluding weka cores, tier values per spec table.

- [ ] **Step 6: Verify core avoidance live** — during a `-a max` bandwidth job: `ssh backend-2 'ps -eLo psr,comm | awk "\$2==\"fio\" {print \$1}" | sort -un'` — no CPU from that host's weka set.

- [ ] **Step 7: Capacity warning** — temporary workload dir with `filesize=100G`, `numjobs=8` bandwidth job (create_only never run to completion is fine — the warning is computed before any IO; abort the run after the warning prints or let the tiny runtime pass).

- [ ] **Step 8: Instant-clean checks** — same as previous smoke tests: `pgrep -a fio` empty on all six immediately after exit, `/mnt/weka` empty (smoke set), `/dev/shm` empty.

- [ ] **Step 9: Commit any fixes found; then final full-suite run.**
