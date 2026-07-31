# wekatester auto mode (-a / --auto) — design

2026-07-31 · branch `shell-rewrite`

## Goal

Add an auto mode that derives system-specific fio options (ioengine, numjobs,
iodepth, nrfiles, cpus_allowed, small-file sizing) from the workers' actual
capabilities, so a field engineer gets near-optimal, honest numbers without
hand-tuning jobfiles per site.

## CLI

- `getopts` is replaced by a manual parse loop (needed for long options and an
  optional option-argument).
- New: `-a [safe|max]` / `--auto[=safe|max]`. Bare `-a` or `--auto` means
  `max`. A token following `-a` that is not a recognized level is not consumed
  (so `-a host1 host2` works). Unknown level → usage error.
- New: `--ignore-capacity` (long only, no argument, default off) — overrides
  the auto-mode capacity abort; see Capacity check.
- All existing options and behavior without `-a` are unchanged, except that
  staging always assembles per-client jobfiles (see Flow).

## Flow changes

```
preflight → start_fio_servers → verify_fio_ports
         → probe (auto only)
         → stage_jobfiles (always per-client variants now)
         → run_jobs (--client=<host> <TARGET_DIR>/<host>/<job>)
```

Per-client staging is unconditional: non-auto variants differ only by the
`directory=` override and are byte-identical across hosts. One code path.

## Probe phase (auto only; bash, parallel, one ssh per host)

Facts per worker, gathered by dumb remote commands and interpreted locally:

- online CPUs: `getconf _NPROCESSORS_ONLN`
- weka-pinned cores: task-level `Cpus_allowed_list` from
  `/proc/<pid>/task/*/status` of every `wekanode` process (works without
  cgroups; dedup + union computed locally). Weka pins each dedicated io
  thread to exactly one CPU, so only single-CPU masks count as dedicated
  cores; wide masks are floating utility threads and are ignored (a
  process-level, main-thread-only mask would union to all CPUs and collapse
  usable cores to nothing). No wekanode processes → host contributes no
  weka cores (e.g. pure load generator); usable = all cores.
- available ioengines: `fio --enghelp`

Master-only extras:

- `df -kP <directory>` → available capacity (shared-filesystem assumption)
- `weka cluster servers list -J` → Σ `ram_allocated` (older releases:
  `memory`) over backend entries = conservative DRAM cache ceiling. Query
  failure → fall back to the working-set floor and warn.

Any per-host probe failure: collect-all, then die (same policy as preflight).

Warnings (once, with a per-host table): system core counts differ across
hosts; weka core counts differ across hosts.

## Tuner (embedded python3; pure function: jobfile + facts → per-host variant)

Classification by the file's `# report` directive; `latency` anywhere in it
wins (a `# report iops latency` file is treated as latency).

Corrections (applied at BOTH tiers, all file types):

- `cpus_allowed` = that host's online cores minus its weka cores; inserted
  into `[global]`. `cpus_allowed_policy` left at fio default (shared).
- `ioengine`: if the file's engine is unavailable on any host, replace with
  the best commonly-available engine (`io_uring` > `libaio` > `psync`).

Tier rules for non-latency files:

| option    | safe (uniform)                          | max (per host)                                    |
|-----------|-----------------------------------------|---------------------------------------------------|
| ioengine  | correction only                         | always best common engine                          |
| numjobs   | min usable cores across hosts           | that host's usable cores                           |
| iodepth   | untouched                               | bw: `max(current, 8)`; iops: `clamp(64×cores/numjobs, current, 128)` |
| nrfiles   | untouched                               | bw: 1; iops: from working-set rule below           |
| filesize  | untouched                               | bw: untouched; iops: 1G (small-file namespace)     |

Latency files at max tier: corrections plus small-file redirection only —
`numjobs`/`iodepth` NEVER touched; `filesize=1G`; `nrfiles=min(8,
nrfiles_iops)`; `file_service_type=random`.

Small-file namespace: at max tier, iops and latency files share one
`filename_format` (exactly `wt-small.$jobnum.$filenum`), so latency reuses the
iops files; create sections are idempotent, whichever runs first lays out
what it needs. Bandwidth files keep their original (large) namespace.

Every staged variant gets header comments recording tier, derived values, and
the probe facts used — the support artifact for "what did auto actually run?"

Override semantics (same as the old Python `override()`): replace the option
wherever it appears in any section; insert into `[global]` when absent.
Create-phase sections inherit the tuned global `numjobs`, keeping file
coverage consistent.

## Working-set sizing (max tier)

Rationale: for random-IO tests, file size is a cache-defeat parameter, not an
accuracy parameter. The small-file working set must exceed the backends'
DRAM read cache or iops/latency numbers measure RAM.

- cache ceiling `C` = Σ backend container RAM (conservative: true data cache
  is a fraction of this)
- per-host working set `ws = max(8 GiB, 2 × C / n_workers)`
- `nrfiles(iops) = max(2, ceil(ws / (numjobs × 1 GiB)))`

Constants (documented in the script, single place):
`SMALL_FILESIZE=1G`, `CACHE_MULT=2`, `WS_FLOOR=8G`,
`IOPS_OUTSTANDING=64×cores`, `IODEPTH_CAP=128`, `LAT_NRFILES_CAP=8`.

## Mount-mode guard (all runs, auto or not)

After preflight, in parallel per worker: `findmnt -T <directory> -n -o
FSTYPE,OPTIONS` (resolves the containing mount even for subdirectories).
If FSTYPE is `wekafs` and the options lack `forcedirect`: collect-all across
hosts, then die, naming each offending host and its actual mode (e.g.
`writecache`). Rationale: fio's `direct=1` requests O_DIRECT per file, but
only the `forcedirect` mount mode guarantees the wekafs client stays out of
the IO path entirely — without it, client-side caching can flatter results.
Non-wekafs targets skip the guard (the tool supports generic filesystems;
`direct=1` remains the only control there). A worker where `-d` is not
mounted at all fails preflight naturally when fio tries to create files —
out of scope here.

## Capacity check

`required = Σ over hosts of [ Σ over filename_format namespaces of max over that namespace's jobfiles(numjobs × filesize × nrfiles) ]`
— files are shared within a namespace, so each namespace contributes its largest jobfile's footprint; distinct namespaces (e.g. bandwidth vs small-file) coexist and sum. Python parses fio
size suffixes.

If `required > available` on `-d`: print both numbers and **die**, inside the
tuner, i.e. during staging and before any fio job starts. Rationale (lab
evidence): continuing does not degrade gracefully — fio hits `ENOSPC` partway
through and the run is lost anyway, so the useful failure is the early,
explanatory one.

`--ignore-capacity` (new long option, no short form; default off) downgrades
the abort to the old loud warning and continues, for the case where `df`
under-reports the usable space (thin provisioning, rebalance in flight).

Unknown capacity is not a failure: when the `df` probe is missing or
unparsable, `available` is 0, and 0 disables the comparison entirely — no
error, no warning, only the informational `auto: capacity required ...` line.
Auto mode only (non-auto never computes a footprint, so `--ignore-capacity`
is accepted and inert there).

## Non-goals (v1)

- No tuning of bandwidth-file `filesize`/`nrfiles`; no latency concurrency
  tuning ever. No `cpus_allowed_policy=split`. No per-host filesize. No
  capacity check in non-auto mode. `direct=1` hygiene in custom workloads is
  the workload author's job.

## Testing

- Local (no cluster): source-guard added to the script (`main` runs only when
  executed). Feed the tuner fabricated probe facts: heterogeneous core
  counts, missing io_uring on one host, latency-wins classification, weka
  query failure fallback, capacity math with unit suffixes.
- Lab: `-a safe` and `-a max` smoke runs; inspect staged variants on the
  master; confirm fio JSON echoes the derived options; confirm fio threads
  avoid weka cores; oversized test workload to prove the capacity check
  aborts the run, and that `--ignore-capacity` runs it anyway;
  heterogeneity warning via an artificial single-host cpus_allowed
  restriction if practical.
- Mount-mode guard: the lab currently mounts `/mnt/weka` in `writecache`
  mode — run once to confirm the guard dies naming all hosts (negative
  test), remount `forcedirect`, confirm the run proceeds (positive test).
