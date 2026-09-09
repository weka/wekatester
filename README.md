# wekatester
Performance test weka clusters (or any network/parallel filesystem) with distributed fio.

wekatester is a single bash script with an embedded python3 result summarizer. There is nothing to install: it needs only bash, an OpenSSH client, and python3 (stdlib only) on the machine you run it from, plus fio on the workers. The workers are Linux hosts reachable by ssh — or, with no server on the command line, the local host itself, in which case the OpenSSH client is not needed either.

# Basics
fio is a benchmark for IO, and is quite popular. However, running it in a distributed fashion across multiple servers can be a bit of a bear to manage, and the output can be quite difficult to read.

The idea of wekatester is to bring some order to this chaos. It starts fio on your workers, runs a standard set of benchmark workloads across all of them at once, and summarizes the results in a few human-readable lines per job.

# How it works
wekatester uses fio's native client/server mode:

- An `fio --server` daemon is started on every worker (daemonized with a pidfile in `/dev/shm`; on exit it is killed via that pidfile only — never by name, so fio jobs that are not ours are untouched).
- The **first host on the command line acts as the coordinator**: jobfiles are staged only to that host, and the fio client process runs there, driving all the workers. Aggregation across workers is done by fio itself (the "All clients" totals).
- ssh and scp are the system binaries, so agent forwarding, `~/.ssh/config`, `ProxyJump`, and ssh certificates work exactly as they do for interactive ssh. Connections run in `BatchMode` — wekatester never prompts; if ssh would have prompted, the run fails fast instead. `ControlMaster` multiplexing means one authentication per host for the entire run.
- All transient staging lives in tmpfs (`/dev/shm` locally when available, and `/dev/shm` on the remote side). The only files written to disk are the run bundles in the output directory (`./results` by default, `-o` to choose another).
- With no servers at all, wekatester runs the whole thing on the local host over loopback — no sshd required. Every phase and guard above still runs, unchanged; only the transport is swapped for direct execution, so the results are shaped exactly like a remote run's.

# Usage
```
usage: wekatester [-d directory] [-w workload] [-f fio_bin] [-o output_dir]
                  [-e engine] [-a [safe|max|cal|brutal[:secs]]] [--ignore-capacity]
                  [-i [login:]keyfile[,...]] [-p [n]] [-t [hostfile]]
                  [-x secs] [-C[set]] [-r] [-n] [-g] [-u] [-v] [-h]
                  [--] [server ...]
       wekatester -s results.json
       wekatester --version

Basic performance test of a network/parallel filesystem (distributed fio).

Option names are case-insensitive (-C is -c, --AUTO is --auto); the values you
give them are not (-Cmyset names myset, never MYSET). A value may be attached
or separate: -w smoke, -wsmoke, -w=smoke and --auto=max all work, and
attaching is the way to pass a value that starts with a dash.

  -d directory   target directory on the workers for test files (default: /mnt/weka);
                 created on request when it is missing under a wekafs mount
  -w workload    workload definition directory, a subdir of fio-jobfiles (default: default)
  -f fio_bin     fio binary on the workers (default: /usr/bin/fio)
  -o, --output dir        each run lands here as <date>-<time>.tgz: fio JSON
                          results, run log, staged jobfiles (default: results)
  -e, --engine eng        force this fio ioengine on every staged jobfile,
                          overriding the jobfiles and auto tuning
  -a, --auto [safe|max|cal|brutal[:secs]]
                          derive system-specific fio options from the workers
                          (default level when omitted: max)
                          cal: measure per-client iodepth ladders (one per
                          type and direction) before staging
                          brutal: measure the whole nrfiles x iodepth grid for
                          every type and direction; the best cell wins, with
                          no band and no knee. Exhaustive and slow
                          :secs sets the measured seconds per cell (cal
                          defaults to 30, brutal wants 10); it does not change
                          how long the measured jobs run -- that is
                          -x/--duration
  --ignore-capacity       when the workload needs more space than is available,
                          ask (no timeout) and run anyway instead of aborting
  -i, --identity [login:]keyfile[,...]
                          ssh key(s) to try, each optionally bound to a login;
                          repeatable, tried in the order given
  -p, --password [n]      prompt for n (default 1) login/password pairs, tried
                          after the keys; no sshpass involved
                          Every credential is tried against every worker --
                          existing ssh sessions and plain defaults first, then
                          keys, then passwords -- and per worker the first
                          success wins
  -t, --targets [file]    per-host settings from a CSV host file: login,
                          ioengine, cpus_allowed, destination dir, per-test
                          geometry. Bare -t = the set's own hostlist.csv,
                          else ./hostlist.csv. CLI flags beat the file; the
                          file beats the jobfiles and the tuner
  -C[set], --customize[=set]
                          copy a workload set, edit its host file (jobfiles
                          on request), then run it;
                          needs a terminal unless -r or -n is given. With no
                          attached value the set may be the next bare token
  -r             fast track: no prompts and no editors -- create whatever is
                 needed and run; a wekafs destination that is not mounted
                 forcedirect is a warning instead of a stop
  -n             dry run: create/generate, print the files and the run details,
                 execute nothing
  -g             force regeneration of existing layout jobfiles
  -x, --duration secs     run every measured job for this many seconds
                          (time_based); layout and unlink keep their own timing
  -u, --unlink   remove the workload's data files from -d after the last job
                 that uses them (a failed run keeps them for the rerun), and
                 the calibration scratch files, which are otherwise kept
                 so the next calibration can reuse them
  -s file        summarize an existing results .json -- or every job in a run
                 bundle .tgz, straight from the archive -- and exit
  -v             increase output verbosity (repeatable: -v, -vv, -vvv)
  --version      display version number and exit
  -h, --help     show this help and exit
  --             everything after this is a server name

With no server given, the test runs on the local host -- no ssh required.
```

`server ...` — the worker hostnames; the first one is the coordinator/master. Optional: give no server at all and wekatester benchmarks the local host instead, using no ssh, no keys, and no sshd (**local mode**). That is the quickest way to sanity-check a single client — `./wekatester -a max` and nothing else. In local mode the data files on the destination are prefixed with the box's short hostname (`hostname -s`, else `$HOSTNAME`), never `localhost` — `localhost.*` identifies nothing on a shared filesystem, and two boxes in local mode against the same mount would otherwise write (and `-u` unlink) each other's files.

`-d directory` — where the benchmark files are created on the workers, typically your mounted filesystem. Defaults to `/mnt/weka`. This overrides the `directory=` line in every jobfile at staging time.

`-w workload` — pick a workload set, a subdirectory of `fio-jobfiles`. See below.

`-f fio_bin` — path to fio on the workers, if it isn't `/usr/bin/fio`.

`-o output_dir` — where the run bundles land on the machine running wekatester. Defaults to `./results`, created on first use. Each run produces one `<date>-<time>.tgz` there; see Results below.

`-e engine` — force a specific fio ioengine everywhere: every staged jobfile, the layout job, and everything derived from it. Beats both the jobfiles' own `ioengine=` lines and auto tuning's choice. The engine is **proven with a real one-file job on every worker's destination** before anything runs — `--enghelp` only shows what fio was built with, and engines routinely pass it yet fail on the actual filesystem — and a host failing the test is fatal, naming the host and the evidence file. Values are passed to fio as typed.

`-t [hostfile]` — per-host settings from one CSV; see **Host files** below.

`-i` / `-p` — the credential pool; see **Authentication** below.

`-s file` — offline mode: re-summarize existing results and exit, no hosts involved. The full summary (all metric groups) is always printed. Takes a single results `.json`, or a run-bundle `.tgz` — every job's results inside the bundle are summarized in run order, read straight from the archive in memory, so nothing needs unpacking and no extra disk space is used (layout jobs are skipped, as during the run).

`-u/--unlink` — clean up after the run: one final generated job removes every data file the layout created, per client, after the last test has finished with them. It is derived from each host's staged layout job (so it always matches the exact file grid that was laid out, whatever auto tuning or hand edits did) and fio itself does the removal — including the per-client name prefixes only fio can reconstruct. A failed or interrupted run never unlinks: the files stay for debugging, and the next run's layout reuses them. The per-client namespace directories themselves may remain, empty.

`-v` — more verbosity; repeatable (`-vv`). Option names are case-insensitive throughout, so `-V` is also verbosity; the version is printed by `--version`.

# Workloads
A workload is a directory of standard fio jobfiles under `fio-jobfiles/`, run in sorted filename order. Shipped sets:

- `default` — the classic 4-corners tests (read/write bandwidth, latency, iops)
- `mixed` — 70/30 read/write workloads
- `2x400Gb` — a heavier bandwidth-oriented variant
- `wekawithin` — 1M/128k/4k reads, writes, and mixed IO
- `smoke` — a fast validation set for the harness itself: 256M files, 10s runs, and it removes its own files afterwards (`-w smoke`)

Add your own directory under `fio-jobfiles/` and select it with `-w`. A few conventions:

- Jobfile names must start with a digit (`011-bandwidthR.job`, ...) — that numeric prefix is both how files are discovered and what sets the run order.
- A comment line of the form `# report bandwidth` (or `latency`, `iops`, or several) at the top of a jobfile selects which metrics appear in the summary for that job. No directive means report everything.
- The `directory=` line is overridden by `-d` when the jobfiles are staged — inserted into `[global]` if missing, and if the jobfile has no `[global]` section at all one is created — so the shipped jobfiles work against any mount point.
- The measured workload should be the **last** job in the jobfile, and the summary describes that last job.

**File layout is a separate, generated job.** Every run puts a `000-wekatester-layout.job` first: it derives one `create_only` section per file namespace from the set's own jobfiles (taking each namespace's largest `numjobs`/`nrfiles`/`filesize`), so **all files exist on all machines before any measured test starts** — wekatester runs jobfiles serially and fio's coordinator waits for every client, so that first job is a true cross-client barrier. A workload directory that carries its own layout job keeps it (it is never regenerated unless you ask with `-g`); every other set gets one generated on the fly, without touching the source directory. The shipped jobfiles still contain their original `create_only` sections — they are harmless no-ops after the layout job has run, and they keep each file usable standalone with plain fio. The layout job prints a duration instead of a summary.

**Layouts heal incrementally, from evidence.** Before the capacity check, every run sweeps each host's destination against the exact file grid its staged layout implies: files whose SIZE deviates from the grid are deleted, files that match are kept and **credited against the capacity requirement**, and the layout phase's plain `create_only` pass then writes only what is missing. A geometry change heals just its delta (bumping `nrfiles` 502→510 creates 8 files, not 22TiB), an interrupted layout is repaired file-by-file on the next run, and nothing is trusted that wasn't measured — there are no marker files. Size is a sufficient test **because the generated layout job sets `fallocate=none`**: fio otherwise defaults to `fallocate=native` on Linux, which gives a file its full size before writing any data, so an interrupted layout would leave a full-size file of zeros that the sweep credits as complete and never rewrites — and the run then measures reads of nothing. Without preallocation a partial create leaves a short file, which fails the size test and is recreated. A set that ships its own layout job keeps it (only `-g` regenerates), so a hand-written layout job wants `fallocate=none` too. To force a from-scratch rebuild, remove the files (`-u` on a run, or `rm -rf` the grid).

# Customizing workloads (-C)
Jobfiles get edited in the field — `-C` makes that a guided flow instead of `cp -r` and hope:

```
./wekatester -C -i ubuntu:key.pem 10.30.0.1 10.30.0.2         # temp set from -w's workload
./wekatester -Cmyset host1 host2                              # named: ./fio-jobfiles/myset
./wekatester -C ./path/to/set -- host1 host2                  # explicit path; hosts after --
```

The flow: the workload set is copied (shipped sets are never edited in place — `-C default` customizes a fresh copy, not `fio-jobfiles/default` itself), the set's `hostlist.csv` opens in your editor (`$VISUAL`, then `$EDITOR`, then `vi`) — the host file is the primary customization surface: per-host login, engine, cpus, destination, and per-direction geometry in one CSV — then a 5s prompt (default no) offers editing the jobfiles individually in run order, the layout job is generated, and you are offered a chance to edit it (5s prompt, default no). A set created without a name lands in `./fio-jobfiles/<date>-<time>/` and you choose whether to keep it for reuse (5s prompt, default keep); a set you chose not to keep is removed **only after a fully successful run** — any failure preserves your edits. Naming an existing *custom* set edits it as-is; adding an explicit `-w` on top of one asks (a real y/N, no timeout) before **replacing** its jobfiles with a fresh copy of that workload.

With no attached set name, the token after `-C` is assumed to be a client; if it turns out unreachable over ssh, wekatester asks (5s, default yes) whether it was actually the set name. Put hosts after `--` to make it unambiguous.

Unattended forms:

- `-r` — fast track: no prompts, no editors; whatever is needed (set copy, layout, a missing destination directory under a wekafs mount) is created and the run proceeds. Existing layout jobs are never touched (add `-g` to regenerate them). Temp sets are kept. A wekafs destination that is not mounted `forcedirect` is a warning instead of a stop: the run goes ahead with the client cache in the IO path, and the warning is repeated into the run log so the bundle says so.
- `-n` — dry run: everything is resolved, generated and staged, then the full paths of the created files, every staged jobfile's contents, and the would-be run details are printed — and nothing executes. Combine with `-C` to prepare a set for manual editing.
- `-g` — force regeneration of existing layout jobs (works with `-r` and `-n` too).

A generated layout job carries a `# wekatester-layout: generated sha256=...` marker. If you edit the file the hash no longer matches, and wekatester treats it as yours: auto mode stages it exactly as written (with a warning that it may not cover auto-tuned namespaces) instead of re-deriving it. A pristine layout job under `-a max` is re-derived per host so it lays out the tuned namespaces (including the small-file working set).

`-C` needs a terminal for its editors and prompts; without one it refuses to run unless `-r` or `-n` is given. Prompts read the terminal directly, so they work fine under `... | tee run.log`.

# Auto mode
`-a` / `--auto` derives system-specific fio options from the workers instead
of trusting the jobfiles' static values. Four levels:

- `-a safe` — uniform and conservative: `numjobs` = the smallest usable core
  count across workers, ioengine fixed only if a worker lacks the one in the
  jobfile, and fio pinned away from weka's cores (`cpus_allowed`). Hosts stay
  directly comparable.
- `-a max` (default when the level is omitted) — each worker is tuned to its
  own capability: `numjobs` = that host's usable cores (every cpu except the
  ones weka has pinned — `isolcpus` does not narrow it further, because the
  widest mask measured fastest and `cpus_allowed_policy=split` keeps each job
  on its own cpu), deeper iodepth,
  and iops/latency files shrink to 1G with a small per-job spread (2
  files per job; the single latency job gets 8) IN PLACE -- the namespace stays the jobfile's own, so `-a` runs and
  plain runs share one on-disk grid and reuse each other's files. (An earlier release sized this against backend
  DRAM as a "cache-defeat working set"; the weka source disproved the
  premise — backends never serve file data from RAM — so the spread is
  stated directly instead of dressed up as a working-set formula.) Highest numbers; hosts with
  different hardware run different settings.
- `-a cal` — measures each client's own iodepth ceiling against this cluster
  instead of guessing it: a per-client iodepth ladder runs before staging,
  and the knees it finds are cached in `hostlist.csv`. The answer to "why
  these numbers" becomes "measured on your clients against this cluster."

How calibration works: before staging, the set is inspected for what it
actually runs — bandwidth and/or iops, read and/or write directions; latency
has no queue to ladder, so its FLOOR is measured instead (one QD1 rung per
direction, reported and bundled, never cached).

The objective is the **client's ceiling**: maximise throughput, and break
ties toward the shallowest rung. These curves have a *plateau*, not a knee —
on one 64-core client (2026-08-22) iops-read ran within 0.2% across qd=32,
64 and 128 — so the verdict is a plateau-membership test against a fixed
band, not a hunt for an elbow that is not there.

Calibration measures **one iodepth ladder per (type, direction)** — bw read,
bw write, iops read, iops write, whichever the set actually contains —
because the knees genuinely differ by direction (in the field: iops write
knee 4 vs read knee 16 on the same clients). File count and size come from
tables: each ladder runs 2 files per job (tunable per type and direction via
`CAL_BW_READ_NR` and friends) at the normalized `FILESIZE_MIB` per file.
(An earlier release searched a (nrfiles × iodepth) grid; the extra axis
multiplied the budget, and A/B tests on real hardware kept landing on 2 files
per job. Another held the working set constant by splitting a total across the
count — retired with the normalization, since sizes are part of the
measurement.) `numjobs` is one job per usable cpu — see
**Refinements** below for the two axes that *are* re-measured once the
depth is settled.

Bandwidth ladders climb qd 1–128, iops 1–256. Every cell runs on ALL clients
at once, so every number is that client's ceiling under contention — the
condition the real jobs run in. **Direction is the outer loop**: the whole
write ladder, one settle, then the whole read ladder, so a read rung never
lands straight on top of a write of the same files.

Each ladder runs in **two passes**, because *where* the uncertainty is
measured matters more than how. Per-rung standard deviation across four runs
of the same command on one client: 4–6% at qd=1–4, under 1% at qd=16–128. An
earlier release probed qd=4 — the noisiest point on the curve — and used that
spread to widen the band over the quietest. Four runs on a quiet cluster then
recorded qd=16, 32 and 64 and reported iops 23% apart, while the ladders
behind them agreed to 2%.

1. The **shape pass** walks every rung once at `CAL_SHAPE_RUNTIME` (10s) and
   only has to bracket the top. A rung must beat the best so far by more than
   `CAL_SHAPE_THR` (2%) to count as progress, and `CAL_STOP_BELOW` (2)
   consecutive misses end the ladder — a curve that turns over stops early. A
   host that stopped keeps running each rung until every host has stopped, so
   contention stays constant for the hosts still climbing.
2. The **decision pass** measures only the rungs that could carry the verdict
   — the shape peak, which anchors the peak estimate, plus the shallowest
   rungs still within `CAL_SHAPE_MARGIN` (4) points of the band, at most
   `CAL_CANDIDATES` (3) of them — `CAL_REPS` (3) times each at `CAL_RUNTIME`
   (30s, `-a cal:15` shortens it), **interleaved**: round-robin across
   candidates, never three-in-a-row. Interleaving is the point. Three
   back-to-back cells cannot tell noise from drift, and a monotone decline
   across them reads as noise it is not.

Wall clock lands about where the single-pass release did, because that one
paid three full-length cells for the probe and measured every rung once.
What changed is that every rung deciding the answer now carries n=3.

The verdict is **plateau membership**, and every candidate is credited with
**its best reading**, not the average of its repeats. A client cannot exceed its
own ceiling and contention only ever subtracts, so a rung's repeats sit under a
hard ceiling with a left tail rather than either side of a true value: averaging
credits a rung with less than it demonstrably did, and does it unevenly, pushing
whichever rung caught a busy window off the plateau. Every candidate within
`CAL_KNEE_PCT` (98.5%) of the best reading anywhere is on the plateau, and the
pick is the shallowest of them. The band is fixed — nothing widens it. 98.5 is measured: on that
client it resolves all four ladders to a unique rung at 99.5–100% of the
peak, while 99.5 destabilises every one of them, because the band can never
be tighter than the peak's own measurement error. Without the decision pass's
averaging, 96–97 is the honest setting. The verdict prints the plateau, the
peak's absolute throughput and the worst coefficient of variation, so a
ladder that measured nothing at all is visible as a number rather than a
ratio.

Two runs that cannot tell qd=32 from qd=64 must not disagree about which to
write down, so a recorded qd the new plateau **contains** is kept
(`CAL_HYSTERESIS`, on by default) and the log says so. That churn is what
"`-a cal` picks different settings every time" actually was.

The measured spread decides nothing. A candidate whose repeats disagree by
more than `CAL_NOISY_PCT` (8%) earns a WARNING naming the host and the ladder,
and the ladder records anyway — the repeats disagreed because some of them ran
in a contended window, and the ones that did not are still evidence of what the
client did. An earlier release discarded the whole ladder in that case, which
had the physics backwards and threw away good measurements; the suspect ledger
that implemented it is gone.

### `-a brutal`: the exhaustive grid

`-a cal` reasons about which rungs are worth measuring. `-a brutal` doesn't
reason at all: it measures the **whole (nrfiles &times; iodepth) cross product**
for every type and direction, **once per numjobs level**, and takes the best
number. The default axes are pruned from the first field grids, not from
theory &mdash; nrfiles was the flattest axis on every surface, bw never won
deep, iops never won shallow:

| axis | default |
|---|---|
| `BRUTAL_STEPS` | 1 2 4 8 16 — **nrfiles and iodepth move together** (nr = qd = step) |
| `BRUTAL_NJ` | 100 200 300 — the diagonal at one, two and three jobs per cpu |

The full cross product ran twice in the field and earned its own retirement:
nrfiles was the flattest axis at every depth, both iops directions collapsed
past qd16, and once numjobs multiplies the peak moves shallower still. The
matched diagonal keeps the informative trend — more concurrent streams per
job with more in flight per stream — at a quarter of the cells, and numjobs,
the axis that actually moves the answer, gets the levels. That is **15 cells
per ladder, 60 for a full set** (~18 min of measuring at `:15` with the write
settles), and a fourth level is `BRUTAL_NJ="100 200 300 400"` away.

**Why numjobs is an axis here and nowhere else.** Everywhere else numjobs is
derived &mdash; one job per usable cpu &mdash; because a derived value cannot go
stale. But whether a *second* job per cpu buys throughput is a question only a
measurement can answer, and the staged jobs can never explore it on their own.
A `BRUTAL_NJ` level above 100 stages every cell with proportionally more jobs
(split affinity wraps them around the same cpus), the seed widens itself to
cover the extra jobs' files, and a winner from that level records its actual
job count in the host file &mdash; the recorded count then earns a note, not a
warning, since an exact multiple of the usable cpus is a measured result.

It exists for one situation, and it is worth being blunt about it: when a
measured selection rule keeps choosing geometry the real test then fails to
reproduce, an exhaustive sweep cannot be wrong about which cell was fastest.
Use `cal` when you want the answer cheaply; use `brutal` when you want the
answer settled. Do not run its write grids with very short cells: even with
the per-cell settle, a `:5` cell is barely longer than its ramp.

Three things differ from `cal` beyond the search:

- **numjobs is not an axis.** It is the cores fio will actually run on &mdash;
  the host file's cpu list minus weka's pinned cores, the same
  `cal_cpus_nj` rule the staged jobs use. Sweeping it too would multiply the
  grid by another eight and measure parallelism a staged run cannot produce.
- **filesize is per FILE** (`BRUTAL_FILESIZE`, 1024 MiB), so the working set is
  `1G &times; nrfiles` per job and **grows along the nrfiles axis** &mdash; the
  opposite of `cal`, which holds the working set constant so the axis isolates
  file count. A wider cell here also reads more distinct data. It also means the
  scratch is sized by the *largest* nrfiles: 128 files &times; 1G &times; one job
  per core, seeded once and kept. On a 52-core client that is ~6.6TiB, and the
  capacity gate asks before writing it.
- **the winner is the highest reading.** No band, no plateau, no knee, no
  hysteresis, and no averaging.

**The estimator is the maximum, and that is a claim about the physics, not a
shortcut.** A client cannot exceed its own ceiling &mdash; cores, NIC and the
backend's service rate bound throughput from above &mdash; while contention (a
busy filesystem, a loaded network, cpu steal) only ever subtracts. A cell's
samples are therefore not scattered either side of a true value; they sit under
a hard ceiling with a left tail. A high reading is evidence the client *did*
that, so averaging it against a contaminated reading throws the evidence away.
The highest value a combination ever reached is the best estimate of what that
combination can do, and it is what gets recorded.

**What the shortlist is for.** Since extra samples can only raise a cell's best
and never lower it, `BRUTAL_CONFIRM` (3) gives the top cells a second run at
showing their ceiling. It is insurance against the genuinely best combination
having drawn a contended window on its single pass &mdash; not a correction to
the winner's number, which needs none. Set it to 0 and the grid's own maximum
stands.

**Write cells settle.** A write cell leaves a destage backlog, and without a
settle the next cell starts inside it. The first field runs showed exactly
that: every read surface was smooth, while the write surfaces carried the
previous cell's debt — the cell after a deep-queue write read 2% of best, and
at 5-second cells an entire write grid came back as a checkerboard. Every
write cell (grid and confirm) now settles `CAL_SETTLE` (10s) before the next,
which adds ~11 minutes per write grid at the defaults. Do not run brutal's
write grids with very short cells even so — at `:5` the measured window is
barely longer than the ramp.

**The in-flight guard.** A cell holds `numjobs &times; iodepth &times; bs` of
buffers &mdash; at the deep corner of a bandwidth grid that is real memory
(52 jobs &times; qd 128 &times; 1MiB is 6.7GiB). A cell needing more than
`BRUTAL_MEM_FRAC` (25%) of a host's MemTotal is skipped and **named in the log**,
never dropped silently. Raise the fraction to measure it anyway.

Latency is untouched: a floor is one QD1 stream by definition, so there is no
grid to sweep, and it is measured exactly as `cal` measures it.

The grid lands in the run bundle cell by cell, and the log prints it as a
percent-of-best table per ladder, so a flat surface and a peaked one are
distinguishable at a glance:

```
brutal: localhost bw-read: nrfiles=8 iodepth=32 -> 41.29GiB/s (n=2; runner-up
        nrfiles=8 qd=64 at 99.4%; grid spans 31-100% of best over 64 cells)
brutal:           qd1   qd2   qd4   qd8  qd16  qd32  qd64 qd128
brutal:   nr1     31%   52%   78%   93%   97%   98%   97%   96%
brutal:   nr2     34%   57%   84%   96%   99%   99%   99%   98%
...
```

### Refinements: the axes the ladder holds fixed

Iodepth alone is not the client's limit. What the client has in flight is
`numjobs × iodepth`, and the two halves are not interchangeable — on that
client iops-read saturated at 52×32 = 1,664 outstanding while iops-write
needed 52×128 = 6,656 and collapsed 9% at 13,312. So once the depth is
settled, two single-axis re-tests run at the winning depth:

- **`CAL_SPLIT`** re-measures the same outstanding IO at a different split,
  at the percentages of usable cores `CAL_SPLIT_PCT` names — and it names
  none by default: there is no reason to test fewer jobs than usable cores
  (a sub-percent "win" at half the cores buys half the parallelism for
  noise), and the widening direction needs extra seed. `50` halves the jobs
  and doubles the depth (free — the seed already covers every job); `200`
  tests more jobs than usable cpus, which doubles the calibration scratch
  and the seed pass. Both are operator opt-ins.
- **`CAL_NR_RETEST`** (off) re-measures `CAL_NR_CANDIDATES` (`1 4 8`) file
  counts at the winning `(numjobs, iodepth)`. Off for capacity, not doubt:
  covering nr=8 means the seed union carries 8 files per job as well as 2,
  roughly 75% more scratch and a longer seed pass. Worth running once per new
  client shape — the historical nrfiles comparisons that motivated the table
  were taken at a shallow qd, the region now known to be the noisiest on the
  curve.

Both are single-axis moves off the same baseline — the pick's own
decision-pass best — and **at most one is adopted**: compounding two
one-sample measurements would claim a joint optimum neither of them measured.
Any measured gain wins: the recorded parameters should be whatever produced
the best reading, and a significance bar would only defend the incumbent —
the pick holds no seniority over a cell that beat it. A split that wins
is recorded as `numjobs` in the host file; otherwise `numjobs` stays the
operator's, one job per usable cpu.

### Calibration measures what the test will run

A knee measured under a parallelism or a file layout the staged jobs will not
reproduce is not the test's ceiling. Two things are therefore derived once and
shared:

- **cpus and numjobs** come from one rule for the rungs, the seed and the
  staged jobs alike: the operator's cpu list minus weka's pinned cores (every
  cpu minus weka's when no list is given), and one job per cpu in that list
  unless the host file pins `nj`. Never more jobs than cpus — split affinity
  has nowhere to put the excess. Seen live before this rule existed: the
  ladders ran 52 jobs in a 46-cpu mask while the staged jobs ran 52 in a
  52-cpu mask.
- **the scratch's file layout** can mirror the workload's `filename_format`
  (`CAL_FMT_PARITY=1`), so a set whose files live in subdirectories is
  measured on files in subdirectories — a different metadata spread is a
  different measurement. **Off by default**, because the scratch's names are
  reused on purpose: the shipped sets do not agree on a layout
  (`$filenum/$jobnum` for default, mixed and 2x400Gb; flat for smoke;
  `wekawithin/$jobnum` for wekawithin), so a shape that follows the set would
  re-seed on every switch between them and strand the other shapes' files
  with nothing to reclaim them. Turn it on when the question is specifically
  whether directory-entry spread moves the number, and expect one re-seed.

**One dataset, one size.** Every calibration cell, every seeded file, and —
through the measured tuples the writeback records — every staged test runs on
`FILESIZE_MIB` (5G) files. Sizes are part of the measurement (the same staged
iops-write geometry delivered 7.5% differently at 256M vs 1024M files, purely
from the working set), so they are held equal everywhere; a host file that
pins its own `fs` still wins, as host files always do.

**Calibration measures on the workload's own files** whenever the set's
`filename_format` can address the grid (both `$filenum` and `$jobnum`, no
`$jobname`), and the dataset splits along the read/write line:

- **Reads — one fleet-shared dataset** (`shared.<fmt>`). Every client's read
  cells and staged read tests open the *same* files: that is the realistic
  fleet workload, it lets one dense set serve any number of clients, and its
  seeding is **sliced evenly across the participating clients** — N clients
  lay it out together at the fleet's aggregate write bandwidth. The set is
  sized by the widest job count any participating host runs. The layout job
  carries its sections on the first host only, so N clients never race to
  create (or the capacity check to price) the same files N times. The host
  name `shared` is reserved.
- **Writes — per-client sets** (`<host>.<fmt>`), because concurrent
  cross-client writes to shared files measure lease arbitration, not the
  client. Seeding is **truncate where appropriate**: a plan whose write
  phases are all sequential gets sparse truncate-created files (measured on
  isca224 2026-08-25: −0.8% vs dense, inside the run-to-run band — a metadata
  op instead of a layout), while any 4k-random write phase (iops-write,
  lat-write) forces the dense seed (holes cost a measured 6.7% on the
  extent-map insert).

Sets whose format cannot express the grid fall back to the private
`.wekatester-cal` scratch exactly as before. `-u` removes the per-client
sets, and — from the first host — the shared dataset.

**The calibration dataset is seeded once, incrementally, and kept.** Every
rung of every ladder reads `<host>.cal.<job>.<filenum>` (or the workload's own
shape under `CAL_FMT_PARITY=1`); ladders differ only
in how much of each file they use, so the scratch needs file *f* sized to
the largest any ladder asks of it — with the default tables, two 1024M files
per job (the bandwidth ladders), which already covers the iops ladders and
the latency floors. A file already at or above the size the union needs is
left alone — size is a sufficient test **because the seed job sets
`fallocate=none`**: a partial create leaves a short file that fails the
test, never a full-size hollow one that passes it — so the scratch survives
the run and the *next* calibration on that host seeds nothing at all. `-u`
removes it, exactly as it removes the workload's own data files. Before
seeding, the needs of every host whose destination sits on the same shared
filesystem are summed and checked against that filesystem's free space
together — ten clients that each fit individually can still not fit at once.

Each direction's winning (iodepth, nrfiles, filesize) is recorded into its
own host-file columns — `bandwidthR`, `bandwidthW`, `iopsR`, `iopsW` — under
the usual rules — filling empty fields only, overwriting under `-g` — so a
geometry you authored yourself still wins over calibration. Under `-g`
everything derived overwrites the host file except the three columns the
operator owns outright: host, login, and allowed_cpus — as written on the
host's **own** line. A generic (host-less) line is a default, not the host's
setting: it is never edited, and each host that ran on it gets its own line
recording what actually ran — the cpu list fio executed on (the generic list
minus weka's pinned cores and any cpu the host does not have), the proven
engine, and the resolved destination. A jobfile that runs
both directions takes the deeper-qd direction's WHOLE tuple — tuples never
mix across directions, because a mixed tuple was never itself measured — and
the writeback records each measured direction's own knee straight from
`cal.results`, so a mixed file cannot copy one direction's knee over the
other's. `numjobs` is never recorded at all: it is re-derived every run as
the operator's cpu list minus weka's pinned cores (every cpu minus weka's
when no list is given), so it can never go stale when weka is re-pinned.
Results flow into the run's geometry one precedence slot below the operator
(CLI > host file > calibration > tuner) and persist to `hostlist.csv` via
the `-a` writeback — which is also the cache: a host whose (fs, nr, qd)
triple for a direction is already complete skips that ladder (`-g`
re-measures; a partial triple never counts, half a geometry is not something
anyone measured). `-n` names the ladders a run would perform without
executing them.

Every staged jobfile records what auto derived for that host in header
comments. Auto also warns when workers differ (core counts, weka cores).

**Every run** is capacity-checked after staging, per host, against each
host's own destination filesystem: the staged variants (auto-tuned,
host-file-shaped, or plain) are what actually run, so their footprint — the
larger of the per-namespace job footprints and the staged layout's
per-section total — is compared with that host's `df` before any fio job
starts. Continuing would only march fio into `ENOSPC` partway through and
throw away the run. Pass `--ignore-capacity` to be **asked** (no timeout)
instead of aborted, and run anyway on a yes — unattended runs with the flag
warn and continue (useful when `df` under-reports, e.g. a filesystem that
is thin-provisioned or still rebalancing). If `df` returns nothing usable
for a host, that host goes unchecked, with a warning.

# SSH configuration
Because wekatester uses the real ssh client, anything you can express in `~/.ssh/config` just works. Two field-typical examples are included:

- `aws_ssh_config.example` — `ec2-user` with a support key, host key checking off
- `on-prem_ssh_config.example` — default key, host key checking off

Remember that `BatchMode` means keys must be usable without a passphrase prompt (use an agent), and unknown host keys will fail the run unless your config handles them.

# Host files (-t)
One CSV assigns per-host settings without a jobfile set per client:

```
host,user_login,ioengine,allowed_cpus,destination_folder,bandwidthR:nj/fs/nr/qd,bandwidthW:nj/fs/nr/qd,latencyR:nj/fs/nr/qd,latencyW:nj/fs/nr/qd,iopsR:nj/fs/nr/qd,iopsW:nj/fs/nr/qd
client-1,ubuntu,io_uring,"8,10,12,14",/mnt/weka,12/10G//8,12/10G//4,1///1,1///1,12/1G/2/64,12/1G/2/16
,,io_uring,,,,,,,,
```

A line naming a host assigns to that host (two lines naming the same host is an error, both line numbers named). Host-less lines are **selector** lines: their login and/or ioengine choose the hosts they apply to — a login selects hosts using that login, an ioengine selects hosts that **passed that engine's functional test** — and their remaining fields fold into any host whose more-specific settings left them unset. A host line beats two selectors beats one beats a global `,,...` line; a generic line never overrides a more specific one regardless of file order; equally specific conflicts keep the *first* line and print a warning. A host-less line's login is only ever a selector — logins are assigned by host lines, the CLI, or your ssh defaults. Empty fields mean "default"; geometry sub-fields may be omitted (`12/10G//8` sets numjobs, filesize and iodepth). Geometry is per type AND direction: the R columns shape read jobs, the W columns write jobs, and a mixed-direction jobfile takes the deeper-queued direction's whole tuple. Quote cpu lists (`"22,24"`), and `#` starts a comment.

Without `-t` no host file is used — with one exception: a `-C` set's own `hostlist.csv` is always honored, because it is the set's customization surface. Bare `-t` looks in the job set folders first — an existing `-C` set's own `hostlist.csv`, then the `-w` set's — falling back to `./hostlist.csv`; when both a set-folder copy and `./hostlist.csv` exist, the set folder wins and is the copy later writebacks (`-a`) update. With `-C` and no file anywhere, the file is created in the custom set (where the editor opens it), never as a stray `./hostlist.csv`. A named path that doesn't exist asks (no timeout) whether to create the self-describing template or quit — under `-r` the same question gets 5 seconds and defaults to create. `-C` sets own a copy (taken from the file in use or the source set, template otherwise), which opens first in the editor flow and serves later runs of that set. Precedence overall: **CLI flags > host file > jobfiles/tuner**.

Every ioengine the file (or `-e`) names is **proven with a real one-file job on that host's destination** before use — `--enghelp` lists what fio was built with, not what the kernel and filesystem will run — and in auto mode the tuner's common engine comes from the proven set. A requested `allowed_cpus` outside the host's current `taskset -cp` mask, or overlapping weka's pinned cores, is an error showing all three (request, mask, weka cores) unless a passwordless escalator works — probed per host as dzdo, pbrun, sesu, pmrun, doas, ksu, then sudo last (sites that install an enterprise escalator usually mandate it), each tested non-interactively with a 5s timeout. Escalation is as-needed: a self-affinable mask (pure-isolated cpus, or inside the current taskset) runs fio as the login user even when an escalator exists. When escalation is needed it covers the `taskset` only — fio itself drops back to the login user via `runuser` where policy allows (keeping test files user-owned), falls back to a root fio with a NOTE otherwise, and is torn down with the same privilege (cpus overlapping weka's dedicated cores are excluded at execution — the host file keeps your list as written). weka CLI queries, when a future feature issues any, try the login user first and get one escalated retry on failure. Each host may also point at its own `destination_folder`: the mount guard, write probe, layout grid sweep, and staged variants all follow it (auto mode's capacity estimate still measures the master's filesystem — approximate when destinations differ).

With `-a`, the derived values (established login, proven engine, cpus, directory, per-direction geometry) are recorded back into the host file for re-use — filling only what the host's own line didn't provide (what a generic line supplied counts as unset, so the host line records the value the run resolved); add `-g` to be asked (no timeout) whether to overwrite instead. Updates never edit lines in place: the old host line is commented out and the new one appended, preserving history. A machine wekatester records for the **first** time is named `<short hostname>/<machine-id>` rather than by whatever the run happened to address it as — `localhost` identifies nothing, and a bare hostname collides as soon as a host file is shared between labs. The id comes from `/sys/class/dmi/id/product_uuid`, falling back to `/etc/machine-id`, and is omitted entirely when neither can be read. You never have to type it: a row you wrote keeps your spelling forever, and the id is ignored when the file is read — the name before the `/` is matched against the host the run is using, so a local run still resolves its own row without ssh. Two rows whose names collide but whose ids differ are rejected with both spellings named, since the run cannot tell which machine you meant.

# Authentication
A large client list rarely shares one credential, so wekatester carries a pool and finds each worker's own. `-i [login:]keyfile` names a key, optionally bound to a login (`-i ubuntu:lab.pem`); it takes comma-separated lists and may be repeated, accumulating in order. A bare path (`-i lab.pem`) means ssh's default user. `-p [n]` prompts — on your terminal, passwords never echoed — for *n* (default 1) login/password pairs; an empty login answer means ssh's default user. `-i` and `-p` combine freely.

Connection establishment runs before anything else touches a host, in rounds, each round trying one credential against **all still-unconnected workers in parallel**:

1. **existing ssh sessions** — a live ControlMaster from your own ssh config is detected (`ssh -O check`) and reused as-is. wekatester never closes a master it didn't create: its teardown only touches its own socket directory.
2. **plain defaults** — your agent and `~/.ssh/config` identities;
3. **each `-i` key**, in the order given;
4. **each `-p` pair**, in the order given — keys go first because failed password attempts burn sshd's `MaxAuthTries` counters.

Per worker, the first success wins and every later ssh/scp in the run rides that session (multiplexed, pinned open until the run ends). Keys are tried with `IdentitiesOnly=yes` so the agent's other keys aren't offered alongside. Passwords are fed through an `SSH_ASKPASS` helper over a per-attempt fifo in tmpfs — no `sshpass`, and the password never appears on a command line, on disk, or in any process's environment; a wrong one fails cleanly rather than hanging. A key path that is missing or unreadable (`-i ~/.ssh` instead of `-i ~/.ssh/id_ed25519`) is reported before the first connection; entries may not contain whitespace. Workers that no credential reaches are named and fail preflight. `-p` needs a terminal — unattended runs should use keys. In local mode both options are accepted and ignored — there is no ssh to configure.

# Output
Each job prints a summary block as it completes, and every run leaves one self-contained bundle in the output directory (`./results` by default, `-o` to choose another). During the run the bundle is a `<date>-<time>/` directory holding:

- `results_<jobname>.json` — the raw fio JSON, one file per job, written as each job completes;
- `wekatester.log` — everything the run printed, stdout and stderr, including teardown;
- `fio-jobfiles/<host>/` — the staged per-host jobfile variants that actually ran (with auto mode these differ per host, and a `-C` temp set may be gone later — this is the execution truth);
- `sysinfo/<host>/` — the box context the numbers depend on, one file per item: `cmdline` and `isolated` (kernel command line and the live isolcpus set), `mounts` and `df`, `meminfo` and `free`, `lscpu` and `numactl`, `lspci` and `ip` (addresses), `uname` and `os-release`, `uptime` (load at run start), `fio` (`--version`), and `weka` (`weka local ps`), plus before/after pairs captured at run start and teardown: `pressure-{cpu,io,memory}-{start,end}` (PSI — sustained cpu `some avg10` above a few percent during a run means housekeeping tasks were queuing), `loadavg-{start,end}`, and `sar-end` (the sysstat log slice covering the run window, when the box keeps one). A host missing a tool records `not available` instead of failing the run;
- `cal/` — on `-a cal` runs, every ladder rung's jobfile and raw JSON plus `cal.results`.

At exit the directory is compressed to `<date>-<time>.tgz` and removed, leaving only the archive — for every run, failed and interrupted ones included, so a crashed suite still keeps everything already measured. Nothing is lost to the fold: `-s` summarizes a bundle directly from the archive, and the log inside records what went wrong.

The summary shows the cluster-wide totals, the per-host average with the min/max hosts called out (straggler visibility), and an IO-weighted average latency:

```
starting test run for job 011-bandwidthR.job on host-1 with 2 workers:
    read bandwidth: 4.50 GiB/s
    write bandwidth: 2.50 GiB/s
    total bandwidth: 7.00 GiB/s
    average bandwidth: 3.50 GiB/s per host  (min 3.00 GiB/s vega-1, max 4.00 GiB/s vega-2)
    read latency: 227.3 us  (min 200.0 us vega-1, max 250.0 us vega-2)
    average latency: 269.7 us (IO-weighted)
```

The layout job that runs first reports a duration instead of a summary:

```
laying out files (000-wekatester-layout.job) on 2 host(s)...
layout: complete in 41s across 2 host(s)
```

Any run can be re-summarized later with `-s` — point it at the bundle (no extraction; it reads the archive in memory) or at a single extracted `.json`:

```
./wekatester -s results/20260808-231119.tgz
```

# Caveats
- fio's client/server protocol is version-sensitive. Keep fio versions consistent across the workers and the coordinator host, or connections may fail in confusing ways.
- TCP port 8765 (fio's server port) must be open from the coordinator to every worker — ssh working does not imply this; host firewalls commonly allow only port 22. wekatester verifies reachability before running and names any blocked hosts, and it refuses to summarize results that are missing hosts (fio itself would silently benchmark the survivors).
- The per-host min/max spread in the summary only appears with 2 or more workers. A run with no host at all is local mode, not an error.
- Local mode still needs fio on the local host, `/dev/shm`, and fio's port 8765 reachable on loopback — the same phases run, they just run against this machine. It is Linux-only (the mount guard uses `findmnt`, staging uses `/dev/shm`) and refuses to start elsewhere; driving remote workers *from* a non-Linux machine is unaffected.
- If `-d` is a wekafs mount it must be mounted with `forcedirect`; wekatester refuses to run otherwise. fio's `direct=1` alone does not keep the wekafs client cache fully out of the IO path. Under `-r` this is a warning rather than a stop — the numbers then include client-cache effects, and the run log says so.
- If `-d` does not exist yet, wekatester offers to create it (once, for every worker that lacks it) — but only when the nearest existing parent is a wekafs mount. Without `-r` that takes a terminal and a `y`; with `-r` or `-n` it is a 5-second prompt defaulting to create, or created outright when there is no terminal. A missing directory anywhere else is a hard stop: with wekafs not mounted, the parent is the root filesystem, and a mistyped `-d` created there would benchmark the boot disk.
- The target directory must be writable by the login user on every worker — fio creates its data files there. wekatester probes this before running (one dotfile, created and removed) because fio's client mode reports a worker-side permission failure so quietly that the run would otherwise "succeed" with zero IO. A root-owned mount root is the usual cause; a one-time `chmod` of the root on any host persists in the shared filesystem. A directory wekatester creates is owned by the login user, so it passes this probe by construction.
- `fio --client` exits 0 even when jobs fail on the workers, so wekatester reads success out of the results themselves: a job whose stats carry an error, or a measured job that moved zero bytes, aborts the run and names the host — it will not print a summary of zeros.
