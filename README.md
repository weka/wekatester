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
                  [-x secs] [-C[set]] [-b] [-l] [-r] [-n] [-g] [-u] [-v] [-h]
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
                          cal: group the clients into hardware shapes and,
                          solo on one client per shape, search numjobs
                          (N/2, N, 2N, 4N of N usable physical cores),
                          iodepth, nrfiles and the ioengine per test type:
                          bandwidth toward NIC line rate, the most iops,
                          the most jobs at the latency floor
                          brutal: the cal search with no early stops --
                          every rung of every ladder is measured. Slow
                          :secs sets the measured seconds per cell (default
                          30); it does not change
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
  -b, --bulk     run every latency test at 1MiB blocks too, as a separate
                 test listed on its own (under -a cal/brutal the 1MiB test
                 gets its own calibrated job count)
  -l, --load     with -a cal or brutal: before each bandwidth and iops test
                 runs, run its setting on every client at once; if they
                 deliver under 90% of their solo results added up, try each
                 client one notch lighter and heavier and run the test on the
                 better one -- or report the cluster as the limit
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

`-b/--bulk` — run every latency test at 1 MiB blocks too. Each latency jobfile gains a 1 MiB twin at staging (`021-latencyR.job` gains `021b-latencyR-1M.job`), which runs right after it on the same files and is summarized as a test of its own. IOPS stays 4k. Under `-a cal` and `-a brutal` the 1 MiB test gets its own calibrated job count, recorded in its own host-file columns (`latency1mR`, `latency1mW`).

`-l/--load` — with `-a cal` or `-a brutal`, check each calibrated bandwidth and IOPS setting under load before its test runs. See *Checking the settings under load* below.

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
- `-a cal` — calibrates before staging, **per client shape**: the clients are
  grouped by hardware, one client of each shape is measured alone, and the
  search finds the parameters that give that shape its best result per test
  type. What it finds is cached in `hostlist.csv`. The answer to "why these
  numbers" becomes "measured on your clients against this cluster."
- `-a brutal` — the same search with every early stop disabled (see below).

### What calibration optimizes

The cluster is assumed to have far more headroom than its clients can
consume, so `-a` exists to make every client run the parameters that give its
hardware its absolute best result per test type. The fleet-wide run then shows
what the cluster can do.

- **Bandwidth** — as close to the client's NIC line rate as it gets, on 1 MiB
  IO, the block size weka moves between clients and backends. Line rate counts
  as reached at 95% (`CAL_LINE_PCT`).
- **IOPS** — the client's maximum 4k random IOPS, with fio's latency
  accounting off. The iops test records no latency, so the calibration cells
  and the staged iops jobs both run with `disable_lat`, `disable_clat`,
  `disable_slat` and `norandommap`.
- **Latency** — the floor, one job at queue depth 1, and then as many jobs as
  keep the latency within 5% of it (`CAL_FLOOR_PCT`). That is the most IOPS
  the client does *at* the floor, not a knee. The shipped latency jobs report
  IOPS beside latency for that reason. With `-b` the same again at 1 MiB.

Under `-a cal` and `-a brutal` every latency test also runs as a **one-job
twin** (`021-latencyR-1job.job`, just before its original): numjobs, iodepth
and nrfiles all 1 on every client, with the same data per job. The run then
shows one single-threaded stream's latency across the fleet next to every
client's latency at its calibrated load.

### Client shapes

Hosts are grouped by their hardware:

- cpu model and count;
- memory, as MemTotal rounded to the nearest GiB;
- how many cores weka has pinned;
- the NICs weka uses, with the link speed `ethtool` reports for each.

The probe reads weka's NICs from `weka local resources net`, which needs root.
It runs that command as the login user when that user is root, and otherwise
under the passwordless escalator the probe already found. Line rate is the sum
of those NICs' link speeds. More things split a shape, because a job count or
an engine measured on one host would not describe the other: N and the number
of usable threads (see below), the engines that passed their test, and an
engine pinned by `-e` or the host file.

When line rate cannot be known, calibration warns and runs the bandwidth search
to its peak instead. That happens when there is no weka CLI, no root and no
escalator, UDP mode, a NIC bound to vfio with no kernel netdev, or ethtool
reporting no speed.

The first host of each shape on the command line is its representative, and it
is measured **alone**: nothing else runs while a shape calibrates, so every
number is that client's ceiling rather than its share of a contended fleet.
Shapes run one after another. The answer is written for every member of the
shape. The run log names each shape, its hosts, its NICs and line rate, and
says up front the most cells the shape can take and roughly how long.

### Usable cores: N

Job counts are counted in **physical cores**. The probe reads every cpu's
socket, core and SMT siblings from sysfs, and N is what is left for fio:

- **weka's DPDK cores go whole.** Weka pins each dedicated io thread to one cpu
  and keeps that core's sibling idle on purpose, so both threads are weka's.
- **core 0 of socket 0 and its sibling always stay with the OS**, and a reserve
  of more cores stays with them, for the OS and weka's own non-DPDK processes:
  2 cores on a host of up to 24 physical cores, 4 above, plus one for every 4
  DPDK cores past 4 (5–8 DPDK cores add 1, 9–12 add 2), at most 12 and never
  more than half the cores. The reserve takes core 0 first, then one core at a
  time round-robin over the sockets starting at socket 1, the lowest free core
  of each: two sockets reserve core 0 and the next core of socket 0 plus the
  first two of socket 1; one socket reserves its next cores.
- **N = physical cores − DPDK cores − reserved cores.** An operator cpu list
  in the host file is the operator's own reserve: only weka's cores and core
  0's pair come out of it. A client with N < 1 stops the run with the numbers.

The searches use four job counts: **N/2 and N run one job per physical core
with the siblings idle; 2N and 4N put the siblings to work too**, which is how
a search finds out whether they help or hurt. Every cell and every staged job
declares its cpu set with split affinity, and a job count at or below N gets
the one-thread-per-core set. The log prints each shape's arithmetic, for
example `8 physical core(s) - 2 weka DPDK - 2 reserved for the OS (0-1 2-3) =
N=4`.

### The search

**The engine comes first.** Short comparison cells (`CAL_ENGINE_RUNTIME`,
10s) run once per test type and per candidate engine, meaning whichever of
io_uring, libaio and psync passed its test job. Bandwidth runs at N jobs and
queue depth 1, IOPS at N jobs and queue depth 16, and latency at one job and
queue depth 1. Each type's best reading wins, or its lowest latency. A tie
inside the band goes to io_uring, then libaio, then psync. The type winners
are tallied into **one engine per shape**, because the host file carries one
engine per host, and every search then runs on that engine. An engine pinned
by `-e` or by the host file is used as it is; `-g` re-chooses a host-file
engine.

**Then one search per test type and direction** the set runs, with cells of
`CAL_RUNTIME` seconds (30 by default; `-a cal:15` shortens them):

**At or below N there is no queue or file ladder**: every cell runs iodepth 1
and nrfiles 1. The ladders — nrfiles 1, 2, 4 (`CAL_NR_LADDER`), iodepth 1–16
for bandwidth (`CAL_BW_QD_LADDER`) and 1–512 for IOPS (`CAL_IOPS_QD_LADDER`) —
run only at 2N and 4N. A ladder ends when it flattens, meaning two rungs that
fail to beat the best by 2%, and 4N runs only when 2N beat N.

- **Bandwidth** walks numjobs 1, 2, 4 … N/2, N. The first rung at 95% of line
  rate is the answer. If none reaches it, 2N and 4N walk iodepth for every
  nrfiles, and again the first cell at 95% is the answer. If nothing reaches
  line rate, or line rate is unknown, the peak rule below decides. A reading
  more than 5% *above* line rate means line rate is not this client's ceiling,
  and the search falls back to the peak.
- **IOPS** measures N/2 and N, then at 2N and 4N walks the queue ladder at
  nrfiles 1 until it flattens, and tries nrfiles 2 and 4 at that count's
  winning iodepth and one step deeper. The peak rule decides.
- **Latency** takes three readings of one job at queue depth 1, and the floor
  is the *lowest*, because contention only ever adds latency. Numjobs then
  widens 2, 4 … N/2, N, and on to 2N and 4N with each nrfiles, at queue depth
  1, while the latency stays within 5% of the floor. A rung that leaves the
  band is re-measured once before it is believed. The answer is the last rung
  inside the band. With `-b` the 1 MiB latency test gets the same search.

**The peak rule.** The top three cells (`CAL_CONFIRM`) get a second reading.
Contention only subtracts, so a second chance can raise a cell and never lower
it, and the best reading is what a cell is credited with. The highest best
reading wins. Inside 98.5% of it (`CAL_KNEE_PCT`) the cheapest cell wins: the
least outstanding IO (numjobs × iodepth), then fewer jobs, then the shallower
queue, then the tabled file count.

Every write cell is followed by `CAL_SETTLE` (10s), so the next cell does not
start inside the previous one's destage backlog. The first field grids showed
exactly that without it: every read surface was smooth, while the write
surfaces carried the previous cell's debt. A cell whose in-flight buffers
(numjobs × iodepth × bs) would exceed `CAL_MEM_PCT` (25%) of the client's
MemTotal is not run, and the log says so.

### `-a brutal`

`-a brutal` runs the same search with every early stop disabled: every
combination of job count, iodepth and nrfiles the ladders define is measured,
and the top five cells get a second reading (`BRUTAL_CONFIRM`). Bandwidth takes
the peak instead of the first rung at line rate. With the default ladders that
is about 120 IOPS cells, 35 bandwidth cells and 12 latency cells per direction,
some 330 per shape, or about three hours at 30s cells. Use `cal` for the answer
cheaply, and `brutal` when the stopping rules themselves are the suspect.

### Checking the settings under load: `-l`

Calibration finds each client's best settings while that client runs
**alone**. The real test runs **every client at once**, sharing the cluster.
With `-l`, before each bandwidth and IOPS test runs for real:

1. Its staged setting runs for `CAL_RUNTIME` seconds on each shape's
   representative alone, then on every client together.
2. If the clients together deliver at least 90% (`CAL_FLEET_PCT`) of what they
   did alone, added up, the setting stands.
3. Short of that, the clients are getting in each other's way at the cluster.
   `-l` tries every client one notch lighter (half the iodepth, or half the
   jobs at iodepth 1) and one notch heavier (twice the iodepth), re-measures
   the better one, and runs the test on it if it still wins by more than 2%.
4. If neither notch moves the total, the cluster itself is the limit, and the
   log says that total is the cluster's number for the test.

A check costs a few 30s cells per test. Latency tests are left alone: their
rise under load is the measurement, next to the one-job twins' single-stream
baseline. The host file keeps the solo calibration; `-l` adjusts only this
run's staged jobs, and the bundle's copy of them.

### Calibration measures what the test will run

A value measured under a parallelism, an engine or a file layout the staged
jobs will not reproduce is not the test's ceiling. So:

- **cpus** come from one rule for the cells and the staged jobs alike, N and
  its two cpu sets (see Usable cores), minus any cpu the host refuses to bind.
  A job count at or below N runs one job per physical core; a wider one
  spreads over the siblings too.
- **the engine** a shape was measured on is the engine its staged jobs run.
- **one amount of data per job.** Every seeded file is `FILESIZE_MIB` (5G),
  and every calibration cell and, through the recorded tuples, every staged
  test gives each job 5G of data split over its files: nrfiles 2 runs two
  2560M regions, nrfiles 4 four 1280M ones, each the leading part of a 5G
  file. The working set is part of the measurement — the same staged
  iops-write geometry delivered 7.5% differently at 256M vs 1024M files, and
  WEKAPP-289548 saw 4k random reads lose 30% from 1M files to 3G files — so
  the file ladder changes the file count and nothing else. A host file that
  pins its own `fs` still wins.

**Calibration measures on the workload's own files** whenever the set's
`filename_format` can address the grid, meaning it has both `$filenum` and
`$jobnum` and no `$jobname`. The dataset splits along the read/write line:

- **Reads use one fleet-shared dataset** (`shared.<fmt>`). Every client's read
  cells and staged read jobs open the *same* files. That is the realistic fleet
  workload, and it lets one dense set serve any number of clients. The layout
  job lays it out once, from the first host, for the widest job count any host
  reads it with. The host name `shared` is reserved.
- **Writes use per-client sets** (`<host>.<fmt>`), because concurrent
  cross-client writes to shared files measure lease arbitration, not the
  client. A set whose calibration writes are all sequential gets
  truncate-created sparse files, which measured −0.8% vs dense on isca224,
  inside the run-to-run band. Any 4k-random write search forces the dense
  seed, because holes cost a measured 6.7% on the extent-map insert.

Sets whose format cannot express the grid fall back to the private
`.wekatester-cal` scratch.

**Only the representatives seed, and incrementally.** Before its first cell, a
shape's representative gets the files N jobs need. A wider cell, such as 4N
jobs or a higher nrfiles, seeds its own extra files first; 4N jobs at nrfiles
4 is 16N files of 5G, which the seed estimate prices before writing. A file already at or above `FILESIZE_MIB` is left alone. Size is
a sufficient test **because the seed job sets `fallocate=none`**: a partial
create leaves a short file that fails the test, never a full-size hollow one
that passes it. Before a byte is written the seed prints its estimate: the
dense files and GiB to write, the sparse truncates, and the free space at the
destination with the share the seed will take. A seed that would not fit
stops there. The dataset is kept after the run, so the next calibration seeds
nothing; `-u` removes it, exactly as it removes the workload's own files.

### What lands in the host file

Each measured direction records its whole tuple, (numjobs, filesize, nrfiles,
iodepth), into its own host-file column: `bandwidthR`, `bandwidthW`,
`latencyR`, `latencyW`, `iopsR`, `iopsW`, and with `-b` `latency1mR` and
`latency1mW`, which come last so a file written before they existed still
lines up. The shape's engine goes into
`ioengine`. `numjobs` is always recorded for a measured direction, because
bandwidth's answer *is* a job count, and so is latency's. The rules are the
usual ones: calibration fills empty fields only, and overwrites them under
`-g`, so a geometry you authored yourself still wins over calibration.

Under `-g` everything derived overwrites the host file except the three columns
the operator owns outright: host, login, and allowed_cpus, as written on the
host's **own** line. A generic (host-less) line is a default, not the host's
setting. It is never edited, and each host that ran on it gets its own line
recording what actually ran: the cpu list fio executed on (the generic list
minus weka's pinned cores and any cpu the host does not have), the engine, and
the resolved destination.

A jobfile that runs both directions takes the deeper-qd direction's WHOLE
tuple. Tuples never mix across directions, because a mixed tuple was never
itself measured. The writeback records each measured direction's own tuple
straight from `cal.results`, so a mixed file cannot copy one direction's tuple
over the other's.

Results flow into the run's geometry one precedence slot below the operator:
CLI > host file > calibration > tuner. They persist to `hostlist.csv` through
the `-a` writeback, which is also the cache. When a shape's representative
already carries a complete tuple for a direction, meaning all four fields
including numjobs, the whole shape reuses it and skips that search. A partial
tuple never counts, and neither does one an `-a max` run wrote down: the
writeback never records a *staged* numjobs, so a tuned guess cannot pass for a
measurement. `-g` re-measures. `-n` names the shapes and the searches a run
would perform without executing them.

A host file written before this calibration existed carries iodepth, nrfiles
and filesize without numjobs, and so does every `-a max` writeback. Those
slots are measured again, and fill mode then keeps the old fields and adds only
numjobs, a mix nobody measured. Calibration warns for each such slot. If the
fields came from an earlier `-a` run rather than from you, re-run once with
`-g` so the measured tuple replaces them.

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
host,user_login,ioengine,allowed_cpus,destination_folder,bandwidthR:nj/fs/nr/qd,bandwidthW:nj/fs/nr/qd,latencyR:nj/fs/nr/qd,latencyW:nj/fs/nr/qd,iopsR:nj/fs/nr/qd,iopsW:nj/fs/nr/qd,latency1mR:nj/fs/nr/qd,latency1mW:nj/fs/nr/qd
client-1,ubuntu,io_uring,"8,10,12,14",/mnt/weka,12/10G//8,12/10G//4,1///1,1///1,12/1G/2/64,12/1G/2/16
,,io_uring,,,,,,,,
```

A line naming a host assigns to that host (two lines naming the same host is an error, both line numbers named). Host-less lines are **selector** lines: their login and/or ioengine choose the hosts they apply to — a login selects hosts using that login, an ioengine selects hosts that **passed that engine's functional test** — and their remaining fields fold into any host whose more-specific settings left them unset. A host line beats two selectors beats one beats a global `,,...` line; a generic line never overrides a more specific one regardless of file order; equally specific conflicts keep the *first* line and print a warning. A host-less line's login is only ever a selector — logins are assigned by host lines, the CLI, or your ssh defaults. Empty fields mean "default"; geometry sub-fields may be omitted (`12/10G//8` sets numjobs, filesize and iodepth). Geometry is per type AND direction: the R columns shape read jobs, the W columns write jobs, and a mixed-direction jobfile takes the deeper-queued direction's whole tuple. Quote cpu lists (`"22,24"`), and `#` starts a comment.

Without `-t` no host file is used — with one exception: a `-C` set's own `hostlist.csv` is always honored, because it is the set's customization surface. Bare `-t` looks in the job set folders first — an existing `-C` set's own `hostlist.csv`, then the `-w` set's — falling back to `./hostlist.csv`; when both a set-folder copy and `./hostlist.csv` exist, the set folder wins and is the copy later writebacks (`-a`) update. With `-C` and no file anywhere, the file is created in the custom set (where the editor opens it), never as a stray `./hostlist.csv`. A named path that doesn't exist asks (no timeout) whether to create the self-describing template or quit — under `-r` the same question gets 5 seconds and defaults to create. `-C` sets own a copy (taken from the file in use or the source set, template otherwise), which opens first in the editor flow and serves later runs of that set. Precedence overall: **CLI flags > host file > jobfiles/tuner**.

Every cpu in a host's `allowed_cpus` is **bind-tested on that host** before the run (`taskset -c <cpu> true`, once per online cpu, plus a retry under the escalator where the plain test fails). A cpu can be online and outside weka's pinned set and still refuse the bind — offline but counted, or held by another cgroup's cpuset partition — and fio's only answer to that is `err=22 cpu_set_affinity` per job, raised on the daemonized server after the run has started. Such cpus are trimmed with a note naming them, on the same contract as the weka overlap: the host file keeps your list as written, execution runs on what works. A cpu that binds only under the escalator is escalated, not trimmed. Where the test cannot run (no `taskset`) the older rule applies: isolated cpus are assumed self-affinable.

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
- `cal/` — on `-a cal` and `-a brutal` runs: `shapes` and `shapes.txt` (the client shapes), per shape `s<n>/` with the engine cells, each search's history of readings, and the tuples it settled, every cell's jobfile and raw JSON, and `cal.results`. When a calibration fio run fails — the seed or a cell — its fio output (`res-*.json`), each host's jobfile (`<rung>.<host>.job`) and each host's own `fio --parse-only` verdict (`parse.<host>.out`) are filed here before the run stops, and fio's own error lines are repeated on the console; the staging area in tmpfs is wiped on exit, so the bundle is the only place that evidence survives.

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
- TCP port 8765 (fio's server port) must be open from the coordinator to every worker — ssh working does not imply this; host firewalls commonly allow only port 22. wekatester verifies reachability before running and names any blocked hosts, and it refuses to summarize results that are missing hosts (fio itself would silently benchmark the survivors). The check is one ssh session to the coordinator that probes every worker in parallel from inside it — one session per worker would pile N sessions onto the coordinator's single multiplexed connection, and sshd's `MaxSessions` (default 10) and `MaxStartups` then refuse the rest, which read as firewalls (seen at 111 workers: 39 false "cannot reach").
- The per-host min/max spread in the summary only appears with 2 or more workers. A run with no host at all is local mode, not an error.
- Local mode still needs fio on the local host, `/dev/shm`, and fio's port 8765 reachable on loopback — the same phases run, they just run against this machine. It is Linux-only (the mount guard uses `findmnt`, staging uses `/dev/shm`) and refuses to start elsewhere; driving remote workers *from* a non-Linux machine is unaffected.
- If `-d` is a wekafs mount it must be mounted with `forcedirect`; wekatester refuses to run otherwise. fio's `direct=1` alone does not keep the wekafs client cache fully out of the IO path. Under `-r` this is a warning rather than a stop — the numbers then include client-cache effects, and the run log says so.
- If `-d` does not exist yet, wekatester offers to create it (once, for every worker that lacks it) — but only when the nearest existing parent is a wekafs mount. Without `-r` that takes a terminal and a `y`; with `-r` or `-n` it is a 5-second prompt defaulting to create, or created outright when there is no terminal. A missing directory anywhere else is a hard stop: with wekafs not mounted, the parent is the root filesystem, and a mistyped `-d` created there would benchmark the boot disk.
- The target directory must be writable by the login user on every worker — fio creates its data files there. wekatester probes this before running (one dotfile, created and removed) because fio's client mode reports a worker-side permission failure so quietly that the run would otherwise "succeed" with zero IO. A root-owned mount root is the usual cause; a one-time `chmod` of the root on any host persists in the shared filesystem. A directory wekatester creates is owned by the login user, so it passes this probe by construction.
- `fio --client` exits 0 even when jobs fail on the workers, so wekatester reads success out of the results themselves: a job whose stats carry an error, or a measured job that moved zero bytes, aborts the run and names the host — it will not print a summary of zeros.
- The fio coordinator takes every worker on its command line (one `--client=<host> <jobfile>` pair per worker), and the coordinator's shell receives that as a single argument, which Linux caps at 128 KiB (`MAX_ARG_STRLEN`). That is roughly 1,100 workers with 25-character names, or 700 with 60-character FQDNs. wekatester measures the line at staging and stops with a clear message before anything runs (a dry run reports it too); past that size, run the fleet as two or more host lists.
