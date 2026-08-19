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
                  [-e engine] [-a [safe|max|cal|hybrid]] [--ignore-capacity]
                  [-i [login:]keyfile[,...]] [-p [n]] [-t [hostfile]]
                  [-C[set]] [-r] [-n] [-g] [-u] [-v] [-h] [--] [server ...]
       wekatester -s results.json
       wekatester --version

Basic performance test of a network/parallel filesystem (distributed fio).

Option names are case-insensitive (-C is -c, --AUTO is --auto); the values you
give them are not (-Cmyset names myset, never MYSET). A value may be attached
or separate: -w smoke, -wsmoke, -w=smoke and --auto=max all work, and
attaching is the way to pass a value that starts with a dash.

  -d directory   target directory on the workers for test files (default: /mnt/weka)
  -w workload    workload definition directory, a subdir of fio-jobfiles (default: default)
  -f fio_bin     fio binary on the workers (default: /usr/bin/fio)
  -o, --output dir        each run lands here as <date>-<time>.tgz: fio JSON
                          results, run log, staged jobfiles (default: results)
  -e, --engine eng        force this fio ioengine on every staged jobfile,
                          overriding the jobfiles and auto tuning
  -a, --auto [safe|max|cal|hybrid]
                          derive system-specific fio options from the workers
                          (default level when omitted: max)
                          cal: measure a per-client iodepth ladder before staging
                          hybrid: same ladder, seeded from a formula rung
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
                 needed and run
  -n             dry run: create/generate, print the files and the run details,
                 execute nothing
  -g             force regeneration of existing layout jobfiles
  -x, --duration secs     run every measured job for this many seconds
                          (time_based); layout and unlink keep their own timing
  -u, --unlink   remove the workload's data files from -d after the last job
                 that uses them (a failed run keeps them for the rerun)
  -s file        summarize an existing results .json -- or every job in a run
                 bundle .tgz, straight from the archive -- and exit
  -v             increase output verbosity (repeatable)
  --version      display version number and exit
  -h             show this help and exit
  --             everything after this is a server name

With no server given, the test runs on the local host -- no ssh required.
```

`server ...` — the worker hostnames; the first one is the coordinator/master. Optional: give no server at all and wekatester benchmarks the local host instead, using no ssh, no keys, and no sshd (**local mode**). That is the quickest way to sanity-check a single client — `./wekatester -a max` and nothing else.

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

**Layouts heal incrementally, from evidence.** Before the capacity check, every run sweeps each host's destination against the exact file grid its staged layout implies: files whose SIZE deviates from the grid are deleted, files that match are kept and **credited against the capacity requirement**, and the layout phase's plain `create_only` pass then writes only what is missing. A geometry change heals just its delta (bumping `nrfiles` 502→510 creates 8 files, not 22TiB), an interrupted layout is repaired file-by-file on the next run, and nothing is trusted that wasn't measured — there are no marker files. Size is a sufficient test on weka: laid-out files cannot be sparse there, so a size-complete file is a complete file. To force a from-scratch rebuild, remove the files (`-u` on a run, or `rm -rf` the grid).

# Customizing workloads (-C)
Jobfiles get edited in the field — `-C` makes that a guided flow instead of `cp -r` and hope:

```
./wekatester -C -i ubuntu:key.pem 10.30.0.1 10.30.0.2         # temp set from -w's workload
./wekatester -Cmyset host1 host2                              # named: ./fio-jobfiles/myset
./wekatester -C ./path/to/set -- host1 host2                  # explicit path; hosts after --
```

The flow: the workload set is copied (shipped sets are never edited in place — `-C default` customizes a fresh copy, not `fio-jobfiles/default` itself), the set's `hostlist.csv` opens in your editor (`$VISUAL`, then `$EDITOR`, then `vi`) — the host file is the primary customization surface: per-host login, engine, cpus, destination, and per-type geometry in one CSV — then a 5s prompt (default no) offers editing the jobfiles individually in run order, the layout job is generated, and you are offered a chance to edit it (5s prompt, default no). A set created without a name lands in `./fio-jobfiles/<date>-<time>/` and you choose whether to keep it for reuse (5s prompt, default keep); a set you chose not to keep is removed **only after a fully successful run** — any failure preserves your edits. Naming an existing *custom* set edits it as-is; adding an explicit `-w` on top of one asks (a real y/N, no timeout) before **replacing** its jobfiles with a fresh copy of that workload.

With no attached set name, the token after `-C` is assumed to be a client; if it turns out unreachable over ssh, wekatester asks (5s, default yes) whether it was actually the set name. Put hosts after `--` to make it unambiguous.

Unattended forms:

- `-r` — fast track: no prompts, no editors; whatever is needed (set copy, layout) is created and the run proceeds. Existing layout jobs are never touched (add `-g` to regenerate them). Temp sets are kept.
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
  own capability: `numjobs` = that host's usable cores, deeper iodepth,
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
- `-a hybrid` — the same ladder as `cal`, but seeded from a formula-derived
  rung instead of starting from scratch, so it confirms a good starting
  point rather than searching for one.

How calibration works: before staging, the set is inspected for what it
actually runs — bandwidth and/or iops ladders, read and/or write directions;
latency has no queue to ladder, so its FLOOR is measured instead (one QD1
rung per direction, reported and bundled, never cached). Each ladder steps
iodepth (cal: 1→128 bandwidth, 1→256 iops; hybrid starts mid-ladder), ~12s a
rung, on ALL clients at once — the values found are each client's ceiling
under contention, the condition the real jobs run in. The ladder hunts the
peak: a rung counts only if it beats the best seen so far by ≥2%, and only
two consecutive misses end the climb, so a single flat rung cannot hide a
later gain. After the qd ladder, a numjobs ladder tries half, double, and
(chasing a proven double) quadruple the per-core job count at the best
queue depth — a win records that host's job count, undersubscription
included. An nrfiles ladder (4, 8, 16, 32, 64 files per job at the same
working set, versus the baseline 2) then samples the file-count curve:
every delta is logged and bundled as evidence but never recorded, since
rewriting your file geometry from a probe would change what you asked to
test — a point that beats the baseline by ≥2% is named with the exact
host-file fields that would adopt it. The reported knee is the
shallowest queue depth within 95% of the peak. The scratch grid (`.wekatester-cal/` under each destination) is
seeded in full before any measured rung — creation is never measured — and
removed afterward. Knees flow
into the run's geometry one precedence slot below the operator (CLI > host
file > calibration > tuner) and persist to `hostlist.csv` via the `-a`
writeback — which is also the cache: a host whose qd columns are already
filled skips those ladders (`-g` re-measures). `-n` names the ladders a run
would perform without executing them.

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
host,user_login,ioengine,allowed_cpus,destination_folder,bandwidth:nj/fs/nr/qd,latency:nj/fs/nr/qd,iops:nj/fs/nr/qd
client-1,ubuntu,io_uring,"8,10,12,14",/mnt/weka,12/10G//8,1///1,12/1G/56/64
,,io_uring,,,,,
```

A line naming a host assigns to that host (two lines naming the same host is an error, both line numbers named). Host-less lines are **selector** lines: their login and/or ioengine choose the hosts they apply to — a login selects hosts using that login, an ioengine selects hosts that **passed that engine's functional test** — and their remaining fields fold into any host whose more-specific settings left them unset. A host line beats two selectors beats one beats a global `,,...` line; a generic line never overrides a more specific one regardless of file order; equally specific conflicts keep the *first* line and print a warning. A host-less line's login is only ever a selector — logins are assigned by host lines, the CLI, or your ssh defaults. Empty fields mean "default"; geometry sub-fields may be omitted (`12/10G//8` sets numjobs, filesize and iodepth). Quote cpu lists (`"22,24"`), and `#` starts a comment.

Without `-t` no host file is used — with one exception: a `-C` set's own `hostlist.csv` is always honored, because it is the set's customization surface. Bare `-t` looks in the job set folders first — an existing `-C` set's own `hostlist.csv`, then the `-w` set's — falling back to `./hostlist.csv`; when both a set-folder copy and `./hostlist.csv` exist, the set folder wins and is the copy later writebacks (`-a`) update. With `-C` and no file anywhere, the file is created in the custom set (where the editor opens it), never as a stray `./hostlist.csv`. A named path that doesn't exist asks (no timeout) whether to create the self-describing template or quit — under `-r` the same question gets 5 seconds and defaults to create. `-C` sets own a copy (taken from the file in use or the source set, template otherwise), which opens first in the editor flow and serves later runs of that set. Precedence overall: **CLI flags > host file > jobfiles/tuner**.

Every ioengine the file (or `-e`) names is **proven with a real one-file job on that host's destination** before use — `--enghelp` lists what fio was built with, not what the kernel and filesystem will run — and in auto mode the tuner's common engine comes from the proven set. A requested `allowed_cpus` outside the host's current `taskset -cp` mask, or overlapping weka's pinned cores, is an error showing all three (request, mask, weka cores) unless a passwordless escalator works — probed per host as dzdo, pbrun, sesu, pmrun, doas, ksu, then sudo last (sites that install an enterprise escalator usually mandate it), each tested non-interactively with a 5s timeout. Escalation is as-needed: a self-affinable mask (pure-isolated cpus, or inside the current taskset) runs fio as the login user even when an escalator exists. When escalation is needed it covers the `taskset` only — fio itself drops back to the login user via `runuser` where policy allows (keeping test files user-owned), falls back to a root fio with a NOTE otherwise, and is torn down with the same privilege (overlap with weka's cores then warns instead — your explicit choice). weka CLI queries, when a future feature issues any, try the login user first and get one escalated retry on failure. Each host may also point at its own `destination_folder`: the mount guard, write probe, layout grid sweep, and staged variants all follow it (auto mode's capacity estimate still measures the master's filesystem — approximate when destinations differ).

With `-a`, the derived values (established login, proven engine, cpus, directory, per-type geometry) are recorded back into the host file for re-use — filling only what the file didn't provide; add `-g` to be asked (no timeout) whether to overwrite instead. Updates never edit lines in place: the old host line is commented out and the new one appended, preserving history.

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
- `fio-jobfiles/<host>/` — the staged per-host jobfile variants that actually ran (with auto mode these differ per host, and a `-C` temp set may be gone later — this is the execution truth).

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
- If `-d` is a wekafs mount it must be mounted with `forcedirect`; wekatester refuses to run otherwise. fio's `direct=1` alone does not keep the wekafs client cache fully out of the IO path.
- The target directory must be writable by the login user on every worker — fio creates its data files there. wekatester probes this before running (one dotfile, created and removed) because fio's client mode reports a worker-side permission failure so quietly that the run would otherwise "succeed" with zero IO. A root-owned mount root is the usual cause; a one-time `chmod` of the root on any host persists in the shared filesystem.
- `fio --client` exits 0 even when jobs fail on the workers, so wekatester reads success out of the results themselves: a job whose stats carry an error, or a measured job that moved zero bytes, aborts the run and names the host — it will not print a summary of zeros.
