# wekatester
Performance test weka clusters (or any network/parallel filesystem) with distributed fio.

wekatester is a single bash script with an embedded python3 result summarizer. There is nothing to install: it needs only bash, an OpenSSH client, and python3 (stdlib only) on the machine you run it from, plus fio on the workers. The workers are Linux hosts reachable by ssh.

# Basics
fio is a benchmark for IO, and is quite popular. However, running it in a distributed fashion across multiple servers can be a bit of a bear to manage, and the output can be quite difficult to read.

The idea of wekatester is to bring some order to this chaos. It starts fio on your workers, runs a standard set of benchmark workloads across all of them at once, and summarizes the results in a few human-readable lines per job.

# How it works
wekatester uses fio's native client/server mode:

- An `fio --server` daemon is started on every worker (daemonized with a pidfile in `/dev/shm`; on exit it is killed via that pidfile only — never by name, so fio jobs that are not ours are untouched).
- The **first host on the command line acts as the coordinator**: jobfiles are staged only to that host, and the fio client process runs there, driving all the workers. Aggregation across workers is done by fio itself (the "All clients" totals).
- ssh and scp are the system binaries, so agent forwarding, `~/.ssh/config`, `ProxyJump`, and ssh certificates work exactly as they do for interactive ssh. Connections run in `BatchMode` — wekatester never prompts; if ssh would have prompted, the run fails fast instead. `ControlMaster` multiplexing means one authentication per host for the entire run.
- All transient staging lives in tmpfs (`/dev/shm` locally when available, and `/dev/shm` on the remote side). The only files written to disk are the results files in the current directory.

# Usage
```
usage: wekatester [-d directory] [-w workload] [-f fio_bin] [-a] [--ignore-capacity] [-v] [-V] [-h] server [server ...]
       wekatester -s results.json [-r "bandwidth latency iops"]

Basic performance test of a network/parallel filesystem (distributed fio).

  -d directory   target directory on the workers for test files (default: /mnt/weka)
  -w workload    workload definition directory, a subdir of fio-jobfiles (default: default)
  -f fio_bin     fio binary on the workers (default: /usr/bin/fio)
  -a, --auto [safe|max]   derive system-specific fio options from the workers
                          (default level when omitted: max)
  --ignore-capacity       run even if the workload needs more space than -d has (auto mode)
  -s file        summarize an existing fio JSON results file and exit
  -r items       report items for -s: any of "bandwidth latency iops" (default: all)
  -v             increase output verbosity (repeatable)
  -V             display version number and exit
  -h             show this help and exit
```

`server ...` — one or more worker hostnames. The first one is the coordinator/master.

`-d directory` — where the benchmark files are created on the workers, typically your mounted filesystem. Defaults to `/mnt/weka`. This overrides the `directory=` line in every jobfile at staging time.

`-w workload` — pick a workload set, a subdirectory of `fio-jobfiles`. See below.

`-f fio_bin` — path to fio on the workers, if it isn't `/usr/bin/fio`.

`-s results.json` — offline mode: re-summarize an existing results file and exit, no hosts involved. `-r "bandwidth latency iops"` (any subset) selects which metrics to report; default is all.

`-v` — more verbosity; repeatable (`-vv`).

# Workloads
A workload is a directory of standard fio jobfiles under `fio-jobfiles/`, run in sorted filename order. Shipped sets:

- `default` — the classic 4-corners tests (read/write bandwidth, latency, iops)
- `mixed` — 70/30 read/write workloads
- `2x400Gb` — a heavier bandwidth-oriented variant
- `wekawithin` — 1M/128k/4k reads, writes, and mixed IO

Add your own directory under `fio-jobfiles/` and select it with `-w`. A few conventions:

- Jobfile names must start with a digit (`011-bandwidthR.job`, ...) — that numeric prefix is both how files are discovered and what sets the run order.
- A comment line of the form `# report bandwidth` (or `latency`, `iops`, or several) at the top of a jobfile selects which metrics appear in the summary for that job. No directive means report everything.
- The `directory=` line is overridden by `-d` when the jobfiles are staged (and inserted if missing), so the shipped jobfiles work against any mount point.
- The measured workload should be the **last** job in the jobfile — the shipped files use an initial `create_only` job to lay out the files, then `stonewall` into the real workload, and the summary describes that last job.

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
comments. Auto also warns when workers differ (core counts, weka cores) and
when the backend RAM query fails.

Auto sizes the workload's file footprint, so it also knows whether the test
can fit. If the derived workload needs more space than `-d` has available,
the run **fails during staging**, before any fio job starts, naming both
numbers — continuing would only march fio into `ENOSPC` partway through and
throw away the run. Pass `--ignore-capacity` to downgrade that to a warning
and run anyway (useful when `df` under-reports, e.g. a filesystem that is
thin-provisioned or still rebalancing). Capacity is only known in auto mode;
if the `df` probe returns nothing usable, no check is made.

# SSH configuration
Because wekatester uses the real ssh client, anything you can express in `~/.ssh/config` just works. Two field-typical examples are included:

- `aws_ssh_config.example` — `ec2-user` with a support key, host key checking off
- `on-prem_ssh_config.example` — default key, host key checking off

Remember that `BatchMode` means keys must be usable without a passphrase prompt (use an agent), and unknown host keys will fail the run unless your config handles them.

# Output
Each job prints a summary block as it completes, and the raw fio JSON is kept — one file per job, named `results_<timestamp>_<jobname>.json` in the current directory, so a crashed suite keeps everything already measured.

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

Any results file can be re-summarized later with `-s`, optionally narrowing the metrics with `-r`:

```
./wekatester -s results_2026-07-30_1112_011-bandwidthR.json -r "bandwidth latency"
```

# Caveats
- fio's client/server protocol is version-sensitive. Keep fio versions consistent across the workers and the coordinator host, or connections may fail in confusing ways.
- TCP port 8765 (fio's server port) must be open from the coordinator to every worker — ssh working does not imply this; host firewalls commonly allow only port 22. wekatester verifies reachability before running and names any blocked hosts, and it refuses to summarize results that are missing hosts (fio itself would silently benchmark the survivors).
- A run needs at least one host; the per-host min/max spread in the summary only appears with 2 or more workers.
- If `-d` is a wekafs mount it must be mounted with `forcedirect`; wekatester refuses to run otherwise. fio's `direct=1` alone does not keep the wekafs client cache fully out of the IO path.
