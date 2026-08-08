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
- All transient staging lives in tmpfs (`/dev/shm` locally when available, and `/dev/shm` on the remote side). The only files written to disk are the results files in the output directory (`./results` by default, `-o` to choose another).
- With no servers at all, wekatester runs the whole thing on the local host over loopback — no sshd required. Every phase and guard above still runs, unchanged; only the transport is swapped for direct execution, so the results are shaped exactly like a remote run's.

# Usage
```
usage: wekatester [-d directory] [-w workload] [-f fio_bin] [-o output_dir]
                  [-a [safe|max]] [--ignore-capacity] [-l login] [-i keyfile]
                  [-C[set]] [-r] [-n] [-g] [-v] [-h] [--] [server ...]
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
  -o, --output dir        local directory for the fio JSON result files
                          (default: results; created if missing)
  -a, --auto [safe|max]   derive system-specific fio options from the workers
                          (default level when omitted: max)
  --ignore-capacity       run even if the workload needs more space than -d has (auto mode)
  -l, --login user        ssh login user for the workers (remote runs only)
  -i, --identity keyfile  ssh private key for the workers (remote runs only);
                          keeps the agent's other keys from being offered
  -C[set], --customize[=set]
                          copy a workload set, edit each jobfile, then run it;
                          needs a terminal unless -r or -n is given. With no
                          attached value the set may be the next bare token
  -r             fast track: no prompts and no editors -- create whatever is
                 needed and run
  -n             dry run: create/generate, print the files and the run details,
                 execute nothing
  -g             force regeneration of existing layout jobfiles
  -s file        summarize an existing fio JSON results file and exit
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

`-o output_dir` — where the raw fio JSON result files land on the machine running wekatester. Defaults to `./results`, created on first use.

`-s results.json` — offline mode: re-summarize an existing results file and exit, no hosts involved. The full summary (all metric groups) is always printed.

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

# Customizing workloads (-C)
Jobfiles get edited in the field — `-C` makes that a guided flow instead of `cp -r` and hope:

```
./wekatester -C -l ubuntu -i key.pem 10.30.0.1 10.30.0.2      # temp set from -w's workload
./wekatester -Cmyset host1 host2                              # named: ./fio-jobfiles/myset
./wekatester -C ./path/to/set -- host1 host2                  # explicit path; hosts after --
```

The flow: the workload set is copied (shipped sets are never edited in place — `-C default` customizes a fresh copy, not `fio-jobfiles/default` itself), each jobfile opens in your editor (`$VISUAL`, then `$EDITOR`, then `vi`) in run order, the layout job is generated, and you are offered a chance to edit it (5s prompt, default no). A set created without a name lands in `./fio-jobfiles/<date>-<time>/` and you choose whether to keep it for reuse (5s prompt, default keep); a set you chose not to keep is removed **only after a fully successful run** — any failure preserves your edits. Naming an existing *custom* set edits it as-is; adding an explicit `-w` on top of one asks (a real y/N, no timeout) before **replacing** its jobfiles with a fresh copy of that workload.

With no attached set name, the token after `-C` is assumed to be a client; if it turns out unreachable over ssh, wekatester asks (5s, default yes) whether it was actually the set name. Put hosts after `--` to make it unambiguous.

Unattended forms:

- `-r` — fast track: no prompts, no editors; whatever is needed (set copy, layout) is created and the run proceeds. Existing layout jobs are never touched (add `-g` to regenerate them). Temp sets are kept.
- `-n` — dry run: everything is resolved, generated and staged, then the full paths of the created files, every staged jobfile's contents, and the would-be run details are printed — and nothing executes. Combine with `-C` to prepare a set for manual editing.
- `-g` — force regeneration of existing layout jobs (works with `-r` and `-n` too).

A generated layout job carries a `# wekatester-layout: generated sha256=...` marker. If you edit the file the hash no longer matches, and wekatester treats it as yours: auto mode stages it exactly as written (with a warning that it may not cover auto-tuned namespaces) instead of re-deriving it. A pristine layout job under `-a max` is re-derived per host so it lays out the tuned namespaces (including the small-file working set).

`-C` needs a terminal for its editors and prompts; without one it refuses to run unless `-r` or `-n` is given. Prompts read the terminal directly, so they work fine under `... | tee run.log`.

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

When the workers want a different login or a specific key and editing `~/.ssh/config` isn't practical — you're root on the coordinator driving `ubuntu@` client nodes, say — use `-l login` and `-i keyfile`. They become `-o User=` and `-o IdentityFile=` internally, so ssh and scp both honour them. `-i` also sets `IdentitiesOnly=yes`, which keeps the ssh agent's other keys from being offered — those attempts count against sshd's `MaxAuthTries` and can exhaust it before the key you named is reached. It bounds the agent, not your config: `IdentityFile` entries in `~/.ssh/config` still apply. A key path that is missing, unreadable, or not a regular file (`-i ~/.ssh` instead of `-i ~/.ssh/id_ed25519`) is reported before the first connection, and neither option may contain whitespace (`SSH_OPTS` is a whitespace-split option list). In local mode both are accepted and ignored — there is no ssh to configure.

# Output
Each job prints a summary block as it completes, and the raw fio JSON is kept — one file per job, named `results_<timestamp>_<jobname>.json` in the output directory (`./results` by default, `-o` to choose another), so a crashed suite keeps everything already measured.

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

Any results file can be re-summarized later with `-s`:

```
./wekatester -s results/results_2026-07-30_1112_011-bandwidthR.json
```

# Caveats
- fio's client/server protocol is version-sensitive. Keep fio versions consistent across the workers and the coordinator host, or connections may fail in confusing ways.
- TCP port 8765 (fio's server port) must be open from the coordinator to every worker — ssh working does not imply this; host firewalls commonly allow only port 22. wekatester verifies reachability before running and names any blocked hosts, and it refuses to summarize results that are missing hosts (fio itself would silently benchmark the survivors).
- The per-host min/max spread in the summary only appears with 2 or more workers. A run with no host at all is local mode, not an error.
- Local mode still needs fio on the local host, `/dev/shm`, and fio's port 8765 reachable on loopback — the same phases run, they just run against this machine. It is Linux-only (the mount guard uses `findmnt`, staging uses `/dev/shm`) and refuses to start elsewhere; driving remote workers *from* a non-Linux machine is unaffected.
- If `-d` is a wekafs mount it must be mounted with `forcedirect`; wekatester refuses to run otherwise. fio's `direct=1` alone does not keep the wekafs client cache fully out of the IO path.
- The target directory must be writable by the login user on every worker — fio creates its data files there. wekatester probes this before running (one dotfile, created and removed) because fio's client mode reports a worker-side permission failure so quietly that the run would otherwise "succeed" with zero IO. A root-owned mount root is the usual cause; a one-time `chmod` of the root on any host persists in the shared filesystem.
- `fio --client` exits 0 even when jobs fail on the workers, so wekatester reads success out of the results themselves: a job whose stats carry an error, or a measured job that moved zero bytes, aborts the run and names the host — it will not print a summary of zeros.
