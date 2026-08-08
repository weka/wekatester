# wekatester auto mode (-a / --auto) and local mode — design

2026-07-31 · branch `shell-rewrite`
2026-08-07 · amended: case-insensitive CLI, `--` client separator, `-C`
customize workflow, generated layout jobs, `-r` fast-track / `-n` dry-run /
`-g` regen; `-r <items>` report filter removed (`-s` always prints the full
summary). See "Layout phase" and "Customize workflow (-C)".

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
- New: `-l login` / `--login[=]login` and `-i keyfile` / `--identity[=]keyfile`,
  for workers that want a login or a key that `~/.ssh/config` cannot supply
  (root on the coordinator driving `ubuntu@` clients). They are translated,
  not passed through: `-l` becomes `-o User=<login>` and `-i` becomes
  `-o IdentityFile=<path> -o IdentitiesOnly=yes`. The `-o` spelling is the
  point — it is accepted by **both** ssh and scp (scp's own `-l` is a bandwidth
  limit), so appending to `SSH_OPTS` reaches both transport wrappers with no
  call-site change. `IdentitiesOnly=yes` is deliberate: once a key is named
  explicitly, a running agent must not also offer its whole keyring, because
  those attempts count against sshd's `MaxAuthTries` and can exhaust it before
  the right key is tried. It bounds the agent only — `IdentityFile` entries
  from `ssh_config` remain eligible.
- `parse_args` only records the two values (`SSH_LOGIN`, `SSH_IDENTITY`);
  `apply_ssh_auth_opts`, called from `main` after `resolve_local_mode` and
  before any host contact, validates them and appends to `SSH_OPTS`. Guards
  there: a `-i` path that is not a readable regular file dies naming the path
  (left to ssh it looks like a cluster-wide auth failure rather than a typo,
  and `-f` as well as `-r` because a directory passes `-r` and `-i ~/.ssh` is
  the likeliest mistype), and neither value may contain whitespace, since
  `SSH_OPTS` is expanded unquoted by design. In local mode both are accepted
  no-ops — there is no ssh to configure. Empty `=`-forms (`--login=`) are a
  usage error: `need_arg` cannot see them, and ignoring them silently would
  make the most deliberate-looking spelling do nothing.
- The `server ...` positional is now optional (`[server ...]` in the synopsis):
  with none given the run happens on the local host — see Local mode.
- All existing options and behavior without `-a` are unchanged, except that
  staging always assembles per-client jobfiles (see Flow).

## Local mode

### Trigger

In the run path only (`-s`, `-V` and `-h` are untouched): `main` calls
`resolve_local_mode`, which fires when the host list is empty and sets
`LOCAL_MODE=1`, `HOSTS=(localhost)`, `MASTER=localhost`, then logs the fact.
The old `die "you must specify at least one server"` is gone — a bare
invocation is now a valid single-host run, not a usage error. The trigger lives
in its own function so the decision is testable without running `main`.

### Design: swap the transport, keep the architecture

fio still runs in **client/server mode, over loopback**: `fio --server
--daemonize` locally, the coordinator as `fio --client=localhost` locally,
jobfiles staged with `cp`. Every phase — preflight, mount guard, daemon
lifecycle, port check, probe, tuner, staging, run, summarize, cleanup — runs
logically unchanged. Only two functions know whether a host is remote:

- `run_host <host> <command>` — `bash -c` locally, `ssh -n $SSH_OPTS` remotely.
- `copy_to_master <src>... <dst-dir>` — `cp -R` locally, `scp -q -r` remotely
  (the destination is the last argument in both, so call sites are identical).

Eleven of the twelve previous transport call sites go through them: ten `ssh`
invocations plus the one `scp`. The twelfth, cleanup's `ssh -O exit`, is a
ControlMaster socket operation with no local equivalent and is left alone — its
loop no-ops in local mode because no sockets were ever created.

Backgrounded sites (`run_host ... &`) keep working — it is a plain function, so
`$!`, `wait`, and the collect-all failure policy are unaffected. Both branches
take stdin from `/dev/null` (`ssh -n`, and an explicit redirect locally): a
foreground call would otherwise inherit and consume the script's own stdin, as
would a backgrounded one whenever job control is in effect.

Rationale for **not** adding a separate no-server fio path (`fio <jobfile>`
directly): the results JSON would change shape (`jobs[]` instead of
`client_stats[]`), which would fork the summarizer, the expected-host guard,
and the create-phase "last entry wins" rule — the three places that are
hardest to test without a cluster. Loopback client/server keeps one code path
and one JSON contract, and the port check stays meaningful (fio's listener must
actually be reachable, even on loopback).

Consequences worth stating:

- **Local mode is Linux-only** and says so up front. The mount guard shells out
  to `findmnt` and staging plus the fio pidfile live in `/dev/shm`, so
  `resolve_local_mode` refuses to run on a non-Linux kernel rather than letting
  the fault surface two phases later as an opaque findmnt failure. The check
  sits *inside* the no-hosts branch: driving remote workers from a macOS laptop
  stays supported, because that plumbing is on the workers.
- **Command strings must be POSIX sh, or wrap themselves in `bash -c`.** The
  local branch runs them under bash, the remote branch under the worker's login
  shell, which need not be bash. `verify_fio_ports` is the exemplar — it needs
  `/dev/tcp`, so it carries its own `bash -c`.
- **ControlMaster** options are not appended to `SSH_OPTS` in local mode — no
  ssh runs, so there is nothing to multiplex. `WORK_DIR` is still created and
  used (probe files, staged variants), and cleanup's socket-close loop already
  no-ops on the empty socket directory.
- **preflight's `rc == 255`** special case ("ssh failed") is gated on remote
  mode. A local command that happens to exit 255 is reported as what it is in
  this mode — `fio not found`.
- **The port-check failure hint** is mode-dependent. Between two machines a
  host firewall is the overwhelmingly likely cause; on loopback it never is, so
  local mode points at the actual suspect instead — the name resolving to `::1`
  while fio's listener is on IPv4. Grep for `loopback resolution? fio binds
  IPv4` to find it.
- **The port check and fio can disagree about loopback**, and the failure that
  results does not look like a port problem. Bash's `/dev/tcp` walks every
  address `getaddrinfo` returns, so the probe falls through a refused `::1` to
  `127.0.0.1` and reports success, while fio's client resolves once and may sit
  on the address that fails — surfacing as the generic
  `fio run failed for <job>` from `run_jobs`, with a clean port check just above
  it in the log. If that combination appears, suspect loopback resolution before
  anything else and check that `localhost` resolves to `127.0.0.1` first.

### No-sshd guarantee

Local mode invokes neither `ssh` nor `scp`, so it works with sshd stopped, no
keys, and no `~/.ssh/config`. The test suite enforces this rather than
asserting it: `no_ssh_fixture` puts `ssh` and `scp` stubs that exit 99 ahead of
the real binaries on `PATH`, and the local-mode tests — including the full
`stage_jobfiles` path — run under them.

### Expected-hostname assumption

The summarizer's missing-host guard is passed `"${HOSTS[*]}"` unchanged, i.e.
`localhost`. This relies on fio keying each `client_stats` entry by the name
given to `--client=`, not by the worker's own hostname — lab evidence from a
multi-host run, where `per_host` was keyed by `backend-N` while `hostname` on
those machines returned the long FQDN form. Deliberately **not** special-cased:
if the assumption were wrong, a special case would hide it in local mode while
leaving the multi-host guard broken. The lab gate below re-verifies it.

### Test plumbing

`TARGET_DIR` is now `${WEKATESTER_TARGET_DIR:-/dev/shm/fio-jobfiles}`. The only
reason is testability: the suite points it at a tmp dir so the real
`stage_jobfiles` — master-side `rm -rf`/`mkdir` plus the jobfile copy, both
through the wrappers — can run with no worker and no `/dev/shm`. It is not a
documented option.

The remote-transport stubs bracket each argument (`SSH[-n][-o][…]`) rather than
echoing `"$*"`. Argv boundaries are the point of those tests: `"$*"` renders a
correctly quoted expansion and a word-splitting one identically, so it cannot
tell `"${@:1:$#-1}"` from `"${*:1:$#-1}"` — verified, both printed the same
line — and the regression the tests exist to catch would pass unnoticed.

The override **must** stay namespaced. This path is what cleanup passes to
`rm -rf` on the master and on every worker, so honouring a bare `$TARGET_DIR` —
a variable common enough in build and CI environments to be exported by
accident — would let unrelated tooling silently redirect those deletions at an
arbitrary path. A test asserts that a bare `TARGET_DIR` in the environment is
ignored.

### Lab validation

- Zero-argument smoke run on a backend: `./wekatester -w smoke` — confirm no
  ssh process appears (`ssh` can even be moved aside), the port check passes on
  loopback, results parse, and `$TARGET_DIR` is removed on exit.
- `./wekatester -a max` on a backend — confirm the probe reads that host's own
  cores/weka pinning and the staged variant under
  `$TARGET_DIR/localhost/` matches.
- Confirm fio's `client_stats[].hostname` is literally `localhost` (the
  expected-host guard above), and that a single-client run still needs no
  `All clients` aggregate.
- Confirm it works with `systemctl stop sshd`.

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

Warnings (once each, printed as a one-line `host=value` list — not a table):
system core counts differ across hosts; weka core counts differ across hosts.

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
`numjobs`/`iodepth` NEVER touched; `filesize=1G`;
`nrfiles=min(8, max(2, ceil(ws / 1 GiB)))`; `file_service_type=random`.
Note the effective job count in that formula is 1, not the host's cores: a
latency job runs QD1 with an untuned `numjobs` (typically 1), so that single
job has to traverse the whole per-host working set by itself to defeat cache.
Dividing `ws` by cores the job never uses would size the files from
concurrency that does not exist. See Working-set sizing.

Small-file namespace: at max tier, iops and latency files share one
`filename_format` (exactly `wt-small.$jobnum.$filenum`), so latency reuses the
iops files; create sections are idempotent, whichever runs first lays out
what it needs. Bandwidth files keep their original (large) namespace. A jobfile
that sizes with `size=` has it rewritten to `nrfiles × 1G` at the same time:
fio divides `size` across `nrfiles`, so a `size=` left over from the large-file
layout would shrink the 1G files straight back down. `size=` is never inserted
where the jobfile had none — that would cap a job that had no cap.

Every staged variant gets header comments recording tier, derived values, and
the probe facts used — the support artifact for "what did auto actually run?"

Override semantics (same as the old Python `override()`): replace the option
wherever it appears in any section; insert into `[global]` when absent, and
create `[global]` at the top of the file when the jobfile has none — a jobfile
with sections but no `[global]` would otherwise lose the option silently, and
for `directory=` that means fio writing its files into the fio server's cwd.
(The non-auto awk staging path does the same.) Create-phase sections inherit
the tuned global `numjobs`, keeping file coverage consistent.

## Working-set sizing (max tier)

Rationale: for random-IO tests, file size is a cache-defeat parameter, not an
accuracy parameter. The small-file working set must exceed the backends'
DRAM read cache or iops/latency numbers measure RAM.

- cache ceiling `C` = Σ backend container RAM (conservative: true data cache
  is a fraction of this)
- per-host working set `ws = max(8 GiB, 2 × C / n_workers)`
- `nrfiles(iops) = max(2, ceil(ws / (numjobs × 1 GiB)))` — an iops job spreads
  its IO over `numjobs` jobs, so each job only needs `ws / numjobs`
- `nrfiles(latency) = min(8, max(2, ceil(ws / 1 GiB)))` — effective job count 1
  (see Tuner): one QD1 job must cover `ws` alone. The cap keeps file-open and
  layout cost bounded.

Constants (documented in the script, single place):
`SMALL_FILESIZE=1G`, `CACHE_MULT=2`, `WS_FLOOR=8G`,
`IOPS_OUTSTANDING=64×cores`, `IODEPTH_CAP=128`, `LAT_NRFILES_CAP=8`.

## Mount-mode guard (all runs, auto or not)

After preflight, sequentially per worker: `findmnt -T <directory> -n -o
FSTYPE,OPTIONS` (resolves the containing mount even for subdirectories).
Sequential is deliberate — preflight has already opened each host's
ControlMaster, so a check costs about one round trip (~30ms) and a parallel
fan-out would only add bookkeeping.
If FSTYPE is `wekafs` and the options lack `forcedirect`: collect-all across
hosts, then die, naming each offending host and its actual mode (e.g.
`writecache`). Rationale: fio's `direct=1` requests O_DIRECT per file, but
only the `forcedirect` mount mode guarantees the wekafs client stays out of
the IO path entirely — without it, client-side caching can flatter results.
Non-wekafs targets skip the guard (the tool supports generic filesystems;
`direct=1` remains the only control there).

**Write probe (same pass).** After a host's mount mode passes (or is skipped
as non-wekafs), create and remove one dotfile under `-d` as the login user.
Lab-falsified assumption this replaces: "a worker where fio cannot create
files fails naturally" — it does not. fio's client mode reports worker-side
EACCES so quietly that a run against a root-owned mount root "succeeds" in
seconds with zero IO (observed on the rebuilt shrw lab, 2026-08-08). The
probe turns that into a one-second preflight failure whose message carries
the fix (`chmod` the mount root once — shared filesystem, persists — or run
as a user that can write), and it fires before `-C` opens any editor, so no
editing time is invested in a run that cannot work.

**Run failure detection (run_jobs).** `fio --client` exits 0 even when every
job on every worker failed, so each results file is checked after its run:
any per-job `error` field nonzero → die naming host, job, and errno; for
measured jobs additionally the last entry per host (the measured section,
same rule the summarizer uses) must have moved nonzero bytes+ios. Layout
jobs skip the zero-IO signal (create_only stats are legitimately zero); a
layout failure that reports neither signal is still caught when the first
measured job trips its own zero-IO check. Any such death is a failed run:
temp `-C` sets are preserved.

## Capacity check

`required = Σ over hosts of [ Σ over namespaces of max over that namespace's jobfiles(footprint) ]`

- A namespace is the staged jobfile's `filename_format`. Files are shared within
  a namespace, so each namespace contributes only its largest jobfile's
  footprint; distinct namespaces (e.g. bandwidth vs small-file) coexist and sum.
- A jobfile that sets **no** `filename_format` gets a namespace of its own: fio
  expands the default format's `$jobname` per section, so two such jobfiles own
  different files and must sum. (Treating the absent format as one shared
  literal key collapsed them onto a single max and under-counted.)
- `footprint = numjobs × filesize × nrfiles`, or `numjobs × size` when the
  jobfile sizes with `size=` and no `filesize=` — fio's `size=` is the per-job
  total *across* that job's files, so `nrfiles` must not multiply it again.
  With neither, or with a `size=` that is not a byte count (`size=50%`, warned
  once), the jobfile contributes 0.
- The estimate deliberately rounds up: over-counting is recoverable with
  `--ignore-capacity`, under-counting silently defeats the guard.

Python parses fio size suffixes.

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

## CLI amendments (2026-08-07)

- **Case-insensitive options.** Every option letter and long-option *name*
  matches case-insensitively (`-C`≡`-c`, `--AUTO`≡`--auto`); attached values
  and option arguments keep their case (`-Cmyset` names `myset`, not `MYSET`).
  Implementation: normalize the option token, never its value, before the
  `case`. Consequence: `-v`/`-V` merge — both mean verbosity; `--version`
  becomes long-only.
- **`-r <items>` removed.** `-s` always prints the full summary (all metric
  groups). Frees `-r`.
- **`-r`** — fast-track: create/copy/generate whatever is needed with zero
  prompts and zero editors, then run.
- **`-n`** — dry run: create/generate as needed without prompting; print the
  full paths of created files, every jobfile's contents, and the would-be run
  details (staged variants, derived tuning, capacity math); execute nothing.
  `-n` performs preflight, the mount guard, and (with `-a`) the probe — host
  contact needed for accurate details — but never starts fio servers and
  never runs a job. (The mount guard includes the write probe: it creates and
  removes one dotfile under `-d`, the only write `-n` performs, because a
  dry run that cannot predict "every job will EACCES" is not a dry run.)
- **`-g`** — force regeneration of existing layout jobfiles (see Layout
  phase for the full flag matrix).
- **`-o`/`--output <dir>`** — local directory for the fio JSON result files.
  Default `./results`, created (mkdir -p) just before the run phase — after
  the `-n` exit, so a dry run predicts the location without creating it —
  and checked writable before any daemon starts.
- **Attached and detached values (all value-taking options).** `-w smoke`,
  `-wsmoke` and `-w=smoke` are equivalent (one leading `=` is stripped from
  an attached value); same for -d/-f/-s/-o/-l/-i/-c and `-asafe`/`-amax`.
  Detached values that look like options are refused (`-f -g` was quietly
  making `-g` the fio binary); the attached form is the escape hatch for a
  value that genuinely starts with a dash. An attached value that is empty
  after stripping (`-w=`) dies rather than silently naming nothing.
- **`--`** — everything after it is the client list (standard separator).
- **`-c`/`-C[name]`** — customize workflow; see below. `-C` with `-s` is a
  usage error. `-C` with `-a` is allowed but prints a notice before editing
  begins naming the keys the tuner will override on non-latency files
  (numjobs, iodepth, ioengine, filesize, nrfiles, filename_format) so the
  operator cannot silently lose edits to auto tuning.

## Layout phase (all runs)

File layout becomes its own jobfile that always runs first. wekatester's run
loop executes jobfiles serially and the fio coordinator does not exit until
every client finishes, so jobfile boundaries are hard cross-client barriers:
a layout job as JOBFILES[0] guarantees all files exist on all machines before
any measured test starts, eliminating create-phase skew and mid-suite
re-layout (the numjobs-superset trap).

- **Generated, not hand-written.** A python heredoc `generate_layout
  <setdir>` reads the set's `[0-9]*` jobfiles (skipping layout-marker files),
  groups them by `filename_format` namespace (absent → per-file key, matching
  the capacity model), computes each namespace's superset geometry (max
  numjobs, max nrfiles, filesize; `size=`-only files via the capacity
  fallback), and emits `000-wekatester-layout.job`: a shared `[global]`
  (directory, create_serialize=0, ioengine from the set) plus one
  `create_only=1` section per namespace with that namespace's
  filename_format/filesize/nrfiles/numjobs and `blocksize=1Mi`.
- **Marker + pristine hash.** The generated file carries
  `# wekatester-layout: generated sha256=<hash of normalized body>`. A hash
  mismatch means the operator edited it.
- **Runtime behavior.** `stage_jobfiles` ensures a layout job exists as
  JOBFILES[0] on every run: the set's own layout file when present, else one
  generated transiently into `$WORK_DIR/gen/` (auto and non-auto paths both).
- **Tuner interplay.** Layout-marker files are exempt from tier rules
  (corrections only: directory, cpus_allowed). At `-a max` a *pristine*
  layout's staged variant is re-derived per host from that host's tuned
  geometry, so it covers the small-file namespace redirect; a *user-edited*
  layout is staged as authored, with a one-time warning that it may not cover
  tuned namespaces.
- **Capacity model** skips layout-marker files (their footprint duplicates
  the measured files' namespaces).
- **run_jobs** times layout jobs and logs `layout: ... in Xs` instead of
  summarizing them (their client_stats are create-phase zeros).
- **Shipped jobfiles** gain a one-line note that layout is normally handled
  by the generated job; their inline create sections remain for standalone
  fio use and are idempotent no-ops after the layout job runs.
- **Regeneration flag matrix** (interactive prompts are 5s single-key,
  see Customize workflow):
  - `-g` (alone or with `-r`/`-n`): always regenerate existing layout files.
  - `-r` without `-g`: existing layout files are never touched; a set lacking
    them gets layout generated silently.
  - Neither `-r` nor `-g`, existing set with layout files: 5s prompt
    skip-or-regenerate (timeout = skip), then the edit-layout prompt.
  - The edit-layout prompt timing out (or `-r`) never modifies layout files.

## Customize workflow (-C)

`-C` copies a workload set, opens each jobfile in the operator's editor,
generates layout, and optionally persists the set for reuse. It is the
tool's first interactive surface; all prompts read `/dev/tty` (never stdin,
which the transport deliberately /dev/nulls), via
`exec 3<>"${WEKATESTER_PROMPT_TTY:-/dev/tty}"` + `[ -t 3 ]`. `-C` without
`-r`/`-n` and without a terminal dies: "-C needs a terminal; use -r for
unattended runs".

**Argument forms.** Attached value (`-Cmyset`) = set name/path. Unattached
bare tokens are presumed clients; if the token immediately following `-C`
fails the ssh phase of preflight, prompt "treat '<token>' as the custom set
name?" (5s, timeout = yes → it moves out of HOSTS and becomes the set name);
under `-r`, no prompt — assume set name on ssh failure. When `--` is present,
a bare pre-`--` token following `-C` is the set name outright (clients are
enumerated after `--`); more than one such token is a usage error.

**Set resolution.**
1. No name: create `./fio-jobfiles/<YYYYMMDD-HHMMSS>/` (a "temp set") and
   copy from `-w`'s set (default workload when -w absent).
2. `/abs` or `./rel` path: exists → use it; missing → `mkdir -p` + copy.
   Writability is checked silently first; failure warns and exits 1.
3. Bare name: a name that matches a SHIPPED set (default, mixed, 2x400Gb,
   wekawithin, smoke) customizes a fresh `<date>-<time>` temp copy of it —
   shipped sets are the checked-in baseline and are never edited in place.
   Any other name found under `fio-jobfiles/` (SCRIPT_DIR then ./, same
   lookup as `-w`) is an existing custom set → used as-is; missing → create
   `./fio-jobfiles/<name>/` + copy. Unwritable `fio-jobfiles` warns and
   exits 1.
4. Existing custom set with an *explicit* `-w` (tracked as
   WORKLOAD_EXPLICIT): untimed y/N confirm before REPLACING its jobfiles
   with a fresh copy of `-w` (old jobfiles, including any stale layout job,
   are cleared first — a refresh is not an overlay). Under `-r` the recopy
   never happens (destruction requires interactive consent).
5. Shipped sets are always copied, never edited in place (rule 3 enforces
   this for the bare-name spelling too).

**Flow** (after `verify_mount_mode`, before `start_fio_servers` — hosts are
validated before the operator invests editing time; nothing is staged or
running while an editor sits open): copy/resolve → editor over each jobfile
in run order ($VISUAL → $EDITOR → vi, all three fds on the tty, nonzero exit
dies) → layout generation per the flag matrix → edit-layout prompt (5s,
default no) → temp sets only: keep-for-reuse prompt (enter/y/space/timeout =
keep; esc/n = auto-remove after a *fully successful* run; any failure or
partial results means the set is never removed) → run with the set as the
workload. `-r` skips every prompt and editor (keep = yes). `-n` skips
editors/prompts, prints paths + contents + run details, exits 0.

**Prompt primitive** (bash 3.2, verified by probe): `IFS= read -r -s -n 1
[-t secs] <&$PROMPT_IN_FD` with a per-character escape-sequence drain
(3.2 discards partial `-n N` input on timeout) classifying
enter/space/esc/escseq/char; `read -s` must use fd redirection, never `-u`
(which echoes); whole-second timeouts only. `confirm_timed <secs> <default>
<msg>`: enter/y/space = yes, esc/n = no, anything else or timeout = default;
the resolved answer is echoed to the tty and logged to stdout. The
destructive recopy uses an untimed strict confirm (only `y` = yes, EOF =
die). Ctrl-C at any prompt aborts via the existing INT trap (verified: read
does not swallow SIGINT and bash restores termios on the signal path). Test
seam: PROMPT_IN_FD/PROMPT_OUT_FD preset by tests run the prompts over plain
pipes; WEKATESTER_PROMPT_TTY=/dev/null pins the no-TTY die.

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
