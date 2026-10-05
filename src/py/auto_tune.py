import math, os, re, sys

# Validate the flag slot before unpacking: without this, an old-style call
# silently succeeds -- a positional shifts into the host list, drops a host
# from both the tuning loop and the capacity total, and exits 0. Wrong
# quietly is worse than not running.
if len(sys.argv) < 8 or sys.argv[5] not in ("0", "1"):
    sys.exit("ERROR: auto_tune: usage: <src> <work> <tier> <directory> "
             "<ignore_capacity 0|1> <targets-final|-> <host>...")

src, work, tier, directory = sys.argv[1:5]
# rules run on `tier`; the log wears the operator's own level (-a cal runs
# max's rules with measured knees layered on top -- printing "max" there
# read as the wrong mode being used)
label = os.environ.get("WEKATESTER_TIER_LABEL") or tier
# the unified namespace splits the STAGED jobs the same way it splits the
# calibration cells: read-only jobs run on the fleet-shared dataset, anything
# that writes runs on this host's own files
ns_unified = os.environ.get("WEKATESTER_NS", "").startswith("unified")
ignore_capacity = sys.argv[5] == "1"
# measured levels: iops jobs run with latency accounting off, as their cells did
iops_nolat = os.environ.get("WEKATESTER_IOPS_NOLAT") == "1"
targets_path = sys.argv[6]
hosts = sys.argv[7:]
FS_GROUP = load_fs_groups(work, hosts)

# Host-file resolution (targets.final): per-host overrides that beat the
# tuner -- CLI beats the file upstream, the file beats what is derived here.
TARGETS = {}
if targets_path != "-" and os.path.exists(targets_path):
    for _line in open(targets_path):
        _p = _line.rstrip("\n").split("\t")
        if len(_p) == len(FIELDS) + 1:
            TARGETS[_p[0]] = {k: v for k, v in zip(FIELDS, _p[1:]) if v != "-"}

def target(h, key):
    return TARGETS.get(h, {}).get(key, "")

SMALL_FILESIZE = "1G"
IOPS_NRFILES = 2   # per job: enough that no job pounds a single inode
LAT_NRFILES = 8    # the one QD1 latency job still walks a small spread
IODEPTH_CAP = 128; OUTSTANDING_PER_CORE = 64

def warn(msg): print(f"WARNING: {msg}", file=sys.stderr)

_warned = set()
def warn_once(msg):   # per-host loops would otherwise repeat the same warning
    if msg not in _warned:
        _warned.add(msg); warn(msg)

# --- probe facts ---
facts = {}
for h in hosts:
    ncpus, weka, engines, iso, nodes = 0, set(), [], set(), 0
    for line in open(os.path.join(work, "probe", h)):
        f = line.split()
        if not f: continue
        if f[0] == "ncpus": ncpus = int(f[1])
        elif f[0] == "wekanode" and len(f) > 1: nodes = int(f[1])
        elif f[0] == "isolated" and len(f) > 1:
            iso = parse_cpulist(f[1])
        elif f[0] == "weka_allowed":
            # weka pins each dedicated io thread to exactly one CPU (a
            # single-CPU task-level mask); utility threads have wide masks
            # and float across CPUs. Only single-CPU masks are dedicated
            # cores -- wide masks must be ignored or the union of every
            # thread's mask collapses to "all CPUs" and usable cores vanish.
            cpuset = parse_cpulist(f[1])
            if len(cpuset) == 1:
                weka |= cpuset
        elif f[0] == "engines": engines = f[1:]
    # probe_cores' rule, in physical cores: every core except weka's DPDK
    # cores (siblings included) and the OS reserve, minus whatever the probe
    # measured as unbindable. isolcpus deliberately does NOT narrow it (see
    # probe_cores). "usable" is every thread of those cores; "phys" one per
    # core, where a job count at or below N runs.
    universe = probe_universe(os.path.join(work, "probe", h), ncpus)
    unbind = probe_unbindable(os.path.join(work, "probe", h),
                              universe or set(range(ncpus)))
    cores = probe_cores(os.path.join(work, "probe", h))
    if cores["weka_core0"]:
        warn(f"{h}: weka has pinned a dedicated core on core 0 -- that core "
             f"and its sibling belong to the OS; fio stays off it regardless")
    usable = cores["all"]
    if nodes and not weka:
        # the pin detection is the only thing keeping fio off weka's cores;
        # if weka is running and none were found, say so rather than
        # silently handing fio the whole machine
        warn(f"{h}: {nodes} wekanode process(es) running but no pinned cores "
             f"detected -- fio will be allowed on every cpu, including "
             f"weka's; check that this weka pins its io threads")
    facts[h] = {"ncpus": ncpus, "weka": weka, "usable": usable,
                "engines": engines, "isolated": sorted(iso),
                "universe": universe, "unbindable": unbind, "cores": cores}

if len({f["ncpus"] for f in facts.values()}) > 1:
    warn("system core counts differ between hosts: "
         + ", ".join(f"{h}={facts[h]['ncpus']}" for h in hosts))
if len({len(f["weka"]) for f in facts.values()}) > 1:
    warn("weka core counts differ between hosts: "
         + ", ".join(f"{h}={len(facts[h]['weka'])}" for h in hosts))

common_engines = [e for e in ENGINE_ORDER
                  if all(e in f["engines"] for f in facts.values())]
_cores_for = {}
def cores_for(h):
    # the nj contract: the operator's cpu list is the base when the file
    # gives one -- minus cpus the host does not have (check_cpu_pinning noted
    # them; a staged cpus_allowed naming one is rejected by the fio SERVER,
    # whose error text is lost), weka's cores and core 0's pair --, and
    # probe_cores' own rule over every cpu otherwise, including for a list
    # that covers every cpu fio could use (a catch-all counts as no list)
    if h not in _cores_for:
        c = target(h, "cpus")
        if not c:
            if facts[h]["cores"]["n"] < 1:
                sys.exit(f"ERROR: {h}: no cpus left for fio -- "
                         f"{cores_summary(facts[h]['cores'])}; mount weka with "
                         f"fewer cores, use a larger client, or name the cpus "
                         f"in the host file, fewer than fio could use (a "
                         f"narrower list is the operator's own reserve)")
            _cores_for[h] = facts[h]["cores"]
        else:
            cc = probe_cores(os.path.join(work, "probe", h), c)
            if cc["n"] < 1 and cc["catchall"]:
                sys.exit(f"ERROR: {h}: the host file's cpu list ({c}) covers every "
                         f"cpu fio could use, which counts as no list, and the OS "
                         f"reserve then leaves fio no cpus -- {cores_summary(cc)}; "
                         f"mount weka with fewer cores, use a larger client, or "
                         f"list fewer cpus (a narrower list is the operator's own "
                         f"reserve)")
            if cc["n"] < 1:
                sys.exit(f"ERROR: {h}: the host file's cpu list ({c}) leaves "
                         f"fio no cpus -- every one is weka's, core 0's pair, "
                         f"or not on this host")
            _cores_for[h] = cc
    return _cores_for[h]

def usable_for(h):    # every thread fio may use: where 2N and 4N jobs run
    return cores_for(h)["all"]

def cpus_for(h, nj):
    # N/2 and N jobs run one per physical core with the siblings idle; more
    # than N spread over the siblings too -- the cpu set a calibration cell
    # with that job count was measured on
    c = cores_for(h)
    return c["phys"] if nj <= c["n"] else c["all"]

min_usable = min(len(usable_for(h)) for h in hosts)

for h in hosts:
    _iso, _use = set(facts[h]["isolated"]), set(usable_for(h))
    if _iso and (_use & _iso) and (_use - _iso):
        print(f"note: {h}: fio cpus {fmt_cpulist(sorted(_use))} span isolated "
              f"and housekeeping cpus; per-job split affinity keeps each job "
              f"on its own cpu", file=sys.stderr)

# --- jobfiles ---
def report_items(path):
    items = []
    for line in open(path):
        m = re.match(r"^#\s*report\s+(.*)", line)
        if m: items += m.group(1).split()
    return items or ["bandwidth", "latency", "iops"]

def override(lines, key, value):
    """Replace key= wherever it appears; else insert into [global].

    A jobfile with sections but no [global] gets one created at the top of the
    file: without it the option would be dropped silently, which for
    directory= means fio writes its files into the server's cwd rather than
    -d. fio treats the leading '# report' comment as a comment wherever it
    sits, so prepending is safe.
    """
    out, found = [], False
    for line in lines:
        if re.match(rf"^{key}=", line):
            out.append(f"{key}={value}"); found = True
        else:
            out.append(line)
    if found:
        return out
    if not any(l.strip() == "[global]" for l in out):
        return ["[global]", f"{key}={value}"] + out
    ins = []
    for line in out:
        ins.append(line)
        if line.strip() == "[global]":
            ins.append(f"{key}={value}")
    return ins

LAYOUT_MARKER = "# wekatester-layout: generated"

def is_layout(path):
    with open(path) as fp:
        return any(next(fp, "").startswith(LAYOUT_MARKER) for _ in range(3))

def layout_pristine(lines):
    """True when the sha256 in the marker still matches the body -- i.e. the
    operator never edited the generated file, so re-deriving it loses nothing."""
    import hashlib
    for l in lines[:3]:
        m = re.match(re.escape(LAYOUT_MARKER) + r" sha256=([0-9a-f]{64})\s*$", l)
        if m:
            body = [x for x in lines if not x.startswith(LAYOUT_MARKER)]
            digest = hashlib.sha256("\n".join(x.rstrip() for x in body).encode()).hexdigest()
            return digest == m.group(1)
    return False

jobs = sorted(f for f in os.listdir(src) if re.match(r"^[0-9]", f))
layout_set = {j for j in jobs if is_layout(os.path.join(src, j))}
os.makedirs(os.path.join(work, "usable"), exist_ok=True)
for h in hosts:
    os.makedirs(os.path.join(work, "jobs", h), exist_ok=True)
    # what fio may run on here, for the host-file writeback: each staged job
    # names only the subset its job count runs on, never this whole list
    with open(os.path.join(work, "usable", h), "w") as fp:
        fp.write(fmt_cpulist(usable_for(h)) + "\n")

def derive_layout_variant(h):
    """Re-derive layout sections from this host's already-tuned variants, so
    the layout covers what will actually run (the tuned numjobs, and at max
    tier the tuned iops/latency filesize and nrfiles).
    Twin of generate_layout in the bash layer -- keep the rules in sync:
    one section per pruned contributor, never one independent-max section,
    or the layout over-provisions by the cross-product of the divergences."""
    namespaces, engines = {}, {}
    for j in jobs:
        if j in layout_set: continue
        vlines = open(os.path.join(work, "jobs", h, j)).read().splitlines()
        fmt = first_value(vlines, "filename_format")
        # the shared dataset is laid out ONCE per filesystem group: only the
        # group's first host's layout job carries its sections, or N clients
        # would race to create (and the sweep to credit) the same files N
        # times over -- and it carries them for EVERY reader in the group,
        # since hosts of different shapes read the set with different job
        # counts and the widest one decides what must exist
        readers = [h]
        if fmt and fmt.startswith("shared."):
            if h != FS_GROUP[h][0]:
                eng = first_value(vlines, "ioengine")
                if eng: engines[eng] = engines.get(eng, 0) + 1
                continue
            readers = FS_GROUP[h]
        if fmt:
            key, section, out_fmt = fmt, None, fmt
        else:
            sec = last_section(vlines) or j
            key, section, out_fmt = f"__jobname__:{sec}", sec, ""
        eng = first_value(vlines, "ioengine")
        if eng: engines[eng] = engines.get(eng, 0) + 1
        for r in readers:
            rl = vlines if r == h else open(os.path.join(work, "jobs", r, j)).read().splitlines()
            fs, size = first_value(rl, "filesize"), first_value(rl, "size")
            size_b = -1
            for v in (fs, size):
                if v:
                    try: size_b = max(size_b, parse_size(v))
                    except ValueError: pass
            ns = namespaces.setdefault(key, {"section": section, "fmt": out_fmt, "contribs": []})
            ns["contribs"].append({"numjobs": int(first_value(rl, "numjobs") or 1),
                                   "nrfiles": int(first_value(rl, "nrfiles") or 1),
                                   "size_b": size_b, "fs": fs, "sz": size})

    def prune(contribs):
        kept = []
        for a in sorted(contribs, key=lambda c: (-c["numjobs"], -c["nrfiles"], -c["size_b"])):
            if not any(a["numjobs"] <= b["numjobs"] and a["nrfiles"] <= b["nrfiles"]
                       and a["size_b"] <= b["size_b"] for b in kept):
                kept.append(a)
        return kept

    best = pick_engine(engines)
    # the marker keeps every reader of the staged dir (capacity, writeback,
    # bundle summary) treating this as the layout job under any file name;
    # no sha: it is re-derived every run, so nothing compares it
    out = [f"{LAYOUT_MARKER} (re-derived by wekatester auto[{label}] from this host's tuned variants)",
           "[global]", f"directory={target(h, 'dir') or directory}",
           f"cpus_allowed={fmt_cpulist(usable_for(h))}",
           "create_serialize=0", "fallocate=none", f"ioengine={best}"]
    n = 0
    for key in sorted(namespaces):
        ns = namespaces[key]
        kept = prune(ns["contribs"])
        prev = None
        for c in kept:
            n += 1
            # Same naming and ordering rules as generate_layout: unique names
            # when a jobname namespace has several contributors, wait_for
            # chains WITHIN a namespace only, namespaces lay out in parallel.
            if ns["section"] and len(kept) == 1:
                sec, fmt = ns["section"], ns["fmt"]
            elif ns["section"]:
                sec, fmt = "layout-%d" % n, f"{ns['section']}.$jobnum.$filenum"
            else:
                sec, fmt = "layout-%d" % n, ns["fmt"]
            out.append("")
            out.append(f"[{sec}]")
            if prev: out.append(f"wait_for={prev}")
            prev = sec
            out.append("create_only=1")
            out.append("blocksize=1Mi")
            if fmt: out.append(f"filename_format={fmt}")
            if c["fs"]: out.append(f"filesize={c['fs']}")
            elif c["sz"]: out.append(f"size={c['sz']}")
            if c["nrfiles"] > 1: out.append(f"nrfiles={c['nrfiles']}")
            out.append(f"numjobs={c['numjobs']}")
    return out

for job in jobs:
    if job in layout_set:
        continue   # layout jobs are handled after every variant exists
    lines = open(os.path.join(src, job)).read().splitlines()
    items = report_items(os.path.join(src, job))
    for h in hosts:
        out = override(lines, "directory", target(h, "dir") or directory)
        # usable_for(h) is the operator's list minus weka's pinned cores --
        # the same effective set the calibration cells were measured on. The
        # host file still keeps the list AS WRITTEN; only what executes is
        # declared here, so calibration and measurement cannot disagree.
        out = override(out, "cpus_allowed", fmt_cpulist(usable_for(h)))
        if ns_unified and file_directions(lines) == {"read"}:
            # a read-only job measures the SHARED dataset: same files for
            # every client, exactly the files the read cells calibrated on.
            # stamp_unique_names leaves "shared." formats alone.
            _fmt = first_value(lines, "filename_format")
            out = override(out, "filename_format",
                           "shared." + (_fmt or "$jobname.$jobnum.$filenum"))

        is_latency = "latency" in items
        is_bw = "bandwidth" in items and not is_latency
        # Precedence latency > bandwidth > iops: a mixed bandwidth+iops file
        # is measuring bandwidth, and per spec bandwidth-file layout
        # (filesize/nrfiles) is part of the measurement and must stay
        # untouched, so it must not also take the iops small-file path.
        is_iops = "iops" in items and not is_latency and not is_bw
        usable_n = len(usable_for(h))
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
                    # outstanding-per-host = OUTSTANDING_PER_CORE * usable_n spread
                    # over numjobs = usable_n jobs reduces to OUTSTANDING_PER_CORE
                    # per job; cap at IODEPTH_CAP, never go below the current depth.
                    depth = max(cur_depth, min(IODEPTH_CAP, OUTSTANDING_PER_CORE))
                    out = override(out, "iodepth", str(depth))

        if tier == "max" and (is_iops or is_latency):
            # The file NAMESPACE is deliberately left alone: -a runs and
            # plain runs must share one grid, or alternating modes lays out
            # two full grids that cannot credit each other (seen live:
            # a 37-minute relayout right after a complete one, because the
            # old wt-small redirect gave -a its own iops namespace).
            out = override(out, "filesize", SMALL_FILESIZE)
            # File spread, stated directly: two 1G files per job so no job
            # pounds a single inode; the one-job latency test gets 8 so its
            # QD1 stream still walks a small spread. NOT a cache bound --
            # per the spec's "Working-set sizing (max tier) -- CORRECTED
            # 2026-08-18", weka backends hold no user data in RAM. (The old
            # 8GiB "working set floor" was an inherited guess this max(2,..)
            # arithmetic always dominated anyway; it is gone.)
            if is_latency:
                nr = LAT_NRFILES
                out = override(out, "nrfiles", str(nr))
                out = override(out, "file_service_type", "random")
            else:
                nr = IOPS_NRFILES
                out = override(out, "nrfiles", str(nr))
            # fio divides size= across nrfiles, so a size= left over from the
            # original large-file layout would resize the 1G files right back
            # down. Rewrite it to match filesize=1G per file -- but only where
            # the source set it: inserting size= would cap a job that had no cap.
            if any(re.match(r"^size=", l) for l in lines):
                out = override(out, "size", f"{nr}G")

        # host-file values land LAST: the file beats the tuner, per type AND
        # direction. A single-direction file takes its own slot; a mixed file
        # takes the deeper-queued direction's WHOLE tuple -- a coherent
        # measured pair, never a blend of the two directions.
        kind_key = (lat_kind(lines) if is_latency else
                    ("bw" if is_bw else "iops" if is_iops else ""))
        if kind_key:
            slot = pick_slot(kind_key, file_directions(lines),
                             lambda k: target(h, k))
            for tkey, jkey in (("nj", "numjobs"), ("fs", "filesize"),
                               ("nr", "nrfiles"), ("qd", "iodepth")):
                v = target(h, f"{slot}_{tkey}") if slot else ""
                if not v:
                    continue
                if tkey == "nj" and v.isdigit() and not is_floor_twin(lines):
                    # The host file is the operator's, so this is honoured.
                    # Past every thread of the usable cores is the 4N rung
                    # of a calibration (two jobs per thread on an SMT host)
                    # and gets a note; past 4N it matches no rung and is
                    # probably stale (seen live on field client B: 52 jobs in a
                    # 46-cpu mask), so it gets the warning.
                    cap, n = len(usable_for(h)), cores_for(h)["n"]
                    if int(v) > 4 * n:
                        warn_once(f"{h}: host-file {slot}_nj={v} exceeds 4N "
                                  f"({4 * n}; N={n} usable physical cores) -- "
                                  f"split affinity will run "
                                  f"{-(-int(v) // cap)} jobs on some cpus")
                    elif int(v) > cap:
                        print(f"note: {h}: {slot}_nj={v} runs up to "
                              f"{-(-int(v) // cap)} jobs per cpu ({cap} usable "
                              f"threads)", file=sys.stderr)
                out = override(out, jkey, v)
        if is_floor_twin(lines):
            # the one-job twin of a latency test: one stream per client at
            # numjobs=iodepth=nrfiles=1, with the same data per job as its
            # calibrated original (the calibration floor's own geometry)
            _slot = pick_slot(kind_key, file_directions(lines),
                              lambda k: target(h, k)) if kind_key else ""
            _fs = target(h, f"{_slot}_fs") if _slot else ""
            _nr = target(h, f"{_slot}_nr") if _slot else ""
            for key in ("numjobs", "iodepth", "nrfiles"):
                out = override(out, key, "1")
            if _fs and _nr.isdigit():
                try:
                    out = override(out, "filesize", "%dM" % max(
                        1, parse_size(_fs) * int(_nr) // (1 << 20)))
                except ValueError:
                    pass
        if target(h, "engine"):
            out = override(out, "ioengine", target(h, "engine"))
        if is_iops and iops_nolat:
            # the iops test records no latency, and its calibration cells
            # measured with the accounting off -- the staged job must run
            # what was measured
            for key in ("disable_lat", "disable_clat", "disable_slat", "norandommap"):
                out = override(out, key, "1")

        # the job count is final now: N/2 and N jobs run one per physical
        # core, more spread over the siblings too -- what the calibration
        # cell with this count ran on
        _nj = first_value(out, "numjobs")
        out = override(out, "cpus_allowed", fmt_cpulist(
            cpus_for(h, int(_nj) if _nj.isdigit() else 1)))
        header = [f"# generated by wekatester auto[{label}] for {h}",
                  f"# usable cores: {cores_summary(cores_for(h))} "
                  f"(of {facts[h]['ncpus']} cpus, weka: {fmt_cpulist(facts[h]['weka']) or 'none'})"]
        with open(os.path.join(work, "jobs", h, job), "w") as fp:
            fp.write("\n".join(header + out) + "\n")
    kind = "latency" if is_latency else ("bandwidth" if is_bw else "iops" if is_iops else "all")
    print(f"auto[{label}]: {job} type={kind}")

# Layout jobs last: the tuned variants above are their ground truth at BOTH
# tiers -- safe re-tunes numjobs too, and a layout built from the un-tuned
# sources would create the source superset (e.g. 64 jobs' worth of 10G files
# for a run tuned down to 5 jobs). A pristine (never-edited) layout is
# re-derived per host; an edited one is the operator's word -- stage it with
# corrections only and say so once.
for job in sorted(layout_set):
    lines = open(os.path.join(src, job)).read().splitlines()
    pristine = layout_pristine(lines)
    if not pristine:
        warn_once(f"{job}: user-edited layout staged as-is; it may not match "
                  "the auto-tuned geometry (regenerate with -g)")
    for h in hosts:
        if pristine:
            out = derive_layout_variant(h)
        else:
            out = override(lines, "directory", target(h, "dir") or directory)
            out = override(out, "cpus_allowed", fmt_cpulist(usable_for(h)))
        with open(os.path.join(work, "jobs", h, job), "w") as fp:
            fp.write("\n".join(out) + "\n")
    print(f"auto[{label}]: {job} type=layout")

# Capacity enforcement lives in check_capacity() now -- one universal
# check for every run, auto or not, computed from the staged variants.
