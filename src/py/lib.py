import os, re

# fio spells the option rw= or readwrite=; trim-only mixes have no
# calibratable direction.
DIRECTIONS = {"read": ("read",), "randread": ("read",),
              "write": ("write",), "randwrite": ("write",),
              "rw": ("read", "write"), "randrw": ("read", "write"),
              "readwrite": ("read", "write"),
              "randreadwrite": ("read", "write")}

def rw_directions(value):
    # fio's ":<modifier>" suffix (rw=randrw:8) is not part of the direction
    return DIRECTIONS.get(value.lower().split(":")[0], ())

def file_directions(lines):
    """Every direction the file's job sections exercise. [global] supplies
    the fallback for sections that do not set rw= themselves."""
    glob, sections, cur = "", [], None
    for line in lines:
        m = re.match(r"^\[(.+)\]\s*$", line)
        if m:
            # [global] is not a job: its rw= is the fallback, not a section
            cur = None if m.group(1).strip() == "global" else {"rw": ""}
            if cur is not None:
                sections.append(cur)
            continue
        m = re.match(r"^(?:rw|readwrite)=(\S+)", line)
        if not m:
            continue
        if cur is None:
            glob = m.group(1)
        else:
            cur["rw"] = m.group(1)
    out = set()
    for sec in sections or [{"rw": ""}]:   # no sections: [global] is the job
        out.update(rw_directions(sec["rw"] or glob))
    return out

def job_bs(lines):
    """The block size the file's MEASURED section runs, in bytes: the last
    job section's bs=/blocksize=, else [global]'s, else fio's 4k. The
    workload runs last in every jobfile (create sections come first), and a
    split value ("4k,8k": read,write) is read by its first entry."""
    glob, last, in_job = "", "", False
    for line in lines:
        m = re.match(r"^\[(.+)\]\s*$", line)
        if m:
            in_job = m.group(1).strip() != "global"
            if in_job:
                last = ""
            continue
        m = re.match(r"^(?:bs|blocksize)=(\S+)", line)
        if m:
            if in_job:
                last = m.group(1)
            else:
                glob = m.group(1)
    v = (last or glob or "4k").split(",")[0].split(":")[0]
    try:
        return parse_size(v)
    except ValueError:
        return 4096

# The first line of a latency test's one-job twin (-a cal/brutal): the tuner
# stages it at numjobs=iodepth=nrfiles=1 on every client whatever the search
# found, so the run shows one single-threaded stream's latency next to the
# latency of every client at its calibrated load.
FLOOR_MARKER = "# wekatester-floor:"

def is_floor_twin(lines):
    return any(l.startswith(FLOOR_MARKER) for l in lines[:3])

def lat_kind(lines):
    """A latency file's geometry kind: 'lat1m' when its measured section
    moves 1MiB blocks (the -b test, whose job count and floor are its own
    slot), 'lat' otherwise."""
    return "lat1m" if job_bs(lines) >= (1 << 20) else "lat"

# The host-file schema: the host, four identity columns, then eight nj/fs/nr/qd
# geometry slots, one per (type, direction). The 1MiB latency slots (-b) come
# LAST, so a host file written before they existed still lines up column for
# column -- its rows simply end early.
GEOM_SLOTS = ("bw_r", "bw_w", "lat_r", "lat_w", "iops_r", "iops_w",
              "lat1m_r", "lat1m_w")
GEOM_NAMES = ("bandwidthR", "bandwidthW", "latencyR", "latencyW",
              "iopsR", "iopsW", "latency1mR", "latency1mW")
HOSTFILE_COLS = 5 + len(GEOM_SLOTS)   # host, login, engine, cpus, dir, slots
# the slots --line-rate measures again even when the host file carries them
# (Frank, 2026-09-27): a recorded answer does not say which line rate it
# stopped at; cal_shapes, apply_cal_results and the writeback all use it
LINE_RATE_SLOTS = ("bw_r", "bw_w")
FIELDS = ("login", "engine", "cpus", "dir") + tuple(
    f"{s}_{k}" for s in GEOM_SLOTS for k in ("nj", "fs", "nr", "qd"))

def slot_base(slot):
    # 0-based ROW index of the slot's nj column (host=0, login=1, engine=2,
    # cpus=3, dir=4, then nj/fs/nr/qd per slot)
    return 5 + 4 * GEOM_SLOTS.index(slot)

# cal.results: host, the shape's ioengine ("-" when calibration chose none),
# then (qd nr fs nj) per slot, every slot of the host-file schema in its
# order. CAL_HEAD, CAL_TUPLE and CAL_COLS live HERE because two separate
# parsers read this file -- apply_cal_results and the host-file writeback.
# They drifted once (one moved to 4, the other stayed at 3) and the writeback
# died on a file calibration had just written, after 11 minutes of measuring.
# Neither may spell the numbers itself.
CAL_SLOTS = GEOM_SLOTS
CAL_HEAD = 2
CAL_TUPLE = 4
CAL_COLS = CAL_HEAD + CAL_TUPLE * len(CAL_SLOTS)

def pick_slot(kind, dirs, get):
    """The geometry slot a file takes: its own direction, or -- for a
    mixed-direction (or unclassifiable) file -- the direction with the
    deeper recorded qd: a coherent measured pair, never a blend.
    get(key) returns that host's recorded value, "" when unset."""
    if dirs == {"read"}:
        return f"{kind}_r"
    if dirs == {"write"}:
        return f"{kind}_w"
    def qd(sfx):
        v = get(f"{kind}_{sfx}_qd")
        return int(v) if v.isdigit() else -1
    def any_vals(sfx):
        return any(get(f"{kind}_{sfx}_{k}") for k in ("nj", "fs", "nr", "qd"))
    if qd("r") < 0 and qd("w") < 0:
        return (f"{kind}_r" if any_vals("r")
                else f"{kind}_w" if any_vals("w") else "")
    return f"{kind}_r" if qd("r") >= qd("w") else f"{kind}_w"

ENGINE_ORDER = ["io_uring", "libaio", "psync"]

def probe_cpu_fact(path, key):
    """The cpu set on a 'key <list>' probe line, plus whether the line was
    there at all. "-" means TESTED AND EMPTY; an absent line means the probe
    could not test, and every caller must then fall back to its own rule
    rather than treat "nothing" as an answer."""
    try:
        fh = open(path)
    except OSError:
        return set(), False   # no probe facts at all: caller falls back
    with fh:
        for line in fh:
            f = line.split()
            if len(f) > 1 and f[0] == key:
                return (set() if f[1] == "-" else parse_cpulist(f[1])), True
    return set(), False

def probe_universe(path, ncpus):
    """The cpus this host actually has: the kernel's own online list when the
    probe read it, else 0..ncpus-1 -- which assumes the ids are contiguous
    from zero, and they are not on a box with an offline cpu."""
    online, ok = probe_cpu_fact(path, "online")
    return online if (ok and online) else set(range(ncpus))

def probe_unbindable(path, universe):
    """Cpus in <universe> that this host refuses to bind, as MEASURED by the
    probe (offline-but-counted, or held by another cgroup's cpuset
    partition). Empty when the probe could not test -- never a guess."""
    bind, tested = probe_cpu_fact(path, "bindable")
    if not tested:
        return set()
    bindp, _ = probe_cpu_fact(path, "bindable_priv")
    return set(universe) - bind - bindp

def probe_topology(path):
    """cpu -> (socket, core) from the probe's topo_* lines (the sysfs
    topology files), where core is the set of that core's hardware threads.
    {} when the probe carried none: an old probe, or a /sys without
    topology -- and then every cpu counts as a core of its own."""
    pkg, cid, sib = {}, {}, {}
    try:
        fh = open(path)
    except OSError:
        return {}
    with fh:
        for line in fh:
            f = line.split()
            if len(f) < 3 or not f[0].startswith("topo_") or not f[1].isdigit():
                continue
            c = int(f[1])
            try:
                if f[0] == "topo_physical_package_id":
                    pkg[c] = int(f[2])
                elif f[0] == "topo_core_id":
                    cid[c] = int(f[2])
                elif f[0] == "topo_thread_siblings_list":
                    sib[c] = frozenset(parse_cpulist(f[2]))
            except ValueError:
                continue
    cpus = set(pkg) | set(cid) | set(sib)
    # threads without a siblings list share a core with every thread of the
    # same (socket, core_id)
    byid = {}
    for c in cpus:
        if c not in sib and c in cid:
            byid.setdefault((pkg.get(c, 0), cid[c]), set()).add(c)
    out = {}
    for c in cpus:
        if c in sib and c in sib[c]:
            core = sib[c]
        elif c in cid:
            core = frozenset(byid[(pkg.get(c, 0), cid[c])])
        else:
            core = frozenset([c])
        out[c] = (pkg.get(c, 0), core)
    return out

def reserve_count(ncores, ndpdk):
    """Cores left to the OS and weka's own non-DPDK work (Frank, 2026-09-25):
    2 on a host of up to 24 physical cores, 4 above, plus one for every 4
    DPDK cores past 4 (5-8 -> +1, 9-12 -> +2), at most 12 and never more than
    half the cores. Core 0 is always one of them."""
    extra = (ndpdk - 4 + 3) // 4 if ndpdk > 4 else 0
    return max(1, min((2 if ncores <= 24 else 4) + extra, 12, ncores // 2))

def place_reserve(order, socket, dpdk, core0, want):
    """Which cores the reserve takes: core 0 of socket 0 first, then one core
    at a time round-robin over the sockets from the one after core 0's, each
    socket giving its lowest free core. That is Frank's placement: two
    sockets reserve core 0 and the next core of socket 0 plus the first two
    of socket 1; one socket reserves its next cores; more sockets share the
    rest one at a time. A DPDK core is never a reserve core -- not even core
    0 when weka has pinned it (a misconfiguration the tuner warns about): the
    OS then gets its full count from the free cores."""
    picked = [core0] if core0 is not None and core0 not in dpdk else []
    socks = sorted(set(socket[k] for k in order))
    if not socks:
        return picked
    s0 = socket.get(core0, socks[0])
    i = socks.index(s0) if s0 in socks else 0
    rr = socks[i + 1:] + socks[:i + 1]
    free = dict((s, [k for k in order if socket[k] == s and k not in dpdk
                     and k not in picked]) for s in socks)
    while len(picked) < want and any(free.values()):
        for s in rr:
            if len(picked) >= want:
                break
            if free[s]:
                picked.append(free[s].pop(0))
    return picked

def probe_cores(path, base_list=""):
    """The cpus fio may run on for one host, counted in PHYSICAL cores
    (Frank's rule, 2026-09-25). ONE rule for the tuner, the calibration
    shapes and usable_cores: a divergence would make a measured job count
    describe a cpu set the staged jobs do not run on.
      - weka's DPDK cores are whole cores. Weka pins each dedicated io thread
        to exactly ONE cpu (a single-cpu task mask; utility threads carry
        wide masks and float), and hives that core's SMT sibling off on
        purpose (WEKAPP-550768), so the sibling is weka's too.
      - core 0 of socket 0 and its sibling always stay with the OS, and the
        reserve (reserve_count, place_reserve) takes more cores beside it.
      - N = physical cores - DPDK cores - reserved cores. N/2 and N jobs run
        one per physical core with the siblings idle ("phys"); 2N and 4N run
        on every thread of those cores ("all"), which is how a calibration
        finds out whether the siblings help or hurt.
      - fio never runs on weka's cores or core 0's pair, whatever a list
        says (Frank, 2026-09-27), nor on a cpu the host refuses to bind. An
        operator cpu list (<base_list>) that leaves out more than those is the
        operator's own reserve: only those come out of it. A list covering
        every cpu fio could use (0-255 on a 64-cpu box, or every cpu but
        weka's) restricts nothing: the whole rule applies.
      - isolcpus does NOT narrow the set: measured on saving-calf
        (2026-08-20), confining the OS cost 4-7% write iops at every
        housekeeping-core count tried. Split affinity keeps a mask spanning
        both partitions safe.
    Returns a dict: n, phys, all, and the counts the logs quote (ncores,
    dpdk, reserved: the reserved cores' threads, sockets, smt, topo;
    unlisted and unbound: the other cores that give fio nothing, left out by
    the list or unbindable), plus catchall: the list covered every cpu fio
    could use and so counted as none."""
    ncpus, weka = 0, set()
    try:
        lines = open(path).read().splitlines()
    except OSError:
        lines = []
    for line in lines:
        f = line.split()
        if len(f) < 2:
            continue          # a bare 'isolated' line means no isolated cpus
        if f[0] == "ncpus" and f[1].isdigit():
            ncpus = int(f[1])
        elif f[0] == "weka_allowed":
            cpuset = parse_cpulist(f[1])
            if len(cpuset) == 1:
                weka |= cpuset
    universe = set(probe_universe(path, ncpus))
    unbind = probe_unbindable(path, universe)
    topo = probe_topology(path)
    core = {}      # cpu -> its core's key: the core's lowest online thread
    for c in sorted(universe):
        t = topo.get(c)
        core[c] = min(((set(t[1]) & universe) if t else set()) | {c})
    threads = {}
    for c in sorted(core):
        threads.setdefault(core[c], []).append(c)
    socket = dict((k, topo[k][0] if k in topo else 0) for k in threads)
    order = sorted(threads)
    dpdk = set(core[c] for c in weka if c in core)
    core0 = core.get(0, order[0] if order else None)
    catchall = False
    if base_list:
        base = parse_cpulist(base_list)
        if universe:
            base &= universe
        # what fio never gets whatever the list says: weka's cores, both
        # threads; core 0's pair; the cpus the host refuses to bind
        never = set(unbind)
        for k in dpdk | ({core0} if core0 is not None else set()):
            never |= set(threads.get(k, []))
        if universe and universe - never <= base:
            # leaving out only those (0-255 on a 64-cpu box, or every cpu
            # but weka's) is no choice: the reserve applies whole, as if the
            # file gave none
            base_list, catchall = "", True
    if base_list:
        # core 0's pair -- unless weka owns core 0: then it already left as
        # a DPDK core, and counting it twice broke the logged sum
        reserved = [core0] if core0 is not None and core0 not in dpdk else []
    else:
        base = set(universe)
        reserved = place_reserve(order, socket, dpdk, core0,
                                 reserve_count(len(order), len(dpdk)))
    skip = dpdk | set(reserved)
    use, unlisted, unbound = [], 0, 0
    for k in order:
        if k in skip:
            continue
        t = [c for c in threads[k] if c in base and c not in unbind]
        if t:
            use.append(t)
        elif any(c in base for c in threads[k]):
            unbound += 1     # listed, but the host binds none of its threads
        else:
            unlisted += 1    # the operator's list leaves the whole core out
    return {"n": len(use), "phys": sorted(t[0] for t in use),
            "all": sorted(c for t in use for c in t),
            "ncores": len(order), "dpdk": len(dpdk),
            "reserved": [threads[k] for k in reserved if k in threads],
            "sockets": len(set(socket.values())) or 1,
            "smt": any(len(v) > 1 for v in threads.values()),
            "topo": bool(topo), "weka_core0": core0 in dpdk,
            "catchall": catchall, "unlisted": unlisted, "unbound": unbound}

def probe_aio_room(path):
    """How many more aio events the kernel lets this host's processes set
    up (fs.aio-max-nr less fs.aio-nr, as the probe read them), or None when
    the probe could not tell. Every libaio job reserves its iodepth against
    it at setup, so numjobs x iodepth past it dies with EAGAIN in
    io_queue_init -- seen on field client B 2026-09-25: 128 jobs x 512 took the
    whole default 65,536 and the other 60 of 188 failed. That exact charge
    is the kernel's before v3.12 and again from v4.14 (fs/aio.c; a vendor
    kernel in between may carry the fix). v3.12-v4.13 charge each io_setup
    max(iodepth, 4 x possible cpus) net -- 1,024 events a job on a 256-cpu
    box whatever its iodepth, so ~64 jobs fill the default -- and read
    fs.aio-nr doubled, so there this room and numjobs x iodepth are both
    rough."""
    mx = nr = None
    try:
        for line in open(path):
            f = line.split()
            if len(f) == 2 and f[1].isdigit():
                if f[0] == "aio_max_nr":
                    mx = int(f[1])
                elif f[0] == "aio_nr":
                    nr = int(f[1])
    except OSError:
        return None
    if mx is None:
        return None
    return max(0, mx - (nr or 0))

def libaio_events(lines):
    """The most kernel aio events one jobfile sets up at once through
    libaio: every clone of a job reserves its iodepth (io_queue_init), so
    numjobs x iodepth per section, summed over the sections that run
    together -- a stonewall starts a new group -- and the largest group
    taken. A section inherits every [global] above it. 0 when nothing in
    the file runs libaio."""
    glob, cur, groups = {}, None, [[]]
    def close(sec):
        if sec is None:
            return
        if sec.get("stonewall", "0") != "0" and groups[-1]:
            groups.append([])
        if sec.get("ioengine") == "libaio":
            try:
                n = int(sec.get("numjobs") or 1) * int(sec.get("iodepth") or 1)
            except ValueError:
                n = 0
            groups[-1].append(n)
    for l in lines:
        s = l.strip()
        if not s or s[0] in "#;":
            continue
        m = re.match(r"^\[(.+)\]$", s)
        if m:
            close(cur)
            cur = None if m.group(1).strip() == "global" else dict(glob)
            continue
        k, _, v = s.partition("=")
        (glob if cur is None else cur)[k.strip()] = v.strip()
    close(cur)
    return max(sum(g) for g in groups)

def cores_summary(c):
    """The one-line account of probe_cores' answer the logs print."""
    res = " ".join(fmt_cpulist(t) for t in c["reserved"]) or "none"
    # the terms only when they count, so the sum adds up: a list written
    # back by a calibration leaves the rest of the reserve out (lab 3,
    # 2026-09-27, printed "16 - 6 weka DPDK - 1 reserved (0-1) = N=7")
    more = ""
    if c.get("unlisted"):
        more += " - %d outside the host-file cpu list" % c["unlisted"]
    if c.get("unbound"):
        more += " - %d unbindable" % c["unbound"]
    return ("%d physical core(s)%s - %d weka DPDK - %d reserved for the OS "
            "(%s)%s = N=%d: N/2 and N jobs on %s, 2N and 4N on %s"
            % (c["ncores"], "" if c["topo"] else " (no topology: one per cpu)",
               c["dpdk"], len(c["reserved"]), res, more, c["n"],
               fmt_cpulist(c["phys"]) or "none", fmt_cpulist(c["all"]) or "none"))

def pick_engine(tally):
    # Most-used engine wins; a tie goes to ENGINE_ORDER -- io_uring over
    # libaio over psync -- instead of to whichever jobfile happened to be
    # read first, which is what plain max() over a dict gives you. Same
    # order decides the no-engine-declared fallback.
    if not tally:
        return ENGINE_ORDER[0]
    rank = {e: i for i, e in enumerate(ENGINE_ORDER)}
    return max(tally, key=lambda e: (tally[e], -rank.get(e, len(ENGINE_ORDER))))

def override_lines(lines, key, value):
    """override_variant_key, in python: replace every 'key=' line; else
    insert 'key=value' right after the first [global]; else create [global]
    at the top. The staging passes stamp hundreds of files per run and must
    leave exactly what the bash helper would have."""
    if any(l.startswith(key + "=") for l in lines):
        return [key + "=" + value if l.startswith(key + "=") else l for l in lines]
    if any(l.startswith("[global]") for l in lines):
        out, done = [], False
        for l in lines:
            out.append(l)
            if not done and l.startswith("[global]"):
                out.append(key + "=" + value)
                done = True
        return out
    return ["[global]", key + "=" + value] + lines

def first_value(lines, key):
    for l in lines:
        m = re.match(rf"^{key}=(\S+)", l)
        if m: return m.group(1)
    return ""

def last_section(lines):
    name = ""
    for l in lines:
        m = re.match(r"^\[(.+)\]\s*$", l)
        if m: name = m.group(1)
    return name

def parse_size(s):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([kKmMgGtT]?)i?[bB]?", s.strip())
    if not m: raise ValueError(f"bad size: {s}")
    mult = {"": 1, "k": 2**10, "m": 2**20, "g": 2**30, "t": 2**40}[m.group(2).lower()]
    return int(float(m.group(1)) * mult)

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

def _kv(name):
    return dict(kv.split("=", 1)
                for kv in os.environ.get(name, "").split(",") if "=" in kv)

ALIAS = _kv("WEKATESTER_HOST_ALIAS")     # name in the file -> address we use
IDENT = _kv("WEKATESTER_HOST_IDENT")     # address -> "<name>/<machine-id>"

def host_addr(cell):
    """A host cell may be '<name>/<machine-id>' and may name the box by
    something other than the address this run uses (local mode calls it
    localhost). Strip the id, then map the name onto the address."""
    name = cell.split("/", 1)[0].strip()
    return ALIAS.get(name, name)

def load_fs_groups(work, hosts):
    """host -> the members of its filesystem group, in host order, from
    collect_fs_groups' $WORK_DIR/groups ("<host> <group>"). The first member
    lays out and prices the group's fleet-shared read set. Without the file
    every host is one group: one shared directory, as before groups."""
    gid = {}
    path = os.path.join(work, "groups")
    if os.path.exists(path):
        for line in open(path):
            f = line.split()
            if len(f) == 2:
                gid[f[0]] = f[1]
    members = {}
    for h in hosts:
        members.setdefault(gid.get(h, "1"), []).append(h)
    return {h: members[gid.get(h, "1")] for h in hosts}

# Seeded file sizes. A job at nrfiles=nr takes FILESIZE_MIB/nr from each of
# its first nr files, so file f only ever needs the largest share any test
# takes from it: with nrfiles 1, 2 and 4 that is 5G, 2.5G, 1.25G and 1.25G
# per job -- 10G, not the 20G of four 5G files. A need is (nj, nr, mib):
# jobs below nj at nrfiles nr read or write mib of each of their first nr
# files. Every size is fixed before the first seed, from every need there
# is, so a file is created once at its final size and never has to grow.
SEED_ANY_JOB = 1 << 30

def ladder_needs(nrs, fsmib, nj=SEED_ANY_JOB):
    return [(nj, nr, max(1, fsmib // nr)) for nr in sorted(set(nrs)) if nr > 0]

def read_needs(path):
    """Listed needs beyond the ladder: "<nj> <nr> <mib>" lines."""
    out = []
    if os.path.exists(path):
        for line in open(path):
            p = line.split()
            if len(p) == 3 and all(x.isdigit() for x in p):
                out.append((int(p[0]), int(p[1]), int(p[2])))
    return out

def seed_size_mib(j, f, needs):
    """MiB file f of job j is seeded at: the largest share any need takes
    from it, or 0 when nothing needs the file."""
    return max([mib for nj, nr, mib in needs if j < nj and f < nr] or [0])
