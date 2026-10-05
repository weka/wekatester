import os, re, sys

work = sys.argv[1]
hosts = sys.argv[2:]
fs_group = load_fs_groups(work, hosts)
SKIP = {"000-wekatester-relayout.job", "999-wekatester-unlink.job"}
MARKER = "# wekatester-layout: generated"

def job_value(path, key, default):
    for line in open(path):
        m = re.match(rf"^{key}=(\S+)", line)
        if m: return m.group(1)
    return default

def is_layout(path):
    if os.path.basename(path) == "000-wekatester-layout.job": return True
    with open(path) as fp:
        return any(next(fp, "").startswith(MARKER) for _ in range(3))

def footprint(path):
    numjobs = int(job_value(path, "numjobs", "1"))
    filesize = job_value(path, "filesize", "")
    if filesize:
        return numjobs * parse_size(filesize) * int(job_value(path, "nrfiles", "1"))
    size = job_value(path, "size", "")
    if size:
        try:
            # size= is fio's per-job total across the job's files
            return numjobs * parse_size(size)
        except ValueError:
            print(f"WARNING: {os.path.basename(path)}: size={size} is not a "
                  "byte count; it contributes nothing to the capacity estimate",
                  file=sys.stderr)
    return 0

def layout_footprint(path):
    total, numjobs, nrfiles, size_b, per_file = 0, 1, 1, 0, True
    def flush(): return numjobs * (nrfiles if per_file else 1) * size_b
    in_section = False
    for line in open(path):
        line = line.strip()
        if re.match(r"^\[.+\]$", line):
            if in_section: total += flush()
            in_section, numjobs, nrfiles, size_b, per_file = \
                line != "[global]", 1, 1, 0, True
            continue
        m = re.match(r"^(numjobs|nrfiles|filesize|size)=(\S+)", line)
        if not m or not in_section: continue
        k, v = m.groups()
        if k == "numjobs": numjobs = int(v)
        elif k == "nrfiles": nrfiles = int(v)
        else:
            try: size_b = parse_size(v)
            except ValueError: size_b = 0
            per_file = (k == "filesize")
    if in_section: total += flush()
    return total

gib = lambda n: f"{n / 2**30:.1f}"
over = False
pools = {}   # (weka fs name, size) -> the hosts on it, their needs, its room
for h in hosts:
    jdir = os.path.join(work, "jobs", h)
    if not os.path.isdir(jdir): continue
    namespaces, layout_total = {}, 0
    for job in sorted(os.listdir(jdir)):
        if job in SKIP: continue
        p = os.path.join(jdir, job)
        if is_layout(p):
            layout_total += layout_footprint(p)
            continue
        ns = job_value(p, "filename_format", "") or f"__default__:{job}"
        if ns.startswith("shared.") and h != fs_group[h][0]:
            continue   # a group's shared dataset is priced once, on its first host
        namespaces[ns] = max(namespaces.get(ns, 0), footprint(p))
    required = max(sum(namespaces.values()), layout_total)
    # bytes the sweep verified as already laid out serve both the layout and
    # the measured namespaces: a rerun only needs what is actually missing
    credit = 0
    cf = os.path.join(work, "probe", h + ".laidout")
    if os.path.exists(cf):
        try:
            credit = min(int(open(cf).read().strip() or 0), required)
        except ValueError:
            credit = 0
    required -= credit
    note = f" (~{gib(credit)}GiB already laid out)" if credit else ""
    avail, key = 0, None
    dfp = os.path.join(work, "df", h)
    if os.path.exists(dfp):
        lines = open(dfp).read().splitlines()
        if len(lines) >= 2:
            f = lines[1].split()
            avail = int(f[3]) * 1024
            # key a weka filesystem by its name -- a stateless mount lists
            # backends before it, and clients list them differently -- and
            # its size, which tells two clusters' same-named filesystems apart
            if len(lines) >= 3 and lines[2].strip() == "wekafs":
                key = (f[0].rsplit("/", 1)[-1], f[1])
    print(f"capacity: {h} needs ~{gib(required)}GiB{note}, has {gib(avail)}GiB available")
    # avail == 0 = df unavailable, not a full filesystem: nothing to check
    if avail and required > avail:
        over = True
        print(f"ERROR: {h}: workload needs ~{gib(required)}GiB but only "
              f"{gib(avail)}GiB is available", file=sys.stderr)
    if key is not None and avail:
        g = pools.setdefault(key, {"hosts": [], "need": 0, "avail": avail})
        g["hosts"].append(h)
        g["need"] += required
        g["avail"] = min(g["avail"], avail)
# every host fitting alone is not the fleet fitting: 3 hosts needing 640 GiB
# each passed against one 1000 GiB filesystem
for (fs, _size), g in sorted(pools.items()):
    if len(g["hosts"]) > 1 and g["need"] > g["avail"]:
        over = True
        names = " ".join(g["hosts"][:8]) + (" (+%d more)" % (len(g["hosts"]) - 8)
                                            if len(g["hosts"]) > 8 else "")
        print(f"ERROR: weka filesystem {fs}: its {len(g['hosts'])} hosts ({names}) need "
              f"~{gib(g['need'])}GiB together but only {gib(g['avail'])}GiB is available",
              file=sys.stderr)
sys.exit(2 if over else 0)
