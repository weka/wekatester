import os, sys

# the widest job count the level searches, in multiples of N (cal_wide)
WIDE = int(os.environ.get("WEKATESTER_CAL_WIDE", "4"))

work, shapes_path, ladders, nsdir, fmt, sep, fsmib, nrs = sys.argv[1:9]
hosts = sys.argv[9:]
unified = nsdir == ""
fsmib = int(fsmib)
nrs = [int(x) for x in nrs.split() if x.isdigit()]
dirs = set(l.split()[1] for l in ladders.splitlines() if len(l.split()) == 2)
fs_group = load_fs_groups(work, hosts)
cap = os.path.join(work, "cal", "cap")
names = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(cap, "names")) if "\t" in l)

shapes = []
for line in open(shapes_path):
    p = line.rstrip("\n").split("\t")
    if len(p) >= 3:
        shapes.append((p[1], int(p[2])))     # rep, N

have, dfs = {}, {}
for rep, _ in shapes:
    raw = open(os.path.join(cap, rep)).read().split("WEKATESTER_DF\n", 1)
    have[rep] = {}
    for l in raw[0].splitlines():
        q = l.split()
        if len(q) == 2 and q[1].isdigit():
            have[rep][q[0]] = int(q[1])
    # the seed's df line: source, size in KiB, free MiB; then the fs type
    tail = raw[1].splitlines() if len(raw) > 1 else []
    f = tail[0].split() if tail else []
    if len(f) >= 3 and f[2].isdigit():
        key = ("host", rep)
        if len(tail) >= 2 and tail[1].strip() == "wekafs":
            key = (f[0].rsplit("/", 1)[-1], f[1])
        dfs[rep] = (key, int(f[2]) << 20)

def name_for(prefix, j, f):
    return (prefix + fmt).replace("$jobnum", str(j)).replace("$filenum", str(f))

def deficit(prefix, needs, listing):
    """Bytes still to write for every file the needs ask for, and the most
    jobs x files they reach."""
    if not needs:
        return 0, 0, 0
    nj, nr = max(n[0] for n in needs), max(n[1] for n in needs)
    total = 0
    for j in range(nj):
        for f in range(nr):
            mib = seed_size_mib(j, f, needs)
            if mib:
                total += max(0, (mib << 20) - listing.get(name_for(prefix, j, f), 0))
    return total, nj, nr

gib = lambda n: "%.1f" % (n / float(1 << 30))
pools, lines = {}, []
def charge(rep, need, what):
    lines.append("cal: capacity: %s: ~%sGiB to write" % (what, gib(need)))
    if rep not in dfs or need == 0:
        return
    key, avail = dfs[rep]
    p = pools.setdefault(key, {"need": 0, "avail": avail, "hosts": []})
    p["need"] += need
    p["avail"] = min(p["avail"], avail)
    if rep not in p["hosts"]:
        p["hosts"].append(rep)

if unified and "read" in dirs:
    # one shared read set per filesystem group, for every shape that reads it
    for first in sorted(set(fs_group[r][0] for r, _ in shapes), key=hosts.index):
        needs = []
        for rep, n in shapes:
            if fs_group[rep][0] == first:
                needs += ladder_needs(nrs, fsmib, WIDE * n)
        needs += read_needs(os.path.join(work, "cal", "needs.read." + first))
        lister = first if first in have else next(r for r, _ in shapes if fs_group[r][0] == first)
        need, nj, nr = deficit("shared.", needs, have[lister])
        charge(lister, need, "the shared read set of %s's filesystem group (up to %d jobs x %d files)" % (first, nj, nr))
for rep, n in shapes:
    if unified and "write" not in dirs:
        continue
    needs = ladder_needs(nrs, fsmib, WIDE * n) + read_needs(os.path.join(work, "cal", "needs.write." + rep))
    if not unified:
        needs += read_needs(os.path.join(work, "cal", "needs.read." + fs_group[rep][0]))
    need, nj, nr = deficit(names.get(rep, rep) + sep, needs, have[rep])
    charge(rep, need, "%s's own %s (up to %d jobs x %d files)" % (
        rep, "write set" if unified else "calibration scratch", nj, nr))

for l in lines:
    print(l)
over = False
for key, p in sorted(pools.items(), key=lambda kv: str(kv[0])):
    where = ("weka filesystem %s" % key[0]) if key[0] != "host" else ("%s's destination" % key[1])
    if p["need"] > p["avail"]:
        over = True
        print("ERROR: calibration needs ~%sGiB on %s (%s) but only %sGiB is available"
              % (gib(p["need"]), where, " ".join(p["hosts"]), gib(p["avail"])), file=sys.stderr)
sys.exit(2 if over else 0)
