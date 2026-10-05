import os
import sys

(host, rnj, rnr, wnj, wnr, fsmib, jobname, outdir, listpath, fmt, sep, unified,
 dense, tlistpath, nrs, membersf, rneedsf, wneedsf) = sys.argv[1:19]
rnj, rnr, wnj, wnr, fsmib = int(rnj), int(rnr), int(wnj), int(wnr), int(fsmib)
nrs = [int(x) for x in nrs.split() if x.isdigit()]
have = {}
for line in open(listpath):
    p = line.split()
    if len(p) == 2 and p[1].isdigit():
        have[p[0]] = int(p[1])

def needs_from(path):
    # the nrfiles ladder's shares, plus any listed need beyond it
    # ("<nj> <nr> <mib>" lines: what a host-file value pins past the grid)
    out = ladder_needs(nrs, fsmib)
    if os.path.exists(path):
        for line in open(path):
            p = line.split()
            if len(p) == 3 and all(x.isdigit() for x in p):
                out.append((int(p[0]), int(p[1]), int(p[2])))
    return out

rneeds, wneeds = needs_from(rneedsf), needs_from(wneedsf)
if unified != "1":
    # the scratch keeps reads and writes on the same files: one size serves both
    rneeds = wneeds = rneeds + wneeds

def size_of(needs, j, f, nr):
    return seed_size_mib(j, f, needs) or max(1, fsmib // nr)

def name_for(prefix, j, f):
    return (prefix + fmt).replace("$jobnum", str(j)).replace("$filenum", str(f))

rtodo, wtodo, trunc, seen = [], [], [], set()
rprefix = "shared." if unified == "1" else host + sep
for j in range(rnj):
    for f in range(rnr):
        name, mib = name_for(rprefix, j, f), size_of(rneeds, j, f, rnr)
        if name in seen or have.get(name, 0) >= mib << 20:
            continue
        seen.add(name)
        rtodo.append((j, name, mib))
for j in range(wnj):
    for f in range(wnr):
        name, mib = name_for(host + sep, j, f), size_of(wneeds, j, f, wnr)
        if name in seen or have.get(name, 0) >= mib << 20:
            continue
        seen.add(name)
        if unified == "1" and dense == "0":
            trunc.append((name, mib))
        else:
            wtodo.append((j, name, mib))
with open(tlistpath, "w") as fh:
    fh.write("".join(f"{n} {mib}\n" for n, mib in trunc))

members = [l.rstrip("\n").split("\t") for l in open(membersf) if l.strip()]
share = {m[0]: [] for m in members}
if unified == "1":
    for k, item in enumerate(rtodo):
        share[members[k % len(members)][0]].append(item)
else:
    share[members[0][0]] += rtodo
share[members[0][0]] += wtodo

# One section per file blew straight through fio's REAL_MAX_JOBS (4096) the
# first time a wide dataset was seeded: 52 jobs x 128 files = 6656 sections,
# dead at parse two seconds in (field client B, 2026-08-24). A section seeds up to
# SEED_CHUNK files of one size through a colon-joined filename list -- the
# incremental skip stays exact (only files that failed the size test are
# listed), and the chunk keeps the option line far below fio's 4096-byte
# parser buffer.
SEED_CHUNK = 16
active = []
for m, directory, cpus, eng in members:
    files = share[m]
    if not files:
        continue
    # fallocate=none: see generate_layout -- the incremental skip trusts
    # size, which is only sound if a partial write leaves a short file.
    out = ["[global]", "directory=%s" % directory, "unique_filename=0",
           "ioengine=%s" % eng, "direct=1", "bs=1Mi", "rw=write",
           "fallocate=none", "create_on_open=1"]
    if cpus:
        out += ["cpus_allowed=%s" % cpus, "cpus_allowed_policy=split"]
    groups = {}
    for j, name, mib in files:
        groups.setdefault((j, mib), []).append(name)
    sections = 0
    for (j, mib), names in sorted(groups.items()):
        for c in range(0, len(names), SEED_CHUNK):
            chunk = names[c:c + SEED_CHUNK]
            sections += 1
            out += ["[seed-%d-%dM-%d]" % (j, mib, c // SEED_CHUNK),
                    "filename=%s" % ":".join(chunk),
                    "nrfiles=%d" % len(chunk), "filesize=%dM" % mib]
    if sections > 4000:
        sys.exit("ERROR: %s: the seed needs %d fio sections and fio caps a run at "
                 "4096 jobs; shorten CAL_NR_LADDER or mount weka with more cores "
                 "(a smaller N)" % (m, sections))
    os.makedirs(os.path.join(outdir, m), exist_ok=True)
    with open(os.path.join(outdir, m, jobname), "w") as fh:
        fh.write("\n".join(out) + "\n")
    active.append(m)
print(len(rtodo) + len(wtodo), sum(mib for _, _, mib in rtodo + wtodo), len(trunc))
print(" ".join(active))
