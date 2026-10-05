import csv, os, re, sys

wb, mode, work, line_gbps = sys.argv[1:5]
hosts = sys.argv[5:]

def load_tsv(path):
    out = {}
    if os.path.exists(path):
        for line in open(path):
            p = line.rstrip("\n").split("\t")
            if len(p) == len(FIELDS) + 1:
                out[p[0]] = {k: v for k, v in zip(FIELDS, p[1:]) if v != "-"}
    return out

hostrows = load_tsv(os.path.join(work, "targets.hostrows"))

# derive per-host values: the measured knees first (cal.results is pure
# measurement -- targets.final would also carry CLI-merged values, which are
# not calibration's to record), then the STAGED variants for whatever was
# not measured
measured = {}
calres = os.path.join(work, "cal.results")
if os.path.exists(calres):
    for line in open(calres):
        p = line.split()
        if not p:
            continue
        # a malformed line is a schema break, not a skip -- see
        # apply_cal_results, which dies on the same seam
        if len(p) != CAL_COLS:
            sys.exit(f"ERROR: cal.results: malformed line "
                     f"(want {CAL_COLS} fields): {line.rstrip()}")
        m = {}
        tuples = p[CAL_HEAD:]
        for i, slot in enumerate(CAL_SLOTS):
            qd, nr, fs, nj = tuples[CAL_TUPLE * i:CAL_TUPLE * (i + 1)]
            if qd != "-":
                m[f"{slot}_qd"], m[f"{slot}_nr"], m[f"{slot}_fs"] = qd, nr, fs
            # a measured tuple always carries its numjobs: bandwidth's answer
            # IS a job count (the first to reach line rate), so is latency's
            # (the widest still at the floor), and the iops re-split may
            # have moved it off one job per cpu. It is also what marks the
            # tuple as MEASURED -- the staged-variant tuples recorded below
            # never carry one, so calibration's cache cannot mistake a tuned
            # guess for a measurement.
            if nj != "-":
                m[f"{slot}_nj"] = nj
        if m:
            measured[p[0]] = m

KIND = {"latency": "lat", "bandwidth": "bw", "iops": "iops"}
derived = {}
for host in hosts:
    d = dict(measured.get(host, {}))
    jdir = os.path.join(work, "jobs", host)
    userf = os.path.join(work, "auth", f"{host}.user")
    if os.path.exists(userf):
        d["login"] = open(userf).read().strip()
    # the cpu list fio may run on here, as the tuner resolved it: a staged
    # job names only the subset its own job count runs on (physical cores
    # alone at N or fewer jobs), so no single job is the list to record
    usable = os.path.join(work, "usable", host)
    if os.path.exists(usable):
        d.setdefault("cpus", open(usable).read().strip())
    for job in sorted(os.listdir(jdir)) if os.path.isdir(jdir) else []:
        p = os.path.join(jdir, job)
        lines = open(p).read().splitlines()
        if job == "000-wekatester-layout.job" or any(
                l.startswith("# wekatester-layout: generated") for l in lines[:3]):
            continue   # the layout is a barrier, not a test: it records nothing
        if is_floor_twin(lines):
            continue   # its one-job geometry is forced, not something to record
        kinds = [KIND[w] for l in lines if l.startswith("# report")
                 for w in l.split()[2:] if w in KIND]
        # precedence latency > bandwidth > iops, same as the tuner; a 1MiB
        # latency file (a -b twin) records into the lat1m slot
        kind = lat_kind(lines) if "lat" in kinds else ("bw" if "bw" in kinds else
                                                       ("iops" if "iops" in kinds else ""))
        d.setdefault("engine", first_value(lines, "ioengine"))
        d.setdefault("cpus", first_value(lines, "cpus_allowed"))
        d.setdefault("dir", first_value(lines, "directory"))
        if kind:
            # a measured direction already carries its own tuple (preloaded
            # above; setdefault cannot overwrite it), so the staged tuple
            # fills only unmeasured slots. A staged numjobs is never recorded:
            # the tuner re-derives it from the usable cores every run, and a
            # recorded count would only go stale (weka re-pins, cpu list
            # edits) -- and the next calibration would test only that guess,
            # since a recorded value pins its knob.
            for sfx in sorted({"read": "r", "write": "w"}[dd]
                              for dd in file_directions(lines)):
                for tkey, jkey in (("fs", "filesize"),
                                   ("nr", "nrfiles"), ("qd", "iodepth")):
                    v = first_value(lines, jkey)
                    if v:
                        d.setdefault(f"{kind}_{sfx}_{tkey}", v)
    derived[host] = {k: v for k, v in d.items() if v}

# desired host line per host: the host's own row, plus what the run derived
# for whatever that row left unset (or everything, under -g). Values a
# generic row supplied are not in `have`, so a host that ran on a generic
# cpu list gets its own line carrying the list that actually executed.
# Values compare by what they mean, not how they are spelled: 5G is 5120M,
# 2-4 is 2,3,4 (but 2,4 is not 2-4) -- a line whose values all hold is left
# exactly as it is (Frank, 2026-10-02).
def norm(k, v):
    try:
        if k == "cpus":
            return frozenset(parse_cpulist(v))
        if k.endswith("_fs"):
            return parse_size(v)
        if k.endswith(("_nj", "_nr", "_qd")):
            return int(v)
    except ValueError:
        pass
    return v

def same(a, b):
    return set(a) == set(b) and all(norm(k, a[k]) == norm(k, b[k]) for k in a)

updates = {}
for host in hosts:
    have = hostrows.get(host, {})
    want = dict(have)
    # the bandwidth tuples --line-rate MEASURED again replace the row's; a
    # staged guess for those slots never does
    fresh = set(k for k in measured.get(host, {})
                if line_gbps != "-" and k.rsplit("_", 1)[0] in LINE_RATE_SLOTS)
    for k, v in derived.get(host, {}).items():
        if k in ("login", "cpus") and k in have:
            continue   # identity, credentials and the operator's OWN cpu
                       # list are never overwritten, -g included
        if k in have and norm(k, have[k]) == norm(k, v):
            continue   # the same value: the row keeps its own spelling
        if mode == "overwrite" or k not in have or k in fresh:
            want[k] = v
    if want and not same(want, have):
        updates[host] = want

if not updates:
    print("host file: nothing to record")
    sys.exit(0)

# The host file is only ever added to (Frank, 2026-10-02): a host's own line
# is commented out and its new version written directly below it; a host
# with no line of its own gets one appended at the end. Nothing is deleted
# or rewritten in place, and a generic (host-less) row is never touched.
lines = open(wb).read().splitlines()

def own_line(line):
    """The address of the host whose own line this is, or ""."""
    try:
        row = next(csv.reader([line]))
    except StopIteration:
        row = []
    h = row[0].strip() if row else ""
    if h and not h.startswith("#") and h.lower() != "host" and host_addr(h) in updates:
        return host_addr(h), h
    return "", ""

# a row the operator already wrote keeps its own spelling of the host,
# machine-id or not -- automation only names a machine it is adding
seen_cell = {}
for line in lines:
    addr, h = own_line(line)
    if addr:
        seen_cell.setdefault(addr, h)

def geom(want, slot):
    parts = [want.get(f"{slot}_{k}", "") for k in ("nj", "fs", "nr", "qd")]
    return "/".join(parts).rstrip("/") if any(parts) else ""

import io
def render(host):
    want = updates[host]
    cell = seen_cell.get(host) or IDENT.get(host, host)
    slots = [geom(want, s) for s in GEOM_SLOTS]
    while slots and not slots[-1] and len(slots) > 6:
        slots.pop()   # no 1MiB latency geometry: the row stays in the old width
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow(
        [cell, want.get("login", ""), want.get("engine", ""),
         want.get("cpus", ""), want.get("dir", "")] + slots)
    return buf.getvalue()

out, placed = [], set()
for line in lines:
    addr, _ = own_line(line)
    if addr:
        out.append("# superseded by -a: " + line)
        if addr not in placed:
            out.append(render(addr))
            placed.add(addr)
    else:
        out.append(line)
out += [render(h) for h in hosts if h in updates and h not in placed]
with open(wb, "w") as fp:
    fp.write("\n".join(out) + "\n")
print(f"host file: recorded {len(updates)} host line(s) in {wb} ({mode})")
