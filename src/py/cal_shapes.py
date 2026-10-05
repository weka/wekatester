import json, os, re, sys

out_path, ladders, work, cli_engine, regen, mem_pct, line_gbps = sys.argv[1:8]
hosts = sys.argv[8:]
NRS = sorted(set(int(x) for x in os.environ.get("WEKATESTER_CAL_NRS", "1 1 2 4").split() if x.isdigit()))
FSMIB = int(os.environ.get("WEKATESTER_FSMIB", "5120"))
line_gbps = "" if line_gbps == "-" else line_gbps
regen = regen == "1"
mem_pct = float(mem_pct)
needed = []
for line in ladders.splitlines():
    p = line.split()
    if len(p) == 2:
        needed.append("%s_%s" % (p[0], p[1][0]))

rows = {}
final = os.path.join(work, "targets.final")
if os.path.exists(final):
    for line in open(final):
        p = line.rstrip("\n").split("\t")
        rows.setdefault(p[0], p)

def field(host, key):
    row = rows.get(host, [])
    i = 1 + FIELDS.index(key)
    v = row[i] if i < len(row) else ""
    return "" if v == "-" else v

PCI = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")

def facts(host):
    path = os.path.join(work, "probe", host)
    f = {"path": path, "ncpus": 0, "model": "", "mem_kb": 0, "weka": set(),
         "nics": {}, "wekanet": [], "wekaerr": [], "cli": True, "engines": []}
    if not os.path.exists(path):
        return f
    for line in open(path).read().splitlines():
        p = line.split()
        if not p:
            continue
        k = p[0]
        if k == "ncpus" and len(p) > 1 and p[1].isdigit():
            f["ncpus"] = int(p[1])
        elif k == "cpu_model":
            v = line.split(None, 1)[1].strip() if len(p) > 1 else ""
            f["model"] = "" if v == "-" else " ".join(v.split())
        elif k == "memtotal_kb" and len(p) > 1 and p[1].isdigit():
            f["mem_kb"] = int(p[1])
        elif k == "weka_allowed" and len(p) > 1:
            s = parse_cpulist(p[1])
            if len(s) == 1:   # a single-cpu mask is a dedicated io thread
                f["weka"] |= s
        elif k == "nic" and len(p) >= 6:
            m = re.match(r"^(\d+)", p[2])
            f["nics"][p[1]] = {"speed": int(m.group(1)) if m else 0,
                               "pci": p[3].lower(), "driver": p[4], "ids": p[5]}
        elif k == "weka_net":
            rest = line.split(None, 2)
            f["wekanet"].append((rest[1] if len(rest) > 1 else "?",
                                 rest[2] if len(rest) > 2 else ""))
        elif k == "weka_net_err":
            rest = line.split(None, 2)
            f["wekaerr"].append("%s: %s" % (rest[1] if len(rest) > 1 else "?",
                                            rest[2] if len(rest) > 2 else "failed"))
        elif k == "weka_cli" and len(p) > 1 and p[1] == "absent":
            f["cli"] = False
        elif k == "engines":
            f["engines"] = p[1:]
    return f

def weka_ports(f):
    """(ports, why): the NICs weka's containers use, as {netdev: nic facts},
    or None and the reason they cannot be named."""
    if not f["cli"]:
        return None, "no weka CLI on the host"
    devs, bad = [], []
    for cname, raw in f["wekanet"]:
        starts = [i for i in (raw.find("["), raw.find("{")) if i >= 0]
        if not starts:
            bad.append("%s: no JSON in weka local resources" % cname)
            continue
        try:
            data, _ = json.JSONDecoder().raw_decode(raw[min(starts):])
        except ValueError:
            bad.append("%s: unreadable weka local resources JSON" % cname)
            continue
        if isinstance(data, dict):
            data = data.get("net_devices", [])
        devs += [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []
    if not f["wekanet"]:
        return None, ("weka local resources could not be read (%s)" % f["wekaerr"][0]
                      if f["wekaerr"] else "weka local resources could not be read")
    if bad:
        return None, bad[0]
    if not devs:
        return {}, "weka uses no dedicated NIC here (UDP mode)"
    by_pci = dict((n["pci"], name) for name, n in f["nics"].items() if n["pci"] != "-")
    ports, lost = {}, []
    for d in devs:
        cand = [str(d.get(k)) for k in ("name", "device", "identifier", "netdev", "interface")
                if isinstance(d.get(k), str) and d.get(k)]
        hit = ""
        for v in cand:
            if v in f["nics"]:
                hit = v
            elif PCI.match(v.lower()) and v.lower() in by_pci:
                hit = by_pci[v.lower()]
            if hit:
                break
        if hit:
            ports[hit] = f["nics"][hit]
        else:
            # name, device and identifier often repeat each other: say each once
            uniq = []
            for v in cand:
                if v not in uniq:
                    uniq.append(v)
            lost.append(" ".join(uniq) or "?")
    if lost:
        return None, ("weka's NIC %s has no kernel netdev to ask ethtool about "
                      "(bound to vfio?)" % lost[0])
    return ports, ""

# A host's pins: the host-file values of each searched slot (qd, nr, fs,
# nj; "" for a knob it leaves open). -g searches everything, and
# --line-rate searches bandwidth again: a recorded answer does not say
# which line rate it stopped at (Frank, 2026-09-27).
def host_pins(h):
    out = []
    if regen:
        return out
    for slot in needed:
        if line_gbps and slot in LINE_RATE_SLOTS:
            continue
        vals = tuple(field(h, "%s_%s" % (slot, k)) for k in ("qd", "nr", "fs", "nj"))
        if any(vals):
            out.append((slot, vals))
    return out

shapes, index, hostinfo = [], {}, []
fs_group = load_fs_groups(work, hosts)
ngroups = len(set(g[0] for g in fs_group.values()))
for h in hosts:
    f = facts(h)
    # the host file's own list, as the tuner reads it (cores_for): probe_cores
    # trims it the way check_cpu_pinning does, and has to see it as written to
    # tell a catch-all like 0-255 from an operator's choice
    base = field(h, "cpus")
    cores = probe_cores(f["path"], base)
    if cores["n"] < 1:
        if cores["catchall"]:
            how = ("its host-file cpu list (%s) covers every cpu fio could use, which "
                   "counts as no list -- mount weka with fewer cores, use a larger "
                   "client, or list fewer cpus (a narrower list is the operator's own "
                   "reserve)" % base)
        elif base:
            how = "mount weka with fewer cores or use a larger client"
        else:
            how = ("mount weka with fewer cores, use a larger client, or name the "
                   "cpus in the host file, fewer than fio could use (a narrower list "
                   "is the operator's own reserve)")
        sys.exit("ERROR: %s: no cpus left for fio -- %s; %s" % (h, cores_summary(cores), how))
    ports, why = weka_ports(f)
    linerate, nicsig = 0, "nics:unknown"
    if ports is not None:
        speeds = [ports[n]["speed"] for n in sorted(ports)]
        nicsig = ",".join("%s[%s]@%d" % (ports[n]["driver"], ports[n]["ids"], ports[n]["speed"])
                          for n in sorted(ports)) or "nics:none"
        if not ports:
            pass
        elif all(speeds):
            linerate = sum(speeds) * 125000   # Mb/s -> bytes/s
        else:
            why = "ethtool reports no link speed for %s" % " ".join(
                n for n in sorted(ports) if not ports[n]["speed"])
    ethtool = linerate
    if line_gbps:
        linerate = float(line_gbps) * 125000000   # Gb/s -> bytes/s
    cands = [e for e in ENGINE_ORDER if e in f["engines"]] or f["engines"][:1] or ["psync"]
    pinned = cli_engine if cli_engine != "-" else ("" if regen else field(h, "engine"))
    mem_gib = int(round(f["mem_kb"] / 1048576.0)) if f["mem_kb"] else 0
    # one representative per shape per filesystem group (Frank, 2026-10-02):
    # a group's read cells must read that group's own shared set; and hosts
    # whose host-file values pin different knobs calibrate apart, since a
    # pin is the only value its search tries
    key = (f["model"], f["ncpus"], mem_gib, len(f["weka"]), nicsig,
           cores["n"], len(cores["all"]), tuple(cands), pinned, fs_group[h][0],
           tuple(host_pins(h)))
    # every host may help seed its group's shared set: what it runs on
    hostinfo.append("%s\t%s\t%s" % (h, fmt_cpulist(cores["all"]), pinned or cands[0]))
    if key not in index:
        index[key] = len(shapes)
        shapes.append({"rep": h, "members": [], "f": f, "cores": cores,
                       "ports": ports, "why": why, "linerate": linerate, "ethtool": ethtool,
                       "cands": cands, "pinned": pinned, "mem_gib": mem_gib, "aio": None})
    s = shapes[index[key]]
    s["members"].append(h)
    # the aio room is state, not hardware (another process may hold part of
    # fs.aio-nr), so it splits no shape -- but every member runs the shape's
    # answer, so its libaio cells must fit the tightest member
    room = probe_aio_room(f["path"])
    if room is not None:
        s["aio"] = room if s["aio"] is None else min(s["aio"], room)

def gib(b):
    return "%.2f GiB/s" % (b / float(1 << 30))

with open(out_path, "w") as fh:
    for i, s in enumerate(shapes, 1):
        rep, f = s["rep"], s["f"]
        pins = host_pins(rep)
        again = [slot for slot in needed if not regen and line_gbps and slot in LINE_RATE_SLOTS
                 and any(field(rep, "%s_%s" % (slot, k)) for k in ("qd", "nr", "fs", "nj"))]
        cached = ["%s=%s" % (slot, "/".join(v or "-" for v in vals)) for slot, vals in pins]
        memcap = int(f["mem_kb"] * 1024 * mem_pct / 100) if f["mem_kb"] else 0
        c = s["cores"]
        fh.write("\t".join([str(i), rep, str(c["n"]), fmt_cpulist(c["phys"]),
                            fmt_cpulist(c["all"]), str(int(s["linerate"])),
                            ",".join(s["cands"]), s["pinned"] or "-", str(memcap),
                            "-" if s["aio"] is None else str(s["aio"]),
                            " ".join(cached) or "-", " ".join(s["members"])]) + "\n")
        if s["ports"]:
            speeds = {}
            for n in sorted(s["ports"]):
                p = s["ports"][n]
                k = "%s [%s] %s" % (p["driver"], p["ids"],
                                    ("%g Gb/s" % (p["speed"] / 1000.0)) if p["speed"] else "unknown speed")
                speeds[k] = speeds.get(k, 0) + 1
            nics = "weka NICs %s: %s" % (" ".join(sorted(s["ports"])), ", ".join(
                "%d x %s" % (c, k) for k, c in sorted(speeds.items())))
            if s["ethtool"]:
                nics += " -> line rate %s" % gib(s["ethtool"])
        else:
            nics = "weka NICs: %s" % s["why"]
        if line_gbps:
            nics += "; line rate %s from --line-rate %g Gb/s%s" % (
                gib(s["linerate"]), float(line_gbps), " in place of ethtool's" if s["ethtool"] else "")
        print("shape %d of %d: %d host(s), calibrated on %s -- %s, %d cpus, %s, %s"
              % (i, len(shapes), len(s["members"]), rep, f["model"] or "cpu model unknown",
                 f["ncpus"], ("%d GiB" % s["mem_gib"]) if s["mem_gib"] else "memory unknown",
                 nics))
        print("  cores: %s" % cores_summary(c))
        if ngroups > 1:
            print("  filesystem group of %s: reads that group's shared set" % fs_group[rep][0])
        more = s["members"][:24]
        print("  hosts: %s%s" % (" ".join(more), "" if len(s["members"]) <= 24
                                 else " (+%d more)" % (len(s["members"]) - 24)))
        if again:
            # a recorded answer does not say which line rate it stopped at,
            # so --line-rate searches bandwidth again (Frank, 2026-09-27); its
            # answer replaces the recorded one (apply_cal_results, writeback)
            print("  --line-rate: the host file's bandwidth answer (%s) is measured "
                  "again against it and replaced%s"
                  % (", ".join(again), "; its other values still pin their knobs" if cached else ""))
        if pins:
            print("  pinned by the host file (the only values tried; -g searches everything): %s"
                  % "; ".join("%s %s" % (slot, ", ".join(
                      "%s=%s" % (n, v) for n, v in zip(("iodepth", "nrfiles", "filesize", "numjobs"), vals) if v))
                      for slot, vals in pins))
        if not s["linerate"] and any(n.startswith("bw_") for n in needed):
            print("WARNING: shape %d (%s): %s -- the bandwidth search has no line-rate "
                  "target and runs to its peak instead" % (i, rep, s["why"] or "no line rate"),
                  file=sys.stderr)
# per host: the cpus and engine it seeds its group's shared set with
caldir = os.path.dirname(out_path)
with open(os.path.join(caldir, "hostinfo"), "w") as fh:
    fh.write("".join(l + "\n" for l in hostinfo))
# What the pins need from the seed beyond the nrfiles ladder, as "<nj> <nr>
# <mib>" needs (seed_size_mib): a pinned nrfiles off the ladder, a pinned
# filesize, a pinned job count past 4N -- and a pinned latency filesize's
# one-job twin, which reads one file of fs x nr. Read needs belong to the
# filesystem group's shared set, write needs to the representative's own.
for name in os.listdir(caldir):
    if name.startswith("needs."):
        os.remove(os.path.join(caldir, name))
needs = {}
for s in shapes:
    rep = s["rep"]
    for slot, (q, n, fs, j) in host_pins(rep):
        typ, d = slot.rsplit("_", 1)
        nrs = [int(n)] if n.isdigit() else NRS
        nj = int(j) if j.isdigit() else 4 * s["cores"]["n"]
        try:
            fmib = parse_size(fs) >> 20 if fs else 0
        except ValueError:
            fmib = 0
        dest = ("needs.read." + fs_group[rep][0]) if d == "r" else ("needs.write." + rep)
        lines = needs.setdefault(dest, [])
        for nr in nrs:
            lines.append("%d %d %d" % (nj, nr, fmib or max(1, FSMIB // nr)))
        if typ in ("lat", "lat1m") and fmib:
            lines.append("1 1 %d" % (fmib * max(nrs)))
for dest, lines in needs.items():
    with open(os.path.join(caldir, dest), "w") as fh:
        fh.write("".join(l + "\n" for l in lines))
