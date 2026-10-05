import os, re, sys

srcdir, work, directory, layout_job, layout_marker = sys.argv[1:6]
hosts = sys.argv[6:]

def load_rows(path):   # first row per host, as targets_field's awk saw it
    rows = {}
    if os.path.exists(path):
        for line in open(path):
            p = line.rstrip("\n").split("\t")
            rows.setdefault(p[0], p)
    return rows

# host_dir's rule: the finished resolution when it exists, the pre-auth
# phase otherwise, the global -d as the fallback; geometry needs the
# finished one
final = os.path.join(work, "targets.final")
has_final = os.path.exists(final)
rows = load_rows(final if has_final else os.path.join(work, "targets.phase1"))

def field(host, n):   # 1-based column; "" for a dash, a missing row or column
    row = rows.get(host, [])
    v = row[n - 1] if n - 1 < len(row) else ""
    return "" if v == "-" else v

def report_words(lines):   # report_directive: '# report <items>' comment lines
    out = []
    for l in lines:
        m = re.match(r"^#\s*report\s+(.*)$", l)
        if m:
            out += m.group(1).split()
    return out

def is_layout(name, lines):   # is_layout_file, on the staged content
    return name == layout_job or any(l.startswith(layout_marker) for l in lines[:3])

jobs = sorted(f for f in os.listdir(srcdir)
              if f[:1].isdigit() and os.path.isfile(os.path.join(srcdir, f)))
changed = []
for host in hosts:
    outdir = os.path.join(work, "jobs", host)
    os.makedirs(outdir, exist_ok=True)
    hd = field(host, 5) or directory
    geo_changed = False
    for base in jobs:
        lines = open(os.path.join(srcdir, base)).read().splitlines()
        # override directory= wherever it appears; jobfiles without one get
        # it inserted right after [global], and jobfiles with no [global]
        # at all get the section created at the top -- otherwise the
        # insert matches nothing and fio silently writes to the server's cwd
        lines = override_lines(lines, "directory", hd)
        if has_final and host in rows and not is_layout(base, lines):
            words = report_words(lines)
            # precedence latency > bandwidth > iops, same as the tuner; a
            # 1MiB latency file (a -b twin) takes the lat1m slot
            kind = (lat_kind(lines) if "latency" in words else "bw" if "bandwidth" in words
                    else "iops" if "iops" in words else "")
            if kind:
                def get(key):
                    i = 1 + FIELDS.index(key)
                    v = rows[host][i] if i < len(rows[host]) else ""
                    return "" if v == "-" else v
                slot = pick_slot(kind, file_directions(lines), get)
                if slot:
                    for tkey, jkey in (("nj", "numjobs"), ("fs", "filesize"),
                                       ("nr", "nrfiles"), ("qd", "iodepth")):
                        v = get(f"{slot}_{tkey}")
                        if v:
                            lines = override_lines(lines, jkey, v)
                            geo_changed = True
        with open(os.path.join(outdir, base), "w") as fh:
            fh.write("\n".join(lines) + "\n")
    if geo_changed:
        changed.append(host)
print(" ".join(changed))
