import os, sys

work, hosts = sys.argv[1], sys.argv[2:]
rows = {}
for line in open(os.path.join(work, "targets.final")):
    p = line.rstrip("\n").split("\t")
    rows.setdefault(p[0], p)
for host in hosts:
    row = rows.get(host, [])
    eng = row[2] if len(row) > 2 else ""
    if eng in ("", "-"):
        continue
    d = os.path.join(work, "jobs", host)
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        if not os.path.isfile(path):
            continue
        lines = override_lines(open(path).read().splitlines(), "ioengine", eng)
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
