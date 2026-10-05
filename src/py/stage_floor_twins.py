import os, re, sys

d, layout_job, marker = sys.argv[1:4]
made = []
for name in sorted(os.listdir(d)):
    path = os.path.join(d, name)
    if not name[:1].isdigit() or not os.path.isfile(path) or name == layout_job:
        continue
    lines = open(path).read().splitlines()
    if any(l.startswith(marker) for l in lines[:3]) or is_floor_twin(lines):
        continue
    words = [w for l in lines for m in [re.match(r"^#\s*report\s+(.*)$", l)] if m
             for w in m.group(1).split()]
    if "latency" not in words:
        continue
    twin = name[:-4] + "-1job.job" if name.endswith(".job") else name + "-1job"
    if os.path.exists(os.path.join(d, twin)):
        sys.exit(f"ERROR: the set already has a file named {twin}")
    out = [f"{FLOOR_MARKER} {name} at numjobs=iodepth=nrfiles=1 on every client, staged by wekatester"] + lines
    with open(os.path.join(d, twin), "w") as fh:
        fh.write("\n".join(out) + "\n")
    made.append(twin)
print(" ".join(made))
