import os, re, sys

d, layout_job, marker = sys.argv[1:4]
made = []
for name in sorted(os.listdir(d)):
    path = os.path.join(d, name)
    if not name[:1].isdigit() or not os.path.isfile(path) or name == layout_job:
        continue
    lines = open(path).read().splitlines()
    if any(l.startswith(marker) for l in lines[:3]):
        continue
    words = [w for l in lines for m in [re.match(r"^#\s*report\s+(.*)$", l)] if m
             for w in m.group(1).split()]
    if "latency" not in words or job_bs(lines) >= (1 << 20):
        continue
    twin = re.sub(r"^(\d+)", r"\1b", name)
    twin = twin[:-4] + "-1M.job" if twin.endswith(".job") else twin + "-1M"
    if os.path.exists(os.path.join(d, twin)):
        sys.exit(f"ERROR: -b: the set already has a file named {twin}")
    has_bs = any(re.match(r"^(bs|blocksize)=", l) for l in lines)
    out = [re.sub(r"^(bs|blocksize)=.*$", r"\1=1Mi", l) for l in lines]
    if not has_bs:
        out = override_lines(out, "bs", "1Mi")
    out = [f"# -b: the 1MiB twin of {name}, staged by wekatester"] + out
    with open(os.path.join(d, twin), "w") as fh:
        fh.write("\n".join(out) + "\n")
    made.append(twin)
print(" ".join(made))
