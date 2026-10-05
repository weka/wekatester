import os, re, sys

src, bulk = sys.argv[1], sys.argv[2] == "1"
if not os.path.isdir(src):
    sys.exit(f"ERROR: cal_required: not a jobfile set directory: {src}")

# Layout-job rule, same as is_layout_file/generate_layout -- keep in sync.
MARKER = "# wekatester-layout: generated"
NAME = "000-wekatester-layout.job"

def report_items(lines):
    """Directive items, by the same rule as report_directive() in the bash
    layer: whitespace after 'report' is required, so a prose comment is not a
    directive and a bare '# report' names nothing. Several directive lines
    accumulate. Empty list = the file carries no directive."""
    items = []
    for line in lines:
        m = re.match(r"^#\s*report\s+(.*)", line)
        if m: items += m.group(1).split()
    return items

needed = set()
for f in sorted(os.listdir(src)):
    if not re.match(r"^[0-9]", f): continue
    path = os.path.join(src, f)
    if not os.path.isfile(path): continue
    lines = open(path).read().splitlines()
    if f == NAME or any(l.startswith(MARKER) for l in lines[:3]):
        continue   # a layout job measures nothing
    items = report_items(lines)
    if "latency" in items:
        # latency runs at qd1 by definition; what is searched is how many
        # jobs keep it at the floor, per direction the file uses. A 1MiB
        # latency file is its own search (lat1m), and under -b every 4k
        # latency file gains a 1MiB twin at staging, so it needs one too.
        kind = lat_kind(lines)
        for d in file_directions(lines):
            needed.add(f"{kind} {d}")
            if bulk and kind == "lat":
                needed.add(f"lat1m {d}")
        continue
    types = []
    if "bandwidth" in items or not items: types.append("bw")
    if "iops" in items: types.append("iops")
    for t in types:
        for d in file_directions(lines):
            needed.add(f"{t} {d}")

for line in sorted(needed):
    print(line)
