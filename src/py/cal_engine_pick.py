import sys

path, band = sys.argv[1], float(sys.argv[2])
rank = dict((e, i) for i, e in enumerate(ENGINE_ORDER))
cells = {}
for line in open(path):
    p = line.split()
    if len(p) >= 3:
        cells.setdefault(p[0], []).append((p[1], float(p[2])))
if not cells:
    sys.exit("ERROR: cal_engine_pick: no engine cells in %s" % path)
tally, said = {}, []
for t in ("bw", "iops", "lat"):
    got = cells.get(t)
    if not got:
        continue
    if t == "lat":
        low = min(v for e, v in got)
        near = [e for e, v in got if v <= low * (2 - band / 100)]
        show = ", ".join("%s %.1f us" % (e, v) for e, v in got)
    else:
        top = max(v for e, v in got)
        near = [e for e, v in got if v >= top * band / 100]
        show = ", ".join("%s %s" % (e, ("%.2f GiB/s" % (v / float(1 << 30))) if t == "bw"
                                    else format(int(v), ",")) for e, v in got)
    win = min(near, key=lambda e: rank.get(e, len(ENGINE_ORDER)))
    tally[win] = tally.get(win, 0) + 1
    said.append("%s: %s -> %s" % (t, show, win))
print(pick_engine(tally), "; ".join(said))
