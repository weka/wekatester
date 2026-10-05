import sys

bad = []
for line in open(sys.argv[1]):
    p = line.rstrip("\n").split("\t")
    if len(p) < 12:
        continue
    sid, rep, engines, pinned, aio, pins = p[0], p[1], p[6].split(","), p[7], p[9], p[10]
    cands = [pinned] if pinned != "-" else engines
    if "libaio" not in cands or not aio.isdigit():
        continue
    for kv in pins.split():
        if "=" not in kv:
            continue
        slot, vals = kv.split("=", 1)
        q, n, f, j = (vals.split("/") + ["-"] * 4)[:4]
        if not (q.isdigit() or j.isdigit()):
            continue
        events = (int(j) if j.isdigit() else 1) * (int(q) if q.isdigit() else 1)
        if events > int(aio):
            bad.append("shape %s (%s): %s pinned at numjobs=%s iodepth=%s needs %d aio events at "
                       "once with libaio (%s), and the kernel has room for %s there "
                       "(fs.aio-max-nr less fs.aio-nr, as probed) -- raise fs.aio-max-nr, pin "
                       "another ioengine (-e or the host file), or change the pin"
                       % (sid, rep, slot, j if j.isdigit() else "1 (open)",
                          q if q.isdigit() else "1 (open)", events,
                          "pinned" if pinned == "libaio" else "one of the engines calibration tries",
                          aio))
for b in bad:
    print("ERROR: " + b, file=sys.stderr)
sys.exit(2 if bad else 0)
