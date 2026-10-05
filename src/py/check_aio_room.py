import os, sys

work, hosts = sys.argv[1], sys.argv[2:]
over = {}
for h in hosts:
    room = probe_aio_room(os.path.join(work, "probe", h))
    d = os.path.join(work, "jobs", h)
    if room is None or not os.path.isdir(d):
        continue
    for job in sorted(os.listdir(d)):
        p = os.path.join(d, job)
        if os.path.isfile(p):
            n = libaio_events(open(p).read().splitlines())
            if n > room:
                over.setdefault((job, n, room), []).append(h)
for (job, n, room), hs in sorted(over.items()):
    names = " ".join(hs[:8]) + (" (+%d more)" % (len(hs) - 8) if len(hs) > 8 else "")
    print("ERROR: %s: libaio sets up %d aio events at once (numjobs x iodepth) on %s, "
          "and the kernel has room for %d (fs.aio-max-nr less fs.aio-nr, as probed): the "
          "jobs past the room would fail io_queue_init with EAGAIN (fio error 11) -- raise "
          "fs.aio-max-nr, run another ioengine (-e or the host file), or lower the job's "
          "numjobs x iodepth" % (job, n, names, room), file=sys.stderr)
sys.exit(2 if over else 0)
