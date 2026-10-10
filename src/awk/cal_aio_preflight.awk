BEGIN {
    if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
    bad = 0
    for (i = 1; i <= n; i++) {
        if (lsplit(L[i], P, "\t") < 12) continue
        pinned = P[8]; aio = P[10]; lib = pinned == "libaio"
        if (pinned == "-") { m = lsplit(P[7], E, ","); for (k = 1; k <= m; k++) if (E[k] == "libaio") lib = 1 }
        if (!lib || aio !~ /^[0-9]+$/) continue
        m = pysplit(P[11], W)
        for (k = 1; k <= m; k++) {
            if (!(e = index(W[k], "="))) continue
            nv = lsplit(substr(W[k], e + 1), V, "/")
            q = V[1]; j = nv >= 4 ? V[4] : "-"
            if (q !~ /^[0-9]+$/ && j !~ /^[0-9]+$/) continue
            ev = (j ~ /^[0-9]+$/ ? j : 1) * (q ~ /^[0-9]+$/ ? q : 1)
            if (ev <= aio + 0) continue
            bad = 1
            if (j !~ /^[0-9]+$/) j = "1 (open)"
            if (q !~ /^[0-9]+$/) q = "1 (open)"
            how = pinned == "libaio" ? "pinned" : "one of the engines calibration tries"
            printf "ERROR: shape %s (%s): %s pinned at numjobs=%s iodepth=%s needs %.0f aio events at once with libaio (%s), and the kernel has room for %s there (fs.aio-max-nr less fs.aio-nr, as probed) -- raise fs.aio-max-nr, pin another ioengine (-e or the host file), or change the pin\n", P[1], P[2], substr(W[k], 1, e - 1), j, q, ev, how, aio > "/dev/stderr"
        }
    }
    exit bad ? 3 : 0   # not 2: an awk that dies on its own exits 2
}
