BEGIN {
    bulk = ARGV[1] == "1"; nn = 0
    for (a = 2; a < ARGC; a++) {
        name = ARGV[a]; sub(/.*\//, "", name)
        if ((n = readlines(ARGV[a], L)) < 0) awk_fail("cal_required: cannot read " ARGV[a])
        if (name == layout_job() || is_layout_marked(L, n)) continue   # a layout job measures nothing
        file_directions(L, n, D)
        if (report_has(L, n, "latency")) {
            # a 1MiB latency file is its own search (lat1m), and under
            # -b every 4k latency file gains a 1MiB twin at staging
            kind = lat_kind(L, n)
            for (d in D) {
                NEED[kind " " d] = 1
                if (bulk && kind == "lat") NEED["lat1m " d] = 1
            }
            continue
        }
        for (d in D) {
            if (report_has(L, n, "bandwidth")) NEED["bw " d] = 1
            if (report_has(L, n, "iops")) NEED["iops " d] = 1
        }
    }
    for (k in NEED) OUT[++nn] = k
    sort_arr(OUT, nn, 0)
    for (i = 1; i <= nn; i++) print OUT[i]
}
