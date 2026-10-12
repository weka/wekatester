BEGIN {
    band = ARGV[2] + 0
    if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cal_engine_pick: cannot read " ARGV[1])
    for (i = 1; i <= n; i++) {
        if (pysplit(L[i], F) < 3) continue
        t = F[1]; any = 1
        C[t, ++CN[t]] = F[2]; V[t, CN[t]] = F[3] + 0
    }
    if (!any) awk_fail("cal_engine_pick: no engine cells in " ARGV[1])
    no = split(engine_order(), O, " ")
    for (j = 1; j <= no; j++) RANK[O[j]] = j - 1
    split("bw iops lat", TY, " "); said = ""; nt = 0
    for (x = 1; x <= 3; x++) {
        t = TY[x]
        if (!(m = CN[t] + 0)) continue
        ext = V[t, 1]   # the best reading: lowest for latency
        for (i = 2; i <= m; i++) if (t == "lat" ? V[t, i] < ext : V[t, i] > ext) ext = V[t, i]
        show = ""; win = ""
        for (i = 1; i <= m; i++) {
            e = C[t, i]; v = V[t, i]
            show = show (i > 1 ? ", " : "") (t == "lat" ? sprintf("%s %.1f us", e, v) : t == "bw" ? sprintf("%s %.2f GiB/s", e, v / 1073741824) : e " " commas(v))
            r = (e in RANK) ? RANK[e] : no
            # the best is always inside its own band, whatever rounding
            # says (band 100)
            if ((v == ext || (t == "lat" ? v <= ext * (2 - band / 100) : v >= ext * band / 100)) && (win == "" || r < wr)) { win = e; wr = r }
        }
        if (!(win in TALLY)) TORD[++nt] = win
        TALLY[win]++
        said = said (said == "" ? "" : "; ") t ": " show " -> " win
    }
    print pick_engine(TALLY, TORD, nt), said
}
