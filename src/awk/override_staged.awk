BEGIN {
    which = ARGV[2]; nk = 0
    for (a = 3; a + 1 < ARGC; a += 2) { K[++nk] = ARGV[a]; V[nk] = ARGV[a + 1] }
    if ((m = readlines(ARGV[1], M)) < 0) awk_fail("cannot read " ARGV[1])
    for (i = 1; i <= m; i++) {
        split(M[i], F, "\t")
        if (F[2] == "") continue
        if ((n = readlines(F[2], L)) < 0) awk_fail("cannot read " F[2])
        if (which == "measured") {
            job = F[2]; sub(/.*\//, "", job)
            if (job == layout_job() || is_layout_marked(L, n)) continue
        }
        for (k = 1; k <= nk; k++) n = override_lines(L, n, K[k], V[k])
        writelines(F[2], L, n)
    }
}
