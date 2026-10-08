BEGIN {
    if ((n = readlines(ARGV[1], R)) < 0) awk_fail("cannot read " ARGV[1])
    for (i = 1; i <= n; i++)
        if (split(R[i], F, " ") == 3 && F[3] == "ok") OK[F[1]] = OK[F[1]] " " F[2]
    for (a = 3; a < ARGC; a++) {
        h = ARGV[a]; p = ARGV[2] "/" h
        if ((m = readlines(p, L)) < 0) awk_fail("cannot read " p)
        for (i = 1; i <= m; i++) if (split(L[i], W, " ") && W[1] == "engines") L[i] = "engines" OK[h]
        writelines(p, L, m)
        if (OK[h] == "") print h
    }
}
