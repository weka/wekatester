BEGIN {
    if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
    for (i = 1; i <= n; i++) {   # the first row per host, as targets_field reads it
        split(L[i], F, "\t")
        if (!(F[1] in eng)) eng[F[1]] = F[3]
    }
    if ((m = readlines(ARGV[2], M)) < 0) awk_fail("cannot read " ARGV[2])
    for (i = 1; i <= m; i++) {
        split(M[i], F, "\t")
        e = (F[1] in eng) ? eng[F[1]] : ""
        if (e == "" || e == "-") continue
        if (F[2] == "") awk_fail(F[1] ": no staged jobfiles")
        if ((n = readlines(F[2], L)) < 0) awk_fail("cannot read " F[2])
        n = override_lines(L, n, "ioengine", e)
        writelines(F[2], L, n)
    }
}
