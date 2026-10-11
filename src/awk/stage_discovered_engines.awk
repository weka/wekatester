BEGIN {   # prints each host that has a discovered engine
    if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
    for (i = 1; i <= n; i++) if (split(L[i], F, " ") == 2) eng[F[1]] = F[2]
    if ((m = readlines(ARGV[2], M)) < 0) awk_fail("cannot read " ARGV[2])
    for (i = 1; i <= m; i++) {
        split(M[i], F, "\t")
        if (!(F[1] in eng)) continue
        if (F[2] == "") awk_fail(F[1] ": no staged jobfiles")
        if (!(F[1] in seen)) { seen[F[1]] = 1; print F[1] }
        if ((n = readlines(F[2], L)) < 0) awk_fail("cannot read " F[2])
        if (first_value(L, n, "ioengine") != "") continue   # the jobfile's own
        n = override_lines(L, n, "ioengine", eng[F[1]])
        writelines(F[2], L, n)
    }
}
