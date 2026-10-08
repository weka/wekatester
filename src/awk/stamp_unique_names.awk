function stamp(path, name, cpus,    L, n, O, m, i, k, s, hasfmt, hascpus, haspol, INS, ni, g) {
    if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
    hasfmt = 0
    for (i = 1; i <= n; i++) if (index(strip(L[i]), "filename_format=") == 1) hasfmt = 1
    m = 0
    for (i = 1; i <= n; i++) {
        s = strip(L[i])
        if (index(s, "filename_format=") == 1) {
            if (!index(substr(s, 17), "$clientuid") && index(substr(s, 17), "shared.") != 1)
                L[i] = "filename_format=" name "." substr(s, 17)
        } else if (index(s, "unique_filename=") == 1)
            continue   # replaced by the forced 0 below
        O[++m] = L[i]
    }
    hascpus = 0; haspol = 0
    for (i = 1; i <= m; i++) {
        s = strip(O[i])
        if (index(s, "cpus_allowed=") == 1) hascpus = 1
        if (index(s, "cpus_allowed_policy=") == 1) haspol = 1
    }
    ni = 0; INS[++ni] = "unique_filename=0"
    if (!hasfmt) INS[++ni] = "filename_format=" name ".$jobname.$jobnum.$filenum"
    if (cpus != "" && !hascpus) { INS[++ni] = "cpus_allowed=" cpus; hascpus = 1 }
    if (hascpus && !haspol) INS[++ni] = "cpus_allowed_policy=split"
    g = 0
    for (i = 1; i <= m && !g; i++) if (strip(O[i]) == "[global]") g = i
    split("", L); n = 0
    if (!g) {
        L[++n] = "[global]"
        for (k = 1; k <= ni; k++) L[++n] = INS[k]
    }
    for (i = 1; i <= m; i++) {
        L[++n] = O[i]
        if (i == g) for (k = 1; k <= ni; k++) L[++n] = INS[k]
    }
    writelines(path, L, n)
}
BEGIN {
    for (a = 2; a + 2 < ARGC; a += 3) {
        NAME[ARGV[a]] = ARGV[a + 1]
        CPUS[ARGV[a]] = ARGV[a + 2] == "-" ? "" : ARGV[a + 2]
    }
    if ((m = readlines(ARGV[1], M)) < 0) awk_fail("cannot read " ARGV[1])
    for (i = 1; i <= m; i++) {
        split(M[i], F, "\t")
        if (F[2] == "") awk_fail(F[1] ": no staged jobfiles")
        stamp(F[2], NAME[F[1]], CPUS[F[1]])
    }
}
