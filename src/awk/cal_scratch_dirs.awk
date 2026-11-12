BEGIN {
    pat = ARGV[1] ARGV[2] ARGV[3]
    if ((nj = py_int(ARGV[4])) == "" || (maxf = py_int(ARGV[5])) == "")
        awk_fail("cal_scratch_dirs: not a number: " ARGV[4] " " ARGV[5])
    n = 0
    for (j = 0; j < nj; j++)
        for (f = 0; f <= maxf; f++) {
            d = dirname(replace_all(replace_all(pat, "$jobnum", j), "$filenum", f))
            if (d != "" && !(d in seen)) { seen[d] = 1; D[++n] = d }
        }
    sort_arr(D, n, 0)
    for (i = 1; i <= n; i++) out = out (i > 1 ? "\n" : "") D[i]
    print out
}
