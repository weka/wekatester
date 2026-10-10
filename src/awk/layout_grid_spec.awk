# one layout jobfile: its spec lines into OUT[1..n] (n returned), and
# FA[1], whether a line reads exactly fallocate=none
function grid_spec(path, OUT, FA,    L, n, SN, KV, ns, s, fmt, fsz, size, nr, nj, glob, no, i) {
    if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
    ns = ini_parse(L, n, SN, KV); no = 0
    for (s = 1; s <= ns; s++) {
        fmt = ini_get(KV, s, "filename_format", ""); fsz = ini_get(KV, s, "filesize", "")
        if (fmt == "" || fsz == "") continue   # nothing statable without both; the fio run still covers it
        if ((size = parse_size(fsz)) == "") awk_fail(path ": [" SN[s] "]: filesize=" fsz " is not a byte count")
        nr = py_int(ini_get(KV, s, "nrfiles", "1")); nj = py_int(ini_get(KV, s, "numjobs", "1"))
        if (nr == "" || nj == "") awk_fail(path ": [" SN[s] "]: nrfiles and numjobs must be numbers")
        fmt = replace_all(fmt, "$jobname", SN[s])
        # a singleton counter is an exact component: with nrfiles=1,
        # $filenum/* would sweep the directories other sections of the
        # namespace own
        if (nr == 1) fmt = replace_all(fmt, "$filenum", "0")
        if (nj == 1) fmt = replace_all(fmt, "$jobnum", "0")
        glob = vars_to_glob(fmt)
        OUT[++no] = sprintf("%.0f\t%s\t%d\t%.0f", size, glob, 1 + count_char(glob, "/"), size * nr * nj)
    }
    FA[1] = 0
    for (i = 1; i <= n; i++) if (L[i] == "fallocate=none") FA[1] = 1
    return no
}
BEGIN {
    if (ARGV[1] != "-o") {
        no = grid_spec(ARGV[1], OUT, FA)
        for (k = 1; k <= no; k++) print OUT[k]
        exit 0
    }
    for (a = 3; a + 1 < ARGC; a += 2) {
        no = grid_spec(ARGV[a + 1], OUT, FA)
        f = path_join(ARGV[2], ARGV[a] ".gridspec")
        printf "" > f
        for (k = 1; k <= no; k++) print OUT[k] > f
        close(f)
        if (no && !FA[1]) print ARGV[a]
    }
}
