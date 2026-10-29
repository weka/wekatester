BEGIN {   # <cal-dir> <basename> <push-dir> <host>...
    for (a = 4; a < ARGC; a++) {
        src = ARGV[1] "/" ARGV[a] "/" ARGV[2]
        if ((n = readlines(src, L)) < 0) awk_fail("cannot read " src)
        writelines(ARGV[3] "/" ARGV[a] "/" ARGV[2], L, n)
    }
}
