BEGIN {
    for (i = 1; i < ARGC; i++) {
        if ((n = readlines(ARGV[i], L)) < 0 || is_layout_marked(L, n)) continue
        fmt = first_value(L, n, "filename_format")
        if (index(fmt, "$filenum") && index(fmt, "$jobnum") && !index(fmt, "$jobname")) {
            print "unified", fmt
            exit 0
        }
    }
    print "scratch", "$jobnum.$filenum"
}
