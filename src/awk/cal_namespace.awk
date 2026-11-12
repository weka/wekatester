BEGIN {
    for (i = 1; i < ARGC; i++) {
        name = ARGV[i]; sub(/.*\//, "", name)
        # a layout job, by its name or its marker, is no test's namespace
        if (name == layout_job() || (n = readlines(ARGV[i], L)) < 0 || is_layout_marked(L, n)) continue
        fmt = first_value(L, n, "filename_format")
        if (index(fmt, "$filenum") && index(fmt, "$jobnum") && !index(fmt, "$jobname")) {
            print "unified", fmt
            exit 0
        }
    }
    print "scratch", "$jobnum.$filenum"
}
