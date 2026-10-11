BEGIN {   # the jobfiles naming no ioengine in any section
    for (a = 1; a < ARGC; a++) {
        if ((n = readlines(ARGV[a], L)) < 0) awk_fail("cannot read " ARGV[a])
        f = ARGV[a]; sub(/.*\//, "", f)
        if (first_value(L, n, "ioengine") == "") print f
    }
}
