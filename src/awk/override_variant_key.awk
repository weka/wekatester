BEGIN {
    if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
    n = override_lines(L, n, ARGV[2], ARGV[3])
    writelines(ARGV[1], L, n)
}
