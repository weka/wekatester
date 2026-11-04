# A set's own layout job, staged: unless a line sets fallocate=none, add it
# as the first line under [global] ([global] made before the first section
# when there is none) and print "added". The file is rewritten in place.
BEGIN {
    path = ARGV[1]
    if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
    for (i = 1; i <= n; i++) if (jf_key(L[i]) == "fallocate" && jf_value(L[i]) == "none") exit 0
    g = 0; f = n + 1
    for (i = n; i >= 1; i--) if ((s = section_name(L[i])) != "") { f = i; if (strip(s) == "global") g = i }
    no = 0
    for (i = 1; i <= n; i++) {
        if (!g && i == f) { O[++no] = "[global]"; O[++no] = "fallocate=none" }
        O[++no] = L[i]
        if (i == g) O[++no] = "fallocate=none"
    }
    if (!g && f > n) { O[++no] = "[global]"; O[++no] = "fallocate=none" }
    writelines(path, O, no)
    print "added"
}
