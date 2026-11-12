# A set's own layout job, staged: every fallocate line set to none in place,
# and, when no line set none and [global] sets no fallocate, fallocate=none
# added as its first line ([global] made before the first section if none).
# Prints what changed for the NOTE; nothing when nothing did.
BEGIN {
    path = ARGV[1]
    if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
    g = 0; f = n + 1; sec = ""; none = 0; inglob = 0; set = 0
    for (i = 1; i <= n; i++) {
        if ((s = section_name(L[i])) != "") {
            if (f > n) f = i
            sec = strip(s); if (sec == "global" && !g) g = i
            continue
        }
        if (jf_key(L[i]) != "fallocate") continue
        if (sec == "global") inglob = 1
        if (jf_value(L[i]) == "none") none++
        else { L[i] = "fallocate=none"; set++ }
    }
    add = !none && !inglob
    if (!add && !set) exit 0
    no = 0
    for (i = 1; i <= n; i++) {
        if (add && !g && i == f) { O[++no] = "[global]"; O[++no] = "fallocate=none" }
        O[++no] = L[i]
        if (add && i == g) O[++no] = "fallocate=none"
    }
    if (add && !g && f > n) { O[++no] = "[global]"; O[++no] = "fallocate=none" }
    writelines(path, O, no)
    print (add ? "added" : "") (add && set ? " and " : "") (set ? "set in " set " line(s)" : "")
}
