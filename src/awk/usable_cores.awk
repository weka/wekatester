BEGIN {
    path = ARGV[1]
    if ((np = readlines(path, P)) < 0) np = 0
    probe_cores(P, np, ARGV[3], R, PHYS, ALL)
    if (R["n"] < 1) awk_fail("usable_cores: " path " leaves fio no cpus: " cores_summary(R, PHYS, ALL))
    if (ARGV[2] == "list") print join_sorted(ALL, ",")
    else if (ARGV[2] == "phys") print join_sorted(PHYS, ",")
    else print R["n"]
}
