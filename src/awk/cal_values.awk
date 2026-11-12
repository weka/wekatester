function idx(p,   a) { split(p, a, "."); return a[2] }
$1 ~ /^client_stats\.[0-9]+\.jobname$/ { job[idx($1)] = $2 }
$1 ~ /^client_stats\.[0-9]+\.hostname$/ { host[idx($1)] = $2 }
BEGIN { re = "^client_stats\\.[0-9]+\\.(read|write)\\." key "$" }
$1 ~ re { v[idx($1)] += $2 }
END {
    for (i in job) if (substr(job[i], 1, 4) == "cal-") {
        h = (i in host) ? host[i] : "?"; if (!(h in tot)) nh++; tot[h] += v[i]; any = 1 }
    if (!any) { printf "ERROR: cal_values: %s carries no cal job stats\n", path > "/dev/stderr"; exit 1 }
    # %.0f, not %d: Ubuntu mawk (1.3.4 20200120) clamps %d at
    # 2^31-1, and a client past ~2.1 GB/s then read 2147483647
    # a cell runs solo: one host, no sort process
    if (nh == 1) for (h in tot) printf "%s %.0f\n", h, tot[h]
    else for (h in tot) printf "%s %.0f\n", h, tot[h] | "LC_ALL=C sort"
}
