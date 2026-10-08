function idx(p,   a) { split(p, a, "."); return a[2] }
$1 ~ /^client_stats\.[0-9]+\.jobname$/ { job[idx($1)] = $2; order[++n] = idx($1) }
$1 ~ /^client_stats\.[0-9]+\.hostname$/ { host[idx($1)] = $2 }
$1 ~ ("^client_stats\\.[0-9]+\\." d "\\.lat_ns\\.mean$") { lat[idx($1)] = $2 }
$1 ~ ("^client_stats\\.[0-9]+\\." d "\\.total_ios$") { ios[idx($1)] = $2 }
$1 ~ ("^client_stats\\.[0-9]+\\." d "\\.iops$") { iops[idx($1)] = $2 }
END {
    # entries in file order: the first per host seeds, the rest fold in by IO count
    for (k = 1; k <= n; k++) {
        i = order[k]
        if (substr(job[i], 1, 4) != "cal-") continue
        h = (i in host) ? host[i] : "?"
        us = lat[i] / 1000.0; io = ios[i] + 0; ip = iops[i] + 0
        if (!(h in seen)) { seen[h] = 1; L[h] = us; I[h] = ip; N[h] = io; continue }
        t = N[h] + io
        if (t > 0) L[h] = (L[h] * N[h] + us * io) / t
        I[h] += ip; N[h] = t
    }
    for (h in seen) { any = 1; printf "%s %.3f %.0f\n", h, L[h], I[h] | "LC_ALL=C sort" }
    if (!any) { printf "ERROR: cal_lat_values: %s carries no cal job stats\n", path > "/dev/stderr"; exit 1 }
}
