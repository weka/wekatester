function idx(p,   a) { split(p, a, "."); return a[2] }
$1 ~ /^client_stats\.[0-9]+\.jobname$/ { job[idx($1)] = $2; order[++n] = idx($1) }
$1 ~ /^client_stats\.[0-9]+\.hostname$/ { host[idx($1)] = $2 }
$1 ~ /^client_stats\.[0-9]+\.error$/ { err[idx($1)] = $2 }
# anything a direction moved -- ios, bytes, or (older fio) only a rate
$1 ~ /^client_stats\.[0-9]+\.(read|write|trim)\.(total_ios|io_bytes|bw_bytes)$/ { moved[idx($1)] += $2 }
END {
    for (k = 1; k <= n; k++) {
        i = order[k]
        if (job[i] == "All clients") continue
        stats++
        e = err[i] + 0
        if (e) { h = (i in host) ? host[i] : job[i]; printf "E\t%s\t%s\t%d\n", h, job[i], e; anybad = 1 }
        h = (i in host) ? host[i] : job[i]; last[h] = i; hosts[h] = 1
    }
    if (!stats) { print "NONE"; exit }
    if (mode == "measured" && !anybad)
        for (h in hosts) if (moved[last[h]] + 0 == 0) printf "Z\t%s\n", h | "LC_ALL=C sort"
}
