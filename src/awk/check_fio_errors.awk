# client_stats.<i>.<leaf>: the index and leaf cut out once per line, not
# four regexes run on each (a layout result is millions of lines)
index($1, "client_stats.") != 1 { next }
{
    k = substr($1, 14); p = index(k, ".")
    if (!p || (i = substr(k, 1, p - 1)) !~ /^[0-9]+$/) next
    f = substr(k, p + 1)
    if (f == "jobname") { job[i] = $2; order[++n] = i }
    else if (f == "hostname") host[i] = $2
    else if (f == "error") err[i] = $2
    # anything a direction moved -- ios, bytes, or (older fio) only a rate
    else if (f ~ /^(read|write|trim)\.(total_ios|io_bytes|bw_bytes)$/) moved[i] += $2
}
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
