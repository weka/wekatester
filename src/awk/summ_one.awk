function fb(n) { if (n >= 2^40) return sprintf("%.2f TiB/s", n / 2^40); if (n >= 2^30) return sprintf("%.2f GiB/s", n / 2^30)
                 if (n >= 2^20) return sprintf("%.2f MiB/s", n / 2^20); if (n >= 2^10) return sprintf("%.2f KiB/s", n / 2^10); return sprintf("%.0f bytes/s", n) }
function fl(ns) { if (ns >= 1e9) return sprintf("%.1f s", ns / 1e9); if (ns >= 1e6) return sprintf("%.1f ms", ns / 1e6)
                  if (ns >= 1e3) return sprintf("%.1f us", ns / 1e3); return sprintf("%.0f ns", ns) }
function fi(n,   s, r) { s = sprintf("%.0f", n); r = ""; while (length(s) > 3) { r = "," substr(s, length(s) - 2) r; s = substr(s, 1, length(s) - 3) } return s r "/s" }
# the FIRST missing value names the error: the direction when absent,
# else the leaf key
function val(i, k,   kk, n) {
    if ((i "." k) in v) return v[i "." k]
    if (missing == "") { n = split(k, kk, "."); missing = ((i "." kk[1]) in dirhas) ? kk[n] : kk[1] }
    return 0 }
# per-host min and max of metric m ("bw", "iops", "lat.read", "lat.write"), when they differ
function spread(m, kind,   h, x, lo, hi, loh, hih, first) {
    if (nh < 2) return ""
    first = 1
    for (h in hosts) {
        i = last[h]
        if (m == "bw") x = val(i, "read.bw_bytes") + val(i, "write.bw_bytes")
        else if (m == "iops") x = val(i, "read.iops") + val(i, "write.iops")
        else x = val(i, substr(m, 5) ".lat_ns.mean")
        if (first || x < lo || (x == lo && h < loh)) { lo = x; loh = h }
        if (first || x > hi || (x == hi && h > hih)) { hi = x; hih = h }
        first = 0
    }
    if (lo == hi) return ""
    if (kind == "bw") return "  (min " fb(lo) " " loh ", max " fb(hi) " " hih ")"
    if (kind == "iops") return "  (min " fi(lo) " " loh ", max " fi(hi) " " hih ")"
    return "  (min " fl(lo) " " loh ", max " fl(hi) " " hih ")"
}
# only the leaves val() reads are kept: an entry has ~240
BEGIN { split("read.bw_bytes write.bw_bytes read.iops write.iops read.lat_ns.mean write.lat_ns.mean read.total_ios write.total_ios", kk, " "); for (j in kk) READS[kk[j]] = 1 }
$1 ~ /^client_stats\.[0-9]+\./ {
    n = split($1, a, "."); i = a[2]; k = a[3]
    for (j = 4; j <= n; j++) k = k "." a[j]
    if (i > maxi) maxi = i
    if (k == "jobname") job[i] = $2
    else if (k == "hostname") host[i] = $2
    else {
        if (a[3] == "read" || a[3] == "write") dirhas[i "." a[3]] = 1
        if (k in READS) v[i "." k] = $2 + 0
    }
    seen[i] = 1
}
END {
    for (i = 0; i <= maxi; i++) {
        if (!(i in seen)) continue
        if (job[i] == "All clients") { alls = i; hasall = 1; continue }
        h = (i in host) ? host[i] : ((i in job) ? job[i] : "?")
        if (!(h in hosts)) { hosts[h] = 1; nh++ }
        last[h] = i
    }
    if (!hasall) {
        if (nh == 1) { for (h in hosts) alls = last[h] }
        else { printf "ERR\t%s: no %sAll clients%s aggregate found\n", label, "\047", "\047"; exit }
    }
    if (expected != "") {
        n = split(expected, ex, " "); miss = ""; nm = 0
        for (j = 1; j <= n; j++) if (ex[j] != "" && !(ex[j] in hosts)) { miss = miss (nm ? ", " : "") ex[j]; nm++ }
        if (nm) { printf "ERR\t%s: no results from %d of %d host(s): %s\n", label, nm, n, miss; exit }
    }
    nl = 0; missing = ""
    if (index(items, " bandwidth ")) {
        r = val(alls, "read.bw_bytes"); w = val(alls, "write.bw_bytes")
        if (r) L[++nl] = "read bandwidth: " fb(r)
        if (w) L[++nl] = "write bandwidth: " fb(w)
        if (r && w) L[++nl] = "total bandwidth: " fb(r + w)
        if (r || w) L[++nl] = "average bandwidth: " fb(nh ? (r + w) / nh : 0) " per host" spread("bw", "bw")
    }
    if (index(items, " iops ")) {
        r = val(alls, "read.iops"); w = val(alls, "write.iops")
        if (r) L[++nl] = "read iops: " fi(r)
        if (w) L[++nl] = "write iops: " fi(w)
        if (r && w) L[++nl] = "total iops: " fi(r + w)
        if (r || w) L[++nl] = "average iops: " fi(nh ? (r + w) / nh : 0) " per host" spread("iops", "iops")
    }
    if (index(items, " latency ")) {
        rl = val(alls, "read.lat_ns.mean"); if (rl) L[++nl] = "read latency: " fl(rl) spread("lat.read", "lat")
        wl = val(alls, "write.lat_ns.mean"); if (wl) L[++nl] = "write latency: " fl(wl) spread("lat.write", "lat")
        ri = val(alls, "read.total_ios"); wi = val(alls, "write.total_ios")
        if (rl && wl && (ri + wi)) L[++nl] = "average latency: " fl((rl * ri + wl * wi) / (ri + wi)) " (IO-weighted)"
    }
    if (missing != "") { printf "ERR\t%s: not the fio JSON layout this summary reads: KeyError(%s%s%s)\n", label, "\047", missing, "\047"; exit }
    if (!nl) L[++nl] = "(no non-zero metrics to report)"
    for (j = 1; j <= nl; j++) print "    " L[j]
}
