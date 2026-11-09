# A staged jobfile's longest timed section: runtime plus ramp_time, in
# seconds (fio's units: s default, ms, us, m, h, d), the longest section
# counted. Prints nothing when no section has a runtime (it runs to size).
function fio_secs(s,    v, u) {
    s = strip(s)
    if (s !~ /^[0-9]+(\.[0-9]+)?(us|ms|s|m|h|d)?$/) return ""
    match(s, /^[0-9]+(\.[0-9]+)?/); v = substr(s, 1, RLENGTH) + 0; u = substr(s, RLENGTH + 1)
    if (u == "us") return v / 1000000
    if (u == "ms") return v / 1000
    if (u == "m") return v * 60
    if (u == "h") return v * 3600
    if (u == "d") return v * 86400
    return v
}
BEGIN {
    if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
    ns = ini_parse(L, n, SN, KV); best = ""
    for (s = (ns ? 1 : "g"); s != ""; s = (s == "g" || s == ns ? "" : s + 1)) {
        rt = fio_secs(ini_get(KV, s, "runtime", "")); rp = fio_secs(ini_get(KV, s, "ramp_time", "0"))
        if (rt == "" || rp == "") continue
        if (best == "" || rt + rp > best) best = rt + rp
    }
    if (best != "") printf "%d\n", (best == int(best) ? best : int(best) + 1)
}
