# A staged jobfile, by mode (ARGV[2]): "secs" (default) its longest timed
# section, runtime plus ramp_time in seconds (fio units: s default, us, ms,
# m, h, d), nothing when no section has a runtime (it runs to size);
# "files" the files its sections write (numjobs x nrfiles); "bytes" those
# files' bytes (filesize, else size).
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
    mode = ARGC > 2 ? ARGV[2] : "secs"
    if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
    ns = ini_parse(L, n, SN, KV); best = ""; files = 0; bytes = 0
    for (s = (ns ? 1 : "g"); s != ""; s = (s == "g" || s == ns ? "" : s + 1)) {
        if (mode != "secs") {
            nj = py_int(ini_get(KV, s, "numjobs", "1")); nr = py_int(ini_get(KV, s, "nrfiles", "1"))
            if (nj == "" || nr == "") continue
            fs = ini_get(KV, s, "filesize", ini_get(KV, s, "size", "0")); b = parse_size(fs)
            files += nj * nr; bytes += nj * nr * (b == "" ? 0 : b)
            continue
        }
        rt = fio_secs(ini_get(KV, s, "runtime", "")); rp = fio_secs(ini_get(KV, s, "ramp_time", "0"))
        if (rt == "" || rp == "") continue
        if (best == "" || rt + rp > best) best = rt + rp
    }
    if (mode == "files") printf "%d\n", files
    else if (mode == "bytes") printf "%.0f\n", bytes
    else if (best != "") printf "%d\n", (best == int(best) ? best : int(best) + 1)
}
