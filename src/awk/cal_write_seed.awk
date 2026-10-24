# A job section's own key else [global]'s, rw= and readwrite= one key; ""
# for none (fio then reads)
function sec_rw(KV, s,    v) {
    if ((s, "rw") in KV) return KV[s, "rw"]
    if ((s, "readwrite") in KV) return KV[s, "readwrite"]
    if (("g", "rw") in KV) return KV["g", "rw"]
    return (("g", "readwrite") in KV) ? KV["g", "readwrite"] : ""
}
# why section s is not one pure sequential write, "" when it is: rw=write
# without a ":<n>" skip, no random share, no verify read-back, no zone skip
function not_seq(KV, s,    v) {
    v = tolower(strip(sec_rw(KV, s)))
    if (v != "write") return "rw=" (v == "" ? " (fio reads)" : v)
    v = strip(ini_get(KV, s, "percentage_random", "0"))
    if (v !~ /^0(,0)*$/) return "percentage_random=" v
    v = strip(ini_get(KV, s, "percentage_sequential", "100"))
    if (v !~ /^100(,100)*$/) return "percentage_sequential=" v
    v = tolower(strip(ini_get(KV, s, "verify", "0")))
    if (v != "0" && v != "none") return "verify=" v " reads it back"
    v = strip(ini_get(KV, s, "zoneskip", "0"))
    if (v !~ /^0+[a-zA-Z]*$/) return "zoneskip=" v
    return ""
}
# Unified -a: may the write grid <host>.<fmt> (ARGV[1]) be seeded sparse?
# Only when every job writing it is a pure sequential write and no
# calibration cell writes it at random (README, Seeding). Prints "sparse",
# else "dense <why>".
BEGIN {
    fmt = ARGV[1]
    for (a = 2; a < ARGC; a++) {
        f = ARGV[a]; sub(/.*\//, "", f)
        if ((n = readlines(ARGV[a], L)) < 0) awk_fail("cannot read " ARGV[a])
        if (f == layout_job() || is_layout_marked(L, n)) continue
        file_directions(L, n, D)
        # a read-only jobfile reads the shared set (stage_hosts)
        if (!("write" in D) && ("read" in D)) continue
        if ("write" in D) {
            if (report_has(L, n, "latency")) { print "dense " f ": its latency write search writes at random"; exit }
            if (report_has(L, n, "iops")) { print "dense " f ": its iops write search writes at random"; exit }
        }
        nsec = job_sections(L, n, SN, KV, J)
        for (x = 1; x <= nsec; x++) {
            s = J[x]
            if (replace_all(sec_value(L, n, KV, s, "filename_format", ""), "$jobname", sec_jobname(L, n, SN, s, f)) != fmt) continue
            if ((why = not_seq(KV, s)) != "") { print "dense " f (s == "g" ? "" : " [" SN[s] "]") ": " why; exit }
        }
    }
    print "sparse"
}
