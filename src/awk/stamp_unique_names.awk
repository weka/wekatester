# A jobfile's own cpu list against the host's fio cpus (auth/<host>.cpus):
# "" when inside them as written, else the line canonical (blanks dropped, or
# trimmed with a note); nothing left stops. The whole value: fio reads
# "2-5, 7" as 2-5 and 7 (atoi per item), and py_int strips each item too.
function trim_cpus(host, path, s, cpus,    v, w, job, REQ, EFF, RUN, c, run) {
    v = jf_value(s); w = v
    gsub(/[ \t\n\013\014\r\034\035\036\037]+/, "", w)
    job = path; sub(/.*\//, "", job)
    parse_cpulist(cpus, EFF)
    if (!parse_cpulist(v, REQ) || !set_any(REQ))
        awk_fail(host ": jobfile " job ": cpus_allowed (" v ") is not a cpu list, so it cannot be held to this host\047s fio cpus (" cpus ")")
    for (c in REQ) if (c in EFF) RUN[c] = 1
    if (!set_any(RUN))
        awk_fail(host ": jobfile " job ": cpus_allowed (" v ") names no cpu fio may use on this host (" cpus ") -- list cpus within it, or drop the line and staging fills it in")
    if (set_size(RUN) == set_size(REQ)) return w == v ? "" : "cpus_allowed=" w
    run = fmt_cpulist(RUN)
    print "note: " host ": jobfile " job ": cpus_allowed (" v ") includes cpus outside this host\047s fio cpus (" cpus "); executing on the remainder (" run ")" > "/dev/stderr"
    return "cpus_allowed=" run
}
function stamp(path, name, cpus, host,    L, n, O, m, i, k, s, t, v, hasfmt, hascpus, haspol, INS, ni, g) {
    if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
    hasfmt = 0; hascpus = 0; haspol = 0; g = 0; m = 0
    for (i = 1; i <= n; i++) {
        s = strip(L[i]); k = jf_key(s)
        if (k == "filename_format") {
            hasfmt = 1; v = jf_value(s)
            if (!index(v, "$clientuid") && index(v, "shared.") != 1)
                L[i] = "filename_format=" name "." v
        } else if (k == "unique_filename")
            continue   # replaced by the forced 0 below
        else if (k == "cpus_allowed") {
            # every one, in any section: fio never runs on weka's cores or
            # core 0's pair, whatever a cpu list says
            hascpus = 1
            if (cpus != "" && (t = trim_cpus(host, path, s, cpus)) != "") L[i] = t
        }
        O[++m] = L[i]
        if (k == "cpus_allowed_policy") haspol = 1
        if (!g && s == "[global]") g = m
    }
    ni = 0; INS[++ni] = "unique_filename=0"
    if (!hasfmt) INS[++ni] = "filename_format=" name ".$jobname.$jobnum.$filenum"
    if (cpus != "" && !hascpus) { INS[++ni] = "cpus_allowed=" cpus; hascpus = 1 }
    if (hascpus && !haspol) INS[++ni] = "cpus_allowed_policy=split"
    split("", L); n = 0
    if (!g) {
        L[++n] = "[global]"
        for (k = 1; k <= ni; k++) L[++n] = INS[k]
    }
    for (i = 1; i <= m; i++) {
        L[++n] = O[i]
        if (i == g) for (k = 1; k <= ni; k++) L[++n] = INS[k]
    }
    writelines(path, L, n)
}
BEGIN {
    for (a = 2; a + 2 < ARGC; a += 3) {
        NAME[ARGV[a]] = ARGV[a + 1]
        CPUS[ARGV[a]] = ARGV[a + 2] == "-" ? "" : ARGV[a + 2]
    }
    if ((m = readlines(ARGV[1], M)) < 0) awk_fail("cannot read " ARGV[1])
    for (i = 1; i <= m; i++) {
        split(M[i], F, "\t")
        if (F[2] == "") awk_fail(F[1] ": no staged jobfiles")
        stamp(F[2], NAME[F[1]], CPUS[F[1]], F[1])
    }
}
