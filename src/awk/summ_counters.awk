# One capture into C[name] = value (digits only); returns the count, and
# WHY the first "not available" or "(... exited N)" line when it holds none
function load(kind, path,    L, n, i, F, m, k, pre, sect, nm, v, c) {
    split("", C); c = 0; WHY = ""
    if ((n = readlines(path, L)) < 0) { WHY = "unreadable"; return 0 }
    sect = ""
    for (i = 1; i <= n; i++) {
        if (L[i] ~ /^not available/ || L[i] ~ /^\(.* exited [0-9]+\)$/) { if (WHY == "") WHY = L[i]; continue }
        if (kind == "tcp") {
            m = split(L[i], F, " ")
            if (m < 2 || substr(F[1], 1, 1) == "#") continue
            if (F[1] ~ /:$/) {
                # /proc/net/snmp and netstat: a header line, then its values
                pre = substr(F[1], 1, length(F[1]) - 1)
                if (F[2] !~ /^-?[0-9]+$/) { HN[pre] = m; for (k = 2; k <= m; k++) HDR[pre, k] = F[k]; continue }
                for (k = 2; k <= m && k <= HN[pre]; k++) if (F[k] ~ /^[0-9]+$/ && !((pre HDR[pre, k]) in GAUGE)) { C[pre HDR[pre, k]] = F[k]; c++ }
            } else if (F[2] ~ /^[0-9]+$/ && !(F[1] in GAUGE)) { C[F[1]] = F[2]; c++ }   # nstat: name value rate
        } else if (kind == "aer") {
            if (L[i] ~ /^--- aer_dev_/) { sect = substr(L[i], 13); continue }
            if (split(L[i], F, " ") == 2 && F[2] ~ /^[0-9]+$/) { C[sect "." F[1]] = F[2]; c++ }
        } else if (match(L[i], /: *[0-9]+[ \t]*$/)) {
            # ethtool -S: "     name: value"
            nm = strip(substr(L[i], 1, RSTART - 1)); v = substr(L[i], RSTART + 1); gsub(/[ \t]/, "", v)
            if (nm != "") { C[nm] = v; c++ }
        }
    }
    return c
}
function out(line) { O[++no] = line }
function nr_counters(n) { return commas(n) (n == 1 ? " counter" : " counters") }
# one source of one host: what rose, what went down, against the start
function compare(label, kind, sp, ep,    ns, ne, nm, d, nr, nd, nshow, k, DN, ORD, nord) {
    if (sp == "" || ep == "") { out("  " label ": at the " (sp == "" ? "end" : "start") " only, so no delta"); flagged = 1; return }
    ns = load(kind, sp); split("", S); for (nm in C) S[nm] = C[nm]; ws = WHY
    ne = load(kind, ep)
    if (!ns || !ne) { out("  " label ": no counters at the " (!ns ? "start" : "end") " (" ((!ns ? ws : WHY) != "" ? (!ns ? ws : WHY) : "empty") ")"); flagged = 1; return }
    nr = 0; nd = 0; nshow = 0; nord = 0
    for (nm in C) {
        if (!(nm in S)) continue
        if (C[nm] + 0 > S[nm] + 0) {
            nr++
            if (verbose > 1 || kind == "aer" || tolower(nm) ~ show_re) ORD[++nord] = nm
        } else if (C[nm] + 0 < S[nm] + 0) DN[++nd] = nm
    }
    sort_arr(ORD, nord, 0); sort_arr(DN, nd, 0)
    SUMM = SUMM (SUMM == "" ? "" : "; ") label " " nr_counters(ne) ", " commas(nr) " rose"
    if (!nord && !nd) return
    flagged = 1
    out("  " label ": " nr_counters(ne) ", " commas(nr) " rose" (verbose > 1 || kind == "aer" ? "" : "; " commas(nord) " of them match SUMMARY_COUNTER_RE") (nord ? ":" : ""))
    for (k = 1; k <= nord; k++) out(sprintf("    %-40s +%s", ORD[k], commas(C[ORD[k]] - S[ORD[k]])))
    if (nd) {
        d = ""
        for (k = 1; k <= nd && k <= 5; k++) d = d (k > 1 ? ", " : "") DN[k] " " commas(S[DN[k]]) " -> " commas(C[DN[k]])
        out("    " commas(nd) " went down, a reset, not counted: " d (nd > 5 ? " (+" (nd - 5) " more)" : ""))
    }
}
BEGIN {
    fl = ARGV[1]; hl = ARGV[2]; verbose = ARGV[3] + 0; show_re = ARGV[4]
    # gauges in /proc/net/snmp: they fall as well as rise
    split("TcpCurrEstab TcpMaxConn TcpRtoAlgorithm TcpRtoMin TcpRtoMax IpForwarding IpDefaultTTL", F, " ")
    for (k in F) GAUGE[F[k]] = 1
    nl = readlines(fl, FL)
    nh = readlines(hl, HL)
    i = 1
    for (hi = 1; hi <= nh; hi++) {
        h = HL[hi]; split("", P); split("", DEVS); nd = 0; no = 0; flagged = 0; SUMM = ""; any = 0
        for (; i <= nl && index(FL[i], h "\t") == 1; i++) {
            split(FL[i], F, "\t"); any = 1
            it = F[3]; sub(/.*\//, "", it); sub(/-(start|end)$/, "", it)
            if (it == "nics" || it == "tcp") key = it
            else if (index(it, "ethtool-S-") == 1) { dev = substr(it, 11); key = "eth:" dev }
            else if (index(it, "aer-") == 1) { dev = substr(it, 5); key = "aer:" dev }
            else continue
            if (key ~ /^(eth|aer):/ && !(dev in DEVS)) { DEVS[dev] = 1; DL[++nd] = dev }
            P[key, F[2]] = F[3]
        }
        if (!any) { print h ": not recorded (no counter captures in sysinfo/" h ")"; continue }
        if (("tcp", "start") in P || ("tcp", "end") in P) compare("tcp", "tcp", P["tcp", "start"], P["tcp", "end"])
        else { out("  tcp: not recorded"); flagged = 1 }
        sort_arr(DL, nd, 0)
        for (k = 1; k <= nd; k++) {
            dev = DL[k]
            if (("eth:" dev, "start") in P || ("eth:" dev, "end") in P) compare(dev, "eth", P["eth:" dev, "start"], P["eth:" dev, "end"])
            if (("aer:" dev, "start") in P || ("aer:" dev, "end") in P) compare(dev " aer", "aer", P["aer:" dev, "start"], P["aer:" dev, "end"])
        }
        if (!nd) {
            v = ""; m = readlines(P["nics", "start"] != "" ? P["nics", "start"] : P["nics", "end"], L)
            out("  NICs: none captured" (m > 0 && L[1] != "" ? " (" L[1] ")" : "")); flagged = 1
        }
        if (!flagged) { print h ": nothing to flag, none matching SUMMARY_COUNTER_RE rose and none went down (" SUMM ")"; continue }
        print h
        for (k = 1; k <= no; k++) print O[k]
    }
}
