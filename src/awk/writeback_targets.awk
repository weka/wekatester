function slurp(path,    L, n, i, v) {   # open(path).read().strip(); slurped: it exists
    slurped = (n = readlines(path, L)) >= 0; v = ""
    for (i = 1; i <= n; i++) v = v (i > 1 ? "\n" : "") L[i]
    return strip(v)
}
# values compare by meaning: 5G is 5120M, 2-4 is 2,3,4 (2,4 is not 2-4)
function norm(k, v,    S, b) {
    if (k == "cpus") return parse_cpulist(v, S) ? "c" fmt_cpulist(S) : "s" v
    if (k ~ /_fs$/) return (b = parse_size(v)) != "" ? "n" sprintf("%.0f", b) : "s" v
    if (k ~ /_(nj|nr|qd)$/) return (b = py_int(v)) != "" ? "n" sprintf("%.0f", b) : "s" v
    return "s" v
}
function geom(h, slot,    q, v, out, any) {   # nj/fs/nr/qd, the trailing blanks dropped
    out = ""; any = 0
    for (q = 1; q <= 4; q++) {
        v = ((h, slot "_" TUPLE[q]) in WANT) ? WANT[h, slot "_" TUPLE[q]] : ""
        if (v != "") any = 1
        out = out (q > 1 ? "/" : "") v
    }
    if (!any) return ""
    sub(/\/+$/, "", out)
    return out
}
function render(h,    cell, row, k, s, n, G) {
    # a row the operator wrote keeps its own spelling of the host,
    # machine-id or not -- automation only names a machine it is adding
    cell = (h in SEEN_CELL) ? SEEN_CELL[h] : (h in IDENT) ? IDENT[h] : h
    row = csv_field(cell)
    for (k = 1; k <= 4; k++) row = row "," csv_field(((h, FIELD[k]) in WANT) ? WANT[h, FIELD[k]] : "")
    for (s = 1; s <= nslot; s++) G[s] = geom(h, SLOT[s])
    n = nslot
    while (n > 6 && G[n] == "") n--   # no 1MiB latency geometry: the row stays in the old width
    for (s = 1; s <= n; s++) row = row "," csv_field(G[s])
    return row
}
function own_line(line,    F, h) {   # the address of the host whose own line this is, or ""
    if (!csv_line(line, F)) return ""
    h = strip(F[1])
    if (h == "" || substr(h, 1, 1) == "#" || tolower(h) == "host" || !(host_addr(h, ALIAS) in WANTED)) return ""
    OWN_CELL = h
    return host_addr(h, ALIAS)
}
BEGIN {
    wb = ARGV[1]; mode = ARGV[2]; work = ARGV[3]; line_gbps = ARGV[4]
    kv_map(ENVIRON["WEKATESTER_HOST_ALIAS"], ALIAS); kv_map(ENVIRON["WEKATESTER_HOST_IDENT"], IDENT)
    nslot = split(geom_slots(), SLOT, " "); split("nj fs nr qd", TUPLE, " ")
    split("login engine cpus dir", FIELD, " "); nfield = 4
    for (s = 1; s <= nslot; s++) for (q = 1; q <= 4; q++) FIELD[++nfield] = SLOT[s] "_" TUPLE[q]
    n = split(line_rate_slots(), F, " ")
    for (i = 1; i <= n; i++) LINE_RATE[F[i]] = 1
    # what each host OWN row provides (resolve_targets hostonly): the
    # last full-width line per host
    n = readlines(work "/targets.hostrows", L)
    for (i = 1; i <= n; i++) if (split(L[i], F, "\t") == nfield + 1) HROW[F[1]] = L[i]
    for (h in HROW) {
        split(HROW[h], F, "\t")
        for (f = 1; f <= nfield; f++) if (F[f + 1] != "-") HAVE[h, FIELD[f]] = F[f + 1]
    }
    # Measured tuples first (cal.results is pure measurement; targets.final
    # also carries CLI values), then the STAGED variants for the rest. A
    # malformed line is a schema break, as in apply_cal_results.
    n = readlines(work "/cal.results", L)
    for (i = 1; i <= n; i++) {
        if (!cal_results_split(L[i], F)) continue
        split("", T); got = 0
        for (s = 1; s <= nslot; s++) {
            b = 2 + 4 * (s - 1)
            if (F[b + 1] != "-") { T[SLOT[s] "_qd"] = F[b + 1]; T[SLOT[s] "_nr"] = F[b + 2]; T[SLOT[s] "_fs"] = F[b + 3]; got = 1 }
            # a measured tuple always carries numjobs: it is the bandwidth
            # and latency answer, and it marks the tuple as measured
            # (staged tuples never carry one)
            if (F[b + 4] != "-") { T[SLOT[s] "_nj"] = F[b + 4]; got = 1 }
        }
        if (!got) continue
        for (f = 1; f <= nfield; f++) delete MEAS[F[1], FIELD[f]]
        for (k in T) MEAS[F[1], k] = T[k]
    }
    # each host staged files (the first block of a host listed twice)
    if ((m = readlines(work "/staged.list", M)) < 0) awk_fail("cannot read " work "/staged.list")
    last = ""
    for (i = 1; i <= m; i++) {
        split(M[i], F, "\t")
        if (F[1] != last) { last = F[1]; take = !(last in NJOB); if (take) NJOB[last] = 0 }
        if (take && F[2] != "") JOB[last, ++NJOB[last]] = F[2]
    }
    nup = 0
    for (a = 5; a < ARGC; a++) {
        h = ARGV[a]; split("", D); split("", DP)
        for (f = 1; f <= nfield; f++) if ((h, FIELD[f]) in MEAS) { D[FIELD[f]] = MEAS[h, FIELD[f]]; DP[FIELD[f]] = 1 }
        v = slurp(work "/auth/" h ".user")
        if (slurped) { D["login"] = v; DP["login"] = 1 }
        # the cpu list as the tuner resolved it; a staged job names only
        # the subset its job count runs on
        v = slurp(work "/usable/" h)
        if (slurped && !("cpus" in DP)) { D["cpus"] = v; DP["cpus"] = 1 }
        for (j = 1; j <= NJOB[h] + 0; j++) {
            p = JOB[h, j]; job = p; sub(/.*\//, "", job)
            if ((n = readlines(p, L)) < 0) awk_fail("cannot read " p)
            if (job == layout_job() || is_layout_marked(L, n)) continue   # the layout is a barrier, not a test: it records nothing
            if (is_floor_marked(L, n)) continue   # its one-job geometry is forced, not something to record
            lat = bw = iops = 0
            for (i = 1; i <= n; i++) {
                if (index(L[i], "# report") != 1) continue
                nw = pysplit(L[i], W)
                for (k = 3; k <= nw; k++) { if (W[k] == "latency") lat = 1; else if (W[k] == "bandwidth") bw = 1; else if (W[k] == "iops") iops = 1 }
            }
            # precedence latency > bandwidth > iops, same as the tuner; a
            # 1MiB latency file (a -b twin) records into the lat1m slot
            kind = lat ? lat_kind(L, n) : bw ? "bw" : iops ? "iops" : ""
            if (!("engine" in DP)) { D["engine"] = first_value(L, n, "ioengine"); DP["engine"] = 1 }
            if (!("cpus" in DP)) { D["cpus"] = first_value(L, n, "cpus_allowed"); DP["cpus"] = 1 }
            if (!("dir" in DP)) { D["dir"] = first_value(L, n, "directory"); DP["dir"] = 1 }
            if (kind == "") continue
            # the staged tuple fills only unmeasured slots, never with a
            # numjobs: the tuner re-derives it every run, and a recorded
            # count would pin its knob
            file_directions(L, n, DIR)
            for (q = 1; q <= 2; q++) {
                if (!((q == 1 ? "read" : "write") in DIR)) continue
                for (t = 2; t <= 4; t++) {
                    v = first_value(L, n, t == 2 ? "filesize" : t == 3 ? "nrfiles" : "iodepth")
                    k = kind "_" (q == 1 ? "r" : "w") "_" TUPLE[t]
                    if (v != "" && !(k in DP)) { D[k] = v; DP[k] = 1 }
                }
            }
        }
        # the host desired line: its own row plus what the run derived for
        # the rest (everything under -g); generic-row values are not the
        # host own
        for (f = 1; f <= nfield; f++) {
            k = FIELD[f]; delete WANT[h, k]
            if ((h, k) in HAVE) WANT[h, k] = HAVE[h, k]
        }
        for (f = 1; f <= nfield; f++) {
            k = FIELD[f]
            if (!(k in DP) || D[k] == "") continue
            # identity, credentials and the operator OWN cpu list are
            # never overwritten, -g included
            if ((k == "login" || k == "cpus") && ((h, k) in HAVE)) continue
            # the row keeps its own spelling; equal text is equal meaning
            if (((h, k) in HAVE) && ((HAVE[h, k] "") == (D[k] "") || norm(k, HAVE[h, k]) == norm(k, D[k]))) continue
            # the bandwidth tuples --line-rate MEASURED again replace the
            # row; a staged guess for those slots never does
            fresh = line_gbps != "-" && ((h, k) in MEAS) && (substr(k, 1, length(k) - 3) in LINE_RATE)
            if (mode == "overwrite" || !((h, k) in HAVE) || fresh) WANT[h, k] = D[k]
        }
        # an update when the line no longer says what holds
        same = 1; any = 0
        for (f = 1; f <= nfield; f++) {
            k = FIELD[f]
            if ((h, k) in WANT) any = 1
            if (((h, k) in WANT) != ((h, k) in HAVE) || ((h, k) in WANT) && (WANT[h, k] "") != (HAVE[h, k] "") && norm(k, WANT[h, k]) != norm(k, HAVE[h, k])) same = 0
        }
        if (any && !same && !(h in WANTED)) { WANTED[h] = 1; nup++ }
    }
    if (!nup) { print "host file: nothing to record"; exit 0 }
    # only ever added to: the host own line commented out with its new
    # version below it, or appended; generic rows untouched
    if ((n = readlines(wb, L)) < 0) awk_fail("cannot read " wb)
    no = 0
    for (i = 1; i <= n; i++) {
        if ((addr = own_line(L[i])) == "") { O[++no] = L[i]; continue }
        # render reads only its own host's first spelling, set here first
        if (!(addr in SEEN_CELL)) SEEN_CELL[addr] = OWN_CELL
        O[++no] = "# superseded by -a: " L[i]
        if (!(addr in PLACED)) { O[++no] = render(addr); PLACED[addr] = 1 }
    }
    for (a = 5; a < ARGC; a++) if ((ARGV[a] in WANTED) && !(ARGV[a] in PLACED)) O[++no] = render(ARGV[a])
    writelines(wb, O, no)
    print "host file: recorded " nup " host line(s) in " wb " (" mode ")"
}
