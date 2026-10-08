function warn(msg) { print "WARNING: " msg > "/dev/stderr" }
function warn_once(msg) {   # per-host loops would otherwise repeat the same warning
    if (!(msg in WARNED)) { WARNED[msg] = 1; warn(msg) }
}
function ceil_div(a, b,    c) { c = int(a / b); return c * b < a ? c + 1 : c }
BEGIN {
    mode = ARGV[1]; work = ARGV[2]; directory = ARGV[3]; label = ARGV[4]; targets = ARGV[5]
    pristine = ARGV[6] == "1"; nf = ARGV[7] + 0; auto = mode == "auto"
    ns_unified = auto && index(ENVIRON["WEKATESTER_NS"], "unified") == 1
    nolat = auto && ENVIRON["WEKATESTER_IOPS_NOLAT"] == "1"
    split("nj fs nr qd", TUPLE, " "); split("numjobs filesize nrfiles iodepth", KNOB, " ")
    # the jobfiles in name order, as the set lists them
    for (a = 1; a <= nf; a++) { NM[a] = ARGV[7 + a]; sub(/.*\//, "", NM[a]); PATHOF[NM[a]] = ARGV[7 + a] }
    sort_arr(NM, nf, 0)
    for (j = 1; j <= nf; j++) {
        if ((n = readlines(PATHOF[NM[j]], L)) < 0) awk_fail("cannot read " PATHOF[NM[j]])
        NL[j] = n
        for (k = 1; k <= n; k++) SL[j, k] = L[k]
        LAY[j] = NM[j] == layout_job() || is_layout_marked(L, n)
    }
    nh = 0
    for (a = 8 + nf; a < ARGC; a++) H[++nh] = ARGV[a]
    # the first host row per host: under -a the named file, else the
    # finished resolution when it exists, else the pre-auth phase
    if (auto) { has_final = targets != "-" && targets != ""; n = has_final ? readlines(targets, T) : 0 }
    else {
        has_final = (n = readlines(work "/targets.final", T)) >= 0
        if (!has_final) n = readlines(work "/targets.phase1", T)
    }
    for (i = 1; i <= n; i++) { split(T[i], F, "\t"); if (!(F[1] in ROWS)) ROWS[F[1]] = T[i] }
    if (auto) auto_facts()
    kinds = work "/staged.kinds"
    printf "" > kinds
    for (j = 1; j <= nf; j++) print (LAY[j] ? "L " : "J ") NM[j] > kinds
    for (x = 1; x <= nh; x++) print "H " H[x] > kinds
    for (x = 1; x <= nh; x++) {
        h = H[x]; split("", ROW)
        if (h in ROWS) lsplit(ROWS[h], ROW, "\t")
        if ((HD[h] = row_get(ROW, "dir")) == "") HD[h] = directory
    }
    # job by job, host by host: the order the notes come out in
    for (j = 1; j <= nf; j++)
        for (x = 1; x <= nh; x++) {
            h = H[x]; split("", ROW)
            if ((hr = (h in ROWS))) lsplit(ROWS[h], ROW, "\t")
            if (auto && LAY[j] && pristine) continue   # derive_layouts writes it
            n = NL[j]
            for (k = 1; k <= n; k++) L[k] = SL[j, k]
            # directory= replaced, else inserted after [global], else
            # [global] created, or fio would silently write to the server
            # cwd
            n = override_lines(L, n, "directory", HD[h])
            if (auto) n = auto_job(j, h, ROW, L, n)
            else if (has_final && hr && !LAY[j] && (kind = job_kind(j)) != "") {
                file_directions_of(j, D)
                if ((slot = pick_slot(kind, D, ROW)) != "")
                    for (q = 1; q <= 4; q++) {
                        if ((v = row_get(ROW, slot "_" TUPLE[q])) == "") continue
                        n = override_lines(L, n, KNOB[q], v)
                        GEO[h] = 1
                    }
            }
            writelines(work "/jobs/" h "/" NM[j], L, n)
        }
    for (x = 1; x <= nh; x++) if (GEO[H[x]]) print "C " H[x] > kinds
    close(kinds)
    if (!auto) exit 0
    for (j = 1; j <= nf; j++) {
        if (LAY[j]) continue
        k = job_kind(j)
        print "auto[" label "]: " NM[j] " type=" (k == "" ? "all" : k == "bw" ? "bandwidth" : k == "iops" ? "iops" : "latency")
    }
    for (j = 1; j <= nf; j++) {
        if (!LAY[j]) continue
        if (!pristine) warn_once(NM[j] ": user-edited layout staged as-is; it may not match the auto-tuned geometry (regenerate with -g)")
        print "auto[" label "]: " NM[j] " type=layout"
    }
}
# Job type by report directive, latency > bandwidth > iops: a
# bandwidth+iops file takes the bandwidth slot and keeps its latency
# accounting. A 1MiB latency file (a -b twin) is lat1m. "" for no
# directive: it runs as written.
function job_kind(j,    n, k, L) {
    n = NL[j]
    for (k = 1; k <= n; k++) L[k] = SL[j, k]
    return report_has(L, n, "latency") ? lat_kind(L, n) : report_has(L, n, "bandwidth") ? "bw" : report_has(L, n, "iops") ? "iops" : ""
}
function file_directions_of(j, D,    n, k, L) {
    n = NL[j]
    for (k = 1; k <= n; k++) L[k] = SL[j, k]
    file_directions(L, n, D)
}
# The facts -a staging needs per host: cpus (probe_cores, the host-file
# list its base), engines and weka cores, with their warnings, in host
# order; usable/<host> for the writeback.
function auto_facts(    x, h, np, P, i, F, m, c, S, nodes, WK, ISO, R, PHYS, ALL, base, e, ok, y, NC1, NW1, fleet, v, IS) {
    for (x = 1; x <= nh; x++) {
        h = H[x]
        if ((np = readlines(work "/probe/" h, P)) < 0) awk_fail("cannot read " work "/probe/" h)
        PN[h] = np
        for (i = 1; i <= np; i++) PL[h, i] = P[i]
        NCPU[h] = 0; nodes = 0; split("", WK); ENGS[h] = " "; ISOL[h] = ""
        for (i = 1; i <= np; i++) {
            if (!(m = pysplit(P[i], F))) continue
            if (F[1] == "ncpus") { if ((NCPU[h] = py_int(F[2])) == "") awk_fail("probe: " h ": bad ncpus line: " P[i]) }
            else if (F[1] == "wekanode" && m > 1) nodes = py_int(F[2]) + 0
            else if (F[1] == "isolated" && m > 1) ISOL[h] = F[2]
            else if (F[1] == "weka_allowed") {
                # only single-cpu masks are dedicated cores: wide masks are
                # floating utility threads, and their union would be every
                # cpu
                if (!parse_cpulist(F[2], S)) awk_fail("probe: bad cpu list on a weka_allowed line: " F[2])
                if (set_size(S) == 1) for (c in S) WK[c] = 1
            }
            else if (F[1] == "engines") { ENGS[h] = " "; for (y = 2; y <= m; y++) ENGS[h] = ENGS[h] F[y] " " }
        }
        NWEKA[h] = set_size(WK); WEKAL[h] = fmt_cpulist(WK)
        probe_cores(P, np, "", R, PHYS, ALL)
        FN[h] = R["n"]
        if (R["weka_core0"])
            warn(h ": weka has pinned a dedicated core on core 0 -- that core and its sibling belong to the OS; fio stays off it regardless")
        # pin detection is all that keeps fio off weka cores: weka running
        # with none found is said, not silently ignored
        if (nodes && !NWEKA[h])
            warn(h ": " nodes " wekanode process(es) running but no pinned cores detected -- fio will be allowed on every cpu, including weka\047s; check that this weka pins its io threads")
    }
    NC1 = ""; NW1 = ""; c = 0; y = 0
    for (x = 1; x <= nh; x++) {
        h = H[x]
        if (x > 1 && NCPU[h] != NCPU[H[1]]) c = 1
        if (x > 1 && NWEKA[h] != NWEKA[H[1]]) y = 1
    }
    if (c) { v = ""; for (x = 1; x <= nh; x++) v = v (x > 1 ? ", " : "") H[x] "=" NCPU[H[x]]; warn("system core counts differ between hosts: " v) }
    if (y) { v = ""; for (x = 1; x <= nh; x++) v = v (x > 1 ? ", " : "") H[x] "=" NWEKA[H[x]]; warn("weka core counts differ between hosts: " v) }
    # the best engine every host can run, in ENGINE_ORDER
    m = split(engine_order(), F, " "); COMMON = ""
    for (i = 1; i <= m && COMMON == ""; i++) {
        ok = 1
        for (x = 1; x <= nh && ok; x++) if (!index(ENGS[H[x]], " " F[i] " ")) ok = 0
        if (ok) COMMON = F[i]
    }
    # the operator cpu list is the base when the file gives one, less
    # missing cpus, weka cores and core 0 pair; otherwise, and for a
    # catch-all list, probe_cores own rule
    for (x = 1; x <= nh; x++) {
        h = H[x]; np = PN[h]
        for (i = 1; i <= np; i++) P[i] = PL[h, i]
        base = ""
        if (h in ROWS) { lsplit(ROWS[h], F, "\t"); base = row_get(F, "cpus") }
        probe_cores(P, np, base, R, PHYS, ALL)
        if (base == "" && R["n"] < 1)
            awk_fail(h ": no cpus left for fio -- " cores_summary(R, PHYS, ALL) "; mount weka with fewer cores, use a larger client, or name the cpus in the host file, fewer than fio could use (a narrower list is the operator\047s own reserve)")
        if (base != "" && R["n"] < 1 && R["catchall"])
            awk_fail(h ": the host file\047s cpu list (" base ") covers every cpu fio could use, which counts as no list, and the OS reserve then leaves fio no cpus -- " cores_summary(R, PHYS, ALL) "; mount weka with fewer cores, use a larger client, or list fewer cpus (a narrower list is the operator\047s own reserve)")
        if (base != "" && R["n"] < 1)
            awk_fail(h ": the host file\047s cpu list (" base ") leaves fio no cpus -- every one is weka\047s, core 0\047s pair, or not on this host")
        CN[h] = R["n"]; CPH[h] = fmt_cpulist(PHYS); CAL[h] = fmt_cpulist(ALL); NALL[h] = set_size(ALL)
        CSUM[h] = cores_summary(R, PHYS, ALL)
        if (ISOL[h] != "" && parse_cpulist(ISOL[h], IS) && set_any(IS)) {
            c = 0; y = 0
            for (v in ALL) if (v in IS) c = 1; else y = 1
            if (c && y) print "note: " h ": fio cpus " CAL[h] " span isolated and housekeeping cpus; per-job split affinity keeps each job on its own cpu" > "/dev/stderr"
        }
    }
    for (x = 1; x <= nh; x++) { v = work "/usable/" H[x]; print CAL[H[x]] > v; close(v) }
    # an engine the jobfile names that some host cannot run gives way
    # to the best one every host can
    for (j = 1; j <= nf; j++) {
        MISSING[j] = 0
        for (k = 1; k <= NL[j]; k++) {
            if ((e = key_value(SL[j, k], "ioengine")) == "") continue
            for (x = 1; x <= nh; x++) if (!index(ENGS[H[x]], " " e " ")) MISSING[j] = 1
        }
    }
}
# One job variant for one host under -a, on lines L (directory already
# set); returns the new line count. Overrides land in the order applied.
function auto_job(j, h, ROW, L, n,    D, kind, floor, fmt, slot, q, v, cap, nn, fs, nr, b, nj, i, O, no, S0) {
    if (LAY[j]) {
        # an edited layout: staged with corrections only
        return override_lines(L, n, "cpus_allowed", CAL[h])
    }
    # the effective set the cells ran on; the host file keeps its list as
    # written
    n = override_lines(L, n, "cpus_allowed", CAL[h])
    file_directions_of(j, D)
    if (ns_unified && ("read" in D) && !("write" in D)) {
        # a read-only job reads the shared set the read cells calibrated
        # on; stamp_unique_names leaves "shared." formats alone
        for (i = 1; i <= NL[j]; i++) S0[i] = SL[j, i]
        fmt = first_value(S0, NL[j], "filename_format")
        n = override_lines(L, n, "filename_format", "shared." (fmt != "" ? fmt : "$jobname.$jobnum.$filenum"))
    }
    if (COMMON != "" && MISSING[j]) n = override_lines(L, n, "ioengine", COMMON)
    kind = job_kind(j)
    floor = 0
    for (i = 1; i <= 3 && i <= NL[j]; i++) if (index(SL[j, i], floor_marker()) == 1) floor = 1
    if (kind != "" && (slot = pick_slot(kind, D, ROW)) != "")
        for (q = 1; q <= 4; q++) {
            if ((v = row_get(ROW, slot "_" TUPLE[q])) == "") continue
            if (q == 1 && v ~ /^[0-9]+$/ && !floor) {
                # The host file is honoured. Past every thread is the 4N
                # rung (a note); past 4N matches no rung and is probably
                # stale (a warning).
                cap = NALL[h]; nn = CN[h]
                if (v + 0 > 4 * nn)
                    warn_once(h ": host-file " slot "_nj=" v " exceeds 4N (" 4 * nn "; N=" nn " usable physical cores) -- split affinity will run " ceil_div(v + 0, cap) " jobs on some cpus")
                else if (v + 0 > cap)
                    print "note: " h ": " slot "_nj=" v " runs up to " ceil_div(v + 0, cap) " jobs per cpu (" cap " usable threads)" > "/dev/stderr"
            }
            n = override_lines(L, n, KNOB[q], v)
        }
    if (floor) {
        # the one-job twin: numjobs=iodepth=nrfiles=1, the data per job of
        # its original
        fs = slot != "" ? row_get(ROW, slot "_fs") : ""
        nr = slot != "" ? row_get(ROW, slot "_nr") : ""
        n = override_lines(L, n, "numjobs", "1"); n = override_lines(L, n, "iodepth", "1"); n = override_lines(L, n, "nrfiles", "1")
        if (fs != "" && nr ~ /^[0-9]+$/ && (b = parse_size(fs)) != "") {
            v = int(b * nr / 1048576)
            n = override_lines(L, n, "filesize", (v > 1 ? v : 1) "M")
        }
    }
    if ((v = row_get(ROW, "engine")) != "") n = override_lines(L, n, "ioengine", v)
    if (kind == "iops" && nolat) {
        # iops cells measured with latency accounting off; the staged job
        # matches
        n = override_lines(L, n, "disable_lat", "1"); n = override_lines(L, n, "disable_clat", "1")
        n = override_lines(L, n, "disable_slat", "1"); n = override_lines(L, n, "norandommap", "1")
    }
    # job count final: N/2 and N one per physical core, more across the
    # siblings
    nj = first_value(L, n, "numjobs")
    n = override_lines(L, n, "cpus_allowed", (nj ~ /^[0-9]+$/ ? nj + 0 : 1) <= CN[h] ? CPH[h] : CAL[h])
    no = 0
    O[++no] = "# generated by wekatester auto[" label "] for " h
    O[++no] = "# usable cores: " CSUM[h] " (of " NCPU[h] " cpus, weka: " (WEKAL[h] != "" ? WEKAL[h] : "none") ")"
    for (i = 1; i <= n; i++) O[++no] = L[i]
    split("", L)
    for (i = 1; i <= no; i++) L[i] = O[i]
    return no
}
