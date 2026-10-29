BEGIN {
    phase = ARGV[1]; path = ARGV[2]; cli_engine = ARGV[3]; cli_dir = ARGV[4]; results = ARGV[5]
    kv_map(ENVIRON["WEKATESTER_HOST_ALIAS"], ALIAS); def_engine = ENVIRON["WEKATESTER_DEFAULT_ENGINE"]
    nslot = split(geom_slots(), SLOT, " "); split(geom_names(), GNAME, " ")
    split("nj fs nr qd", TUPLE, " "); ncols = 5 + nslot
    split("login engine cpus dir", FIELD, " "); nfield = 4
    for (s = 1; s <= nslot; s++) for (q = 1; q <= 4; q++) FIELD[++nfield] = SLOT[s] "_" TUPLE[q]
    # ---- parse: one entry per row, its fields in the order they count ----
    if ((n = readlines(path, L)) < 0) awk_fail("cannot read host file: " path)
    nrec = csv_read(L, n, CN, CV); ne = 0
    for (r = 1; r <= nrec; r++) {
        all = ""
        for (k = 1; k <= CN[r]; k++) all = all CV[r, k]
        if (!CN[r] || strip(all) == "") continue
        if (substr(strip(CV[r, 1]), 1, 1) == "#") continue
        if (is_setting_cell(CV[r, 1])) continue   # read_settings reads these
        if (r == 1 && tolower(strip(CV[r, 1])) == "host") continue   # the header
        # an unquoted cpu list ("0-3, 8") splits into cells and shifts every
        # later column; trailing empty cells (spreadsheet padding) are fine
        for (w = CN[r]; w > ncols && strip(CV[r, w]) == ""; w--) ;
        if (w > ncols)
            awk_fail(path ":" r ": " w " cells, but a host-file row has at most " ncols " -- quote cpu lists, e.g. \"0-3,8\"")
        for (k = 1; k <= ncols; k++) C[k] = k <= CN[r] ? strip(CV[r, k]) : ""
        if (C[5] != "" && substr(C[5], 1, 1) != "/")
            awk_fail(path ":" r ": destination dir \047" C[5] "\047 is not an absolute path -- quote cpu lists, e.g. \"0-3,8\"")
        ne++; nk = 0
        if (C[3] != "") { EK[ne, ++nk] = "engine"; EV[ne, nk] = C[3] }
        if (C[4] != "") { EK[ne, ++nk] = "cpus"; EV[ne, nk] = C[4] }
        if (C[5] != "") { EK[ne, ++nk] = "dir"; EV[ne, nk] = trim_dir(C[5]) }
        # geometry: "bandwidthR:12/10G/1/8" or a bare "12/10G/1/8";
        # empty parts are unset
        for (s = 1; s <= nslot; s++) {
            if ((raw = C[5 + s]) == "") continue
            if ((p = index(raw, ":"))) {
                pfx = substr(raw, 1, p - 1)
                if (tolower(strip(pfx)) != tolower(GNAME[s]))
                    awk_fail(path ":" r ": column for " GNAME[s] " carries prefix \047" pfx "\047")
                raw = substr(raw, p + 1)
            }
            np = lsplit(raw, PART, "/")
            for (q = 1; q <= 4 && q <= np; q++)
                if (strip(PART[q]) != "") { EK[ne, ++nk] = SLOT[s] "_" TUPLE[q]; EV[ne, nk] = strip(PART[q]) }
        }
        ELINE[ne] = r
        if (is_glob_cell(C[1])) {
            # a pattern row: a host line for every host it matches, its
            # login assigned; a name glob outranks the bare * row
            pat = C[1]; sub(/\/.*/, "", pat); pat = strip(pat)
            if ((ERE[ne] = glob_re(pat)) == "")
                awk_fail(path ":" r ": host pattern \047" pat "\047: a [...] class may not hold [ or \\ or a backwards range such as z-a")
            if (C[2] != "") { EK[ne, ++nk] = "login"; EV[ne, nk] = C[2] }
            EPAT[ne] = pat; ENSEL[ne] = pat == "*" ? 3 : 4
            GL[++ngl] = ne   # the pattern rows, in file order
        } else if ((EHOST[ne] = host_addr(C[1], ALIAS)) != "") {
            if (C[2] != "") { EK[ne, ++nk] = "login"; EV[ne, nk] = C[2] }
            h = EHOST[ne]
            if (h in HLINE) {
                # two spellings of one machine, most likely one short name
                # with two machine ids, both resolving to the same address
                extra = HCELL[h] == C[1] ? "" : "; \047" HCELL[h] "\047 and \047" C[1] "\047 both resolve to \047" h "\047 -- keep the row for this machine and drop the other"
                awk_fail(path ":" r ": duplicate definition for host \047" h "\047 (first at line " HLINE[h] ")" extra)
            }
            HLINE[h] = r; HCELL[h] = C[1]; HENT[h] = ne
            ELOGIN[ne] = ""; EENG[ne] = ""; ENSEL[ne] = 5
        } else {
            # host-less: login and engine are SELECTORS; login is never assigned
            ELOGIN[ne] = C[2]; EENG[ne] = C[3]; ENSEL[ne] = (C[2] != "") + (C[3] != "")
            HL[++nhl] = ne   # the host-less lines, in file order
        }
        ENK[ne] = nk
    }
    # ---- engines: every line's ioengine, the candidates test_engines proves ----
    if (phase == "engines") {
        for (e = 1; e <= ne; e++) for (j = 1; j <= ENK[e]; j++) if (EK[e, j] == "engine") print EV[e, j]
        if (def_engine != "") print def_engine
    }
    # ---- phase2 input: the engine test results ----
    if (phase == "phase2" && results != "-") {
        if ((n = readlines(results, L)) < 0) awk_fail("cannot read " results)
        for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 3 && F[3] == "ok") PASSED[F[1], F[2]] = 1
    }
    # ---- resolve per host ----
    # a pattern matches the address or a name aliased to it (local mode)
    for (nm in ALIAS) NAMES[ALIAS[nm]] = NAMES[ALIAS[nm]] "\n" tolower(nm)
    for (a = 6; a < ARGC; a++) {
        h = ARGV[a]; split("", CFG); split("", SN); split("", SL)
        # the host line first: the most specific, unique -- looked up,
        # not scanned for: a scan per host was hosts x lines
        if (h in HENT) {
            e = HENT[h]
            for (j = 1; j <= ENK[e]; j++) { k = EK[e, j]; CFG[k] = EV[e, j]; SN[k] = ENSEL[e]; SL[k] = ELINE[e] }
        }
        # then the pattern rows, name globs before *; not the host own
        nn = split(tolower(h) NAMES[h], NM, "\n")
        for (sel = 4; sel >= 3 && phase != "hostonly"; sel--)
            for (q = 1; q <= ngl; q++) {
                e = GL[q]
                if (ENSEL[e] != sel) continue
                for (i = 1; i <= nn && NM[i] !~ ERE[e]; i++) ;
                if (i > nn) continue
                GHIT[e] = 1
                for (j = 1; j <= ENK[e]; j++) {
                    k = EK[e, j]; v = EV[e, j]
                    if (!(k in CFG)) { CFG[k] = v; SN[k] = sel; SL[k] = ELINE[e] }
                    else if (SN[k] == sel && CFG[k] != v)
                        print "WARNING: " path ": host \047" h "\047 field \047" k "\047: line " ELINE[e] " conflicts with equally specific line " SL[k] "; keeping line " SL[k] > "/dev/stderr"
                }
            }
        login = ("login" in CFG) ? CFG["login"] : ""
        # host-less lines, most selectors first, ties to the first line
        # (none in hostonly: their values are defaults, not the host own)
        for (sel = 2; sel >= 0 && phase != "hostonly"; sel--)
            for (q = 1; q <= nhl; q++) {
                e = HL[q]
                if (ENSEL[e] != sel) continue
                if (ELOGIN[e] != "" && ELOGIN[e] != login) continue
                # an engine selector needs test results; it folds in later
                if (EENG[e] != "" && (phase != "phase2" || !((h, EENG[e]) in PASSED))) continue
                for (j = 1; j <= ENK[e]; j++) {
                    k = EK[e, j]; v = EV[e, j]
                    if (k == "login") continue
                    if (!(k in CFG)) { CFG[k] = v; SN[k] = sel; SL[k] = ELINE[e] }
                    else if (SN[k] == sel && CFG[k] != v)
                        print "WARNING: " path ": host \047" h "\047 field \047" k "\047: line " ELINE[e] " conflicts with equally specific line " SL[k] "; keeping line " SL[k] > "/dev/stderr"
                }
            }
        # WT_ENGINE: the default every row refines, never the host own
        if (!("engine" in CFG) && def_engine != "" && phase != "hostonly") CFG["engine"] = def_engine
        if (cli_engine != "-") CFG["engine"] = cli_engine   # the CLI beats the file
        if (cli_dir != "-") CFG["dir"] = cli_dir
        line = h
        for (f = 1; f <= nfield; f++) line = line "\t" ((FIELD[f] in CFG) && CFG[FIELD[f]] != "" ? CFG[FIELD[f]] : "-")
        print line
    }
    # once per run (phase1): a name glob no host matched is likely a typo
    for (q = 1; q <= ngl && phase == "phase1"; q++)
        if (ENSEL[e = GL[q]] == 4 && !(e in GHIT))
            print "WARNING: " path ":" ELINE[e] ": host pattern \047" EPAT[e] "\047 matches none of this run\047s hosts" > "/dev/stderr"
}
