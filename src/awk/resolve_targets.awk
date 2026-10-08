BEGIN {
    phase = ARGV[1]; path = ARGV[2]; cli_engine = ARGV[3]; cli_dir = ARGV[4]; results = ARGV[5]
    kv_map(ENVIRON["WEKATESTER_HOST_ALIAS"], ALIAS)
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
        if (r == 1 && tolower(strip(CV[r, 1])) == "host") continue   # the header
        for (k = 1; k <= ncols; k++) C[k] = k <= CN[r] ? strip(CV[r, k]) : ""
        ne++; nk = 0
        if (C[3] != "") { EK[ne, ++nk] = "engine"; EV[ne, nk] = C[3] }
        if (C[4] != "") { EK[ne, ++nk] = "cpus"; EV[ne, nk] = C[4] }
        if (C[5] != "") { EK[ne, ++nk] = "dir"; EV[ne, nk] = C[5] }
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
        if ((EHOST[ne] = host_addr(C[1], ALIAS)) != "") {
            if (C[2] != "") { EK[ne, ++nk] = "login"; EV[ne, nk] = C[2] }
            h = EHOST[ne]
            if (h in HLINE) {
                # two spellings of one machine, most likely one short name
                # with two machine ids, both resolving to the same address
                extra = HCELL[h] == C[1] ? "" : "; \047" HCELL[h] "\047 and \047" C[1] "\047 both resolve to \047" h "\047 -- keep the row for this machine and drop the other"
                awk_fail(path ":" r ": duplicate definition for host \047" h "\047 (first at line " HLINE[h] ")" extra)
            }
            HLINE[h] = r; HCELL[h] = C[1]; HENT[h] = ne
            ELOGIN[ne] = ""; EENG[ne] = ""; ENSEL[ne] = 3
        } else {
            # host-less: login and engine are SELECTORS; login is never assigned
            ELOGIN[ne] = C[2]; EENG[ne] = C[3]; ENSEL[ne] = (C[2] != "") + (C[3] != "")
            HL[++nhl] = ne   # the host-less lines, in file order
        }
        ENK[ne] = nk
    }
    # ---- phase2 input: the engine test results ----
    if (phase == "phase2" && results != "-") {
        if ((n = readlines(results, L)) < 0) awk_fail("cannot read " results)
        for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 3 && F[3] == "ok") PASSED[F[1], F[2]] = 1
    }
    # ---- resolve per host ----
    for (a = 6; a < ARGC; a++) {
        h = ARGV[a]; split("", CFG); split("", SN); split("", SL)
        # the host line first: the most specific, unique -- looked up,
        # not scanned for: a scan per host was hosts x lines
        if (h in HENT) {
            e = HENT[h]
            for (j = 1; j <= ENK[e]; j++) { k = EK[e, j]; CFG[k] = EV[e, j]; SN[k] = ENSEL[e]; SL[k] = ELINE[e] }
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
        if (cli_engine != "-") CFG["engine"] = cli_engine   # the CLI beats the file
        if (cli_dir != "-") CFG["dir"] = cli_dir
        line = h
        for (f = 1; f <= nfield; f++) line = line "\t" ((FIELD[f] in CFG) && CFG[FIELD[f]] != "" ? CFG[FIELD[f]] : "-")
        print line
    }
}
