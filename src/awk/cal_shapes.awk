# str.split(None, n): up to n fields, then the rest as one, its leading
# blanks off
function split_rest(s, F, n,    k) {
    split("", F); k = 0
    while (k < n) {
        sub(/^[ \t\n\013\014\r\034\035\036\037]+/, "", s)
        if (s == "") return k
        if (!match(s, /[ \t\n\013\014\r\034\035\036\037]/)) { F[++k] = s; return k }
        F[++k] = substr(s, 1, RSTART - 1); s = substr(s, RSTART)
    }
    sub(/^[ \t\n\013\014\r\034\035\036\037]+/, "", s)
    if (s != "") F[++k] = s
    return k
}
function py_round(x,    r) {   # round(): half to even
    r = int(x)
    return x - r > 0.5 || (x - r == 0.5 && r % 2) ? r + 1 : r
}
function field(h, key,    ROW) {   # the host-file value, "" for none
    if (!(h in ROWS)) return ""
    lsplit(ROWS[h], ROW, "\t")
    return row_get(ROW, key)
}
# Host-file values per searched slot (qd nr fs nj, "" for an open knob); -g
# pins nothing, and --line-rate searches bandwidth again.
function host_pins(h, PS, PQ, PN, PF, PJ,    k, i, s, q, n, f, j) {
    split("", PS); k = 0
    if (regen) return 0
    for (i = 1; i <= nneed; i++) {
        s = NEED[i]
        if (line_gbps != "" && (s in LRS)) continue
        q = field(h, s "_qd"); n = field(h, s "_nr"); f = field(h, s "_fs"); j = field(h, s "_nj")
        if (q != "" || n != "" || f != "" || j != "") { PS[++k] = s; PQ[k] = q; PN[k] = n; PF[k] = f; PJ[k] = j }
    }
    return k
}
# Weka NICs into PORT (netdev -> 1): 1 when named (none is UDP mode), 0
# when not, and WHY says why.
function weka_ports(    w, r, base, k, p, rest, idx, key, d, nd, DEV, DSEEN, DV, bad, BYPCI, i, c, v, lc, hit, nc, CAND, U, u, nl, LOST) {
    split("", PORT); WHY = ""
    if (!cli) { WHY = "no weka CLI on the host"; return 0 }
    nd = 0; bad = ""
    for (w = 1; w <= nw; w++) {
        json_begin("[{")
        r = json_line(WRAW[w])
        if (!J_STARTED) { if (bad == "") bad = WNAME[w] ": no JSON in weka local resources"; continue }
        if (r != 1) { if (bad == "") bad = WNAME[w] ": unreadable weka local resources JSON"; continue }
        # a list of devices, or an object carrying them as net_devices;
        # only the objects among them are devices
        base = J_ROOT == "[" ? "" : "net_devices"
        split("", DSEEN)
        for (k = 1; k <= JN; k++) {
            p = JP[k]
            if (index(p, base ".") != 1) continue
            rest = substr(p, length(base) + 2)
            if (!match(rest, /^[0-9]+/)) continue
            idx = substr(rest, 1, RLENGTH); key = substr(rest, RLENGTH + 1)
            if (key == "") { if (JS[k] || JV[k] != "{}") continue }
            else if (substr(key, 1, 1) != "." || key ~ /^\.[0-9]+(\.|$)/) continue
            if (!(idx in DSEEN)) { DSEEN[idx] = ++nd }
            d = DSEEN[idx]; key = substr(key, 2)
            if (JS[k] && JV[k] != "" && (key == "name" || key == "device" || key == "identifier" || key == "netdev" || key == "interface"))
                DV[d, key] = JV[k]
        }
    }
    if (!nw) { WHY = ne ? "weka local resources could not be read (" WERR[1] ")" : "weka local resources could not be read"; return 0 }
    if (bad != "") { WHY = bad; return 0 }
    if (!nd) { WHY = "weka uses no dedicated NIC here (UDP mode)"; return 1 }
    for (i = 1; i <= nn; i++) if (NPCI[NORD[i]] != "-") BYPCI[NPCI[NORD[i]]] = NORD[i]
    nl = 0
    for (d = 1; d <= nd; d++) {
        nc = 0; hit = ""
        split("name device identifier netdev interface", U, " ")
        for (u = 1; u <= 5; u++) if ((d, U[u]) in DV) CAND[++nc] = DV[d, U[u]]
        for (c = 1; c <= nc; c++) {
            v = CAND[c]; lc = tolower(v)
            if (v in NSPD) hit = v
            else if (lc ~ /^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]\.[0-7]$/ && (lc in BYPCI)) hit = BYPCI[lc]
            if (hit != "") break
        }
        if (hit != "") { PORT[hit] = 1; continue }
        # name, device and identifier often repeat each other: say each once
        v = ""; split("", U)
        for (c = 1; c <= nc; c++) if (!(CAND[c] in U)) { U[CAND[c]] = 1; v = v (v == "" ? "" : " ") CAND[c] }
        LOST[++nl] = v == "" ? "?" : v
    }
    if (nl) { split("", PORT); WHY = "weka\047s NIC " LOST[1] " has no kernel netdev to ask ethtool about (bound to vfio?)"; return 0 }
    return 1
}
function gibs(b) { return sprintf("%.2f GiB/s", b / 1073741824) }
BEGIN {
    out = ARGV[1]; work = ARGV[3]; cli_engine = ARGV[4]; regen = ARGV[5] == "1"; mem_pct = ARGV[6] + 0
    line_gbps = ARGV[7] == "-" ? "" : ARGV[7]
    nnrs = 0; m = pysplit(ARGV[8], A)
    for (i = 1; i <= m; i++) if (A[i] ~ /^[0-9]+$/ && !((A[i] + 0) in NRSEEN)) { NRSEEN[A[i] + 0] = 1; NRS[++nnrs] = A[i] + 0 }
    sort_arr(NRS, nnrs, 1)
    fsmib = ARGV[9] + 0; wide = ARGV[10] + 0   # the job-count ceiling, x N (cal_wide)
    nh = 0
    for (a = 11; a < ARGC; a++) H[++nh] = ARGV[a]
    n = split(line_rate_slots(), F, " ")
    for (i = 1; i <= n; i++) LRS[F[i]] = 1
    nneed = 0; n = split(ARGV[2], L, "\n")
    for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2) NEED[++nneed] = F[1] "_" substr(F[2], 1, 1)
    n = readlines(work "/targets.final", L)
    for (i = 1; i <= n; i++) { lsplit(L[i], F, "\t"); if (!(F[1] in ROWS)) ROWS[F[1]] = L[i] }
    fs_groups(work, H, nh, GF, GM)
    ngroups = 0
    for (i = 1; i <= nh; i++) if (!(GF[H[i]] in GSEEN)) { GSEEN[GF[H[i]]] = 1; ngroups++ }
    neo = split(engine_order(), EO, " ")
    ns = 0
    for (x = 1; x <= nh; x++) {
        h = H[x]
        if ((np = readlines(work "/probe/" h, P)) < 0) np = 0
        ncpus = 0; model = ""; memkb = 0; cli = 1; neng = 0; nn = 0; nw = 0; ne = 0
        split("", WK); split("", ENG); split("", NSPD); split("", NPCI); split("", NDRV); split("", NIDS); split("", NORD)
        for (i = 1; i <= np; i++) {
            if (!(m = pysplit(P[i], F))) continue
            k = F[1]
            if (k == "ncpus" && m > 1 && F[2] ~ /^[0-9]+$/) ncpus = F[2] + 0
            else if (k == "cpu_model") {
                v = ""
                if (m > 1) { split_rest(P[i], R, 1); v = strip(R[2]) }
                if (v == "-") model = ""
                else { c = pysplit(v, R); model = R[1]; for (j = 2; j <= c; j++) model = model " " R[j] }
            }
            else if (k == "memtotal_kb" && m > 1 && F[2] ~ /^[0-9]+$/) memkb = F[2] + 0
            else if (k == "weka_allowed" && m > 1) {
                # a single-cpu mask is a dedicated io thread
                if (!parse_cpulist(F[2], S)) awk_fail("probe: bad cpu list on a weka_allowed line: " F[2])
                if (set_size(S) == 1) for (c in S) WK[c] = 1
            }
            else if (k == "nic" && m >= 6) {
                if (!(F[2] in NSPD)) NORD[++nn] = F[2]
                NSPD[F[2]] = match(F[3], /^[0-9]+/) ? substr(F[3], 1, RLENGTH) + 0 : 0
                NPCI[F[2]] = tolower(F[4]); NDRV[F[2]] = F[5]; NIDS[F[2]] = F[6]
            }
            else if (k == "weka_net") {
                c = split_rest(P[i], R, 2)
                WNAME[++nw] = c > 1 ? R[2] : "?"; WRAW[nw] = c > 2 ? R[3] : ""
            }
            else if (k == "weka_net_err") {
                c = split_rest(P[i], R, 2)
                WERR[++ne] = (c > 1 ? R[2] : "?") ": " (c > 2 ? R[3] : "failed")
            }
            else if (k == "weka_cli" && m > 1 && F[2] == "absent") cli = 0
            else if (k == "engines") { split("", ENG); neng = m - 1; for (j = 2; j <= m; j++) ENG[j - 1] = F[j] }
        }
        nweka = set_size(WK)
        # the host-file list as written: probe_cores must tell a catch-all
        # (0-255) from an operator choice
        base = field(h, "cpus")
        probe_cores(P, np, base, CR, PHYS, ALL)
        if (CR["n"] < 1) {
            if (CR["catchall"])
                how = "its host-file cpu list (" base ") covers every cpu fio could use, which counts as no list -- mount weka with fewer cores, use a larger client, or list fewer cpus (a narrower list is the operator\047s own reserve)"
            else if (base != "") how = "mount weka with fewer cores or use a larger client"
            else how = "mount weka with fewer cores, use a larger client, or name the cpus in the host file, fewer than fio could use (a narrower list is the operator\047s own reserve)"
            awk_fail(h ": no cpus left for fio -- " cores_summary(CR, PHYS, ALL) "; " how)
        }
        named = weka_ports(); why = WHY
        np_ = 0; split("", PN)
        for (p in PORT) PN[++np_] = p
        sort_arr(PN, np_, 0)
        linerate = 0; nicsig = "nics:unknown"
        if (named) {
            nicsig = ""; allsp = 1; sum = 0; nospeed = ""
            for (i = 1; i <= np_; i++) {
                p = PN[i]
                nicsig = nicsig (i > 1 ? "," : "") sprintf("%s[%s]@%d", NDRV[p], NIDS[p], NSPD[p])
                sum += NSPD[p]
                if (!NSPD[p]) { allsp = 0; nospeed = nospeed (nospeed == "" ? "" : " ") p }
            }
            if (nicsig == "") nicsig = "nics:none"
            if (np_ && allsp) linerate = sum * 125000   # Mb/s -> bytes/s
            else if (np_) why = "ethtool reports no link speed for " nospeed
        }
        ethtool = linerate
        if (line_gbps != "") linerate = line_gbps * 125000000   # Gb/s -> bytes/s
        nc = 0; cands = ""
        for (i = 1; i <= neo; i++) for (j = 1; j <= neng; j++) if (ENG[j] == EO[i]) { cands = cands (nc++ ? "," : "") EO[i]; break }
        if (!nc) cands = neng ? ENG[1] : "psync"
        first = cands; sub(/,.*/, "", first)
        pinned = cli_engine != "-" ? cli_engine : regen ? "" : field(h, "engine")
        memgib = memkb ? py_round(memkb / 1048576) : 0
        # one representative per shape per filesystem group (each reads its
        # own shared set); hosts with different pins calibrate apart
        npin = host_pins(h, PS, PQ, PNR, PFS, PJ)
        pinsig = ""
        for (i = 1; i <= npin; i++) pinsig = pinsig SUBSEP PS[i] SUBSEP PQ[i] SUBSEP PNR[i] SUBSEP PFS[i] SUBSEP PJ[i]
        key = model SUBSEP ncpus SUBSEP memgib SUBSEP nweka SUBSEP nicsig SUBSEP CR["n"] SUBSEP set_size(ALL) SUBSEP cands SUBSEP pinned SUBSEP GF[h] SUBSEP pinsig
        # every host may help seed its group shared set: what it runs on
        HOSTINFO[x] = h "\t" fmt_cpulist(ALL) "\t" (pinned != "" ? pinned : first)
        if (!(key in SHAPE)) {
            SHAPE[key] = ++ns; s = ns
            SREP[s] = h; SNM[s] = 0; SMODEL[s] = model; SNCPU[s] = ncpus; SMEMKB[s] = memkb; SMEMGIB[s] = memgib
            SN[s] = CR["n"]; SPHYS[s] = fmt_cpulist(PHYS); SALL[s] = fmt_cpulist(ALL); SSUM[s] = cores_summary(CR, PHYS, ALL)
            SLR[s] = linerate; SETH[s] = ethtool; SWHY[s] = why; SCANDS[s] = cands; SPIN[s] = pinned; SAIO[s] = ""
            SNICS[s] = ""
            if (np_) {
                split("", CNT); split("", KS); nk = 0
                for (i = 1; i <= np_; i++) {
                    p = PN[i]
                    k = NDRV[p] " [" NIDS[p] "] " (NSPD[p] ? sprintf("%g Gb/s", NSPD[p] / 1000) : "unknown speed")
                    if (!(k in CNT)) { CNT[k] = 0; KS[++nk] = k }
                    CNT[k]++
                }
                sort_arr(KS, nk, 0)
                v = ""
                for (i = 1; i <= nk; i++) v = v (i > 1 ? ", " : "") CNT[KS[i]] " x " KS[i]
                p = PN[1]
                for (i = 2; i <= np_; i++) p = p " " PN[i]
                SNICS[s] = "weka NICs " p ": " v
                if (ethtool) SNICS[s] = SNICS[s] " -> line rate " gibs(ethtool)
            } else SNICS[s] = "weka NICs: " why
        }
        s = SHAPE[key]
        SMEM[s, ++SNM[s]] = h
        # the aio room is state, not hardware: it splits no shape, but the
        # shape cells must fit its tightest member
        if ((room = probe_aio_room(P, np)) != "" && (SAIO[s] == "" || room < SAIO[s])) SAIO[s] = room
    }
    bw = 0
    for (i = 1; i <= nneed; i++) if (index(NEED[i], "bw_") == 1) bw = 1
    for (s = 1; s <= ns; s++) {
        rep = SREP[s]
        npin = host_pins(rep, PS, PQ, PNR, PFS, PJ)
        cached = ""; again = ""
        for (i = 1; i <= npin; i++)
            cached = cached (i > 1 ? " " : "") PS[i] "=" (PQ[i] != "" ? PQ[i] : "-") "/" (PNR[i] != "" ? PNR[i] : "-") "/" (PFS[i] != "" ? PFS[i] : "-") "/" (PJ[i] != "" ? PJ[i] : "-")
        if (!regen && line_gbps != "")
            for (i = 1; i <= nneed; i++)
                if ((NEED[i] in LRS) && (field(rep, NEED[i] "_qd") != "" || field(rep, NEED[i] "_nr") != "" || field(rep, NEED[i] "_fs") != "" || field(rep, NEED[i] "_nj") != ""))
                    again = again (again == "" ? "" : ", ") NEED[i]
        memcap = SMEMKB[s] ? int(SMEMKB[s] * 1024 * mem_pct / 100) : 0
        members = SMEM[s, 1]
        for (i = 2; i <= SNM[s]; i++) members = members " " SMEM[s, i]
        # id rep usable phys all linerate engines pinned memcap aio pins members;
        # usable = N, linerate bytes/s (0 unknown), pinned "-" for none, memcap
        # bytes (0 no guard), aio the tightest member room ("-" unknown), pins
        # slot=qd/nr/fs/nj words ("-" open)
        printf "%d\t%s\t%d\t%s\t%s\t%.0f\t%s\t%s\t%.0f\t%s\t%s\t%s\n", s, rep, SN[s], SPHYS[s], SALL[s], int(SLR[s]), SCANDS[s], (SPIN[s] != "" ? SPIN[s] : "-"), memcap, (SAIO[s] == "" ? "-" : sprintf("%.0f", SAIO[s])), (cached == "" ? "-" : cached), members > out
        nics = SNICS[s]
        if (line_gbps != "")
            nics = nics sprintf("; line rate %s from --line-rate %g Gb/s%s", gibs(SLR[s]), line_gbps + 0, SETH[s] ? " in place of ethtool\047s" : "")
        printf "shape %d of %d: %d host(s), calibrated on %s -- %s, %d cpus, %s, %s\n", s, ns, SNM[s], rep, (SMODEL[s] != "" ? SMODEL[s] : "cpu model unknown"), SNCPU[s], (SMEMGIB[s] ? SMEMGIB[s] " GiB" : "memory unknown"), nics
        print "  cores: " SSUM[s]
        if (ngroups > 1) print "  filesystem group of " GF[rep] ": reads that group\047s shared set"
        v = SMEM[s, 1]
        for (i = 2; i <= SNM[s] && i <= 24; i++) v = v " " SMEM[s, i]
        print "  hosts: " v (SNM[s] <= 24 ? "" : " (+" (SNM[s] - 24) " more)")
        if (again != "")
            # --line-rate searches bandwidth again; its answer replaces the
            # recorded one
            print "  --line-rate: the host file\047s bandwidth answer (" again ") is measured again against it and replaced" (cached != "" ? "; its other values still pin their knobs" : "")
        if (npin) {
            v = ""
            for (i = 1; i <= npin; i++) {
                w = ""
                if (PQ[i] != "") w = w (w == "" ? "" : ", ") "iodepth=" PQ[i]
                if (PNR[i] != "") w = w (w == "" ? "" : ", ") "nrfiles=" PNR[i]
                if (PFS[i] != "") w = w (w == "" ? "" : ", ") "filesize=" PFS[i]
                if (PJ[i] != "") w = w (w == "" ? "" : ", ") "numjobs=" PJ[i]
                v = v (i > 1 ? "; " : "") PS[i] " " w
            }
            print "  pinned by the host file (the only values tried; -g searches everything): " v
        }
        if (!SLR[s] && bw)
            printf "WARNING: shape %d (%s): %s -- the bandwidth search has no line-rate target and runs to its peak instead\n", s, rep, (SWHY[s] != "" ? SWHY[s] : "no line rate") > "/dev/stderr"
    }
    close(out)
    # per host: the cpus and engine it seeds its group shared set with
    caldir = dirname(out)
    f = path_join(caldir, "hostinfo")
    if (nh) writelines(f, HOSTINFO, nh)
    else { printf "" > f; close(f) }
    # Seed needs the pins add beyond the ladder ("<nj> <nr> <mib>",
    # seed_size): an off-ladder nrfiles, a pinned filesize, nj past 4N, the
    # twin of a pinned latency fs. Reads go to the group shared set, writes
    # to the rep.
    nd = 0
    for (s = 1; s <= ns; s++) {
        rep = SREP[s]
        npin = host_pins(rep, PS, PQ, PNR, PFS, PJ)
        for (i = 1; i <= npin; i++) {
            d = substr(PS[i], length(PS[i])); typ = substr(PS[i], 1, length(PS[i]) - 2)
            split("", NR2); n2 = 0
            if (PNR[i] ~ /^[0-9]+$/) NR2[++n2] = PNR[i] + 0
            else for (j = 1; j <= nnrs; j++) NR2[++n2] = NRS[j]
            nj = PJ[i] ~ /^[0-9]+$/ ? PJ[i] + 0 : wide * SN[s]
            fmib = 0
            if (PFS[i] != "" && (b = parse_size(PFS[i])) != "") fmib = int(b / 1048576)
            dest = d == "r" ? "needs.read." GF[rep] : "needs.write." rep
            if (!(dest in DL)) { DO[++nd] = dest; DL[dest] = "" }
            mx = 0
            for (j = 1; j <= n2; j++) {
                DL[dest] = DL[dest] sprintf("%d %d %d\n", nj, NR2[j], fmib ? fmib : (int(fsmib / NR2[j]) > 1 ? int(fsmib / NR2[j]) : 1))
                if (NR2[j] > mx) mx = NR2[j]
            }
            if ((typ == "lat" || typ == "lat1m") && fmib) DL[dest] = DL[dest] sprintf("1 1 %d\n", fmib * mx)
        }
    }
    for (i = 1; i <= nd; i++) { f = path_join(caldir, DO[i]); printf "%s", DL[DO[i]] > f; close(f) }
}
