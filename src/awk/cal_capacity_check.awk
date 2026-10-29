function deficit(prefix, ND, n, rep,    i, nj, nr, j, f, mib, have, total) {
    # bytes still to write for every file the needs ask for; DNJ x DNR
    # the most jobs x files they reach
    nj = 0; nr = 0; total = 0
    for (i = 1; i <= n; i++) { if (ND[i, 1] > nj) nj = ND[i, 1]; if (ND[i, 2] > nr) nr = ND[i, 2] }
    for (j = 0; j < nj; j++)
        for (f = 0; f < nr; f++) {
            if (!(mib = seed_size(ND, n, j, f))) continue
            have = ((rep, seed_name(prefix, fmt, j, f)) in HAVE) ? HAVE[rep, seed_name(prefix, fmt, j, f)] : 0
            if (mib * 1048576 > have) total += mib * 1048576 - have
        }
    DNJ = nj; DNR = nr
    return total
}
function gib(b) { return sprintf("%.1f", b / 1073741824) }
function charge(rep, need, what,    k) {
    print "cal: capacity: " what ": ~" gib(need) "GiB to write"
    if (!(rep in AVAIL) || need == 0) return
    k = PKEY[rep]
    if (!(k in PNEED)) { PNEED[k] = 0; PAVAIL[k] = AVAIL[rep]; PO[++np] = k; P0[k] = K0[rep]; P1[k] = K1[rep] }
    PNEED[k] += need
    if (AVAIL[rep] < PAVAIL[k]) PAVAIL[k] = AVAIL[rep]
    PH[k, rep] = 1
}
# the hosts charged to a filesystem, in host order
function phosts(k,    i, s) { s = ""; for (i = 1; i <= nh; i++) if ((k, H[i]) in PH) s = s (s == "" ? "" : " ") H[i]; return s }
BEGIN {
    work = ARGV[1]; unified = ARGV[4] == ""; fmt = ARGV[5]; sep = ARGV[6]
    fsmib = ARGV[7] + 0; nrs = ARGV[8]; wide = ARGV[9] + 0   # the widest job count, x N (cal_wide)
    nh = 0
    for (a = 10; a < ARGC; a++) { H[++nh] = ARGV[a]; if (!(ARGV[a] in HIDX)) HIDX[ARGV[a]] = nh }
    n = split(ARGV[3], L, "\n")
    for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2) DIRS[F[2]] = 1
    fs_groups(work, H, nh, GF, GM)
    cap = work "/cal/cap"
    if ((n = readlines(cap "/names", L)) < 0) awk_fail("cannot read " cap "/names")
    for (i = 1; i <= n; i++) if (index(L[i], "\t")) { lsplit(L[i], F, "\t"); NAME[F[1]] = F[2] }
    if ((n = readlines(ARGV[2], L)) < 0) awk_fail("cannot read " ARGV[2])
    ns = 0
    for (i = 1; i <= n; i++) if (lsplit(L[i], F, "\t") >= 3) { ns++; SID[ns] = F[1] + 0; SR[ns] = F[2]; SN[ns] = F[3] + 0 }
    # the clients each shape calibrates on (cal/clients, cal_list_clients):
    # every one is priced; without the file, the representative alone
    if ((n = readlines(work "/cal/clients", L)) >= 0)
        for (i = 1; i <= n; i++) if (lsplit(L[i], F, "\t") == 2) CL[F[1] + 0] = F[2]
    nc = 0
    for (s = 1; s <= ns; s++) {
        m = split((SID[s] in CL) ? CL[SID[s]] : SR[s], F, " ")
        for (j = 1; j <= m; j++) { C[++nc] = F[j]; CS[nc] = s }
    }
    for (x = 1; x <= nc; x++) {
        rep = C[x]
        if ((n = readlines(cap "/" rep, L)) < 0) awk_fail("cannot read " cap "/" rep)
        # deficit asks only for shared. and the rep own files: a shared
        # destination lists every member write set too
        pre = ((rep in NAME) ? NAME[rep] : rep) sep
        for (i = 1; i <= n && L[i] != "WEKATESTER_DF"; i++)
            if ((index(L[i], "shared.") == 1 || index(L[i], pre) == 1) && pysplit(L[i], F) == 2 && F[2] ~ /^[0-9]+$/) HAVE[rep, F[1]] = F[2] + 0
        LISTED[rep] = 1
        # the seed df line: source, size in KiB, free MiB; then the fs
        # type. Hosts on one weka filesystem share its free space.
        if (i < n && pysplit(L[i + 1], F) >= 3 && F[3] ~ /^[0-9]+$/) {
            K0[rep] = "host"; K1[rep] = rep
            if (i + 2 <= n && strip(L[i + 2]) == "wekafs") { K0[rep] = F[1]; sub(/.*\//, "", K0[rep]); K1[rep] = F[2] }
            PKEY[rep] = "(\047" K0[rep] "\047, \047" K1[rep] "\047)"
            AVAIL[rep] = F[3] * 1048576
        }
    }
    if (unified && ("read" in DIRS)) {
        # one shared read set per filesystem group, for every client that
        # reads it, in host order
        nf = 0
        for (x = 1; x <= nc; x++)
            if (!((g = GF[C[x]]) in FSEEN)) { FSEEN[g] = 1; FL[++nf] = sprintf("%09d %s", HIDX[g], g) }
        sort_arr(FL, nf, 0)
        for (y = 1; y <= nf; y++) {
            first = substr(FL[y], 11); split("", ND); nd = 0; split("", SSEEN)
            for (x = 1; x <= nc; x++)
                if (GF[C[x]] == first && !(CS[x] in SSEEN)) { SSEEN[CS[x]] = 1; nd = needs_ladder(ND, nd, nrs, fsmib, wide * SN[CS[x]]) }
            nd = needs_listed(ND, nd, work "/cal/needs.read." first)
            lister = first
            if (!(first in LISTED)) for (x = 1; x <= nc; x++) if (GF[C[x]] == first) { lister = C[x]; break }
            need = deficit("shared.", ND, nd, lister)
            charge(lister, need, sprintf("the shared read set of %s\047s filesystem group (up to %d jobs x %d files)", first, DNJ, DNR))
        }
    }
    for (x = 1; x <= nc; x++) {
        rep = C[x]; s = CS[x]
        if (unified && !("write" in DIRS)) continue
        split("", ND)
        nd = needs_listed(ND, needs_ladder(ND, 0, nrs, fsmib, wide * SN[s]), work "/cal/needs.write." rep)
        if (!unified) nd = needs_listed(ND, nd, work "/cal/needs.read." GF[rep])
        need = deficit(((rep in NAME) ? NAME[rep] : rep) sep, ND, nd, rep)
        charge(rep, need, sprintf("%s\047s own %s (up to %d jobs x %d files)", rep, unified ? "write set" : "calibration scratch", DNJ, DNR))
    }
    sort_arr(PO, np, 0)
    over = 0
    for (x = 1; x <= np; x++) {
        k = PO[x]
        if (PNEED[k] <= PAVAIL[k]) continue
        over = 1
        printf "ERROR: calibration needs ~%sGiB on %s (%s) but only %sGiB is available\n", gib(PNEED[k]), (P0[k] != "host" ? "weka filesystem " P0[k] : P1[k] "\047s destination"), phosts(k), gib(PAVAIL[k]) > "/dev/stderr"
    }
    exit over ? 3 : 0   # not 2: an awk that dies on its own exits 2
}
