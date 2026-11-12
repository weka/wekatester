BEGIN {
    res = ARGV[1]; final = ARGV[2]; force = ARGV[3] == "1"; lr = ARGV[4] != "-"
    nslot = split(geom_slots(), SLOT, " ")
    n = split(line_rate_slots(), F, " ")
    for (i = 1; i <= n; i++) LRS[F[i]] = 1
    ncols = 5 + 4 * nslot   # the host, login engine cpus dir, then nj fs nr qd per slot
    if ((n = readlines(res, L)) < 0) awk_fail("cannot read " res)
    nk = 0
    for (i = 1; i <= n; i++) {
        if (!(m = cal_results_split(L[i], F))) continue
        if (!(F[1] in KH)) KHOST[++nk] = F[1]
        KH[F[1]] = 1
        for (c = 2; c <= m; c++) K[F[1], c] = F[c]
    }
    no = 0
    if ((n = readlines(final, T)) >= 0)
        for (i = 1; i <= n; i++) { lsplit(T[i], F, "\t"); ROW[F[1]] = T[i]; ORD[++no] = F[1] }
    sort_arr(KHOST, nk, 0)
    for (x = 1; x <= nk; x++) {
        h = KHOST[x]
        if (h in ROW) nc = lsplit(ROW[h], R, "\t")
        else { split("", R); R[1] = h; nc = 1; ORD[++no] = h }
        while (nc < ncols) R[++nc] = "-"
        if (K[h, 2] != "-" && (force || R[3] == "-")) R[3] = K[h, 2]
        for (s = 1; s <= nslot; s++) {
            # Pinned values are already in the tuple; fill adds what was
            # searched. cal.results holds qd nr fs nj, the row nj fs nr qd.
            c = 3 + 4 * (s - 1); b = 6 + 4 * (s - 1)
            win = force || (lr && (SLOT[s] in LRS))
            for (q = 0; q < 4; q++)
                if ((v = K[h, c + q]) != "-" && (win || R[b + 3 - q] == "-")) R[b + 3 - q] = v
        }
        row = R[1]
        for (c = 2; c <= nc; c++) row = row "\t" R[c]
        ROW[h] = row
    }
    for (i = 1; i <= no; i++) OUT[i] = ROW[ORD[i]]
    if (no) writelines(final, OUT, no)
    else { printf "" > final; close(final) }
}
