# --- the calibration seed ---
# A need is (nj, nr, mib) in ND[i, 1..3]. File f is sized to the largest share
# any need takes (README, Seeding); all sizes fixed before the first seed.
function needs_ladder(ND, n, nrs, fsmib, nj,    A, m, i, k, U, S) {   # the nrfiles ladder <nrs>, appended; the new count
    m = pysplit(nrs, A); k = 0
    for (i = 1; i <= m; i++) if (A[i] ~ /^[0-9]+$/ && !((A[i] + 0) in U)) { U[A[i] + 0] = 1; S[++k] = A[i] + 0 }
    sort_arr(S, k, 1)
    for (i = 1; i <= k; i++)
        if (S[i] > 0) { n++; ND[n, 1] = nj; ND[n, 2] = S[i]; ND[n, 3] = int(fsmib / S[i]) > 1 ? int(fsmib / S[i]) : 1 }
    return n
}
function needs_listed(ND, n, path,    L, m, i, F) {   # "<nj> <nr> <mib>" lines (cal_shapes' needs.*), appended
    m = readlines(path, L)
    for (i = 1; i <= m; i++)
        if (pysplit(L[i], F) == 3 && F[1] ~ /^[0-9]+$/ && F[2] ~ /^[0-9]+$/ && F[3] ~ /^[0-9]+$/) {
            n++; ND[n, 1] = F[1] + 0; ND[n, 2] = F[2] + 0; ND[n, 3] = F[3] + 0
        }
    return n
}
function seed_size(ND, n, j, f,    i, best) {   # MiB file f of job j is seeded at; 0 when nothing needs it
    best = 0
    for (i = 1; i <= n; i++) if (j < ND[i, 1] && f < ND[i, 2] && ND[i, 3] > best) best = ND[i, 3]
    return best
}
function seed_name(prefix, fmt, j, f) { return replace_all(replace_all(prefix fmt, "$jobnum", j), "$filenum", f) }
# GF[h] the first member of h's filesystem group (lays out and prices its
# shared read set), GM[h] all members; no groups file means one group.
function fs_groups(work, H, nh, GF, GM,    L, n, i, F, G, g, FIRST, ALL) {
    split("", GF); split("", GM)
    n = readlines(work "/groups", L)
    for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2) G[F[1]] = F[2]
    for (i = 1; i <= nh; i++) {
        g = (H[i] in G) ? G[H[i]] : "1"
        if (g in FIRST) ALL[g] = ALL[g] " " H[i]
        else { FIRST[g] = H[i]; ALL[g] = H[i] }
    }
    for (i = 1; i <= nh; i++) { g = (H[i] in G) ? G[H[i]] : "1"; GF[H[i]] = FIRST[g]; GM[H[i]] = ALL[g] }
}
