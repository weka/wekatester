# --- probe facts (the probe snippet's lines, P[1..np]) ---
# Cpus on the first "key <list>" line: "-" means tested and empty; an absent
# line (0) means untested, and the caller falls back to its own rule.
function probe_cpu_fact(P, np, key, S,    i, F) {
    split("", S)
    for (i = 1; i <= np; i++)
        if (index(P[i], key) && pysplit(P[i], F) > 1 && F[1] == key) {
            if (F[2] != "-" && !parse_cpulist(F[2], S)) awk_fail("probe: bad cpu list on its " key " line: " F[2])
            return 1
        }
    return 0
}
# The kernel online list, else 0..ncpus-1 (wrong when a cpu is offline).
function probe_universe(P, np, ncpus, U,    c) {
    if (probe_cpu_fact(P, np, "online", U) && set_any(U)) return
    split("", U)
    for (c = 0; c < ncpus; c++) U[c] = 1
}
# Cpus the probe measured as unbindable; empty when it could not test.
function probe_unbindable(P, np, U, UB,    B, BP, c) {
    split("", UB)
    if (!probe_cpu_fact(P, np, "bindable", B)) return
    probe_cpu_fact(P, np, "bindable_priv", BP)
    for (c in U) if (!(c in B) && !(c in BP)) UB[c] = 1
}
# TK[c] every cpu named, TS[c] its socket, TL[c] its core threads; 1 when the
# probe carried topology, else every cpu counts as its own core.
function probe_topology(P, np, TK, TS, TL,    i, F, c, v, pkg, cid, sib, self, S, key, BY) {
    split("", TK); split("", TS); split("", TL)
    split("", pkg); split("", cid); split("", sib); split("", self); split("", BY)
    for (i = 1; i <= np; i++) {
        if (!index(P[i], "topo_") || pysplit(P[i], F) < 3 || substr(F[1], 1, 5) != "topo_" || F[2] !~ /^[0-9]+$/) continue
        c = F[2] + 0
        if (F[1] == "topo_physical_package_id") { if ((v = py_int(F[3])) != "") pkg[c] = v }
        else if (F[1] == "topo_core_id") { if ((v = py_int(F[3])) != "") cid[c] = v }
        else if (F[1] == "topo_thread_siblings_list" && parse_cpulist(F[3], S)) { sib[c] = join_sorted(S, ","); self[c] = c in S }
    }
    for (c in pkg) TK[c] = 1
    for (c in cid) TK[c] = 1
    for (c in sib) TK[c] = 1
    # threads without a siblings list share a core with every thread of the
    # same (socket, core_id)
    for (c in TK) {
        TS[c] = (c in pkg) ? pkg[c] : 0
        if (!(c in sib) && (c in cid)) {
            key = TS[c] SUBSEP cid[c]
            if (key in BY) BY[key] = BY[key] "," c; else BY[key] = c
        }
    }
    for (c in TK) {
        if ((c in sib) && self[c]) TL[c] = sib[c]
        else if (c in cid) {
            key = TS[c] SUBSEP cid[c]
            if (!(key in BY)) awk_fail("probe: cpu " c " is missing from its own thread_siblings_list")
            TL[c] = BY[key]
        } else
            TL[c] = c
    }
    return set_any(TK)
}
# OS reserve (README, Usable cores). reserve_count: how many; place_reserve:
# core 0 first, then round-robin over sockets, lowest free core each. Never a
# DPDK core, not even core 0 when weka pinned it.
function reserve_count(ncores, ndpdk,    v) {
    v = (ncores <= 24 ? 2 : 4) + (ndpdk > 4 ? int((ndpdk - 1) / 4) : 0)
    if (v > 12) v = 12
    if (v > int(ncores / 2)) v = int(ncores / 2)
    return v < 1 ? 1 : v
}
function place_reserve(ORD, nk, SOCK, DPDK, core0, want, RES,    n, i, s, ns, SO, seen, p, r, RR, FREE, FH, FN, left) {
    split("", RES); n = 0
    if (core0 != "" && !(core0 in DPDK)) RES[++n] = core0
    ns = 0
    for (i = 1; i <= nk; i++)
        if (!((s = SOCK[ORD[i]]) in seen)) { seen[s] = 1; SO[++ns] = s }
    if (ns == 0) return n
    sort_arr(SO, ns, 1)
    p = 1
    for (i = 1; i <= ns; i++) if (SO[i] == SOCK[core0]) { p = i; break }
    r = 0
    for (i = p + 1; i <= ns; i++) RR[++r] = SO[i]
    for (i = 1; i <= p; i++) RR[++r] = SO[i]
    for (i = 1; i <= ns; i++) { FH[SO[i]] = 1; FN[SO[i]] = 0 }
    for (i = 1; i <= nk; i++)
        if (!(ORD[i] in DPDK) && !(n && ORD[i] == RES[1])) {
            s = SOCK[ORD[i]]; FREE[s, ++FN[s]] = ORD[i]
        }
    while (n < want) {
        left = 0
        for (i = 1; i <= ns; i++) if (FH[SO[i]] <= FN[SO[i]]) left = 1
        if (!left) break
        for (i = 1; i <= r; i++) {
            if (n >= want) break
            s = RR[i]
            if (FH[s] <= FN[s]) RES[++n] = FREE[s, FH[s]++]
        }
    }
    return n
}
# The cpus fio may use, in physical cores: ONE rule for staging, calibration,
# usable_cores and the pinning check (README, Usable cores). DPDK cores go
# whole (WEKAPP-550768). R gets n, ncores, dpdk, nres, res, weka_core0,
# unlisted, unbound, topo, catchall. Three functions: awk caps parameters plus
# locals at 50.
function probe_cores(P, np, base_list, R, PHYS, ALL,    U, UB, CORE, THR, ORD, nk, SOCK, DPDK, core0, B, RES, nres, SKIP, S, i, j, k, T, nt, t, inb, use, unlisted, unbound, res) {
    split("", R); split("", PHYS); split("", ALL)
    nk = probe_core_map(P, np, U, UB, CORE, THR, ORD, SOCK, DPDK, R)
    core0 = (0 in CORE) ? CORE[0] : (nk ? ORD[1] : "")
    split("", RES); nres = 0
    if (probe_base(base_list, U, UB, THR, DPDK, core0, B, R)) {
        # core 0's pair -- unless weka owns core 0: then it already left as
        # a DPDK core, and counting it twice broke the logged sum
        if (core0 != "" && !(core0 in DPDK)) RES[++nres] = core0
    } else {
        split("", B)
        for (k in U) B[k] = 1
        nres = place_reserve(ORD, nk, SOCK, DPDK, core0, reserve_count(nk, set_size(DPDK)), RES)
    }
    res = ""
    for (i = 1; i <= nres; i++) {
        split("", S); nt = split(THR[RES[i]], T, ",")
        for (j = 1; j <= nt; j++) S[T[j]] = 1
        res = res (i > 1 ? " " : "") fmt_cpulist(S)
        SKIP[RES[i]] = 1
    }
    use = 0; unlisted = 0; unbound = 0
    for (i = 1; i <= nk; i++) {
        k = ORD[i]
        if ((k in DPDK) || (k in SKIP)) continue
        nt = split(THR[k], T, ","); t = 0; inb = 0
        for (j = 1; j <= nt; j++) {
            if (!(T[j] in B)) continue
            inb = 1
            if (T[j] in UB) continue
            if (!t++) PHYS[T[j]] = 1
            ALL[T[j]] = 1
        }
        if (t) use++
        else if (inb) unbound++   # listed, but the host binds none of its threads
        else unlisted++           # the operator's list leaves the whole core out
    }
    R["n"] = use; R["ncores"] = nk; R["dpdk"] = set_size(DPDK)
    R["nres"] = nres; R["res"] = res == "" ? "none" : res
    R["weka_core0"] = core0 != "" && (core0 in DPDK)
    R["unlisted"] = unlisted; R["unbound"] = unbound
}
# U cpus, UB unbindable, CORE[cpu] its core key (lowest online thread),
# THR[key] threads, ORD[1..n] keys (n returned), SOCK[key], DPDK the keys of
# single-cpu weka masks, R["topo"].
function probe_core_map(P, np, U, UB, CORE, THR, ORD, SOCK, DPDK, R,    i, F, S, ncpus, weka, TK, TS, TL, A, n, c, m, T, nt, j, k, nk) {
    ncpus = 0; split("", weka)
    for (i = 1; i <= np; i++) {
        if (!index(P[i], "ncpus") && !index(P[i], "weka_allowed")) continue
        if (pysplit(P[i], F) < 2) continue   # a bare isolated line: no isolated cpus
        if (F[1] == "ncpus" && F[2] ~ /^[0-9]+$/) ncpus = F[2] + 0
        else if (F[1] == "weka_allowed") {
            if (!parse_cpulist(F[2], S)) awk_fail("probe: bad cpu list on a weka_allowed line: " F[2])
            if (set_size(S) == 1) for (c in S) weka[c] = 1
        }
    }
    probe_universe(P, np, ncpus, U)
    probe_unbindable(P, np, U, UB)
    R["topo"] = probe_topology(P, np, TK, TS, TL)
    split("", CORE); split("", THR)
    n = set_sorted(U, A)
    for (i = 1; i <= n; i++) {
        c = A[i]; m = c
        if (c in TK) {
            nt = split(TL[c], T, ",")
            for (j = 1; j <= nt; j++) if ((T[j] in U) && T[j] + 0 < m) m = T[j] + 0
        }
        CORE[c] = m
        if (m in THR) THR[m] = THR[m] "," c; else THR[m] = c
    }
    nk = set_sorted(THR, ORD)
    split("", SOCK); split("", DPDK)
    for (i = 1; i <= nk; i++) SOCK[ORD[i]] = (ORD[i] in TK) ? TS[ORD[i]] : 0
    for (c in weka) if (c in CORE) DPDK[CORE[c]] = 1
    return nk
}
# An operator cpu list, trimmed to the host cpus, into B; one covering every
# cpu fio could use restricts nothing (R["catchall"]).
function probe_base(base_list, U, UB, THR, DPDK, core0, B, R,    BU, NEVER, c, k, T, nt, j) {
    R["catchall"] = 0
    if (base_list == "") return 0
    if (!parse_cpulist(base_list, B)) awk_fail("bad cpu list: " base_list)
    if (!set_any(U)) return 1
    for (c in B) if (c in U) BU[c] = 1
    split("", B)
    for (c in BU) B[c] = 1
    for (c in UB) NEVER[c] = 1
    for (k in DPDK) { nt = split(THR[k], T, ","); for (j = 1; j <= nt; j++) NEVER[T[j]] = 1 }
    if (core0 != "") { nt = split(THR[core0], T, ","); for (j = 1; j <= nt; j++) NEVER[T[j]] = 1 }
    for (c in U) if (!(c in NEVER) && !(c in B)) return 1
    R["catchall"] = 1
    return 0
}
# probe_cores in one log line; a term only when nonzero, so the sum adds up.
function cores_summary(R, PHYS, ALL) { return cores_summary_s(R, fmt_cpulist(PHYS), fmt_cpulist(ALL)) }
function cores_summary_s(R, p, a,    more) {   # p and a already formatted
    more = ""
    if (R["unlisted"]) more = more sprintf(" - %d outside the host-file cpu list", R["unlisted"])
    if (R["unbound"]) more = more sprintf(" - %d unbindable", R["unbound"])
    return sprintf("%d physical core(s)%s - %d weka DPDK - %d reserved for the OS (%s)%s = N=%d: N/2 and N jobs on %s, 2N and 4N on %s", R["ncores"], R["topo"] ? "" : " (no topology: one per cpu)", R["dpdk"], R["nres"], R["res"], more, R["n"], p == "" ? "none" : p, a == "" ? "none" : a)
}
# Aio events left: fs.aio-max-nr less fs.aio-nr, "" when unknown. Exact
# before kernel 3.12 and from 4.14; 3.12-4.13 charge max(iodepth, 4 x cpus)
# per job and double aio-nr, so it is rough there.
function probe_aio_room(P, np,    i, F, mx, nr) {
    mx = ""; nr = ""
    for (i = 1; i <= np; i++)
        if (index(P[i], "aio_") && pysplit(P[i], F) == 2 && F[2] ~ /^[0-9]+$/) {
            if (F[1] == "aio_max_nr") mx = F[2] + 0
            else if (F[1] == "aio_nr") nr = F[2] + 0
        }
    if (mx == "") return ""
    mx -= (nr == "" ? 0 : nr)
    return mx < 0 ? 0 : mx
}
