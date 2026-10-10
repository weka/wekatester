function knob(k) { if (!(k in K)) awk_fail("cal_plan: no " k "= knob"); return K[k] }
# a ladder knob, "1,2,4": sorted, each value once
function lad(k, A,    n, P, i, v, m, U) {
    split("", A); m = 0
    n = split(knob(k), P, ",")
    for (i = 1; i <= n; i++) {
        if (strip(P[i]) == "") continue
        if ((v = py_int(P[i])) == "") awk_fail("cal_plan: " k "=" K[k] ": not a list of numbers")
        if (!(v in U)) { U[v] = 1; A[++m] = v }
    }
    sort_arr(A, m, 1)
    return m
}
# A pinned value is the only value its knob takes, on every rung, never
# capped by a guard (README, What lands in the host file).
function pin(k,    v) { v = (k in K) ? K[k] : "-"; return v ~ /^[0-9]+$/ && v + 0 > 0 ? v + 0 : 0 }
function key(nj, qd, nr) { return nj SUBSEP qd SUBSEP nr }
function kj(k,    P) { split(k, P, SUBSEP); return P[1] + 0 }
function kq(k,    P) { split(k, P, SUBSEP); return P[2] + 0 }
function kr(k,    P) { split(k, P, SUBSEP); return P[3] + 0 }
# the readings of a cell: decision ones leave out the confirm pass,
# whose readings never steer a step that came before it
function best(k, decision) { return decision ? ((k in BDEC) ? BDEC[k] : "") : ((k in BALL) ? BALL[k] : "") }
function nreads(k) { return (k in NRD) ? NRD[k] : 0 }
function cell(phase, k, rt) {
    printf "cell %s %d %d %d %s\n", phase, kj(k), kq(k), kr(k), (rt != "" ? rt : RUNT)
    exit 0
}
function finish(k, msg) { printf "done %d %d %d %s\n", kj(k), kq(k), kr(k), msg; exit 0 }
# The leader rule (Frank, 2026-10-05): a reading takes the lead only
# when it is at least THR percent better than the leader.
function ahead(v, lead) { return lead <= 0 || v >= lead * (1 + THR / 100) }
function plateau(V, n,    top, miss, i) {   # STOP consecutive rungs failed to take the lead
    top = 0; miss = 0
    for (i = 1; i <= n; i++) {
        if (ahead(V[i], top)) { top = V[i]; miss = 0 }
        else if (++miss >= STOP) return 1
    }
    return 0
}
# Walk the cells in the order the ladder measured them; a cell takes
# the lead only when it beats the leader by THR percent.
function leader(KS, n, decision,    lead, i) {
    lead = ""
    for (i = 1; i <= n; i++) if (lead == "" || ahead(best(KS[i], decision), best(lead, decision))) lead = KS[i]
    return lead
}
# Confirm order: best reading, then least outstanding IO, fewer jobs,
# shallower queue, ladder nrfiles. Does a sort before b?
function before(a, b,    x, y) {
    if ((x = best(a, 1)) != (y = best(b, 1))) return x > y
    if ((x = kj(a) * kq(a)) != (y = kj(b) * kq(b))) return x < y
    if ((x = kj(a)) != (y = kj(b))) return x < y
    if ((x = kq(a)) != (y = kq(b))) return x < y
    if ((x = (kr(a) != NRT)) != (y = (kr(b) != NRT))) return x < y
    return kr(a) < kr(b)
}
function confirm_then_pick(KS, n,    I, i, j, t) {
    for (i = 1; i <= n; i++) {   # a stable insertion sort
        t = KS[i]
        for (j = i - 1; j >= 1 && before(t, I[j]); j--) I[j + 1] = I[j]
        I[j + 1] = t
    }
    for (i = 1; i <= n && i <= CONFIRM; i++) if (nreads(I[i]) < 2) cell("confirm", I[i])
    return leader(KS, n, 0)
}
function human(v) { return ctype == "bw" ? sprintf("%.2f GiB/s", v / 1073741824) : commas(v) " IOPS" }
function geo(k) { return sprintf("numjobs=%d iodepth=%d nrfiles=%d", kj(k), kq(k), kr(k)) }
function where(nj) { return nj <= N ? "one job per physical core" : "siblings in" }
# Every in-flight limit that refuses cell k; neither depends on nrfiles.
function over(k,    why) {
    why = ""
    if (memcap > 0 && kj(k) * kq(k) * BS > memcap) why = "its in-flight buffers exceed the memory guard (CAL_MEM_PCT)"
    if (AIOCAP != "" && kj(k) * kq(k) > AIOCAP)
        why = why (why == "" ? "" : " and ") sprintf("libaio would set up %.0f aio events and the kernel has room for %.0f", kj(k) * kq(k), AIOCAP)
    return why
}
# a pinned depth at a pinned job count is used as written: no guard
function fits(k) { return (PNJ && PQD) || over(k) == "" }
# One note per job count and depth, naming every limit that refused it.
function guard(k,    why, n) {
    why = over(k)
    n = sprintf("the queue ladder stopped short of numjobs=%d iodepth=%d: %s", kj(k), kq(k), why)
    if (index(why, "libaio") == 1) n = n " (raise fs.aio-max-nr and re-measure with -g to search deeper)"
    if (!(n in NOTED)) { NOTED[n] = 1; NOTES[++nnotes] = n }
}
function note(    s, i) { s = ""; for (i = 1; i <= nnotes; i++) s = s "; " NOTES[i]; return s }
function reading(k,    n) { n = nreads(k); return n > 1 ? sprintf("%s (best of %d)", human(best(k, 0)), n) : human(best(k, 0)) }
function of_line(k) { return linerate > 0 ? sprintf(" = %.1f%% of the %.2f GiB/s line rate", best(k, 0) * 100 / linerate, linerate / 1073741824) : "" }
function add(A, n, v) { A[n + 1] = v; return n + 1 }
BEGIN {
    act = ARGV[1]; ctype = ARGV[2]; eng = ARGV[4]
    N = py_int(ARGV[5]) + 0; if (N < 1) N = 1
    linerate = ARGV[6] + 0; memcap = ARGV[7] + 0; hist = ARGV[8]
    for (a = 9; a < ARGC; a++) if ((p = index(ARGV[a], "="))) K[substr(ARGV[a], 1, p - 1)] = substr(ARGV[a], p + 1)
    EXH = ("exh" in K) && K["exh"] == "1"
    # safe and max search numjobs only, at a fixed fq/fn; cal and brutal
    # walk the ladders
    LVL = ("lvl" in K) ? K["lvl"] : "cal"; FIXED = LVL == "safe" || LVL == "max"
    LINE = knob("line") + 0; THR = knob("thr") + 0; STOP = py_int(knob("stop")) + 0; CONFIRM = py_int(knob("confirm")) + 0
    RUNT = knob("rt"); NRT = py_int(knob("nr")) + 0
    nnrl = lad("nrc", NRL); nbq = lad("bwqd", BWQD); niq = lad("iopsqd", IOPSQD)
    sync = eng == "psync" || eng == "sync" || eng == "pvsync" || eng == "pvsync2" || eng == "vsync"
    if (sync) { split("", BWQD); split("", IOPSQD); BWQD[1] = 1; IOPSQD[1] = 1; nbq = 1; niq = 1 }   # one IO in flight per job, whatever iodepth says
    # libaio: numjobs x iodepth events past the room die with EAGAIN
    AIOCAP = eng == "libaio" && ("aio" in K) && K["aio"] ~ /^[0-9]+$/ ? K["aio"] + 0 : ""
    BS = ctype == "bw" || ctype == "lat1m" ? 1048576 : 4096
    N2 = int(N / 2); if (N2 < 1) N2 = 1
    # at or below N: powers of two, N/2 and N itself (always measured), qd1
    # nr1; past N the siblings join and the ladders run
    nbl = 0; for (v = 1; v < N; v *= 2) U1[v] = 1
    U1[N] = 1; U1[N2] = 1
    for (v in U1) BW_LOW[++nbl] = v + 0
    sort_arr(BW_LOW, nbl, 1)
    nhigh = 2; HIGH[1] = 2 * N; HIGH[2] = 4 * N
    nil = 0; IOPS_LOW[++nil] = N2; if (N != N2) IOPS_LOW[++nil] = N
    nfx = 0; FIXED_NJ[++nfx] = N2; if (N != N2) FIXED_NJ[++nfx] = N; FIXED_NJ[++nfx] = 2 * N
    PNJ = pin("pin_nj"); PQD = pin("pin_qd"); PNR = pin("pin_nr")
    if (PNJ) {
        split("", BW_LOW); split("", IOPS_LOW); split("", HIGH); split("", FIXED_NJ)
        nbl = 0; nil = 0; nhigh = 0
        if (PNJ <= N) { BW_LOW[++nbl] = PNJ; IOPS_LOW[++nil] = PNJ } else HIGH[++nhigh] = PNJ
        nfx = 1; FIXED_NJ[1] = PNJ
    }
    if (PQD) { split("", BWQD); split("", IOPSQD); BWQD[1] = PQD; IOPSQD[1] = PQD; nbq = 1; niq = 1 }
    if (PNR) { split("", NRL); NRL[1] = PNR; nnrl = 1; NRT = PNR }
    QD1 = PQD ? PQD : 1   # the qd of the qd1 rungs
    nnrx = 0; for (i = 1; i <= nnrl; i++) if (NRL[i] != NRT) NRX[++nnrx] = NRL[i]
    pinned = ""
    if (PNJ) pinned = pinned (pinned == "" ? "" : ", ") "numjobs=" PNJ
    if (PQD) pinned = pinned (pinned == "" ? "" : ", ") "iodepth=" PQD
    if (PNR) pinned = pinned (pinned == "" ? "" : ", ") "nrfiles=" PNR
    if (act == "budget") {
        if (ctype == "lat" || ctype == "lat1m") n = nnrl
        else if (FIXED) n = nfx + CONFIRM
        else if (ctype == "bw") n = nbl + nhigh * nnrl * nbq + CONFIRM
        else if (EXH) n = nil + nhigh * nnrl * niq + CONFIRM
        else n = nil + nhigh * (niq + 2 * nnrx) + CONFIRM
        print n
        exit 0
    }
    if ((n = readlines(hist, L)) < 0) awk_fail("cal_plan: cannot read " hist)
    top_all = ""
    for (i = 1; i <= n; i++) {
        if ((m = pysplit(L[i], F)) < 7) continue
        k = key(F[3] + 0, F[4] + 0, F[5] + 0); v = F[7] + 0
        NRD[k]++
        if (!(k in BALL) || v > BALL[k]) BALL[k] = v
        if (!(k in MINR) || v < MINR[k]) MINR[k] = v
        if (F[1] != "confirm" && (!(k in BDEC) || v > BDEC[k])) BDEC[k] = v
        if (m > 7 && (!(k in AUX) || F[8] + 0 > AUX[k])) AUX[k] = F[8] + 0
        if (top_all == "" || v > top_all) top_all = v
    }
    nnotes = 0
    if (pinned != "") NOTES[++nnotes] = "pinned by the host file: " pinned " -- the only value(s) tried"

    if (FIXED && (ctype == "bw" || ctype == "iops")) {
        # safe and max: N/2, N, 2N at one iodepth and nrfiles, every rung,
        # the leader wins; a sync engine at qd1
        qd = PQD ? PQD : sync ? 1 : (("fq" in K) && K["fq"] ~ /^[0-9]+$/) ? K["fq"] + 0 : 1
        nr = PNR ? PNR : (("fn" in K) && K["fn"] ~ /^[0-9]+$/) ? K["fn"] + 0 : 1
        nk = 0
        for (i = 1; i <= nfx; i++) {
            k = key(FIXED_NJ[i], qd, nr)
            if (!fits(k)) { guard(k); break }   # both guards grow with numjobs: a wider count cannot fit either
            if (best(k, 1) == "") cell("numjobs", k)
            KS[++nk] = k
        }
        if (!nk) awk_fail(sprintf("cal_plan: -a %s: no job count fits at iodepth=%d (%s)", LVL, qd, substr(note(), 3)))
        k = confirm_then_pick(KS, nk)
        js = ""
        for (i = 1; i <= nk; i++) js = js (i > 1 ? ", " : "") kj(KS[i])
        finish(k, sprintf("%s -> %s%s (-a %s: numjobs %s at iodepth %d nrfiles %d, the leader by %g%%; %s)%s", geo(k), reading(k), ctype == "bw" ? of_line(k) : "", LVL, js, qd, nr, THR, where(kj(k)), note()))
    }

    if (ctype == "bw") {
        target = linerate > 0 ? linerate * LINE / 100 : 0
        if (target && top_all != "" && top_all > linerate * 1.05) {
            target = 0
            # "the line rate", not the NIC: it may be the operator --line-rate
            NOTES[++nnotes] = "a reading beat the line rate by more than 5%, so line rate is not this client\047s ceiling -- searched for the peak"
        }
        # at or below N: one job per physical core, nrfiles=1 iodepth=1, nothing else
        n1 = 0; nv = 0
        for (i = 1; i <= nbl; i++) {
            k = key(BW_LOW[i], QD1, NRT)
            if (best(k, 1) == "") cell("numjobs", k)
            D1[++n1] = k; V[++nv] = best(k, 1)
            if (target && !EXH && best(k, 1) >= target)
                finish(k, sprintf("%s -> %s%s (the first numjobs at >= %g%% of line rate, one job per physical core)%s", geo(k), human(best(k, 0)), of_line(k), LINE, note()))
            if (!target && !EXH && plateau(V, nv)) break
        }
        top1 = 0
        for (i = 1; i <= n1; i++) if (best(D1[i], 1) > top1) top1 = best(D1[i], 1)
        # past N the siblings join, and iodepth x nrfiles are searched
        n2 = 0
        for (h = 1; h <= nhigh; h++) {
            nj = HIGH[h]; top2 = 0; got = 0
            for (r = 1; r <= nnrl; r++) {
                nv = 0; split("", V)
                for (q = 1; q <= nbq; q++) {
                    k = key(nj, BWQD[q], NRL[r])
                    if (!fits(k)) { guard(k); break }
                    if (best(k, 1) == "") cell("wide", k)
                    D2[++n2] = k; got = 1
                    v = best(k, 1); V[++nv] = v
                    if (v > top2) top2 = v
                    if (target && !EXH && v >= target)
                        finish(k, sprintf("%s -> %s%s (numjobs up to N=%d on the physical cores did not reach %g%% of line rate; this is the first cell with the siblings in that did)%s", geo(k), human(v), of_line(k), N, LINE, note()))
                    if (!EXH && plateau(V, nv)) break
                }
            }
            # a guard refused every nrfiles at this count, so it was never
            # measured, and 4N cannot fit either
            if (!got) break
            if (!EXH && nj == 2 * N && !ahead(top2, top1)) {
                NOTES[++nnotes] = sprintf("2N (%d jobs, siblings in) did not beat N by %g%%; 4N was not tried", nj, THR)
                break
            }
        }
        nk = 0
        for (i = 1; i <= n1; i++) KS[++nk] = D1[i]
        for (i = 1; i <= n2; i++) KS[++nk] = D2[i]
        k = confirm_then_pick(KS, nk)
        why = EXH ? sprintf("the leader of every rung measured, by %g%%", THR) : target ? sprintf("never reached %g%% of line rate; the leader by %g%%", LINE, THR) : sprintf("the leader by %g%%", THR)
        finish(k, sprintf("%s -> %s%s (%s, %s)%s", geo(k), reading(k), of_line(k), why, where(kj(k)), note()))
    }

    if (ctype == "iops") {
        np = 0; trail = ""
        # at or below N: one job per physical core at iodepth=1 nrfiles=1, nothing else
        for (i = 1; i <= nil; i++) {
            k = key(IOPS_LOW[i], QD1, NRT)
            if (best(k, 1) == "") cell("numjobs", k)
            POOL[++np] = k
            trail = trail (trail == "" ? "" : ", ") sprintf("%d jobs %s at iodepth %d", IOPS_LOW[i], human(best(k, 1)), QD1)
        }
        top_low = 0
        for (i = 1; i <= np; i++) if (best(POOL[i], 1) > top_low) top_low = best(POOL[i], 1)
        # past N the siblings join, and iodepth x nrfiles are searched
        for (h = 1; h <= nhigh; h++) {
            nj = HIGH[h]; nm = 0; split("", MINE)
            nrs = EXH ? nnrl : 1
            for (r = 1; r <= nrs; r++) {
                nr = EXH ? NRL[r] : NRT; nv = 0; split("", V)
                for (q = 1; q <= niq; q++) {
                    k = key(nj, IOPSQD[q], nr)
                    if (!fits(k)) { guard(k); break }
                    if (best(k, 1) == "") cell(nr == NRT ? "iodepth" : "nrfiles", k)
                    POOL[++np] = k; MINE[++nm] = k; V[++nv] = best(k, 1)
                    if (!EXH && plateau(V, nv)) break
                }
            }
            if (!nm) break   # a guard (memory or aio room) stopped this job count before its first cell
            top = leader(MINE, nm, 1)
            if (!EXH)
                for (r = 1; r <= nnrx; r++) {
                    # the leader depth, and twice it within the ladder
                    q1 = kq(top); q2 = q1 * 2 < IOPSQD[niq] ? q1 * 2 : IOPSQD[niq]
                    nq = 0; split("", QS); QS[++nq] = q1 < q2 ? q1 : q2; if (q1 != q2) QS[++nq] = q1 < q2 ? q2 : q1
                    for (q = 1; q <= nq; q++) {
                        k = key(nj, QS[q], NRX[r])
                        if (!fits(k)) continue
                        if (best(k, 1) == "") cell("nrfiles", k)
                        POOL[++np] = k; MINE[++nm] = k
                    }
                }
            top = leader(MINE, nm, 1)
            trail = trail (trail == "" ? "" : ", ") sprintf("%d jobs %s at iodepth %d nrfiles %d", nj, human(best(top, 1)), kq(top), kr(top))
            if (!EXH && nj == 2 * N && !ahead(best(top, 1), top_low)) {
                NOTES[++nnotes] = sprintf("2N (%d jobs, siblings in) did not beat N by %g%%; 4N was not tried", nj, THR)
                break
            }
        }
        k = confirm_then_pick(POOL, np)
        finish(k, sprintf("%s -> %s (%s; %s)%s", geo(k), reading(k), trail, where(kj(k)), note()))
    }

    if (ctype == "lat" || ctype == "lat1m") {
        # N jobs at qd1, nrfiles the only ladder, the lowest mean wins
        nj = PNJ ? PNJ : N
        for (r = 1; r <= nnrl; r++) { k = key(nj, QD1, NRL[r]); if (!nreads(k)) cell("nrfiles", k) }
        bk = ""; list = ""
        for (r = 1; r <= nnrl; r++) {
            k = key(nj, QD1, NRL[r])
            if (bk == "" || MINR[k] < MINR[bk] || (MINR[k] == MINR[bk] && NRL[r] < kr(bk))) bk = k
            list = list (r > 1 ? ", " : "") sprintf("%d %.1f us", NRL[r], MINR[k])
        }
        msg = sprintf("%s%s -> %.1f us, %s IOPS (the lowest mean of nrfiles %s at %d jobs, %s)", ctype == "lat1m" ? "1MiB " : "", geo(bk), MINR[bk], commas((bk in AUX) ? AUX[bk] : 0), list, nj, where(nj))
        finish(bk, msg note())
    }
    awk_fail("cal_plan: unknown cell type: " ctype)
}
