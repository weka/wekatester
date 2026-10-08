# a cpu list the way this check reads one: blanks around a part
# dropped, an empty part skipped
function expand(s, S,    n, P, i, p, a, b, c) {
    split("", S)
    n = lsplit(s, P, ",")
    for (i = 1; i <= n; i++) {
        if ((p = strip(P[i])) == "") continue
        if (index(p, "-")) {
            a = py_int(substr(p, 1, index(p, "-") - 1)); b = py_int(substr(p, index(p, "-") + 1))
            if (a == "" || b == "") awk_fail("pinning: not a cpu list: " s)
            for (c = a; c <= b; c++) S[c] = 1
        } else {
            if ((a = py_int(p)) == "") awk_fail("pinning: not a cpu list: " s)
            S[a] = 1
        }
    }
}
function fact(P, np, key,    i, F) {   # the first "<key> <value>" line, as the awk did
    for (i = 1; i <= np; i++) if (index(P[i], key) && pysplit(P[i], F) && F[1] == key) return F[2]
    return ""
}
function fmt_or(S, none,    v) { v = fmt_cpulist(S); return v == "" ? none : v }
function flag(f) { flags = flags (flags == "" ? "" : ",") f }
BEGIN {
    auto = ARGV[3] != "-"
    # each host row, the first per host (targets_field reads the first)
    if ((n = readlines(ARGV[1], L)) > 0)
        for (i = 1; i <= n; i++) {
            split(L[i], F, "\t")
            if (!(F[1] in ROW)) ROW[F[1]] = (4 in F) ? F[4] : ""
        }
    for (a = 4; a < ARGC; a++) {
        host = ARGV[a]; req_s = (host in ROW) ? ROW[host] : ""
        # a host the file gives no cpu list is pinned all the same: fio
        # never lands on the pinned cores of weka (Frank, 2026-09-29)
        if ((nolist = req_s == "" || req_s == "-")) req_s = ""
        if ((np = readlines(ARGV[2] "/" host, P)) < 0) {
            if (nolist) continue   # never probed: nothing to pin against
            np = 0
        }
        cur_s = fact(P, np, "taskset"); iso_s = fact(P, np, "isolated"); ncpus_s = fact(P, np, "ncpus")
        priv = ""   # host_priv rule: the first "priv " line, the rest of it verbatim
        for (i = 1; i <= np; i++) if (index(P[i], "priv ") == 1) { priv = substr(P[i], 6); break }
        expand(req_s, REQ); expand(cur_s, CUR); expand(iso_s, ISO)
        ncpus = ncpus_s ~ /^[0-9]+$/ ? ncpus_s + 0 : 0
        # MEASURED facts (empty, untested, when the probe could not test)
        tested = probe_cpu_fact(P, np, "bindable", BIND)
        probe_cpu_fact(P, np, "bindable_priv", BINDP)
        probe_universe(P, np, ncpus, U)
        # weka pins each dedicated io thread to exactly one cpu; wide masks
        # are floating utility threads and must be ignored, or everything
        # overlaps
        split("", WEKA)
        for (i = 1; i <= np; i++)
            if (index(P[i], "weka_allowed") && pysplit(P[i], F) > 1 && F[1] == "weka_allowed") {
                expand(F[2], S)
                if (set_size(S) == 1) for (c in S) WEKA[c] = 1
            }
        # a dedicated core is the whole core: weka idles the sibling too
        # (WEKAPP-550768)
        probe_topology(P, np, TK, TS, TL)
        nw = set_sorted(WEKA, W)
        for (i = 1; i <= nw; i++)
            if (W[i] in TK) { nt = split(TL[W[i]], T, ","); for (j = 1; j <= nt; j++) WEKA[T[j]] = 1 }
        flags = ""
        if (nolist && !set_any(U)) continue   # a probe that cannot say which cpus exist: nothing to pin to
        if (nolist) {
            # every cpu this login binds without privilege (an unlisted
            # host never escalates), less weka cores and core 0 pair, as a
            # list naming them all would
            flag("nolist")
            split("", REQ)
            for (c in U) if (tested ? (c in BIND) : (!set_any(CUR) || (c in CUR))) REQ[c] = 1
            if ((req_s = fmt_cpulist(REQ)) == "") req_s = "-"
        }
        # cpus the host does not have: fio rejects them on the daemonized
        # server, where the error is lost, so trim with a note; the host
        # file keeps its list
        split("", PHANTOM)
        if (set_any(U)) for (c in REQ) if (!(c in U)) PHANTOM[c] = 1
        if (set_any(PHANTOM)) flag("phantom")
        # cpus the host refuses to bind (measured): fio answers err=22
        # cpu_set_affinity per job, after the run has started
        split("", UNBIND)
        if (tested) for (c in REQ) if (!(c in WEKA) && !(c in PHANTOM) && !(c in BIND) && !(c in BINDP)) UNBIND[c] = 1
        if (set_any(UNBIND)) flag("unbindable")
        # core 0 of socket 0 and its sibling always stay with the OS
        # (Frank, 2026-09-25)
        split("", PAIR)
        if (0 in TK) { nt = split(TL[0], T, ","); for (j = 1; j <= nt; j++) PAIR[T[j]] = 1 }
        else PAIR[0] = 1
        split("", OS0)
        for (c in REQ) if (c in PAIR) OS0[c] = 1
        if (set_any(OS0)) flag("core0")
        # the EFFECTIVE set: the request minus the cores of weka, the
        # pair of core 0, and the cpus the host does not have or bind
        split("", EFF)
        for (c in REQ) if (!(c in WEKA) && !(c in PHANTOM) && !(c in UNBIND) && !(c in PAIR)) EFF[c] = 1
        # A list covering every usable cpu is no choice: under -a the
        # effective set is the tuner set (probe_cores), or the notes would
        # name reserve cpus fio never runs on and an "outside" verdict
        # could escalate for them. Plain runs have no reserve.
        if (auto) {
            probe_cores(P, np, nolist ? "" : req_s, R, PHYS, ALL)
            if (nolist || R["catchall"]) {
                if (!nolist) flag("catchall")
                split("", EFF); for (c in ALL) EFF[c] = 1
            }
        }
        # a mask mixing isolated and housekeeping cpus collapses onto
        # housekeeping
        iso_in = 0; iso_out = 0
        if (set_any(ISO)) for (c in REQ) if (c in ISO) iso_in = 1; else iso_out = 1
        if (iso_in && iso_out) flag("mixed")
        # Which cpus need the escalator: MEASURED, those the probe could
        # bind only under it. Without the measurement, isolated cpus are
        # assumed self-affinable.
        if (!set_any(EFF)) flag("allweka")
        else if (tested) {
            for (c in EFF) if (!(c in BIND)) { flag("outside"); break }
        } else if (set_any(CUR)) {
            for (c in EFF) if (!(c in CUR) && !(c in ISO)) { flag("outside"); break }
        }
        for (c in REQ) if (c in WEKA) { flag("overlap"); break }
        w = join_sorted(WEKA, ",")
        print host, req_s, (cur_s == "" ? "-" : cur_s), (ncpus_s == "" ? "-" : ncpus_s), (w == "" ? "none" : w), fmt_or(EFF, "none"), fmt_or(PHANTOM, "none"), fmt_or(UNBIND, "none"), fmt_or(OS0, "none"), (flags == "" ? "ok" : flags), (priv == "" ? "-" : priv)
    }
}
