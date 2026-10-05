import os, sys
targets, probedir = sys.argv[1], sys.argv[2]
auto = sys.argv[3] != "-"
hosts = sys.argv[4:]
def expand(s):
    out = set()
    for part in s.split(","):
        part = part.strip()
        if not part: continue
        if "-" in part:
            a, b = part.split("-", 1); out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out
def fmt(cpus):
    out, i = [], 0
    while i < len(cpus):
        j = i
        while j + 1 < len(cpus) and cpus[j + 1] == cpus[j] + 1:
            j += 1
        out.append(str(cpus[i]) if i == j else f"{cpus[i]}-{cpus[j]}")
        i = j + 1
    return ",".join(out)

# each host's row, first match wins (targets_field's awk exits on the first)
rows = {}
if os.path.exists(targets):
    for line in open(targets):
        p = line.rstrip("\n").split("\t")
        rows.setdefault(p[0], p)

for host in hosts:
    row = rows.get(host, [])
    req_s = row[3] if len(row) > 3 else ""
    # a host the file gives no cpu list is pinned all the same: fio never
    # lands on weka's pinned cores (Frank, 2026-09-29)
    nolist = req_s in ("", "-")
    if nolist:
        req_s = ""
    probe = os.path.join(probedir, host)
    if nolist and not os.path.exists(probe):
        continue   # never probed: nothing to pin against
    raw = open(probe).read().splitlines() if os.path.exists(probe) else []
    facts = [l.split() for l in raw]
    def first(key):   # the first "<key> <value>" line, as the awk did
        for f in facts:
            if f and f[0] == key:
                return f[1] if len(f) > 1 else ""
        return ""
    cur_s, iso_s, ncpus_s = first("taskset"), first("isolated"), first("ncpus")
    # host_priv's rule: the first "priv " line, the rest of it verbatim
    priv = next((l[len("priv "):] for l in raw if l.startswith("priv ")), "")
    req, cur, iso = expand(req_s), expand(cur_s), expand(iso_s)
    ncpus = int(ncpus_s) if ncpus_s.isdigit() else 0
    # MEASURED facts (empty/False when the probe could not test them)
    bind, tested = probe_cpu_fact(probe, "bindable")
    bindp = probe_cpu_fact(probe, "bindable_priv")[0]
    universe = probe_universe(probe, ncpus)
    # same rule as the tuner: weka pins each dedicated io thread to exactly
    # one CPU; wide masks are floating utility threads and MUST be ignored,
    # or the union covers every CPU and everything "overlaps" (seen live)
    weka = set()
    for f in facts:
        if len(f) > 1 and f[0] == "weka_allowed":
            cpus = expand(f[1])
            if len(cpus) == 1:
                weka |= cpus
    # and a dedicated core is the WHOLE core: weka hives the io thread's SMT
    # sibling off too (WEKAPP-550768), as probe_cores counts it. fio never
    # runs on either thread, whatever the list says (Frank, 2026-09-27).
    topo = probe_topology(probe)
    for c in sorted(weka):
        if c in topo:
            weka |= set(topo[c][1])

    # cpus the host does not have. fio rejects a cpus_allowed naming one -- and
    # with --client that rejection happens on the daemonized SERVER, whose error
    # text is lost: the client exits 0 with an empty client_stats and the run
    # dies later with "the jobs did not run". Trimmed here, where the row is
    # resolved, with a note naming them -- same contract as the weka overlap:
    # the host file keeps the list as written, execution runs on what exists.
    # Only when the probe carries ncpus (0 = unprobed, nothing to judge against).
    flags = []
    if nolist and not universe:
        continue   # a probe that cannot say which cpus exist: nothing to pin to
    if nolist:
        # every cpu this login can bind WITHOUT privilege -- an unlisted
        # host never escalates -- and, below, minus weka's cores (whole) and
        # core 0's pair, exactly as a list naming them all would be
        flags.append("nolist")
        req = set(universe)
        if tested:
            req &= bind
        elif cur:
            req &= cur
        req_s = fmt(sorted(req)) or "-"
    phantom = sorted(req - universe) if universe else []
    if phantom:
        flags.append("phantom")
    # Cpus this host REFUSES to bind, measured: fio's answer to one of these in
    # a cpus_allowed is err=22 cpu_set_affinity, per job, raised on the
    # daemonized server after the run has started (field client C, 2026-09-09).
    # Trimmed here on the same contract as the weka overlap.
    unbind = sorted((req - weka - set(phantom)) - bind - bindp) if tested else []
    if unbind:
        flags.append("unbindable")
    # core 0 of socket 0 and its sibling always stay with the OS (Frank,
    # 2026-09-25): fio never runs there, whatever the list says
    pair = set(topo[0][1]) if 0 in topo else {0}
    os0 = sorted(req & pair)
    if os0:
        flags.append("core0")
    # the EFFECTIVE set is the request minus weka's dedicated cores, core 0's
    # pair and the cpus the host does not have: the host file keeps the
    # operator's list as written, execution never touches those cpus
    eff = sorted(req - weka - set(phantom) - set(unbind) - pair)
    # A list covering every cpu fio could use is no choice: under -a the tuner
    # applies the whole OS reserve as if the file gave none (probe_cores), so
    # the effective set -- what the notes quote, the fio server's taskset and
    # the escalation check below -- is the tuner's, or the notes would name
    # reserve cpus fio never runs on and an "outside" verdict could escalate
    # (or die) for them. Plain runs have no reserve: the rule above stands.
    if auto:
        # under -a an unlisted host gets the tuner's own set, the one its
        # staged cpus_allowed names -- the full OS reserve applies
        tuned = probe_cores(probe, "" if nolist else req_s)
        if nolist:
            eff = tuned["all"]
        elif tuned["catchall"]:
            flags.append("catchall")
            eff = tuned["all"]
    if iso and (req & iso) and (req - iso):
        # a mask mixing isolated and housekeeping cpus silently collapses onto
        # the housekeeping partition -- worse than failing, it runs WRONG
        flags.append("mixed")
    if not eff:
        flags.append("allweka")
    # Which cpus need the escalator? MEASURED: the ones the probe could not
    # bind plainly but could under it. Without that measurement, the old rule
    # stands -- isolated cpus assumed self-affinable, so only cpus outside both
    # the current mask and the isolated set need privilege.
    elif tested:
        if set(eff) - bind:
            flags.append("outside")
    elif cur and not set(eff) <= (cur | iso):
        flags.append("outside")
    if req & weka:
        flags.append("overlap")
    print(host, req_s, cur_s or "-", ncpus_s or "-",
          ",".join(map(str, sorted(weka))) or "none",
          fmt(eff) or "none", fmt(phantom) or "none", fmt(unbind) or "none",
          fmt(os0) or "none", ",".join(flags) or "ok", priv or "-")
