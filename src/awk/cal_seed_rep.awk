BEGIN {
    SEED_ANY_JOB = 2 ^ 30; SEED_CHUNK = 16
    host = ARGV[1]; rnj = ARGV[2] + 0; rnr = ARGV[3] + 0; wnj = ARGV[4] + 0; wnr = ARGV[5] + 0
    fsmib = ARGV[6] + 0; job = ARGV[7]; outdir = ARGV[8]; fmt = ARGV[10]; sep = ARGV[11]
    unified = ARGV[12] == "1"; sparse = unified && ARGV[13] == "0"; tlist = ARGV[14]
    # streamed, and only shared. and this host own names: a shared
    # destination lists every member write set too
    while ((r = (getline line < ARGV[9])) > 0)
        if ((index(line, "shared.") == 1 || index(line, host sep) == 1) && pysplit(line, F) == 2 && F[2] ~ /^[0-9]+$/) HAVE[F[1]] = F[2] + 0
    if (r < 0) awk_fail("cannot read " ARGV[9])
    close(ARGV[9])
    # the nrfiles ladder shares, plus any listed need beyond it: what a
    # host-file value pins past the grid
    nrd = needs_listed(RN, needs_ladder(RN, 0, ARGV[15], fsmib, SEED_ANY_JOB), ARGV[17])
    nwr = needs_listed(WN, needs_ladder(WN, 0, ARGV[15], fsmib, SEED_ANY_JOB), ARGV[18])
    if (!unified) {
        # the scratch keeps reads and writes on the same files: one size serves both
        for (i = 1; i <= nwr; i++) for (k = 1; k <= 3; k++) RN[nrd + i, k] = WN[i, k]
        nrd += nwr; nwr = nrd
        for (i = 1; i <= nrd; i++) for (k = 1; k <= 3; k++) WN[i, k] = RN[i, k]
    }
    # what is missing: the read side, then the write side; a file both
    # sides name is seeded once
    ntodo = 0; nread = 0; nt = 0; tmib = 0
    for (j = 0; j < rnj; j++)
        for (f = 0; f < rnr; f++) {
            name = seed_name(unified ? "shared." : host sep, fmt, j, f)
            if (!(mib = seed_size(RN, nrd, j, f))) mib = int(fsmib / rnr) > 1 ? int(fsmib / rnr) : 1
            if ((name in SEEN) || ((name in HAVE) && HAVE[name] >= mib * 1048576)) continue
            SEEN[name] = 1; nread++
            TJ[++ntodo] = j; TN[ntodo] = name; TM[ntodo] = mib; tmib += mib
        }
    for (j = 0; j < wnj; j++)
        for (f = 0; f < wnr; f++) {
            name = seed_name(host sep, fmt, j, f)
            if (!(mib = seed_size(WN, nwr, j, f))) mib = int(fsmib / wnr) > 1 ? int(fsmib / wnr) : 1
            if ((name in SEEN) || ((name in HAVE) && HAVE[name] >= mib * 1048576)) continue
            SEEN[name] = 1
            if (sparse) { TR[++nt] = name " " mib; continue }
            TJ[++ntodo] = j; TN[ntodo] = name; TM[ntodo] = mib; tmib += mib
        }
    if (nt) writelines(tlist, TR, nt)
    else { printf "" > tlist; close(tlist) }
    nm = 0
    if ((n = readlines(ARGV[16], L)) < 0) awk_fail("cannot read " ARGV[16])
    for (i = 1; i <= n; i++) {
        if (strip(L[i]) == "") continue
        if (lsplit(L[i], F, "\t") != 4) awk_fail("a seed member line needs host, dir, cpus and engine: " L[i])
        nm++; MH[nm] = F[1]; MD[nm] = F[2]; MC[nm] = F[3]; ME[nm] = F[4]
    }
    # the unified read side round robin over the members, by file; the
    # rest to the rep
    for (k = 1; k <= ntodo; k++) {
        m = (unified && k <= nread) ? MH[(k - 1) % nm + 1] : MH[1]
        SH[m, ++SC[m]] = k
    }
    active = ""
    for (i = 1; i <= nm; i++) {
        m = MH[i]
        if (!SC[m]) continue
        # fallocate=none: a partial write must leave a short file
        # (generate_layout).
        no = 0; split("", O)
        O[++no] = "[global]"; O[++no] = "directory=" MD[i]; O[++no] = "unique_filename=0"
        O[++no] = "ioengine=" ME[i]; O[++no] = "direct=1"; O[++no] = "bs=1Mi"; O[++no] = "rw=write"
        O[++no] = "fallocate=none"; O[++no] = "create_on_open=1"
        if (MC[i] != "") { O[++no] = "cpus_allowed=" MC[i]; O[++no] = "cpus_allowed_policy=split" }
        # A section seeds up to SEED_CHUNK same-size files through a colon
        # list: one section per file passed fio REAL_MAX_JOBS (4096) on a
        # wide dataset, and the chunk keeps the line under the 4096-byte
        # parser buffer.
        split("", GK); split("", GC); split("", GN); ng = 0
        for (x = 1; x <= SC[m]; x++) {
            k = SH[m, x]; g = sprintf("%012d %012d", TJ[k], TM[k])
            if (!(g in GC)) { GK[++ng] = g; GC[g] = 0 }
            GN[g, ++GC[g]] = TN[k]
        }
        sort_arr(GK, ng, 0)
        sections = 0
        for (x = 1; x <= ng; x++) {
            g = GK[x]; split(g, P, " ")
            for (c = 0; c < GC[g]; c += SEED_CHUNK) {
                s = GN[g, c + 1]
                for (y = c + 2; y <= GC[g] && y <= c + SEED_CHUNK; y++) s = s ":" GN[g, y]
                sections++
                O[++no] = sprintf("[seed-%d-%dM-%d]", P[1], P[2], c / SEED_CHUNK)
                O[++no] = "filename=" s; O[++no] = "nrfiles=" (y - c - 1); O[++no] = "filesize=" (P[2] + 0) "M"
            }
        }
        if (sections > 4000)
            awk_fail(m ": the seed needs " sections " fio sections and fio caps a run at 4096 jobs; shorten CAL_NR_LADDER or mount weka with more cores (a smaller N)")
        writelines(outdir "/" m "/" job, O, no)
        active = active (active == "" ? "" : " ") m
    }
    printf "%d %.0f %d\n", ntodo, tmib, nt
    print active
}
