function gib(b) { return sprintf("%.1f", b / 1073741824) }
function need_int(v, what) {   # int(), or a stop where python raised
    if ((v = py_int(v)) == "") awk_fail("capacity: " what " is not a number")
    return v
}
# one staged jobfile: numjobs x filesize x nrfiles, or numjobs x size=
# (fio: the job total across its files)
function footprint(path, L, n,    nj, fs, sz, nr, b, job) {
    nj = first_value(L, n, "numjobs"); nj = need_int(nj == "" ? "1" : nj, path ": numjobs")
    if ((fs = first_value(L, n, "filesize")) != "") {
        if ((b = parse_size(fs)) == "") awk_fail("capacity: " path ": filesize=" fs " is not a byte count")
        nr = first_value(L, n, "nrfiles")
        return nj * b * need_int(nr == "" ? "1" : nr, path ": nrfiles")
    }
    if ((sz = first_value(L, n, "size")) != "") {
        if ((b = parse_size(sz)) != "") return nj * b
        job = path; sub(/.*\//, "", job)
        print "WARNING: " job ": size=" sz " is not a byte count; it contributes nothing to the capacity estimate" > "/dev/stderr"
    }
    return 0
}
# the layout job: per job section numjobs x nrfiles x filesize, or
# numjobs x size=
function layout_footprint(L, n,    i, s, total, insec, nj, nr, b, perfile, k, v) {
    total = 0; insec = 0
    for (i = 1; i <= n; i++) {
        s = strip(L[i])
        if (s ~ /^\[.+\]$/) {
            if (insec) total += nj * (perfile ? nr : 1) * b
            insec = s != "[global]"; nj = 1; nr = 1; b = 0; perfile = 1
            continue
        }
        if (!insec || !match(s, /^(numjobs|nrfiles|filesize|size)=[^ \t\n\013\014\r\034\035\036\037]+/)) continue
        k = substr(s, 1, index(s, "=") - 1); v = substr(s, length(k) + 2, RLENGTH - length(k) - 1)
        if (k == "numjobs") nj = need_int(v, "the layout numjobs")
        else if (k == "nrfiles") nr = need_int(v, "the layout nrfiles")
        else { if ((b = parse_size(v)) == "") b = 0; perfile = k == "filesize" }
    }
    if (insec) total += nj * (perfile ? nr : 1) * b
    return total
}
BEGIN {
    work = ARGV[1]; preview = ARGV[3] == "preview"
    before = preview ? " before calibration" : ""
    # load_fs_groups: the first host of each filesystem group prices
    # its fleet-shared read set; without the groups file, one group
    if ((n = readlines(work "/groups", L)) > 0)
        for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2) GID[F[1]] = F[2]
    for (a = 4; a < ARGC; a++) {
        g = (ARGV[a] in GID) ? GID[ARGV[a]] : "1"
        if (!(g in FIRST)) FIRST[g] = ARGV[a]
    }
    # each host staged files (the first block of a host listed twice)
    if ((m = readlines(ARGV[2], M)) < 0) awk_fail("cannot read " ARGV[2])
    last = ""
    for (i = 1; i <= m; i++) {
        split(M[i], F, "\t")
        if (F[1] != last) { last = F[1]; take = !(last in NJOB); if (take) NJOB[last] = 0 }
        if (!take) continue
        if (F[2] == "") NODIR[last] = 1
        else JOB[last, ++NJOB[last]] = F[2]
    }
    over = 0; npool = 0
    for (a = 4; a < ARGC; a++) {
        h = ARGV[a]
        if (h in NODIR) continue
        split("", NSV); nns = 0; layout = 0
        for (j = 1; j <= NJOB[h] + 0; j++) {
            p = JOB[h, j]; job = p; sub(/.*\//, "", job)
            if (job == "000-wekatester-relayout.job" || job == "999-wekatester-unlink.job") continue
            if ((n = readlines(p, L)) < 0) awk_fail("cannot read " p)
            if (job == layout_job() || is_layout_marked(L, n)) { layout += layout_footprint(L, n); continue }
            if ((ns = first_value(L, n, "filename_format")) == "") ns = "__default__:" job
            # a group fleet-shared dataset is priced once, on its first host
            if (index(ns, "shared.") == 1 && h != FIRST[(h in GID) ? GID[h] : "1"]) continue
            if (!(ns in NSV)) { NSV[ns] = 0; NSK[++nns] = ns }
            if ((b = footprint(p, L, n)) > NSV[ns]) NSV[ns] = b
        }
        req = 0
        for (k = 1; k <= nns; k++) req += NSV[NSK[k]]
        if (layout > req) req = layout
        # bytes the sweep verified serve both the layout and measured
        # namespaces
        credit = 0
        if ((n = readlines(work "/probe/" h ".laidout", L)) >= 0) {
            v = ""
            for (i = 1; i <= n; i++) v = v (i > 1 ? "\n" : "") L[i]
            v = strip(v)
            if ((credit = v == "" ? 0 : py_int(v)) == "") credit = 0
            else if (credit > req) credit = req
        }
        req -= credit
        avail = 0; key = ""
        if ((n = readlines(work "/df/" h, L)) >= 2) {
            if (pysplit(L[2], F) < 4 || (avail = py_int(F[4])) == "") awk_fail(h ": cannot read the df line: " L[2])
            avail *= 1024
            # a weka filesystem is keyed by its name (clients list
            # stateless-mount backends differently) and its size
            # (same-named filesystems of two clusters)
            if (n >= 3 && strip(L[3]) == "wekafs") { fs = F[1]; sub(/.*\//, "", fs); key = fs SUBSEP F[2] }
        }
        print "capacity" before ": " h " needs ~" gib(req) "GiB" (credit ? " (~" gib(credit) "GiB already laid out)" : "") ", has " gib(avail) "GiB available"
        # avail 0 = df unavailable, not a full filesystem: nothing to check
        if (avail && req > avail) {
            over = 1
            if (preview) print "note: " h ": the jobfiles as written need ~" gib(req) "GiB but only " gib(avail) "GiB is available; -a stages the calibrated sizes instead and checks again after calibration"
            else print "ERROR: " h ": workload needs ~" gib(req) "GiB but only " gib(avail) "GiB is available" > "/dev/stderr"
        }
        if (key != "" && avail) {
            if (!(key in PN)) { PN[key] = 0; PNEED[key] = 0; PAVAIL[key] = avail; PK[++npool] = key }
            PH[key, ++PN[key]] = h; PNEED[key] += req
            if (avail < PAVAIL[key]) PAVAIL[key] = avail
        }
    }
    # every host fitting alone is not the fleet fitting: 3 hosts needing
    # 640 GiB each passed against one 1000 GiB filesystem
    sort_arr(PK, npool, 0)
    for (i = 1; i <= npool; i++) {
        key = PK[i]
        if (PN[key] < 2 || PNEED[key] <= PAVAIL[key]) continue
        over = 1; split(key, KF, SUBSEP); names = ""
        for (j = 1; j <= PN[key] && j <= 8; j++) names = names (j > 1 ? " " : "") PH[key, j]
        if (PN[key] > 8) names = names " (+" (PN[key] - 8) " more)"
        if (preview) print "note: weka filesystem " KF[1] ": its " PN[key] " hosts (" names ") would need ~" gib(PNEED[key]) "GiB together at the jobfiles\047 sizes, and " gib(PAVAIL[key]) "GiB is available; the run checks again after calibration"
        else print "ERROR: weka filesystem " KF[1] ": its " PN[key] " hosts (" names ") need ~" gib(PNEED[key]) "GiB together but only " gib(PAVAIL[key]) "GiB is available" > "/dev/stderr"
    }
    exit (over && !preview ? 3 : 0)   # not 2: an awk that dies on its own exits 2
}
