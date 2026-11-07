function gib(b) { return sprintf("%.1f", b / 1073741824) }
function need_int(v, what) {   # int(), or a stop where python raised
    if ((v = py_int(v)) == "") awk_fail("capacity: " what " is not a number")
    return v
}
# one job section s of a staged jobfile (job_sections): numjobs x filesize
# x nrfiles, or numjobs x size= (fio: the job total across its files). A
# filename_format without $jobnum (or $filenum) names one file for every
# job (or every file number), as layout_footprint counts them.
function footprint(path, L, n, KV, s,    nj, fs, sz, nr, b, job, fmt, oj, of) {
    nj = need_int(sec_value(L, n, KV, s, "numjobs", "1"), path ": numjobs")
    fmt = sec_value(L, n, KV, s, "filename_format", "")
    oj = fmt != "" && !index(fmt, "$jobnum"); of = fmt != "" && !index(fmt, "$filenum")
    if (oj) nj = 1
    if ((fs = sec_value(L, n, KV, s, "filesize", "")) != "") {
        if ((b = parse_size(fs)) == "") awk_fail("capacity: " path ": filesize=" fs " is not a byte count")
        return nj * b * (of ? 1 : need_int(sec_value(L, n, KV, s, "nrfiles", "1"), path ": nrfiles"))
    }
    if ((sz = sec_value(L, n, KV, s, "size", "")) != "") {
        if ((b = parse_size(sz)) != "") {
            # one file of the job's size / nrfiles, when the format names one
            if (of && (nr = py_int(sec_value(L, n, KV, s, "nrfiles", "1"))) != "" && nr + 0 > 0) b /= nr
            return nj * b
        }
        job = path; sub(/.*\//, "", job)
        print "WARNING: " job ": size=" sz " is not a byte count; it contributes nothing to the capacity estimate" > "/dev/stderr"
    }
    return 0
}
# fio's filename= list into N[1..]: ':' separates, "\:" is a colon, empty
# names are skipped (get_next_str). Every clone opens these same files,
# under the job's directory (staging sets it), so they are priced once.
function fio_names(v, N,    n, i, c, cur) {
    split("", N); n = 0; cur = ""
    for (i = 1; i <= length(v); i++) {
        c = substr(v, i, 1)
        if (c == "\\" && substr(v, i + 1, 1) == ":") { cur = cur ":"; i++ }
        else if (c == ":") { if (cur != "") N[++n] = cur; cur = "" }
        else cur = cur c
    }
    if (cur != "") N[++n] = cur
    return n
}
# a filename= section's per-file length: filesize, else size over its cnt
# names; unreadable sizes as footprint() treats them
function named_len(path, L, n, KV, s, cnt,    fs, sz, b, job) {
    if ((fs = sec_value(L, n, KV, s, "filesize", "")) != "") {
        if ((b = parse_size(fs)) == "") awk_fail("capacity: " path ": filesize=" fs " is not a byte count")
        return b
    }
    if ((sz = sec_value(L, n, KV, s, "size", "")) != "") {
        if ((b = parse_size(sz)) != "") return b / cnt
        job = path; sub(/.*\//, "", job)
        print "WARNING: " job ": size=" sz " is not a byte count; it contributes nothing to the capacity estimate" > "/dev/stderr"
    }
    return 0
}
# The layout job, each file priced once. Per section (create_only ones too,
# [global] the fallback): its namespace, filename_format else fio's default
# <section>.$jobnum.$filenum; a counter the format lacks names one file; the
# length is filesize, else size / nrfiles. An unreadable size prices nothing.
function layout_footprint(L, n,    LSN, LKV, ns, s, total, fmt, nj, nr, len, v, G, NC, NK, nk, c, NM, x) {
    ns = ini_parse(L, n, LSN, LKV); nk = 0; split("", G); split("", NC)
    for (s = 1; s <= ns; s++) {
        nj = need_int(sec_value(L, n, LKV, s, "numjobs", "1"), "the layout numjobs") + 0
        if ((v = sec_value(L, n, LKV, s, "filename", "")) != "") {
            # named files (fio_names): one 1 x 1 grid each, filesize else
            # size over the names; an unreadable size prices nothing
            if (!(nr = fio_names(v, NM))) continue
            if ((v = sec_value(L, n, LKV, s, "filesize", "")) != "") { if ((len = parse_size(v)) == "") continue }
            else if ((len = parse_size(sec_value(L, n, LKV, s, "size", ""))) == "") continue
            else len /= nr
            for (x = 1; x <= nr; x++) {
                fmt = "file:" NM[x]
                if (!(fmt in NC)) { NC[fmt] = 0; NK[++nk] = fmt }
                c = ++NC[fmt]; G[fmt, c, "j"] = 1; G[fmt, c, "r"] = 1; G[fmt, c, "l"] = len + 0
            }
            continue
        }
        # nrfiles is required beside filesize (as before); beside size an
        # unreadable one prices the job total as one file, as before
        if ((v = sec_value(L, n, LKV, s, "filesize", "")) != "") {
            if ((len = parse_size(v)) == "") continue
            nr = need_int(sec_value(L, n, LKV, s, "nrfiles", "1"), "the layout nrfiles") + 0
        } else {
            if ((len = parse_size(sec_value(L, n, LKV, s, "size", ""))) == "") continue
            if ((nr = py_int(sec_value(L, n, LKV, s, "nrfiles", "1"))) == "" || nr + 0 <= 0) nr = 1
            else { nr += 0; len /= nr }
        }
        if ((fmt = sec_value(L, n, LKV, s, "filename_format", "")) == "") fmt = LSN[s] ".$jobnum.$filenum"
        else fmt = replace_all(fmt, "$jobname", LSN[s])
        if (!index(fmt, "$jobnum")) nj = 1
        if (!index(fmt, "$filenum")) nr = 1
        if (!(fmt in NC)) { NC[fmt] = 0; NK[++nk] = fmt }
        c = ++NC[fmt]; G[fmt, c, "j"] = nj; G[fmt, c, "r"] = nr; G[fmt, c, "l"] = len + 0
    }
    total = 0
    for (c = 1; c <= nk; c++) total += grid_union(G, NK[c], NC[NK[c]])
    return total
}
# A namespace's m grids (jobs 0..nj-1 x files 0..nr-1, all from 0) as their
# union: over the distinct job and file edges, each block at the largest
# length of the grids covering it. At most m^2 blocks of m checks; m is a
# handful (lay_prune's survivors).
function grid_union(G, k, m,    D, E, F, ne, nf, a, b, c, best, sum) {
    split("", D); ne = 0; nf = 0
    for (c = 1; c <= m; c++) {
        if (!(("j", G[k, c, "j"]) in D)) { D["j", G[k, c, "j"]] = 1; E[++ne] = G[k, c, "j"] }
        if (!(("r", G[k, c, "r"]) in D)) { D["r", G[k, c, "r"]] = 1; F[++nf] = G[k, c, "r"] }
    }
    sort_arr(E, ne, 1); sort_arr(F, nf, 1)
    sum = 0
    for (a = 1; a <= ne; a++)
        for (b = 1; b <= nf; b++) {
            best = 0
            for (c = 1; c <= m; c++)
                if (G[k, c, "j"] >= E[a] + 0 && G[k, c, "r"] >= F[b] + 0 && G[k, c, "l"] > best) best = G[k, c, "l"]
            sum += (E[a] - (a > 1 ? E[a - 1] : 0)) * (F[b] - (b > 1 ? F[b - 1] : 0)) * best
        }
    return sum
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
            if (job == layout_job() || is_layout_marked(L, n)) {
                # the grid the sweep kept, not the run's write of what is missing
                if ((gn = readlines(work "/grid/" h "/" job, GL)) >= 0) layout += layout_footprint(GL, gn)
                else layout += layout_footprint(L, n)
                continue
            }
            # Per job section: one filename_format is one set of files, costing
            # its largest section; without one, fio's default
            # <section>.$jobnum.$filenum, so like-named sections of two
            # jobfiles share theirs, as the layout lays them out. Namespaces
            # sum below.
            nsec = job_sections(L, n, SN, KV, J)
            for (x = 1; x <= nsec; x++) {
                s = J[x]
                if ((v = sec_value(L, n, KV, s, "filename", "")) != "") {
                    # named files (fio_names), filename_format unused: each
                    # its own namespace, at its largest per-file length
                    if (!(nm = fio_names(v, NM))) continue
                    b = named_len(p, L, n, KV, s, nm)
                    for (w = 1; w <= nm; w++) {
                        ns = "file:" NM[w]
                        if (!(ns in NSV)) { NSV[ns] = 0; NSK[++nns] = ns }
                        if (b > NSV[ns]) NSV[ns] = b
                    }
                    continue
                }
                if ((ns = sec_value(L, n, KV, s, "filename_format", "")) == "") ns = sec_jobname(L, n, SN, s, job) ".$jobnum.$filenum"
                else {
                    ns = replace_all(ns, "$jobname", sec_jobname(L, n, SN, s, job))   # its own files, as the layout names them
                    # a group fleet-shared dataset is priced once, on its first host
                    if (index(ns, "shared.") == 1 && h != FIRST[(h in GID) ? GID[h] : "1"]) continue
                }
                if (!(ns in NSV)) { NSV[ns] = 0; NSK[++nns] = ns }
                if ((b = footprint(p, L, n, KV, s)) > NSV[ns]) NSV[ns] = b
            }
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
        avail = ""; key = ""
        if ((n = readlines(work "/df/" h, L)) >= 2) {
            if (pysplit(L[2], F) < 4 || (avail = py_int(F[4])) == "") awk_fail(h ": cannot read the df line: " L[2])
            avail *= 1024
            # a weka filesystem is keyed by its name (clients list
            # stateless-mount backends differently) and its size
            # (same-named filesystems of two clusters)
            if (n >= 3 && strip(L[3]) == "wekafs") { fs = F[1]; sub(/.*\//, "", fs); key = fs SUBSEP F[2] }
        }
        # a host with nothing left to write shows at -v (bytes, not the GiB shown)
        gated(req > 0 ? 0 : 1, "capacity" before ": " h " needs ~" gib(req) "GiB" (credit ? " (~" gib(credit) "GiB already laid out)" : "") ", has " gib(avail) "GiB available", "")
        # avail "" = no df line, unchecked; 0 is a full filesystem
        if (avail != "" && req > avail) {
            over = 1
            if (preview) print "note: " h ": the jobfiles as written need ~" gib(req) "GiB but only " gib(avail) "GiB is available; -a stages the calibrated sizes instead and checks again after calibration"
            else print "ERROR: " h ": workload needs ~" gib(req) "GiB but only " gib(avail) "GiB is available" > "/dev/stderr"
        }
        if (key != "") {
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
