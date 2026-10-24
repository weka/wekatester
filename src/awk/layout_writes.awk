# Per host, after the sweep: its staged layout (the grid) against the sizes
# the sweep listed. Writes grid/<host>/<layout> (the grid, for the directory
# pass and the capacity check), probe/<host>.laidout (the bytes present) and,
# when converting, the run's layout: a dense sequential write of each file
# missing or short of its size. Prints per host "<host> <files> <bytes>
# <reused> <kept-sections>", tab-separated.
function lowbit(v,    b) {   # the largest power of two up to 1Mi dividing v
    b = 1048576
    while (b > 1 && v % b) b /= 2
    return b
}
function esc_colon(s) { gsub(/:/, "\\:", s); return s }
function do_host(h, convert,    L, n, SZ, m, S, S0, i, p, P, SN, KV, ns, s, fmt, fs, F, nr, nj, dir, NSBAD, WHY, W, WJ, WN, ORD, nw, j, f, name, path, credit, nwrite, bytes, reused, b, app, g, GK, GC, GN, ng, O, no, x, c, y, line, sections, HDR, nh, k, kept, inglob) {
    if ((n = readlines(work "/jobs/" h "/" lay, L)) < 0) awk_fail("cannot read the staged layout for " h)
    writelines(work "/grid/" h "/" lay, L, n)
    if ((m = readlines(work "/probe/" h ".sizes", S)) < 0) awk_fail("cannot read the sweep listing for " h)
    split("", SZ)
    for (i = 1; i <= m; i++)
        if ((p = index(S[i], " ")) > 1) SZ[substr(S[i], p + 1)] = substr(S[i], 1, p - 1) + 0
    ns = ini_parse(L, n, SN, KV)
    # A section the sweep cannot state (no format or filesize, a variable
    # other than $jobname/$jobnum/$filenum, a size off 4KiB) keeps its
    # create_only section, and so does the rest of its namespace: two
    # writers must never share a file.
    split("", NSBAD); split("", WHY)
    for (s = 1; s <= ns; s++) {
        fmt = replace_all(ini_get(KV, s, "filename_format", ""), "$jobname", SN[s])
        fs = ini_get(KV, s, "filesize", ""); F = fs == "" ? "" : parse_size(fs)
        if (fmt == "" || F == "" || F < 4096 || F % 4096) WHY[s] = 1
        else if (index(replace_all(replace_all(fmt, "$jobnum", ""), "$filenum", ""), "$")) WHY[s] = 1
        if (WHY[s]) NSBAD[fmt] = 1
    }
    nw = 0; split("", W)
    for (s = 1; s <= ns; s++) {
        fmt = replace_all(ini_get(KV, s, "filename_format", ""), "$jobname", SN[s])
        if (fmt in NSBAD) { WHY[s] = 1; continue }
        F = parse_size(ini_get(KV, s, "filesize", ""))
        nr = py_int(ini_get(KV, s, "nrfiles", "1")); nj = py_int(ini_get(KV, s, "numjobs", "1"))
        if (nr == "" || nj == "") awk_fail(h ": layout [" SN[s] "]: nrfiles and numjobs must be numbers")
        dir = ini_get(KV, s, "directory", "")
        # a file several grids name is laid out once, at the largest size
        for (j = 0; j < nj; j++)
            for (f = 0; f < nr; f++) {
                name = replace_all(replace_all(fmt, "$jobnum", j), "$filenum", f)
                path = path_join(dir, name)
                if (!(path in W)) { W[path] = F; WJ[path] = j; WN[path] = name; ORD[++nw] = path }
                else if (F > W[path]) W[path] = F
            }
    }
    credit = 0; nwrite = 0; bytes = 0; reused = 0; ng = 0
    split("", GC)
    for (i = 1; i <= nw; i++) {
        path = ORD[i]; F = W[path]; S0 = (path in SZ) ? SZ[path] : 0
        credit += S0 < F ? S0 : F
        if (S0 >= F) { reused++; continue }
        # appended from its end when that end sits on the block size, else
        # rewritten from 0 in place: never a hole either way
        b = lowbit(F); app = S0 % b == 0
        nwrite++; bytes += app ? F - S0 : F
        g = sprintf("%012d %015.0f %d", WJ[path], F, app)
        if (!(g in GC)) { GK[++ng] = g; GC[g] = 0 }
        GN[g, ++GC[g]] = esc_colon(WN[path])
    }
    printf "%.0f\n", credit > (work "/probe/" h ".laidout"); close(work "/probe/" h ".laidout")
    kept = 0
    for (s = 1; s <= ns; s++) if (WHY[s]) kept++
    printf "%s\t%d\t%.0f\t%d\t%d\n", h, nwrite, bytes, reused, kept
    if (!convert) return
    no = 0; split("", O)
    O[++no] = layout_write_marker()
    O[++no] = "# Staged per run from the layout grid, after the sweep: every file missing"
    O[++no] = "# or short of its size is written sequentially from its end, so a stopped"
    O[++no] = "# layout leaves a short file, never a full-size one with a hole (README)."
    # the grid's [global], as staged
    inglob = 0; nh = 0
    for (i = 1; i <= n; i++) {
        if ((x = section_name(L[i])) != "") { inglob = strip(x) == "global"; if (inglob) O[++no] = "[global]"; HDR[++nh] = i; continue }
        if (inglob && strip(L[i]) != "" && substr(strip(L[i]), 1, 1) != "#" && jf_key(L[i]) != "group_reporting") O[++no] = L[i]
    }
    if (!nh || strip(L[HDR[1]]) != "[global]") { for (i = no; i > 4; i--) O[i + 1] = O[i]; O[5] = "[global]"; no++ }
    # one entry per host in the results: the layout reports as a test
    O[++no] = "group_reporting=1"
    sort_arr(GK, ng, 0); sections = 0
    for (x = 1; x <= ng; x++) {
        g = GK[x]; split(g, P, " ")
        c = 0
        while (c < GC[g]) {
            line = GN[g, c + 1]; y = c + 2
            # SEED_CHUNK files a section, the line under fio's 4096-byte parser buffer
            while (y <= GC[g] && y <= c + 16 && length(line) + 1 + length(GN[g, y]) < 3900) line = line ":" GN[g, y++]
            sections++
            O[++no] = ""
            O[++no] = sprintf("[lay-%d-%.0f-%s%d]", P[1], P[2], (P[3] == 1 ? "a" : "w"), sections)
            O[++no] = "rw=write"; O[++no] = sprintf("bs=%d", lowbit(P[2] + 0)); O[++no] = "direct=1"
            O[++no] = "create_on_open=1"; O[++no] = "file_append=" (P[3] == 1 ? 1 : 0)
            O[++no] = "numjobs=1"; O[++no] = "nrfiles=" (y - c - 1); O[++no] = sprintf("filesize=%.0f", P[2])
            O[++no] = "filename=" line
            c = y - 1
        }
    }
    if (sections > 4000)
        awk_fail(h ": the layout needs " sections " fio sections and fio caps a run at 4096 jobs; lay out fewer files per host (a smaller numjobs or nrfiles)")
    # sections the sweep cannot state, as staged (create_only)
    s = 0   # the k-th header past [global] is ini_parse's section s
    for (k = 1; k <= nh; k++) {
        if (strip(L[HDR[k]]) == "[global]") continue
        if (!WHY[++s]) continue
        O[++no] = ""
        for (i = HDR[k]; i <= n && (i == HDR[k] || section_name(L[i]) == ""); i++) if (strip(L[i]) != "") O[++no] = L[i]
    }
    writelines(work "/jobs/" h "/" lay, O, no)
}
BEGIN {
    work = ARGV[1]; lay = ARGV[2]; convert = ARGV[3] == "1"
    for (a = 4; a < ARGC; a++) do_host(ARGV[a], convert)
}
