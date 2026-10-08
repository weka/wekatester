# --- layout derivation: generate_layout's, and the staged re-derivation's ---
# One namespace per filename_format, else per measured section name; one
# create section per pruned contributor, so only files jobs open are laid out
# (a max-of-everything section creates the cross-product). Order: lay_reset,
# lay_add and lay_engine per jobfile, lay_sections.
function lay_reset() {
    split("", LAY_NS); split("", LAY_TALLY); split("", LAY_EORD); LAY_NNS = 0; LAY_NE = 0
}
function lay_engine(L, n,    eng) {
    if ((eng = first_value(L, n, "ioengine")) == "") return
    if (!(eng in LAY_TALLY)) LAY_EORD[++LAY_NE] = eng
    LAY_TALLY[eng]++
}
function lay_add(L, n, fname, where,    fmt, key, sec, fs, sz, sb, v, nj, nr, k, c) {
    # No filename_format: fio names files after the section, so the layout
    # section takes the measured section name.
    if ((fmt = first_value(L, n, "filename_format")) != "") { key = fmt; sec = "" }
    else {
        if ((sec = last_section(L, n)) == "") sec = fname
        key = "__jobname__:" sec
    }
    fs = first_value(L, n, "filesize"); sz = first_value(L, n, "size"); sb = -1
    # size=50% and the like are not derivable: no size of their own
    if (fs != "" && (v = parse_size(fs)) != "" && v > sb) sb = v
    if (sz != "" && (v = parse_size(sz)) != "" && v > sb) sb = v
    nj = first_value(L, n, "numjobs"); nj = nj == "" ? 1 : py_int(nj)
    nr = first_value(L, n, "nrfiles"); nr = nr == "" ? 1 : py_int(nr)
    if (nj == "" || nr == "") awk_fail(where ": numjobs and nrfiles must be numbers")
    if (!(key in LAY_NS)) { LAY_NS[key] = ++LAY_NNS; LAY_KEY[LAY_NNS] = key; LAY_SEC[LAY_NNS] = sec; LAY_FMT[LAY_NNS] = fmt; LAY_NC[LAY_NNS] = 0 }
    k = LAY_NS[key]; c = ++LAY_NC[k]
    LAY_CNJ[k, c] = nj; LAY_CNR[k, c] = nr; LAY_CSB[k, c] = sb; LAY_CFS[k, c] = fs; LAY_CSZ[k, c] = sz
}
# Keep contributors no kept grid covers; widest first, stable, so a dominated
# entry meets its dominator first.
function lay_prune(k, KEPT,    n, I, i, j, t, nk, a, b, dom) {
    n = LAY_NC[k]
    for (i = 1; i <= n; i++) {
        t = i
        for (j = i - 1; j >= 1 && lay_wider(k, t, I[j]); j--) I[j + 1] = I[j]
        I[j + 1] = t
    }
    nk = 0
    for (i = 1; i <= n; i++) {
        a = I[i]; dom = 0
        for (j = 1; j <= nk && !dom; j++) {
            b = KEPT[j]
            dom = LAY_CNJ[k, a] <= LAY_CNJ[k, b] && LAY_CNR[k, a] <= LAY_CNR[k, b] && LAY_CSB[k, a] <= LAY_CSB[k, b]
        }
        if (!dom) KEPT[++nk] = a
    }
    return nk
}
function lay_wider(k, a, b) {   # does contributor a sort before b?
    if (LAY_CNJ[k, a] != LAY_CNJ[k, b]) return LAY_CNJ[k, a] > LAY_CNJ[k, b]
    if (LAY_CNR[k, a] != LAY_CNR[k, b]) return LAY_CNR[k, a] > LAY_CNR[k, b]
    return LAY_CSB[k, a] > LAY_CSB[k, b]
}
function lay_sections(B, nb,    KS, q, k, nk, KEPT, prev, x, c, cnt, sec, fmt) {   # the new line count
    for (k = 1; k <= LAY_NNS; k++) KS[k] = LAY_KEY[k]
    sort_arr(KS, LAY_NNS, 0)
    cnt = 0
    for (q = 1; q <= LAY_NNS; q++) {
        k = LAY_NS[KS[q]]; nk = lay_prune(k, KEPT); prev = ""
        for (x = 1; x <= nk; x++) {
            c = KEPT[x]; cnt++
            # A lone jobname contributor keeps its name; several need distinct
            # names for wait_for, so fio default naming is spelled out.
            if (LAY_SEC[k] != "" && nk == 1) { sec = LAY_SEC[k]; fmt = LAY_FMT[k] }
            else if (LAY_SEC[k] != "") { sec = "layout-" cnt; fmt = LAY_SEC[k] ".$jobnum.$filenum" }
            else { sec = "layout-" cnt; fmt = LAY_FMT[k] }
            B[++nb] = ""
            B[++nb] = "[" sec "]"
            # One namespace chains via wait_for: overlapping grids must not lay
            # out a file concurrently (an extend can unlink a file mid-write).
            # Distinct namespaces run in parallel.
            if (prev != "") B[++nb] = "wait_for=" prev
            prev = sec
            B[++nb] = "create_only=1"
            B[++nb] = "blocksize=1Mi"
            if (fmt != "") B[++nb] = "filename_format=" fmt
            if (LAY_CFS[k, c] != "") B[++nb] = "filesize=" LAY_CFS[k, c]
            else if (LAY_CSZ[k, c] != "") B[++nb] = "size=" LAY_CSZ[k, c]
            else B[++nb] = "# WARNING: no derivable file size in this namespace (" LAY_KEY[k] ")"
            if (LAY_CNR[k, c] > 1) B[++nb] = "nrfiles=" LAY_CNR[k, c]
            B[++nb] = "numjobs=" LAY_CNJ[k, c]
        }
    }
    return nb
}
# One cal.results line into F: host, engine, then (qd nr fs nj) per schema
# slot; 0 for a blank line. Any other width is a schema break, not a skip.
function cal_results_split(line, F,    m, S, w) {
    if (!(m = pysplit(line, F))) return 0
    w = 2 + 4 * split(geom_slots(), S, " ")
    if (m != w) awk_fail("cal.results: malformed line (want " w " fields): " rstrip(line))
    return m
}
function commas(v,    s, out) {   # format(int(v), ","): a count, thousands grouped
    s = sprintf("%.0f", int(v)); out = ""
    while (length(s) > 3 && substr(s, length(s) - 3, 1) ~ /[0-9]/) {
        out = "," substr(s, length(s) - 2) out; s = substr(s, 1, length(s) - 3)
    }
    return s out
}
function csv_field(v) {   # csv.writer's QUOTE_MINIMAL, with no line terminator
    if (!index(v, ",") && !index(v, "\"")) return v
    gsub(/"/, "\"\"", v)
    return "\"" v "\""
}
# name=value,... (the WEKATESTER_HOST_ALIAS and _IDENT environment) into M
function kv_map(s, M,    n, P, i, p) {
    split("", M)
    n = lsplit(s, P, ",")
    for (i = 1; i <= n; i++) if ((p = index(P[i], "="))) M[substr(P[i], 1, p - 1)] = substr(P[i], p + 1)
}
# <name>/<machine-id> cells: the id stripped, the name mapped onto the address
# this run uses (local mode calls it localhost).
function host_addr(cell, ALIAS,    name) {
    name = cell; sub(/\/.*/, "", name); name = strip(name)
    return (name in ALIAS) ? ALIAS[name] : name
}
