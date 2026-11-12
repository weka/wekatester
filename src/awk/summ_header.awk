function nr_str(n, one, many) { return n " " (n == 1 ? one : many) }
# Tally <v> for host <h> under bucket set <B> (B[v] = host count, BO order)
function tally(B, BO, v) { if (!(v in B)) { B[v] = 0; BO[++BO[0]] = v } B[v]++ }
# One value, or each with its host count when the hosts differ
function tallied(B, BO,    i, s) {
    if (BO[0] == 1) return BO[1]
    s = ""
    for (i = 1; i <= BO[0]; i++) s = s (i > 1 ? ", " : "") BO[i] " (" nr_str(B[BO[i]], "host", "hosts") ")"
    return s
}
function first_line(path,    L, n, i) {   # first non-blank line, "" when none, "-1" when unreadable
    if ((n = readlines(path, L)) < 0) return -1
    for (i = 1; i <= n; i++) if (strip(L[i]) != "") return strip(L[i])
    return ""
}
# weka local ps: the VERSION column by its header offset (other headers
# hold blanks); distinct versions, else why there are none
function weka_version(path,    L, n, i, p, v, s, SEEN) {
    if ((n = readlines(path, L)) < 0) return "not recorded"
    p = 0
    for (i = 1; i <= n; i++) if (match(L[i], /(^| )VERSION( |$)/)) { p = RSTART + (substr(L[i], RSTART, 1) == " "); break }
    if (!p) {
        for (i = 1; i <= n; i++) if (index(L[i], "weka: not available") == 1) return "no weka CLI"
        return "not readable"
    }
    s = ""
    for (i = i + 1; i <= n; i++) {
        v = substr(L[i], p); sub(/^ +/, "", v); sub(/ .*/, "", v)
        if (v != "" && !(v in SEEN)) { SEEN[v] = 1; s = s (s == "" ? "" : "+") v }
    }
    return s == "" ? "no container listed" : "weka " s
}
# The mount a directory lives on (the longest mount point that is it or a
# parent): its fs type, else ""
function fs_type(h, dir,    L, n, i, F, mp, best, bl, t) {
    if (!((h) in MOUNTN)) { MOUNTN[h] = readlines(rd "/sysinfo/" h "/mounts", L); for (i = 1; i <= MOUNTN[h]; i++) MOUNTL[h, i] = L[i] }
    best = ""; bl = -1
    for (i = 1; i <= MOUNTN[h]; i++) {
        if (split(MOUNTL[h, i], F, " ") < 3) continue
        mp = replace_all(F[2], "\\040", " ")
        if (mp != "/" && dir != mp && index(dir, mp "/") != 1) continue
        if (length(mp) > bl) { bl = length(mp); best = F[3] }
    }
    return best
}
# A staged job's row: kind-direction (1job for the floor twin), then the
# measured sections' knobs, distinct values comma-joined; "-" = not set
function knob(L, n, SN, KV, J, nj, key, alt,    k, v, s, SEEN) {
    s = ""
    for (k = 1; k <= nj; k++) {
        v = sec_value(L, n, KV, J[k], key, "")
        if (v == "" && alt != "") v = sec_value(L, n, KV, J[k], alt, "")
        if (v == "") v = "-"
        if (!(v in SEEN)) { SEEN[v] = 1; s = s (s == "" ? "" : ",") v }
    }
    return s
}
function job_row(path, name,    L, n, kind, D, dirn, SN, KV, J, nj) {
    if ((n = readlines(path, L)) < 0) { ROWERR = "cannot read " path; return "" }
    ROWERR = ""
    if (name == layout_job() || name == unlink || is_layout_marked(L, n)) return ""
    kind = report_has(L, n, "latency") ? lat_kind(L, n) : report_has(L, n, "bandwidth") ? "bw" : report_has(L, n, "iops") ? "iops" : "job"
    file_directions(L, n, D)
    dirn = ("read" in D) && ("write" in D) ? "rw" : ("read" in D) ? "read" : ("write" in D) ? "write" : "-"
    nj = job_sections(L, n, SN, KV, J)
    ROWENG = knob(L, n, SN, KV, J, nj, "ioengine", "")
    sub(/\.job$/, "", name)
    return sprintf("%-16s nj %-5s qd %-5s nr %-5s bs %-7s %s", kind "-" dirn (is_floor_marked(L, n) ? " 1job" : ""), knob(L, n, SN, KV, J, nj, "numjobs", ""), knob(L, n, SN, KV, J, nj, "iodepth", ""), knob(L, n, SN, KV, J, nj, "nrfiles", ""), knob(L, n, SN, KV, J, nj, "bs", "blocksize"), name)
}
function host_list(A, n, total,    i, s) {   # up to 4 names, then +k
    s = ""
    for (i = 1; i <= n && i <= 4; i++) s = s " " A[i]
    return s (n > 4 ? " +" (n - 4) : "")
}
# A host's rows under <ind>, its engine first when it has one
function print_host_rows(h, ind,    k, e, EB, EO) {
    if (!NJOBS[h]) { print ind "staged jobfiles: none in the bundle for " h; return }
    EO[0] = 0
    for (k = 1; k <= NJOBS[h]; k++) if (ROW[h, k] != "") tally(EB, EO, ENG[h, k])
    if (EO[0] == 1) print ind "engine " EO[1]
    for (k = 1; k <= NJOBS[h]; k++) {
        if (ROW[h, k] == "") continue
        print ind ROW[h, k] (EO[0] > 1 ? "   engine " ENG[h, k] : "")
    }
}
BEGIN {
    rd = ARGV[1]; bname = ARGV[2]; jl = ARGV[3]; hl = ARGV[4]; unlink = ARGV[5]
    if ((n = readlines(rd "/settings", L)) >= 0) {
        have_set = 1
        for (i = 1; i <= n; i++) if ((p = index(L[i], "\t"))) SET[substr(L[i], 1, p - 1)] = substr(L[i], p + 1)
    }
    # hosts: the recorded order, then any other the bundle has a directory for
    nh = 0
    if (SET["hosts"] != "") { m = split(SET["hosts"], F, " "); for (i = 1; i <= m; i++) if (!(F[i] in HIDX)) { HOST[++nh] = F[i]; HIDX[F[i]] = nh } }
    n = readlines(hl, L)
    for (i = 1; i <= n; i++) if (L[i] != "" && !(L[i] in HIDX)) { HOST[++nh] = L[i]; HIDX[L[i]] = nh }
    # staged jobs, per host in name order
    n = readlines(jl, L)
    for (i = 1; i <= n; i++) {
        if (!(p = index(L[i], "\t"))) continue
        h = substr(L[i], 1, p - 1); f = substr(L[i], p + 1); name = f; sub(/.*\//, "", name)
        k = ++NJOBS[h]; ROW[h, k] = job_row(f, name); ENG[h, k] = ROWENG; JNAME[h, k] = name; JP[h, k] = f
        if (ROWERR != "") ROW[h, k] = "(" ROWERR ")"
    }

    # run
    stamp = rd; sub(/.*\//, "", stamp)
    when = stamp ~ /^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]$/ ? substr(stamp, 1, 4) "-" substr(stamp, 5, 2) "-" substr(stamp, 7, 2) " " substr(stamp, 10, 2) ":" substr(stamp, 12, 2) ":" substr(stamp, 14, 2) : stamp
    print "run      " when " (bundle " bname ")"

    # versions: fio and weka per host from sysinfo
    FO[0] = 0; WO[0] = 0
    for (i = 1; i <= nh; i++) {
        # fio --version prints fio-<version>; anything else is its failure
        v = first_line(rd "/sysinfo/" HOST[i] "/fio")
        tally(FB, FO, v == -1 ? "not recorded" : v ~ /^fio-/ ? substr(v, 5) : "not available")
        tally(WB, WO, weka_version(rd "/sysinfo/" HOST[i] "/weka"))
    }
    print "version  wekatester " (("version" in SET) ? SET["version"] : "not recorded") ", fio " (nh ? tallied(FB, FO) : "not recorded") ", " (nh ? tallied(WB, WO) : "weka not recorded")

    print "command  " ((v = first_line(rd "/cmdline")) == -1 || v == "" ? "not recorded" : v)

    # clients, shapes, fs groups
    master = SET["master"]
    if (master == "") {
        # older bundles: the master every measured job ran from
        while ((r = (getline line < (rd "/wekatester.log"))) > 0)
            if (match(line, /starting test run for job .* on [^ ]+ with [0-9]+ workers:$/)) { master = line; sub(/ with [0-9]+ workers:$/, "", master); sub(/.* on /, "", master); break }
        close(rd "/wekatester.log")
    }
    nshape = (n = readlines(rd "/cal/shapes", SHL)) < 0 ? -1 : n
    ng = -1
    if ((n = readlines(rd "/fs-groups", L)) >= 0) { ng = 0; for (i = 1; i <= n; i++) if (split(L[i], F, " ") >= 2 && !(F[2] in GS)) { GS[F[2]] = 1; ng++ } }
    print "clients  " nh " (master " (master != "" ? master : "not recorded") "), " (nshape >= 0 ? nr_str(nshape, "shape", "shapes") : SET["auto"] == "-" ? "no shapes (no -a)" : "shapes not recorded") ", " (ng >= 0 ? nr_str(ng, "filesystem group", "filesystem groups") : "filesystem groups not recorded")

    # workload; -a; the destination the staged jobs name, with its fs type
    if (!have_set) au = nshape >= 0 ? "-a (its level not recorded)" : "-a not recorded"
    else if (SET["auto"] == "-") au = "no -a"
    else au = "-a " SET["auto"] " (" SET["cal-seconds"] " s cells)"
    DO[0] = 0
    for (i = 1; i <= nh; i++) {
        h = HOST[i]; split("", HD); nd = 0
        for (k = 1; k <= NJOBS[h]; k++) {
            if ((n = readlines(JP[h, k], L)) < 0) continue
            if ((v = first_value(L, n, "directory")) != "" && !(v in HD)) { HD[v] = 1; HDO[++nd] = v }
        }
        for (k = 1; k <= nd; k++) { t = fs_type(h, HDO[k]); tally(DB, DO, HDO[k] " (" (t != "" ? t : "fs type not recorded") ")") }
    }
    print "workload " (("workload" in SET) ? SET["workload"] : "not recorded") "; " au "; dest " (DO[0] ? tallied(DB, DO) : "not recorded")
    print ""

    # parameters: per shape its representative's staged jobs; without
    # shapes one line per distinct row across hosts, with its host count
    if (nshape > 0) {
        n = readlines(rd "/cal/shapes.txt", L)
        for (i = 1; i <= n; i++) if (match(L[i], /^shape [0-9]+ of [0-9]+: .* -- /)) { split(L[i], F, " "); STXT[F[2]] = substr(L[i], RLENGTH + 1) }
        for (s = 1; s <= nshape; s++) {
            if (split(SHL[s], F, "\t") < 12) { print "shape " s ": unreadable line in cal/shapes"; continue }
            m = split(F[12], M, " ")
            print "shape " F[1] ": " nr_str(m, "host", "hosts") ", rep " F[2] ", N=" F[3] ", line rate " (F[6] + 0 > 0 ? sprintf("%g Gb/s", F[6] * 8 / 1e9) : "unknown")
            if (F[1] in STXT) print "  " STXT[F[1]]
            print_host_rows(F[2], "  ")
        }
    } else {
        print "parameters: the staged jobs per host (" nr_str(nh, "host", "hosts") ")"
        EO[0] = 0; nrow = 0
        for (i = 1; i <= nh; i++) {
            h = HOST[i]
            for (k = 1; k <= NJOBS[h]; k++) {
                if (ROW[h, k] == "") continue
                tally(EB, EO, ENG[h, k])
                key = JNAME[h, k] SUBSEP ROW[h, k] SUBSEP ENG[h, k]
                if (!(key in RC)) { RO[++nrow] = key; RC[key] = 0 }
                RH[key, ++RC[key]] = h
            }
        }
        if (!nrow) print "  staged jobfiles: none in the bundle"
        if (EO[0] == 1) print "  engine " EO[1]
        # rows in job-name order (insertion sort: a few dozen)
        for (i = 2; i <= nrow; i++) { v = RO[i]; for (j = i - 1; j >= 1 && RO[j] > v; j--) RO[j + 1] = RO[j]; RO[j + 1] = v }
        w = 0
        for (i = 1; i <= nrow; i++) {
            split(RO[i], F, SUBSEP); RTXT[i] = F[2] (EO[0] > 1 ? "   engine " F[3] : "")
            if (length(RTXT[i]) > w) w = length(RTXT[i])
        }
        for (i = 1; i <= nrow; i++) {
            c = RC[RO[i]]
            split("", A); for (j = 1; j <= c; j++) A[j] = RH[RO[i], j]
            printf "  %-" w "s   %s\n", RTXT[i], (c == nh ? (nh == 1 ? "1 host" : "all " nh " hosts") : nr_str(c, "host", "hosts") ":" host_list(A, c))
        }
    }
    print ""
}
