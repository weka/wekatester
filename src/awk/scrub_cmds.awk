# --scrub private|shared|full: the removal commands for the files a workload
# set names, with no staged layout to read them from. Each jobfile format
# goes through what staging does to it: ".$filenum" appended when it has none
# (stage_hosts), the host name in front (stamp_unique_names), "shared." for a
# group read set. Prints "<S|P>\t<host>\t<command>": S, from the first
# listed host of a group, its shared read set and, under full, its
# calibration scratch; P, a host own files.
BEGIN {
    mode = ARGV[1]; scratch = ARGV[3]; nf = ARGV[4] + 0; ng = 0; nfmt = 0
    if (ARGV[2] != "-")
        while ((getline line < ARGV[2]) > 0)
            if (split(line, F, " ") == 2) { ng++; G[F[1]] = F[2]; if (!(F[2] in FIRST)) FIRST[F[2]] = F[1] }
    for (a = 5; a < 5 + nf; a++) {
        if ((n = readlines(ARGV[a], L)) < 0) awk_fail("cannot read " ARGV[a])
        has = 0
        for (i = 1; i <= n; i++) {
            t = strip(L[i])
            if (jf_key(t) != "filename_format") continue
            has = 1; add_fmt(jf_value(t), ARGV[a])
        }
        if (!has) add_fmt("$jobname.$jobnum.$filenum", ARGV[a])
    }
    for (a = 5 + nf; a + 2 < ARGC; a += 3) {
        h = ARGV[a]; name = ARGV[a + 1]; hd = ARGV[a + 2]
        first = ng ? (!(h in G) || FIRST[G[h]] == h) : (a == 5 + nf)
        if (first && mode != "private") {
            cmd = ""
            for (i = 1; i <= nfmt; i++) cmd = cmd (cmd == "" ? "" : " && ") dataset_remove_cmd("shared." FMT[i], hd, 1)
            # one removal of the scratch per group: its hosts would race on one tree
            if (mode == "full") cmd = cmd (cmd == "" ? "" : " && ") "rm -rf " squote(hd "/" scratch)
            if (cmd != "") print "S\t" h "\t" cmd
        }
        cmd = ""
        for (i = 1; i <= nfmt; i++) cmd = cmd (cmd == "" ? "" : " && ") dataset_remove_cmd(name "." FMT[i], hd, 1)
        if (cmd != "") print "P\t" h "\t" cmd
    }
}
function add_fmt(v, path,    t) {
    if (index(v, "$clientuid")) {
        t = path; sub(/.*\//, "", t)
        print "WARNING: " t ": filename_format=" v " names files by fio client id, which no host name finds; --scrub all removes them" > "/dev/stderr"
        return
    }
    if (index(v, "shared.") == 1) v = substr(v, 8)
    # staging appends .$filenum only where nrfiles is above 1: both names
    if (!index(v, "$filenum")) add_one(v ".$filenum")
    add_one(v)
}
function add_one(v) {
    if (v in SEEN) return
    SEEN[v] = 1; FMT[++nfmt] = v
}
