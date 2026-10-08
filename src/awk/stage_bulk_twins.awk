BEGIN {
    d = ARGV[1]; nf = 0
    for (a = 2; a < ARGC; a++) {   # "f<name>": a file; "o<name>": taken
        name = substr(ARGV[a], 2); EXISTS[name] = 1
        if (substr(ARGV[a], 1, 1) == "f") FILES[++nf] = name
    }
    made = ""
    for (j = 1; j <= nf; j++) {
        name = FILES[j]
        if (name !~ /^[0-9]/ || name == layout_job()) continue
        if ((n = readlines(d "/" name, L)) < 0) awk_fail("cannot read " d "/" name)
        if (is_layout_marked(L, n) || !report_has(L, n, "latency") || job_bs(L, n) >= 1048576) continue
        match(name, /^[0-9]+/)
        twin = substr(name, 1, RLENGTH) "b" substr(name, RLENGTH + 1)
        twin = twin ~ /\.job$/ ? substr(twin, 1, length(twin) - 4) "-1M.job" : twin "-1M"
        if (twin in EXISTS) awk_fail("-b: the set already has a file named " twin)
        hasbs = 0
        for (i = 1; i <= n; i++)
            if (match(L[i], /^(bs|blocksize)=/)) { L[i] = substr(L[i], 1, RLENGTH) "1Mi"; hasbs = 1 }
        if (!hasbs) n = override_lines(L, n, "bs", "1Mi")
        for (i = n; i >= 1; i--) L[i + 1] = L[i]
        L[1] = "# -b: the 1MiB twin of " name ", staged by wekatester"
        writelines(d "/" twin, L, n + 1)
        EXISTS[twin] = 1
        made = made (made == "" ? "" : " ") twin
    }
    print made
}
