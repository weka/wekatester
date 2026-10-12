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
        if (is_layout_marked(L, n) || is_floor_marked(L, n) || !report_has(L, n, "latency")) continue
        twin = name ~ /\.job$/ ? substr(name, 1, length(name) - 4) "-1job.job" : name "-1job"
        if (twin in EXISTS) awk_fail("the set already has a file named " twin)
        for (i = n; i >= 1; i--) L[i + 1] = L[i]
        L[1] = floor_marker() " " name " at numjobs=iodepth=nrfiles=1 on every client, staged by wekatester"
        writelines(d "/" twin, L, n + 1)
        EXISTS[twin] = 1
        made = made (made == "" ? "" : " ") twin
    }
    print made
}
