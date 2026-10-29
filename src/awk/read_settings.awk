BEGIN {
    path = ARGV[1]; n = split(ARGV[2], K, ",")
    for (i = 1; i <= n; i++) KNOWN[K[i]] = 1
    if ((n = readlines(path, L)) < 0) awk_fail("cannot read host file: " path)
    nrec = csv_read(L, n, CN, CV)
    for (r = 1; r <= nrec; r++) {
        if (!CN[r] || !is_setting_cell(CV[r, 1])) continue
        cell = strip(CV[r, 1])
        # the cell first: a host named wt_... (an ssh alias) lands here
        if (!(p = index(cell, "="))) awk_fail(path ":" r ": \047" cell "\047 is not WT_NAME=value (a first cell starting WT_ is a setting, never a host)")
        for (k = 2; k <= CN[r]; k++)
            if (strip(CV[r, k]) != "") awk_fail(path ":" r ": a settings line is one WT_NAME=value cell; quote a value that holds a comma")
        name = substr(cell, 1, p - 1); v = strip(substr(cell, p + 1))
        if (!(name in KNOWN)) awk_fail(path ":" r ": unknown setting \047" name "\047")
        if (name in SEEN) awk_fail(path ":" r ": " name " is set twice (first at line " SEEN[name] ")")
        SEEN[name] = r
        if (v != "") print r "\t" name "\t" v   # empty: this file sets nothing
    }
}
