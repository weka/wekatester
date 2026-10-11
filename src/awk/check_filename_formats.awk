BEGIN {
    # every filename_format line, any section, blanks around key and value
    # dropped as fio drops them; the first bad one printed, exit 1
    for (a = 1; a < ARGC; a++) {
        if ((n = readlines(ARGV[a], L)) < 0) awk_fail("cannot read " ARGV[a])
        for (i = 1; i <= n; i++) {
            line = strip(L[i]); c = substr(line, 1, 1)
            if (c == "#" || c == ";" || !(p = index(line, "="))) continue
            if (strip(substr(line, 1, p - 1)) != "filename_format") continue
            v = strip(substr(line, p + 1))
            if (v ~ /[ \t\013\014\r\034\035\036\037]/) {
                print ARGV[a] ": filename_format must not contain whitespace: \047" v "\047"
                exit 1
            }
        }
    }
}
