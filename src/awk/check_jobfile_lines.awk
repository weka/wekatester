BEGIN {
    # every line, any section, blanks around key and value dropped as fio
    # drops them; the first bad one printed, exit 1
    for (a = 1; a < ARGC; a++) {
        if ((n = readlines(ARGV[a], L)) < 0) awk_fail("cannot read " ARGV[a])
        for (i = 1; i <= n; i++) {
            if ((k = jf_key(L[i])) == "") continue
            line = strip(L[i])
            # only cpus_allowed is held to the host's fio cpus at staging
            if (k == "cpumask" || k == "numa_cpu_nodes") {
                print ARGV[a] ": \047" line "\047: " k " can place fio on weka\047s cores or core 0\047s pair; use cpus_allowed, which wekatester holds to each host\047s fio cpus"
                exit 1
            }
            if (k != "filename_format") continue
            v = jf_value(line)
            if (v ~ /[ \t\013\014\r\034\035\036\037]/) {
                print ARGV[a] ": filename_format must not contain whitespace: \047" v "\047"
                exit 1
            }
        }
    }
}
