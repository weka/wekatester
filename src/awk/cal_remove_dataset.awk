BEGIN {
    sep = ARGV[1]; fmt = ARGV[2]; ng = 0
    # group_first: the first host of each group in the groups file;
    # a host it does not list is its own; no groups file, the first host
    if (ARGV[3] != "-")
        while ((getline line < ARGV[3]) > 0)
            if (split(line, F, " ") == 2) { ng++; G[F[1]] = F[2]; if (!(F[2] in FIRST)) FIRST[F[2]] = F[1] }
    for (a = 4; a + 2 < ARGC; a += 3) {
        h = ARGV[a]
        first = ng ? (!(h in G) || FIRST[G[h]] == h) : (a == 4)
        if (first) print "S\t" h "\t" dataset_remove_cmd("shared." fmt, ARGV[a + 2])
        print "P\t" h "\t" dataset_remove_cmd(ARGV[a + 1] sep fmt, ARGV[a + 2])
    }
}
