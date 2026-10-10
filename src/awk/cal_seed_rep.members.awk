BEGIN {
    rep = ARGV[1]; eng = ARGV[2]; ng = 0
    # group_members: the groups file says who shares the rep group;
    # without one, every host does
    if (ARGV[3] != "-")
        while ((getline line < ARGV[3]) > 0)
            if (split(line, F, " ") == 2) { ng++; G[F[1]] = F[2] }
    while ((getline line < ARGV[4]) > 0) {
        split(line, F, "\t")
        if (!(F[1] in CPU)) { CPU[F[1]] = F[2]; ENG[F[1]] = F[3] }
    }
    for (a = 5; a + 1 < ARGC; a += 2) {
        m = ARGV[a]
        if (m == rep) continue
        if (ng && !((rep in G) && (m in G) && G[m] == G[rep])) continue
        printf "%s\t%s\t%s\t%s\n", m, ARGV[a + 1], CPU[m], (ENG[m] != "" ? ENG[m] : eng)
    }
}
