BEGIN {
    while ((getline line < ARGV[2]) > 0) {
        split(line, F, "\t")
        if (!(F[1] in v)) v[F[1]] = F[ARGV[1] + 0]
    }
    for (a = 3; a < ARGC; a++) {
        x = (ARGV[a] in v) ? v[ARGV[a]] : ""
        if (x == "-") x = ""
        print x
    }
}
