BEGIN {
    for (a = 3; a < ARGC; a++) {
        ok = 0; m = readlines(ARGV[2] "/" ARGV[a], L)
        for (i = 1; i <= m && !ok; i++)
            if ((nw = pysplit(L[i], W)) && W[1] == "engines")
                for (k = 2; k <= nw; k++) if (W[k] == ARGV[1]) ok = 1
        if (!ok) printf "%s%s", (n++ ? " " : ""), ARGV[a]
    }
}
