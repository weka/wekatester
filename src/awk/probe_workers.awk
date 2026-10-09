BEGIN {
    for (a = 3; a < ARGC; a++) {
        ok = 0; p = ARGV[2] "/" ARGV[a]
        # the probe's one engines line sits near the top
        while ((getline line < p) > 0)
            if ((nw = pysplit(line, W)) && W[1] == "engines") {
                for (k = 2; k <= nw; k++) if (W[k] == ARGV[1]) ok = 1
                break
            }
        close(p)
        if (!ok) printf "%s%s", (n++ ? " " : ""), ARGV[a]
    }
}
