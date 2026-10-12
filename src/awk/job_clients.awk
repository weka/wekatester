BEGIN {
    for (a = 3; a < ARGC; a++) {
        n = readlines(ARGV[1] "/" ARGV[a] "/" ARGV[2], L); has = n < 0
        for (i = 1; i <= n && !has; i++) { s = strip(L[i]); if (s ~ /^\[.+\]$/ && s != "[global]") has = 1 }
        if (has) print ARGV[a]
    }
}
