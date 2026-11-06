# Host names from one source (ARGV[1], for messages): how many held a
# range, a line per such name with its count, then every name in order.
# A malformed range prints only the error and exits 2.
BEGIN {
    src = ARGV[1]; nn = 0; nr = 0
    for (a = 2; a < ARGC; a++) {
        s = ARGV[a]
        if (!index(s, "[") && !index(s, "]") && !index(s, "{") && !index(s, "}")) { N[++nn] = s; continue }
        if ((n = expand_ranges(s, X)) < 0) { print src ": host range \047" s "\047: " RANGE_ERR; exit 2 }
        R[++nr] = src ": host range \047" s "\047 gives " n " host(s)"
        for (i = 1; i <= n; i++) N[++nn] = X[i]
    }
    print nr
    for (i = 1; i <= nr; i++) print R[i]
    for (i = 1; i <= nn; i++) print N[i]
}
