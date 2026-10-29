BEGIN {
    n = readlines(ARGV[1], L)
    for (i = 1; i <= 3 && i <= n; i++) if ((want = marker_sha(L[i])) != "") break
    if (want == "") exit 1
    print want
    printf "%s", layout_body(L, n)
}
