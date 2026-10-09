# truncate.list ("<name> <MiB>" lines) as remote commands: a truncate per
# size, sizes ascending, names in list order; a new line only past ~100 KB,
# under the 128 KiB one sh -c string may hold
{ if (!($2 in N)) S[++ns] = $2; NM[$2, ++N[$2]] = $1 }
END {
    sort_arr(S, ns, 1); len = 0
    for (i = 1; i <= ns; i++) {
        s = S[i]; k = 0
        while (k < N[s]) {
            if (len) { printf " && "; len += 4 }
            printf "truncate -s %sM", s; len += 13 + length(s)
            while (k < N[s] && len < 100000) { q = " " squote(NM[s, ++k]); printf "%s", q; len += length(q) }
            if (len >= 100000) { print ""; len = 0 }
        }
    }
    if (len) print ""
}
