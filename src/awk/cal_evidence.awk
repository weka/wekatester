/^\{/ { exit }
/[Ee]rror|ERROR|[Ff]ailed|err=/ {
    k = $0; gsub(/pid=[0-9]+/, "pid=<n>", k)
    if (!(k in n)) { order[++d] = k; sample[k] = $0 }
    n[k]++
}
END {
    for (i = 1; i <= d && i <= 5; i++) {
        k = order[i]
        printf "ERROR: %s: fio said%s: %s\n", what,
            (n[k] > 1 ? sprintf(" (%d jobs)", n[k]) : ""), sample[k]
    }
    if (d > 5)
        printf "ERROR: %s: and %d more distinct error line(s) in the fio output\n", what, d - 5
}
