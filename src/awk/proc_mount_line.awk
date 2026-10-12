BEGIN { t = ENVIRON["T"]; i = index(t, "\n"); if (i) t = substr(t, 1, i - 1) }
{
    m = $2
    gsub(/\\040/, " ", m); gsub(/\\011/, "\t", m); gsub(/\\012/, "\n", m)
    n = split(m, p, /\\134/); m = p[1]
    for (k = 2; k <= n; k++) m = m "\\" p[k]
    if (m == t) l = $0
}
END { print l }
