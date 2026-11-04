# --- the host file (CSV) ---
# csv.reader default dialect: a quoted field may span lines, "" is a quote,
# text after a closing quote runs on. Returns the record count; CN[r], CV[r,
# i].
function csv_read(L, n, CN, CV,    r, i, s, len, k, c, st, f, nf) {
    split("", CN); split("", CV); r = 0; st = 0
    for (i = 1; i <= n; i++) {
        s = L[i]; len = length(s)
        if (st == 3) f = f "\n"              # the quoted field spans the line break
        else { nf = 0; f = ""; st = 1 }      # 1: a field starts
        for (k = 1; k <= len; k++) {
            c = substr(s, k, 1)
            if (st == 1) {
                if (c == "\"") st = 3        # 3: inside quotes
                else if (c == ",") CV[r + 1, ++nf] = ""
                else { f = c; st = 2 }       # 2: an unquoted field
            } else if (st == 2) {
                if (c == ",") { CV[r + 1, ++nf] = f; f = ""; st = 1 }
                else f = f c
            } else if (st == 3) {
                if (c == "\"") st = 4        # 4: a quote inside quotes
                else f = f c
            } else if (c == "\"") { f = f c; st = 3 }
            else if (c == ",") { CV[r + 1, ++nf] = f; f = ""; st = 1 }
            else { f = f c; st = 2 }
        }
        if (st == 3) continue
        if (len) CV[r + 1, ++nf] = f         # a blank line is a record of no fields
        CN[++r] = nf
    }
    if (st == 3) { CV[r + 1, ++nf] = f; CN[++r] = nf }   # the file ends inside quotes
    return r
}
function csv_line(s, F,    L, CN, CV, k) {   # one line, as csv.reader([line]) parses it
    L[1] = s
    csv_read(L, 1, CN, CV)
    split("", F)
    for (k = 1; k <= CN[1]; k++) F[k] = CV[1, k]
    return CN[1]
}
# A first cell starting WT_ (any case) is a settings line, never a host:
# a host name holds no underscore (RFC 1123).
function is_setting_cell(cell) {
    return tolower(strip(cell)) ~ /^wt_/
}
# A host cell with *, ? or [ before any /<machine-id> is a pattern row,
# unless it is a range row.
function is_glob_cell(cell,    name) {
    name = cell; sub(/\/.*/, "", name)
    return name ~ /[*?[]/ && !is_range_cell(cell)
}
# A range row: no * or ?, and a {..} or only range-shaped [..] ([N-M],
# [a-z]); [ab] or [!a] stays a glob class.
function is_range_cell(cell,    s, k, b) {
    s = cell; sub(/\/.*/, "", s)
    if (s ~ /[*?]/) return 0
    if (index(s, "{")) return 1
    if (!index(s, "[")) return 0
    while ((k = index(s, "["))) {
        s = substr(s, k + 1)
        if (!(k = index(s, "]"))) return 0
        b = substr(s, 1, k - 1); s = substr(s, k + 1)
        if (b !~ /^[0-9]+-[0-9]+$/ && b !~ /^[a-z]-[a-z]$/ && b !~ /^[A-Z]-[A-Z]$/) return 0
    }
    return 1
}
# A host name's ranges multiplied out, left to right: [N-M] and {N..M}
# zero-padded to the left side's width, [a-f] and {a..f}, {a,b,c}. -> the
# count, the names in X; -1 and RANGE_ERR when one is malformed or backwards.
function expand_ranges(s, X,    n, i, j, k, q, c, cl, lit, nv, V, m, Y) {
    split("", X); X[1] = ""; n = 1; lit = ""
    while (s != "") {
        c = substr(s, 1, 1)
        if (c == "]" || c == "}") { RANGE_ERR = "\047" c "\047 closes no range"; return -1 }
        if (c != "[" && c != "{") { lit = lit c; s = substr(s, 2); continue }
        cl = c == "[" ? "]" : "}"
        if (!(j = index(s, cl))) { RANGE_ERR = "\047" c "\047 is never closed"; return -1 }
        if ((nv = range_values(substr(s, 1, j), V)) < 0) return -1
        s = substr(s, j + 1); m = 0; split("", Y)
        for (k = 1; k <= n; k++) for (q = 1; q <= nv; q++) Y[++m] = X[k] lit V[q]
        split("", X); for (k = 1; k <= m; k++) X[k] = Y[k]
        n = m; lit = ""
    }
    for (k = 1; k <= n; k++) X[k] = X[k] lit
    return n
}
# One [..] or {..} as its values, in order -> the count, the values in V.
function range_values(t, V,    b, a, z, k, w, AL, ia, iz, n, sep, ok) {
    split("", V); b = substr(t, 2, length(t) - 2)
    if (index(b, "[") || index(b, "]") || index(b, "{") || index(b, "}")) {
        RANGE_ERR = t " holds a bracket or brace: ranges do not nest"; return -1 }
    sep = substr(t, 1, 1) == "[" ? "-" : ".."
    if (sep == ".." && !index(b, "..")) {   # a list
        n = split(b, V, ",")
        if (n < 1) { RANGE_ERR = t " is empty"; return -1 }
        return n
    }
    if (sep == "-") ok = b ~ /^([0-9]+-[0-9]+|[a-z]-[a-z]|[A-Z]-[A-Z])$/
    else ok = b ~ /^([0-9]+[.][.][0-9]+|[a-z][.][.][a-z]|[A-Z][.][.][A-Z])$/
    if (!ok) {
        RANGE_ERR = t " is not a range: " (sep == "-" ? "[N-M] or [a-z]" : "{N..M}, {a..z} or {a,b,c}"); return -1 }
    k = index(b, sep); a = substr(b, 1, k - 1); z = substr(b, k + length(sep))
    if (a ~ /^[0-9]/) {
        w = length(a); a = dnorm(a); z = dnorm(z)
        if (length(a) > length(z) || length(a) == length(z) && a > z) { RANGE_ERR = t " runs backwards"; return -1 }
        for (n = 0; ; a = dinc(a)) { V[++n] = a; while (length(V[n]) < w) V[n] = "0" V[n]; if (a == z) break }
        return n
    }
    AL = a ~ /[a-z]/ ? "abcdefghijklmnopqrstuvwxyz" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ia = index(AL, a); iz = index(AL, z)
    if (ia > iz) { RANGE_ERR = t " runs backwards"; return -1 }
    for (n = 0; ia <= iz; ia++) V[++n] = substr(AL, ia, 1)
    return n
}
# decimal strings, so no awk's number formatting limits a range
function dnorm(s) { sub(/^0+/, "", s); return s == "" ? "0" : s }
function dinc(s,    i, z) {
    z = ""
    for (i = length(s); i > 0 && substr(s, i, 1) == "9"; i--) z = z "0"
    return i ? substr(s, 1, i - 1) (substr(s, i, 1) + 1) z : "1" z
}
# Shell glob to an anchored ERE, lowercased: * and ? cross dots, [..] and
# [!..] are classes, every other character is literal. "" for a class that
# holds [ or \, which the two awks read differently, or a backwards range
# (z-a), which gawk aborts on, mawk reads as the set {a, z} and BSD awk never matches.
function glob_re(g,    re, i, n, c, j, k, neg, body, p) {
    g = tolower(g); re = "^"; n = length(g)
    for (i = 1; i <= n; i++) {
        c = substr(g, i, 1)
        if (c == "*") re = re ".*"
        else if (c == "?") re = re "."
        else if (c == "[") {
            k = i + 1; neg = substr(g, k, 1) == "!" || substr(g, k, 1) == "^"
            if (neg) k++
            j = k + (substr(g, k, 1) == "]")   # a leading ] is a member
            while (j <= n && substr(g, j, 1) != "]") j++
            if (j > n) { re = re "\\["; continue }   # unclosed: a literal [
            body = substr(g, k, j - k)
            if (index(body, "[") || index(body, "\\")) return ""
            for (p = 1; p + 2 <= length(body); p++)
                if (substr(body, p + 1, 1) == "-") {
                    if (substr(body, p, 1) > substr(body, p + 2, 1)) return ""
                    p += 2
                }
            re = re "[" (neg ? "^" : "") body "]"; i = j
        } else if (c == "^" || c == "\\") re = re "\\" c
        else if (index(".$+(){}|", c)) re = re "[" c "]"
        else re = re c
    }
    return re "$"
}
