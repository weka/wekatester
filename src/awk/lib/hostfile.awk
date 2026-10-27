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
# A host cell with *, ? or [ before any /<machine-id> is a pattern row.
function is_glob_cell(cell,    name) {
    name = cell; sub(/\/.*/, "", name)
    return name ~ /[*?[]/
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
