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
