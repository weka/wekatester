function awk_fail(msg) { print "ERROR: " msg > "/dev/stderr"; exit 1 }

# ASCII whitespace strip and split; the common cases skip the regex, since
# they run on every probe line.
function strip(s,    c) {
    c = substr(s, 1, 1)
    if (c != "" && index(" \t\n\013\014\r\034\035\036\037", c)) sub(/^[ \t\n\013\014\r\034\035\036\037]+/, "", s)
    c = substr(s, length(s), 1)
    if (c != "" && index(" \t\n\013\014\r\034\035\036\037", c)) sub(/[ \t\n\013\014\r\034\035\036\037]+$/, "", s)
    return s
}
function rstrip(s,    c) {
    c = substr(s, length(s), 1)
    if (c != "" && index(" \t\n\013\014\r\034\035\036\037", c)) sub(/[ \t\n\013\014\r\034\035\036\037]+$/, "", s)
    return s
}
function pysplit(s, F) {   # str.split(): F[1..n]
    # only space, tab and newline: what awk splits on by itself
    if (s !~ /[\013\014\r\034\035\036\037]/) return split(s, F, " ")
    split("", F)
    s = strip(s)
    return s == "" ? 0 : split(s, F, /[ \t\n\013\014\r\034\035\036\037]+/)
}
# int(): the number, or "" where python raises ValueError
function py_int(s) {
    if (s ~ /^[0-9]+$/) return s + 0
    s = strip(s)
    if (s !~ /^[+-]?[0-9]+(_[0-9]+)*$/) return ""
    gsub(/_/, "", s)
    return s + 0 + 0
}
# str.split(sep) for a one-character sep: an empty string is one empty
# field, and a newline in a quoted host-file cell is no separator
function lsplit(s, A, sep,    n, i) {
    split("", A); n = 0
    while ((i = index(s, sep)) > 0) { A[++n] = substr(s, 1, i - 1); s = substr(s, i + 1) }
    A[++n] = s
    return n
}
function replace_all(s, from, to,    i, out) {   # str.replace
    out = ""
    while ((i = index(s, from)) > 0) {
        out = out substr(s, 1, i - 1) to
        s = substr(s, i + length(from))
    }
    return out s
}
function vars_to_glob(s) {   # re.sub(r"\$\w+", "*", s)
    gsub(/\$[A-Za-z0-9_]+/, "*", s)
    return s
}
function count_char(s, c) { return gsub(c, "", s) }
function dirname(p,    head) {   # os.path.dirname
    if (!match(p, /\/[^\/]*$/)) return ""
    head = substr(p, 1, RSTART)
    if (head !~ /^\/+$/) sub(/\/+$/, "", head)
    return head
}
function path_join(a, b) {   # os.path.join(a, b)
    if (substr(b, 1, 1) == "/" || a == "") return b
    return a (substr(a, length(a)) == "/" ? "" : "/") b
}
function squote(s) { return "\047" s "\047" }
# Commands that delete the files <pattern> names under <hd>: find bounded at
# the pattern depth, then the directories left empty.
function dataset_remove_cmd(pattern, hd,    glob, depth, cmd) {
    glob = vars_to_glob(pattern)
    depth = 1 + count_char(glob, "/")
    cmd = sprintf("find %s -maxdepth %d -type f -path %s -delete", squote(hd), depth, squote(hd "/" glob))
    if (index(glob, "/"))
        cmd = cmd sprintf(" && find %s -maxdepth %d -type d -path %s -empty -delete", squote(hd), depth - 1, squote(hd "/" substr(glob, 1, match(glob, /\/[^\/]*$/) - 1)))
    return cmd
}

# open(path).read().splitlines() into L[1..n]; -1 when it cannot be read
function readlines(path, L,    n, r, line, m, k, parts) {
    split("", L); n = 0
    while ((r = (getline line < path)) > 0) {
        if (index(line, "\r")) {
            sub(/\r$/, "", line)
            m = split(line, parts, "\r")
            if (m == 0) L[++n] = ""
            for (k = 1; k <= m; k++) L[++n] = parts[k]
        } else
            L[++n] = line
    }
    close(path)
    return r < 0 ? -1 : n
}
function writelines(path, L, n,    i) {   # "\n".join(L) + "\n"
    if (n == 0) printf "\n" > path
    for (i = 1; i <= n; i++) print L[i] > path
    close(path)
}

# A[1..n] sorted in place, numerically or bytewise
function sort_arr(A, n, num,    gap, i, j, t) {
    for (gap = int(n / 2); gap > 0; gap = int(gap / 2))
        for (i = gap + 1; i <= n; i++) {
            t = A[i]
            for (j = i; j > gap && (num ? (A[j - gap] + 0 > t + 0) : (A[j - gap] "" > t "")); j -= gap)
                A[j] = A[j - gap]
            A[j] = t
        }
}

# cpu sets: arrays keyed by cpu number
function set_size(S,    k, n) { n = 0; for (k in S) n++; return n }
function set_any(S,    k) { for (k in S) return 1; return 0 }
function set_sorted(S, A,    k, n, lo, hi, c) {
    split("", A); n = 0; lo = 0; hi = -1
    for (k in S) {
        A[++n] = k + 0
        if (A[n] < lo) lo = A[n]
        if (A[n] > hi) hi = A[n]
    }
    if (n > 8 && lo == 0 && hi < 4 * n + 64) {   # dense, as cpu sets are: count up
        n = 0
        for (c = 0; c <= hi; c++) if (c in S) A[++n] = c
        return n
    }
    sort_arr(A, n, 1)
    return n
}
function join_sorted(S, sep,    A, n, i, out) {   # sep.join(sorted(S))
    n = set_sorted(S, A); out = ""
    for (i = 1; i <= n; i++) out = out (i > 1 ? sep : "") A[i]
    return out
}
function fmt_cpulist(S,    A, n, i, j, out) {   # 0-3,8: runs collapsed
    n = set_sorted(S, A); out = ""
    for (i = 1; i <= n; i = j + 1) {
        for (j = i; j < n && A[j + 1] == A[j] + 1; j++)
            ;
        out = out (out == "" ? "" : ",") (i == j ? A[i] : A[i] "-" A[j])
    }
    return out
}
# A cpu list ("0-3,8") into the set S: 1, or 0 when it is not one
function parse_cpulist(s, S,    n, P, i, ab, a, b, c) {
    split("", S)
    n = split(s, P, ",")   # not lsplit: a probe's bindable list runs to ~1,500 bytes
    for (i = 1; i <= n; i++) {
        if (index(P[i], "-")) {
            if (lsplit(P[i], ab, "-") != 2) return 0
            if ((a = py_int(ab[1])) == "" || (b = py_int(ab[2])) == "") return 0
            for (c = a; c <= b; c++) S[c] = 1
        } else if (P[i] != "") {
            if ((a = py_int(P[i])) == "") return 0
            S[a] = 1
        }
    }
    return 1
}

