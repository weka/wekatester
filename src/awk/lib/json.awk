# --- JSON ---
# A tokenizer, one line at a time: json_line fills JP[i] (dot path), JV[i]
# (unescaped value), JS[i] (1 for a string) up to JN; empty containers are {}
# or []. Text before the first <starts> char is skipped. Whole-file strings are
# quadratic in macOS awk and mawk.
function json_begin(starts) {
    J_WANT = "v"; J_VPATH = ""; J_D = 0; J_STARTED = 0; J_CARRY = ""; J_FPOS = 0
    J_STARTS = starts; J_ROOT = ""; J_ERR = ""; JN = 0
}
# One line: 0 to go on, 1 when the document is complete, -1 when it does
# not parse (J_ERR says where)
function json_line(s,    line, lstart, rest, p, i, c, tl) {
    if (J_CARRY != "") { line = J_CARRY s; lstart = J_CSTART; J_CARRY = "" }
    else { line = s; lstart = J_FPOS }
    J_FPOS += length(s) + 1
    if (!J_STARTED) {
        p = 0
        for (i = 1; i <= length(J_STARTS); i++)
            if ((c = index(line, substr(J_STARTS, i, 1))) && (!p || c < p)) p = c
        if (!p) return 0
        J_STARTED = 1; rest = substr(line, p); J_ROOT = substr(rest, 1, 1)
    } else rest = line
    while (1) {
        sub(/^[ \t\r]+/, "", rest)
        if (rest == "") return 0
        J_TOKOFF = lstart + length(line) - length(rest) + 1
        c = substr(rest, 1, 1)
        if (c == "\"") {
            if (!match(rest, /^"([^"\\]|\\.)*"/)) {
                # the string goes on past this line
                J_CARRY = rest "\n"; J_CSTART = J_TOKOFF - 1; return 0
            }
            tl = RLENGTH; json_feed(substr(rest, 2, tl - 2), 1)
        } else if (index("{}[]:,", c)) {
            tl = 1; json_feed(c, 0)
        } else {
            match(rest, /^[^],} \t\r]+/); tl = RLENGTH; json_feed(substr(rest, 1, tl), 0)
        }
        if (J_ERR != "") return -1
        if (J_WANT == "end") return 1
        rest = substr(rest, tl + 1)
    }
}
# After the last line: 0 when the document was complete, 2 when there was
# none at all, 3 when it does not parse (J_ERR)
function json_end() {
    if (J_ERR != "") return 3
    if (!J_STARTED) return 2
    J_TOKOFF = J_FPOS
    if (J_CARRY != "") return json_fail("unterminated string")
    if (J_WANT != "end") return json_fail("unexpected end")
    return 0
}
function json_fail(what) { J_ERR = sprintf("json: %s at offset %d", what, J_TOKOFF); return 3 }
function json_emit(path, v, isstr) { JN++; JP[JN] = path; JV[JN] = v; JS[JN] = isstr }
function json_unesc(s,   out, p, e) {
    if (!index(s, "\\")) return s
    out = ""
    while ((p = index(s, "\\"))) {
        out = out substr(s, 1, p - 1); e = substr(s, p + 1, 1)
        if (e == "u") { out = out "?"; s = substr(s, p + 6); continue }
        if (e == "n") out = out "\n"; else if (e == "t") out = out "\t"
        else if (e == "r") out = out "\r"; else out = out e
        s = substr(s, p + 2)
    }
    return out s
}
# after a value: the enclosing container wants a separator, or the
# document is complete
function json_done() { J_WANT = J_D == 0 ? "end" : J_T[J_D] == "o" ? "o" : "a" }
# one token: tok, and whether it was a quoted string
function json_feed(tok, isstr) {
    if (J_WANT == "v" || J_WANT == "V") {
        if (!isstr && tok == "]" && J_WANT == "V") { json_emit(J_CP[J_D], "[]", 0); J_D--; json_done(); return }
        if (!isstr && tok == "{") { J_T[++J_D] = "o"; J_CP[J_D] = J_VPATH; J_WANT = "k"; return }
        if (!isstr && tok == "[") { J_T[++J_D] = "a"; J_CP[J_D] = J_VPATH; J_IX[J_D] = 0; J_VPATH = J_VPATH ".0"; J_WANT = "V"; return }
        if (!isstr && index("{}[]:,", tok)) { json_fail("unexpected character"); return }
        json_emit(J_VPATH, isstr ? json_unesc(tok) : tok, isstr)
        json_done(); return
    }
    if (J_WANT == "k" || J_WANT == "K") {
        if (!isstr && tok == "}" && J_WANT == "k") { json_emit(J_CP[J_D], "{}", 0); J_D--; json_done(); return }
        if (!isstr) { json_fail("expected a key"); return }
        tok = json_unesc(tok); J_VPATH = J_CP[J_D] == "" ? tok : J_CP[J_D] "." tok; J_WANT = ":"; return
    }
    if (J_WANT == ":") {
        if (isstr || tok != ":") json_fail("expected :")
        else J_WANT = "v"
        return
    }
    if (J_WANT == "o") {
        if (!isstr && tok == ",") { J_WANT = "K"; return }
        if (!isstr && tok == "}") { J_D--; json_done(); return }
        json_fail("expected , or }"); return
    }
    if (J_WANT == "a") {
        if (!isstr && tok == ",") { J_VPATH = J_CP[J_D] "." (++J_IX[J_D]); J_WANT = "v"; return }
        if (!isstr && tok == "]") { J_D--; json_done(); return }
        json_fail("expected , or ]"); return
    }
}
