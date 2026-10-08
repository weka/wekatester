BEGIN {
    for (a = 1; a + 1 < ARGC; a += 2) {
        host = ARGV[a]; path = ARGV[a + 1]
        if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
        split("", KV); split("", SN); split("", seen); split("", D)
        ns = 0; cur = ""   # "": before any section, where keys count for nothing
        for (i = 1; i <= n; i++) {
            line = strip(L[i]); c = substr(line, 1, 1)
            if (line == "" || c == "#" || c == ";") continue
            if (c == "[") {
                name = substr(line, 2, length(line) - 2)
                if (name == "global") cur = "g"
                else { SN[++ns] = name; cur = ns }
                continue
            }
            if ((p = index(line, "=")) && cur != "")
                KV[cur, strip(substr(line, 1, p - 1))] = strip(substr(line, p + 1))
        }
        nd = 0
        for (s = 1; s <= ns; s++) {
            name = SN[s]
            fmt = ((s, "filename_format") in KV) ? KV[s, "filename_format"] : KV["g", "filename_format"]
            if (!index(fmt, "/")) continue
            pre = replace_all(substr(fmt, 1, match(fmt, /\/[^\/]*$/) - 1), "$jobname", name)
            nc = 1; C[1] = pre
            for (v = 1; v <= 2; v++) {
                var = v == 1 ? "$filenum" : "$jobnum"; key = v == 1 ? "nrfiles" : "numjobs"
                if (!index(pre, var)) continue
                cnt = ((s, key) in KV) ? KV[s, key] : (("g", key) in KV) ? KV["g", key] : 1
                if ((cnt = py_int(cnt)) == "") awk_fail("[" name "]: " key " is not a number")
                m = 0
                for (j = 1; j <= nc; j++) for (k = 0; k < cnt; k++) C2[++m] = replace_all(C[j], var, k)
                nc = m
                for (j = 1; j <= nc; j++) C[j] = C2[j]
            }
            for (j = 1; j <= nc; j++) if (index(C[j], "$")) break
            if (j <= nc) {
                # the same file on every host says it once, not once per host
                msg = "WARNING: cannot pre-create directories for [" name "]: unsupported variable in " squote(pre)
                if (!(msg in said)) { said[msg] = 1; print msg > "/dev/stderr" }
                continue
            }
            base = ((s, "directory") in KV) ? KV[s, "directory"] : KV["g", "directory"]
            for (j = 1; j <= nc; j++)
                if (!((d = path_join(base, C[j])) in seen)) { seen[d] = 1; D[++nd] = d }
        }
        sort_arr(D, nd, 0)
        out = ""
        for (i = 1; i <= nd; i++)
            out = out ((i - 1) % 400 ? "" : (i > 1 ? " && " : "") "mkdir -p") " " squote(D[i])
        if (out != "") print host "\t" out
    }
}
