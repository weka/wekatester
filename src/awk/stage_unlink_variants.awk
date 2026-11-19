BEGIN {
    mode = ARGV[1]; lay = ARGV[2]; unl = ARGV[3]; jobs = ARGV[4]
    for (a = 5; a < ARGC; a++) {
        h = ARGV[a]; src = jobs "/" h "/" lay
        if ((n = readlines(src, L)) < 0)
            awk_fail("no staged layout variant for " h "; cannot derive the -u unlink job")
        # private (shared and full keep them): a section on the shared read set (its own filename_format,
        # else the one in [global], starts with "shared.") is left out, so its
        # files stay
        split("", SH); split("", OWN); split("", SEC); s = 0; gsh = 0
        if (mode == "private")
            for (i = 1; i <= n; i++) {
                t = strip(L[i])
                if (t ~ /^\[.+\]$/) { s++; SEC[s] = t; continue }
                if (jf_key(t) != "filename_format") continue
                v = index(jf_value(t), "shared.") == 1
                if (!s || SEC[s] == "[global]") gsh = v
                else { OWN[s] = 1; SH[s] = v }
            }
        m = 0; split("", O); s = 0; skip = 0
        for (i = 1; i <= n; i++) {
            if (index(L[i], layout_marker()) == 1) continue
            t = strip(L[i])
            if (t ~ /^\[.+\]$/) { s++; skip = t != "[global]" && ((s in OWN) ? SH[s] : gsh) }
            if (skip) continue
            k = jf_key(L[i])
            if (k == "filesize" || k == "size") O[++m] = "filesize=4k"
            else if (k == "blocksize" || k == "bs") O[++m] = "blocksize=4k"
            else O[++m] = L[i]
        }
        # every section must unlink: a hand-written layout may have no
        # [global] at all, and override_lines creates one then
        m = override_lines(O, m, "unlink", "1")
        writelines(jobs "/" h "/" unl, O, m)
    }
}
