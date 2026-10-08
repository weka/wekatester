BEGIN {
    lay = ARGV[1]; unl = ARGV[2]; jobs = ARGV[3]
    for (a = 4; a < ARGC; a++) {
        h = ARGV[a]; src = jobs "/" h "/" lay
        if ((n = readlines(src, L)) < 0)
            awk_fail("no staged layout variant for " h "; cannot derive the -u unlink job")
        m = 0; split("", O)
        for (i = 1; i <= n; i++) {
            if (index(L[i], layout_marker()) == 1) continue
            if (L[i] ~ /^filesize=/ || L[i] ~ /^size=/) O[++m] = "filesize=4k"
            else if (L[i] ~ /^(blocksize|bs)=/) O[++m] = "blocksize=4k"
            else O[++m] = L[i]
        }
        # every section must unlink: a hand-written layout may have no
        # [global] at all, and override_lines creates one then
        m = override_lines(O, m, "unlink", "1")
        writelines(jobs "/" h "/" unl, O, m)
    }
}
