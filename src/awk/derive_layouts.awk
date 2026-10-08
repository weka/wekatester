BEGIN {
    mode = ARGV[1]; label = ARGV[2]; directory = ARGV[3]; work = ARGV[4]
    nh = 0
    for (a = 5; a < ARGC; a++) H[++nh] = ARGV[a]
    if ((n = readlines(work "/staged.kinds", K)) < 0) awk_fail("cannot read " work "/staged.kinds")
    nj = 0; nl = 0
    for (i = 1; i <= n; i++) {
        if (substr(K[i], 1, 2) == "J ") JOB[++nj] = substr(K[i], 3)
        else if (substr(K[i], 1, 2) == "L ") LAYN[++nl] = substr(K[i], 3)
    }
    # plain staging always re-derived the layout job, set or no set
    if (!nl) { if (mode == "auto") exit 0; LAYN[++nl] = layout_job() }
    # the whole fleet groups: a group first member lays out its set
    nall = 0
    for (i = 1; i <= n; i++) if (substr(K[i], 1, 2) == "H ") ALLH[++nall] = substr(K[i], 3)
    fs_groups(work, ALLH, nall, GF, GM)
    for (x = 1; x <= nh; x++) {
        h = H[x]; lay_reset(); hdir = ""
        for (j = 1; j <= nj; j++) {
            p = work "/jobs/" h "/" JOB[j]
            if ((m = readlines(p, V)) < 0) awk_fail("cannot read " p)
            if (hdir == "") hdir = first_value(V, m, "directory")
            lay_engine(V, m)
            if (mode == "auto" && index(first_value(V, m, "filename_format"), "shared.") == 1) {
                if (GF[h] != h) continue   # its group first lays the set out
                nr = split(GM[h], RD, " ")
            } else { nr = 1; RD[1] = h }
            for (r = 1; r <= nr; r++) {
                if (RD[r] == h) { lay_add(V, m, JOB[j], p); continue }
                q = work "/jobs/" RD[r] "/" JOB[j]
                if ((mr = readlines(q, RL)) < 0) awk_fail("cannot read " q)
                lay_add(RL, mr, JOB[j], q)
            }
        }
        nb = 0; split("", B)
        B[++nb] = layout_marker() (mode == "auto" ? " (re-derived by wekatester auto[" label "] from this host\047s tuned variants)" : " (re-derived by wekatester from this host\047s staged variants)")
        B[++nb] = "[global]"
        B[++nb] = "directory=" (hdir != "" ? hdir : directory)
        if (mode == "auto") {
            if (readlines(work "/usable/" h, U) < 1) awk_fail("cannot read " work "/usable/" h)
            B[++nb] = "cpus_allowed=" U[1]
        }
        B[++nb] = "create_serialize=0"
        B[++nb] = "fallocate=none"
        B[++nb] = "ioengine=" pick_engine(LAY_TALLY, LAY_EORD, LAY_NE)
        nb = lay_sections(B, nb)
        for (i = 1; i <= nl; i++) writelines(work "/jobs/" h "/" LAYN[i], B, nb)
    }
}
