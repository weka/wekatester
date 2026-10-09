# A probe's lines up to its aio_nr line (aio_max_nr comes just before it),
# not the ~1,000 topology lines after
function aio_head(p, P,    n, line) {
    split("", P); n = 0
    while ((getline line < p) > 0) { P[++n] = line; if (index(line, "aio_nr ") == 1) break }
    close(p)
    return n
}
BEGIN {
    if ((m = readlines(ARGV[2], M)) < 0) awk_fail("cannot read " ARGV[2])
    nk = 0; last = ""
    for (i = 1; i <= m; i++) {
        split(M[i], F, "\t")
        if (F[1] != last) {
            last = F[1]
            np = aio_head(ARGV[1] "/probe/" last, P)   # apart: BWK awk passes P untyped otherwise
            room = probe_aio_room(P, np)
        }
        if (room == "" || F[2] == "") continue
        if ((n = readlines(F[2], L)) < 0) awk_fail("cannot read " F[2])
        if ((ev = libaio_events(L, n)) <= room) continue
        job = F[2]; sub(/.*\//, "", job)
        key = job SUBSEP sprintf("%.0f", ev) SUBSEP sprintf("%.0f", room)
        if (!(key in nh)) {   # ordered by (job, events, room)
            K[++nk] = sprintf("%s\001%020.0f\001%020.0f", job, ev, room)
            KEY[K[nk]] = key; JOB[key] = job; EV[key] = ev; ROOM[key] = room
        }
        if (++nh[key] <= 8) names[key] = names[key] (nh[key] > 1 ? " " : "") last
    }
    sort_arr(K, nk, 0)
    for (i = 1; i <= nk; i++) {
        key = KEY[K[i]]
        printf "ERROR: %s: libaio sets up %.0f aio events at once (numjobs x iodepth) on %s, and the kernel has room for %.0f (fs.aio-max-nr less fs.aio-nr, as probed): the jobs past the room would fail io_queue_init with EAGAIN (fio error 11) -- raise fs.aio-max-nr, run another ioengine (-e or the host file), or lower the job\047s numjobs x iodepth\n", JOB[key], EV[key], names[key] (nh[key] > 8 ? sprintf(" (+%d more)", nh[key] - 8) : ""), ROOM[key] > "/dev/stderr"
    }
    exit (nk ? 3 : 0)   # not 2: an awk that dies on its own exits 2
}
