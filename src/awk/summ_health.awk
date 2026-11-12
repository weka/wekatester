function flag(line) { O[++no] = "  " line; flagged = 1 }
function gap(what) { GAP = GAP (GAP == "" ? "" : ", ") what }
function ok(what) { OK = OK (OK == "" ? "" : ", ") what }
# PSI "some avg10" from a pressure capture: the value, "" when there is none
function psi(path,    L, n, i) {
    if (path == "" || (n = readlines(path, L)) < 0) return ""
    for (i = 1; i <= n; i++) if (index(L[i], "some ") == 1 && match(L[i], /avg10=[0-9.]+/)) return substr(L[i], RSTART + 6, RLENGTH - 6) + 0
    return ""
}
function check_psi(res, side, lim,    v) {
    v = psi(P["pressure-" res "-" side])
    if (v == "") { gap(res " PSI " side); return }
    if (v > lim) flag(sprintf("%s pressure at the %s: some avg10 %.2f%% (over SUMMARY_PSI_%s %s)", res, side, v, toupper(res), lim))
    else ok(res " PSI " side)
}
function check_load(    L, n, i, cpus, v, F) {
    if (P["loadavg-start"] == "" || (n = readlines(P["loadavg-start"], L)) < 1 || split(L[1], F, " ") < 3 || F[1] !~ /^[0-9.]+$/) { gap("load start"); return }
    v = F[1] + 0; cpus = 0
    if (P["lscpu"] != "" && (n = readlines(P["lscpu"], L)) > 0)
        for (i = 1; i <= n; i++) if (match(L[i], /^CPU\(s\): *[0-9]+/)) { cpus = substr(L[i], 8) + 0; break }
    if (!cpus) { gap("load start (no cpu count in lscpu)"); return }
    if (v / cpus > lim_load) flag(sprintf("load at the start: %.2f on %d cpus = %.2f per cpu (over SUMMARY_LOAD_PER_CPU %s)", v, cpus, v / cpus, lim_load))
    else ok("load start")
}
# The run window's kernel log: lines that match, a boot inside the run,
# a ring that wrapped; the annotations kernel_log_cmd writes are not lines
function check_klog(    L, n, i, s, inwin, nl, nm, shown, why) {
    if (P["kernel-log-end"] == "" || (n = readlines(P["kernel-log-end"], L)) < 0) { gap("kernel log"); return }
    inwin = 0; nl = 0; nm = 0; why = ""; split("", HIT)
    for (i = 1; i <= n; i++) {
        s = L[i]
        if (substr(s, 1, 2) == "# ") { inwin = 1; continue }
        if (!inwin || s == "") continue
        if (index(s, "(this host booted after the run start") == 1) { flag("kernel log: this host booted during the run"); continue }
        if (index(s, "(the oldest line in the buffer is at") == 1) { flag("kernel log: the ring wrapped during the run, so its start is lost " s); continue }
        if (s ~ /^\(.*\)$/ || substr(s, 1, 3) == "-- ") continue
        if (index(s, "not available:") == 1) { if (why == "") why = s; continue }
        nl++
        if (tolower(s) ~ klog_re) HIT[++nm] = s
    }
    if (!nl && why != "") { gap("kernel log (" why ")"); return }
    if (!nm) { ok("kernel log " nl " line" (nl == 1 ? "" : "s")); return }
    flag("kernel log: " nm " of " nl " line" (nl == 1 ? "" : "s") " in the run window match SUMMARY_KLOG_RE:")
    for (i = 1; i <= nm && i <= klog_lines; i++) O[++no] = "    " HIT[i]
    if (nm > klog_lines) O[++no] = "    (+" (nm - klog_lines) " more; SUMMARY_KLOG_LINES shows " klog_lines ")"
}
function check_clock(    L, n, i, v, ms, sync, why) {
    if (P["chrony"] == "" || (n = readlines(P["chrony"], L)) < 0) { gap("clock"); return }
    v = ""; sync = ""; why = ""
    for (i = 1; i <= n; i++) {
        if (match(L[i], /^System time *: *[0-9.]+ seconds (fast|slow)/)) { v = L[i]; sub(/^System time *: */, "", v); v = v + 0 }
        else if (match(L[i], /^Leap status *: */)) sync = substr(L[i], RLENGTH + 1) == "Not synchronised" ? "no" : "yes"
        else if (match(L[i], /System clock synchronized: */)) sync = substr(L[i], RSTART + RLENGTH)
        else if (why == "" && (L[i] ~ /^\(.* exited [0-9]+\)$/ || index(L[i], "not available:") == 1) && L[i] !~ /timedatectl instead$/) why = L[i]
    }
    if (sync == "no") flag("clock: not synchronised to NTP")
    if (v != "") {
        ms = v * 1000
        if (ms > lim_clock) flag(sprintf("clock: %.1f ms off NTP time (over SUMMARY_CLOCK_MS %s)", ms, lim_clock))
        else if (sync != "no") ok(sprintf("clock %.2f ms off", ms))
    } else if (sync == "yes") ok("clock synchronised (no offset recorded)")
    else if (sync == "") gap("clock" (why != "" ? " (" why ")" : ""))
}
BEGIN {
    fl = ARGV[1]; hl = ARGV[2]
    lim_cpu = ARGV[3]; lim_io = ARGV[4]; lim_mem = ARGV[5]; lim_load = ARGV[6]; lim_clock = ARGV[7]; klog_re = ARGV[8]; klog_lines = ARGV[9] + 0
    nl = readlines(fl, FL); nh = readlines(hl, HL)
    i = 1
    for (hi = 1; hi <= nh; hi++) {
        h = HL[hi]; split("", P); no = 0; flagged = 0; GAP = ""; OK = ""; any = 0
        for (; i <= nl && index(FL[i], h "\t") == 1; i++) { split(FL[i], F, "\t"); P[F[2]] = F[3]; any = 1 }
        if (!any) { print h ": not recorded (no pressure, load, kernel log or clock capture in sysinfo/" h ")"; continue }
        check_psi("cpu", "start", lim_cpu); check_psi("cpu", "end", lim_cpu)
        check_psi("memory", "start", lim_mem); check_psi("memory", "end", lim_mem)
        check_psi("io", "start", lim_io)
        check_load(); check_klog(); check_clock()
        if (!flagged) { print h ": nothing to flag (" OK ")" (GAP != "" ? "; not recorded: " GAP : ""); continue }
        print h
        for (k = 1; k <= no; k++) print O[k]
        if (GAP != "") print "  not recorded: " GAP
    }
}
