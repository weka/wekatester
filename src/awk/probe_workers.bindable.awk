# A "host reason" line per host whose probe has no bindable line: the
# probe's bindable_err, else its silence. Read as probe_cpu_fact reads it.
BEGIN {
    for (a = 2; a < ARGC; a++) {
        p = ARGV[1] "/" ARGV[a]; ok = 0; why = ""
        while ((getline line < p) > 0) {
            if (!index(line, "bindable") || pysplit(line, F) < 2) continue
            if (F[1] == "bindable") { ok = 1; break }
            if (F[1] == "bindable_err") why = substr(line, index(line, "bindable_err") + 13)
        }
        close(p)
        if (!ok) print ARGV[a], (why == "" ? "its probe printed no bindable line" : why)
    }
}
