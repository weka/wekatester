{ p = index($0, "{"); s = p ? substr($0, 1, p - 1) : $0; l = tolower(s) }
index(l, "error") || index(l, "failed") { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); print "ERROR: " s; if (++n == 3) exit }
p { exit }
