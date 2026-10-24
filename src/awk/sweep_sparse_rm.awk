# The calibration's truncate record ("<name> <MiB>" lines) as rm commands, a
# new line only past ~100 KB, under the 128 KiB one remote command may hold
{
    if (!len) { printf "rm -f --"; len = 8 }
    q = " " squote($1); printf "%s", q; len += length(q)
    if (len >= 100000) { print ""; len = 0 }
}
END { if (len) print "" }
