    function human(m) { return m >= 1048576 ? sprintf("%.1f TiB", m / 1048576) : sprintf("%.1f GiB", m / 1024) }
    BEGIN {
    printf "%d dense file(s) = %s to write, %d sparse truncate(s)", n, human(mib), t
    if (av == "") printf "; free space at %s unknown", d
    else printf "; free %s at %s (%.1f%% of it)", human(av), d, (av > 0 ? mib * 100 / av : 0)
}
