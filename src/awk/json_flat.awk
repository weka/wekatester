BEGIN { json_begin("{") }
{
    r = json_line($0)
    for (i = 1; i <= JN; i++) print JP[i] "\t" JV[i]
    JN = 0
    if (r < 0) { print J_ERR > "/dev/stderr"; failed = 1; exit 3 }
    if (r > 0) exit 0
}
END {
    if (failed) exit 3
    if ((r = json_end())) { if (J_ERR != "") print J_ERR > "/dev/stderr"; exit r }
}
