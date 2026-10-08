BEGIN {
    while ((getline line < ARGV[1]) > 0) { split(line, F, "\t"); if (!(F[1] in eng)) eng[F[1]] = F[3] }
    while ((getline line < ARGV[2]) > 0)
        if (split(line, F, " ") == 3 && F[3] == "ok") ok[F[1] " " F[2]] = 1
    for (a = 3; a < ARGC; a++) {
        h = ARGV[a]; e = (h in eng) ? eng[h] : "-"
        if (e != "-" && e != "" && !((h " " e) in ok)) { print h " " e; exit }
    }
}
