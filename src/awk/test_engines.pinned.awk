BEGIN {
    while ((getline line < ARGV[2]) > 0)
        if (split(line, F, " ") == 3 && F[2] == ARGV[1] && F[3] == "ok") ok[F[1]] = 1
    for (a = 3; a < ARGC; a++) if (!(ARGV[a] in ok)) { print ARGV[a]; exit }
}
