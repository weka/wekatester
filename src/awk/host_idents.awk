BEGIN {
    for (a = 1; a < ARGC; a++) {
        id = ""
        while ((getline line < ARGV[a]) > 0)
            if (split(line, W, " ") && W[1] == "ident") { id = tolower(W[2]); break }
        close(ARGV[a])
        print id
    }
}
