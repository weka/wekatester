FNR == 1 && NR > 1 { print id; id = "" }
$1 == "ident" && !got[FILENAME]++ { id = tolower($2) }
END { print id }
