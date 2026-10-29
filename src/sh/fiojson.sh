# --- fio JSON -------------------------------------------------------------------
# json_flat <file>: path<TAB>value per scalar. Exit 2: no JSON; exit 3: it
# does not parse (offset on stderr).
json_flat() {   # json_flat <file>
    awkrun '
    #@awk json_flat' "$1"
}

# One parse per results file: check_fio_errors loads it, the next reader reuses
# it. In a run the flat form is a file, one per shell so a subshell's load
# never rewrites its parent's: a layout result at a few hundred hosts is
# hundreds of MB.
JSON_PATH=""; JSON_FLAT=""; JSON_FLAT_FILE=""; JSON_RC=0; JSON_ERR=""
json_load() {   # json_load <file> -> JSON_FLAT_FILE or JSON_FLAT, JSON_RC, JSON_ERR (json_flat's own message)
    # the parser's message goes through a private file (mktemp) inside the
    # run's own directory where there is one -- never a guessable /tmp name
    local e
    JSON_PATH=$1
    if ! e=$(mktemp "${WORK_DIR:-${TMPDIR:-/tmp}}/wt.jsonerr.XXXXXX"); then
        JSON_FLAT=""; JSON_FLAT_FILE=""; JSON_RC=3; JSON_ERR="json: cannot create a scratch file for the parser"
        return 1
    fi
    if [ -n "${WORK_DIR:-}" ]; then
        JSON_FLAT=""; JSON_FLAT_FILE="$WORK_DIR/json.flat.$BASHPID"
        json_flat "$1" > "$JSON_FLAT_FILE" 2> "$e"; JSON_RC=$?
    else
        JSON_FLAT_FILE=""
        JSON_FLAT=$(json_flat "$1" 2> "$e"); JSON_RC=$?
    fi
    JSON_ERR=""
    [ ! -s "$e" ] || IFS= read -r JSON_ERR < "$e"
    rm -f "$e"
}
json_use() {   # json_use <file>: the loaded lines when they are this file's, else load them
    [ -n "$JSON_PATH" ] && [ "$JSON_PATH" = "$1" ] || json_load "$1"
}
json_awk() {   # json_awk <awk args>: awk (LC_ALL=C) over the loaded lines
    if [ -n "$JSON_FLAT_FILE" ]; then
        LC_ALL=C awk "$@" "$JSON_FLAT_FILE"
    else
        printf '%s\n' "$JSON_FLAT" | LC_ALL=C awk "$@"
    fi
}

# Linux strerror for the errno fio reports (the workers are Linux, whatever
# the controller is); the bare number when unknown.
errno_text() {   # errno_text <n>
    errno_text_v "$1"
    printf '%s' "$ERRNO_TEXT"
}
errno_text_v() {   # errno_text_v <n> -> ERRNO_TEXT, without a subshell per error line
    ERRNO_TEXT=""
    case "$1" in
        1) ERRNO_TEXT='Operation not permitted' ;;      2) ERRNO_TEXT='No such file or directory' ;;
        4) ERRNO_TEXT='Interrupted system call' ;;      5) ERRNO_TEXT='Input/output error' ;;
        9) ERRNO_TEXT='Bad file descriptor' ;;          11) ERRNO_TEXT='Resource temporarily unavailable' ;;
        12) ERRNO_TEXT='Cannot allocate memory' ;;      13) ERRNO_TEXT='Permission denied' ;;
        16) ERRNO_TEXT='Device or resource busy' ;;     17) ERRNO_TEXT='File exists' ;;
        19) ERRNO_TEXT='No such device' ;;              20) ERRNO_TEXT='Not a directory' ;;
        21) ERRNO_TEXT='Is a directory' ;;              22) ERRNO_TEXT='Invalid argument' ;;
        24) ERRNO_TEXT='Too many open files' ;;         27) ERRNO_TEXT='File too large' ;;
        28) ERRNO_TEXT='No space left on device' ;;     30) ERRNO_TEXT='Read-only file system' ;;
        110) ERRNO_TEXT='Connection timed out' ;;       122) ERRNO_TEXT='Disk quota exceeded' ;;
        # the ones a network filesystem adds
        6) ERRNO_TEXT='No such device or address' ;;    23) ERRNO_TEXT='Too many open files in system' ;;
        32) ERRNO_TEXT='Broken pipe' ;;                 36) ERRNO_TEXT='File name too long' ;;
        38) ERRNO_TEXT='Function not implemented' ;;    39) ERRNO_TEXT='Directory not empty' ;;
        61) ERRNO_TEXT='No data available' ;;           95) ERRNO_TEXT='Operation not supported' ;;
        104) ERRNO_TEXT='Connection reset by peer' ;;   107) ERRNO_TEXT='Transport endpoint is not connected' ;;
        111) ERRNO_TEXT='Connection refused' ;;         112) ERRNO_TEXT='Host is down' ;;
        113) ERRNO_TEXT='No route to host' ;;           116) ERRNO_TEXT='Stale file handle' ;;
        125) ERRNO_TEXT='Operation canceled' ;;
    esac
}
