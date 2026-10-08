# --- fio JSON -------------------------------------------------------------------
# json_flat <file>: path<TAB>value per scalar. Exit 2: no JSON; exit 3: it
# does not parse (offset on stderr).
json_flat() {   # json_flat <file>
    awkrun '
    #@awk json_flat' "$1"
}

# One parse per results file: check_fio_errors loads it, the next reader reuses
# it.
JSON_PATH=""; JSON_FLAT=""; JSON_RC=0; JSON_ERR=""
json_load() {   # json_load <file> -> JSON_FLAT, JSON_RC, JSON_ERR (json_flat's own message)
    # the parser's message goes through a private file (mktemp) inside the
    # run's own directory where there is one -- never a guessable /tmp name
    local e
    JSON_PATH=$1
    if ! e=$(mktemp "${WORK_DIR:-${TMPDIR:-/tmp}}/wt.jsonerr.XXXXXX"); then
        JSON_FLAT=""; JSON_RC=3; JSON_ERR="json: cannot create a scratch file for the parser"
        return 1
    fi
    JSON_FLAT=$(json_flat "$1" 2> "$e"); JSON_RC=$?
    JSON_ERR=""
    [ ! -s "$e" ] || IFS= read -r JSON_ERR < "$e"
    rm -f "$e"
}
json_use() {   # json_use <file>: the loaded lines when they are this file's, else load them
    [ -n "$JSON_PATH" ] && [ "$JSON_PATH" = "$1" ] || json_load "$1"
}

# Linux strerror for the errno fio reports (the workers are Linux, whatever
# the controller is); the bare number when unknown.
errno_text() {   # errno_text <n>
    case "$1" in
        1) printf 'Operation not permitted' ;;      2) printf 'No such file or directory' ;;
        4) printf 'Interrupted system call' ;;      5) printf 'Input/output error' ;;
        9) printf 'Bad file descriptor' ;;          11) printf 'Resource temporarily unavailable' ;;
        12) printf 'Cannot allocate memory' ;;      13) printf 'Permission denied' ;;
        16) printf 'Device or resource busy' ;;     17) printf 'File exists' ;;
        19) printf 'No such device' ;;              20) printf 'Not a directory' ;;
        21) printf 'Is a directory' ;;              22) printf 'Invalid argument' ;;
        24) printf 'Too many open files' ;;         27) printf 'File too large' ;;
        28) printf 'No space left on device' ;;     30) printf 'Read-only file system' ;;
        110) printf 'Connection timed out' ;;       122) printf 'Disk quota exceeded' ;;
        # the ones a network filesystem adds
        6) printf 'No such device or address' ;;    23) printf 'Too many open files in system' ;;
        32) printf 'Broken pipe' ;;                 36) printf 'File name too long' ;;
        38) printf 'Function not implemented' ;;    39) printf 'Directory not empty' ;;
        61) printf 'No data available' ;;           95) printf 'Operation not supported' ;;
        104) printf 'Connection reset by peer' ;;   107) printf 'Transport endpoint is not connected' ;;
        111) printf 'Connection refused' ;;         112) printf 'Host is down' ;;
        113) printf 'No route to host' ;;           116) printf 'Stale file handle' ;;
        125) printf 'Operation canceled' ;;
    esac
}
