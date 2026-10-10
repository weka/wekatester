# --- logging -----------------------------------------------------------------
log()   { local ts; printf -v ts '%(%H:%M:%S)T' -1; echo "$ts $*"; }
debug() { [ "$VERBOSITY" -ge 1 ] && log "DEBUG: $*"; return 0; }
die()   { log "ERROR: $*" >&2; exit 1; }

# Warnings raised before the run log opens, replayed once into the log FILE
# (not stderr: the console saw them live).
PRERUN_WARNINGS=()
warn_prerun() {
    local w
    log "WARNING: $*" >&2
    for w in "${PRERUN_WARNINGS[@]}"; do
        [ "$w" != "$*" ] || return 0
    done
    PRERUN_WARNINGS+=("$*")
}
replay_prerun_warnings() {
    local w f="$RUN_DIR/wekatester.log"
    # Gated on the run directory, not the file: the background tees may not
    # have created it yet.
    [ ${#PRERUN_WARNINGS[@]} -gt 0 ] && [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || return 0
    for w in "${PRERUN_WARNINGS[@]}"; do
        log "WARNING (before the run log opened): $w" >> "$f"
    done
}

# --- transport ----------------------------------------------------------------
# The only two places that know whether a host is remote. A command string
# must be POSIX sh or wrap itself in bash -c: remotely it runs under the
# login shell (verify_fio_ports carries its own bash -c for /dev/tcp).

# stdin is /dev/null on both branches, or a child can eat the script's stdin.
# host_ssh_opts: our ControlPath and User= per host; nothing for a host on a
# user-owned master, or when AUTH_DIR is unset. The _v form, without the
# subshell, is what every remote call uses.
host_ssh_opts_v() {   # host_ssh_opts_v <host> -> HOST_SSH_OPTS
    HOST_SSH_OPTS=""
    if [ -n "$AUTH_DIR" ] && [ -f "$AUTH_DIR/$1.external" ]; then
        return 0
    fi
    HOST_SSH_OPTS=$CONTROL_OPTS
    if [ -n "$AUTH_DIR" ] && [ -f "$AUTH_DIR/$1.user" ]; then
        local u=""
        IFS= read -r u < "$AUTH_DIR/$1.user" || :
        HOST_SSH_OPTS="$HOST_SSH_OPTS -o User=$u"
    fi
}
host_ssh_opts() {   # host_ssh_opts <host>
    host_ssh_opts_v "$1"
    printf '%s' "$HOST_SSH_OPTS"
}

run_host() {   # run_host <host> <command-string>
    if [ "$LOCAL_MODE" -eq 1 ]; then
        bash -c "$2" </dev/null
    else
        host_ssh_opts_v "$1"
        ssh -n $SSH_OPTS $HOST_SSH_OPTS "$1" "$2"
    fi
}

# One tar stream over the master's connection: scp pays a round trip per
# file. The sources share one parent directory.
copy_to_master() {   # copy_to_master <src>... <dst-dir-on-master>
    if [ "$LOCAL_MODE" -eq 1 ]; then
        cp -R "$@"
        return
    fi
    # ${!#} is the last positional (the destination), ${@:1:$#-1} is
    # everything before it
    local dst=${!#} parent=${1%/*} names=() s
    for s in "${@:1:$#-1}"; do
        [ "${s%/*}" = "$parent" ] || { log "ERROR: copy_to_master: $s is not in $parent" >&2; return 1; }
        names+=("${s##*/}")
    done
    local -
    set -o pipefail
    host_ssh_opts_v "$MASTER"
    tar -C "$parent" -cf - -- "${names[@]}" \
        | ssh $SSH_OPTS $HOST_SSH_OPTS "$MASTER" "mkdir -p '$dst' && tar -xf - -C '$dst'"
}

# For a worker that needs its own copy (the postmortem's fio --parse-only).
copy_to_host() {   # copy_to_host <host> <src>... <dst-dir-on-host>
    local host=$1; shift
    if [ "$LOCAL_MODE" -eq 1 ]; then
        cp -R "$@"
    else
        host_ssh_opts_v "$host"
        scp $SSH_OPTS $HOST_SSH_OPTS -q -r "${@:1:$#-1}" "$host:${!#}"
    fi
}

# pgrep and pkill take a regex: a path goes in with every ERE metacharacter
# backslashed, or a binary named fio-3.38+git never matches itself.
ere_quote_v() {   # ere_quote_v <string> -> ERE_QUOTED
    local i c q=
    for ((i = 0; i < ${#1}; i++)); do
        c=${1:i:1}
        case $c in '.'|'['|'\'|'('|')'|'*'|'+'|'?'|'{'|'|'|'^'|'$') q+=\\$c ;; *) q+=$c ;; esac
    done
    ERE_QUOTED=$q
}

# No server given: benchmark this host over loopback; only the transport
# changes.
resolve_local_mode() {
    [ ${#HOSTS[@]} -eq 0 ] || return 0
    LOCAL_MODE=1
    HOSTS=(localhost)
    MASTER=localhost
    LOCAL_NAME=$(local_short_hostname)
    log "no servers given: running on the local host (no ssh required)"
    debug "local mode: data files are prefixed ${LOCAL_NAME:-localhost}. (host_name)"
}

# Split -i entries into (login, key) at the first colon, in order. Paths are
# checked now: left to ssh, a typo fails every host and reads like a cluster
# problem.
validate_credentials() {
    local raw entry login key
    if [ "$LOCAL_MODE" -eq 1 ]; then
        # Local mode: accepted and ignored, like --ignore-capacity outside -a.
        [ ${#IDENT_RAW[@]} -eq 0 ] && [ "$PW_COUNT" -eq 0 ] \
            || debug "local mode: ignoring -i/-p (no ssh involved)"
        return 0
    fi
    for raw in ${IDENT_RAW[@]+"${IDENT_RAW[@]}"}; do
        # ssh option lists are whitespace-split into argv; a login or path
        # with whitespace would arrive as several options nobody wrote.
        case "$raw" in
            *[[:space:]]*) die "-i entries must not contain whitespace: '$raw'" ;;
        esac
        for entry in $(printf '%s' "$raw" | tr ',' ' '); do
            case "$entry" in
                *:*) login=${entry%%:*}; key=${entry#*:} ;;
                *)   login=""; key=$entry ;;
            esac
            [ -n "$key" ] || die "empty key path in -i entry: '$entry'"
            { [ -f "$key" ] && [ -r "$key" ]; } || \
                die "identity file not readable: $key"
            IDENT_LOGINS+=("$login")
            IDENT_KEYS+=("$key")
        done
    done
}

# --- interactive prompting (-C) --------------------------------------------------
# Prompts use /dev/tty on one rw fd: children get /dev/null on stdin and
# stdout is often piped. read -s must read through a redirection (read -u
# echoes), and partial -n input is discarded on timeout, so the escape drain
# reads one byte at a time.
PROMPT_TTY="${WEKATESTER_PROMPT_TTY:-/dev/tty}"   # test plumbing only, namespaced
PROMPT_OPENED=0      # 1 = we own fd 3 and must close it
PROMPT_IN_FD=""      # read side  -- the suite presets these two and then
PROMPT_OUT_FD=""     # write side -- the tty gate below is a no-op
PROMPT_DRAIN_SECS=0.2  # an escape sequence's bytes arrive together; 0.2 s is ample

require_interactive() {   # require_interactive <what-needs-it> [advice]
    if [ -n "$PROMPT_IN_FD" ] && [ -n "$PROMPT_OUT_FD" ]; then return 0; fi
    # exec with only redirections fails without killing the shell; its stderr
    # names the device.
    if exec 3<>"$PROMPT_TTY" && [ -t 3 ]; then
        PROMPT_IN_FD=3; PROMPT_OUT_FD=3; PROMPT_OPENED=1
        return 0
    fi
    die "$1 needs a terminal; ${2:-use -r for unattended runs}"
}

# Best effort, for prompts that have a default on unattended runs (-r/-n).
try_interactive() {
    if [ -n "$PROMPT_IN_FD" ] && [ -n "$PROMPT_OUT_FD" ]; then return 0; fi
    if exec 3<>"$PROMPT_TTY" && [ -t 3 ]; then
        PROMPT_IN_FD=3; PROMPT_OUT_FD=3; PROMPT_OPENED=1
        return 0
    fi
    return 1
}

# Hand the run phase back exactly the world it has today: no child inherits a
# readable terminal fd behind the transport's /dev/null-ed stdin.
close_interactive() {
    [ "$PROMPT_OPENED" -eq 1 ] || return 0
    exec 3<&-
    PROMPT_OPENED=0; PROMPT_IN_FD=""; PROMPT_OUT_FD=""
}

prompt_say()  { printf '%s'   "$*" >&"$PROMPT_OUT_FD"; }
prompt_line() { printf '%s\n' "$*" >&"$PROMPT_OUT_FD"; }

# 0 when ESC starts a sequence (another byte within PROMPT_DRAIN_SECS); the
# rest is swallowed so the next prompt does not read it as keys.
prompt_drain_escape() {
    local c rc=1
    if IFS= read -r -s -n 1 -t "$PROMPT_DRAIN_SECS" c <&"$PROMPT_IN_FD"; then
        rc=0
        while IFS= read -r -s -n 1 -t "$PROMPT_DRAIN_SECS" c <&"$PROMPT_IN_FD"; do :; done
    fi
    return $rc
}

# Sets PROMPT_KEY to enter|space|esc|escseq|none|<char>; 0 waits forever (read
# -t 0 means something else). IFS= keeps space apart from Enter, -r keeps \.
prompt_key() {   # prompt_key <timeout-seconds|0>
    local key rc
    if [ "$1" -gt 0 ]; then
        IFS= read -r -s -n 1 -t "$1" key <&"$PROMPT_IN_FD"; rc=$?
    else
        IFS= read -r -s -n 1 key <&"$PROMPT_IN_FD"; rc=$?
    fi
    # 3.2 returns 1 for both timeout and EOF; 4+ returns >128 for timeout.
    # Only zero/nonzero is branched on, so the contract holds on both.
    if [ "$rc" -ne 0 ]; then PROMPT_KEY=none; return 1; fi
    case $key in
        '')      PROMPT_KEY=enter ;;
        ' ')     PROMPT_KEY=space ;;
        $'\033') if prompt_drain_escape; then PROMPT_KEY=escseq
                 else PROMPT_KEY=esc; fi ;;
        *)       PROMPT_KEY=$key ;;
    esac
    return 0
}

# Enter/y/space yes, Esc/n no; any other key or none takes the default, so
# there is no re-prompt loop. Returns 0 for yes.
confirm_timed() {   # confirm_timed <secs> <yes|no> <message>
    local secs=$1 default=$2 msg=$3 answer
    prompt_say "$msg [Enter/y = yes, Esc/n = no] (${secs}s -> $default) "
    prompt_key "$secs"
    case "$PROMPT_KEY" in
        enter|space|y|Y) answer=yes ;;
        esc|n|N)         answer=no  ;;
        *)               answer=$default ;;
    esac
    prompt_line "$answer"
    log "$msg $answer"
    [ "$answer" = yes ]
}

# Untimed: only y means yes; Enter takes the no the prompt shows.
confirm_explicit() {   # confirm_explicit <message>
    local answer=no
    prompt_say "$1 [y/N] "
    if prompt_key 0; then
        case "$PROMPT_KEY" in (y|Y) answer=yes ;; esac
    fi
    prompt_line "$answer"
    log "$1 $answer"
    [ "$answer" = yes ]
}

# Only y means yes; EOF (the terminal went away) dies rather than answer.
confirm_destructive() {   # confirm_destructive <message>
    prompt_say "$1 [y/N] "
    prompt_key 0 || { prompt_line ""; die "prompt input closed while waiting for an answer"; }
    case "$PROMPT_KEY" in
        y|Y) prompt_line yes; log "$1 yes"; return 0 ;;
        *)   prompt_line no;  log "$1 no";  return 1 ;;
    esac
}

# The value is a command (code -w): word-split, only the first word checked.
resolve_editor() {
    EDITOR_CMD=${VISUAL:-${EDITOR:-vi}}
    set -- $EDITOR_CMD
    [ $# -gt 0 ] || die "\$VISUAL/\$EDITOR is set but empty"
    [ -n "$(command -v "$1")" ] || die "editor not found: $1 (from \$VISUAL/\$EDITOR)"
}

# All three fds go to the terminal: stdout may be a pipe.
edit_jobfile() {   # edit_jobfile <path>
    log "editing $1 with $EDITOR_CMD"
    $EDITOR_CMD "$1" <&"$PROMPT_IN_FD" >&"$PROMPT_OUT_FD" 2>&"$PROMPT_OUT_FD" \
        || die "editor exited $? on $1 -- nothing has been run"
}
