#!/usr/bin/env bash
#
# wekatester - performance test a network/parallel filesystem with distributed fio
#
# Shell rewrite. Orchestration uses the system OpenSSH binary, so agent
# forwarding, certificates, ProxyJump, and ~/.ssh/config behave exactly as
# they do for interactive ssh. Connections are multiplexed over ControlMaster
# sockets: one TCP+auth handshake per host for the whole run. fio's results
# are read with awk; -a's calibration planner and tuner are python3 (stdlib
# only). No installable dependencies. It runs on a Linux controller with
# bash 4.4 or later (Frank, 2026-10-06).
#
# With no server on the command line the same orchestration runs against the
# local host with the transport swapped for direct execution (see run_host):
# fio still runs client/server, over loopback, so no sshd is needed at all.
#
# All transient staging (jobfiles, control sockets, remote jobfile copies,
# fio pidfiles) lives in tmpfs (/dev/shm), never on disk. The only files
# written to disk are the results_*.json outputs in the output directory
# (./results by default, -o/--output to choose another).

# Checked before anything else is read: an older bash would otherwise stop
# on syntax it does not know, with a message that names neither.
bash_floor_ok() {   # bash_floor_ok <major> <minor>: 4.4 or later
    [ "$1" -gt 4 ] || { [ "$1" -eq 4 ] && [ "$2" -ge 4 ]; }
}
bash_floor_ok "${BASH_VERSINFO[0]:-0}" "${BASH_VERSINFO[1]:-0}" || {
    echo "wekatester needs bash 4.4 or later; this is ${BASH_VERSION:-not bash}" >&2
    exit 1
}

VERSION="2026-10-06"

# --- defaults ----------------------------------------------------------------
DIRECTORY="/mnt/weka"           # target directory on the workers for test files
WORKLOAD="default"              # workload definition dir, a subdir of fio-jobfiles
FIO_BIN="/usr/bin/fio"          # fio binary on the workers
OUTPUT_DIR="results"            # local directory for the run bundles
DIRECTORY_EXPLICIT=0            # -d was given (CLI beats a host file's dir)
TARGETS=0                       # -t given: a host file is in play
TARGETS_PATH=""                 # -t's explicit path ("" = bare -t, resolve later)
TARGETS_FILE=""                 # the resolved host file actually in use
ENGINE=""                       # -e: force this fio ioengine everywhere
DURATION=""                     # -x: one runtime (seconds) for every measured job
RUN_STAMP=""                    # <date>-<time> of this run, set at run start
RUN_DIR=""                      # $OUTPUT_DIR/$RUN_STAMP: results, log, jobfiles
VERBOSITY=0
SUMMARIZE_FILE=""               # -s: just summarize an existing results file
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# -w was named on the command line rather than defaulted. The customize
# workflow needs the distinction: re-copying -w's jobfiles over an existing
# custom set destroys edits, so it may only happen when the operator actually
# asked for that workload.
WORKLOAD_EXPLICIT=0

# Run-shape flags.
FAST_TRACK=0        # -r: no prompts, no editors -- create what is needed and run
DRY_RUN=0           # -n: create/generate and print what would run; execute nothing
REGEN_LAYOUT=0      # -g: force regeneration of existing layout jobfiles
UNLINK=0            # -u: remove the workload's data files after the last job
CAL_UNLINK_PENDING=0   # calibrate under -u: cal_remove_dataset runs after the last job
GROUP_FILE=""       # this run's filesystem-group file in every destination (collect_fs_groups)
BULK=0              # -b: every latency test also runs at 1MiB, as its own test
LINE_RATE_GBPS=""   # --line-rate: every client's dataplane line rate in Gb/s,
                    # in place of what ethtool reports (a cloud VF says 100 Gb/s
                    # on a 16 Gb/s instance) or when nothing can report it

# -C/--customize: copy a workload set, edit it, run it.
CUSTOMIZE=0
CUSTOM_SET=""       # the set named by an attached value or a consumed bare token
# A bare -C leaves its following bare token in HOSTS and only remembers it here:
# it could be a client or a set name, and preflight is what tells them apart.
C_CANDIDATE=""
SET_DIR_OVERRIDE="" # the resolved custom set dir; stage_jobfiles runs it instead of -w
TEMP_SET=0          # 1 = the set is a <date>-<time> temp dir
TEMP_REMOVE=0       # 1 = operator chose not to keep it; removed after a clean run
# The sets distributed with wekatester: -C never edits these in place, only
# copies of them. Anything else under fio-jobfiles is a custom set.
SHIPPED_SETS="default mixed 2x400Gb wekawithin smoke"

# remote hosts are Linux: /dev/shm is guaranteed tmpfs.
# The override is namespaced on purpose. This path is what cleanup feeds to
# `rm -rf` on the master and on every worker, so honouring a bare $TARGET_DIR --
# a common variable in build and CI environments -- would let a stray export
# silently point those deletions somewhere else. Test plumbing only: the suite
# sets it to exercise the real staging path without a worker.
TARGET_DIR="${WEKATESTER_TARGET_DIR:-/dev/shm/fio-jobfiles}"   # staging dir on the master
FIO_PIDFILE="/dev/shm/wekatester-fio.pid"
FIO_PORT=8765                           # fio --server listen port

# local staging: tmpfs, which every Linux controller has (the suite, run on a
# development Mac, points WEKATESTER_STAGE_BASE elsewhere)
STAGE_BASE=${WEKATESTER_STAGE_BASE:-/dev/shm}

# BatchMode: fail cleanly instead of hanging on an interactive prompt.
# ControlMaster opts live in CONTROL_OPTS (set in main once the socket dir
# exists); they are applied per host, because a host reached over a
# pre-existing user-owned master must NOT get our ControlPath.
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=10"
CONTROL_OPTS=""
CTRL_DIR=""   # the ssh master sockets' directory (make_ctrl_dir)

# Credentials to try against every client, first success per client wins:
# pre-existing masters, then plain defaults (agent/ssh_config), then each -i
# key, then each -p password -- keys before passwords, each in the order
# given. -l is gone: the login travels with its credential.
IDENT_RAW=()        # -i entries as typed ([login:]key, comma lists, repeatable)
IDENT_LOGINS=()     # validated split of IDENT_RAW ("" = ssh's default user)
IDENT_KEYS=()
PW_COUNT=0          # -p [n]: how many login/password pairs to prompt for
PW_LOGINS=()        # prompted pairs ("" login = ssh's default user)
PW_SECRETS=()       # passwords live only here and in the per-attempt fifos
AUTH_DIR=""          # $WORK_DIR/auth: per-host winning-credential state

# Local mode: no server on the command line, so the "cluster" is this host and
# the transport below executes directly instead of over ssh. Set by
# resolve_local_mode() in the run path only.
LOCAL_MODE=0
LOCAL_NAME=""      # local mode: the short hostname data files are prefixed with (host_name)

# Auto mode: derive system-specific fio options
AUTO_LEVEL=""    # "", "safe", "max", "cal", or "brutal"
IGNORE_CAPACITY=0   # 1: run even when the workload does not fit at $DIRECTORY

# --- logging -----------------------------------------------------------------
log()   { local ts; printf -v ts '%(%H:%M:%S)T' -1; echo "$ts $*"; }
debug() { [ "$VERBOSITY" -ge 1 ] && log "DEBUG: $*"; return 0; }
die()   { log "ERROR: $*" >&2; exit 1; }

# A warning raised before the run log exists (the mount guard runs long
# before start_run_log) would otherwise be console-only. It is kept and
# replayed once the log is open, so the bundle carries every caveat that
# applies to its numbers -- a reader of the archive never sees the console.
# Kept once per distinct message (the mount guard runs twice under -C and
# says the same thing both times), and replayed into the log FILE only: the
# console already saw every warning live, and after start_run_log stderr is
# tee'd to both, so a replay on stderr showed each warning twice more.
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
    # gated on the run DIRECTORY, not the file: start_run_log's tees open
    # the log in the background and may not have created it yet when this
    # runs -- >> creates it, and every writer appends, so nothing clobbers
    [ ${#PRERUN_WARNINGS[@]} -gt 0 ] && [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || return 0
    for w in "${PRERUN_WARNINGS[@]}"; do
        log "WARNING (before the run log opened): $w" >> "$f"
    done
}

# --- transport ----------------------------------------------------------------
# The only two places that know whether a host is remote. Every phase --
# preflight, the mount guard, the fio daemon lifecycle, the port check, the
# probe, staging, the run, cleanup -- goes through these, so local mode is a
# transport swap and nothing else: fio still runs in client/server mode, just
# over loopback, so every guard applies and the results JSON keeps its shape.
#
# Invariant for callers: a command string must be POSIX sh, or wrap itself in
# `bash -c`. Locally it runs under bash; remotely it runs under the worker's
# login shell, which is not necessarily bash. verify_fio_ports is the exemplar
# -- it needs /dev/tcp, a bash feature, so it carries its own `bash -c`.

# Run a command on a host. Local mode executes directly -- no sshd needed.
# Both branches take stdin from /dev/null (ssh -n, and an explicit redirect
# locally). Without it a foreground call inherits and can consume the script's
# own stdin, and so can a backgrounded one whenever job control is in effect
# (bash only auto-redirects async commands to /dev/null when it is not). The
# invariant has to hold on both sides of the branch or it is not an invariant.
# Per-host transport delta, written by establish_connections. A host that
# was reached over a pre-existing (user-owned) master gets NO control opts:
# ssh's own config routes it through that master, and cleanup never touches
# sockets it did not create. Every other host rides a master in our socket
# dir, addressed (via %C) with the same User= its winning credential used.
# No AUTH_DIR (unit tests, or a path that never established) means no delta.
host_ssh_opts() {   # host_ssh_opts <host>
    if [ -n "$AUTH_DIR" ] && [ -f "$AUTH_DIR/$1.external" ]; then
        return 0
    fi
    printf '%s' "$CONTROL_OPTS"
    if [ -n "$AUTH_DIR" ] && [ -f "$AUTH_DIR/$1.user" ]; then
        local u=""
        IFS= read -r u < "$AUTH_DIR/$1.user" || :
        printf ' -o User=%s' "$u"
    fi
}

run_host() {   # run_host <host> <command-string>
    if [ "$LOCAL_MODE" -eq 1 ]; then
        bash -c "$2" </dev/null
    else
        ssh -n $SSH_OPTS $(host_ssh_opts "$1") "$1" "$2"
    fi
}

# Copy files to the master's staging area. The destination directory is the
# last argument, exactly as cp expects it. Remotely, one tar stream over the
# master's connection: scp waits on the network once per file and per
# directory, and a fleet's jobfiles are a dozen per host. The sources share
# one parent directory -- every caller copies a directory's entries.
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
    (
        set -o pipefail
        tar -C "$parent" -cf - -- "${names[@]}" \
            | ssh $SSH_OPTS $(host_ssh_opts "$MASTER") "$MASTER" "mkdir -p '$dst' && tar -xf - -C '$dst'"
    )
}

# Copy files to ONE worker's staging area (the master gets everything through
# copy_to_master; this is for the rare case a worker needs its own copy --
# the failure postmortem parses a jobfile with the worker's own fio).
copy_to_host() {   # copy_to_host <host> <src>... <dst-dir-on-host>
    local host=$1; shift
    if [ "$LOCAL_MODE" -eq 1 ]; then
        cp -R "$@"
    else
        scp $SSH_OPTS $(host_ssh_opts "$host") -q -r "${@:1:$#-1}" "$host:${!#}"
    fi
}

# No server on the command line: benchmark this host instead of refusing to run.
# fio still drives the whole thing in client/server mode, over loopback, so no
# phase below needs a second code path -- only the transport changes.
resolve_local_mode() {
    [ ${#HOSTS[@]} -eq 0 ] || return 0
    LOCAL_MODE=1
    HOSTS=(localhost)
    MASTER=localhost
    LOCAL_NAME=$(local_short_hostname)
    log "no servers given: running on the local host (no ssh required)"
    debug "local mode: data files are prefixed ${LOCAL_NAME:-localhost}. (host_name)"
}

# Split every -i entry into (login, keyfile) pairs, kept in the order given.
# The FIRST colon separates login from path; no colon means ssh's default
# user with that key. Key paths are validated now: left to ssh, a typo
# surfaces as an auth failure on every host at once, which reads like a
# cluster problem instead of a typo. Everything becomes `-o` forms later
# because that is the one spelling BOTH ssh and scp accept.
#
# Called from main in the run path only, after resolve_local_mode has decided
# whether ssh is involved at all and before anything can touch a host.
validate_credentials() {
    local raw entry login key
    if [ "$LOCAL_MODE" -eq 1 ]; then
        # No ssh in local mode, so the flags are accepted and ignored rather
        # than treated as a usage error -- same shape as --ignore-capacity
        # outside auto mode.
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
# The transport /dev/null's stdin for every child (see run_host), and a run is
# commonly piped ('wekatester ... | tee run.log'), so neither fd 0 nor fd 1 is a
# reliable answer to "is a human here". The controlling terminal is: /dev/tty is
# the same device whether or not stdin/stdout were redirected. One rw fd carries
# both directions, so the prompt stays visible under a pipe and the run log on
# stdout is never polluted with UI. read -s must consume via fd redirection
# (read -u echoes), and partial -n input is DISCARDED on timeout, so the
# escape drain reads one byte at a time.
PROMPT_TTY="${WEKATESTER_PROMPT_TTY:-/dev/tty}"   # test plumbing only, namespaced
PROMPT_OPENED=0      # 1 = we own fd 3 and must close it
PROMPT_IN_FD=""      # read side  -- the suite presets these two and then
PROMPT_OUT_FD=""     # write side -- the tty gate below is a no-op
PROMPT_DRAIN_SECS=0.2  # an escape sequence's bytes arrive together; 0.2 s is ample

require_interactive() {   # require_interactive <what-needs-it> [advice]
    if [ -n "$PROMPT_IN_FD" ] && [ -n "$PROMPT_OUT_FD" ]; then return 0; fi
    # exec with only redirections reports failure without killing the shell
    # (non-posix bash), so the open is testable. Its own stderr line names the
    # device and reason; leaving it visible is the point.
    if exec 3<>"$PROMPT_TTY" && [ -t 3 ]; then
        PROMPT_IN_FD=3; PROMPT_OUT_FD=3; PROMPT_OPENED=1
        return 0
    fi
    die "$1 needs a terminal; ${2:-use -r for unattended runs}"
}

# Best-effort variant: open the terminal if there is one, say so if not --
# for prompts that have a sane default on unattended runs (-r/-n), where
# require_interactive's die would be wrong and writing to the unopened
# prompt fds is a bad-fd error (seen live).
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

# ESC arrived. Arrow/function keys send ESC plus more bytes; a bare Esc sends
# ESC alone. Returns 0 (it was a sequence) when another byte follows within
# PROMPT_DRAIN_SECS, and swallows the remainder either way -- leftover bytes
# would otherwise be delivered as keypresses at the NEXT prompt.
prompt_drain_escape() {
    local c rc=1
    if IFS= read -r -s -n 1 -t "$PROMPT_DRAIN_SECS" c <&"$PROMPT_IN_FD"; then
        rc=0
        while IFS= read -r -s -n 1 -t "$PROMPT_DRAIN_SECS" c <&"$PROMPT_IN_FD"; do :; done
    fi
    return $rc
}

# Read exactly one keypress. $1 = whole-second timeout, 0 = wait forever
# (which means: omit -t entirely -- `read -t 0` means something else and
# something different again across bash versions). Sets PROMPT_KEY to
# enter|space|esc|escseq|none|<char>. Returns 0 when a key was read.
# IFS= and -r are load-bearing: without IFS= a space reads as the empty string
# (indistinguishable from Enter); without -r a backslash swallows the next key.
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

# Enter / y / space = yes; Esc / n = no; anything else, or no key at all, takes
# the default -- an unrecognized key resolving like the timeout means there is
# no re-prompt loop to get stuck in. The resolved answer is echoed on the tty
# (the operator sees what registered) and logged on stdout (the run record
# shows what was chosen). Returns 0 for yes, 1 for no.
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

# An untimed question whose yes changes something -- a directory created on
# every host, a run past the capacity check, a new host file -- takes a y.
# Enter, space and every other key take the no the prompt shows: under
# confirm_timed 0 no, Enter answered yes while the screen said "(0s -> no)".
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

# The recopy that throws away existing edits gets no timeout and no forgiving
# default: only 'y' means yes, Enter takes the [y/N] default. Without -t a
# failed read means EOF -- the terminal went away mid-flow; die rather than
# answer for the operator.
confirm_destructive() {   # confirm_destructive <message>
    prompt_say "$1 [y/N] "
    prompt_key 0 || { prompt_line ""; die "prompt input closed while waiting for an answer"; }
    case "$PROMPT_KEY" in
        y|Y) prompt_line yes; log "$1 yes"; return 0 ;;
        *)   prompt_line no;  log "$1 no";  return 1 ;;
    esac
}

# $VISUAL, then $EDITOR, then vi -- the order every editor-delegating tool
# uses. The value is a command, not a path ('code -w', 'emacs -nw'), so it is
# deliberately word-split and only the first word is checked for existence.
resolve_editor() {
    EDITOR_CMD=${VISUAL:-${EDITOR:-vi}}
    set -- $EDITOR_CMD
    [ $# -gt 0 ] || die "\$VISUAL/\$EDITOR is set but empty"
    command -v "$1" >/dev/null || die "editor not found: $1 (from \$VISUAL/\$EDITOR)"
}

# Give the editor the terminal on all three fds: the script's own stdin may be
# closed and stdout piped, and a full-screen editor on a pipe either refuses to
# start or scribbles control codes into the log. This is a handoff, not a
# suppression -- the editor's stderr lands on the operator's screen.
edit_jobfile() {   # edit_jobfile <path>
    log "editing $1 with $EDITOR_CMD"
    $EDITOR_CMD "$1" <&"$PROMPT_IN_FD" >&"$PROMPT_OUT_FD" 2>&"$PROMPT_OUT_FD" \
        || die "editor exited $? on $1 -- nothing has been run"
}

usage() {
    cat <<EOF
usage: ${0##*/} [-d directory] [-w workload] [-f fio_bin] [-o output_dir]
                  [-e engine] [-a [safe|max|cal|brutal[:secs]]] [--ignore-capacity]
                  [--line-rate Gb/s]
                  [-i [login:]keyfile[,...]] [-p [n]] [-t [hostfile]]
                  [-x secs] [-C[set]] [-b] [-r] [-n] [-g] [-u] [-v] [-h]
                  [--] [server ...]
       ${0##*/} -s results.json
       ${0##*/} --version

Basic performance test of a network/parallel filesystem (distributed fio).

Option names are case-insensitive (-C is -c, --AUTO is --auto); the values you
give them are not (-Cmyset names myset, never MYSET). A value may be attached
or separate: -w smoke, -wsmoke, -w=smoke and --auto=max all work, and
attaching is the way to pass a value that starts with a dash.

  -d directory   target directory on the workers for test files (default: $DIRECTORY);
                 created on request when it is missing under a wekafs mount
  -w workload    workload definition directory, a subdir of fio-jobfiles (default: $WORKLOAD)
  -f fio_bin     fio binary on the workers (default: $FIO_BIN)
  -o, --output dir        each run lands here as <date>-<time>.tgz: fio JSON
                          results, run log, staged jobfiles (default: $OUTPUT_DIR)
  -e, --engine eng        force this fio ioengine on every staged jobfile,
                          overriding the jobfiles and auto tuning
  -a, --auto [safe|max|cal|brutal[:secs]]
                          measure the clients and run what they do best
                          (default level when omitted: max): clients are
                          grouped into hardware shapes, one client of each
                          is measured alone; N = its usable physical cores
                          safe: numjobs N/2, N, 2N at iodepth 1, nrfiles 1
                          max: numjobs N/2, N, 2N at the deepest iodepth and
                          nrfiles cal has chosen (bandwidth 16 and 4, iops
                          32 and 2)
                          cal: walk numjobs to 4N, iodepth and nrfiles --
                          bandwidth toward NIC line rate, the most iops
                          brutal: the cal search with no early stops --
                          every rung of every ladder is measured. Slow
                          every level: the ioengine, and latency at N jobs
                          over nrfiles beside a one-job test
                          :secs sets the measured seconds per cell (default
                          15 for safe and max, 30 for cal and brutal); it
                          does not change how long the measured jobs run --
                          that is -x/--duration
  --line-rate Gb/s        every client's dataplane line rate, for the -a
                          bandwidth target, in place of what ethtool reports:
                          a cloud VF can report 100 Gb/s on a 16 Gb/s
                          instance, and without the weka CLI nothing reports it
  --ignore-capacity       when the workload needs more space than is available,
                          ask (no timeout) and run anyway instead of aborting
  -i, --identity [login:]keyfile[,...]
                          ssh key(s) to try, each optionally bound to a login;
                          repeatable, tried in the order given
  -p, --password [n]      prompt for n (default 1) login/password pairs, tried
                          after the keys; no sshpass involved
                          Every credential is tried against every worker --
                          existing ssh sessions and plain defaults first, then
                          keys, then passwords -- and per worker the first
                          success wins
  -t, --targets [file]    per-host settings from a CSV host file: login,
                          ioengine, cpus_allowed, destination dir, per-test
                          geometry. Bare -t = the set's own hostlist.csv,
                          else ./hostlist.csv. CLI flags beat the file; the
                          file beats the jobfiles and the tuner
  -C[set], --customize[=set]
                          copy a workload set, edit its host file (jobfiles
                          on request), then run it;
                          needs a terminal unless -r or -n is given. With no
                          attached value the set may be the next bare token
  -b, --bulk     run every latency test at 1MiB blocks too, as a separate
                 test listed on its own (under -a the 1MiB test is
                 calibrated on its own)
  -r             fast track: no prompts and no editors -- create whatever is
                 needed and run; a wekafs destination that is not mounted
                 forcedirect is a warning instead of a stop
  -n             dry run: create/generate, print the files and the run details;
                 no measured job runs, but a missing -d is created and, with
                 -a/-t/-e, the ioengines are proven with small fio jobs
  -g             force regeneration of existing layout jobfiles
  -x, --duration secs     run every measured job for this many seconds
                          (time_based); layout and unlink keep their own timing
  -u, --unlink   remove the workload's data files from -d after the last job
                 that uses them (a failed run keeps them for the rerun), and
                 the calibration scratch files, which are otherwise kept
                 so the next calibration can reuse them
  -s file        summarize an existing results .json -- or every job in a run
                 bundle .tgz, straight from the archive -- and exit
  -v             increase output verbosity (repeatable: -v, -vv, -vvv)
  --version      display version number and exit
  -h, --help     show this help and exit
  --             everything after this is a server name

With no server given, the test runs on the local host -- no ssh required.
EOF
}

# --- argument parsing ----------------------------------------------------------
# An option's value never starts with a dash: nothing wekatester takes as a
# value looks like that, but a mistyped flag sequence does (-f -g quietly made
# "-g" the fio binary in the field, and preflight then hunted for a binary
# named -g). Refusing here turns that into a one-line answer.
need_arg() {   # need_arg <option-as-typed> <argc> <next-token>
    [ "$2" -ge 2 ] || { usage >&2; die "option $1 requires an argument"; }
    case "$3" in
        -?*) usage >&2; die "option $1 requires an argument, got '$3' (looks like another option)" ;;
    esac
}

# A short option's attached value: -wsmoke and -w=smoke both mean smoke (one
# leading = is stripped, so the GNU-style spelling works too). Attaching is
# also the escape hatch for a value that genuinely starts with a dash, which
# need_arg refuses in detached form. Empty after stripping dies: -w= looks
# deliberate but names nothing. Sets OPT_VAL rather than printing so the die
# fires in the parsing shell, not inside a command substitution.
OPT_VAL=""
opt_val() {   # opt_val <normalized-token> <canonical-option>
    OPT_VAL=${1#"$2"}
    OPT_VAL=${OPT_VAL#=}
    [ -n "$OPT_VAL" ] || { usage >&2; die "option $2 requires a value"; }
}

# Lowercasing under the C locale: a Turkish one would map I to a dotless i.
lower() { local LC_ALL=C; printf '%s' "${1,,}"; }

# Case-fold an option token's NAME and nothing else, so the `case` below can
# stay lowercase-only while -D, --AUTO=MAX and -CMySet all land on the right
# arm. What must survive untouched is everything the user chose: a long
# option's =value, and a short option's attached value.
#
#   --LOGIN=Ubuntu -> --login=Ubuntu     (name folded, value kept)
#   -CMySet        -> -cMySet            (only the leading -C folded)
#   -VV / -vV      -> -vv                (a run of v's is all name)
normalize_opt() {   # normalize_opt <token>
    case "$1" in
        --)      printf '%s' "$1" ;;
        --*=*)   printf '%s=%s' "$(lower "${1%%=*}")" "${1#*=}" ;;
        --*)     lower "$1" ;;
        # -v runs are name all the way down, so fold the whole token. Anything
        # else keeps its tail: that tail is an attached value.
        -[vV][vV]*) lower "$1" ;;
        -?*)     printf '%s%s' "$(lower "${1:0:2}")" "${1:2}" ;;
        *)       printf '%s' "$1" ;;
    esac
}

# --- the shared python layer -------------------------------------------------
# One definition of the direction rule, the host-file schema, the slot
# tie-break, and the small helpers every embedded python used to carry its
# own copy of. pyrun() prepends this to the script on stdin, so a consumer
# just uses the names. Four copies of the rw= rule in two languages had
# already drifted once (the ':' modifier strip); this is where it lives now.
WEKA_PYLIB=$(cat <<'PYLIBEOF'
#@include py/lib.py
PYLIBEOF
)

pyrun() {   # pyrun <args...> -- python script on stdin, WEKA_PYLIB prepended
    { printf '%s\n' "$WEKA_PYLIB"; cat; } | python3 - "$@"
}

# --- the shared awk layer ----------------------------------------------------
# What WEKA_PYLIB is to the embedded python, WEKA_AWK is to every awk that
# took a python's place: each rule both need, spelled once per language.
# Where lib.py keeps its own copy because the remaining python still uses
# it, the suite holds the two to the same answers ("awk and python agree").
# awkrun prepends it, and the schema and marker constants below, to one
# program. Conventions every program keeps:
#   - BEGIN only, its data on ARGV: -v would put a path or a value through
#     awk's escape processing, and a BEGIN-only program never reads ARGV as
#     files. awk_fail exits 1 from anywhere, which only BEGIN makes safe.
#   - LC_ALL=C: byte order is the code-point order python sorted by.
#   - files are read whole by readlines, python's universal newlines (\n,
#     \r\n, a lone \r), and written back as python did: lines joined by \n,
#     one at the end.
#   - a byte count is printed with %.0f: print and %d round or clip past
#     2^31 on some awks.
#   - portable to gawk and mawk alike: a comparison inside a
#     print list is parenthesized, a function has at most 50 parameters and
#     locals, and A[k] = (k in A) ? ... is never written (mawk creates A[k]
#     before it tests).
#
# The host-file schema: the host, four identity columns, then eight
# nj/fs/nr/qd geometry slots, one per (type, direction). The 1MiB latency
# slots come LAST, so a host file written before they existed still lines up
# column for column. lib.py spells the same lists; the suite keeps them equal.
GEOM_SLOTS="bw_r bw_w lat_r lat_w iops_r iops_w lat1m_r lat1m_w"
GEOM_NAMES="bandwidthR bandwidthW latencyR latencyW iopsR iopsW latency1mR latency1mW"
# The first line of a latency test's one-job twin (-a cal/brutal), lib.py's
# FLOOR_MARKER: stage_floor_twins writes it, the tuner and the writeback
# read it.
FLOOR_MARKER="# wekatester-floor:"
# lib.py's ENGINE_ORDER: the engine a tie goes to, best first, and the one a
# set that names none gets.
ENGINE_ORDER="io_uring libaio psync"
# lib.py's LINE_RATE_SLOTS: the slots --line-rate measures again even when
# the host file carries them -- a recorded answer does not say which line
# rate it stopped at
LINE_RATE_SLOTS="bw_r bw_w"

IFS= read -r -d '' WEKA_AWK <<'AWKLIB' || :
function awk_fail(msg) { print "ERROR: " msg > "/dev/stderr"; exit 1 }

# python's str.strip() and str.split() whitespace, its ASCII part. The
# common cases skip the regex: the probe readers run these on every line
# of every host's probe.
function strip(s,    c) {
    c = substr(s, 1, 1)
    if (c != "" && index(" \t\n\013\014\r\034\035\036\037", c)) sub(/^[ \t\n\013\014\r\034\035\036\037]+/, "", s)
    c = substr(s, length(s), 1)
    if (c != "" && index(" \t\n\013\014\r\034\035\036\037", c)) sub(/[ \t\n\013\014\r\034\035\036\037]+$/, "", s)
    return s
}
function rstrip(s,    c) {
    c = substr(s, length(s), 1)
    if (c != "" && index(" \t\n\013\014\r\034\035\036\037", c)) sub(/[ \t\n\013\014\r\034\035\036\037]+$/, "", s)
    return s
}
function pysplit(s, F) {   # str.split(): F[1..n]
    # only space, tab and newline: what awk splits on by itself
    if (s !~ /[\013\014\r\034\035\036\037]/) return split(s, F, " ")
    split("", F)
    s = strip(s)
    return s == "" ? 0 : split(s, F, /[ \t\n\013\014\r\034\035\036\037]+/)
}
# int(): the number, or "" where python raises ValueError
function py_int(s) {
    if (s ~ /^[0-9]+$/) return s + 0
    s = strip(s)
    if (s !~ /^[+-]?[0-9]+(_[0-9]+)*$/) return ""
    gsub(/_/, "", s)
    return s + 0 + 0
}
# str.split(sep) for a one-character sep: an empty string is one empty
# field, and a newline in a quoted host-file cell is no separator
function lsplit(s, A, sep,    n, i) {
    split("", A); n = 0
    while ((i = index(s, sep)) > 0) { A[++n] = substr(s, 1, i - 1); s = substr(s, i + 1) }
    A[++n] = s
    return n
}
function replace_all(s, from, to,    i, out) {   # str.replace
    out = ""
    while ((i = index(s, from)) > 0) {
        out = out substr(s, 1, i - 1) to
        s = substr(s, i + length(from))
    }
    return out s
}
function vars_to_glob(s) {   # re.sub(r"\$\w+", "*", s)
    gsub(/\$[A-Za-z0-9_]+/, "*", s)
    return s
}
function count_char(s, c) { return gsub(c, "", s) }
function dirname(p,    head) {   # os.path.dirname
    if (!match(p, /\/[^\/]*$/)) return ""
    head = substr(p, 1, RSTART)
    if (head !~ /^\/+$/) sub(/\/+$/, "", head)
    return head
}
function path_join(a, b) {   # os.path.join(a, b)
    if (substr(b, 1, 1) == "/" || a == "") return b
    return a (substr(a, length(a)) == "/" ? "" : "/") b
}
function squote(s) { return "\047" s "\047" }
# The commands that delete the dataset files <pattern> names under <hd>:
# every $var a wildcard, find bounded at the pattern's own depth so nothing
# outside the grid is touched, then the directories that leaves empty.
function dataset_remove_cmd(pattern, hd,    glob, depth, cmd) {
    glob = vars_to_glob(pattern)
    depth = 1 + count_char(glob, "/")
    cmd = sprintf("find %s -maxdepth %d -type f -path %s -delete", squote(hd), depth, squote(hd "/" glob))
    if (index(glob, "/"))
        cmd = cmd sprintf(" && find %s -maxdepth %d -type d -path %s -empty -delete", squote(hd), depth - 1, squote(hd "/" substr(glob, 1, match(glob, /\/[^\/]*$/) - 1)))
    return cmd
}

# open(path).read().splitlines() into L[1..n]; -1 when it cannot be read
function readlines(path, L,    n, r, line, m, k, parts) {
    split("", L); n = 0
    while ((r = (getline line < path)) > 0) {
        if (index(line, "\r")) {
            sub(/\r$/, "", line)
            m = split(line, parts, "\r")
            if (m == 0) L[++n] = ""
            for (k = 1; k <= m; k++) L[++n] = parts[k]
        } else
            L[++n] = line
    }
    close(path)
    return r < 0 ? -1 : n
}
function writelines(path, L, n,    i) {   # "\n".join(L) + "\n"
    if (n == 0) printf "\n" > path
    for (i = 1; i <= n; i++) print L[i] > path
    close(path)
}

# A[1..n] sorted in place, numerically or bytewise
function sort_arr(A, n, num,    gap, i, j, t) {
    for (gap = int(n / 2); gap > 0; gap = int(gap / 2))
        for (i = gap + 1; i <= n; i++) {
            t = A[i]
            for (j = i; j > gap && (num ? (A[j - gap] + 0 > t + 0) : (A[j - gap] "" > t "")); j -= gap)
                A[j] = A[j - gap]
            A[j] = t
        }
}

# cpu sets: arrays keyed by cpu number
function set_size(S,    k, n) { n = 0; for (k in S) n++; return n }
function set_any(S,    k) { for (k in S) return 1; return 0 }
function set_sorted(S, A,    k, n, lo, hi, c) {
    split("", A); n = 0; lo = 0; hi = -1
    for (k in S) {
        A[++n] = k + 0
        if (A[n] < lo) lo = A[n]
        if (A[n] > hi) hi = A[n]
    }
    if (n > 8 && lo == 0 && hi < 4 * n + 64) {   # dense, as cpu sets are: count up
        n = 0
        for (c = 0; c <= hi; c++) if (c in S) A[++n] = c
        return n
    }
    sort_arr(A, n, 1)
    return n
}
function join_sorted(S, sep,    A, n, i, out) {   # sep.join(sorted(S))
    n = set_sorted(S, A); out = ""
    for (i = 1; i <= n; i++) out = out (i > 1 ? sep : "") A[i]
    return out
}
function fmt_cpulist(S,    A, n, i, j, out) {   # 0-3,8: runs collapsed
    n = set_sorted(S, A); out = ""
    for (i = 1; i <= n; i = j + 1) {
        for (j = i; j < n && A[j + 1] == A[j] + 1; j++)
            ;
        out = out (out == "" ? "" : ",") (i == j ? A[i] : A[i] "-" A[j])
    }
    return out
}
# lib.py's parse_cpulist: 1, or 0 where it raises ValueError
function parse_cpulist(s, S,    n, P, i, ab, a, b, c) {
    split("", S)
    n = lsplit(s, P, ",")
    for (i = 1; i <= n; i++) {
        if (index(P[i], "-")) {
            if (lsplit(P[i], ab, "-") != 2) return 0
            if ((a = py_int(ab[1])) == "" || (b = py_int(ab[2])) == "") return 0
            for (c = a; c <= b; c++) S[c] = 1
        } else if (P[i] != "") {
            if ((a = py_int(P[i])) == "") return 0
            S[a] = 1
        }
    }
    return 1
}

# --- jobfiles ---
# lib.py's first_value: the first "key=<value>" line's value, up to the
# first blank; "" when none
function first_value(L, n, key,    i, v) {
    for (i = 1; i <= n; i++) {
        if (index(L[i], key "=") != 1) continue
        v = substr(L[i], length(key) + 2)
        if (match(v, /^[^ \t\n\013\014\r\034\035\036\037]+/)) return substr(v, 1, RLENGTH)
    }
    return ""
}
function is_layout_marked(L, n,    i) {   # the layout marker in the first three lines
    for (i = 1; i <= 3 && i <= n; i++)
        if (index(L[i], layout_marker()) == 1) return 1
    return 0
}
# override_variant_key's three cases, on lines held in L: replace every
# key= line; else insert key=value after the first [global]; else create
# [global] at the top. The new line count.
function override_lines(L, n, key, value,    O, i, m, hit, g) {
    m = 0; hit = 0; g = 0
    for (i = 1; i <= n; i++)
        if (index(L[i], key "=") == 1) hit = 1
        else if (!g && index(L[i], "[global]") == 1) g = i
    if (!hit && !g) { O[++m] = "[global]"; O[++m] = key "=" value }
    for (i = 1; i <= n; i++) {
        O[++m] = (hit && index(L[i], key "=") == 1) ? key "=" value : L[i]
        if (!hit && i == g) O[++m] = key "=" value
    }
    split("", L)
    for (i = 1; i <= m; i++) L[i] = O[i]
    return m
}
# The sha256 a generated layout job's marker carries, "" for another line.
# The body it covers is layout_body's.
function marker_sha(line,    p, h) {
    p = layout_marker() " sha256="
    if (index(line, p) != 1) return ""
    h = rstrip(substr(line, length(p) + 1))
    return (length(h) == 64 && h ~ /^[0-9a-f]+$/) ? h : ""
}
function layout_body(L, n,    i, k, out) {   # every non-marker line, trailing blanks off, \n-joined
    out = ""; k = 0
    for (i = 1; i <= n; i++)
        if (index(L[i], layout_marker()) != 1) out = out (k++ ? "\n" : "") rstrip(L[i])
    return out
}
# The most kernel aio events one jobfile sets up at once through libaio:
# every clone of a job reserves its iodepth (io_queue_init), so numjobs x
# iodepth per section (each inherits every [global] above it; a value that
# is not a number counts 0), summed over the sections that run together --
# a stonewall starts a new group -- and the largest group taken. 0 when
# nothing in the file runs libaio.
function libaio_events(L, n,    i, s, p, k, v, G, sec, insec, ng, GS, GN, best) {
    split("", G); split("", sec); insec = 0; ng = 1; GS[1] = 0; GN[1] = 0
    for (i = 1; i <= n + 1; i++) {
        if (i <= n) {
            s = strip(L[i])
            if (s == "" || substr(s, 1, 1) == "#" || substr(s, 1, 1) == ";") continue
            if (s !~ /^\[.+\]$/) {
                if ((p = index(s, "="))) { k = strip(substr(s, 1, p - 1)); v = strip(substr(s, p + 1)) }
                else { k = strip(s); v = "" }
                if (insec) sec[k] = v; else G[k] = v
                continue
            }
        }
        if (insec) {   # a section ends: at the next header, or at the end
            if ((("stonewall" in sec) ? sec["stonewall"] : "0") != "0" && GN[ng] > 0) {
                ng++; GS[ng] = 0; GN[ng] = 0
            }
            if (("ioengine" in sec) && sec["ioengine"] == "libaio") {
                k = ("numjobs" in sec) && sec["numjobs"] != "" ? py_int(sec["numjobs"]) : 1
                v = ("iodepth" in sec) && sec["iodepth"] != "" ? py_int(sec["iodepth"]) : 1
                GS[ng] += (k == "" || v == "") ? 0 : k * v
                GN[ng]++
            }
        }
        if (i > n) break
        insec = strip(substr(s, 2, length(s) - 2)) != "global"
        if (insec) { split("", sec); for (k in G) sec[k] = G[k] }
    }
    best = GS[1]
    for (i = 2; i <= ng; i++) if (GS[i] > best) best = GS[i]
    return best
}

# lib.py's parse_size: "5G", "1.5GiB", "4k" as bytes; "" where it raises
function parse_size(s,    u, m) {
    s = strip(s)
    if (s !~ /^[0-9]+(\.[0-9]+)?[kKmMgGtT]?i?[bB]?$/) return ""
    match(s, /^[0-9]+(\.[0-9]+)?/)
    u = substr(s, RLENGTH + 1, 1)
    m = u == "" ? 0 : index("kmgt", tolower(u))
    return int(substr(s, 1, RLENGTH) * (m ? 2 ^ (10 * m) : 1))
}
# A section header ("[name]", blanks may follow): its name, else ""
function section_name(line,    t) {
    if (line !~ /^\[.+\][ \t\n\013\014\r\034\035\036\037]*$/) return ""
    t = rstrip(line)
    return substr(t, 2, length(t) - 2)
}
function last_section(L, n,    i, s, name) {   # lib.py's last_section
    name = ""
    for (i = 1; i <= n; i++) if ((s = section_name(L[i])) != "") name = s
    return name
}
# Does a "# report <items>" line (whitespace after "report") name <word>?
function report_has(L, n, word,    i, F, k, m) {
    for (i = 1; i <= n; i++) {
        if (!match(L[i], /^#[ \t\n\013\014\r\034\035\036\037]*report[ \t\n\013\014\r\034\035\036\037]/)) continue
        m = pysplit(substr(L[i], RLENGTH + 1), F)
        for (k = 1; k <= m; k++) if (F[k] == word) return 1
    }
    return 0
}
# The value of a "<key>=<value>" line whose key matches the anchored ERE
# <keys>, up to the first blank; "" for any other line
function key_value(line, keys,    v) {
    if (!match(line, "^(" keys ")=[^ \t\n\013\014\r\034\035\036\037]+")) return ""
    v = substr(line, 1, RLENGTH)
    return substr(v, index(v, "=") + 1)
}
# lib.py's job_bs: the block size the file's MEASURED section runs, in
# bytes -- the last job section's bs=/blocksize=, else [global]'s, else 4k;
# a split value ("4k,8k") by its first entry
function job_bs(L, n,    i, name, injob, glob, last, v) {
    glob = ""; last = ""; injob = 0
    for (i = 1; i <= n; i++) {
        if ((name = section_name(L[i])) != "") {
            injob = strip(name) != "global"
            if (injob) last = ""
            continue
        }
        if ((v = key_value(L[i], "bs|blocksize")) == "") continue
        if (injob) last = v; else glob = v
    }
    v = last != "" ? last : glob != "" ? glob : "4k"
    sub(/,.*/, "", v); sub(/:.*/, "", v)
    v = parse_size(v)
    return v == "" ? 4096 : v
}
function lat_kind(L, n) { return job_bs(L, n) >= 1048576 ? "lat1m" : "lat" }
# lib.py's rw_directions and file_directions: every direction the file's
# job sections exercise into D (D["read"], D["write"]), [global]'s rw= the
# fallback for a section without its own; no sections: [global] is the job
function rw_directions(v, D) {
    v = tolower(v); sub(/:.*/, "", v)   # fio's ":<modifier>" is no direction
    if (v == "read" || v == "randread") D["read"] = 1
    else if (v == "write" || v == "randwrite") D["write"] = 1
    else if (v == "rw" || v == "randrw" || v == "readwrite" || v == "randreadwrite") {
        D["read"] = 1; D["write"] = 1
    }
}
function file_directions(L, n, D,    i, name, ns, cur, glob, RW, v) {
    split("", D); glob = ""; ns = 0; cur = 0
    for (i = 1; i <= n; i++) {
        if ((name = section_name(L[i])) != "") {
            if (strip(name) == "global") cur = 0
            else { RW[++ns] = ""; cur = ns }
            continue
        }
        if ((v = key_value(L[i], "rw|readwrite")) == "") continue
        if (cur) RW[cur] = v; else glob = v
    }
    if (!ns) rw_directions(glob, D)
    for (i = 1; i <= ns; i++) rw_directions(RW[i] != "" ? RW[i] : glob, D)
}
# A resolved host-file row (resolve_targets' tab-separated output, split
# into ROW): the 1-based column of a FIELDS key, and its value ("" for "-")
function field_col(key,    S, n, i) {
    if (key == "login") return 2
    if (key == "engine") return 3
    if (key == "cpus") return 4
    if (key == "dir") return 5
    n = split(geom_slots(), S, " ")
    for (i = 1; i <= n; i++)
        if (index(key, S[i] "_") == 1)
            return 6 + 4 * (i - 1) + (index("nj fs nr qd", substr(key, length(S[i]) + 2)) - 1) / 3
    return 0
}
function row_get(ROW, key,    c) {
    c = field_col(key)
    return (c in ROW) && ROW[c] != "-" ? ROW[c] : ""
}
# lib.py's pick_slot: the geometry slot a file takes -- its own direction,
# or for a mixed (or unclassifiable) file the direction with the deeper
# recorded qd, a coherent measured pair, never a blend; "" for none
function pick_slot(kind, D, ROW,    r, w) {
    if (("read" in D) && !("write" in D)) return kind "_r"
    if (("write" in D) && !("read" in D)) return kind "_w"
    r = row_get(ROW, kind "_r_qd"); r = r ~ /^[0-9]+$/ ? r + 0 : -1
    w = row_get(ROW, kind "_w_qd"); w = w ~ /^[0-9]+$/ ? w + 0 : -1
    if (r < 0 && w < 0)
        return slot_any(ROW, kind "_r") ? kind "_r" : slot_any(ROW, kind "_w") ? kind "_w" : ""
    return r >= w ? kind "_r" : kind "_w"
}
function slot_any(ROW, slot) {
    return row_get(ROW, slot "_nj") != "" || row_get(ROW, slot "_fs") != "" || row_get(ROW, slot "_nr") != "" || row_get(ROW, slot "_qd") != ""
}
# lib.py's pick_engine: the most-used engine; a tie goes to ENGINE_ORDER
# (an engine it does not list ranks last, and among those the first seen),
# and no engine at all to its first
function pick_engine(TALLY, ORD, n,    O, no, i, j, e, r, best, bc, br) {
    no = split(engine_order(), O, " ")
    if (!n) return O[1]
    for (i = 1; i <= n; i++) {
        e = ORD[i]; r = no
        for (j = 1; j <= no; j++) if (O[j] == e) { r = j - 1; break }
        if (i == 1 || TALLY[e] > bc || (TALLY[e] == bc && r < br)) { best = e; bc = TALLY[e]; br = r }
    }
    return best
}
function is_floor_marked(L, n,    i) {   # lib.py's is_floor_twin
    for (i = 1; i <= 3 && i <= n; i++)
        if (index(L[i], floor_marker()) == 1) return 1
    return 0
}
# The INI view the layout readers share: every line stripped, blanks and
# #/; comments skipped, "[name]" opens a section (substr, no further test)
# and key=value, both stripped, lands in the section it is in -- before
# any section, nowhere. SN[1..ns] the sections in order, KV[s, key] their
# values, KV["g", key] [global]'s; ini_get falls back from a section to
# [global], then to <dflt>.
function ini_parse(L, n, SN, KV,    i, line, c, cur, ns, p) {
    split("", SN); split("", KV); ns = 0; cur = ""
    for (i = 1; i <= n; i++) {
        line = strip(L[i]); c = substr(line, 1, 1)
        if (line == "" || c == "#" || c == ";") continue
        if (c == "[") {
            SN[++ns] = substr(line, 2, length(line) - 2)
            if (SN[ns] == "global") { cur = "g"; ns-- }
            else cur = ns
            continue
        }
        if ((p = index(line, "=")) && cur != "")
            KV[cur, strip(substr(line, 1, p - 1))] = strip(substr(line, p + 1))
    }
    return ns
}
function ini_get(KV, s, key, dflt) {
    return ((s, key) in KV) ? KV[s, key] : (("g", key) in KV) ? KV["g", key] : dflt
}

# --- probe facts (the probe snippet's lines, P[1..np]) ---
# lib.py's probe_cpu_fact: the cpus on the first "key <list>" line (none
# for "-", tested and empty); 1 when the line is there, 0 when the probe
# could not test -- never an answer
function probe_cpu_fact(P, np, key, S,    i, F) {
    split("", S)
    for (i = 1; i <= np; i++)
        if (index(P[i], key) && pysplit(P[i], F) > 1 && F[1] == key) {
            if (F[2] != "-" && !parse_cpulist(F[2], S)) awk_fail("probe: bad cpu list on its " key " line: " F[2])
            return 1
        }
    return 0
}
function probe_universe(P, np, ncpus, U,    c) {   # the online list, else 0..ncpus-1
    if (probe_cpu_fact(P, np, "online", U) && set_any(U)) return
    split("", U)
    for (c = 0; c < ncpus; c++) U[c] = 1
}
function probe_unbindable(P, np, U, UB,    B, BP, c) {   # measured, never a guess
    split("", UB)
    if (!probe_cpu_fact(P, np, "bindable", B)) return
    probe_cpu_fact(P, np, "bindable_priv", BP)
    for (c in U) if (!(c in B) && !(c in BP)) UB[c] = 1
}
# lib.py's probe_topology: TK[c] for every cpu it names, TS[c] its socket,
# TL[c] its core's threads (a list); 1 when the probe carried topology
function probe_topology(P, np, TK, TS, TL,    i, F, c, v, pkg, cid, sib, self, S, key, BY) {
    split("", TK); split("", TS); split("", TL)
    split("", pkg); split("", cid); split("", sib); split("", self); split("", BY)
    for (i = 1; i <= np; i++) {
        if (!index(P[i], "topo_") || pysplit(P[i], F) < 3 || substr(F[1], 1, 5) != "topo_" || F[2] !~ /^[0-9]+$/) continue
        c = F[2] + 0
        if (F[1] == "topo_physical_package_id") { if ((v = py_int(F[3])) != "") pkg[c] = v }
        else if (F[1] == "topo_core_id") { if ((v = py_int(F[3])) != "") cid[c] = v }
        else if (F[1] == "topo_thread_siblings_list" && parse_cpulist(F[3], S)) { sib[c] = join_sorted(S, ","); self[c] = c in S }
    }
    for (c in pkg) TK[c] = 1
    for (c in cid) TK[c] = 1
    for (c in sib) TK[c] = 1
    # threads without a siblings list share a core with every thread of the
    # same (socket, core_id)
    for (c in TK) {
        TS[c] = (c in pkg) ? pkg[c] : 0
        if (!(c in sib) && (c in cid)) {
            key = TS[c] SUBSEP cid[c]
            if (key in BY) BY[key] = BY[key] "," c; else BY[key] = c
        }
    }
    for (c in TK) {
        if ((c in sib) && self[c]) TL[c] = sib[c]
        else if (c in cid) {
            key = TS[c] SUBSEP cid[c]
            if (!(key in BY)) awk_fail("probe: cpu " c " is missing from its own thread_siblings_list")
            TL[c] = BY[key]
        } else
            TL[c] = c
    }
    return set_any(TK)
}
# lib.py's reserve_count and place_reserve: how many cores the OS keeps,
# and which -- core 0 first, then round-robin over the sockets from the one
# after core 0's, each giving its lowest free core; never a DPDK core
function reserve_count(ncores, ndpdk,    v) {
    v = (ncores <= 24 ? 2 : 4) + (ndpdk > 4 ? int((ndpdk - 1) / 4) : 0)
    if (v > 12) v = 12
    if (v > int(ncores / 2)) v = int(ncores / 2)
    return v < 1 ? 1 : v
}
function place_reserve(ORD, nk, SOCK, DPDK, core0, want, RES,    n, i, s, ns, SO, seen, p, r, RR, FREE, FH, FN, left) {
    split("", RES); n = 0
    if (core0 != "" && !(core0 in DPDK)) RES[++n] = core0
    ns = 0
    for (i = 1; i <= nk; i++)
        if (!((s = SOCK[ORD[i]]) in seen)) { seen[s] = 1; SO[++ns] = s }
    if (ns == 0) return n
    sort_arr(SO, ns, 1)
    p = 1
    for (i = 1; i <= ns; i++) if (SO[i] == SOCK[core0]) { p = i; break }
    r = 0
    for (i = p + 1; i <= ns; i++) RR[++r] = SO[i]
    for (i = 1; i <= p; i++) RR[++r] = SO[i]
    for (i = 1; i <= ns; i++) { FH[SO[i]] = 1; FN[SO[i]] = 0 }
    for (i = 1; i <= nk; i++)
        if (!(ORD[i] in DPDK) && !(n && ORD[i] == RES[1])) {
            s = SOCK[ORD[i]]; FREE[s, ++FN[s]] = ORD[i]
        }
    while (n < want) {
        left = 0
        for (i = 1; i <= ns; i++) if (FH[SO[i]] <= FN[SO[i]]) left = 1
        if (!left) break
        for (i = 1; i <= r; i++) {
            if (n >= want) break
            s = RR[i]
            if (FH[s] <= FN[s]) RES[++n] = FREE[s, FH[s]++]
        }
    }
    return n
}
# lib.py's probe_cores: the cpus fio may run on for one host, in PHYSICAL
# cores -- ONE rule for the tuner, the calibration shapes, usable_cores and
# the pinning check; the python says why for every step. R gets n, ncores,
# dpdk, nres and res (the reserved cores' threads, for the summary),
# weka_core0 (weka holds core 0), unlisted, unbound, topo and catchall; PHYS one thread per usable core,
# ALL every thread of them. In three parts: awk caps a function at 50
# parameters and locals together.
function probe_cores(P, np, base_list, R, PHYS, ALL,    U, UB, CORE, THR, ORD, nk, SOCK, DPDK, core0, B, RES, nres, SKIP, S, i, j, k, T, nt, t, inb, use, unlisted, unbound, res) {
    split("", R); split("", PHYS); split("", ALL)
    nk = probe_core_map(P, np, U, UB, CORE, THR, ORD, SOCK, DPDK, R)
    core0 = (0 in CORE) ? CORE[0] : (nk ? ORD[1] : "")
    split("", RES); nres = 0
    if (probe_base(base_list, U, UB, THR, DPDK, core0, B, R)) {
        # core 0's pair -- unless weka owns core 0: then it already left as
        # a DPDK core, and counting it twice broke the logged sum
        if (core0 != "" && !(core0 in DPDK)) RES[++nres] = core0
    } else {
        split("", B)
        for (k in U) B[k] = 1
        nres = place_reserve(ORD, nk, SOCK, DPDK, core0, reserve_count(nk, set_size(DPDK)), RES)
    }
    res = ""
    for (i = 1; i <= nres; i++) {
        split("", S); nt = split(THR[RES[i]], T, ",")
        for (j = 1; j <= nt; j++) S[T[j]] = 1
        res = res (i > 1 ? " " : "") fmt_cpulist(S)
        SKIP[RES[i]] = 1
    }
    use = 0; unlisted = 0; unbound = 0
    for (i = 1; i <= nk; i++) {
        k = ORD[i]
        if ((k in DPDK) || (k in SKIP)) continue
        nt = split(THR[k], T, ","); t = 0; inb = 0
        for (j = 1; j <= nt; j++) {
            if (!(T[j] in B)) continue
            inb = 1
            if (T[j] in UB) continue
            if (!t++) PHYS[T[j]] = 1
            ALL[T[j]] = 1
        }
        if (t) use++
        else if (inb) unbound++   # listed, but the host binds none of its threads
        else unlisted++           # the operator's list leaves the whole core out
    }
    R["n"] = use; R["ncores"] = nk; R["dpdk"] = set_size(DPDK)
    R["nres"] = nres; R["res"] = res == "" ? "none" : res
    R["weka_core0"] = core0 != "" && (core0 in DPDK)
    R["unlisted"] = unlisted; R["unbound"] = unbound
}
# The host's cpus and cores: U the cpus it has, UB those it refuses to
# bind, CORE[cpu] its core's key (the core's lowest online thread), THR[key]
# the core's threads (a list), ORD[1..n] the keys in order (n returned),
# SOCK[key] its socket, DPDK the keys of weka's dedicated cores -- weka pins
# each dedicated io thread to exactly ONE cpu, so only single-cpu masks
# count -- and R["topo"].
function probe_core_map(P, np, U, UB, CORE, THR, ORD, SOCK, DPDK, R,    i, F, S, ncpus, weka, TK, TS, TL, A, n, c, m, T, nt, j, k, nk) {
    ncpus = 0; split("", weka)
    for (i = 1; i <= np; i++) {
        if (!index(P[i], "ncpus") && !index(P[i], "weka_allowed")) continue
        if (pysplit(P[i], F) < 2) continue   # a bare isolated line: no isolated cpus
        if (F[1] == "ncpus" && F[2] ~ /^[0-9]+$/) ncpus = F[2] + 0
        else if (F[1] == "weka_allowed") {
            if (!parse_cpulist(F[2], S)) awk_fail("probe: bad cpu list on a weka_allowed line: " F[2])
            if (set_size(S) == 1) for (c in S) weka[c] = 1
        }
    }
    probe_universe(P, np, ncpus, U)
    probe_unbindable(P, np, U, UB)
    R["topo"] = probe_topology(P, np, TK, TS, TL)
    split("", CORE); split("", THR)
    n = set_sorted(U, A)
    for (i = 1; i <= n; i++) {
        c = A[i]; m = c
        if (c in TK) {
            nt = split(TL[c], T, ",")
            for (j = 1; j <= nt; j++) if ((T[j] in U) && T[j] + 0 < m) m = T[j] + 0
        }
        CORE[c] = m
        if (m in THR) THR[m] = THR[m] "," c; else THR[m] = c
    }
    split("", ORD); nk = 0
    for (k in THR) ORD[++nk] = k + 0
    sort_arr(ORD, nk, 1)
    split("", SOCK); split("", DPDK)
    for (i = 1; i <= nk; i++) SOCK[ORD[i]] = (ORD[i] in TK) ? TS[ORD[i]] : 0
    for (c in weka) if (c in CORE) DPDK[CORE[c]] = 1
    return nk
}
# Does an operator cpu list (the host file's) stand? B gets it, trimmed to
# the cpus the host has. A list covering every cpu fio could use -- all but
# weka's cores (both threads), core 0's pair and the cpus the host refuses
# to bind -- restricts nothing and counts as none (R["catchall"]).
function probe_base(base_list, U, UB, THR, DPDK, core0, B, R,    BU, NEVER, c, k, T, nt, j) {
    R["catchall"] = 0
    if (base_list == "") return 0
    if (!parse_cpulist(base_list, B)) awk_fail("bad cpu list: " base_list)
    if (!set_any(U)) return 1
    for (c in B) if (c in U) BU[c] = 1
    split("", B)
    for (c in BU) B[c] = 1
    for (c in UB) NEVER[c] = 1
    for (k in DPDK) { nt = split(THR[k], T, ","); for (j = 1; j <= nt; j++) NEVER[T[j]] = 1 }
    if (core0 != "") { nt = split(THR[core0], T, ","); for (j = 1; j <= nt; j++) NEVER[T[j]] = 1 }
    for (c in U) if (!(c in NEVER) && !(c in B)) return 1
    R["catchall"] = 1
    return 0
}
function cores_summary(R, PHYS, ALL,    more, p, a) {   # lib.py's: the one line the logs print
    more = ""
    if (R["unlisted"]) more = more sprintf(" - %d outside the host-file cpu list", R["unlisted"])
    if (R["unbound"]) more = more sprintf(" - %d unbindable", R["unbound"])
    p = fmt_cpulist(PHYS); a = fmt_cpulist(ALL)
    return sprintf("%d physical core(s)%s - %d weka DPDK - %d reserved for the OS (%s)%s = N=%d: N/2 and N jobs on %s, 2N and 4N on %s", R["ncores"], R["topo"] ? "" : " (no topology: one per cpu)", R["dpdk"], R["nres"], R["res"], more, R["n"], p == "" ? "none" : p, a == "" ? "none" : a)
}
# lib.py's probe_aio_room: fs.aio-max-nr less fs.aio-nr as the probe read
# them, "" when it could not tell
function probe_aio_room(P, np,    i, F, mx, nr) {
    mx = ""; nr = ""
    for (i = 1; i <= np; i++)
        if (index(P[i], "aio_") && pysplit(P[i], F) == 2 && F[2] ~ /^[0-9]+$/) {
            if (F[1] == "aio_max_nr") mx = F[2] + 0
            else if (F[1] == "aio_nr") nr = F[2] + 0
        }
    if (mx == "") return ""
    mx -= (nr == "" ? 0 : nr)
    return mx < 0 ? 0 : mx
}
# --- the host file (CSV) ---
# python's csv.reader with the default dialect -- "," between fields, a
# field that STARTS with " is quoted, "" inside quotes is a quote, text
# after a closing quote runs on unquoted (not strict), no skipinitialspace
# -- over the lines L[1..n] of a file: a quoted field may span lines. The
# record count is returned; record r has CN[r] fields, CV[r, 1..CN[r]].
function csv_read(L, n, CN, CV,    r, i, s, len, k, c, st, f, nf) {
    split("", CN); split("", CV); r = 0; st = 0
    for (i = 1; i <= n; i++) {
        s = L[i]; len = length(s)
        if (st == 3) f = f "\n"              # the quoted field spans the line break
        else { nf = 0; f = ""; st = 1 }      # 1: a field starts
        for (k = 1; k <= len; k++) {
            c = substr(s, k, 1)
            if (st == 1) {
                if (c == "\"") st = 3        # 3: inside quotes
                else if (c == ",") CV[r + 1, ++nf] = ""
                else { f = c; st = 2 }       # 2: an unquoted field
            } else if (st == 2) {
                if (c == ",") { CV[r + 1, ++nf] = f; f = ""; st = 1 }
                else f = f c
            } else if (st == 3) {
                if (c == "\"") st = 4        # 4: a quote inside quotes
                else f = f c
            } else if (c == "\"") { f = f c; st = 3 }
            else if (c == ",") { CV[r + 1, ++nf] = f; f = ""; st = 1 }
            else { f = f c; st = 2 }
        }
        if (st == 3) continue
        if (len) CV[r + 1, ++nf] = f         # a blank line is a record of no fields
        CN[++r] = nf
    }
    if (st == 3) { CV[r + 1, ++nf] = f; CN[++r] = nf }   # the file ends inside quotes
    return r
}
function csv_line(s, F,    L, CN, CV, k) {   # one line, as csv.reader([line]) parses it
    L[1] = s
    csv_read(L, 1, CN, CV)
    split("", F)
    for (k = 1; k <= CN[1]; k++) F[k] = CV[1, k]
    return CN[1]
}
# --- the calibration seed ---
# Seeded file sizes. A job at nrfiles=nr takes FILESIZE_MIB/nr from each of
# its first nr files, so file f only ever needs the largest share any test
# takes from it: with nrfiles 1, 2 and 4 that is 5G, 2.5G, 1.25G and 1.25G
# per job -- 10G, not the 20G of four 5G files. A need is (nj, nr, mib),
# ND[i, 1..3]: jobs below nj at nrfiles nr read or write mib of each of
# their first nr files. Every size is fixed before the first seed, from
# every need there is, so a file is created once at its final size and
# never has to grow.
function needs_ladder(ND, n, nrs, fsmib, nj,    A, m, i, k, U, S) {   # the nrfiles ladder <nrs>, appended; the new count
    m = pysplit(nrs, A); k = 0
    for (i = 1; i <= m; i++) if (A[i] ~ /^[0-9]+$/ && !((A[i] + 0) in U)) { U[A[i] + 0] = 1; S[++k] = A[i] + 0 }
    sort_arr(S, k, 1)
    for (i = 1; i <= k; i++)
        if (S[i] > 0) { n++; ND[n, 1] = nj; ND[n, 2] = S[i]; ND[n, 3] = int(fsmib / S[i]) > 1 ? int(fsmib / S[i]) : 1 }
    return n
}
function needs_listed(ND, n, path,    L, m, i, F) {   # "<nj> <nr> <mib>" lines (cal_shapes' needs.*), appended
    m = readlines(path, L)
    for (i = 1; i <= m; i++)
        if (pysplit(L[i], F) == 3 && F[1] ~ /^[0-9]+$/ && F[2] ~ /^[0-9]+$/ && F[3] ~ /^[0-9]+$/) {
            n++; ND[n, 1] = F[1] + 0; ND[n, 2] = F[2] + 0; ND[n, 3] = F[3] + 0
        }
    return n
}
function seed_size(ND, n, j, f,    i, best) {   # MiB file f of job j is seeded at; 0 when nothing needs it
    best = 0
    for (i = 1; i <= n; i++) if (j < ND[i, 1] && f < ND[i, 2] && ND[i, 3] > best) best = ND[i, 3]
    return best
}
function seed_name(prefix, fmt, j, f) { return replace_all(replace_all(prefix fmt, "$jobnum", j), "$filenum", f) }
# Each host's filesystem group from collect_fs_groups' <work>/groups
# ("<host> <group>"), over H[1..nh] in order: GF[h] its first member, who
# lays out and prices the group's fleet-shared read set, and GM[h] every
# member, space-joined. Without the file every host is one group: one
# shared directory, as before groups.
function fs_groups(work, H, nh, GF, GM,    L, n, i, F, G, g, FIRST, ALL) {
    split("", GF); split("", GM)
    n = readlines(work "/groups", L)
    for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2) G[F[1]] = F[2]
    for (i = 1; i <= nh; i++) {
        g = (H[i] in G) ? G[H[i]] : "1"
        if (g in FIRST) ALL[g] = ALL[g] " " H[i]
        else { FIRST[g] = H[i]; ALL[g] = H[i] }
    }
    for (i = 1; i <= nh; i++) { g = (H[i] in G) ? G[H[i]] : "1"; GF[H[i]] = FIRST[g]; GM[H[i]] = ALL[g] }
}
# --- layout derivation: generate_layout's, and the staged re-derivation's ---
# One namespace per filename_format -- or, for a job without one, per its
# measured section name -- collects CONTRIBUTORS: each job's geometry. One
# section per (pruned) contributor lays out exactly the union of files the
# jobs will open. A single independent-max section (max numjobs x max
# nrfiles x max filesize) would instead create the full cross-product grid,
# over-provisioning disk by integer factors whenever the geometries diverge
# -- and the capacity guard would never see it coming. lay_reset, then
# lay_add per jobfile and lay_engine per jobfile whose engine counts, then
# lay_sections appends the create sections to B.
function lay_reset() {
    split("", LAY_NS); split("", LAY_TALLY); split("", LAY_EORD); LAY_NNS = 0; LAY_NE = 0
}
function lay_engine(L, n,    eng) {
    if ((eng = first_value(L, n, "ioengine")) == "") return
    if (!(eng in LAY_TALLY)) LAY_EORD[++LAY_NE] = eng
    LAY_TALLY[eng]++
}
function lay_add(L, n, fname, where,    fmt, key, sec, fs, sz, sb, v, nj, nr, k, c) {
    # No filename_format: fio default naming embeds the job section name, so
    # the layout section must carry the SAME name as the measured (last)
    # section of the file, or it would create differently-named files.
    if ((fmt = first_value(L, n, "filename_format")) != "") { key = fmt; sec = "" }
    else {
        if ((sec = last_section(L, n)) == "") sec = fname
        key = "__jobname__:" sec
    }
    fs = first_value(L, n, "filesize"); sz = first_value(L, n, "size"); sb = -1
    # size=50% and the like are not derivable: no size of their own
    if (fs != "" && (v = parse_size(fs)) != "" && v > sb) sb = v
    if (sz != "" && (v = parse_size(sz)) != "" && v > sb) sb = v
    nj = first_value(L, n, "numjobs"); nj = nj == "" ? 1 : py_int(nj)
    nr = first_value(L, n, "nrfiles"); nr = nr == "" ? 1 : py_int(nr)
    if (nj == "" || nr == "") awk_fail(where ": numjobs and nrfiles must be numbers")
    if (!(key in LAY_NS)) { LAY_NS[key] = ++LAY_NNS; LAY_KEY[LAY_NNS] = key; LAY_SEC[LAY_NNS] = sec; LAY_FMT[LAY_NNS] = fmt; LAY_NC[LAY_NNS] = 0 }
    k = LAY_NS[key]; c = ++LAY_NC[k]
    LAY_CNJ[k, c] = nj; LAY_CNR[k, c] = nr; LAY_CSB[k, c] = sb; LAY_CFS[k, c] = fs; LAY_CSZ[k, c] = sz
}
# prune keeps only contributors no kept contributor grid fully covers:
# sorted widest first (stably: ties keep file order), a duplicate or
# dominated entry always meets its dominator first
function lay_prune(k, KEPT,    n, I, i, j, t, nk, a, b, dom) {
    n = LAY_NC[k]
    for (i = 1; i <= n; i++) {
        t = i
        for (j = i - 1; j >= 1 && lay_wider(k, t, I[j]); j--) I[j + 1] = I[j]
        I[j + 1] = t
    }
    nk = 0
    for (i = 1; i <= n; i++) {
        a = I[i]; dom = 0
        for (j = 1; j <= nk && !dom; j++) {
            b = KEPT[j]
            dom = LAY_CNJ[k, a] <= LAY_CNJ[k, b] && LAY_CNR[k, a] <= LAY_CNR[k, b] && LAY_CSB[k, a] <= LAY_CSB[k, b]
        }
        if (!dom) KEPT[++nk] = a
    }
    return nk
}
function lay_wider(k, a, b) {   # does contributor a sort before b?
    if (LAY_CNJ[k, a] != LAY_CNJ[k, b]) return LAY_CNJ[k, a] > LAY_CNJ[k, b]
    if (LAY_CNR[k, a] != LAY_CNR[k, b]) return LAY_CNR[k, a] > LAY_CNR[k, b]
    return LAY_CSB[k, a] > LAY_CSB[k, b]
}
function lay_sections(B, nb,    KS, q, k, nk, KEPT, prev, x, c, cnt, sec, fmt) {   # the new line count
    for (k = 1; k <= LAY_NNS; k++) KS[k] = LAY_KEY[k]
    sort_arr(KS, LAY_NNS, 0)
    cnt = 0
    for (q = 1; q <= LAY_NNS; q++) {
        k = LAY_NS[KS[q]]; nk = lay_prune(k, KEPT); prev = ""
        for (x = 1; x <= nk; x++) {
            c = KEPT[x]; cnt++
            # A jobname namespace (no filename_format) names its files after
            # the section, so a lone contributor keeps that name; several
            # need distinct names for wait_for, so the default naming of fio
            # ($jobname.$jobnum.$filenum) is spelled out.
            if (LAY_SEC[k] != "" && nk == 1) { sec = LAY_SEC[k]; fmt = LAY_FMT[k] }
            else if (LAY_SEC[k] != "") { sec = "layout-" cnt; fmt = LAY_SEC[k] ".$jobnum.$filenum" }
            else { sec = "layout-" cnt; fmt = LAY_FMT[k] }
            B[++nb] = ""
            B[++nb] = "[" sec "]"
            # Contributors of one namespace have overlapping grids and must
            # not lay out the same file concurrently (an extend in fio can
            # unlink a file another section is mid-write on), so they chain
            # via wait_for. Distinct namespaces touch disjoint files: those
            # sections run in parallel -- a global stonewall here would only
            # slow the layout.
            if (prev != "") B[++nb] = "wait_for=" prev
            prev = sec
            B[++nb] = "create_only=1"
            B[++nb] = "blocksize=1Mi"
            if (fmt != "") B[++nb] = "filename_format=" fmt
            if (LAY_CFS[k, c] != "") B[++nb] = "filesize=" LAY_CFS[k, c]
            else if (LAY_CSZ[k, c] != "") B[++nb] = "size=" LAY_CSZ[k, c]
            else B[++nb] = "# WARNING: no derivable file size in this namespace (" LAY_KEY[k] ")"
            if (LAY_CNR[k, c] > 1) B[++nb] = "nrfiles=" LAY_CNR[k, c]
            B[++nb] = "numjobs=" LAY_CNJ[k, c]
        }
    }
    return nb
}
# One cal.results line into F: the host, its engine, then (qd nr fs nj) per
# slot, every slot of the host-file schema in its order; 0 for a blank line.
# Two parsers read the file (apply_cal_results, the writeback) and they once
# disagreed on the width: the writeback died on a file calibration had just
# written, after 11 minutes of measuring. Any other width is a schema break,
# not a skip -- dropping the line would discard a measurement without a word.
function cal_results_split(line, F,    m, S, w) {
    if (!(m = pysplit(line, F))) return 0
    w = 2 + 4 * split(geom_slots(), S, " ")
    if (m != w) awk_fail("cal.results: malformed line (want " w " fields): " rstrip(line))
    return m
}
function commas(v,    s, out) {   # format(int(v), ","): a count, thousands grouped
    s = sprintf("%.0f", int(v)); out = ""
    while (length(s) > 3 && substr(s, length(s) - 3, 1) ~ /[0-9]/) {
        out = "," substr(s, length(s) - 2) out; s = substr(s, 1, length(s) - 3)
    }
    return s out
}
function csv_field(v) {   # csv.writer's QUOTE_MINIMAL, with no line terminator
    if (!index(v, ",") && !index(v, "\"")) return v
    gsub(/"/, "\"\"", v)
    return "\"" v "\""
}
# name=value,... (the WEKATESTER_HOST_ALIAS and _IDENT environment) into M
function kv_map(s, M,    n, P, i, p) {
    split("", M)
    n = lsplit(s, P, ",")
    for (i = 1; i <= n; i++) if ((p = index(P[i], "="))) M[substr(P[i], 1, p - 1)] = substr(P[i], p + 1)
}
# A host cell may be <name>/<machine-id>, and may name the box by something
# other than the address this run uses (local mode calls it localhost):
# the id stripped, the name mapped onto the address
function host_addr(cell, ALIAS,    name) {
    name = cell; sub(/\/.*/, "", name); name = strip(name)
    return (name in ALIAS) ? ALIAS[name] : name
}
# --- JSON (Frank, 2026-10-05: no jq, no python) ---
# A tokenizer, not a line matcher, so fio's one-key-per-line output and
# compact JSON read the same. One document's lines go through json_line one
# at a time, and every scalar comes out as JP[i] (its path: keys and array
# indexes dot-joined, client_stats.3.read.bw_bytes), JV[i] (its value, a
# string unescaped) and JS[i] (1 for a string), i up to JN; an empty
# container is "{}" or "[]" at its own path. json_flat prints and clears
# them after every line; cal_shapes reads weka's NIC list from them. Text
# before the document is skipped: it starts at the first character of
# <starts> ("{" for fio, whose own log lines come first).
# A line at a time, with the parser's own stack, so no awk ever holds a
# file as one string: over a whole-file buffer the cost was quadratic on
# two of the three awks this runs under -- macOS awk's substr() measures
# the whole string on every call, and mawk copies the buffer on every
# appended line; a 451-client result took ~130 s and ~9 s to read (gawk:
# 0.4 s). fio prints one key per line, so every line is short; a single
# huge compact line would still be quadratic on those two, and fio never
# writes one. A string may run across lines.
function json_begin(starts) {
    J_WANT = "v"; J_VPATH = ""; J_D = 0; J_STARTED = 0; J_CARRY = ""; J_FPOS = 0
    J_STARTS = starts; J_ROOT = ""; J_ERR = ""; JN = 0
}
# One line: 0 to go on, 1 when the document is complete, -1 when it does
# not parse (J_ERR says where)
function json_line(s,    line, lstart, rest, p, i, c, tl) {
    if (J_CARRY != "") { line = J_CARRY s; lstart = J_CSTART; J_CARRY = "" }
    else { line = s; lstart = J_FPOS }
    J_FPOS += length(s) + 1
    if (!J_STARTED) {
        p = 0
        for (i = 1; i <= length(J_STARTS); i++)
            if ((c = index(line, substr(J_STARTS, i, 1))) && (!p || c < p)) p = c
        if (!p) return 0
        J_STARTED = 1; rest = substr(line, p); J_ROOT = substr(rest, 1, 1)
    } else rest = line
    while (1) {
        sub(/^[ \t\r]+/, "", rest)
        if (rest == "") return 0
        J_TOKOFF = lstart + length(line) - length(rest) + 1
        c = substr(rest, 1, 1)
        if (c == "\"") {
            if (!match(rest, /^"([^"\\]|\\.)*"/)) {
                # the string goes on past this line
                J_CARRY = rest "\n"; J_CSTART = J_TOKOFF - 1; return 0
            }
            tl = RLENGTH; json_feed(substr(rest, 2, tl - 2), 1)
        } else if (index("{}[]:,", c)) {
            tl = 1; json_feed(c, 0)
        } else {
            match(rest, /^[^],} \t\r]+/); tl = RLENGTH; json_feed(substr(rest, 1, tl), 0)
        }
        if (J_ERR != "") return -1
        if (J_WANT == "end") return 1
        rest = substr(rest, tl + 1)
    }
}
# After the last line: 0 when the document was complete, 2 when there was
# none at all, 3 when it does not parse (J_ERR)
function json_end() {
    if (J_ERR != "") return 3
    if (!J_STARTED) return 2
    J_TOKOFF = J_FPOS
    if (J_CARRY != "") return json_fail("unterminated string")
    if (J_WANT != "end") return json_fail("unexpected end")
    return 0
}
function json_fail(what) { J_ERR = sprintf("json: %s at offset %d", what, J_TOKOFF); return 3 }
function json_emit(path, v, isstr) { JN++; JP[JN] = path; JV[JN] = v; JS[JN] = isstr }
function json_unesc(s,   out, p, e) {
    if (!index(s, "\\")) return s
    out = ""
    while ((p = index(s, "\\"))) {
        out = out substr(s, 1, p - 1); e = substr(s, p + 1, 1)
        if (e == "u") { out = out "?"; s = substr(s, p + 6); continue }
        if (e == "n") out = out "\n"; else if (e == "t") out = out "\t"
        else if (e == "r") out = out "\r"; else out = out e
        s = substr(s, p + 2)
    }
    return out s
}
# after a value: the enclosing container wants a separator, or the
# document is complete
function json_done() { J_WANT = J_D == 0 ? "end" : J_T[J_D] == "o" ? "o" : "a" }
# one token: tok, and whether it was a quoted string
function json_feed(tok, isstr) {
    if (J_WANT == "v" || J_WANT == "V") {
        if (!isstr && tok == "]" && J_WANT == "V") { json_emit(J_CP[J_D], "[]", 0); J_D--; json_done(); return }
        if (!isstr && tok == "{") { J_T[++J_D] = "o"; J_CP[J_D] = J_VPATH; J_WANT = "k"; return }
        if (!isstr && tok == "[") { J_T[++J_D] = "a"; J_CP[J_D] = J_VPATH; J_IX[J_D] = 0; J_VPATH = J_VPATH ".0"; J_WANT = "V"; return }
        if (!isstr && index("{}[]:,", tok)) { json_fail("unexpected character"); return }
        json_emit(J_VPATH, isstr ? json_unesc(tok) : tok, isstr)
        json_done(); return
    }
    if (J_WANT == "k" || J_WANT == "K") {
        if (!isstr && tok == "}" && J_WANT == "k") { json_emit(J_CP[J_D], "{}", 0); J_D--; json_done(); return }
        if (!isstr) { json_fail("expected a key"); return }
        tok = json_unesc(tok); J_VPATH = J_CP[J_D] == "" ? tok : J_CP[J_D] "." tok; J_WANT = ":"; return
    }
    if (J_WANT == ":") {
        if (isstr || tok != ":") json_fail("expected :")
        else J_WANT = "v"
        return
    }
    if (J_WANT == "o") {
        if (!isstr && tok == ",") { J_WANT = "K"; return }
        if (!isstr && tok == "}") { J_D--; json_done(); return }
        json_fail("expected , or }"); return
    }
    if (J_WANT == "a") {
        if (!isstr && tok == ",") { J_VPATH = J_CP[J_D] "." (++J_IX[J_D]); J_WANT = "v"; return }
        if (!isstr && tok == "]") { J_D--; json_done(); return }
        json_fail("expected , or ]"); return
    }
}
AWKLIB

awkrun() {   # awkrun <program> <arg>... -- WEKA_AWK prepended, LC_ALL=C
    LC_ALL=C awk "$WEKA_AWK
function geom_slots() { return \"$GEOM_SLOTS\" }
function geom_names() { return \"$GEOM_NAMES\" }
function layout_job() { return \"$LAYOUT_JOB\" }
function layout_marker() { return \"$LAYOUT_MARKER\" }
function floor_marker() { return \"$FLOOR_MARKER\" }
function engine_order() { return \"$ENGINE_ORDER\" }
function line_rate_slots() { return \"$LINE_RATE_SLOTS\" }
$1" "${@:2}"
}

# stdin's sha256, lowercase hex
sha256_hex() {
    local out
    out=$(sha256sum) || return 1
    printf '%s' "${out%% *}"
}

# --- fio JSON in awk (Frank, 2026-10-05: no jq, no python) -------------------
# json_flat <file>: fio's JSON as "path<TAB>value" lines, one per scalar, e.g.
# client_stats.3.read.bw_bytes<TAB>2147483648, by the library's tokenizer
# (json_begin, json_line, json_end), a line at a time. Text before the first
# "{" (fio's own log lines) is skipped. Exit 2: no JSON at all; exit 3: the
# JSON does not parse (the offset is on stderr).
json_flat() {   # json_flat <file>
    awkrun '
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
    }' "$1"
}

# One parse per results file: check_fio_errors loads it fresh, and the
# reader that follows it (summ_one, cal_values, cal_lat_values) takes the
# same lines instead of flattening the file a second time.
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

# -a takes a level and, for the measuring levels, an optional per-rung
# duration: "cal:15" runs each ladder rung for 15 measured seconds instead of
# the 30s default. This is the CALIBRATION rung length; -x/--duration sets
# how long the measured jobs run, and the two are independent.
set_auto_level() {   # set_auto_level <raw> <flag, for error messages>
    local raw=$1 flag=$2 lvl secs
    lvl=$(lower "${raw%%:*}")
    case "$lvl" in
        (safe|max|cal|brutal) ;;
        (*) usage >&2; die "unknown auto level: ${raw} (safe|max|cal|brutal)" ;;
    esac
    if [ "$raw" != "${raw%%:*}" ]; then
        secs=${raw#*:}
        case "$secs" in
            (""|*[!0-9]*|0) usage >&2
                die "$flag: the rung duration must be whole seconds > 0, got: $secs" ;;
        esac
        CAL_RUNTIME=$secs
    elif [ -z "$CAL_RUNTIME_FROM_ENV" ]; then
        # the level's own cell length: safe and max search three job counts
        # at a fixed geometry, cal and brutal walk the ladders
        case "$lvl" in (safe|max) CAL_RUNTIME=15 ;; (*) CAL_RUNTIME=30 ;; esac
    fi
    AUTO_LEVEL=$lvl
}

parse_args() {
    HOSTS=()
    # Whether a `--` appears anywhere decides how a bare token after -C is
    # read, so it has to be known before the left-to-right pass reaches one.
    # With `--` present the client list is explicit, which makes a bare
    # pre---- token after -C unambiguously the set name; without it the token
    # is more likely a client, so it stays in HOSTS as a mere candidate.
    local opt arg tok servers_only=0 dashdash=0 c_pending=0
    for tok in "$@"; do
        [ "$tok" = "--" ] && { dashdash=1; break; }
    done
    while [ $# -gt 0 ]; do
        if [ "$servers_only" -eq 1 ]; then HOSTS+=("$1"); shift; continue; fi
        case "$1" in
            -*) opt=$(normalize_opt "$1") ;;
            *)  opt=$1 ;;
        esac
        # Every arm below matches and extracts from $opt, never $1: $1 still
        # carries the user's capitalization and would miss the arm. $1 survives
        # only in need_arg's message, which should echo what was typed.
        case "$opt" in
            --) servers_only=1; shift ;;
            -d) need_arg "$1" $# "${2:-}"; DIRECTORY=$2; DIRECTORY_EXPLICIT=1; shift 2 ;;
            -d?*) opt_val "$opt" -d; DIRECTORY=$OPT_VAL; DIRECTORY_EXPLICIT=1; shift ;;
            -w) need_arg "$1" $# "${2:-}"; WORKLOAD=$2; WORKLOAD_EXPLICIT=1; shift 2 ;;
            -w?*) opt_val "$opt" -w; WORKLOAD=$OPT_VAL; WORKLOAD_EXPLICIT=1; shift ;;
            -f) need_arg "$1" $# "${2:-}"; FIO_BIN=$2; shift 2 ;;
            -f?*) opt_val "$opt" -f; FIO_BIN=$OPT_VAL; shift ;;
            -s) need_arg "$1" $# "${2:-}"; SUMMARIZE_FILE=$2; shift 2 ;;
            -s?*) opt_val "$opt" -s; SUMMARIZE_FILE=$OPT_VAL; shift ;;
            -o|--output)   need_arg "$1" $# "${2:-}"; OUTPUT_DIR=$2; shift 2 ;;
            --output=*)    OUTPUT_DIR=${opt#--output=}
                           [ -n "$OUTPUT_DIR" ] || { usage >&2; die "option --output requires a value"; }
                           shift ;;
            -o?*) opt_val "$opt" -o; OUTPUT_DIR=$OPT_VAL; shift ;;
            --line-rate)   need_arg "$1" $# "${2:-}"; LINE_RATE_GBPS=$2
                           # an empty value (an unset variable in a wrapper)
                           # would silently mean "no override"
                           [ -n "$LINE_RATE_GBPS" ] || { usage >&2; die "option --line-rate requires a value"; }
                           shift 2 ;;
            --line-rate=*) LINE_RATE_GBPS=${opt#--line-rate=}
                           [ -n "$LINE_RATE_GBPS" ] || { usage >&2; die "option --line-rate requires a value"; }
                           shift ;;
            -e|--engine)   need_arg "$1" $# "${2:-}"; ENGINE=$2; shift 2 ;;
            --engine=*)    ENGINE=${opt#--engine=}
                           [ -n "$ENGINE" ] || { usage >&2; die "option --engine requires a value"; }
                           shift ;;
            -e?*) opt_val "$opt" -e; ENGINE=$OPT_VAL; shift ;;
            # -p's count is optional like -a's level: consumed only when the
            # next token is a plain positive integer, else it is a server name.
            # A leading zero is rejected too, not normalized: "00" is all
            # digits yet [ "00" -eq 0 ] is true, so it would silently skip
            # the prompts while the key rounds still ran.
            -p|--password)
                PW_COUNT=1
                case "${2:-}" in
                    ("" | *[!0-9]*) ;;
                    (0*) usage >&2; die "-p needs a positive count of login/password pairs, got '$2'" ;;
                    (*) PW_COUNT=$2; shift ;;
                esac
                shift ;;
            --password=*)
                PW_COUNT=${opt#--password=}
                case "$PW_COUNT" in
                    ("" | *[!0-9]* | 0*) usage >&2
                        die "option --password takes a positive count of login/password pairs" ;;
                esac
                shift ;;
            -p?*)
                opt_val "$opt" -p
                PW_COUNT=$OPT_VAL
                case "$PW_COUNT" in
                    (*[!0-9]* | 0*) usage >&2
                        die "option -p takes a positive count of login/password pairs, got '$OPT_VAL'" ;;
                esac
                shift ;;
            # -t's path is optional: the next token is consumed as a path
            # only when it looks like one (contains / or ends .csv) --
            # anything else is a server name. Bare -t resolves to the source
            # set's hostlist.csv, else ./hostlist.csv (see resolve_targets_file).
            -t|--targets)
                TARGETS=1
                # the filesystem decides first: an existing file is a host
                # file whatever it is named; then the path-shaped heuristics
                case "${2:-}" in
                    ("") ;;
                    (*/* | *.csv) TARGETS_PATH=$2; shift ;;
                    (*) if [ -f "$2" ]; then TARGETS_PATH=$2; shift; fi ;;
                esac
                shift ;;
            --targets=*)
                TARGETS=1
                TARGETS_PATH=${opt#--targets=}
                [ -n "$TARGETS_PATH" ] || { usage >&2; die "option --targets requires a value"; }
                shift ;;
            -t?*) TARGETS=1; opt_val "$opt" -t; TARGETS_PATH=$OPT_VAL; shift ;;
            -x|--duration)
                DURATION=${2:-}
                case "$DURATION" in
                    (""|*[!0-9]*|0) usage >&2; die "option -x needs a duration in whole seconds" ;;
                esac
                shift 2 ;;
            --duration=*)
                DURATION=${opt#--duration=}
                case "$DURATION" in
                    (""|*[!0-9]*|0) usage >&2; die "option --duration needs a duration in whole seconds" ;;
                esac
                shift ;;
            -x?*)
                opt_val "$opt" -x; DURATION=$OPT_VAL
                case "$DURATION" in
                    (""|*[!0-9]*|0) usage >&2; die "option -x needs a duration in whole seconds" ;;
                esac
                shift ;;
            -r) FAST_TRACK=1; shift ;;
            -n) DRY_RUN=1; shift ;;
            -g) REGEN_LAYOUT=1; shift ;;
            -u|--unlink) UNLINK=1; shift ;;
            -b|--bulk) BULK=1; shift ;;
            # the load check re-tuned calibrated settings for the fleet run,
            # against calibration's intent (Frank, 2026-10-05): say so
            -l|--load) usage >&2; die "-l/--load was removed: the test runs exactly what calibration measured" ;;
            -a|--auto)
                # bare -a is max, with max's cell length
                set_auto_level max "$1"
                # The level is a keyword, not a value, so it is matched
                # case-insensitively too -- and only consumed when it really is
                # one, otherwise it is the first server name. A ":secs" suffix
                # rides along with the keyword.
                arg=$(lower "${2:-}")
                case "${arg%%:*}" in
                    (safe|max|cal|brutal) set_auto_level "$2" "$1"; shift ;;
                esac
                shift ;;
            --auto=*)
                set_auto_level "${opt#--auto=}" --auto
                shift ;;
            -a?*)
                opt_val "$opt" -a
                set_auto_level "$OPT_VAL" -a
                shift ;;
            --ignore-capacity) IGNORE_CAPACITY=1; shift ;;
            # -i is repeatable and each value may be a comma list of
            # [login:]keyfile combos; entries accumulate in the order given.
            # Validation waits for validate_credentials, once local mode is
            # known. An empty =-form is rejected here: need_arg cannot see it,
            # and silently ignoring --identity= would make the one spelling
            # that looks most deliberate do nothing.
            -i|--identity) need_arg "$1" $# "${2:-}"; IDENT_RAW+=("$2"); shift 2 ;;
            --identity=*)  arg=${opt#--identity=}
                           [ -n "$arg" ] || { usage >&2; die "option --identity requires a value"; }
                           IDENT_RAW+=("$arg"); shift ;;
            -i?*)          opt_val "$opt" -i; IDENT_RAW+=("$OPT_VAL"); shift ;;
            # -C with an attached value names the set outright. Bare -C arms
            # the candidate rule handled by the bare-token arm below.
            -c|--customize)  CUSTOMIZE=1; c_pending=1; shift ;;
            -c?*)            CUSTOMIZE=1; opt_val "$opt" -c; CUSTOM_SET=$OPT_VAL; shift ;;
            --customize=*)   CUSTOMIZE=1; CUSTOM_SET=${opt#--customize=}
                             [ -n "$CUSTOM_SET" ] || { usage >&2; die "option --customize requires a value"; }
                             shift ;;
            -v)   VERBOSITY=$((VERBOSITY + 1)); shift ;;
            -vv)  VERBOSITY=$((VERBOSITY + 2)); shift ;;
            -vvv) VERBOSITY=$((VERBOSITY + 3)); shift ;;
            --version) echo "${0##*/} version $VERSION"; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            -*) usage >&2; die "unknown option: $1" ;;
            *)
                if [ "$c_pending" -eq 1 ] && [ "$dashdash" -eq 1 ]; then
                    # Clients come after --, so this token is the set name.
                    [ -z "$CUSTOM_SET" ] || { usage >&2
                        die "-C takes one set name before --; got '$CUSTOM_SET' and '$1'"; }
                    CUSTOM_SET=$1
                elif [ "$c_pending" -eq 1 ] && [ -z "$C_CANDIDATE" ]; then
                    # The filesystem beats the network: a token with a path
                    # separator, a shipped set name, or an existing set
                    # directory can never be a hostname -- claim it as the
                    # set outright. Probing such tokens over ssh printed
                    # credential warnings on purely local runs. Only a
                    # genuinely ambiguous bare word stays provisional for
                    # preflight's ssh test (see C_CANDIDATE).
                    c_claim=0
                    case "$1" in (*/*) c_claim=1 ;; esac
                    case " $SHIPPED_SETS " in (*" $1 "*) c_claim=1 ;; esac
                    [ ! -d "$SCRIPT_DIR/fio-jobfiles/$1" ] || c_claim=1
                    [ ! -d "./fio-jobfiles/$1" ] || c_claim=1
                    if [ "$c_claim" -eq 1 ]; then
                        CUSTOM_SET=$1
                    else
                        C_CANDIDATE=$1; HOSTS+=("$1")
                    fi
                else
                    HOSTS+=("$1")
                fi
                shift ;;
        esac
    done
    MASTER=${HOSTS[0]:-}

    # Combination checks live here rather than in main so they hold for every
    # caller -- the test suite drives parse_args directly.
    if [ -n "$SUMMARIZE_FILE" ]; then
        [ "$CUSTOMIZE" -eq 0 ] || { usage >&2; die "-C cannot be combined with -s"; }
        # -r no longer takes a report-items list; -s always prints all of them.
        # Silently accepting the old form would demote its argument to a
        # hostname, so name the change instead.
        [ "$FAST_TRACK" -eq 0 ] || { usage >&2
            die "-r cannot be combined with -s; -s now always prints the full summary (the '-r items' filter was removed)"; }
    fi
    if [ -n "$LINE_RATE_GBPS" ]; then
        case "$LINE_RATE_GBPS" in
            (*[!0-9.]*|*.*.*|.)
                usage >&2; die "--line-rate takes the line rate in Gb/s, a positive number such as 16 or 12.5: '$LINE_RATE_GBPS'" ;;
        esac
        # bounded: a figure under 8e-9 would turn into a 0 bytes/s target
        # (no target, and no warning either), and one of ~310 digits into an
        # infinity that crashes the shape grouping after the probes ran
        awk -v v="$LINE_RATE_GBPS" 'BEGIN {v += 0; exit !(v >= 0.1 && v <= 100000)}' \
            || { usage >&2; die "--line-rate must be between 0.1 and 100000 Gb/s: '$LINE_RATE_GBPS'"; }
        # only a calibration's bandwidth search has a target to set
        cal_mode || { usage >&2; die "--line-rate sets the bandwidth target of a calibration: it needs -a"; }
    fi
}

# Measured levels run a calibration phase before staging; safe/max/off never
# do. Both run the same per-shape search (see calibrate):
#   cal     with its early stops -- a ladder ends when it flattens, bandwidth
#           when it reaches line rate, latency when it leaves the floor band
#   brutal  with none: every rung of every ladder is measured, the re-splits
#           run to their caps, and more top cells are re-measured. When the
#           stopping rules are the suspect, the exhaustive search settles it
# Every -a level calibrates (Frank, 2026-10-05): safe and max search numjobs
# only, at fixed iodepth/nrfiles; cal and brutal walk the ladders.
cal_mode()    { case "$AUTO_LEVEL" in (safe|max|cal|brutal) return 0 ;; esac; return 1; }
# the widest job count a level's searches reach, in multiples of N: safe and
# max stop at 2N, cal and brutal climb to 4N (latency stays at N everywhere)
cal_wide()    { case "$AUTO_LEVEL" in (safe|max) echo 2 ;; (*) echo 4 ;; esac; }
brutal_mode() { [ "$AUTO_LEVEL" = brutal ]; }

# Set inspection: which searches does a jobfile set actually need?
# Prints unique sorted lines from exactly {bw read, bw write, iops read,
# iops write, lat read, lat write, lat1m read, lat1m write} -- nothing else
# ever; lat1m only for a 1MiB latency file or, under -b, beside every 4k
# one -- and prints NOTHING
# when the set needs no calibration. That grammar is a contract: the calibration engine and the
# dry-run report both consume these lines verbatim, so an extra ladder is
# wasted measurement time on every client and a missing one silently falls
# back to a guessed queue depth.
#
# Report type comes from the '# report' directive:
#   - 'latency' anywhere in the directive wins the whole file and asks for
#     the latency search only -- N jobs at iodepth 1 over the nrfiles
#     ladder ('# report iops latency' is a latency file). Same rule staging
#     applies to the same file.
#   - otherwise 'bandwidth' -> bw and 'iops' -> iops, and a directive naming
#     both types contributes both.
#   - NO directive at all: no type, so nothing to calibrate -- the file runs
#     as written (Frank, 2026-10-06), as staging leaves it.
# '# report bandwidth iops' asks for one search more than staging applies:
# its precedence is latency > bw > iops, so that file runs the bandwidth
# answer and the iops one only lands in the host file. Over-asking is the
# safe direction (a search nobody applies costs its cells once; one never
# made leaves the jobfile's guess in place for the whole run).
# Direction comes from each job section's effective rw= (the section's own
# value, else [global]'s): read/randread -> read, write/randwrite -> write,
# the mixed forms -> both. A file that names no rw= anywhere contributes no
# direction, hence no ladder.
cal_required() {   # cal_required <setdir> [bulk 0|1]
    local f files=()
    [ -d "$1" ] || { echo "ERROR: cal_required: not a jobfile set directory: $1" >&2; return 1; }
    for f in "$1"/[0-9]*; do [ -f "$f" ] && files+=("$f"); done
    [ ${#files[@]} -gt 0 ] || return 0
    awkrun 'BEGIN {
        bulk = ARGV[1] == "1"; nn = 0
        for (a = 2; a < ARGC; a++) {
            name = ARGV[a]; sub(/.*\//, "", name)
            if ((n = readlines(ARGV[a], L)) < 0) awk_fail("cal_required: cannot read " ARGV[a])
            if (name == layout_job() || is_layout_marked(L, n)) continue   # a layout job measures nothing
            file_directions(L, n, D)
            if (report_has(L, n, "latency")) {
                # a 1MiB latency file is its own search (lat1m), and under
                # -b every 4k latency file gains a 1MiB twin at staging
                kind = lat_kind(L, n)
                for (d in D) {
                    NEED[kind " " d] = 1
                    if (bulk && kind == "lat") NEED["lat1m " d] = 1
                }
                continue
            }
            for (d in D) {
                if (report_has(L, n, "bandwidth")) NEED["bw " d] = 1
                if (report_has(L, n, "iops")) NEED["iops " d] = 1
            }
        }
        for (k in NEED) OUT[++nn] = k
        sort_arr(OUT, nn, 0)
        for (i = 1; i <= nn; i++) print OUT[i]
    }' "${2:-0}" "${files[@]}"
}

# Usable cores for ONE host, by staging's own rule (probe_cores in the
# shared layer) -- the same arithmetic stage_hosts does under -a for its
# cpus_allowed/numjobs stamping, and the one the calibration shapes use to
# size their cells (a divergence would make a measured job count describe a
# cpu set the staged jobs do not run on). ONE rule, in physical cores: every
# core except weka's DPDK cores (with their siblings) and the OS reserve
# (core 0 and its sibling first); see probe_cores.
# count = N, the usable PHYSICAL cores; phys = one thread per usable core,
# where N/2 and N jobs run; list = every thread of them, where 2N and 4N run.
# Fails loudly rather than printing 0: numjobs=0 is no valid fio job, so a
# ladder sized from an unreadable probe must not run.
usable_cores() {   # usable_cores <host> [count|phys|list] [cpulist]
                   # an operator cpu list (the host-file nj contract) is the
                   # base: weka's cores and core 0's pair come out of it,
                   # nothing else -- unless it covers every cpu fio could
                   # use, which counts as no list (see probe_cores)
    [ -f "$WORK_DIR/probe/$1" ] || {
        log "ERROR: usable_cores: no probe facts for $1 ($WORK_DIR/probe/$1)" >&2
        return 1
    }
    awkrun 'BEGIN {
        path = ARGV[1]
        if ((np = readlines(path, P)) < 0) np = 0
        probe_cores(P, np, ARGV[3], R, PHYS, ALL)
        if (R["n"] < 1) awk_fail("usable_cores: " path " leaves fio no cpus: " cores_summary(R, PHYS, ALL))
        if (ARGV[2] == "list") print join_sorted(ALL, ",")
        else if (ARGV[2] == "phys") print join_sorted(PHYS, ",")
        else print R["n"]
    }' "$WORK_DIR/probe/$1" "${2:-count}" "${3:-}" || return 1
}

# WHERE calibration measures: on the workload's own files whenever the set's
# filename_format can express the grid, in a private scratch otherwise.
#
# ONE dataset for calibration and execution. The seed lays out the exact files
# the staged jobs will run on -- same directory, same names, same 5G size --
# so the staged layout pass finds everything already in place, the sweep
# credits it (a file is a deviant only when SMALLER than a section expects,
# and one normalized size means nothing ever is), and the capacity check
# counts it once. Before this, the scratch and the workload layout were two
# copies of much the same data, and calibration measured a layout the test
# never used.
#
# Unified needs a format that can address the grid: both $filenum and $jobnum,
# and no $jobname (which would resolve to the CAL section's name, not the
# workload's). A set without one -- flat formats, single-variable formats --
# falls back to the private scratch exactly as before.
#
# Prints "unified <fmt>" or "scratch $jobnum.$filenum".
cal_namespace() {   # cal_namespace <set-dir>
    local f files=() LC_ALL=C
    [ -d "$1" ] || { log "ERROR: cal_namespace: no set directory $1" >&2; return 1; }
    for f in "$1"/[0-9]*; do
        [ -f "$f" ] && files+=("$f")
    done
    # the first jobfile (byte order) with a grid-addressable format decides;
    # the layout job mirrors the measured ones, so it never does
    awkrun 'BEGIN {
        for (i = 1; i < ARGC; i++) {
            if ((n = readlines(ARGV[i], L)) < 0 || is_layout_marked(L, n)) continue
            fmt = first_value(L, n, "filename_format")
            if (index(fmt, "$filenum") && index(fmt, "$jobnum") && !index(fmt, "$jobname")) {
                print "unified", fmt
                exit 0
            }
        }
        print "scratch", "$jobnum.$filenum"
    }' ${files[@]+"${files[@]}"}
}

# Every directory the scratch's names imply, relative to the scratch root.
# fio never mkdirs, so the caller creates these before the seed writes.
cal_scratch_dirs() {   # cal_scratch_dirs <host> <sep> <fmt> <nj> <maxfilenum>
    awkrun 'BEGIN {
        pat = ARGV[1] ARGV[2] ARGV[3]
        if ((nj = py_int(ARGV[4])) == "" || (maxf = py_int(ARGV[5])) == "")
            awk_fail("cal_scratch_dirs: not a number: " ARGV[4] " " ARGV[5])
        n = 0
        for (j = 0; j < nj; j++)
            for (f = 0; f <= maxf; f++) {
                d = dirname(replace_all(replace_all(pat, "$jobnum", j), "$filenum", f))
                if (d != "" && !(d in seen)) { seen[d] = 1; D[++n] = d }
            }
        sort_arr(D, n, 0)
        for (i = 1; i <= n; i++) out = out (i > 1 ? "\n" : "") D[i]
        print out
    }' "$1" "$2" "$3" "$4" "$5"
}

# Copy a failed seed's evidence into the run dir so it lands in the bundle:
# the workdir is on /dev/shm and is removed on exit, so anything left there
# is gone before anyone can read the path the error printed.
# The error text from a server-side jobfile rejection never reaches the
# operator: fio --client exits 0 and the daemonized server's stderr is gone,
# so the run dies with "the jobs did not run" and nothing else. Ask the
# host's own fio to re-parse the jobfile it just ran (or refused): a dirty
# parse names the bad option here and now; a clean parse means the jobs died
# at setup, not at option parsing. The output lands in the run bundle.
fio_parse_postmortem() {   # fio_parse_postmortem <what> <host> <remote-jobfile> <outfile>
    local what=$1 host=$2 jf=$3 outf=$4 l
    if run_host "$host" "'$FIO_BIN' --parse-only '$jf'" > "$outf" 2>&1; then
        log "note: $host: the $what jobfile parses cleanly on its host -- the jobs died at setup, not at option parsing" >&2
    else
        log "ERROR: $host: the host's own fio rejects the $what jobfile (full text: ${outf##*/} in the run bundle):" >&2
        head -5 "$outf" | while IFS= read -r l; do
            log "ERROR: $host:   $l" >&2
        done
    fi
}

# A failed calibration fio run (a seed or a cell) leaves its
# evidence in the run bundle: $WORK_DIR is tmpfs and wiped on exit, so a die
# pointing there named a file the operator could never open (seen live on
# the seed, then again on a rung: field client C, 2026-09-09). Copies the fio
# output and every host's jobfile under cal/, and asks each host's fio to
# parse the jobfile so a rejected option is named. With "say", fio's own
# text -- the lines it prints before, or instead of, the JSON -- is searched
# for the cause and said now; the check_fio_errors path passes "quiet"
# because it has already surfaced those lines itself.
cal_evidence() {   # cal_evidence <what> <results.json> <jobfile-basename> <say|quiet> <host>...
    local what=$1 res=$2 jf=$3 say=$4 h l shown=0
    shift 4
    [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || return 0
    mkdir -p "$RUN_DIR/cal" || return 0
    [ ! -s "$res" ] || cp "$res" "$RUN_DIR/cal/" || true
    for h in "$@"; do
        [ ! -s "$WORK_DIR/cal/$h/$jf" ] \
            || cp "$WORK_DIR/cal/$h/$jf" "$RUN_DIR/cal/${jf%.job}.$h.job" || true
    done
    if [ "$say" = say ] && [ -s "$res" ]; then
        # One line per DISTINCT error with a job count, not the first five of
        # a hundred identical ones: how MANY jobs failed the same way is the
        # most useful fact about the failure, and a flat five-line cap hid it
        # (seen live: five cpu_set_affinity lines out of an unknown number).
        # The pid varies per job, so it is normalized for counting only --
        # the line itself is still shown verbatim, first occurrence.
        shown=0
        while IFS= read -r l; do
            [ -n "$l" ] || continue
            log "$l" >&2
            shown=$((shown + 1))
        done <<EVIDEOF
$(LC_ALL=C awk -v what="$what" '
    /^\{/ { exit }
    /[Ee]rror|ERROR|[Ff]ailed|err=/ {
        k = $0; gsub(/pid=[0-9]+/, "pid=<n>", k)
        if (!(k in n)) { order[++d] = k; sample[k] = $0 }
        n[k]++
    }
    END {
        for (i = 1; i <= d && i <= 5; i++) {
            k = order[i]
            printf "ERROR: %s: fio said%s: %s\n", what,
                (n[k] > 1 ? sprintf(" (%d jobs)", n[k]) : ""), sample[k]
        }
        if (d > 5)
            printf "ERROR: %s: and %d more distinct error line(s) in the fio output\n", what, d - 5
    }' "$res")
EVIDEOF
        [ "$shown" -gt 0 ] || log "ERROR: $what: fio printed no error line before exiting; see ${res##*/} in the run bundle under cal/" >&2
    fi
    for h in "$@"; do
        [ -s "$WORK_DIR/cal/$h/$jf" ] || continue
        # fio --client hands jobfiles to the workers over its own protocol,
        # so cal_push staged them on the MASTER only; a worker's fio can
        # only parse what the worker has. Stage this host's copy there
        # first (the master already holds it).
        if [ "$h" != "$MASTER" ]; then
            run_host "$h" "mkdir -p '$TARGET_DIR.cal/$h'" \
                && copy_to_host "$h" "$WORK_DIR/cal/$h/$jf" "$TARGET_DIR.cal/$h/" \
                || { log "WARNING: $h: cannot stage the $what jobfile for a parse check on that host" >&2
                     continue; }
        fi
        fio_parse_postmortem "$what" "$h" "$TARGET_DIR.cal/$h/$jf" \
            "$RUN_DIR/cal/parse.$h.out"
    done
}


# The calibration scratch namespace, under each host's own destination dir.
CAL_SCRATCH=".wekatester-cal"

# --- calibration: per client shape, solo, one search per test type -----------
# WHAT IS OPTIMIZED (Frank's rulings, 2026-09-23). -a exists so that when the
# fleet-wide run starts, every client runs the parameters that give ITS
# hardware its absolute best result per test type, and the run then shows
# what the weka cluster can do -- the cluster is assumed to have far more
# headroom than its clients can consume.
#   bandwidth  as close to the client's NIC line rate as it gets, on 1MiB IO
#              (the block size weka moves between clients and backends, so
#              not a lever); "reached" is CAL_LINE_PCT (95) percent of it
#   iops       the client's maximum 4k random IOPS, with fio's latency
#              accounting off -- the iops test records no latency
#   latency    N jobs (one per physical core) at queue depth 1, the nrfiles
#              ladder only, the lowest mean wins (Frank, 2026-10-05); the
#              one-job twin runs beside it in the measured run. Under -b the
#              same again at 1MiB blocks (lat1m), its own test and slot.
#
# WHERE IT IS MEASURED. Clients are grouped into SHAPES by their hardware --
# cpu model and count, memory, weka's pinned cores, and the NICs weka uses
# with their ethtool link speeds -- plus the cpus and engines fio may use
# there (a job count means nothing without the cpu set it runs on). Each
# shape is calibrated on ONE representative, the first host of that shape on
# the command line, ALONE: nothing else runs while a shape is measured, so a
# number is that client's ceiling rather than its share of a contended fleet.
# Shapes run one after another, and a shape's answer is written for every
# member. The fleet-wide measured jobs are unchanged: they run every host at
# once, on those answers.
#
# HOW. Per shape: one engine, then one search per (type, direction) the set
# runs. The engine is chosen first by short comparison cells, one per type
# and candidate, the winners tallied (ENGINE_ORDER breaks ties) -- one engine
# per client, because the host file carries one, and every search then runs
# on the engine the staged jobs will use. cal_plan holds every search rule:
# it reads the history of readings and names the next cell, bash runs it,
# until the planner says done. The recorded tuple is (qd nr fs nj), with nj
# always written down: bandwidth's answer IS a job count, and so is latency's.
#
# THE JOB COUNTS (Frank, 2026-09-25) come from N, the client's usable
# PHYSICAL cores (probe_cores: every core minus weka's DPDK cores and the OS
# reserve). N/2 and N jobs run one per physical core with the siblings idle;
# 2N and 4N run on the siblings too, which is how a search learns whether
# they help or hurt. nrfiles walks CAL_NR_LADDER, iodepth
# CAL_BW_QD_LADDER or CAL_IOPS_QD_LADDER.
#
# `-a brutal` is the same search with every early stop disabled: every
# combination of numjobs, iodepth and nrfiles the ladders define is measured,
# and more cells are re-measured before a peak is picked.
CAL_RUNTIME_FROM_ENV=${CAL_RUNTIME:+1}   # an exported CAL_RUNTIME beats the level default
CAL_RUNTIME=${CAL_RUNTIME:-30}   # seconds per search cell (plus a 2s ramp);
                         # "-a cal:15" sets it per run. It does not change how
                         # long the measured jobs run -- that is -x.
CAL_ENGINE_RUNTIME=${CAL_ENGINE_RUNTIME:-10}   # seconds per engine-comparison
                         # cell: they only have to rank the engines, and the
                         # searches that follow run full length
CAL_SETTLE=${CAL_SETTLE:-10}   # seconds after every write cell and after a
                         # seed: a write leaves a destage backlog, and the next
                         # cell would start inside it (seen live: every read
                         # surface smooth while the write surfaces carried the
                         # previous cell's debt; at 5s cells a whole write grid
                         # came back a checkerboard)
# ONE amount of data per job everywhere. Every seeded file is 5G, and every
# calibration cell -- and through the measured tuples the writeback records,
# every staged test -- gives each job 5G of data, split over its files
# (nrfiles=2 runs 2 x 2560M, nrfiles=4 4 x 1280M, each the leading part of a
# 5G file), so a number from any level is comparable with any other and the
# sweep's size floor is satisfied by construction. The working set is part of
# the measurement: on field client A (2026-08-24) the same staged iops-write geometry
# delivered 7.5% differently at fs=256M vs fs=1024M, and WEKAPP-289548 saw 4k
# random reads lose 30% from 1M files to 3G files -- so the file ladder moves
# the file count and nothing else. A host file that pins its own fs still
# wins, as host files always do.
FILESIZE_MIB=${FILESIZE_MIB:-5120}
CAL_NR=${CAL_NR:-1}      # files per job in the first cell of every search,
                         # and in every latency cell: at iodepth 1 one IO is in
                         # flight per job, so more files add no concurrency
CAL_NR_LADDER=${CAL_NR_LADDER:-"1 2 4"}   # nrfiles tried per job count: at
                         # 2N and 4N for bandwidth, at every count for iops
CAL_BW_QD_LADDER=${CAL_BW_QD_LADDER:-"1 2 4 8 16"}   # bandwidth iodepths at
                         # 2N and 4N; at or below N bandwidth runs nrfiles=1
                         # iodepth=1 only (1 is kept at 2N so N x qd1 against
                         # 2N x qd1 isolates what the siblings add)
CAL_IOPS_QD_LADDER=${CAL_IOPS_QD_LADDER:-"1 2 4 8 16 32 64 128 256 512"}
# -a max searches numjobs at these (Frank, 2026-10-05): the largest iodepth
# and nrfiles any cal or brutal search had chosen per type across the labs
# and field runs by then -- bandwidth qd 16 and 4 files, iops qd 32 and 2
# files (a 128 iops pick came only from a re-split rule since removed). -a
# safe searches at 1 and 1.
CAL_MAX_BW_QD=${CAL_MAX_BW_QD:-16}
CAL_MAX_BW_NR=${CAL_MAX_BW_NR:-4}
CAL_MAX_IOPS_QD=${CAL_MAX_IOPS_QD:-32}
CAL_MAX_IOPS_NR=${CAL_MAX_IOPS_NR:-2}
CAL_LINE_PCT=${CAL_LINE_PCT:-95}   # bandwidth: line rate counts as reached here
CAL_KNEE_PCT=${CAL_KNEE_PCT:-98.5}   # the engine tie band: engines whose reading
                         # is within this percent of the best are tied, and the
                         # tie goes to ENGINE_ORDER
CAL_SHAPE_THR=${CAL_SHAPE_THR:-3}   # THE LEADER RULE (Frank, 2026-10-05): a cell
                         # takes the lead only when at least this percent better
                         # than the leader -- for bandwidth and iops, at every
                         # level; a ladder ends after CAL_STOP_BELOW rungs in a
                         # row fail to. Latency has no threshold: the lowest mean
                         # wins
CAL_STOP_BELOW=${CAL_STOP_BELOW:-2}   # consecutive rungs without progress that
                         # end a ladder (cal only; brutal measures every rung)
CAL_CONFIRM=${CAL_CONFIRM:-3}   # before a peak is picked, the top cells get a
                         # second reading: contention only subtracts, so a
                         # second chance can raise a cell and never lower it
CAL_MEM_PCT=${CAL_MEM_PCT:-25}   # percent of a client's MemTotal that one cell's
                         # in-flight buffers (numjobs x iodepth x bs) may take:
                         # a backstop for small clients at the deep end of a
                         # queue ladder, named in the log when it bites. Every
                         # step up in jobs or files also widens the seeded
                         # dataset (4N jobs x 4 files x 5G); the seed prices it
                         # before writing a byte and stops if it will not fit.
BRUTAL_CONFIRM=${BRUTAL_CONFIRM:-5}

# The knobs as the planner takes them, one k=v word each; a ladder is one
# comma-joined word.
cal_knobs() {   # cal_knobs [bw|iops|lat|lat1m]: the planner's knobs for this level
    local exh=0 conf=$CAL_CONFIRM fq=- fn=-
    case "$AUTO_LEVEL" in
        (brutal) exh=1; conf=$BRUTAL_CONFIRM ;;
        # safe and max measure three job counts once each: no confirm pass
        (safe) conf=0; fq=1; fn=1 ;;
        (max)  conf=0
               case "${1:-}" in
                   (bw)   fq=$CAL_MAX_BW_QD; fn=$CAL_MAX_BW_NR ;;
                   (iops) fq=$CAL_MAX_IOPS_QD; fn=$CAL_MAX_IOPS_NR ;;
               esac ;;
    esac
    printf '%s ' "lvl=${AUTO_LEVEL:-cal}" "fq=$fq" "fn=$fn" "exh=$exh" "line=$CAL_LINE_PCT" \
        "thr=$CAL_SHAPE_THR" "stop=$CAL_STOP_BELOW" \
        "confirm=$conf" "rt=$CAL_RUNTIME" "nr=$CAL_NR" \
        "nrc=$(printf '%s' "$CAL_NR_LADDER" | tr -s ' ' ',')" \
        "bwqd=$(printf '%s' "$CAL_BW_QD_LADDER" | tr -s ' ' ',')" \
        "iopsqd=$(printf '%s' "$CAL_IOPS_QD_LADDER" | tr -s ' ' ',')"
}

# One calibration cell, staged as a jobfile for ONE host. Pure: every input
# is an argument -- the caller resolved the host's directory, name and cpu set
# once per shape -- so a cell costs no lookups. The cell IS the measurement
# definition: time_based with a 2s ramp, direct=1 so no client cache can
# flatter it, and group_reporting=1, which gives one client_stats entry per
# host instead of one per job (per-job entries made every rung's JSON grow
# with numjobs x hosts). The cpu list always carries split affinity:
# isolcpus cores have no scheduler load balancing, so a RANGE without split
# parks every job on the cpu it forked on (seen live) -- the same rule
# stamp_unique_names applies to the staged jobfiles. A cell never creates a
# file: a creating write cell measures weka's file-extend path, not
# steady-state writes (seen live: 0.7GB/s "knees" on an 18GB/s box), so the
# seed owns creation. iops cells run with fio's latency accounting off, the
# same flags the staged iops jobs carry (and wekawithin has run with for
# years): the iops test records no latency, and the cell measures exactly
# what the test will run.
stage_cal_cell() {   # stage_cal_cell <file> <dir> <name> <cpus> <bw|iops|lat|lat1m> <read|write> <engine> <nj> <qd> <nr> <runtime>
    local f=$1 hd=$2 name=$3 cpus=$4 type=$5 dirn=$6 eng=$7 nj=$8 qd=$9 nr=${10} rt=${11} bs rw v
    case "$type" in
        (bw)       bs=1Mi; rw=$dirn ;;
        (iops|lat) bs=4k;  rw=rand$dirn ;;
        (lat1m)    bs=1Mi; rw=rand$dirn ;;   # -b: the latency test at 1MiB
        (*) die "stage_cal_cell: unknown cell type: $type (bw|iops|lat|lat1m)" ;;
    esac
    case "$dirn" in
        (read|write) ;;
        (*) die "stage_cal_cell: unknown direction: $dirn (read|write)" ;;
    esac
    for v in "$nj" "$qd" "$nr" "$rt"; do
        case "$v" in
            (""|*[!0-9]*|0) die "stage_cal_cell: not a positive whole number: '$v' (numjobs=$nj iodepth=$qd nrfiles=$nr runtime=$rt)" ;;
        esac
    done
    [ -n "$eng" ] || die "stage_cal_cell: no ioengine given"
    mkdir -p "${f%/*}" || die "cannot create ${f%/*}"
    {
        printf '[global]\n'
        printf 'directory=%s%s\n' "$hd" "${CAL_NS_DIR-/$CAL_SCRATCH}"
        printf 'unique_filename=0\n'
        # unified reads measure the SHARED dataset -- every client reads the
        # same files, which is both the realistic fleet workload and what
        # lets one dense read set serve any number of clients. Writes always
        # own their files per client (leases).
        if [ "${CAL_NS_DIR-unset}" = "" ] && [ "$dirn" = read ]; then
            printf 'filename_format=shared.%s\n' "${CAL_FMT:-\$jobnum.\$filenum}"
        else
            printf 'filename_format=%s%s%s\n' "$name" "${CAL_SEP:-.cal.}" "${CAL_FMT:-\$jobnum.\$filenum}"
        fi
        printf 'ioengine=%s\n' "$eng"
        printf 'direct=1\n'
        printf 'bs=%s\n' "$bs"
        # a job's data stays FILESIZE_MIB however many files it is split over:
        # the file ladder measures the file count, not a bigger working set
        if [ -n "${CAL_PIN_FS:-}" ]; then
            printf 'filesize=%s\n' "$CAL_PIN_FS"   # pinned by the host file, as written
        else
            printf 'filesize=%sM\n' "$(( FILESIZE_MIB / nr > 0 ? FILESIZE_MIB / nr : 1 ))"
        fi
        printf 'nrfiles=%s\n' "$nr"
        printf 'numjobs=%s\n' "$nj"
        printf 'iodepth=%s\n' "$qd"
        printf 'time_based=1\n'
        printf 'runtime=%s\n' "$rt"
        printf 'ramp_time=2\n'
        printf 'group_reporting=1\n'
        if [ "$type" = iops ]; then
            printf 'disable_lat=1\ndisable_clat=1\ndisable_slat=1\nnorandommap=1\n'
        fi
        if [ -n "$cpus" ]; then
            printf 'cpus_allowed=%s\n' "$cpus"
            printf 'cpus_allowed_policy=split\n'
        fi
        printf '[cal-%s-%s]\n' "$type" "$dirn"
        printf 'rw=%s\n' "$rw"
    } > "$f" || die "cannot write the calibration cell $f"
}

# Per-client value for one cell: prints "<host> <value>" for every client in
# <cur>, sorted, where value is read+write summed -- bytes/sec in bw mode,
# ios/sec in iops mode.
#
# WHICH entries count: every job of the cal section, SUMMED per host. Cells
# carry group_reporting=1, so there is one entry per host; without it fio's
# client JSON carries one entry per job, and the summarizer's last-entry-per-
# host rule (built to pick a SECTION among several) silently kept 1 job of 28
# here and reported knees 28x low (seen live: 0.6GB/s "knees" that were
# 16GB/s aggregates). Summing keeps both shapes right. Only entries named
# cal-* count, so aggregates ("All clients") and any foreign section can
# never pollute the sum.
cal_values() {   # cal_values <cur.json> <bw|iops>
    local key
    case "$2" in (bw) key=bw_bytes ;; (iops) key=iops ;;
        (*) echo "ERROR: cal_values: unknown mode: $2 (bw|iops)" >&2; return 1 ;; esac
    [ -r "$1" ] || { echo "ERROR: cal_values: cannot read $1" >&2; return 1; }
    json_use "$1"
    case $JSON_RC in
        2) echo "ERROR: cal_values: no JSON in $1" >&2; return 1 ;;
        3) [ -z "$JSON_ERR" ] || echo "$JSON_ERR" >&2
           echo "ERROR: cal_values: cannot parse fio JSON in $1" >&2; return 1 ;;
    esac
    printf '%s\n' "$JSON_FLAT" | LC_ALL=C awk -F'\t' -v key="$key" -v path="$1" '
        function idx(p,   a) { split(p, a, "."); return a[2] }
        $1 ~ /^client_stats\.[0-9]+\.jobname$/ { job[idx($1)] = $2 }
        $1 ~ /^client_stats\.[0-9]+\.hostname$/ { host[idx($1)] = $2 }
        $1 ~ ("^client_stats\\.[0-9]+\\.(read|write)\\." key "$") { v[idx($1)] += $2 }
        END {
            for (i in job) if (substr(job[i], 1, 4) == "cal-") {
                h = (i in host) ? host[i] : "?"; tot[h] += v[i]; any = 1 }
            if (!any) { printf "ERROR: cal_values: %s carries no cal job stats\n", path > "/dev/stderr"; exit 1 }
            # %.0f, not %d: Ubuntu mawk (1.3.4 20200120) clamps %d at
            # 2^31-1, and a client past ~2.1 GB/s then read 2147483647
            for (h in tot) printf "%s %.0f\n", h, tot[h] | "LC_ALL=C sort"
        }'
}

# Per-client latency cell result: "<host> <mean-us> <iops>" -- fio's total
# latency (lat_ns: submission plus completion) of the cell's direction, and
# the IOPS delivered at it. Entries of one host are folded together weighted
# by their IO count, so a cell without group_reporting still reads right.
cal_lat_values() {   # cal_lat_values <json> <read|write>
    [ -r "$1" ] || { echo "ERROR: cal_lat_values: cannot read $1" >&2; return 1; }
    json_use "$1"
    case $JSON_RC in
        2) echo "ERROR: cal_lat_values: no JSON in $1" >&2; return 1 ;;
        3) [ -z "$JSON_ERR" ] || echo "$JSON_ERR" >&2
           echo "ERROR: cal_lat_values: cannot parse fio JSON in $1" >&2; return 1 ;;
    esac
    printf '%s\n' "$JSON_FLAT" | LC_ALL=C awk -F'\t' -v d="$2" -v path="$1" '
        function idx(p,   a) { split(p, a, "."); return a[2] }
        $1 ~ /^client_stats\.[0-9]+\.jobname$/ { job[idx($1)] = $2; order[++n] = idx($1) }
        $1 ~ /^client_stats\.[0-9]+\.hostname$/ { host[idx($1)] = $2 }
        $1 ~ ("^client_stats\\.[0-9]+\\." d "\\.lat_ns\\.mean$") { lat[idx($1)] = $2 }
        $1 ~ ("^client_stats\\.[0-9]+\\." d "\\.total_ios$") { ios[idx($1)] = $2 }
        $1 ~ ("^client_stats\\.[0-9]+\\." d "\\.iops$") { iops[idx($1)] = $2 }
        END {
            # entries in file order: the first per host seeds, the rest fold in by IO count
            for (k = 1; k <= n; k++) {
                i = order[k]
                if (substr(job[i], 1, 4) != "cal-") continue
                h = (i in host) ? host[i] : "?"
                us = lat[i] / 1000.0; io = ios[i] + 0; ip = iops[i] + 0
                if (!(h in seen)) { seen[h] = 1; L[h] = us; I[h] = ip; N[h] = io; continue }
                t = N[h] + io
                if (t > 0) L[h] = (L[h] * N[h] + us * io) / t
                I[h] += ip; N[h] = t
            }
            for (h in seen) { any = 1; printf "%s %.3f %.0f\n", h, L[h], I[h] | "LC_ALL=C sort" }
            if (!any) { printf "ERROR: cal_lat_values: %s carries no cal job stats\n", path > "/dev/stderr"; exit 1 }
        }'
}

# Fill '-' geometry in targets.final from the measured tuples, one precedence
# slot BELOW the operator: CLI > host file > calibration > tuner. The shape's
# engine fills the engine column the same way. When no host file is in play
# targets.final does not exist -- synthesize it with every other field '-' so
# the tuples ride the exact application path the host file uses (the
# tuner's per-slot geometry, and the -a writeback after it).
apply_cal_results() {
    [ -s "$WORK_DIR/cal.results" ] || return 0
    # -g forces a re-measure -- and a re-measure someone forced should WIN:
    # its tuples replace host-file values instead of only filling gaps. So
    # does --line-rate's, for the bandwidth slots it measured again.
    awkrun 'BEGIN {
        res = ARGV[1]; final = ARGV[2]; force = ARGV[3] == "1"; lr = ARGV[4] != "-"
        nslot = split(geom_slots(), SLOT, " ")
        n = split(line_rate_slots(), F, " ")
        for (i = 1; i <= n; i++) LRS[F[i]] = 1
        ncols = 5 + 4 * nslot   # the host, login engine cpus dir, then nj fs nr qd per slot
        if ((n = readlines(res, L)) < 0) awk_fail("cannot read " res)
        nk = 0
        for (i = 1; i <= n; i++) {
            if (!(m = cal_results_split(L[i], F))) continue
            if (!(F[1] in KH)) KHOST[++nk] = F[1]
            KH[F[1]] = 1
            for (c = 2; c <= m; c++) K[F[1], c] = F[c]
        }
        no = 0
        if ((n = readlines(final, T)) >= 0)
            for (i = 1; i <= n; i++) { lsplit(T[i], F, "\t"); ROW[F[1]] = T[i]; ORD[++no] = F[1] }
        sort_arr(KHOST, nk, 0)
        for (x = 1; x <= nk; x++) {
            h = KHOST[x]
            if (h in ROW) nc = lsplit(ROW[h], R, "\t")
            else { split("", R); R[1] = h; nc = 1; ORD[++no] = h }
            while (nc < ncols) R[++nc] = "-"
            if (K[h, 2] != "-" && (force || R[3] == "-")) R[3] = K[h, 2]
            for (s = 1; s <= nslot; s++) {
                # The host file values pinned the search (cal_shapes), so the
                # measured tuple already carries them: fill mode adds only
                # what was searched, and every field of the row was measured
                # together. cal.results holds qd nr fs nj, the row nj fs nr qd.
                c = 3 + 4 * (s - 1); b = 6 + 4 * (s - 1)
                win = force || (lr && (SLOT[s] in LRS))
                for (q = 0; q < 4; q++)
                    if ((v = K[h, c + q]) != "-" && (win || R[b + 3 - q] == "-")) R[b + 3 - q] = v
            }
            row = R[1]
            for (c = 2; c <= nc; c++) row = row "\t" R[c]
            ROW[h] = row
        }
        for (i = 1; i <= no; i++) OUT[i] = ROW[ORD[i]]
        if (no) writelines(final, OUT, no)
        else { printf "" > final; close(final) }
    }' "$WORK_DIR/cal.results" "$WORK_DIR/targets.final" "$REGEN_LAYOUT" "${LINE_RATE_GBPS:--}" \
        || die "cannot apply the calibration results"
}

# Only the cell's own file belongs on the master -- the per-host dirs
# accumulate every staged cell, so shipping whole dirs would grow with every
# cell measured. One staging tree, one scp per push.
cal_push() {   # cal_push <basename> <host>...
    local base=$1 h dirs=(); shift
    rm -rf "$WORK_DIR/cal/.push" || return 1
    for h in "$@"; do dirs+=("$WORK_DIR/cal/.push/$h"); done
    mkdir -p "${dirs[@]}" || return 1
    # one awk copies every host's jobfile: a seed can name the whole fleet,
    # and a cp per host was a process per host
    awkrun 'BEGIN {
        for (a = 3; a < ARGC; a++) {
            src = ARGV[1] "/" ARGV[a] "/" ARGV[2]
            if ((n = readlines(src, L)) < 0) awk_fail("cannot read " src)
            writelines(ARGV[1] "/.push/" ARGV[a] "/" ARGV[2], L, n)
        }
    }' "$WORK_DIR/cal" "$base" "$@" || return 1
    copy_to_master "$WORK_DIR/cal/.push"/* "$TARGET_DIR.cal/"
}

# One line of the pre-seed estimate: what this host's seed will write, and
# against how much free space. MiB in, prose out.
seed_estimate_line() {   # seed_estimate_line <nfiles> <nmib> <ntrunc> <availmib|""> <dir>
    if [ "$1" -eq 0 ] && [ "$3" -eq 0 ]; then
        printf 'dataset already complete, nothing to write'
        return 0
    fi
    LC_ALL=C awk -v n="$1" -v mib="$2" -v t="$3" -v av="$4" -v d="$5" '
        function human(m) { return m >= 1048576 ? sprintf("%.1f TiB", m / 1048576) : sprintf("%.1f GiB", m / 1024) }
        BEGIN {
        printf "%d dense file(s) = %s to write, %d sparse truncate(s)", n, human(mib), t
        if (av == "") printf "; free space at %s unknown", d
        else printf "; free %s at %s (%.1f%% of it)", human(av), d, (av > 0 ? mib * 100 / av : 0)
    }'
}

# Seed ONE representative's calibration dataset, incrementally: a file that
# already exists at or above FILESIZE_MIB is left alone, so a re-run against
# a warm dataset writes nothing. Size is a sufficient test for the same
# reason it is for the main layout -- the seed job sets fallocate=none, so a
# partial write leaves a SHORT file that fails the test, never a full-size
# hollow one that passes it. The requirement is explicit: jobs j < <nj> each
# with files f < <nr>, for the read side and the write side separately.
#
# In the unified namespace the READ side is the fleet-shared dataset
# ("shared.<fmt>": every client's read cells and staged read jobs open the
# same files) and the WRITE side is the host's own files, because concurrent
# cross-client writes to shared files measure lease arbitration, not the
# client. A write side whose calibration writes are all sequential is
# truncate-seeded (sparse; measured on field client A 2026-08-25 at -0.8% vs dense,
# inside the run-to-run band -- a metadata op, not a layout); any 4k random
# write phase forces the dense seed, because holes cost a measured 6.7% on
# the extent-map insert. The scratch fallback keeps both sides on the host's
# own files, dense.
#
# The estimate goes out BEFORE a byte is written, and a seed that would not
# fit in the free space at the destination stops right there.
cal_seed_rep() {   # cal_seed_rep <host> <read-nj> <read-nr> <write-nj> <write-nr> <dense-write 0|1> <engine> <cpus>
    local host=$1 rnj=$2 rnr=$3 wnj=$4 wnr=$5 dense=$6 eng=$7 cpus=$8
    local hd root unified=0 want nfiles nmib ntrunc src totkb availmib maxf subdirs sd cmd
    local tlist tmib tn tchunk wantnj tag job res
    tag=all
    if [ "$wnj" -eq 0 ]; then tag=read; elif [ "$rnj" -eq 0 ]; then tag=write; fi
    job="cal-seed-$tag.job"; res="$WORK_DIR/cal/res-seed-$tag.json"
    hd=$(host_dir "$host")
    root="$hd${CAL_NS_DIR-/$CAL_SCRATCH}"
    host_name_v "$host"
    local hname=$HOST_NAME
    [ "${CAL_NS_DIR-unset}" != "" ] || unified=1
    mkdir -p "$WORK_DIR/cal/$host" || die "cannot create $WORK_DIR/cal/$host"
    rm -f "$WORK_DIR/cal/$host/truncfail"
    # What exists, and how much room is left, in one session. No error
    # suppression on the find: one without GNU -printf must fail LOUDLY, or
    # an empty listing silently re-seeds everything every run; the -d guard
    # covers the one legitimate empty case.
    run_host "$host" "if [ -d '$root' ]; then find '$root' -type f -printf '%P %s\\n'; fi; echo WEKATESTER_DF; df -Pk '$hd' | awk 'NR==2 {print \$1, \$2, int(\$4/1024)}'" \
        > "$WORK_DIR/cal/$host/scratch.raw" \
        || die "$host: cannot inspect the calibration dataset or its free space"
    awk '/^WEKATESTER_DF$/ {exit} {print}' "$WORK_DIR/cal/$host/scratch.raw" > "$WORK_DIR/cal/$host/scratch.list"
    awk 'f {print; exit} /^WEKATESTER_DF$/ {f = 1}' "$WORK_DIR/cal/$host/scratch.raw" > "$WORK_DIR/cal/$host/dfline"
    # fio never mkdirs. A flat shape needs nothing beyond the dataset root; a
    # subdirectory shape needs its directories before a file lands in them.
    maxf=$rnr; [ "$wnr" -le "$maxf" ] || maxf=$wnr
    wantnj=$wnj
    [ "$unified" -eq 1 ] || [ "$rnj" -le "$wantnj" ] || wantnj=$rnj
    subdirs=""
    if [ "$maxf" -gt 0 ] && [ "$wantnj" -gt 0 ]; then
        subdirs=$(cal_scratch_dirs "$hname" "${CAL_SEP:-.cal.}" \
                      "${CAL_FMT:-\$jobnum.\$filenum}" "$wantnj" $((maxf - 1))) \
            || die "$host: cannot derive the calibration namespace directories"
    fi
    if [ "$unified" -eq 1 ] && [ "$rnj" -gt 0 ] && [ "$rnr" -gt 0 ]; then
        subdirs="$subdirs
$(cal_scratch_dirs shared "." "$CAL_FMT" "$rnj" $((rnr - 1)))" \
            || die "$host: cannot derive the shared dataset directories"
    fi
    cmd="mkdir -p"
    while IFS= read -r sd; do
        [ -n "$sd" ] || continue
        cmd="$cmd '$root/$sd'"
    done <<SUBDIREOF
$subdirs
SUBDIREOF
    if [ "$cmd" != "mkdir -p" ]; then
        run_host "$host" "$cmd" \
            || die "$host: cannot create the calibration namespace subdirectories"
    fi
    tlist="$WORK_DIR/cal/$host/truncate.list"
    # Who writes: the rep alone, except for the unified READ side, which its
    # whole filesystem group shares -- every member's fio server is up and
    # idle while shapes calibrate one at a time, so each takes a slice of
    # the missing files (round robin, by file) into its own view of the one
    # directory, on its own cpus and engine. A member's line is
    # "<host> <dir> <cpus> <engine>"; the rep comes first.
    local members="$WORK_DIR/cal/$host/seed.members" active i gf=- margs=()
    printf '%s\t%s\t%s\t%s\n' "$host" "$root" "$cpus" "$eng" > "$members"
    if [ "$unified" -eq 1 ] && [ "$rnj" -gt 0 ]; then
        # the rest of its group, in host order, each with its destination,
        # cpus and engine: one awk, where each member cost three and a
        # group can be the whole fleet
        load_host_dirs
        [ ! -s "$WORK_DIR/groups" ] || gf="$WORK_DIR/groups"
        for i in "${!HOSTS[@]}"; do margs+=("${HOSTS[$i]}" "${HOST_DIRS[$i]}"); done
        awk 'BEGIN {
            rep = ARGV[1]; eng = ARGV[2]; ng = 0
            # group_members: the groups file says who shares the rep group;
            # without one, every host does
            if (ARGV[3] != "-")
                while ((getline line < ARGV[3]) > 0)
                    if (split(line, F, " ") == 2) { ng++; G[F[1]] = F[2] }
            while ((getline line < ARGV[4]) > 0) {
                split(line, F, "\t")
                if (!(F[1] in CPU)) { CPU[F[1]] = F[2]; ENG[F[1]] = F[3] }
            }
            for (a = 5; a + 1 < ARGC; a += 2) {
                m = ARGV[a]
                if (m == rep) continue
                if (ng && !((rep in G) && (m in G) && G[m] == G[rep])) continue
                printf "%s\t%s\t%s\t%s\n", m, ARGV[a + 1], CPU[m], (ENG[m] != "" ? ENG[m] : eng)
            }
        }' "$host" "$eng" "$gf" "$WORK_DIR/cal/hostinfo" "${margs[@]}" >> "$members" \
            || die "$host: cannot list its filesystem group for the shared seed"
    fi
    # each member's seed jobfile lands in its own directory under cal/: one
    # mkdir for the group, whoever ends up with files to write
    local m mdirs=()
    while IFS=$'\t' read -r m _; do mdirs+=("$WORK_DIR/cal/$m"); done < "$members"
    mkdir -p "${mdirs[@]}" || die "$host: cannot create the seed jobfile directories"
    want=$(awkrun 'BEGIN {
        SEED_ANY_JOB = 2 ^ 30; SEED_CHUNK = 16
        host = ARGV[1]; rnj = ARGV[2] + 0; rnr = ARGV[3] + 0; wnj = ARGV[4] + 0; wnr = ARGV[5] + 0
        fsmib = ARGV[6] + 0; job = ARGV[7]; outdir = ARGV[8]; fmt = ARGV[10]; sep = ARGV[11]
        unified = ARGV[12] == "1"; sparse = unified && ARGV[13] == "0"; tlist = ARGV[14]
        if ((n = readlines(ARGV[9], L)) < 0) awk_fail("cannot read " ARGV[9])
        for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2 && F[2] ~ /^[0-9]+$/) HAVE[F[1]] = F[2] + 0
        # the nrfiles ladder shares, plus any listed need beyond it: what a
        # host-file value pins past the grid
        nrd = needs_listed(RN, needs_ladder(RN, 0, ARGV[15], fsmib, SEED_ANY_JOB), ARGV[17])
        nwr = needs_listed(WN, needs_ladder(WN, 0, ARGV[15], fsmib, SEED_ANY_JOB), ARGV[18])
        if (!unified) {
            # the scratch keeps reads and writes on the same files: one size serves both
            for (i = 1; i <= nwr; i++) for (k = 1; k <= 3; k++) RN[nrd + i, k] = WN[i, k]
            nrd += nwr; nwr = nrd
            for (i = 1; i <= nrd; i++) for (k = 1; k <= 3; k++) WN[i, k] = RN[i, k]
        }
        # what is missing: the read side, then the write side; a file both
        # sides name is seeded once
        ntodo = 0; nread = 0; nt = 0; tmib = 0
        for (j = 0; j < rnj; j++)
            for (f = 0; f < rnr; f++) {
                name = seed_name(unified ? "shared." : host sep, fmt, j, f)
                if (!(mib = seed_size(RN, nrd, j, f))) mib = int(fsmib / rnr) > 1 ? int(fsmib / rnr) : 1
                if ((name in SEEN) || ((name in HAVE) && HAVE[name] >= mib * 1048576)) continue
                SEEN[name] = 1; nread++
                TJ[++ntodo] = j; TN[ntodo] = name; TM[ntodo] = mib; tmib += mib
            }
        for (j = 0; j < wnj; j++)
            for (f = 0; f < wnr; f++) {
                name = seed_name(host sep, fmt, j, f)
                if (!(mib = seed_size(WN, nwr, j, f))) mib = int(fsmib / wnr) > 1 ? int(fsmib / wnr) : 1
                if ((name in SEEN) || ((name in HAVE) && HAVE[name] >= mib * 1048576)) continue
                SEEN[name] = 1
                if (sparse) { TR[++nt] = name " " mib; continue }
                TJ[++ntodo] = j; TN[ntodo] = name; TM[ntodo] = mib; tmib += mib
            }
        if (nt) writelines(tlist, TR, nt)
        else { printf "" > tlist; close(tlist) }
        nm = 0
        if ((n = readlines(ARGV[16], L)) < 0) awk_fail("cannot read " ARGV[16])
        for (i = 1; i <= n; i++) {
            if (strip(L[i]) == "") continue
            if (lsplit(L[i], F, "\t") != 4) awk_fail("a seed member line needs host, dir, cpus and engine: " L[i])
            nm++; MH[nm] = F[1]; MD[nm] = F[2]; MC[nm] = F[3]; ME[nm] = F[4]
        }
        # the unified read side round robin over the members, by file; the
        # rest to the rep
        for (k = 1; k <= ntodo; k++) {
            m = (unified && k <= nread) ? MH[(k - 1) % nm + 1] : MH[1]
            SH[m, ++SC[m]] = k
        }
        active = ""
        for (i = 1; i <= nm; i++) {
            m = MH[i]
            if (!SC[m]) continue
            # fallocate=none: see generate_layout -- the incremental skip
            # trusts size, which is only sound if a partial write leaves a
            # short file.
            no = 0; split("", O)
            O[++no] = "[global]"; O[++no] = "directory=" MD[i]; O[++no] = "unique_filename=0"
            O[++no] = "ioengine=" ME[i]; O[++no] = "direct=1"; O[++no] = "bs=1Mi"; O[++no] = "rw=write"
            O[++no] = "fallocate=none"; O[++no] = "create_on_open=1"
            if (MC[i] != "") { O[++no] = "cpus_allowed=" MC[i]; O[++no] = "cpus_allowed_policy=split" }
            # One section per file blew straight through fio REAL_MAX_JOBS
            # (4096) the first time a wide dataset was seeded: 52 jobs x 128
            # files = 6656 sections, dead at parse two seconds in (field
            # client B, 2026-08-24). A section seeds up to SEED_CHUNK files
            # of one size through a colon-joined filename list -- the
            # incremental skip stays exact (only files that failed the size
            # test are listed), and the chunk keeps the option line far
            # below the 4096-byte fio parser buffer.
            split("", GK); split("", GC); split("", GN); ng = 0
            for (x = 1; x <= SC[m]; x++) {
                k = SH[m, x]; g = sprintf("%012d %012d", TJ[k], TM[k])
                if (!(g in GC)) { GK[++ng] = g; GC[g] = 0 }
                GN[g, ++GC[g]] = TN[k]
            }
            sort_arr(GK, ng, 0)
            sections = 0
            for (x = 1; x <= ng; x++) {
                g = GK[x]; split(g, P, " ")
                for (c = 0; c < GC[g]; c += SEED_CHUNK) {
                    s = GN[g, c + 1]
                    for (y = c + 2; y <= GC[g] && y <= c + SEED_CHUNK; y++) s = s ":" GN[g, y]
                    sections++
                    O[++no] = sprintf("[seed-%d-%dM-%d]", P[1], P[2], c / SEED_CHUNK)
                    O[++no] = "filename=" s; O[++no] = "nrfiles=" (y - c - 1); O[++no] = "filesize=" (P[2] + 0) "M"
                }
            }
            if (sections > 4000)
                awk_fail(m ": the seed needs " sections " fio sections and fio caps a run at 4096 jobs; shorten CAL_NR_LADDER or mount weka with more cores (a smaller N)")
            writelines(outdir "/" m "/" job, O, no)
            active = active (active == "" ? "" : " ") m
        }
        printf "%d %.0f %d\n", ntodo, tmib, nt
        print active
    }' "$hname" "$rnj" "$rnr" "$wnj" "$wnr" "$FILESIZE_MIB" \
        "$job" "$WORK_DIR/cal" "$WORK_DIR/cal/$host/scratch.list" \
        "${CAL_FMT:-\$jobnum.\$filenum}" "${CAL_SEP:-.cal.}" "$unified" "$dense" \
        "$tlist" "$CAL_NR $CAL_NR_LADDER" "$members" \
        "$WORK_DIR/cal/needs.read.$(group_first "$host")" "$WORK_DIR/cal/needs.write.$host" \
        ) || die "$host: cannot build the calibration seed"
    read -r nfiles nmib ntrunc <<<"${want%%$'\n'*}"
    active=""; [ "$want" = "${want#*$'\n'}" ] || active=${want#*$'\n'}
    read -r src totkb availmib < "$WORK_DIR/cal/$host/dfline" || true
    case "$availmib" in (""|*[!0-9]*) availmib="" ;; esac
    local side="dataset" by=""
    if [ "$wnj" -eq 0 ]; then
        side="read set"; [ "$unified" -eq 0 ] || side="shared read set"
    elif [ "$rnj" -eq 0 ]; then
        side="write set"
    fi
    set -- $active
    [ "$#" -le 1 ] || by=" across $# client(s) of its filesystem group"
    log "cal: seed estimate: $host ($side, ${rnj:-0}x${rnr:-0} read + ${wnj:-0}x${wnr:-0} write jobs x files$by): $(seed_estimate_line "${nfiles:-0}" "${nmib:-0}" "${ntrunc:-0}" "$availmib" "$hd")"
    if [ "${nmib:-0}" -gt 0 ]; then
        if [ -z "$availmib" ]; then
            log "WARNING: $host: cannot read free space on $hd; seeding anyway" >&2
        elif [ "$nmib" -gt "$availmib" ]; then
            die "$host: the calibration dataset needs ${nmib}MiB and $hd has ${availmib}MiB free; free space under the destination, shrink FILESIZE_MIB, shorten CAL_NR_LADDER, or drop -a $AUTO_LEVEL"
        fi
    fi
    if [ "${ntrunc:-0}" -gt 0 ]; then
        # sparse write canvases: st_size set by truncate, bytes land as the
        # write cells put them there. One pass per file size, chunked so the
        # command string stays small.
        for tmib in $(awk '{print $2}' "$tlist" | sort -un); do
            awk -v s="$tmib" '$2 == s {print $1}' "$tlist" | while IFS= read -r tn || [ -n "$tn" ]; do
                printf "'%s' " "$tn"
            done | xargs -n 64 | while IFS= read -r tchunk; do
                run_host "$host" "cd '$root' && truncate -s ${tmib}M $tchunk" \
                    || { echo TRUNCFAIL > "$WORK_DIR/cal/$host/truncfail"; break; }
            done
        done
        [ ! -f "$WORK_DIR/cal/$host/truncfail" ] \
            || die "$host: cannot truncate-seed the write set"
        log "cal: $host: truncate-seeded ${ntrunc} write file(s) (sequential-write-only set)"
    fi
    [ "${nfiles:-0}" -gt 0 ] && [ -n "$active" ] || return 0
    cal_push "$job" $active || die "cannot copy the calibration seed to $MASTER"
    log "cal: seeding $host's calibration $side${by}..."
    cmd="${COORD_NOFILE:+ulimit -Sn $COORD_NOFILE && }'$FIO_BIN' --output-format=json --eta=never"
    for m in $active; do cmd="$cmd --client=$m '$TARGET_DIR.cal/$m/$job'"; done
    # a failed seed must leave its evidence somewhere that survives the
    # workdir cleanup: /dev/shm/wt.* is wiped on exit
    # shellcheck disable=SC2086 -- active is a list of host names
    if ! run_host "$MASTER" "$cmd" > "$res"; then
        cal_evidence seed "$res" "$job" say $active
        die "calibration seed failed (${res##*/} and $job are in the run bundle under cal/)"
    fi
    if ! check_fio_errors "$res" layout; then
        cal_evidence seed "$res" "$job" quiet $active
        die "calibration seed errored on $host (${res##*/} and $job are in the run bundle under cal/)"
    fi
    sleep "$CAL_SETTLE"   # let the seed's write backlog destage
}

# Make sure <host>'s dataset covers a cell of <nj> jobs x <nr> files in one
# direction, seeding what is missing. Seeding is incremental anyway; this
# keeps the listing and the df out of every cell that is already covered.
cal_ensure_seed() {   # cal_ensure_seed <host> <read|write> <nj> <nr>
    local host=$1 dirn=$2 nj=$3 nr=$4 cov a b
    cov="$WORK_DIR/cal/$host/seeded.$dirn"
    if [ -s "$cov" ]; then
        while read -r a b; do
            [ "$a" -ge "$nj" ] && [ "$b" -ge "$nr" ] && return 0
        done < "$cov"
    fi
    if [ "$dirn" = read ]; then
        cal_seed_rep "$host" "$nj" "$nr" 0 0 "$CAL_DENSE_WRITE" "$CAL_SEED_ENG" "$CAL_REP_ALL"
    else
        cal_seed_rep "$host" 0 0 "$nj" "$nr" "$CAL_DENSE_WRITE" "$CAL_SEED_ENG" "$CAL_REP_ALL"
    fi
    mkdir -p "$WORK_DIR/cal/$host"
    printf '%s %s\n' "$nj" "$nr" >> "$cov"
}

# Group HOSTS into client shapes, in command-line order. The key is the
# hardware -- cpu model and count, memory (MemTotal to the nearest GiB),
# how many cores weka has pinned, and the NICs weka uses with their ethtool
# link speeds -- plus what fio may use there: the usable cpu count, the
# engines that passed their test, and an engine pinned by -e or the host
# file. Hosts that share hardware but not those calibrate as shapes of their
# own, because a job count or an engine measured on one would not describe
# the other. The first host of a shape is its representative.
#
# Writes the machine form to <out>, one TSV line per shape:
#   id rep usable phys all linerate engines pinned memcap aio pins members
# (usable = N; phys and all the cpu lists N/2..N and 2N/4N jobs run on;
# linerate in bytes/s, --line-rate's figure when given, 0 = unknown; engines
# comma-joined in ENGINE_ORDER; pinned "-" when nothing pins it; memcap in
# bytes, 0 = no guard; aio the kernel aio room the shape's libaio cells must
# fit, the SMALLEST of its members' -- every member runs the shape's answer
# --, "-" when no probe could tell; pins the rep's host-file values as
# slot=qd/nr/fs/nj words, "-" for an open knob and for no pins at all;
# members last) and prints the human form on
# stdout. Warnings go to stderr. Also writes cal/hostinfo (each host's cpus
# and engine, for the shared seed) and cal/needs.* (what the pins need from
# the seed beyond the nrfiles ladder).
cal_shapes() {   # cal_shapes <out> <ladders>
    local caldir=.
    [[ $1 != */* ]] || caldir=${1%/*}
    # what the pins need from the seed is worked out from scratch below
    rm -f "$caldir"/needs.* || return 1
    awkrun '
    # str.split(None, n): up to n fields, then the rest as one, its leading
    # blanks off
    function split_rest(s, F, n,    k) {
        split("", F); k = 0
        while (k < n) {
            sub(/^[ \t\n\013\014\r\034\035\036\037]+/, "", s)
            if (s == "") return k
            if (!match(s, /[ \t\n\013\014\r\034\035\036\037]/)) { F[++k] = s; return k }
            F[++k] = substr(s, 1, RSTART - 1); s = substr(s, RSTART)
        }
        sub(/^[ \t\n\013\014\r\034\035\036\037]+/, "", s)
        if (s != "") F[++k] = s
        return k
    }
    function py_round(x,    r) {   # round(): half to even
        r = int(x)
        return x - r > 0.5 || (x - r == 0.5 && r % 2) ? r + 1 : r
    }
    function field(h, key,    ROW) {   # the host-file value, "" for none
        if (!(h in ROWS)) return ""
        lsplit(ROWS[h], ROW, "\t")
        return row_get(ROW, key)
    }
    # A host pins: the host-file values of each searched slot (qd, nr, fs,
    # nj; "" for a knob it leaves open). -g searches everything, and
    # --line-rate searches bandwidth again: a recorded answer does not say
    # which line rate it stopped at (Frank, 2026-09-27).
    function host_pins(h, PS, PQ, PN, PF, PJ,    k, i, s, q, n, f, j) {
        split("", PS); k = 0
        if (regen) return 0
        for (i = 1; i <= nneed; i++) {
            s = NEED[i]
            if (line_gbps != "" && (s in LRS)) continue
            q = field(h, s "_qd"); n = field(h, s "_nr"); f = field(h, s "_fs"); j = field(h, s "_nj")
            if (q != "" || n != "" || f != "" || j != "") { PS[++k] = s; PQ[k] = q; PN[k] = n; PF[k] = f; PJ[k] = j }
        }
        return k
    }
    # The NICs weka containers use, into PORT (netdev -> 1): 1 when they
    # can be named (none at all is UDP mode), 0 when they cannot; WHY says
    # why not. Reads the host facts NIC*, WNAME/WRAW (nw), WERR (ne), cli.
    function weka_ports(    w, r, base, k, p, rest, idx, key, d, nd, DEV, DSEEN, DV, bad, BYPCI, i, c, v, lc, hit, nc, CAND, U, u, nl, LOST) {
        split("", PORT); WHY = ""
        if (!cli) { WHY = "no weka CLI on the host"; return 0 }
        nd = 0; bad = ""
        for (w = 1; w <= nw; w++) {
            json_begin("[{")
            r = json_line(WRAW[w])
            if (!J_STARTED) { if (bad == "") bad = WNAME[w] ": no JSON in weka local resources"; continue }
            if (r != 1) { if (bad == "") bad = WNAME[w] ": unreadable weka local resources JSON"; continue }
            # a list of devices, or an object carrying them as net_devices;
            # only the objects among them are devices
            base = J_ROOT == "[" ? "" : "net_devices"
            split("", DSEEN)
            for (k = 1; k <= JN; k++) {
                p = JP[k]
                if (index(p, base ".") != 1) continue
                rest = substr(p, length(base) + 2)
                if (!match(rest, /^[0-9]+/)) continue
                idx = substr(rest, 1, RLENGTH); key = substr(rest, RLENGTH + 1)
                if (key == "") { if (JS[k] || JV[k] != "{}") continue }
                else if (substr(key, 1, 1) != "." || key ~ /^\.[0-9]+(\.|$)/) continue
                if (!(idx in DSEEN)) { DSEEN[idx] = ++nd }
                d = DSEEN[idx]; key = substr(key, 2)
                if (JS[k] && JV[k] != "" && (key == "name" || key == "device" || key == "identifier" || key == "netdev" || key == "interface"))
                    DV[d, key] = JV[k]
            }
        }
        if (!nw) { WHY = ne ? "weka local resources could not be read (" WERR[1] ")" : "weka local resources could not be read"; return 0 }
        if (bad != "") { WHY = bad; return 0 }
        if (!nd) { WHY = "weka uses no dedicated NIC here (UDP mode)"; return 1 }
        for (i = 1; i <= nn; i++) if (NPCI[NORD[i]] != "-") BYPCI[NPCI[NORD[i]]] = NORD[i]
        nl = 0
        for (d = 1; d <= nd; d++) {
            nc = 0; hit = ""
            split("name device identifier netdev interface", U, " ")
            for (u = 1; u <= 5; u++) if ((d, U[u]) in DV) CAND[++nc] = DV[d, U[u]]
            for (c = 1; c <= nc; c++) {
                v = CAND[c]; lc = tolower(v)
                if (v in NSPD) hit = v
                else if (lc ~ /^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]\.[0-7]$/ && (lc in BYPCI)) hit = BYPCI[lc]
                if (hit != "") break
            }
            if (hit != "") { PORT[hit] = 1; continue }
            # name, device and identifier often repeat each other: say each once
            v = ""; split("", U)
            for (c = 1; c <= nc; c++) if (!(CAND[c] in U)) { U[CAND[c]] = 1; v = v (v == "" ? "" : " ") CAND[c] }
            LOST[++nl] = v == "" ? "?" : v
        }
        if (nl) { split("", PORT); WHY = "weka\047s NIC " LOST[1] " has no kernel netdev to ask ethtool about (bound to vfio?)"; return 0 }
        return 1
    }
    function gibs(b) { return sprintf("%.2f GiB/s", b / 1073741824) }
    BEGIN {
        out = ARGV[1]; work = ARGV[3]; cli_engine = ARGV[4]; regen = ARGV[5] == "1"; mem_pct = ARGV[6] + 0
        line_gbps = ARGV[7] == "-" ? "" : ARGV[7]
        nnrs = 0; m = pysplit(ARGV[8], A)
        for (i = 1; i <= m; i++) if (A[i] ~ /^[0-9]+$/ && !((A[i] + 0) in NRSEEN)) { NRSEEN[A[i] + 0] = 1; NRS[++nnrs] = A[i] + 0 }
        sort_arr(NRS, nnrs, 1)
        fsmib = ARGV[9] + 0; wide = ARGV[10] + 0   # the job-count ceiling, x N (cal_wide)
        nh = 0
        for (a = 11; a < ARGC; a++) H[++nh] = ARGV[a]
        n = split(line_rate_slots(), F, " ")
        for (i = 1; i <= n; i++) LRS[F[i]] = 1
        nneed = 0; n = split(ARGV[2], L, "\n")
        for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2) NEED[++nneed] = F[1] "_" substr(F[2], 1, 1)
        n = readlines(work "/targets.final", L)
        for (i = 1; i <= n; i++) { lsplit(L[i], F, "\t"); if (!(F[1] in ROWS)) ROWS[F[1]] = L[i] }
        fs_groups(work, H, nh, GF, GM)
        ngroups = 0
        for (i = 1; i <= nh; i++) if (!(GF[H[i]] in GSEEN)) { GSEEN[GF[H[i]]] = 1; ngroups++ }
        neo = split(engine_order(), EO, " ")
        ns = 0
        for (x = 1; x <= nh; x++) {
            h = H[x]
            if ((np = readlines(work "/probe/" h, P)) < 0) np = 0
            ncpus = 0; model = ""; memkb = 0; cli = 1; neng = 0; nn = 0; nw = 0; ne = 0
            split("", WK); split("", ENG); split("", NSPD); split("", NPCI); split("", NDRV); split("", NIDS); split("", NORD)
            for (i = 1; i <= np; i++) {
                if (!(m = pysplit(P[i], F))) continue
                k = F[1]
                if (k == "ncpus" && m > 1 && F[2] ~ /^[0-9]+$/) ncpus = F[2] + 0
                else if (k == "cpu_model") {
                    v = ""
                    if (m > 1) { split_rest(P[i], R, 1); v = strip(R[2]) }
                    if (v == "-") model = ""
                    else { c = pysplit(v, R); model = R[1]; for (j = 2; j <= c; j++) model = model " " R[j] }
                }
                else if (k == "memtotal_kb" && m > 1 && F[2] ~ /^[0-9]+$/) memkb = F[2] + 0
                else if (k == "weka_allowed" && m > 1) {
                    # a single-cpu mask is a dedicated io thread
                    if (!parse_cpulist(F[2], S)) awk_fail("probe: bad cpu list on a weka_allowed line: " F[2])
                    if (set_size(S) == 1) for (c in S) WK[c] = 1
                }
                else if (k == "nic" && m >= 6) {
                    if (!(F[2] in NSPD)) NORD[++nn] = F[2]
                    NSPD[F[2]] = match(F[3], /^[0-9]+/) ? substr(F[3], 1, RLENGTH) + 0 : 0
                    NPCI[F[2]] = tolower(F[4]); NDRV[F[2]] = F[5]; NIDS[F[2]] = F[6]
                }
                else if (k == "weka_net") {
                    c = split_rest(P[i], R, 2)
                    WNAME[++nw] = c > 1 ? R[2] : "?"; WRAW[nw] = c > 2 ? R[3] : ""
                }
                else if (k == "weka_net_err") {
                    c = split_rest(P[i], R, 2)
                    WERR[++ne] = (c > 1 ? R[2] : "?") ": " (c > 2 ? R[3] : "failed")
                }
                else if (k == "weka_cli" && m > 1 && F[2] == "absent") cli = 0
                else if (k == "engines") { split("", ENG); neng = m - 1; for (j = 2; j <= m; j++) ENG[j - 1] = F[j] }
            }
            nweka = set_size(WK)
            # the host file own list, as staging reads it: probe_cores
            # trims it the way check_cpu_pinning does, and has to see it as
            # written to tell a catch-all like 0-255 from an operator choice
            base = field(h, "cpus")
            probe_cores(P, np, base, CR, PHYS, ALL)
            if (CR["n"] < 1) {
                if (CR["catchall"])
                    how = "its host-file cpu list (" base ") covers every cpu fio could use, which counts as no list -- mount weka with fewer cores, use a larger client, or list fewer cpus (a narrower list is the operator\047s own reserve)"
                else if (base != "") how = "mount weka with fewer cores or use a larger client"
                else how = "mount weka with fewer cores, use a larger client, or name the cpus in the host file, fewer than fio could use (a narrower list is the operator\047s own reserve)"
                awk_fail(h ": no cpus left for fio -- " cores_summary(CR, PHYS, ALL) "; " how)
            }
            named = weka_ports(); why = WHY
            np_ = 0; split("", PN)
            for (p in PORT) PN[++np_] = p
            sort_arr(PN, np_, 0)
            linerate = 0; nicsig = "nics:unknown"
            if (named) {
                nicsig = ""; allsp = 1; sum = 0; nospeed = ""
                for (i = 1; i <= np_; i++) {
                    p = PN[i]
                    nicsig = nicsig (i > 1 ? "," : "") sprintf("%s[%s]@%d", NDRV[p], NIDS[p], NSPD[p])
                    sum += NSPD[p]
                    if (!NSPD[p]) { allsp = 0; nospeed = nospeed (nospeed == "" ? "" : " ") p }
                }
                if (nicsig == "") nicsig = "nics:none"
                if (np_ && allsp) linerate = sum * 125000   # Mb/s -> bytes/s
                else if (np_) why = "ethtool reports no link speed for " nospeed
            }
            ethtool = linerate
            if (line_gbps != "") linerate = line_gbps * 125000000   # Gb/s -> bytes/s
            nc = 0; cands = ""
            for (i = 1; i <= neo; i++) for (j = 1; j <= neng; j++) if (ENG[j] == EO[i]) { cands = cands (nc++ ? "," : "") EO[i]; break }
            if (!nc) cands = neng ? ENG[1] : "psync"
            first = cands; sub(/,.*/, "", first)
            pinned = cli_engine != "-" ? cli_engine : regen ? "" : field(h, "engine")
            memgib = memkb ? py_round(memkb / 1048576) : 0
            # one representative per shape per filesystem group (Frank,
            # 2026-10-02): a group read cells must read that group own
            # shared set; and hosts whose host-file values pin different
            # knobs calibrate apart, since a pin is the only value its
            # search tries
            npin = host_pins(h, PS, PQ, PNR, PFS, PJ)
            pinsig = ""
            for (i = 1; i <= npin; i++) pinsig = pinsig SUBSEP PS[i] SUBSEP PQ[i] SUBSEP PNR[i] SUBSEP PFS[i] SUBSEP PJ[i]
            key = model SUBSEP ncpus SUBSEP memgib SUBSEP nweka SUBSEP nicsig SUBSEP CR["n"] SUBSEP set_size(ALL) SUBSEP cands SUBSEP pinned SUBSEP GF[h] SUBSEP pinsig
            # every host may help seed its group shared set: what it runs on
            HOSTINFO[x] = h "\t" fmt_cpulist(ALL) "\t" (pinned != "" ? pinned : first)
            if (!(key in SHAPE)) {
                SHAPE[key] = ++ns; s = ns
                SREP[s] = h; SNM[s] = 0; SMODEL[s] = model; SNCPU[s] = ncpus; SMEMKB[s] = memkb; SMEMGIB[s] = memgib
                SN[s] = CR["n"]; SPHYS[s] = fmt_cpulist(PHYS); SALL[s] = fmt_cpulist(ALL); SSUM[s] = cores_summary(CR, PHYS, ALL)
                SLR[s] = linerate; SETH[s] = ethtool; SWHY[s] = why; SCANDS[s] = cands; SPIN[s] = pinned; SAIO[s] = ""
                SNICS[s] = ""
                if (np_) {
                    split("", CNT); split("", KS); nk = 0
                    for (i = 1; i <= np_; i++) {
                        p = PN[i]
                        k = NDRV[p] " [" NIDS[p] "] " (NSPD[p] ? sprintf("%g Gb/s", NSPD[p] / 1000) : "unknown speed")
                        if (!(k in CNT)) { CNT[k] = 0; KS[++nk] = k }
                        CNT[k]++
                    }
                    sort_arr(KS, nk, 0)
                    v = ""
                    for (i = 1; i <= nk; i++) v = v (i > 1 ? ", " : "") CNT[KS[i]] " x " KS[i]
                    p = PN[1]
                    for (i = 2; i <= np_; i++) p = p " " PN[i]
                    SNICS[s] = "weka NICs " p ": " v
                    if (ethtool) SNICS[s] = SNICS[s] " -> line rate " gibs(ethtool)
                } else SNICS[s] = "weka NICs: " why
            }
            s = SHAPE[key]
            SMEM[s, ++SNM[s]] = h
            # the aio room is state, not hardware (another process may hold
            # part of fs.aio-nr), so it splits no shape -- but every member
            # runs the shape answer, so its libaio cells must fit the
            # tightest member
            if ((room = probe_aio_room(P, np)) != "" && (SAIO[s] == "" || room < SAIO[s])) SAIO[s] = room
        }
        bw = 0
        for (i = 1; i <= nneed; i++) if (index(NEED[i], "bw_") == 1) bw = 1
        for (s = 1; s <= ns; s++) {
            rep = SREP[s]
            npin = host_pins(rep, PS, PQ, PNR, PFS, PJ)
            cached = ""; again = ""
            for (i = 1; i <= npin; i++)
                cached = cached (i > 1 ? " " : "") PS[i] "=" (PQ[i] != "" ? PQ[i] : "-") "/" (PNR[i] != "" ? PNR[i] : "-") "/" (PFS[i] != "" ? PFS[i] : "-") "/" (PJ[i] != "" ? PJ[i] : "-")
            if (!regen && line_gbps != "")
                for (i = 1; i <= nneed; i++)
                    if ((NEED[i] in LRS) && (field(rep, NEED[i] "_qd") != "" || field(rep, NEED[i] "_nr") != "" || field(rep, NEED[i] "_fs") != "" || field(rep, NEED[i] "_nj") != ""))
                        again = again (again == "" ? "" : ", ") NEED[i]
            memcap = SMEMKB[s] ? int(SMEMKB[s] * 1024 * mem_pct / 100) : 0
            members = SMEM[s, 1]
            for (i = 2; i <= SNM[s]; i++) members = members " " SMEM[s, i]
            printf "%d\t%s\t%d\t%s\t%s\t%.0f\t%s\t%s\t%.0f\t%s\t%s\t%s\n", s, rep, SN[s], SPHYS[s], SALL[s], int(SLR[s]), SCANDS[s], (SPIN[s] != "" ? SPIN[s] : "-"), memcap, (SAIO[s] == "" ? "-" : sprintf("%.0f", SAIO[s])), (cached == "" ? "-" : cached), members > out
            nics = SNICS[s]
            if (line_gbps != "")
                nics = nics sprintf("; line rate %s from --line-rate %g Gb/s%s", gibs(SLR[s]), line_gbps + 0, SETH[s] ? " in place of ethtool\047s" : "")
            printf "shape %d of %d: %d host(s), calibrated on %s -- %s, %d cpus, %s, %s\n", s, ns, SNM[s], rep, (SMODEL[s] != "" ? SMODEL[s] : "cpu model unknown"), SNCPU[s], (SMEMGIB[s] ? SMEMGIB[s] " GiB" : "memory unknown"), nics
            print "  cores: " SSUM[s]
            if (ngroups > 1) print "  filesystem group of " GF[rep] ": reads that group\047s shared set"
            v = SMEM[s, 1]
            for (i = 2; i <= SNM[s] && i <= 24; i++) v = v " " SMEM[s, i]
            print "  hosts: " v (SNM[s] <= 24 ? "" : " (+" (SNM[s] - 24) " more)")
            if (again != "")
                # a recorded answer does not say which line rate it stopped
                # at, so --line-rate searches bandwidth again (Frank,
                # 2026-09-27); its answer replaces the recorded one
                # (apply_cal_results, the writeback)
                print "  --line-rate: the host file\047s bandwidth answer (" again ") is measured again against it and replaced" (cached != "" ? "; its other values still pin their knobs" : "")
            if (npin) {
                v = ""
                for (i = 1; i <= npin; i++) {
                    w = ""
                    if (PQ[i] != "") w = w (w == "" ? "" : ", ") "iodepth=" PQ[i]
                    if (PNR[i] != "") w = w (w == "" ? "" : ", ") "nrfiles=" PNR[i]
                    if (PFS[i] != "") w = w (w == "" ? "" : ", ") "filesize=" PFS[i]
                    if (PJ[i] != "") w = w (w == "" ? "" : ", ") "numjobs=" PJ[i]
                    v = v (i > 1 ? "; " : "") PS[i] " " w
                }
                print "  pinned by the host file (the only values tried; -g searches everything): " v
            }
            if (!SLR[s] && bw)
                printf "WARNING: shape %d (%s): %s -- the bandwidth search has no line-rate target and runs to its peak instead\n", s, rep, (SWHY[s] != "" ? SWHY[s] : "no line rate") > "/dev/stderr"
        }
        close(out)
        # per host: the cpus and engine it seeds its group shared set with
        caldir = dirname(out)
        f = path_join(caldir, "hostinfo")
        if (nh) writelines(f, HOSTINFO, nh)
        else { printf "" > f; close(f) }
        # What the pins need from the seed beyond the nrfiles ladder, as
        # "<nj> <nr> <mib>" needs (seed_size): a pinned nrfiles off the
        # ladder, a pinned filesize, a pinned job count past 4N -- and a
        # pinned latency filesize one-job twin, which reads one file of fs x
        # nr. Read needs belong to the filesystem group shared set, write
        # needs to the representative own.
        nd = 0
        for (s = 1; s <= ns; s++) {
            rep = SREP[s]
            npin = host_pins(rep, PS, PQ, PNR, PFS, PJ)
            for (i = 1; i <= npin; i++) {
                d = substr(PS[i], length(PS[i])); typ = substr(PS[i], 1, length(PS[i]) - 2)
                split("", NR2); n2 = 0
                if (PNR[i] ~ /^[0-9]+$/) NR2[++n2] = PNR[i] + 0
                else for (j = 1; j <= nnrs; j++) NR2[++n2] = NRS[j]
                nj = PJ[i] ~ /^[0-9]+$/ ? PJ[i] + 0 : wide * SN[s]
                fmib = 0
                if (PFS[i] != "" && (b = parse_size(PFS[i])) != "") fmib = int(b / 1048576)
                dest = d == "r" ? "needs.read." GF[rep] : "needs.write." rep
                if (!(dest in DL)) { DO[++nd] = dest; DL[dest] = "" }
                mx = 0
                for (j = 1; j <= n2; j++) {
                    DL[dest] = DL[dest] sprintf("%d %d %d\n", nj, NR2[j], fmib ? fmib : (int(fsmib / NR2[j]) > 1 ? int(fsmib / NR2[j]) : 1))
                    if (NR2[j] > mx) mx = NR2[j]
                }
                if ((typ == "lat" || typ == "lat1m") && fmib) DL[dest] = DL[dest] sprintf("1 1 %d\n", fmib * mx)
            }
        }
        for (i = 1; i <= nd; i++) { f = path_join(caldir, DO[i]); printf "%s", DL[DO[i]] > f; close(f) }
    }' "$1" "$2" "$WORK_DIR" "${ENGINE:--}" "$REGEN_LAYOUT" "$CAL_MEM_PCT" "${LINE_RATE_GBPS:--}" \
       "$CAL_NR $CAL_NR_LADDER" "$FILESIZE_MIB" "$(cal_wide)" "${HOSTS[@]}"
}

# THE SEARCH RULES, one place. Stateless: reads the history of readings for
# one (type, direction) on one shape and prints the next cell to measure,
#   cell <phase> <numjobs> <iodepth> <nrfiles> <runtime>
# or the verdict,
#   done <numjobs> <iodepth> <nrfiles> <message>
# History lines are "<phase> <engine> <nj> <qd> <nr> <runtime> <value> [aux]"
# -- bytes/s for bw, IOPS for iops, mean latency in us (aux: IOPS) for lat
# and lat1m. "budget" instead of "next" prints the most cells the search can
# take. N is the shape's usable PHYSICAL cores (probe_cores); the job counts
# are Frank's (2026-09-25): N/2 and N run one job per physical core with the
# siblings idle, 2N and 4N put the siblings to work too.
#   bandwidth  numjobs 1, 2, 4 ... N/2, N at nrfiles=1 iodepth=1, stopping at
#              the first rung >= CAL_LINE_PCT of line rate -- no queue or file
#              ladder at or below N. Short of it: 2N and 4N, each walking
#              iodepth (CAL_BW_QD_LADDER) for every nrfiles (CAL_NR_LADDER),
#              again stopping at the target; 4N only when 2N beat N (cal).
#              Never reached, or line rate unknown: the leader -- the top
#              CAL_CONFIRM cells re-measured, then the cells walked in ladder
#              order, a cell taking the lead only CAL_SHAPE_THR (3) percent
#              ahead (Frank, 2026-10-05). A reading 5% above line rate means
#              the line rate is not the ceiling, and the leader decides.
#   iops       N/2 and N at iodepth=1 nrfiles=1 -- no ladder at or below N
#              (Frank, 2026-09-25). Then 2N and 4N: the queue ladder
#              CAL_IOPS_QD_LADDER at nrfiles=1 until it flattens, then nrfiles
#              2 and 4 at that count's winning iodepth and one step deeper; 4N
#              only when 2N beat N. Then the leader rule above. Brutal walks the
#              whole queue ladder at every file count at 2N and 4N, as far
#              as the guards below let it.
#   latency    N jobs at qd1, one cell per nrfiles of CAL_NR_LADDER, at every
#   lat1m      level; the lowest mean wins, no threshold, equal means keep
#              the fewer files. lat1m is the same search at 1MiB blocks (-b).
#   safe, max  (lvl=safe|max) bandwidth and iops measure numjobs N/2, N and
#              2N only, at the iodepth and nrfiles the caller fixes per type
#              (fq, fn), every rung, the leader rule deciding.
# Every cell keeps a job's data at FILESIZE_MIB, split over its files
# (nrfiles=4 reads 4 x 1280M of 5G files): a file ladder that also grew the
# data would measure the working set, not the file count (WEKAPP-289548: the
# same 4k test lost 30% IOPS from 1M files to 3G files).
# A sync engine keeps one IO in flight per job, so its iodepth ladders are
# just qd1. Readings from a confirm pass never steer a step that came before
# it, so re-measuring the top cells cannot reopen a decision already taken.
# Two guards end a 2N/4N queue ladder early, and the verdict names each cell
# they refused: the memory guard (numjobs x iodepth x bs past <memcap>) and,
# with libaio, the kernel's aio room (numjobs x iodepth past the aio= knob:
# the shape's tightest member); under safe and max they stop the job counts
# the fixed iodepth cannot fit. The qd1 rungs, the latency ladders and the
# engine cells are not guarded: they need at most ~16N aio events, far
# inside the default 65,536 room.
cal_plan() {   # cal_plan <next|budget> <bw|iops|lat|lat1m> <read|write> <engine> <N> <linerate> <memcap> <history> <k=v>...
    python3 - "$@" <<'PYEOF'
#@include py/cal_plan.py
PYEOF
}

# The shape's engine, from the comparison cells: per type the best reading
# (lowest for latency) wins, a tie inside CAL_KNEE_PCT going to ENGINE_ORDER;
# the type winners are tallied and pick_engine settles the tally the same
# way. Prints "<engine> <what each type said>".
cal_engine_pick() {   # cal_engine_pick <engine-cells-file>
    awkrun 'BEGIN {
        band = ARGV[2] + 0
        if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cal_engine_pick: cannot read " ARGV[1])
        for (i = 1; i <= n; i++) {
            if (pysplit(L[i], F) < 3) continue
            t = F[1]; any = 1
            C[t, ++CN[t]] = F[2]; V[t, CN[t]] = F[3] + 0
        }
        if (!any) awk_fail("cal_engine_pick: no engine cells in " ARGV[1])
        no = split(engine_order(), O, " ")
        for (j = 1; j <= no; j++) RANK[O[j]] = j - 1
        split("bw iops lat", TY, " "); said = ""; nt = 0
        for (x = 1; x <= 3; x++) {
            t = TY[x]
            if (!(m = CN[t] + 0)) continue
            ext = V[t, 1]   # the best reading: lowest for latency
            for (i = 2; i <= m; i++) if (t == "lat" ? V[t, i] < ext : V[t, i] > ext) ext = V[t, i]
            show = ""; win = ""
            for (i = 1; i <= m; i++) {
                e = C[t, i]; v = V[t, i]
                show = show (i > 1 ? ", " : "") (t == "lat" ? sprintf("%s %.1f us", e, v) : t == "bw" ? sprintf("%s %.2f GiB/s", e, v / 1073741824) : e " " commas(v))
                r = (e in RANK) ? RANK[e] : no
                # inside the band of the best, the first in ENGINE_ORDER; the
                # best is always inside its own band, whatever rounding says
                # of best x band / 100 (the python died there at band 100)
                if ((v == ext || (t == "lat" ? v <= ext * (2 - band / 100) : v >= ext * band / 100)) && (win == "" || r < wr)) { win = e; wr = r }
            }
            if (!(win in TALLY)) TORD[++nt] = win
            TALLY[win]++
            said = said (said == "" ? "" : "; ") t ": " show " -> " win
        }
        print pick_engine(TALLY, TORD, nt), said
    }' "$1" "$CAL_KNEE_PCT"
}

# Run one cell solo on <rep> and leave its reading in $WORK_DIR/cal/reading:
# bytes/s (bw), IOPS (iops), or "<mean-us> <iops>" (lat, lat1m). Called
# directly, never inside $(...): a die in a command substitution would only
# end the substitution. Globals from cal_shape_run: CAL_SID, CAL_REP_DIR,
# CAL_REP_NAME, CAL_REP_N, CAL_REP_PHYS, CAL_REP_ALL. A cell of at most N
# jobs runs one job per physical core with the siblings idle; a wider one
# spreads over the siblings too -- the same split the staged jobs get.
CAL_CELLS=0
CAL_PIN_FS=""   # a pinned filesize for the cells being run (cal_search, the engine cells)

# A slot's host-file pins, from cal_shape_run's pins-<type>-<dirn> file ("qd nr
# fs nj", "-" for an unpinned knob): as planner knobs, and the pinned fs.
cal_pin_knobs() {   # cal_pin_knobs <shape-dir> <type> <dirn>
    local q=- n=- f=- j=-
    [ ! -s "$1/pins-$2-$3" ] || read -r q n f j < "$1/pins-$2-$3"
    printf 'pin_qd=%s pin_nr=%s pin_fs=%s pin_nj=%s' "$q" "$n" "$f" "$j"
}
cal_pin_fs() {   # cal_pin_fs <shape-dir> <type> <dirn> -> the pinned fs, or nothing
    local q=- n=- f=- j=-
    [ ! -s "$1/pins-$2-$3" ] || read -r q n f j < "$1/pins-$2-$3"
    [ "$f" = - ] || printf '%s' "$f"
}

cal_run_cell() {   # cal_run_cell <rep> <bw|iops|lat|lat1m> <read|write> <engine> <nj> <qd> <nr> <runtime>
    local rep=$1 type=$2 dirn=$3 eng=$4 nj=$5 qd=$6 nr=$7 rt=$8 base json vals h v a what cpus
    base="cal-$type-$dirn-$eng-nj$nj-qd$qd-nr$nr-${rt}s"
    what="cell $type-$dirn $eng numjobs=$nj iodepth=$qd nrfiles=$nr"
    cpus=$CAL_REP_ALL
    [ "$nj" -gt "$CAL_REP_N" ] || cpus=$CAL_REP_PHYS
    stage_cal_cell "$WORK_DIR/cal/$rep/$base.job" "$CAL_REP_DIR" "$CAL_REP_NAME" \
        "$cpus" "$type" "$dirn" "$eng" "$nj" "$qd" "$nr" "$rt"
    cal_push "$base.job" "$rep" || die "cannot copy a calibration cell to $MASTER"
    CAL_CELLS=$((CAL_CELLS + 1))
    json="$WORK_DIR/cal/res-s$CAL_SID-$CAL_CELLS-$base.json"
    if ! run_host "$MASTER" "'$FIO_BIN' --output-format=json --eta=never --client=$rep '$TARGET_DIR.cal/$rep/$base.job'" > "$json"; then
        cal_evidence "$what" "$json" "$base.job" say "$rep"
        die "calibration $what failed on $rep (${json##*/} and the cell jobfile are in the run bundle under cal/)"
    fi
    if ! check_fio_errors "$json" measured; then
        cal_evidence "$what" "$json" "$base.job" quiet "$rep"
        die "calibration $what errored on $rep (${json##*/} and the cell jobfile are in the run bundle under cal/)"
    fi
    if [ "$type" = lat ] || [ "$type" = lat1m ]; then
        vals=$(cal_lat_values "$json" "$dirn") || die "cannot read the latency of ${json##*/}"
        read -r h v a <<<"$vals"
        printf '%s %s\n' "$v" "$a" > "$WORK_DIR/cal/reading"
    else
        vals=$(cal_values "$json" "$type") || die "cannot read the throughput of ${json##*/}"
        read -r h v <<<"$vals"
        printf '%s\n' "$v" > "$WORK_DIR/cal/reading"
    fi
    debug "cal: shape $CAL_SID $what ${rt}s: $(cat "$WORK_DIR/cal/reading")"
    [ "$dirn" != write ] || sleep "$CAL_SETTLE"
}

# Search one (type, direction) on the shape's representative: the planner
# names each cell, bash runs it, until the planner is done. The verdict's
# tuple lands in cal/s<id>/tuple-<type>-<dirn> as "qd nr fs nj".
cal_search() {   # cal_search <rep> <bw|iops|lat|lat1m> <read|write> <engine> <N> <linerate> <memcap>
    local rep=$1 type=$2 dirn=$3 eng=$4 usable=$5 linerate=$6 memcap=$7
    local sdir="$WORK_DIR/cal/s$CAL_SID" hist act phase nj qd nr rt msg n=0 knobs
    hist="$sdir/hist-$type-$dirn"
    : > "$hist"
    knobs="$(cal_knobs "$type")aio=${CAL_REP_AIO:--} $(cal_pin_knobs "$sdir" "$type" "$dirn")"
    CAL_PIN_FS=$(cal_pin_fs "$sdir" "$type" "$dirn")
    while :; do
        # shellcheck disable=SC2086 -- the knobs are one k=v word each
        act=$(cal_plan next "$type" "$dirn" "$eng" "$usable" "$linerate" "$memcap" "$hist" $knobs) \
            || die "the calibration planner failed for $type $dirn (history: cal/s$CAL_SID/${hist##*/} in the run bundle)"
        case "$act" in
            ("cell "*)
                read -r _ phase nj qd nr rt <<<"$act"
                [ "$n" -lt 400 ] || die "the $type $dirn search did not converge in 400 cells (history: cal/s$CAL_SID/${hist##*/})"
                cal_ensure_seed "$rep" "$dirn" "$nj" "$nr"
                cal_run_cell "$rep" "$type" "$dirn" "$eng" "$nj" "$qd" "$nr" "$rt"
                printf '%s %s %s %s %s %s %s\n' "$phase" "$eng" "$nj" "$qd" "$nr" "$rt" \
                    "$(cat "$WORK_DIR/cal/reading")" >> "$hist"
                n=$((n + 1)) ;;
            ("done "*)
                read -r _ nj qd nr msg <<<"$act"
                printf '%s %s %s %s\n' "$qd" "$nr" "${CAL_PIN_FS:-$(( FILESIZE_MIB / nr > 0 ? FILESIZE_MIB / nr : 1 ))M}" "$nj" > "$sdir/tuple-$type-$dirn"
                log "cal: shape $CAL_SID $type-$dirn: $msg [$n cell(s), $eng]"
                CAL_PIN_FS=""
                return 0 ;;
            (*) die "the calibration planner said something unexpected for $type $dirn: $act" ;;
        esac
    done
}

# One shape, start to finish, solo on its representative: reuse what the
# rep's host-file row already carries, seed what the rest needs, choose the
# engine, run one search per remaining (type, direction). Leaves the engine
# in cal/s<id>/engine and one tuple file per slot it settled.
cal_shape_run() {   # cal_shape_run <id> <rep> <N> <phys-cpus> <all-cpus> <linerate> <engines> <pinned> <memcap> <aio> <pins> <ladders>
    local sid=$1 rep=$2 usable=$3 phys=$4 allc=$5 linerate=$6 engines=$7 pinned=$8 memcap=$9 aio=${10} pins=${11} ladders=${12}
    local sdir="$WORK_DIR/cal/s$1" type dirn slot kv c todo="" any_read=0 any_write=0
    local eng pick rest etype ctype edirn enj eqd enr pq pn pj e ncand budget wcells mins qmax
    CAL_SID=$sid
    CAL_REP_DIR=$(host_dir "$rep")
    CAL_REP_NAME=$(host_name "$rep")
    CAL_REP_N=$usable
    CAL_REP_PHYS=$phys
    CAL_REP_ALL=$allc
    # the shape's aio room (cal_shapes: its tightest member's), for cal_search
    CAL_REP_AIO=$aio
    CAL_DENSE_WRITE=0
    mkdir -p "$sdir" "$WORK_DIR/cal/$rep" || die "cannot create $sdir"
    rm -f "$WORK_DIR/cal/$rep/seeded.read" "$WORK_DIR/cal/$rep/seeded.write"
    while read -r type dirn; do
        [ -n "$type" ] || continue
        slot="${type}_${dirn:0:1}"
        c=""
        for kv in $pins; do
            [ "${kv%%=*}" != "$slot" ] || c=${kv#*=}
        done
        rm -f "$sdir/pins-$type-$dirn"
        if [ -n "$c" ]; then
            # the host file pins these knobs: they are the only values this
            # search tries, and every other knob is searched around them
            printf '%s\n' "$c" | tr '/' ' ' > "$sdir/pins-$type-$dirn"
            log "cal: shape $sid: $type $dirn is pinned by $rep's host-file row (qd/nr/fs/nj $c): only those values are tested (-g searches everything)"
        fi
        todo="$todo$type $dirn"$'\n'
        if [ "$dirn" = read ]; then any_read=1; else any_write=1; fi
        case "$type $dirn" in ("iops write"|"lat write"|"lat1m write") CAL_DENSE_WRITE=1 ;; esac
    done <<SLOTEOF
$ladders
SLOTEOF
    [ -n "$todo" ] || return 0
    # the most this shape can cost, said before it starts
    ncand=1
    [ "$pinned" != "-" ] || ncand=$(printf '%s\n' "${engines//,/ }" | wc -w | tr -d ' ')
    budget=0; wcells=0
    while read -r type dirn; do
        [ -n "$type" ] || continue
        c=$(cal_plan budget "$type" "$dirn" x "$usable" 0 0 /dev/null $(cal_knobs "$type") $(cal_pin_knobs "$sdir" "$type" "$dirn")) \
            || die "cannot size the $type $dirn search"
        budget=$((budget + c))
        [ "$dirn" != write ] || wcells=$((wcells + c))
    done <<BUDEOF
$todo
BUDEOF
    mins=$(( (budget * (CAL_RUNTIME + 5) + wcells * CAL_SETTLE) / 60 + 1 ))
    # engine cells: one per candidate per type the engine loop below runs --
    # bandwidth, iops, latency; a 1MiB latency search is latency's stand-in
    # there only when no 4k latency search is asked for
    log "cal: shape $sid: measuring $(printf '%s' "$todo" | tr '\n' ',' | sed 's/,$//;s/,/, /g') solo on $rep -- at most $budget search cell(s) (~$mins min at ${CAL_RUNTIME}s)$([ "$ncand" -le 1 ] || printf ' plus %d engine cell(s)' $(( ncand * $(printf '%s\n' "$todo" | awk '{t = ($1 == "lat1m") ? "lat" : $1} t == "bw" || t == "iops" || t == "lat" {print t}' | sort -u | wc -l) )))"
    # the dataset every first-pass cell reads or writes; wider cells seed
    # their own extra files as they come
    if [ "$pinned" != "-" ]; then CAL_SEED_ENG=$pinned; else CAL_SEED_ENG=${engines%%,*}; fi
    [ "$any_read" -eq 0 ] || cal_ensure_seed "$rep" read "$usable" "$CAL_NR"
    [ "$any_write" -eq 0 ] || cal_ensure_seed "$rep" write "$usable" "$CAL_NR"
    if [ "$pinned" != "-" ]; then
        eng=$pinned
        log "cal: shape $sid: ioengine $eng (pinned by -e or the host file; -g re-chooses it)"
    elif [ "$ncand" -le 1 ]; then
        eng=${engines%%,*}
        log "cal: shape $sid: ioengine $eng (the only candidate that passed its test)"
    else
        : > "$sdir/engines"
        for etype in bw iops lat; do
            edirn="" ctype=$etype
            if printf '%s' "$todo" | grep -qx "$etype read"; then edirn=read
            elif printf '%s' "$todo" | grep -qx "$etype write"; then edirn=write
            elif [ "$etype" = lat ]; then
                # only a 1MiB latency search: its cells stand in, tallied as
                # latency, or a set like that has no engine cell at all
                ctype=lat1m
                if printf '%s' "$todo" | grep -qx "lat1m read"; then edirn=read
                elif printf '%s' "$todo" | grep -qx "lat1m write"; then edirn=write
                fi
            fi
            [ -n "$edirn" ] || continue
            case "$etype" in
                (bw)   enj=$usable; eqd=1 ;;
                (iops) qmax=1
                       for e in $CAL_IOPS_QD_LADDER; do [ "$e" -le "$qmax" ] || qmax=$e; done
                       enj=$usable; eqd=16; [ "$eqd" -le "$qmax" ] || eqd=$qmax ;;
                (lat)  enj=1; eqd=1 ;;
            esac
            # the slot's pins hold here too: an engine is ranked on what the
            # search will run
            enr=$CAL_NR
            read -r pq pn _ pj <<<"$(cal_pin_knobs "$sdir" "$ctype" "$edirn" | sed 's/pin_[a-z]*=//g')"
            [ "$pj" = - ] || enj=$pj
            [ "$pq" = - ] || eqd=$pq
            [ "$pn" = - ] || enr=$pn
            CAL_PIN_FS=$(cal_pin_fs "$sdir" "$ctype" "$edirn")
            for e in ${engines//,/ }; do
                cal_run_cell "$rep" "$ctype" "$edirn" "$e" "$enj" "$eqd" "$enr" "$CAL_ENGINE_RUNTIME"
                printf '%s %s %s\n' "$etype" "$e" "$(cat "$WORK_DIR/cal/reading")" >> "$sdir/engines"
            done
            CAL_PIN_FS=""
        done
        pick=$(cal_engine_pick "$sdir/engines") || die "cannot choose shape $sid's ioengine"
        read -r eng rest <<<"$pick"
        log "cal: shape $sid: ioengine $eng -- $rest"
    fi
    printf '%s\n' "$eng" > "$sdir/engine"
    for type in bw iops lat lat1m; do
        for dirn in write read; do
            printf '%s' "$todo" | grep -qx "$type $dirn" || continue
            cal_search "$rep" "$type" "$dirn" "$eng" "$usable" "$linerate" "$memcap"
        done
    done
}

# The removal command for the dataset files <name><sep><fmt> names under <hd>
# (the sweep's glob derivation: every $var a wildcard, find bounded at the
# format's own depth), then whatever directories that leaves empty.
cal_remove_cmd() {   # cal_remove_cmd <name> <sep> <fmt> <hd>
    awkrun 'BEGIN { print dataset_remove_cmd(ARGV[1] ARGV[2] ARGV[3], ARGV[4]) }' "$@"
}

# -u, after the last measured job (main): the calibration dataset -- in the
# unified namespace each host's write set and, from the first host only, the
# fleet-shared read set, by the same glob derivation the sweep uses; in the
# private scratch the whole scratch dir. Never from calibrate itself: the
# measured jobs still use the unified dataset, and a failed run keeps it.
cal_remove_dataset() {
    local i kind host ucmd args=() pids=() hs=() cmds="$WORK_DIR/cal-remove.cmds" gf=-
    load_host_dirs
    if [ -n "$CAL_NS_DIR" ]; then
        for i in "${!HOSTS[@]}"; do
            run_host "${HOSTS[$i]}" "rm -rf '${HOST_DIRS[$i]}$CAL_NS_DIR'" &
            pids+=($!); hs+=("${HOSTS[$i]}")
        done
    else
        # unified: this host's write set, and -- from the first host of
        # each filesystem group only, before its own -- the group's
        # fleet-shared read set; one awk derives every command
        [ ! -s "$WORK_DIR/groups" ] || gf="$WORK_DIR/groups"
        for i in "${!HOSTS[@]}"; do
            host_name_v "${HOSTS[$i]}"
            args+=("${HOSTS[$i]}" "$HOST_NAME" "${HOST_DIRS[$i]}")
        done
        awkrun 'BEGIN {
            sep = ARGV[1]; fmt = ARGV[2]; ng = 0
            # group_first: the first host of each group in the groups file;
            # a host it does not list is its own; no groups file, the first host
            if (ARGV[3] != "-")
                while ((getline line < ARGV[3]) > 0)
                    if (split(line, F, " ") == 2) { ng++; G[F[1]] = F[2]; if (!(F[2] in FIRST)) FIRST[F[2]] = F[1] }
            for (a = 4; a + 2 < ARGC; a += 3) {
                h = ARGV[a]
                first = ng ? (!(h in G) || FIRST[G[h]] == h) : (a == 4)
                if (first) print "S\t" h "\t" dataset_remove_cmd("shared." fmt, ARGV[a + 2])
                print "P\t" h "\t" dataset_remove_cmd(ARGV[a + 1] sep fmt, ARGV[a + 2])
            }
        }' "${CAL_SEP:-.}" "$CAL_FMT" "$gf" \
            "${args[@]}" > "$cmds" || die "cannot derive the dataset removal commands"
        while IFS=$'\t' read -r kind host ucmd; do
            if [ "$kind" = S ]; then
                run_host "$host" "$ucmd" \
                    || log "WARNING: could not remove the shared dataset" >&2
            else
                run_host "$host" "$ucmd" &
                pids+=($!); hs+=("$host")
            fi
        done < "$cmds"
    fi
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" \
            || log "WARNING: could not remove the calibration dataset on ${hs[$i]}" >&2
    done
}

# What calibration itself will write, priced per filesystem before the first
# cell, so a dataset that cannot fit stops before the first shape instead of
# in the middle of the third: each filesystem group's shared read set for its
# widest reader (4N of its widest shape, every nrfiles step, plus anything a
# listed need adds), each representative's own write set for its shape's
# widest cell, every file at its seeded size, less what is already there.
# Groups and hosts on one weka filesystem add up against it together (Frank,
# 2026-10-02), the pooling check_capacity uses. The other members' own write
# sets are not calibration's to write: the run's capacity check prices them
# at the measured answers before the first measured job. Over: die, or with
# --ignore-capacity ask, as check_capacity does.
cal_capacity_check() {   # cal_capacity_check <shapes> <ladders>
    local shapes=$1 ladders=$2 rep hd root depth pids=() hs=() i rc line
    depth=$(( $(printf '%s' "${CAL_FMT:-\$jobnum.\$filenum}" | tr -cd / | wc -c) + 1 ))
    mkdir -p "$WORK_DIR/cal/cap" || die "cannot create $WORK_DIR/cal/cap"
    : > "$WORK_DIR/cal/cap/names"
    while IFS=$'\t' read -r _ rep _; do
        hd=$(host_dir "$rep")
        root="$hd${CAL_NS_DIR-/$CAL_SCRATCH}"
        printf '%s\t%s\n' "$rep" "$(host_name "$rep")" >> "$WORK_DIR/cal/cap/names"
        ( run_host "$rep" "if [ -d '$root' ]; then find '$root' -maxdepth $depth -type f -printf '%P %s\\n'; fi; echo WEKATESTER_DF; df -Pk '$hd' | awk 'NR==2 {print \$1, \$2, int(\$4/1024)}'; findmnt -T '$hd' -n -o FSTYPE 2>&1 || :" > "$WORK_DIR/cal/cap/$rep" ) &
        pids+=($!); hs+=("$rep")
    done < "$shapes"
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || die "${hs[$i]}: cannot list the calibration dataset or its free space"
    done
    awkrun '
    function deficit(prefix, ND, n, rep,    i, nj, nr, j, f, mib, have, total) {
        # bytes still to write for every file the needs ask for; DNJ x DNR
        # the most jobs x files they reach
        nj = 0; nr = 0; total = 0
        for (i = 1; i <= n; i++) { if (ND[i, 1] > nj) nj = ND[i, 1]; if (ND[i, 2] > nr) nr = ND[i, 2] }
        for (j = 0; j < nj; j++)
            for (f = 0; f < nr; f++) {
                if (!(mib = seed_size(ND, n, j, f))) continue
                have = ((rep, seed_name(prefix, fmt, j, f)) in HAVE) ? HAVE[rep, seed_name(prefix, fmt, j, f)] : 0
                if (mib * 1048576 > have) total += mib * 1048576 - have
            }
        DNJ = nj; DNR = nr
        return total
    }
    function gib(b) { return sprintf("%.1f", b / 1073741824) }
    function charge(rep, need, what,    k) {
        print "cal: capacity: " what ": ~" gib(need) "GiB to write"
        if (!(rep in AVAIL) || need == 0) return
        k = PKEY[rep]
        if (!(k in PNEED)) { PNEED[k] = 0; PAVAIL[k] = AVAIL[rep]; PO[++np] = k; PHOSTS[k] = ""; P0[k] = K0[rep]; P1[k] = K1[rep] }
        PNEED[k] += need
        if (AVAIL[rep] < PAVAIL[k]) PAVAIL[k] = AVAIL[rep]
        if (!((k, rep) in PH)) { PH[k, rep] = 1; PHOSTS[k] = PHOSTS[k] (PHOSTS[k] == "" ? "" : " ") rep }
    }
    BEGIN {
        work = ARGV[1]; unified = ARGV[4] == ""; fmt = ARGV[5]; sep = ARGV[6]
        fsmib = ARGV[7] + 0; nrs = ARGV[8]; wide = ARGV[9] + 0   # the widest job count, x N (cal_wide)
        nh = 0
        for (a = 10; a < ARGC; a++) { H[++nh] = ARGV[a]; if (!(ARGV[a] in HIDX)) HIDX[ARGV[a]] = nh }
        n = split(ARGV[3], L, "\n")
        for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2) DIRS[F[2]] = 1
        fs_groups(work, H, nh, GF, GM)
        cap = work "/cal/cap"
        if ((n = readlines(cap "/names", L)) < 0) awk_fail("cannot read " cap "/names")
        for (i = 1; i <= n; i++) if (index(L[i], "\t")) { lsplit(L[i], F, "\t"); NAME[F[1]] = F[2] }
        if ((n = readlines(ARGV[2], L)) < 0) awk_fail("cannot read " ARGV[2])
        ns = 0
        for (i = 1; i <= n; i++) if (lsplit(L[i], F, "\t") >= 3) { ns++; SR[ns] = F[2]; SN[ns] = F[3] + 0 }
        for (s = 1; s <= ns; s++) {
            rep = SR[s]
            if ((n = readlines(cap "/" rep, L)) < 0) awk_fail("cannot read " cap "/" rep)
            for (i = 1; i <= n && L[i] != "WEKATESTER_DF"; i++)
                if (pysplit(L[i], F) == 2 && F[2] ~ /^[0-9]+$/) HAVE[rep, F[1]] = F[2] + 0
            LISTED[rep] = 1
            # the seed df line: source, size in KiB, free MiB; then the fs
            # type. Hosts on one weka filesystem share its free space.
            if (i < n && pysplit(L[i + 1], F) >= 3 && F[3] ~ /^[0-9]+$/) {
                K0[rep] = "host"; K1[rep] = rep
                if (i + 2 <= n && strip(L[i + 2]) == "wekafs") { K0[rep] = F[1]; sub(/.*\//, "", K0[rep]); K1[rep] = F[2] }
                PKEY[rep] = "(\047" K0[rep] "\047, \047" K1[rep] "\047)"
                AVAIL[rep] = F[3] * 1048576
            }
        }
        if (unified && ("read" in DIRS)) {
            # one shared read set per filesystem group, for every shape that
            # reads it, in host order
            nf = 0
            for (s = 1; s <= ns; s++)
                if (!((g = GF[SR[s]]) in FSEEN)) { FSEEN[g] = 1; FL[++nf] = sprintf("%09d %s", HIDX[g], g) }
            sort_arr(FL, nf, 0)
            for (x = 1; x <= nf; x++) {
                first = substr(FL[x], 11); split("", ND); nd = 0
                for (s = 1; s <= ns; s++) if (GF[SR[s]] == first) nd = needs_ladder(ND, nd, nrs, fsmib, wide * SN[s])
                nd = needs_listed(ND, nd, work "/cal/needs.read." first)
                lister = first
                if (!(first in LISTED)) for (s = 1; s <= ns; s++) if (GF[SR[s]] == first) { lister = SR[s]; break }
                need = deficit("shared.", ND, nd, lister)
                charge(lister, need, sprintf("the shared read set of %s\047s filesystem group (up to %d jobs x %d files)", first, DNJ, DNR))
            }
        }
        for (s = 1; s <= ns; s++) {
            rep = SR[s]
            if (unified && !("write" in DIRS)) continue
            split("", ND)
            nd = needs_listed(ND, needs_ladder(ND, 0, nrs, fsmib, wide * SN[s]), work "/cal/needs.write." rep)
            if (!unified) nd = needs_listed(ND, nd, work "/cal/needs.read." GF[rep])
            need = deficit(((rep in NAME) ? NAME[rep] : rep) sep, ND, nd, rep)
            charge(rep, need, sprintf("%s\047s own %s (up to %d jobs x %d files)", rep, unified ? "write set" : "calibration scratch", DNJ, DNR))
        }
        sort_arr(PO, np, 0)
        over = 0
        for (x = 1; x <= np; x++) {
            k = PO[x]
            if (PNEED[k] <= PAVAIL[k]) continue
            over = 1
            printf "ERROR: calibration needs ~%sGiB on %s (%s) but only %sGiB is available\n", gib(PNEED[k]), (P0[k] != "host" ? "weka filesystem " P0[k] : P1[k] "\047s destination"), PHOSTS[k], gib(PAVAIL[k]) > "/dev/stderr"
        }
        exit over ? 3 : 0   # not 2: an awk that dies on its own exits 2
    }' "$WORK_DIR" "$shapes" "$ladders" "${CAL_NS_DIR-unset}" "${CAL_FMT:-\$jobnum.\$filenum}" \
        "${CAL_SEP:-.cal.}" "$FILESIZE_MIB" "$CAL_NR $CAL_NR_LADDER" "$(cal_wide)" "${HOSTS[@]}" \
        > "$WORK_DIR/cal/cap/report"
    rc=$?
    while IFS= read -r line; do log "$line"; done < "$WORK_DIR/cal/cap/report"
    case $rc in
        0) return 0 ;;
        3) ;;
        *) die "calibration capacity check failed" ;;
    esac
    [ "$IGNORE_CAPACITY" -eq 1 ] \
        || die "not enough capacity for the calibration dataset (use --ignore-capacity to be asked anyway)"
    if try_interactive; then
        confirm_explicit "not enough capacity for the calibration dataset: continue anyway and risk ENOSPC mid-calibration?" \
            || die "not enough capacity"
    else
        log "WARNING: --ignore-capacity: not enough capacity for the calibration dataset, calibrating anyway (unattended)" >&2
    fi
}

# The pins a calibration must run as written (cal_shapes), checked against
# each shape's kernel aio room before anything starts (Frank, 2026-10-02):
# the smallest cell a pin forces -- pinned numjobs x pinned iodepth, 1 for a
# knob left open -- with libaio pinned or among the engines calibration may
# try (the engine cells run the pins too). Over: an alert naming the shape,
# the slot and the room, and a stop; the host file is not touched.
cal_aio_preflight() {   # cal_aio_preflight <shapes>
    awkrun 'BEGIN {
        if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
        bad = 0
        for (i = 1; i <= n; i++) {
            if (lsplit(L[i], P, "\t") < 12) continue
            pinned = P[8]; aio = P[10]; lib = pinned == "libaio"
            if (pinned == "-") { m = lsplit(P[7], E, ","); for (k = 1; k <= m; k++) if (E[k] == "libaio") lib = 1 }
            if (!lib || aio !~ /^[0-9]+$/) continue
            m = pysplit(P[11], W)
            for (k = 1; k <= m; k++) {
                if (!(e = index(W[k], "="))) continue
                nv = lsplit(substr(W[k], e + 1), V, "/")
                q = V[1]; j = nv >= 4 ? V[4] : "-"
                if (q !~ /^[0-9]+$/ && j !~ /^[0-9]+$/) continue
                ev = (j ~ /^[0-9]+$/ ? j : 1) * (q ~ /^[0-9]+$/ ? q : 1)
                if (ev <= aio + 0) continue
                bad = 1
                if (j !~ /^[0-9]+$/) j = "1 (open)"
                if (q !~ /^[0-9]+$/) q = "1 (open)"
                how = pinned == "libaio" ? "pinned" : "one of the engines calibration tries"
                printf "ERROR: shape %s (%s): %s pinned at numjobs=%s iodepth=%s needs %.0f aio events at once with libaio (%s), and the kernel has room for %s there (fs.aio-max-nr less fs.aio-nr, as probed) -- raise fs.aio-max-nr, pin another ioengine (-e or the host file), or change the pin\n", P[1], P[2], substr(W[k], 1, e - 1), j, q, ev, how, aio > "/dev/stderr"
            }
        }
        exit bad ? 3 : 0   # not 2: an awk that dies on its own exits 2
    }' "$1"
    case $? in
        0) return 0 ;;
        3) die "calibration would exceed the kernel's aio room (above); nothing was run and the host file is unchanged" ;;
        *) die "cannot check the calibration pins against the kernel's aio room" ;;
    esac
}

# Before any fio server starts, and in a dry run (Frank, 2026-10-05): the
# shapes a calibration would measure, and the pins they must run checked
# against each shape's kernel aio room -- everything this needs (the probe,
# the proven engines, the host file, the filesystem groups) is known by then.
# A pin past the room stops the run here; calibrate and the dry-run report
# take the ladders and the shapes from here rather than work them out again.
cal_preflight() {
    cal_mode || return 0
    local capdir=${SET_DIR_OVERRIDE:-$(workload_src_dir)}
    cal_ladders_once || die "cannot inspect $capdir for calibration"
    [ -n "$CAL_LADDERS" ] || return 0
    mkdir -p "$WORK_DIR/cal" || die "cannot create $WORK_DIR/cal"
    cal_shapes_once || die "cannot group the hosts into client shapes"
    cal_aio_preflight "$WORK_DIR/cal/shapes"
}

# What the set calibrates (cal_required) and the shapes it calibrates on
# (cal_shapes, into cal/shapes and cal/shapes.txt): each is a python over
# the set or the whole fleet's probe files, and nothing either reads
# changes between the preflight and the calibration -- worked out once.
CAL_LADDERS=""; CAL_LADDERS_DONE=0; CAL_SHAPES_DONE=0
cal_ladders_once() {   # -> CAL_LADDERS
    [ "$CAL_LADDERS_DONE" -eq 0 ] || return 0
    CAL_LADDERS=$(cal_required "${SET_DIR_OVERRIDE:-$(workload_src_dir)}" "$BULK") || return 1
    CAL_LADDERS_DONE=1
}
cal_shapes_once() {   # cal/shapes and cal/shapes.txt for CAL_LADDERS
    [ "$CAL_SHAPES_DONE" -eq 0 ] || return 0
    cal_shapes "$WORK_DIR/cal/shapes" "$CAL_LADDERS" > "$WORK_DIR/cal/shapes.txt" || return 1
    CAL_SHAPES_DONE=1
}

calibrate() {
    cal_mode || return 0
    local capdir=${SET_DIR_OVERRIDE:-$(workload_src_dir)} ladders
    cal_ladders_once || die "cannot inspect $capdir for calibration"
    ladders=$CAL_LADDERS
    if [ -z "$ladders" ]; then
        log "cal: nothing to calibrate in this set (no measurable jobs)"
        return 0
    fi
    echo
    log "calibrating ($AUTO_LEVEL) $(printf '%s' "$ladders" | tr '\n' ',' | sed 's/,$//;s/,/, /g') per client shape, each shape solo on its first host"
    if brutal_mode; then
        log "cal: -a brutal: the same search with every early stop disabled -- every rung of every ladder is measured"
    fi
    # NOT local: stage_cal_cell and cal_seed_rep read these, and the whole
    # point is that one namespace serves the seed, every cell, and the staged
    # jobs. CAL_NS_DIR is the subdirectory under each host's destination
    # ("" = the destination itself); CAL_SEP joins host to format in every
    # filename.
    local nsline
    nsline=$(cal_namespace "$capdir") \
        || die "cannot derive the calibration namespace from $capdir"
    read -r CAL_NS CAL_FMT <<<"$nsline"
    if [ "$CAL_NS" = unified ]; then
        for host in "${HOSTS[@]}"; do
            # the data files carry host_name (local mode: the box's short
            # hostname), so both it and the address must stay clear
            host_name_v "$host"
            [ "$host" != shared ] && [ "$HOST_NAME" != shared ] \
                || die "the host name 'shared' is reserved for the fleet-shared read dataset ($host)"
        done
        CAL_NS_DIR=""; CAL_SEP="."
        log "cal: measuring on the workload's own files (filename_format=$CAL_FMT at the destination) -- reads on the shared dataset, writes on each client's own"
    else
        CAL_NS_DIR=/$CAL_SCRATCH; CAL_SEP=".cal."
        log "cal: this set's filename_format cannot express the grid; measuring in the private scratch ($CAL_SCRATCH)"
    fi
    mkdir -p "$WORK_DIR/cal"
    local shapes="$WORK_DIR/cal/shapes" line host i pids hs
    cal_shapes_once || die "cannot group the hosts into client shapes"
    while IFS= read -r line; do log "cal: $line"; done < "$WORK_DIR/cal/shapes.txt"
    run_host "$MASTER" "mkdir -p '$TARGET_DIR.cal'" \
        || die "cannot create $TARGET_DIR.cal on $MASTER"
    local sid rep usable phys allc linerate engines pinned memcap aio cached members
    pids=(); hs=()
    while IFS=$'\t' read -r sid rep rest; do
        run_host "$rep" "mkdir -p '$(host_dir "$rep")${CAL_NS_DIR-/$CAL_SCRATCH}'" &
        pids+=($!); hs+=("$rep")
    done < "$shapes"
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || die "cannot create the calibration namespace dir on ${hs[$i]}"
    done
    cal_capacity_check "$shapes" "$ladders"
    # one shape at a time, each alone
    while IFS=$'\t' read -r sid rep usable phys allc linerate engines pinned memcap aio cached members <&3; do
        cal_shape_run "$sid" "$rep" "$usable" "$phys" "$allc" "$linerate" "$engines" "$pinned" "$memcap" "$aio" "$cached" "$ladders"
    done 3< "$shapes"

    # One cal.results line per MEMBER: the shape's engine, then (qd nr fs nj)
    # per slot in CAL_SLOTS order, "- - - -" for a slot this set does not
    # run. The slot order IS the schema: GEOM_SLOTS, lib.py's CAL_SLOTS,
    # instead of spelled a second time here.
    : > "$WORK_DIR/cal.results"
    local slot type dirn t eng any m
    while IFS=$'\t' read -r sid rep usable phys allc linerate engines pinned memcap aio cached members <&3; do
        eng="-"
        [ ! -s "$WORK_DIR/cal/s$sid/engine" ] || read -r eng < "$WORK_DIR/cal/s$sid/engine"
        line=$eng; any=0
        for slot in $GEOM_SLOTS; do
            type=${slot%_*}
            dirn=read; [ "${slot##*_}" = r ] || dirn=write
            t="$WORK_DIR/cal/s$sid/tuple-$type-$dirn"
            if [ -s "$t" ]; then
                line="$line $(cat "$t")"; any=1
            else
                line="$line - - - -"
            fi
        done
        [ "$any" -eq 1 ] || continue
        for m in $members; do
            printf '%s %s\n' "$m" "$line" >> "$WORK_DIR/cal.results"
        done
    done 3< "$shapes"
    apply_cal_results

    # the evidence outlives the workdir: cell jobfiles, every cell's raw JSON,
    # the shapes and each search's history land in the run bundle
    if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
        mkdir -p "$RUN_DIR/cal" \
            && cp -R "$WORK_DIR/cal/." "$RUN_DIR/cal/" \
            && cp "$WORK_DIR/cal.results" "$RUN_DIR/cal/cal.results" \
            || log "WARNING: could not snapshot the calibration artifacts into $RUN_DIR/cal" >&2
    fi

    # The dataset is KEPT by default so the next calibration seeds nothing:
    # cal_seed_rep validates by size, and re-creating it is the single most
    # expensive part of a run. -u removes it -- after the last measured job
    # (cal_remove_dataset, from main), never here: in the unified namespace
    # the dataset IS the workload's own files, which the measured jobs still
    # read and write, and a run that fails dies before the removal, so it
    # keeps everything for the rerun.
    if [ "$UNLINK" -eq 1 ]; then
        CAL_UNLINK_PENDING=1
        log "cal: -u: the calibration dataset is removed after the last measured job"
    elif [ -z "$CAL_NS_DIR" ]; then
        log "cal: keeping the measured dataset (the workload's own files) so the next run reuses it; -u removes it"
    else
        log "cal: keeping the calibration scratch (${CAL_NS_DIR#/} under each destination) so the next calibration reuses it; -u removes it"
    fi
    run_host "$MASTER" "rm -rf '$TARGET_DIR.cal'" \
        || log "WARNING: could not remove $TARGET_DIR.cal on $MASTER" >&2
}

# --- phase 1: preflight --------------------------------------------------------
# Verify every host is reachable over ssh and has $FIO_BIN installed (local mode:
# just the fio check -- there is no connection to test).
# Policy: check all hosts in parallel, report every failure, then exit.
# Side effect: each check opens the host's ControlMaster socket, so every
# later ssh/scp to that host rides the authenticated connection for free.
preflight() {
    if [ "$LOCAL_MODE" -eq 1 ]; then
        log "checking $FIO_BIN on the local host..."
    else
        log "checking ssh connectivity and $FIO_BIN on ${#HOSTS[@]} host(s)..."
    fi
    local pids=() failed=() host i rc
    for host in "${HOSTS[@]}"; do
        run_host "$host" "command -v '$FIO_BIN' >/dev/null" &
        pids+=($!)
    done
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}"
        rc=$?
        # 255 is ssh's own "could not connect" status. Local mode has no ssh, so
        # a local command that happens to exit 255 is just a missing fio.
        if [ "$rc" -eq 255 ] && [ "$LOCAL_MODE" -eq 0 ]; then
            failed+=("${HOSTS[$i]}: ssh failed")
        elif [ "$rc" -ne 0 ]; then
            failed+=("${HOSTS[$i]}: $FIO_BIN not found")
        fi
    done
    # A bare -C left its following token in HOSTS as a mere candidate. If that
    # exact token failed the ssh phase it is almost certainly the custom set's
    # name rather than a client -- confirm (5s, default yes), or assume so
    # outright on unattended runs. Everything else that failed still fails.
    if [ ${#failed[@]} -gt 0 ] && [ "$CUSTOMIZE" -eq 1 ] && [ -z "$CUSTOM_SET" ] \
            && [ -n "$C_CANDIDATE" ] && [ "${PREFLIGHT_RETRY:-0}" -eq 0 ]; then
        local cand_failed=0 rest=() as_set=0 h2 new=()
        for host in "${failed[@]}"; do
            case "$host" in
                "$C_CANDIDATE: ssh failed") cand_failed=1 ;;
                *) rest+=("$host") ;;
            esac
        done
        if [ "$cand_failed" -eq 1 ]; then
            if [ "$FAST_TRACK" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
                as_set=1
                log "'$C_CANDIDATE' is not reachable over ssh; treating it as the custom set name"
            elif confirm_timed 5 yes "'$C_CANDIDATE' is not reachable over ssh; treat it as the custom set name?"; then
                as_set=1
            fi
        fi
        if [ "$as_set" -eq 1 ]; then
            CUSTOM_SET=$C_CANDIDATE
            C_CANDIDATE=""
            for h2 in "${HOSTS[@]}"; do
                [ "$h2" = "$CUSTOM_SET" ] || new+=("$h2")
            done
            HOSTS=()
            [ ${#new[@]} -eq 0 ] || HOSTS=("${new[@]}")
            MASTER=${HOSTS[0]:-}
            failed=()
            [ ${#rest[@]} -eq 0 ] || failed=("${rest[@]}")
            if [ ${#HOSTS[@]} -eq 0 ]; then
                # The candidate was the only "host": this is a local run now.
                resolve_local_mode
                PREFLIGHT_RETRY=1 preflight
                return
            fi
        fi
    fi
    if [ ${#failed[@]} -gt 0 ]; then
        for host in "${failed[@]}"; do
            log "ERROR: $host" >&2
        done
        die "preflight failed on ${#failed[@]} of ${#HOSTS[@]} host(s), exiting"
    fi
    debug "preflight passed on all hosts"
}

# --- phase 1b: mount mode verification ----------------------------------------
# Decide whether a "FSTYPE OPTIONS" line from findmnt satisfies the guard.
# wekafs must be mounted forcedirect: fio's direct=1 asks for O_DIRECT per
# file, but only the forcedirect mount mode keeps the wekafs client cache
# out of the IO path entirely. Any other target must be a network
# filesystem: wekatester never writes to a local disk (Frank, 2026-10-06) --
# and an unmounted weka leaves its mount point an empty directory on the
# root disk, which would otherwise pass for a destination.
# The filesystem types (findmnt FSTYPE) that count as network filesystems
# besides wekafs; WEKATESTER_NETWORK_FSTYPES adds any this list lacks.
NETWORK_FSTYPES="nfs nfs4 cifs smb3 smbfs lustre gpfs beegfs ceph fuse.ceph fuse.ceph-fuse glusterfs fuse.glusterfs panfs pvfs2 orangefs ocfs2 gfs2 afs cvfs quobyte fuse.quobyte fuse.daos fuse.juicefs fuse.mfs ${WEKATESTER_NETWORK_FSTYPES:-}"

# ok, "fail <mode>" (wekafs in another mode), network (another network
# filesystem: the mount guard is weka's), or "local <type>" (anything else,
# the type empty when findmnt named none). Printed, and left in MOUNT_VERDICT.
classify_mount_line() {
    set -- $1
    local fstype=${1:-} opts=${2:-}
    if [ "$fstype" = "wekafs" ]; then
        case ",$opts," in
            *,forcedirect,*) MOUNT_VERDICT=ok ;;
            *,writecache,*)  MOUNT_VERDICT="fail writecache" ;;
            *,readcache,*)   MOUNT_VERDICT="fail readcache" ;;
            *)               MOUNT_VERDICT="fail unknown" ;;
        esac
    else
        case " $NETWORK_FSTYPES " in
            (*" $fstype "*) MOUNT_VERDICT=network ;;
            (*)             MOUNT_VERDICT="local $fstype" ;;
        esac
        [ -n "$fstype" ] || MOUNT_VERDICT="local "
    fi
    echo "$MOUNT_VERDICT"
}

# Remote snippet that creates a missing destination -- every host runs its
# own, and mkdir -p makes the shared ones harmless -- but only after the
# nearest directory that exists is seen on a wekafs mount, in this same
# session: the mount check that found it there ran earlier, maybe before an
# untimed prompt, and a weka client that restarts in between leaves its
# mount point an empty directory on the root disk. Exit 4: not wekafs now.
create_dest_cmd() {   # create_dest_cmd <dir>
    printf '%s' "p='$1'; while [ ! -e \"\$p\" ]; do q=\$(dirname \"\$p\"); [ \"\$q\" != \"\$p\" ] || exit 4; p=\$q; done; [ \"\$(findmnt -T \"\$p\" -n -o FSTYPE)\" = wekafs ] || exit 4; mkdir -p -- '$1'"
}

# Remote snippet for a destination that does not exist: print its nearest
# existing ancestor on one line and that ancestor's findmnt FSTYPE,OPTIONS on
# the next. Exits nonzero when the destination DOES exist (the caller's plain
# findmnt then failed for some other reason, and the old message stands) or
# when nothing on the way up exists. dirname rather than ${p%/*}: it handles
# a trailing slash and stops at /.
missing_dir_probe_cmd() {   # missing_dir_probe_cmd <dir>
    printf '%s' "[ ! -e '$1' ] || exit 1; p='$1'; while [ ! -e \"\$p\" ]; do q=\$(dirname \"\$p\"); [ \"\$q\" != \"\$p\" ] || exit 1; p=\$q; done; printf '%s\\n' \"\$p\"; findmnt -T \"\$p\" -n -o FSTYPE,OPTIONS"
}

# One probe file, created and removed, as the same user fio will run as. On
# a shared filesystem the directory's owner/mode is a property of the
# filesystem itself, so one failing host usually means all do.
probe_writable() {   # probe_writable <host> <dir>
    # the same session drops the host's name into the run's group file
    # there: collect_fs_groups hashes it once every host is through
    host_name_v "$1"
    run_host "$1" "p='$2'/.wekatester-write-probe.\$\$; : > \"\$p\" && rm -f \"\$p\"${GROUP_FILE:+ && printf '%s\\n' '$HOST_NAME' >> '$2/$GROUP_FILE'}"
}

# --- filesystem groups (Frank, 2026-10-02) --------------------------------------
# Clients whose destinations are one directory share one fleet-shared read
# set, laid out once for all of them and priced once against their
# filesystem. A mount path says nothing about that: one weka filesystem can
# sit at /mnt/foo on one client and /mnt/bar on another. So the mount check's
# write probe has every client append its name to the run's group file in its
# own destination, and once every client has passed every other check, each
# returns the file's hash. Equal hashes are one file, so one directory, so one
# group. A separate subdirectory, even of the same filesystem, is a group of
# its own -- the operator gave it its own directory on purpose. Two different
# files can never hash alike: each ends with a name only its own clients
# appended, and every reader of one file reads the same bytes even if an
# append was lost. The file is removed once hashed. Writes $WORK_DIR/groups,
# "<host> <group>" in host order, a group numbered by its first host.
collect_fs_groups() {
    [ -n "$GROUP_FILE" ] || return 0
    local i h hd pids=() sum n=0 line
    mkdir -p "$WORK_DIR/fsgroup" || die "cannot create $WORK_DIR/fsgroup"
    load_host_dirs
    for i in "${!HOSTS[@]}"; do
        h=${HOSTS[$i]}
        ( run_host "$h" "sha256sum '${HOST_DIRS[$i]}/$GROUP_FILE'" > "$WORK_DIR/fsgroup/$i.sum" ) &
        pids[$i]=$!
    done
    : > "$WORK_DIR/fsgroup/sums"
    for i in "${!HOSTS[@]}"; do
        h=${HOSTS[$i]}
        sum=""
        if wait "${pids[$i]}"; then read -r sum _ < "$WORK_DIR/fsgroup/$i.sum" || sum=""; fi
        case "$sum" in
            (*[!0-9a-f]*|"") die "$h: cannot hash the filesystem-group file ${HOST_DIRS[$i]}/$GROUP_FILE (written by the mount check; the destination must not change after it)" ;;
        esac
        printf '%s %s\n' "$h" "$sum" >> "$WORK_DIR/fsgroup/sums"
    done
    pids=()
    for i in "${!HOSTS[@]}"; do
        run_host "${HOSTS[$i]}" "rm -f '${HOST_DIRS[$i]}/$GROUP_FILE'" &
        pids+=($!)
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || log "WARNING: ${HOSTS[$i]}: could not remove ${HOST_DIRS[$i]}/$GROUP_FILE" >&2
    done
    awk '!($2 in g) {g[$2] = ++n} {print $1, g[$2]}' "$WORK_DIR/fsgroup/sums" > "$WORK_DIR/groups"
    n=$(awk '{print $2}' "$WORK_DIR/groups" | sort -u | wc -l | tr -d ' ')
    if [ "$n" -le 1 ]; then
        debug "filesystem groups: all ${#HOSTS[@]} host(s) share $(host_dir "${HOSTS[0]}")"
        return 0
    fi
    log "filesystem groups: $n -- each lays out and is priced for its own fleet-shared read set"
    for i in $(seq 1 "$n"); do
        line=$(awk -v g="$i" '$2 == g {printf "%s%s", (c++ ? " " : ""), $1}' "$WORK_DIR/groups")
        hd=$(host_dir "${line%% *}")
        log "  group $i: $line (at $hd on ${line%% *})"
    done
}

# The first host of <host>'s filesystem group: it lays out, prices and
# removes the group's fleet-shared read set. Every host is one group when
# collect_fs_groups did not run.
group_first() {   # group_first <host>
    if [ -s "$WORK_DIR/groups" ]; then
        awk -v h="$1" '$1 == h {g = $2} {if (!($2 in f)) f[$2] = $1} END {print (g != "" ? f[g] : h)}' "$WORK_DIR/groups"
    else
        printf '%s\n' "${HOSTS[0]}"
    fi
}

# Every host of <host>'s filesystem group, in host order, one per line.
group_members() {   # group_members <host>
    if [ -s "$WORK_DIR/groups" ]; then
        awk -v h="$1" 'NR == FNR {if ($1 == h) g = $2; next} $2 == g {print $1}' \
            "$WORK_DIR/groups" "$WORK_DIR/groups"
    else
        printf '%s\n' "${HOSTS[@]}"
    fi
}

write_fix_hint() {   # write_fix_hint <dir> -> how to fix a directory the login user cannot write
    printf '%s' "fix the root's owner/mode (a one-time 'sudo chmod 1777 $1' on any host persists in the filesystem) or run as a user that can write"
}

# The one prompt of the mount pass, asked once for every host that lacks the
# destination. -r/-n: 5s, default create, unattended without a terminal (the
# -t host file precedent); otherwise a terminal is required and only a yes
# creates.
confirm_create_dirs() {   # confirm_create_dirs <count>
    local msg="create the missing destination directory on $1 host(s)?"
    if [ "$FAST_TRACK" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
        if try_interactive; then
            confirm_timed 5 yes "$msg" \
                || die "destination directory does not exist on $1 host(s)"
        else
            log "destination directory does not exist on $1 host(s); creating it (unattended)"
        fi
    else
        require_interactive "creating the destination directory" "create it yourself, or use -r"
        confirm_explicit "$msg" \
            || die "destination directory does not exist on $1 host(s)"
    fi
}

# All workers: -d must not be a cached-mode wekafs mount, and it must be
# writable by the login user -- fio creates every data file there, and its
# client mode reports a worker-side EACCES so quietly that without this probe
# the run "succeeds" with zero IO.
#
# A destination that does not exist yet is not a fault when its nearest
# existing ancestor is a wekafs mount: the operator is asked once, for every
# host that lacks it, and the directory is created as the login user (so it
# is theirs, and the probe then proves it) before anything runs. Anything
# else that is missing stays a hard stop -- with wekafs not mounted the
# ancestor is the root filesystem, and a mistyped -d created there would
# benchmark the boot disk. Under -r a cached mount mode is a WARNING rather
# than a stop: the client cache is then in the IO path, the numbers include
# it, and the warning is replayed into the run log so the bundle says so.
verify_mount_mode() {
    log "checking mount mode and writability of the destination on ${#HOSTS[@]} host(s)..."
    # one name per run, so two runs sharing a destination never read each
    # other's group lines (collect_fs_groups)
    [ -n "$GROUP_FILE" ] || printf -v GROUP_FILE '.wekatester-group.%(%s)T.%s.lst' -1 "$$"
    local host line verdict failed=() mode_fail=0 write_fail=0 local_fail=0 gone_fail=0 hd anc i ft
    local missing=() missing_dirs=() missing_parents=()
    local cached_hosts=() cached_modes=() mode who n
    # Three fan-outs instead of one serial walk. Every host still receives
    # the same commands in the same order -- findmnt; the ancestor walk when
    # that fails; the write probe once the mode passes (or is only a warning
    # under -r) -- and the messages are collected one per host in host
    # order, exactly as the walk produced them; only the waiting overlaps.
    # Serially this was 2 sessions x ~30ms per host, twice under -C: seven
    # seconds at 111 hosts for a check whose floor is one round trip. A
    # backgrounded command has nowhere to put its output but a file, so each
    # round writes per-host files under the work dir (a real run: cleaned up
    # with it) or a temp dir (the suite calls this phase on its own).
    local td pids=() hds=() rcs=() lines=() ancs=() msgs=() probe=()
    td=$(mktemp -d "${WORK_DIR:-${TMPDIR:-/tmp}}/mnt.XXXXXX") \
        || die "cannot create a scratch dir for the mount check"
    load_host_dirs
    for i in "${!HOSTS[@]}"; do
        hds[$i]=${HOST_DIRS[$i]}
        ( run_host "${HOSTS[$i]}" "findmnt -T '${hds[$i]}' -n -o FSTYPE,OPTIONS" > "$td/$i.mnt" ) &
        pids[$i]=$!
    done
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}"; rcs[$i]=$?
        # findmnt -n prints one line: read it, no $(cat) per host
        line=""; IFS= read -r line < "$td/$i.mnt" || :
        lines[$i]=$line
    done
    # findmnt fails for a path that does not exist: classify the nearest
    # ancestor that does, and remember that the destination is missing
    pids=()
    for i in "${!HOSTS[@]}"; do
        [ "${rcs[$i]}" -ne 0 ] || continue
        ( run_host "${HOSTS[$i]}" "$(missing_dir_probe_cmd "${hds[$i]}")" > "$td/$i.anc" ) &
        pids[$i]=$!
    done
    for i in "${!HOSTS[@]}"; do
        [ "${rcs[$i]}" -ne 0 ] || continue
        if wait "${pids[$i]}" && line=$(cat "$td/$i.anc") \
                && [ "$line" != "${line#*$'\n'}" ]; then
            ancs[$i]=${line%%$'\n'*}; lines[$i]=${line#*$'\n'}
        else
            msgs[$i]="${HOSTS[$i]}: findmnt failed for ${hds[$i]} -- does it exist? (wrong -d?)"
        fi
    done
    # classification is local; probe[i] marks the hosts that get the write
    # probe: destination present, mode ok (or -r's warning)
    for i in "${!HOSTS[@]}"; do
        [ -z "${msgs[$i]:-}" ] || continue
        host=${HOSTS[$i]}; hd=${hds[$i]}; anc=${ancs[$i]:-}
        classify_mount_line "${lines[$i]}" > /dev/null; verdict=$MOUNT_VERDICT
        case "$verdict" in
            ok)   ;;
            network)
                  if [ -n "$anc" ]; then
                      msgs[$i]="$host: $hd does not exist, and $anc is not a wekafs mount -- create it yourself, or check that -d names the right directory"
                      continue
                  fi
                  debug "$host: $hd is on a network filesystem, not wekafs; the weka mount guard does not apply" ;;
            local*)
                  # refused before anything is written: a local disk is never a target
                  local_fail=1
                  ft=${verdict#local }; [ -n "$ft" ] || ft="a filesystem findmnt did not name"
                  if [ -n "$anc" ]; then
                      msgs[$i]="$host: $hd does not exist, and $anc is on $ft, not a network filesystem -- wekatester never writes to a local disk: check that weka is mounted on this host and that -d names a directory on it"
                  else
                      msgs[$i]="$host: $hd is on $ft, not a network filesystem -- wekatester never writes to a local disk: check that weka (or another network filesystem) is mounted there on this host"
                  fi
                  continue ;;
            fail*) if [ "$FAST_TRACK" -eq 1 ]; then
                       # said once per MODE after the loop: 111 identical
                       # lines is noise, not information (field fleet D, 2026-09-09)
                       cached_hosts+=("$host"); cached_modes+=("${verdict#fail }")
                   else
                       msgs[$i]="$host: wekafs mounted ${verdict#fail } (need forcedirect)"
                       mode_fail=1
                       continue
                   fi ;;
        esac
        if [ -n "$anc" ]; then
            missing+=("$host"); missing_dirs+=("$hd"); missing_parents+=("$anc")
            continue   # created below, once the operator agrees, then probed
        fi
        probe[$i]=1
    done
    pids=()
    for i in "${!HOSTS[@]}"; do
        [ "${probe[$i]:-0}" -eq 1 ] || continue
        ( probe_writable "${HOSTS[$i]}" "${hds[$i]}" ) &
        pids[$i]=$!
    done
    for i in "${!HOSTS[@]}"; do
        [ "${probe[$i]:-0}" -eq 1 ] || continue
        wait "${pids[$i]}" \
            || { msgs[$i]="${HOSTS[$i]}: cannot create files in ${hds[$i]} -- $(write_fix_hint "${hds[$i]}")"
                 write_fail=1; }
    done
    for i in "${!HOSTS[@]}"; do
        [ -z "${msgs[$i]:-}" ] || failed+=("${msgs[$i]}")
    done
    rm -rf "$td"
    # The -r warning, one line per distinct cached mode: the host alone when
    # it is one host, "all N" when it is every host, the list otherwise.
    if [ ${#cached_hosts[@]} -gt 0 ]; then
        for mode in $(printf '%s\n' "${cached_modes[@]}" | sort -u); do
            who=""; n=0
            for i in "${!cached_hosts[@]}"; do
                [ "${cached_modes[$i]}" = "$mode" ] || continue
                who="$who${who:+ }${cached_hosts[$i]}"; n=$((n + 1))
            done
            if [ "$n" -eq 1 ]; then
                warn_prerun "$who: wekafs mounted $mode (need forcedirect); -r continues anyway -- the client cache is in the IO path and the numbers include it"
            elif [ "$n" -eq ${#HOSTS[@]} ]; then
                warn_prerun "wekafs mounted $mode (need forcedirect) on all $n hosts; -r continues anyway -- the client cache is in the IO path and the numbers include it"
            else
                warn_prerun "wekafs mounted $mode (need forcedirect) on $n of ${#HOSTS[@]} hosts ($who); -r continues anyway -- the client cache is in the IO path and the numbers include it"
            fi
        done
    fi
    # Missing destinations are created only when nothing else is wrong: no
    # mutation on a run that is about to stop anyway.
    if [ ${#missing[@]} -gt 0 ]; then
        if [ ${#failed[@]} -gt 0 ]; then
            for i in "${!missing[@]}"; do
                log "${missing[$i]}: ${missing_dirs[$i]} does not exist; not created while other checks fail"
            done
        else
            for i in "${!missing[@]}"; do
                log "${missing[$i]}: ${missing_dirs[$i]} does not exist; ${missing_parents[$i]} is a wekafs mount"
            done
            confirm_create_dirs "${#missing[@]}"
            # one fan-out, each host its mkdir and then its write probe
            local rc
            pids=()
            for i in "${!missing[@]}"; do
                ( run_host "${missing[$i]}" "$(create_dest_cmd "${missing_dirs[$i]}")"
                  case $? in (0) ;; (4) exit 4 ;; (*) exit 2 ;; esac
                  probe_writable "${missing[$i]}" "${missing_dirs[$i]}" || exit 3 ) &
                pids[$i]=$!
            done
            for i in "${!missing[@]}"; do
                host=${missing[$i]}; hd=${missing_dirs[$i]}
                wait "${pids[$i]}"; rc=$?
                if [ "$rc" -eq 4 ]; then
                    failed+=("$host: $hd was not created -- the nearest directory above it is no longer on a wekafs mount (did the weka client restart?)")
                    gone_fail=1
                    continue
                fi
                if [ "$rc" -eq 2 ]; then
                    failed+=("$host: cannot create $hd -- $(write_fix_hint "${missing_parents[$i]}")")
                    write_fail=1
                    continue
                fi
                log "$host: created $hd"
                [ "$rc" -eq 0 ] \
                    || { failed+=("$host: cannot create files in $hd -- $(write_fix_hint "$hd")")
                         write_fail=1; }
            done
        fi
    fi
    if [ ${#failed[@]} -gt 0 ]; then
        for line in "${failed[@]}"; do log "ERROR: $line" >&2; done
        # Only advise a remount when a mount mode was actually the problem. When
        # every failure came from findmnt, the mode is unknown rather than
        # wrong -- most often -d simply names a directory that does not exist
        # (a bare run defaults to /mnt/weka), and "remount forcedirect" would be
        # confidently wrong advice pointing away from the real fault.
        [ "$mode_fail" -eq 0 ] || \
            die "wekafs at $DIRECTORY must be mounted with forcedirect; remount and re-run"
        [ "$local_fail" -eq 0 ] || \
            die "a destination is on a local filesystem; wekatester writes only to weka or another network filesystem -- nothing was written"
        [ "$gone_fail" -eq 0 ] || \
            die "the weka mount above a missing destination went away before it was created; nothing was created on a local disk -- check the weka client and re-run"
        [ "$write_fail" -eq 0 ] || \
            die "$DIRECTORY is not writable on every host; fio cannot lay out its files there"
        die "cannot determine the mount at $DIRECTORY; check that it exists and that -d names the right directory"
    fi
    debug "mount mode and writability ok on all hosts"
}

# --- phase 2: fio server lifecycle ---------------------------------------------
# Start 'fio --server' on every host; guarantee teardown on any exit path.
# Daemons are tracked by pidfile only -- never pkill by name, the host may be
# running fio jobs that are not ours.
FIO_STARTED=0

# remote shell snippet: kill the pidfile daemon and WAIT until every process
# of ours is actually gone (TERM, up to 3s, then KILL). The pidfile only names
# the parent -- fio --server forks a child per client connection (same argv),
# so the drain loop matches the full unique command line instead. The pattern
# is anchored to the fio binary so the shell running this snippet (whose own
# cmdline contains the pattern) can never match itself, and the pidfile path
# makes it ours alone -- fio runs that are not ours can never match.
kill_fio_cmd() {   # kill_fio_cmd [priv]
    # A server launched under sudo/dzdo/doas taskset is root-owned: the kill,
    # the pidfile removal, and the last-resort pkill all need the same
    # escalator or every privileged run leaks a root fio server.
    # The ^ anchor is load-bearing: the shell running this snippet carries
    # the pattern in its OWN cmdline and must never match itself (an
    # unanchored pkill -9 here once killed the teardown). taskset EXECs fio,
    # so the daemon's argv still begins with the binary even when launched
    # as "sudo taskset -c ... fio --server ...".
    local priv=${1:+$1 }
    local pat="^$FIO_BIN --server --daemonize=$FIO_PIDFILE"
    printf '%s' "if [ -f '$FIO_PIDFILE' ]; then _o=\$(${priv}kill \$(cat '$FIO_PIDFILE') 2>&1) || true; ${priv}rm -f '$FIO_PIDFILE'; fi; \
        i=0; while pgrep -f '$pat' >/dev/null && [ \"\$i\" -lt 15 ]; do sleep 0.2; i=\$((i+1)); done; \
        if pgrep -f '$pat' >/dev/null; then ${priv}pkill -9 -f '$pat' || true; fi"
}

start_fio_servers() {
    echo
    log "starting fio servers on ${#HOSTS[@]} host(s)..."
    local pids=() failed=() host i priv cpus launch base
    for host in "${HOSTS[@]}"; do
        priv=""; cpus=""
        [ ! -s "$AUTH_DIR/$host.priv" ] || IFS= read -r priv < "$AUTH_DIR/$host.priv" || :
        [ ! -s "$AUTH_DIR/$host.cpus" ] || IFS= read -r cpus < "$AUTH_DIR/$host.cpus" || :
        base="'$FIO_BIN' --server --daemonize='$FIO_PIDFILE'"
        # a requested cpu list pins the server (children inherit the mask);
        # a recorded escalator means the mask cannot be self-applied -- but
        # the escalation is for the TASKSET, not for fio: fio drops back to
        # the login user when runuser allows, keeping the test files
        # user-owned (a root fio leaves files that later unprivileged runs
        # EACCES on). No runuser, or a policy refusal, means a root fio --
        # the remote says which happened and the NOTE below reports it.
        launch=$base
        [ -z "$cpus" ] || launch="taskset -c $cpus $launch"
        if [ -n "$priv" ] && [ -n "$cpus" ]; then
            launch="u=\$(id -un); if command -v runuser >/dev/null && $priv runuser -u \"\$u\" -- true </dev/null; then echo WEKATESTER_FIO_AS=user; $priv taskset -c $cpus runuser -u \"\$u\" -- $base; else echo WEKATESTER_FIO_AS=root; $priv taskset -c $cpus $base; fi"
        elif [ -n "$priv" ]; then
            launch="$priv $launch"
        fi
        run_host "$host" "$(kill_fio_cmd "$priv"); $launch" > "$WORK_DIR/launch.$host" &
        pids+=($!)
    done
    FIO_STARTED=1   # set before checking: partial starts must still be torn down
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}" || failed+=("${HOSTS[$i]}")
    done
    # one grep for the fleet: the launches that reported a root fio
    local roots
    roots=$(grep -l "WEKATESTER_FIO_AS=root" "${HOSTS[@]/#/$WORK_DIR/launch.}") || :
    for host in "${HOSTS[@]}"; do
        case $'\n'"$roots"$'\n' in
            (*$'\n'"$WORK_DIR/launch.$host"$'\n'*)
                log "NOTE: $host: fio runs as root (no runuser drop-back) -- files it creates are root-owned, and a later unprivileged run on them will fail with EACCES" >&2 ;;
        esac
    done
    [ ${#failed[@]} -eq 0 ] || die "failed to start fio server on: ${failed[*]}"
    # let the listeners settle before the first coordinator connect; the
    # override exists for the test suite, whose stubbed servers need no settling
    sleep "${WEKATESTER_SETTLE:-2}"
    debug "fio servers running on all hosts"
}

# The coordinator ($MASTER) must reach every worker on $FIO_PORT -- ssh working
# does not imply the fio port is open (host firewalls commonly allow only 22).
# fio itself treats an unreachable client as a warning and silently benchmarks
# the survivors, so we refuse to run instead.
# The remote side of the port check: probe every worker's fio port from the
# master, all at once, inside ONE shell. Each probe is a single statement on
# purpose -- bash does not exit on a failed exec redirection, so a compound
# probe would mask the connect failure -- and prints "FAIL <host>" when it
# cannot connect. DONE last proves the snippet ran to the end; without it
# the caller knows the SESSION failed, which is not a firewall. The wait is
# the remote shell's, over its own children only.
port_probe_cmd() {   # port_probe_cmd <host>... -> remote snippet
    local h cmd="${COORD_NPROC:+ulimit -Su $COORD_NPROC; }pids=''; for h in"
    for h in "$@"; do cmd="$cmd '$h'"; done
    cmd="$cmd; do ( timeout 3 bash -c \": </dev/tcp/\$h/$FIO_PORT\" || echo \"FAIL \$h\" ) & pids=\"\$pids \$!\"; done; wait \$pids; echo DONE"
    printf '%s' "$cmd"
}

# --- the limits a run must fit (Frank, 2026-10-06) -------------------------------
# Every client runs at once -- that is the test -- so the limits that grow with
# the fleet are checked before anything starts. A soft limit short of what the
# run needs is raised for it when the hard limit allows that (no privilege
# needed, nothing changed on the box); otherwise the run stops, naming the
# limit and the host.
limit_short() {   # limit_short <limit|unlimited> <need>: the limit is a number below the need
    case $1 in (unlimited|''|*[!0-9]*) return 1 ;; esac
    [ "$1" -lt "$2" ]
}

# The controller: an ssh master per host for the whole run, and while a phase
# talks to every host at once a subshell and an ssh client per host -- three
# per host (measured: 302 processes for 100 hosts with a stub ssh that adds a
# sleep of its own). Checked before the first connection.
check_controller_procs() {
    [ "$LOCAL_MODE" -eq 0 ] || return 0
    local n=${#HOSTS[@]} soft hard cur need
    soft=$(ulimit -Su); hard=$(ulimit -Hu)
    cur=$(ps -u "$(id -u)" -o pid= | wc -l)
    need=$(( 3 * n + cur + 64 ))
    limit_short "$soft" "$need" || return 0
    if limit_short "$hard" "$need"; then
        die "this controller allows $(id -un) $hard processes (ulimit -Hu), and $n hosts need about $need at once: an ssh master per host, plus a subshell and an ssh client per host while a phase talks to every host ($cur already running) -- raise nproc for $(id -un) (/etc/security/limits.conf), or run from a controller that allows more"
    fi
    ulimit -Su "$need" || die "cannot raise this run's process limit to $need (ulimit -Su)"
    log "note: raised this run's process limit (ulimit -u) from $soft to $need for $n hosts (the hard limit is $hard)"
}

# The coordinator (the first host), from its probe: fio --client keeps one
# connection open per client and raises no limit itself (client.c polls
# them all), and the port check probes every client at once from one shell,
# three processes each. The raise rides those commands (COORD_NOFILE,
# COORD_NPROC); the probe ran in the same kind of ssh session they do.
COORD_NOFILE=""; COORD_NPROC=""
check_coordinator_limits() {
    local n=${#HOSTS[@]} tag sn hn su hu need
    read -r tag sn hn su hu < <(awk '$1 == "limits" {print; exit}' "$WORK_DIR/probe/$MASTER")
    if [ "$tag" != limits ]; then
        log "WARNING: $MASTER: its probe reported no limits; the coordinator's open files and processes are unchecked" >&2
        return 0
    fi
    need=$(( n + 64 ))
    if limit_short "$sn" "$need"; then
        limit_short "$hn" "$need" \
            && die "$MASTER: fio's coordinator keeps one connection open per client, so $n clients need about $need open files, and $MASTER allows $hn (ulimit -Hn) -- raise nofile for the login user on $MASTER (/etc/security/limits.conf), or name a host that allows more first"
        COORD_NOFILE=$need
        log "note: $MASTER: fio's coordinator runs with its open-file limit raised from $sn to $need for $n clients (the hard limit is $hn)"
    fi
    need=$(( 3 * n + 64 ))
    if limit_short "$su" "$need"; then
        limit_short "$hu" "$need" \
            && die "$MASTER: the fio port check probes every client at once from one shell, so $n clients need about $need processes there, and $MASTER allows $hu (ulimit -Hu) -- raise nproc for the login user on $MASTER (/etc/security/limits.conf), or name a host that allows more first"
        COORD_NPROC=$need
        log "note: $MASTER: the port check runs with its process limit raised from $su to $need for $n clients (the hard limit is $hu)"
    fi
}

# One ssh session to the master, N probes inside it. One session PER WORKER
# used to fan N sessions into the master's single multiplexed connection:
# sshd refuses the 11th (MaxSessions, default 10), ssh drops to fresh
# connections, and MaxStartups (10:30:100) then resets the burst -- so on
# 111 workers 39 probes never ran and were reported as firewalls (field fleet D,
# 2026-09-09). Every other phase is one session per DISTINCT host, which is
# fine; this was the only place that concentrated N sessions on one host.
verify_fio_ports() {
    log "verifying fio port $FIO_PORT reachability from $MASTER..."
    local out rc failed=() host hint line
    out=$(run_host "$MASTER" "$(port_probe_cmd "${HOSTS[@]}")"); rc=$?
    case "$out" in
        (*DONE*) ;;   # the session ran to its end; FAIL lines, not rc, carry the verdict
        (*) die "cannot run the fio port check on $MASTER -- the ssh session to the master failed (rc=$rc), which says nothing about port $FIO_PORT" ;;
    esac
    while IFS= read -r line; do
        case "$line" in ("FAIL "*) failed+=("${line#FAIL }") ;; esac
    done <<PORTEOF
$out
PORTEOF
    if [ ${#failed[@]} -gt 0 ]; then
        # A firewall is the overwhelmingly likely cause between two machines,
        # but never on loopback: there the usual culprit is the name resolving
        # to ::1 while fio's listener is on IPv4.
        hint="(host firewall?)"
        [ "$LOCAL_MODE" -eq 0 ] || \
            hint="(loopback resolution? fio binds IPv4 -- check that localhost resolves to 127.0.0.1)"
        for host in "${failed[@]}"; do
            log "ERROR: $MASTER cannot reach $host:$FIO_PORT $hint" >&2
        done
        die "fio port check failed on ${#failed[@]} of ${#HOSTS[@]} host(s), exiting"
    fi
    debug "fio port reachable on all hosts"
}

cleanup() {
    local host f priv pids=()
    # the end-of-run pressure/sar capture rides the still-open connections;
    # after this function the control masters are gone
    if [ "$PRESSURE_END_DONE" -eq 0 ]; then
        PRESSURE_END_DONE=1
        snapshot_pressure end
    fi
    if [ "$FIO_STARTED" -eq 1 ]; then
        FIO_STARTED=0   # idempotent: EXIT trap may follow an INT trap
        log "stopping fio servers..."
        for host in "${HOSTS[@]}"; do
            # a privileged launch made a ROOT-owned server: the kill needs
            # the same escalator or every privileged run leaks a root fio
            # (seen live: "Operation not permitted" teardowns, orphan healed
            # only by the NEXT privileged run's pre-start sweep)
            priv=""
            [ -z "$AUTH_DIR" ] || [ ! -s "$AUTH_DIR/$host.priv" ] || IFS= read -r priv < "$AUTH_DIR/$host.priv" || :
            run_host "$host" "$(kill_fio_cmd "$priv"); rm -rf '$TARGET_DIR' '$TARGET_DIR.cal'" &
            pids+=($!)
        done
        # These pids only -- a bare `wait` also waits on the run-log tees,
        # which cannot exit until finalize_run_dir closes their fifos AFTER
        # cleanup returns: that is a deadlock, not a slow teardown.
        wait "${pids[@]}" || true
    fi
    if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
        # close any ControlMaster still running, then drop the whole work dir.
        # -O exit talks only to the socket; the trailing hostname is unused.
        # -q silences ssh's "Exit request sent." banner -- a status line, not a
        # result: a failed -O exit still reports its failure on stderr.
        # every master at once: one ssh per socket in turn was seconds of
        # teardown at a few hundred hosts
        pids=()
        for f in "${CTRL_DIR:-$WORK_DIR/c}"/*; do
            [ -S "$f" ] || continue
            ssh -q -O exit -o ControlPath="$f" unused-host-arg &
            pids+=($!)
        done
        [ ${#pids[@]} -eq 0 ] || wait "${pids[@]}" || true
        rm -rf "$WORK_DIR"
    fi
}

# --- connection establishment ----------------------------------------------------

# The ssh master sockets, in the work dir: /dev/shm/wt.XXXXXX/c plus %C's 40
# and ssh's ~17-byte temporary suffix stays well inside a unix socket path.
make_ctrl_dir() {
    CTRL_DIR=$WORK_DIR/c
    mkdir -p "$CTRL_DIR" || die "cannot create $CTRL_DIR"
}
# Try every credential against every client, keeping the first success per
# client. Rounds, in order: pre-existing user-owned masters, plain defaults
# (agent and ssh_config), each -i key, each -p password -- keys before
# passwords because a wrong password costs lockout counters, and each group
# in the order given. Every round attempts ONLY the clients still
# unconnected, all in parallel. Nothing here dies on a failed host: a client
# no credential reaches simply fails preflight -- which is also what lets a
# bare -C candidate resolve into a set name.
#
# Passwords ride the SSH_ASKPASS-over-fifo trick (no sshpass): one fifo PER
# ATTEMPT so parallel readers never race, written from a subshell that holds
# its own read-write fd -- the write cannot block if ssh dies before asking
# -- and the helper reads exactly ONE LINE so it never waits on an EOF.
# NumberOfPasswordPrompts=1 turns a wrong password into a clean failure.
# The auth overrides go BEFORE $SSH_OPTS: ssh keeps the FIRST value of a
# repeated option, and SSH_OPTS carries BatchMode=yes, which would silently
# disable askpass.
prompt_password_creds() {
    local j login pw
    require_interactive "-p" "use key-based auth (-i) for unattended runs"
    for ((j = 1; j <= PW_COUNT; j++)); do
        printf 'ssh login %d of %d (empty for %s): ' "$j" "$PW_COUNT" "$(id -un)" >&"$PROMPT_OUT_FD"
        IFS= read -r login <&"$PROMPT_IN_FD" || die "no login read"
        case "$login" in
            *[[:space:]]*) die "logins must not contain whitespace" ;;
        esac
        printf 'password for %s: ' "${login:-the default user}" >&"$PROMPT_OUT_FD"
        IFS= read -r -s pw <&"$PROMPT_IN_FD" || die "no password read"
        printf '\n' >&"$PROMPT_OUT_FD"
        [ -n "$pw" ] || die "empty password (pair $j of $PW_COUNT)"
        PW_LOGINS+=("$login")
        PW_SECRETS+=("$pw")
    done
}

# One connection attempt. Modes: external = is a user-owned master already
# alive for this host (ssh -O check via the user's own config -- OUR
# ControlPath deliberately absent)? default/key = establish a master in our
# socket dir with BatchMode. pw = same, fed through askpass.
SETSID_BIN=""
attempt_host() {   # attempt_host <mode> <host> <login> <key-or-pw-index>
    local u=() fifo rc
    [ -z "$3" ] || u=(-o "User=$3")
    case "$1" in
        external)
            ssh -O check $SSH_OPTS "$2" > "$AUTH_DIR/$2.extcheck" 2>&1 ;;
        default)
            ssh -n "${u[@]}" $SSH_OPTS $CONTROL_OPTS "$2" true ;;
        key)
            ssh -n "${u[@]}" -o "IdentityFile=$4" -o IdentitiesOnly=yes \
                $SSH_OPTS $CONTROL_OPTS "$2" true ;;
        pw)
            fifo="$AUTH_DIR/$2.fifo"
            mkfifo -m 600 "$fifo" || return 1
            # Hold the fifo open read-write for the whole attempt (auth_round
            # backgrounds attempt_host, so fd 4 is private to this attempt):
            # a fifo discards its contents when its last fd closes, and the
            # helper's read-open blocks until SOME writer exists -- both
            # problems end as long as this fd outlives the ssh below. The
            # write itself can never block (we are our own reader), and the
            # helper reads exactly ONE LINE so it never waits for an EOF
            # this held fd would withhold.
            exec 4<>"$fifo"
            printf '%s\n' "${PW_SECRETS[$4]}" >&4
            WEKATESTER_PW_FIFO="$fifo" SSH_ASKPASS="$AUTH_DIR/askpass.sh" \
                SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-wekatester}" \
                $SETSID_BIN ssh -o BatchMode=no -o NumberOfPasswordPrompts=1 \
                "${u[@]}" $SSH_OPTS $CONTROL_OPTS "$2" true </dev/null
            rc=$?
            exec 4>&-
            rm -f "$fifo" "$fifo.used"
            return "$rc" ;;
    esac
}

# One round: this credential against every still-unconnected client, in
# parallel. Winners record their per-host transport delta and leave the pool.
REMAINING=()
auth_round() {   # auth_round <label> <mode> <login> <key-or-pw-index>
    [ ${#REMAINING[@]} -gt 0 ] || return 0
    local host pids=() effs=() left=() i n=0 eff logins=()
    # a credential's own login wins; else the host file pins this host's
    # (one awk for the round, not one per host)
    if [ -z "$3" ] && [ -f "$WORK_DIR/targets.phase1" ]; then
        while IFS= read -r eff; do logins+=("$eff"); done \
            < <(targets_column 2 "$WORK_DIR/targets.phase1" "${REMAINING[@]}")
    fi
    for i in "${!REMAINING[@]}"; do
        host=${REMAINING[$i]}
        eff=$3
        [ -n "$eff" ] || eff=${logins[$i]:-}
        effs+=("${eff:-.}")
        attempt_host "$2" "$host" "$eff" "$4" &
        pids+=($!)
    done
    for i in "${!REMAINING[@]}"; do
        host=${REMAINING[$i]}
        if wait "${pids[$i]}"; then
            n=$((n + 1))
            eff=${effs[$i]}; [ "$eff" = "." ] && eff=""
            [ "$2" != external ] || : > "$AUTH_DIR/$host.external"
            [ -z "$eff" ] || printf '%s\n' "$eff" > "$AUTH_DIR/$host.user"
            debug "$host: connected via $1"
        else
            left+=("$host")
        fi
    done
    REMAINING=()
    [ ${#left[@]} -eq 0 ] || REMAINING=("${left[@]}")
    [ "$n" -eq 0 ] || log "auth: $n host(s) connected via $1"
}

# The helper ssh runs for every question it would put to a terminal under
# -p. The password goes back ONCE per attempt: a second question
# (keyboard-interactive after password, a PAM retry) gets a failure, never a
# second read on the fifo, which the attempt holds open and never closes. A
# host-key question gets "no", so an unknown key fails the attempt the way
# BatchMode fails a key attempt -- answered with the password, ssh asked
# again and that second read hung the run forever. A key's passphrase
# question is refused without using the answer up, so ssh moves on to the
# password (keys had their own rounds before this one).
write_askpass_helper() {   # write_askpass_helper <path>
    cat > "$1" <<'ASKSH' || die "cannot write the askpass helper"
#!/bin/sh
case "$1" in
    *"continue connecting"*|*"(yes/no"*) echo no; exit 0 ;;
    *[Pp]assphrase*) exit 1 ;;
esac
[ ! -e "$WEKATESTER_PW_FIFO.used" ] || exit 1
: > "$WEKATESTER_PW_FIFO.used"
IFS= read -r pw < "$WEKATESTER_PW_FIFO"
printf '%s\n' "$pw"
ASKSH
    chmod 700 "$1" || die "cannot mark the askpass helper executable"
}

establish_connections() {
    AUTH_DIR="$WORK_DIR/auth"
    mkdir -p "$AUTH_DIR" || die "cannot create $AUTH_DIR"
    [ "$PW_COUNT" -eq 0 ] || prompt_password_creds
    # The helper resolves its fifo at run time from the attempt's environment
    # (single-quoted heredoc-style: no expansion here).
    write_askpass_helper "$AUTH_DIR/askpass.sh"
    # setsid detaches the tty for OpenSSH older than 8.4, which lacks
    # SSH_ASKPASS_REQUIRE.
    SETSID_BIN=$(command -v setsid || true)
    log "connecting to ${#HOSTS[@]} host(s)..."
    REMAINING=("${HOSTS[@]}")
    auth_round "an existing ssh session" external "" ""
    auth_round "default ssh auth" default "" ""
    local i
    for i in "${!IDENT_KEYS[@]}"; do
        auth_round "key ${IDENT_LOGINS[$i]:+${IDENT_LOGINS[$i]}:}${IDENT_KEYS[$i]}" \
            key "${IDENT_LOGINS[$i]}" "${IDENT_KEYS[$i]}"
    done
    for i in "${!PW_SECRETS[@]}"; do
        auth_round "password $((i + 1)) (${PW_LOGINS[$i]:-default user})" \
            pw "${PW_LOGINS[$i]}" "$i"
    done
    PW_SECRETS=()
    [ ${#REMAINING[@]} -eq 0 ] \
        || log "WARNING: no working ssh credentials for: ${REMAINING[*]}" >&2
}

# --- phase 2b: probe workers for auto-mode system info -----------------------
# Remote fact-gathering snippet. Dumb by design: emits raw lines, all
# interpretation happens locally in the tuner.
probe_remote_cmd() {
    # One wekanode PROCESS per weka node, each pinned to the one core it
    # owns: its process-level mask (/proc/<pid>/status, i.e. the main
    # thread's) IS that core, and the MANAGEMENT node -- which owns no core
    # -- carries a wide mask instead. Read per-process, never per-task: a
    # node's auxiliary threads are pinned to single cpus too, and counting
    # those invents cores weka does not own. Measured on field client A: per-task
    # scanning reported 4-27 where weka's own core_id list is 14-27, and
    # those ten phantom cores were then excluded from every fio job.
    # Interpretation of dedicated vs. floating masks happens in the tuner.
    #
    # "ident" is the machine id (host_machine_id's rule: product_uuid, else
    # machine-id, else empty), carried here so the host-file writeback never
    # opens a session of its own per host to fetch it.
    #
    # The shape facts come last (see cal_shapes): cpu_model, memtotal_kb, the
    # kernel's aio room (aio_max_nr and aio_nr, for the libaio queue ladders
    # and the staged libaio jobs), the cpu topology as
    # "topo_<file> <cpu> <value>" lines -- one grep over every
    # cpu's physical_package_id, core_id and thread_siblings_list, which is
    # how probe_cores counts PHYSICAL cores and finds each one's sibling --, one
    # "nic <dev> <speed> <pci> <driver> <vendor:device>" line per bus-backed
    # netdev with the speed ethtool reports (sysfs where ethtool is missing),
    # and one "weka_net <container> <json>" line per weka container -- the
    # NICs it uses, from `weka local resources net -J`, which insists on
    # root: the login user when it is root, else the escalator found above.
    # A failure is a "weka_net_err" line naming it, never silence; no weka
    # CLI at all is "weka_cli absent". Virtual netdevs (veth, bridges,
    # bonds) are skipped: weka's dataplane NICs are always bus devices.
    # WEKATESTER_SYSROOT prefixes /proc and /sys for the suite's fake trees
    # (and lscpu, which reads the live machine, runs only without it); no
    # worker ever has it set.
    #
    # The last two facts are MEASURED, not inferred: for every online cpu,
    # can a process on this box actually bind to it (taskset -c <cpu> true),
    # plainly and, where that fails and an escalator exists, under it? A cpu
    # can be online, outside weka's pinned set, and still refuse the bind --
    # offline-but-counted, or held by another cgroup's cpuset partition --
    # and fio's answer to that is err=22 cpu_set_affinity per job, on the
    # daemonized server, after the run has already started (seen live on
    # field client C, 2026-09-09: a brutal bw-write rung died on it). The old
    # rule assumed every isolated cpu was self-affinable; measuring costs
    # one fork per cpu, once, and cannot be wrong.
    printf '%s' "_sr=\${WEKATESTER_SYSROOT:-}; echo \"ncpus \$(getconf _NPROCESSORS_ONLN)\"; \
        echo \"limits \$(ulimit -Sn) \$(ulimit -Hn) \$(ulimit -Su) \$(ulimit -Hu)\"; \
        echo \"wekanode \$(pgrep -xc wekanode || true)\"; \
        for p in \$(pgrep -x wekanode || true); do cat /proc/\$p/status; done \
        | awk '/^Cpus_allowed_list/ {print \"weka_allowed\", \$2}' | sort -u; \
        echo \"engines \$('$FIO_BIN' --enghelp | tr \"\\n\" \" \")\"; \
        echo \"taskset \$(taskset -cp \$\$ | awk -F': ' '{print \$2}')\"; \
        echo \"isolated \$([ -f \"\$_sr/sys/devices/system/cpu/isolated\" ] && cat \"\$_sr/sys/devices/system/cpu/isolated\")\"; \
        echo \"online \$([ -r \"\$_sr/sys/devices/system/cpu/online\" ] && cat \"\$_sr/sys/devices/system/cpu/online\")\"; \
        echo \"ident \$(if [ -r /sys/class/dmi/id/product_uuid ]; then cat /sys/class/dmi/id/product_uuid; elif [ -r /etc/machine-id ]; then cat /etc/machine-id; fi)\"; \
        _pv=; for pc in 'dzdo -n' pbrun sesu pmrun 'doas -n' 'ksu -e' 'sudo -n'; do set -- \$pc; command -v \$1 >/dev/null || continue; if _o=\$(timeout 5 \$pc true </dev/null 2>&1); then echo \"priv \$pc\"; _pv=\$pc; break; fi; done; \
        if command -v taskset >/dev/null; then \
            _on=\$([ -r \"\$_sr/sys/devices/system/cpu/online\" ] && cat \"\$_sr/sys/devices/system/cpu/online\"); \
            _ids=\$(printf '%s' \"\${_on:-0-\$(( \$(getconf _NPROCESSORS_ONLN) - 1 ))}\" | awk 'BEGIN {RS = \",\"} {n = split(\$0, a, \"-\"); if (n == 2) {for (i = a[1]; i <= a[2]; i++) print i} else if (length(\$0)) print \$0 + 0}'); \
            _bd=; _bp=; for c in \$_ids; do \
                if _o=\$(taskset -c \$c true 2>&1); then _bd=\"\$_bd,\$c\"; \
                elif [ -n \"\$_pv\" ] && _o=\$(\$_pv taskset -c \$c true 2>&1); then _bp=\"\$_bp,\$c\"; fi; \
            done; \
            [ -n \"\$_bd\" ] || _bd=,-; [ -n \"\$_bp\" ] || _bp=,-; \
            echo \"bindable \${_bd#,}\"; echo \"bindable_priv \${_bp#,}\"; \
        fi; \
        _m=; if [ -z \"\$_sr\" ] && command -v lscpu >/dev/null; then _m=\$(lscpu | awk -F: '/^Model name/ {sub(/^[ \\t]+/, \"\", \$2); print \$2; exit}'); fi; \
        if [ -z \"\$_m\" ] && [ -r \"\$_sr/proc/cpuinfo\" ]; then _m=\$(awk -F: '/^model name/ {sub(/^[ \\t]+/, \"\", \$2); print \$2; exit}' \"\$_sr/proc/cpuinfo\"); fi; \
        echo \"cpu_model \${_m:--}\"; \
        echo \"memtotal_kb \$([ -r \"\$_sr/proc/meminfo\" ] && awk '/^MemTotal:/ {print \$2; exit}' \"\$_sr/proc/meminfo\")\"; \
        echo \"aio_max_nr \$([ -r \"\$_sr/proc/sys/fs/aio-max-nr\" ] && cat \"\$_sr/proc/sys/fs/aio-max-nr\")\"; \
        echo \"aio_nr \$([ -r \"\$_sr/proc/sys/fs/aio-nr\" ] && cat \"\$_sr/proc/sys/fs/aio-nr\")\"; \
        if [ -r \"\$_sr/sys/devices/system/cpu/cpu0/topology/core_id\" ]; then \
            grep -H . \"\$_sr\"/sys/devices/system/cpu/cpu[0-9]*/topology/physical_package_id \"\$_sr\"/sys/devices/system/cpu/cpu[0-9]*/topology/core_id \"\$_sr\"/sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list \
            | awk -F: '{n = split(\$1, p, \"/\"); c = p[n - 2]; sub(/^cpu/, \"\", c); print \"topo_\" p[n], c, \$2}'; \
        fi; \
        for _d in \"\$_sr\"/sys/class/net/*; do \
            [ -e \"\$_d/device\" ] || continue; _n=\${_d##*/}; \
            _s=; if command -v ethtool >/dev/null; then _s=\$(ethtool \"\$_n\" 2>&1 | awk '\$1 == \"Speed:\" {print \$2; exit}'); fi; \
            case \"\$_s\" in [0-9]*) ;; *) _s=; [ ! -r \"\$_d/speed\" ] || _s=\$(cat \"\$_d/speed\" 2>&1) ;; esac; \
            _p=\$(readlink \"\$_d/device\"); _p=\${_p##*/}; _r=-; _i=-; \
            if [ -e \"\$_d/device/driver\" ]; then _r=\$(readlink \"\$_d/device/driver\"); _r=\${_r##*/}; fi; \
            if [ -r \"\$_d/device/vendor\" ] && [ -r \"\$_d/device/device\" ]; then _i=\$(cat \"\$_d/device/vendor\"):\$(cat \"\$_d/device/device\"); fi; \
            case \"\$_s\" in [0-9]*) ;; *) _s=- ;; esac; \
            echo \"nic \$_n \$_s \${_p:--} \${_r:--} \${_i:--}\"; \
        done; \
        if command -v weka >/dev/null; then \
            _wx=; [ \"\$(id -u)\" = 0 ] || _wx=\$_pv; \
            if ! _cs=\$(timeout 15 weka local ps --no-header -o name 2>&1); then \
                if [ -z \"\$_wx\" ] || ! _cs=\$(timeout 15 \$_wx weka local ps --no-header -o name 2>&1); then \
                    echo \"weka_net_err ps \$(printf '%s' \"\$_cs\" | head -1)\"; _cs=; fi; fi; \
            for _c in \$_cs; do \
                if [ \"\$(id -u)\" = 0 ]; then _j=\$(timeout 15 weka local resources net -C \"\$_c\" -J 2>&1); _rc=\$?; \
                elif [ -n \"\$_wx\" ]; then _j=\$(timeout 15 \$_wx weka local resources net -C \"\$_c\" -J 2>&1); _rc=\$?; \
                else _j='needs root, and no passwordless escalator works here'; _rc=1; fi; \
                if [ \$_rc -eq 0 ]; then echo \"weka_net \$_c \$(printf '%s' \"\$_j\" | tr '\\n' ' ')\"; \
                else echo \"weka_net_err \$_c \$(printf '%s' \"\$_j\" | head -1)\"; fi; \
            done; \
        else echo 'weka_cli absent'; fi; true"
}

# Prove each host's ioengine candidates with a REAL one-file job on that
# host's destination dir: --enghelp lists what fio was built with, not what
# the kernel and filesystem will actually run (io_uring is the classic liar).
# Candidates per host: the CLI -e engine, every engine the host file
# mentions, and in auto mode the tuner's preference list -- all filtered by
# enghelp first so impossible names never burn a job. Results land in
# $WORK_DIR/engine.results as "host engine ok|fail" (phase2's input), and
# each host's probe "engines" line is REWRITTEN to its functional subset, so
# the tuner's common-engine pick is proven rather than advertised.
test_engines() {
    local host results="$WORK_DIR/engine.results" csv_engines="" cand et_pids=() _p
    mkdir -p "$WORK_DIR/et"
    : > "$results"
    if [ -n "$TARGETS_FILE" ] && [ -f "$TARGETS_FILE" ]; then
        csv_engines=$(awk -F, '!/^[[:space:]]*#/ {gsub(/[[:space:]]/, "", $3);
            if ($3 != "" && $3 != "ioengine") print $3}' "$TARGETS_FILE" | sort -u | tr '\n' ' ')
    fi
    cand="$ENGINE $csv_engines"
    [ -z "$AUTO_LEVEL" ] || cand="$cand io_uring libaio psync"
    cand=$(printf '%s\n' $cand | awk '!seen[$0]++' | tr '\n' ' ')
    [ -n "${cand// /}" ] || return 0
    log "proving ioengine candidates on ${#HOSTS[@]} host(s):$(printf ' %s' $cand)"
    load_host_dirs
    local i
    for i in "${!HOSTS[@]}"; do
        host=${HOSTS[$i]}
        (
            hd=${HOST_DIRS[$i]}
            avail=$(awk '$1 == "engines" {$1 = ""; print}' "$WORK_DIR/probe/$host")
            for c in $cand; do
                case " $avail " in
                    *" $c "*) ;;
                    *) echo "$host $c fail" >> "$results"; continue ;;
                esac
                # A broken engine on a real filesystem HANGS at least as
                # often as it errors (io_uring's specialty, seen live on a
                # field box) -- an unbounded test job hangs the whole run.
                # And timeout(1) alone is not enough: a direct-IO write on a
                # sick mount parks fio in D state, where even SIGKILL does
                # not land and timeout blocks forever waiting for the corpse
                # (also seen live, same box, next engine). So: background the
                # bounded job, POLL it, and if it will not die, ABANDON it --
                # never wait on a possibly-uninterruptible child. A working
                # engine finishes this 64k write in milliseconds.
                tmo=${WEKATESTER_ENGINE_TEST_TIMEOUT:-15}
                if run_host "$host" "f='$hd/.wekatester-enginetest.'\$\$; \
                        timeout -k 5 $tmo \
                        '$FIO_BIN' --name=et --ioengine=$c --rw=write --bs=64k \
                        --filesize=64k --filename=\"\$f\" --direct=1 \
                        --output-format=json & p=\$!; i=0; \
                        while kill -0 \$p 2>/dev/null && [ \$i -lt $((tmo + 10)) ]; do sleep 1; i=\$((i+1)); done; \
                        if kill -0 \$p 2>/dev/null; then \
                            kill -9 \$p 2>/dev/null; sleep 1; \
                            kill -0 \$p 2>/dev/null && echo WEKATESTER_ENGINE_STUCK; \
                            rm -f \"\$f\"; exit 124; \
                        fi; \
                        wait \$p; rc=\$?; rm -f \"\$f\"; exit \$rc" \
                        > "$WORK_DIR/et/$host.$c.out" 2>&1; then
                    echo "$host $c ok" >> "$results"
                else
                    echo "$host $c fail" >> "$results"
                    if grep -q WEKATESTER_ENGINE_STUCK "$WORK_DIR/et/$host.$c.out"; then
                        log "WARNING: $host: ioengine $c test is STUCK in uninterruptible IO -- abandoned; direct IO on $hd may be broken on this host" >&2
                    else
                        log "WARNING: $host: ioengine $c failed its test job (see $WORK_DIR/et/$host.$c.out)" >&2
                    fi
                fi
            done
        ) &
        et_pids+=($!)
    done
    # SCOPED wait -- a bare `wait` here also waits on the run-log tees,
    # which cannot exit until finalize closes their fifos: the same deadlock
    # cleanup once had, and it presents as a silent hang right after the
    # last per-engine warning (seen live: no fio running, no D state, just
    # this wait).
    for _p in "${et_pids[@]}"; do wait "$_p"; done
    # rewrite each probe's engines line to the proven subset (untested
    # engines are dropped only in auto mode, where the list WAS the tests)
    if [ -n "$AUTO_LEVEL" ]; then
        local none=() c nolist
        # one awk for the fleet: each probe's engines line becomes the
        # engines that passed there, in test order; the hosts where none
        # did come back one per line
        nolist=$(awkrun 'BEGIN {
            if ((n = readlines(ARGV[1], R)) < 0) awk_fail("cannot read " ARGV[1])
            for (i = 1; i <= n; i++)
                if (split(R[i], F, " ") == 3 && F[3] == "ok") OK[F[1]] = OK[F[1]] " " F[2]
            for (a = 3; a < ARGC; a++) {
                h = ARGV[a]; p = ARGV[2] "/" h
                if ((m = readlines(p, L)) < 0) awk_fail("cannot read " p)
                for (i = 1; i <= m; i++) if (split(L[i], W, " ") && W[1] == "engines") L[i] = "engines" OK[h]
                writelines(p, L, m)
                if (OK[h] == "") print h
            }
        }' "$results" "$WORK_DIR/probe" "${HOSTS[@]}") || die "cannot record the proven ioengines"
        while IFS= read -r host; do
            [ -z "$host" ] || none+=("$host")
        done <<<"$nolist"
        # -a stages every job on a proven engine; a host with none would
        # only fail later, in a calibration cell or a measured job, under an
        # error that no longer names the cause. The workdir dies with the
        # process, so quote each engine's evidence now.
        if [ ${#none[@]} -gt 0 ]; then
            for host in "${none[@]}"; do
                for c in $cand; do
                    [ -s "$WORK_DIR/et/$host.$c.out" ] || continue
                    log "$host: ioengine $c: $(tail -1 "$WORK_DIR/et/$host.$c.out")" >&2
                done
            done
            die "no ioengine passed its test job on ${none[*]} (tried:$(printf ' %s' $cand)); -a $AUTO_LEVEL needs one that works there -- check direct IO on the destination and the fio build"
        fi
    fi
    # a PINNED engine failing anywhere is fatal, naming host and evidence
    if [ -n "$ENGINE" ]; then
        # one awk: the first host, in host order, without a passing test of it
        host=$(awk 'BEGIN {
            while ((getline line < ARGV[2]) > 0)
                if (split(line, F, " ") == 3 && F[2] == ARGV[1] && F[3] == "ok") ok[F[1]] = 1
            for (a = 3; a < ARGC; a++) if (!(ARGV[a] in ok)) { print ARGV[a]; exit }
        }' "$ENGINE" "$results" "${HOSTS[@]}")
        if [ -n "$host" ]; then
            # the workdir dies with the process: quote the evidence now
            [ ! -f "$WORK_DIR/et/$host.$ENGINE.out" ] || tail -5 "$WORK_DIR/et/$host.$ENGINE.out" >&2
            die "ioengine '$ENGINE' failed its test job on $host (fio output above)"
        fi
    fi
}

# Finish the host-file resolution with the engine results, then insist any
# host-line engine assignment actually works on its host.
finalize_targets() {
    [ "$TARGETS" -eq 1 ] || return 0
    local host eng
    resolve_targets phase2 "$TARGETS_FILE" "${ENGINE:--}" \
        "$([ "$DIRECTORY_EXPLICIT" -eq 1 ] && printf '%s' "$DIRECTORY" || printf -- -)" \
        "$WORK_DIR/engine.results" "${HOSTS[@]}" > "$WORK_DIR/targets.final" \
        || die "host file resolution failed ($TARGETS_FILE)"
    # one awk for the fleet: the first host, in host order, whose host-file
    # engine did not pass its test there
    local bad
    bad=$(awk 'BEGIN {
        while ((getline line < ARGV[1]) > 0) { split(line, F, "\t"); if (!(F[1] in eng)) eng[F[1]] = F[3] }
        while ((getline line < ARGV[2]) > 0)
            if (split(line, F, " ") == 3 && F[3] == "ok") ok[F[1] " " F[2]] = 1
        for (a = 3; a < ARGC; a++) {
            h = ARGV[a]; e = (h in eng) ? eng[h] : "-"
            if (e != "-" && e != "" && !((h " " e) in ok)) { print h " " e; exit }
        }
    }' "$WORK_DIR/targets.final" "$WORK_DIR/engine.results" "${HOSTS[@]}")
    if [ -n "$bad" ]; then
        host=${bad%% *}; eng=${bad#* }
        [ ! -f "$WORK_DIR/et/$host.$eng.out" ] || tail -5 "$WORK_DIR/et/$host.$eng.out" >&2
        die "host file assigns ioengine '$eng' to $host but its test job failed (fio output above)"
    fi
}

# cpus_allowed enforcement. A host with a requested cpu list must either
# already be allowed those cpus (taskset -cp) or have a passwordless
# escalator to launch fio under `taskset -c` -- and a request overlapping
# weka's own pinned cores is fatal without one, a warning with one (the
# operator explicitly chose those cpus). The winning launch decision lands
# in $WORK_DIR/auth/<host>.priv + <host>.cpus for the fio server lifecycle.
check_cpu_pinning() {
    local host req cur priv ncpus
    # local mode never ran establish_connections; the lifecycle still reads
    # the same per-host files
    [ -n "$AUTH_DIR" ] || { AUTH_DIR="$WORK_DIR/auth"; mkdir -p "$AUTH_DIR"; }
    # One awk for every host, not six for each: the verdict is set
    # arithmetic on the probe file and the host's row, and ~45ms of process
    # starts per host before any judgment is 20s of serial nothing at 451
    # hosts. It writes one line per host that has a request,
    # in host order: host, the request, the taskset and cpu count the
    # messages quote back, the four cpu sets, the flags (comma-joined), and
    # the escalator prefix last (it has spaces) -- "-" for an empty field.
    # The bash below still speaks per host, unchanged.
    awkrun '
    # a cpu list the way this check reads one: blanks around a part
    # dropped, an empty part skipped
    function expand(s, S,    n, P, i, p, a, b, c) {
        split("", S)
        n = lsplit(s, P, ",")
        for (i = 1; i <= n; i++) {
            if ((p = strip(P[i])) == "") continue
            if (index(p, "-")) {
                a = py_int(substr(p, 1, index(p, "-") - 1)); b = py_int(substr(p, index(p, "-") + 1))
                if (a == "" || b == "") awk_fail("pinning: not a cpu list: " s)
                for (c = a; c <= b; c++) S[c] = 1
            } else {
                if ((a = py_int(p)) == "") awk_fail("pinning: not a cpu list: " s)
                S[a] = 1
            }
        }
    }
    function fact(P, np, key,    i, F) {   # the first "<key> <value>" line, as the awk did
        for (i = 1; i <= np; i++) if (index(P[i], key) && pysplit(P[i], F) && F[1] == key) return F[2]
        return ""
    }
    function fmt_or(S, none,    v) { v = fmt_cpulist(S); return v == "" ? none : v }
    function flag(f) { flags = flags (flags == "" ? "" : ",") f }
    BEGIN {
        auto = ARGV[3] != "-"
        # each host row, the first per host (targets_field reads the first)
        if ((n = readlines(ARGV[1], L)) > 0)
            for (i = 1; i <= n; i++) {
                split(L[i], F, "\t")
                if (!(F[1] in ROW)) ROW[F[1]] = (4 in F) ? F[4] : ""
            }
        for (a = 4; a < ARGC; a++) {
            host = ARGV[a]; req_s = (host in ROW) ? ROW[host] : ""
            # a host the file gives no cpu list is pinned all the same: fio
            # never lands on the pinned cores of weka (Frank, 2026-09-29)
            if ((nolist = req_s == "" || req_s == "-")) req_s = ""
            if ((np = readlines(ARGV[2] "/" host, P)) < 0) {
                if (nolist) continue   # never probed: nothing to pin against
                np = 0
            }
            cur_s = fact(P, np, "taskset"); iso_s = fact(P, np, "isolated"); ncpus_s = fact(P, np, "ncpus")
            priv = ""   # host_priv rule: the first "priv " line, the rest of it verbatim
            for (i = 1; i <= np; i++) if (index(P[i], "priv ") == 1) { priv = substr(P[i], 6); break }
            expand(req_s, REQ); expand(cur_s, CUR); expand(iso_s, ISO)
            ncpus = ncpus_s ~ /^[0-9]+$/ ? ncpus_s + 0 : 0
            # MEASURED facts (empty, untested, when the probe could not test)
            tested = probe_cpu_fact(P, np, "bindable", BIND)
            probe_cpu_fact(P, np, "bindable_priv", BINDP)
            probe_universe(P, np, ncpus, U)
            # same rule as the tuner: weka pins each dedicated io thread to
            # exactly one cpu; wide masks are floating utility threads and
            # MUST be ignored, or the union covers every cpu and everything
            # "overlaps" (seen live)
            split("", WEKA)
            for (i = 1; i <= np; i++)
                if (index(P[i], "weka_allowed") && pysplit(P[i], F) > 1 && F[1] == "weka_allowed") {
                    expand(F[2], S)
                    if (set_size(S) == 1) for (c in S) WEKA[c] = 1
                }
            # and a dedicated core is the WHOLE core: weka hives the SMT
            # sibling of the io thread off too (WEKAPP-550768), as probe_cores
            # counts it. fio never runs on either thread, whatever the list
            # says (Frank, 2026-09-27).
            probe_topology(P, np, TK, TS, TL)
            nw = set_sorted(WEKA, W)
            for (i = 1; i <= nw; i++)
                if (W[i] in TK) { nt = split(TL[W[i]], T, ","); for (j = 1; j <= nt; j++) WEKA[T[j]] = 1 }
            flags = ""
            if (nolist && !set_any(U)) continue   # a probe that cannot say which cpus exist: nothing to pin to
            if (nolist) {
                # every cpu this login can bind WITHOUT privilege -- an
                # unlisted host never escalates -- and, below, minus the
                # cores of weka (whole) and the pair of core 0, exactly as a
                # list naming them all would be
                flag("nolist")
                split("", REQ)
                for (c in U) if (tested ? (c in BIND) : (!set_any(CUR) || (c in CUR))) REQ[c] = 1
                if ((req_s = fmt_cpulist(REQ)) == "") req_s = "-"
            }
            # cpus the host does not have: fio rejects a cpus_allowed naming
            # one -- on the daemonized SERVER, whose error text is lost -- so
            # they are trimmed here with a note, the host file keeping the
            # list as written. Only when the probe knows the cpus.
            split("", PHANTOM)
            if (set_any(U)) for (c in REQ) if (!(c in U)) PHANTOM[c] = 1
            if (set_any(PHANTOM)) flag("phantom")
            # cpus this host REFUSES to bind, measured: fio answers one of
            # these with err=22 cpu_set_affinity, per job, on the daemonized
            # server after the run has started (field client C, 2026-09-09)
            split("", UNBIND)
            if (tested) for (c in REQ) if (!(c in WEKA) && !(c in PHANTOM) && !(c in BIND) && !(c in BINDP)) UNBIND[c] = 1
            if (set_any(UNBIND)) flag("unbindable")
            # core 0 of socket 0 and its sibling always stay with the OS
            # (Frank, 2026-09-25)
            split("", PAIR)
            if (0 in TK) { nt = split(TL[0], T, ","); for (j = 1; j <= nt; j++) PAIR[T[j]] = 1 }
            else PAIR[0] = 1
            split("", OS0)
            for (c in REQ) if (c in PAIR) OS0[c] = 1
            if (set_any(OS0)) flag("core0")
            # the EFFECTIVE set: the request minus the cores of weka, the
            # pair of core 0, and the cpus the host does not have or bind
            split("", EFF)
            for (c in REQ) if (!(c in WEKA) && !(c in PHANTOM) && !(c in UNBIND) && !(c in PAIR)) EFF[c] = 1
            # A list covering every cpu fio could use is no choice: under -a
            # the tuner applies the whole OS reserve as if the file gave none
            # (probe_cores), so the effective set -- what the notes quote, the
            # taskset of the fio server, the escalation check -- is the
            # tuner set, or the notes would name reserve cpus fio never runs
            # on and an "outside" verdict could escalate (or die) for them.
            # Plain runs have no reserve: the rule above stands.
            if (auto) {
                probe_cores(P, np, nolist ? "" : req_s, R, PHYS, ALL)
                if (nolist || R["catchall"]) {
                    if (!nolist) flag("catchall")
                    split("", EFF); for (c in ALL) EFF[c] = 1
                }
            }
            # a mask mixing isolated and housekeeping cpus silently
            # collapses onto the housekeeping partition -- worse than
            # failing, it runs WRONG
            iso_in = 0; iso_out = 0
            if (set_any(ISO)) for (c in REQ) if (c in ISO) iso_in = 1; else iso_out = 1
            if (iso_in && iso_out) flag("mixed")
            # Which cpus need the escalator? MEASURED: the ones the probe
            # could not bind plainly but could under it. Without that, the
            # old rule stands -- isolated cpus assumed self-affinable, so
            # only cpus outside both the current mask and the isolated set
            # need privilege.
            if (!set_any(EFF)) flag("allweka")
            else if (tested) {
                for (c in EFF) if (!(c in BIND)) { flag("outside"); break }
            } else if (set_any(CUR)) {
                for (c in EFF) if (!(c in CUR) && !(c in ISO)) { flag("outside"); break }
            }
            for (c in REQ) if (c in WEKA) { flag("overlap"); break }
            w = join_sorted(WEKA, ",")
            print host, req_s, (cur_s == "" ? "-" : cur_s), (ncpus_s == "" ? "-" : ncpus_s), (w == "" ? "none" : w), fmt_or(EFF, "none"), fmt_or(PHANTOM, "none"), fmt_or(UNBIND, "none"), fmt_or(OS0, "none"), (flags == "" ? "ok" : flags), (priv == "" ? "-" : priv)
        }
    }' "$WORK_DIR/targets.final" "$WORK_DIR/probe" "${AUTO_LEVEL:--}" "${HOSTS[@]}" \
        > "$WORK_DIR/pin.verdicts" || die "cpu pinning check failed"
    local dedicated effective phantom unbindable os0 vflags nolist_hosts=() nolist_eff=()
    while read -r host req cur ncpus dedicated effective phantom unbindable os0 vflags priv; do
        [ "$cur" != "-" ] || cur=""
        [ "$ncpus" != "-" ] || ncpus=""
        [ "$priv" != "-" ] || priv=""
        vflags=${vflags//,/ }
        # a host with no list asked for nothing: the notes below all describe
        # a request, so it gets none of them, only the one summary line
        case "$vflags" in
            (*nolist*)
                case "$vflags" in
                    (*allweka*)
                        die "$host: no cpu is left for fio -- each is one of weka's pinned cores, core 0's pair, or one this login cannot bind" ;;
                esac
                nolist_hosts+=("$host"); nolist_eff+=("$effective") ;;
        esac
        case "$vflags" in
            (*nolist*) ;;
            (*allweka*)
                case "$vflags" in
                    (*catchall*)
                        die "$host: the host file's cpu list ($req) covers every cpu fio could use, which counts as no list, and the OS reserve then leaves fio no cpus -- mount weka with fewer cores, use a larger client, or list fewer cpus (a narrower list is the operator's own reserve)" ;;
                esac
                if [ "$unbindable" != none ]; then
                    die "$host: no requested cpu ($req) is usable -- each is a weka dedicated core, a cpu this host does not have, or one it refuses to bind ($unbindable)"
                fi
                if [ "$phantom" != none ]; then
                    die "$host: no requested cpu ($req) is usable -- each is a weka dedicated core or a cpu this host does not have ($phantom; the host has $ncpus cpus: 0-$((ncpus - 1)))"
                fi
                if [ "$os0" != none ]; then
                    die "$host: no requested cpu ($req) is usable -- core 0 and its sibling ($os0) stay with the OS, and the rest are weka dedicated cores"
                fi
                die "$host: every requested cpu ($req) is a weka dedicated core -- nothing left to run fio on" ;;
        esac
        case "$vflags" in
            (*nolist*) ;;
            (*unbindable*)
                log "note: $host: requested cpus ($req) include $unbindable, which this host refuses to bind -- offline, or held by another cgroup's cpuset partition; executing on the remainder ($effective) -- the host file keeps the list as written" ;;
        esac
        case "$vflags" in
            (*nolist*) ;;
            (*catchall*)
                # one note says it all: the phantom, core-0 and weka-overlap
                # notes below would each describe a list that counts as none
                log "note: $host: requested cpus ($req) cover every cpu fio could use, which counts as no list: the OS reserve applies as if the host file gave none; executing on $effective -- the host file keeps the list as written" ;;
            (*phantom*)
                log "note: $host: requested cpus ($req) name cpus this host does not have ($phantom; the host has $ncpus cpus: 0-$((ncpus - 1))); executing on the remainder ($effective) -- the host file keeps the list as written" ;;
        esac
        case "$vflags" in
            (*nolist*) ;;
            (*mixed*)
                # Safe since cpus_allowed_policy=split is stamped beside
                # every cpu list: each job holds ONE cpu, and single-cpu
                # affinity cannot collapse. The old whole-mask trap (a
                # mixed RANGE collapsing onto housekeeping) needed shared
                # masks, which no staged variant uses any more.
                log "note: $host: requested cpus ($req) span isolated and housekeeping cpus; per-job split affinity keeps each job on its own cpu" ;;
        esac
        case "$vflags" in
            (*nolist*|*catchall*) ;;
            (*core0*)
                log "note: $host: requested cpus ($req) include core 0's pair ($os0), which stays with the OS; executing on the remainder ($effective) -- the host file keeps the list as written" ;;
        esac
        case "$vflags" in
            (*nolist*|*catchall*) ;;
            (*overlap*)
                # the host file keeps the operator's list AS WRITTEN;
                # execution simply never touches weka's own cores
                log "note: $host: requested cpus ($req) overlap weka's dedicated cores ($dedicated); executing on the remainder ($effective) -- the host file keeps the list as written" ;;
        esac
        case "$vflags" in
            (*outside*)
                if [ -z "$priv" ]; then
                    log "ERROR: $host: effective cpus_allowed: $effective (requested: $req)" >&2
                    log "ERROR: $host: current taskset:        ${cur:-unknown}" >&2
                    log "ERROR: $host: weka dedicated cores:   $dedicated" >&2
                    die "$host: the effective cpus are outside the current taskset and no passwordless escalator (dzdo/pbrun/sesu/pmrun/doas/ksu/sudo) works"
                fi ;;
        esac
        # record the launch decision: escalate ONLY where the effective mask
        # cannot be self-applied (outside). A self-affinable request runs as
        # the login user even when an escalator exists -- privileges are
        # as-needed, never just because they are available.
        local need_priv=0
        case "$vflags" in (*outside*) need_priv=1 ;; esac
        if [ -n "$priv" ] && [ "$need_priv" -eq 1 ]; then
            printf '%s\n' "$priv" > "$AUTH_DIR/$host.priv"
        fi
        printf '%s\n' "$effective" > "$AUTH_DIR/$host.cpus"
        local under=""
        [ -z "$priv" ] || [ "$need_priv" -ne 1 ] || under="under $priv "
        debug "$host: fio server will run ${under}taskset -c $effective"
    done < "$WORK_DIR/pin.verdicts"
    if [ ${#nolist_hosts[@]} -gt 0 ]; then
        log "note: fio stays off weka's pinned cores and core 0's pair on the ${#nolist_hosts[@]} host(s) the host file gives no cpu list (${nolist_hosts[0]}: ${nolist_eff[0]}$([ ${#nolist_hosts[@]} -eq 1 ] || printf ', ...'))"
    fi
}

# Run a weka CLI on the master: always try as the login user first; a failure
# gets ONE retry under the master's escalator (sites lock the weka socket
# or config to root), then the caller's fallback applies. Escalation only
# after the user attempt fails -- never first.
#
# No caller at present: the backend-RAM query that used it is retired with
# the DRAM ceiling (see probe_workers). Kept because it is the tested,
# correct way to reach the weka CLI for any future master-side fact.
run_weka_master() {   # run_weka_master <weka-cmd> <outfile>
    local mpriv
    run_host "$MASTER" "$1" > "$2" && return 0
    mpriv=$(host_priv "$MASTER")
    [ -n "$mpriv" ] || return 1
    run_host "$MASTER" "$mpriv $1" > "$2" || return 1
    log "NOTE: $MASTER: '$1' needed $mpriv (the unprivileged attempt failed)" >&2
}

# Gather per-host facts + master-side extras into $WORK_DIR/probe/.
probe_workers() {
    echo
    log "probing ${#HOSTS[@]} worker(s) for auto tuning..."
    mkdir -p "$WORK_DIR/probe"
    local pids=() failed=() host i bad=()
    for host in "${HOSTS[@]}"; do
        run_host "$host" "$(probe_remote_cmd)" > "$WORK_DIR/probe/$host" &
        pids+=($!)
    done
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}" || failed+=("${HOSTS[$i]}")
    done
    [ ${#failed[@]} -eq 0 ] || die "probe failed on: ${failed[*]}"

    # -e names an engine explicitly, and the probe already knows what each
    # worker's fio can load -- refuse now rather than fail at job start.
    if [ -n "$ENGINE" ]; then
        # one awk for the fleet: the hosts whose engines line lacks it
        local lack
        # (an empty or unreadable probe lacks it too, as the grep said)
        lack=$(awkrun 'BEGIN {
            for (a = 3; a < ARGC; a++) {
                ok = 0; m = readlines(ARGV[2] "/" ARGV[a], L)
                for (i = 1; i <= m && !ok; i++)
                    if ((nw = pysplit(L[i], W)) && W[1] == "engines")
                        for (k = 2; k <= nw; k++) if (W[k] == ARGV[1]) ok = 1
                if (!ok) printf "%s%s", (n++ ? " " : ""), ARGV[a]
            }
        }' "$ENGINE" "$WORK_DIR/probe" "${HOSTS[@]}")
        [ -z "$lack" ] \
            || die "ioengine '$ENGINE' is not available (fio --enghelp) on: $lack"
    fi

    # df is the only master-side fact the tuner needs. The backend-RAM query
    # that used to live here is gone with the DRAM ceiling it fed (corrected
    # 2026-08-18): weka backends hold no user data in RAM, so there was never
    # a cache to defeat.
    [ -n "$AUTO_LEVEL" ] || return 0   # df matters to the tuner only
    run_host "$MASTER" "df -kP '$DIRECTORY'" > "$WORK_DIR/probe/_df" \
        || die "cannot df $DIRECTORY on $MASTER"
}

# --- capacity check (every run) ----------------------------------------------------
# Per host: group that host's STAGED variants by filename_format namespace
# (absent -> the jobfile's own key: fio's default naming makes each file own
# its files); a namespace costs the max of its jobfiles' footprints; the
# host's requirement is the larger of the namespace sum and the staged
# layout variant's per-section total (an operator-edited layout must not
# shrink the answer). Compared against each host's OWN destination df.
# Over capacity: die -- or with --ignore-capacity, PROMPT (untimed) and
# continue on a yes; unattended runs with the flag continue with a warning.
check_capacity() {
    local host pids=() i failed=0
    mkdir -p "$WORK_DIR/df"
    load_host_dirs
    for i in "${!HOSTS[@]}"; do
        host=${HOSTS[$i]}
        # the fs type rides along (a third line): hosts on one weka
        # filesystem draw from one pool, checked together below
        run_host "$host" "df -kP '${HOST_DIRS[$i]}' && { findmnt -T '${HOST_DIRS[$i]}' -n -o FSTYPE 2>&1 || :; }" > "$WORK_DIR/df/$host" &
        pids+=($!)
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || log "WARNING: cannot df on ${HOSTS[$i]}; its capacity is unchecked" >&2
    done
    list_staged "$WORK_DIR/staged.list" && awkrun '
    function gib(b) { return sprintf("%.1f", b / 1073741824) }
    function need_int(v, what) {   # int(), or a stop where python raised
        if ((v = py_int(v)) == "") awk_fail("capacity: " what " is not a number")
        return v
    }
    # one staged jobfile: numjobs x filesize x nrfiles, or numjobs x size=
    # (fio: the job total across its files)
    function footprint(path, L, n,    nj, fs, sz, nr, b, job) {
        nj = first_value(L, n, "numjobs"); nj = need_int(nj == "" ? "1" : nj, path ": numjobs")
        if ((fs = first_value(L, n, "filesize")) != "") {
            if ((b = parse_size(fs)) == "") awk_fail("capacity: " path ": filesize=" fs " is not a byte count")
            nr = first_value(L, n, "nrfiles")
            return nj * b * need_int(nr == "" ? "1" : nr, path ": nrfiles")
        }
        if ((sz = first_value(L, n, "size")) != "") {
            if ((b = parse_size(sz)) != "") return nj * b
            job = path; sub(/.*\//, "", job)
            print "WARNING: " job ": size=" sz " is not a byte count; it contributes nothing to the capacity estimate" > "/dev/stderr"
        }
        return 0
    }
    # the layout job: per job section numjobs x nrfiles x filesize, or
    # numjobs x size=
    function layout_footprint(L, n,    i, s, total, insec, nj, nr, b, perfile, k, v) {
        total = 0; insec = 0
        for (i = 1; i <= n; i++) {
            s = strip(L[i])
            if (s ~ /^\[.+\]$/) {
                if (insec) total += nj * (perfile ? nr : 1) * b
                insec = s != "[global]"; nj = 1; nr = 1; b = 0; perfile = 1
                continue
            }
            if (!insec || !match(s, /^(numjobs|nrfiles|filesize|size)=[^ \t\n\013\014\r\034\035\036\037]+/)) continue
            k = substr(s, 1, index(s, "=") - 1); v = substr(s, length(k) + 2, RLENGTH - length(k) - 1)
            if (k == "numjobs") nj = need_int(v, "the layout numjobs")
            else if (k == "nrfiles") nr = need_int(v, "the layout nrfiles")
            else { if ((b = parse_size(v)) == "") b = 0; perfile = k == "filesize" }
        }
        if (insec) total += nj * (perfile ? nr : 1) * b
        return total
    }
    BEGIN {
        work = ARGV[1]
        # load_fs_groups: the first host of each filesystem group prices
        # its fleet-shared read set; without the groups file, one group
        if ((n = readlines(work "/groups", L)) > 0)
            for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 2) GID[F[1]] = F[2]
        for (a = 3; a < ARGC; a++) {
            g = (ARGV[a] in GID) ? GID[ARGV[a]] : "1"
            if (!(g in FIRST)) FIRST[g] = ARGV[a]
        }
        # each host staged files (the first block of a host listed twice)
        if ((m = readlines(ARGV[2], M)) < 0) awk_fail("cannot read " ARGV[2])
        last = ""
        for (i = 1; i <= m; i++) {
            split(M[i], F, "\t")
            if (F[1] != last) { last = F[1]; take = !(last in NJOB); if (take) NJOB[last] = 0 }
            if (!take) continue
            if (F[2] == "") NODIR[last] = 1
            else JOB[last, ++NJOB[last]] = F[2]
        }
        over = 0; npool = 0
        for (a = 3; a < ARGC; a++) {
            h = ARGV[a]
            if (h in NODIR) continue
            split("", NSV); nns = 0; layout = 0
            for (j = 1; j <= NJOB[h] + 0; j++) {
                p = JOB[h, j]; job = p; sub(/.*\//, "", job)
                if (job == "000-wekatester-relayout.job" || job == "999-wekatester-unlink.job") continue
                if ((n = readlines(p, L)) < 0) awk_fail("cannot read " p)
                if (job == layout_job() || is_layout_marked(L, n)) { layout += layout_footprint(L, n); continue }
                if ((ns = first_value(L, n, "filename_format")) == "") ns = "__default__:" job
                # a group fleet-shared dataset is priced once, on its first host
                if (index(ns, "shared.") == 1 && h != FIRST[(h in GID) ? GID[h] : "1"]) continue
                if (!(ns in NSV)) { NSV[ns] = 0; NSK[++nns] = ns }
                if ((b = footprint(p, L, n)) > NSV[ns]) NSV[ns] = b
            }
            req = 0
            for (k = 1; k <= nns; k++) req += NSV[NSK[k]]
            if (layout > req) req = layout
            # bytes the sweep verified as already laid out serve both the
            # layout and the measured namespaces: a rerun only needs what is
            # actually missing
            credit = 0
            if ((n = readlines(work "/probe/" h ".laidout", L)) >= 0) {
                v = ""
                for (i = 1; i <= n; i++) v = v (i > 1 ? "\n" : "") L[i]
                v = strip(v)
                if ((credit = v == "" ? 0 : py_int(v)) == "") credit = 0
                else if (credit > req) credit = req
            }
            req -= credit
            avail = 0; key = ""
            if ((n = readlines(work "/df/" h, L)) >= 2) {
                if (pysplit(L[2], F) < 4 || (avail = py_int(F[4])) == "") awk_fail(h ": cannot read the df line: " L[2])
                avail *= 1024
                # a weka filesystem is keyed by its name -- a stateless mount
                # lists backends before it, and clients list them differently
                # -- and its size, which tells two clusters same-named
                # filesystems apart
                if (n >= 3 && strip(L[3]) == "wekafs") { fs = F[1]; sub(/.*\//, "", fs); key = fs SUBSEP F[2] }
            }
            print "capacity: " h " needs ~" gib(req) "GiB" (credit ? " (~" gib(credit) "GiB already laid out)" : "") ", has " gib(avail) "GiB available"
            # avail 0 = df unavailable, not a full filesystem: nothing to check
            if (avail && req > avail) {
                over = 1
                print "ERROR: " h ": workload needs ~" gib(req) "GiB but only " gib(avail) "GiB is available" > "/dev/stderr"
            }
            if (key != "" && avail) {
                if (!(key in PN)) { PN[key] = 0; PNEED[key] = 0; PAVAIL[key] = avail; PK[++npool] = key }
                PH[key, ++PN[key]] = h; PNEED[key] += req
                if (avail < PAVAIL[key]) PAVAIL[key] = avail
            }
        }
        # every host fitting alone is not the fleet fitting: 3 hosts needing
        # 640 GiB each passed against one 1000 GiB filesystem
        sort_arr(PK, npool, 0)
        for (i = 1; i <= npool; i++) {
            key = PK[i]
            if (PN[key] < 2 || PNEED[key] <= PAVAIL[key]) continue
            over = 1; split(key, KF, SUBSEP); names = ""
            for (j = 1; j <= PN[key] && j <= 8; j++) names = names (j > 1 ? " " : "") PH[key, j]
            if (PN[key] > 8) names = names " (+" (PN[key] - 8) " more)"
            print "ERROR: weka filesystem " KF[1] ": its " PN[key] " hosts (" names ") need ~" gib(PNEED[key]) "GiB together but only " gib(PAVAIL[key]) "GiB is available" > "/dev/stderr"
        }
        exit (over ? 2 : 0)
    }' "$WORK_DIR" "$WORK_DIR/staged.list" "${HOSTS[@]}"
    case $? in
        0) return 0 ;;
        2) ;;
        *) die "capacity check failed" ;;
    esac
    [ "$IGNORE_CAPACITY" -eq 1 ] \
        || die "not enough capacity on at least one host (use --ignore-capacity to be asked anyway)"
    if try_interactive; then
        confirm_explicit "not enough capacity: continue anyway and risk ENOSPC mid-run?" \
            || die "not enough capacity"
    else
        log "WARNING: --ignore-capacity: not enough capacity, running anyway (unattended)" >&2
    fi
}

# --- layout jobs -----------------------------------------------------------------
# File layout is its own jobfile that always runs first. The run loop executes
# jobfiles serially and the fio coordinator does not exit until every client
# finishes, so jobfile boundaries are hard cross-client barriers: a layout job
# as JOBFILES[0] guarantees all files exist on all machines before any measured
# test starts -- no create-phase skew, no mid-suite re-layout when one job needs
# more files than the previous one created.
LAYOUT_JOB="000-wekatester-layout.job"
LAYOUT_MARKER="# wekatester-layout: generated"

# A layout job is recognized by its reserved name or its marker line, so a
# renamed copy in a custom set is still treated as layout.
is_layout_file() {   # is_layout_file <path>
    [ -f "$1" ] || return 1
    case "${1##*/}" in "$LAYOUT_JOB") return 0 ;; esac
    head -3 "$1" | grep -q "^${LAYOUT_MARKER}" 2>&1
}

# Derive the layout job for a set: group its jobfiles by filename_format
# namespace, take each namespace's superset geometry, and emit one create_only
# section per namespace. Generated deterministically so the embedded sha256 of
# the body identifies a pristine (never hand-edited) file -- the tuner uses
# that to decide whether it may re-derive the staged variant at -a max.
generate_layout() {   # generate_layout <setdir> <outdir>
    local f files=() out n body sha path LC_ALL=C
    [ -d "$1" ] || { log "ERROR: generate_layout: no set directory $1" >&2; return 1; }
    for f in "$1"/[0-9]*; do
        [ -f "$f" ] && files+=("$f")
    done
    # prints the namespace count, then the body the marker's digest covers
    out=$(awkrun 'BEGIN {
        lay_reset(); directory = ""
        for (a = 2; a < ARGC; a++) {
            f = ARGV[a]; sub(/.*\//, "", f)
            if ((n = readlines(ARGV[a], L)) < 0) awk_fail("cannot read " ARGV[a])
            if (f == layout_job() || is_layout_marked(L, n)) continue   # never derive layout from layout
            lay_add(L, n, f, ARGV[a]); lay_engine(L, n)
            if (directory == "") directory = first_value(L, n, "directory")
        }
        if (!LAY_NNS) awk_fail("no jobfiles to derive a layout from in " ARGV[1])
        nb = 0
        B[++nb] = "# Auto-generated by wekatester: lays out every file the set\047s jobs"
        B[++nb] = "# will use, as the first job of the run -- a cross-client barrier, so"
        B[++nb] = "# all files exist on all machines before any measured test starts."
        B[++nb] = "# Edit freely: an edited layout job is preserved (regenerate with -g)."
        B[++nb] = "[global]"
        B[++nb] = "directory=" (directory != "" ? directory : "/mnt/weka")
        # fallocate=none is what makes the layout sweep size test sound. fio
        # defaults to fallocate=native on Linux, which gives a file its full
        # st_size instantly and only then writes the data -- so a layout
        # killed part way leaves a full-size file full of zeros, which the
        # sweep credits as complete and never rewrites. Without
        # preallocation an interrupted create leaves a SHORT file, which the
        # sweep deletes and recreates.
        B[++nb] = "fallocate=none"
        B[++nb] = "create_serialize=0"
        B[++nb] = "ioengine=" pick_engine(LAY_TALLY, LAY_EORD, LAY_NE)
        nb = lay_sections(B, nb)
        print LAY_NNS
        for (i = 1; i <= nb; i++) print rstrip(B[i])
    }' "$1" ${files[@]+"${files[@]}"}) || return 1
    n=${out%%$'\n'*}; body=${out#*$'\n'}
    sha=$(printf '%s' "$body" | sha256_hex) || return 1
    case "$2" in (*/) path="$2$LAYOUT_JOB" ;; (*) path="$2/$LAYOUT_JOB" ;; esac
    { [ -d "$2" ] || mkdir -p "$2"; } && printf '%s sha256=%s\n%s\n' "$LAYOUT_MARKER" "$sha" "$body" > "$path" \
        || return 1
    printf 'layout: generated %s (%s namespace(s))\n' "$path" "$n"
}

# --- host files (-t) --------------------------------------------------------------
# A hostlist.csv assigns per-host settings without a jobfile set per client:
#   host,user_login,ioengine,allowed_cpus,destination_folder,\
#       bandwidthR:nj/fs/nr/qd,bandwidthW:...,latencyR:...,latencyW:...,\
#       iopsR:...,iopsW:...
# Lines naming a host assign to that host (two lines naming one host is
# fatal). Host-less lines are SELECTOR lines: their login and/or ioengine
# choose which hosts they apply to (login = hosts using that login; engine =
# hosts that PASSED that engine's functional test), and their remaining
# fields fold into any host whose more-specific config left them unset.
# Specificity: host line > two selectors > one selector > global; generic
# never overrides specific regardless of file order; equal specificity =
# first line wins with a warning. A host-less line's login is ONLY a
# selector -- logins are assigned by host lines, the CLI, or defaults,
# which is what makes resolution well-founded: engine-selector lines need
# test results, tests need auth, auth needs logins.
#
# Two phases for that same reason: phase1 (pre-auth) = logins + initial
# dirs from host lines and login-selector folding; phase2 (post engine
# tests, results in a file as "host engine ok|fail" lines) = everything.
# Output, one host per line, tab-separated, "-" = unset:
#   host login engine cpus dir, then nj/fs/nr/qd per slot in
#   bw_r, bw_w, lat_r, lat_w, iops_r, iops_w, lat1m_r, lat1m_w order
#   (37 columns)
# CLI values arrive as arguments and take precedence over the file.
# A fresh host file: header plus a commented format reference, so an editor
# session or a later -a writeback starts from something self-describing.
write_targets_template() {   # write_targets_template <path>
    local header="host,user_login,ioengine,allowed_cpus,destination_folder" n
    # the column list comes from the shared schema, not a second spelling
    for n in $GEOM_NAMES; do header="$header,$n:nj/fs/nr/qd"; done
    { printf '%s\n' "$header"
      cat <<'CSVEOF'
# One host per line assigns to that host; lines without a host apply to the
# hosts their login and/or ioengine select. Quote cpu lists: "22,24,26".
# Geometry is per type AND direction: R columns shape read jobs, W columns
# write jobs; a mixed-direction jobfile takes the deeper-queued direction's
# whole tuple.
# Example:  client-1,ubuntu,io_uring,"8,10",/mnt/weka,12/10G/2/8,12/10G/2/4,1/1G/2/1,1/1G/2/1,42/256M/2/16,42/256M/2/8
# Example:  ,,io_uring,,,,,,,,     (io_uring for every host that supports it)
# A host may be written as <name>/<machine-id>; the id is ignored when the
# row is read and only ever added by wekatester itself, to name a machine it
# is recording for the first time. Plain hostnames are equally valid, and a
# row you wrote keeps the spelling you gave it.
CSVEOF
    } > "$1" || die "cannot create host file $1"
    log "created host file $1"
}

# The directory an existing -C set name points at, if any -- lookup only,
# never creating (resolve_custom_set runs later and may create it). Shipped
# names return nothing: those are always customized via a fresh copy.
custom_set_probe_dir() {
    [ "$CUSTOMIZE" -eq 1 ] && [ -n "$CUSTOM_SET" ] || return 0
    case " $SHIPPED_SETS " in *" $CUSTOM_SET "*) return 0 ;; esac
    case "$CUSTOM_SET" in
        /*|./*) [ ! -d "$CUSTOM_SET" ] || printf '%s' "$CUSTOM_SET" ;;
        *)  if [ -d "$SCRIPT_DIR/fio-jobfiles/$CUSTOM_SET" ]; then
                printf '%s' "$SCRIPT_DIR/fio-jobfiles/$CUSTOM_SET"
            elif [ -d "./fio-jobfiles/$CUSTOM_SET" ]; then
                printf '%s' "./fio-jobfiles/$CUSTOM_SET"
            fi ;;
    esac
}

# Which file does -t mean? Explicit path wins (missing: confirm-create or
# quit -- 5s defaulting to create under -r). Bare -t looks in the job set
# folders first: an existing -C set's own hostlist.csv, then the -w set's,
# then ./hostlist.csv -- a set-folder copy beats ./hostlist.csv and is the
# one later writebacks update. With -C and no file anywhere, the file
# belongs IN the set: creation defers to ensure_set_hostfile (the -C editor
# opens the fresh template), never a stray ./hostlist.csv. Without -C,
# nothing anywhere creates ./hostlist.csv with the usual confirmation.
# Without -t no file is ever used (except a -C set's own, always honored).
# --- host identity: what the host FILE and the data files call a machine -----
# Internally a host is an ADDRESS: what ssh connects to, what fio is handed as
# --client=, and a path component under $WORK_DIR. None of that may contain a
# slash, and in local mode it has to stay "localhost" so fio keeps talking to
# a loopback server.
#
# The host FILE and the DATA FILES want a NAME instead: "localhost" identifies
# nothing on a shared filesystem, and two boxes in local mode against the same
# mount would write (and -u would unlink) each other's localhost.* files. So
# host_name() is the address for a remote worker and the box's own short
# hostname in local mode; it prefixes every data file on the destination and
# names an automatically written host file row as <name>/<machine-id>. Rows a
# person wrote are left exactly as written; the id is never required.
#
# Reading, the id is stripped and the name mapped back to an address, so
# nothing downstream ever sees it.

# Machine id, cached per host. product_uuid is the mainboard's and survives a
# reinstall, but is root-only on most kernels; machine-id is world-readable
# and survives everything except a reimage. Either identifies the box far
# better than "localhost"; neither is required.
host_machine_id() {   # host_machine_id <host>
    local host=$1 cache="$WORK_DIR/ident/$1.id" out
    [ -d "$WORK_DIR/ident" ] || mkdir -p "$WORK_DIR/ident"
    if [ ! -f "$cache" ]; then
        # The probe already carried the id over its own session (probe_workers
        # runs before every writeback), so read it from there: one awk, no
        # round trip. A probe without the line, or no probe, asks the host.
        # -r tests instead of stderr suppression: product_uuid is root-only
        # on most kernels and either file may be absent -- both are ordinary,
        # neither is an error. A FAILED run_host, by contrast, is said out
        # loud: an unreachable box degrading to a bare name should be
        # distinguishable from a box that has no readable id.
        if [ -f "$WORK_DIR/probe/$host" ] && out=$(awk \
                '$1 == "ident" {print tolower($2); f = 1; exit} END {exit !f}' \
                "$WORK_DIR/probe/$host"); then
            printf '%s' "$out" > "$cache"
        elif out=$(run_host "$host" "if [ -r /sys/class/dmi/id/product_uuid ]; \
                then cat /sys/class/dmi/id/product_uuid; \
                elif [ -r /etc/machine-id ]; then cat /etc/machine-id; fi"); then
            printf '%s' "$out" | tr -d '[:space:]' | tr 'A-Z' 'a-z' > "$cache"
        else
            log "WARNING: $host: cannot read a machine id; recording the bare name" >&2
            : > "$cache"
        fi
    fi
    cat "$cache"
}

# The box's own short name: hostname -s first, then bash's HOSTNAME trimmed
# to its first label (set from gethostname() with no resolution, so it
# answers where `hostname -s` fails with "Name or service not known"), then
# a bare hostname. Empty when nothing answers; the caller falls back.
local_short_hostname() {
    local n
    n=$(hostname -s) || n=""
    [ -n "$n" ] || n=${HOSTNAME%%.*}
    [ -n "$n" ] || n=$(hostname) || n=""
    printf '%s' "$n"
}

# The name this host goes by -- in the host file and as the prefix of its
# data files. Remote: the address. Local mode: the short hostname, fixed
# once by resolve_local_mode (LOCAL_NAME) and derived on demand for a
# caller that runs without it; "localhost" only when the box has no name.
host_name() {   # host_name <host>
    host_name_v "$1"
    printf '%s' "$HOST_NAME"
}
# host_name into HOST_NAME, without the subshell a $(host_name) costs: the
# loops over the fleet use this -- remotely the name is the address itself,
# and a fork per host to say so added up
host_name_v() {   # host_name_v <host> -> HOST_NAME
    if [ "$LOCAL_MODE" -eq 1 ]; then
        HOST_NAME=${LOCAL_NAME:-$(local_short_hostname)}
        HOST_NAME=${HOST_NAME:-$1}
    else
        HOST_NAME=$1
    fi
}

# "<name>/<machine-id>", or just the name when no id could be read.
host_identity() {   # host_identity <host>
    local n id
    n=$(host_name "$1"); id=$(host_machine_id "$1")
    [ -n "$id" ] && printf '%s/%s' "$n" "$id" || printf '%s' "$n"
}

# "addr=<host_identity>,..." for the fleet: one awk reads every id the
# probe carried; only a host whose probe has none goes through
# host_identity, and its round trip, on its own.
host_idents() {
    local h i=0 out="" files=() ids=() id
    for h in "${HOSTS[@]}"; do
        [ ! -s "$WORK_DIR/probe/$h" ] || files+=("$WORK_DIR/probe/$h")
    done
    if [ ${#files[@]} -gt 0 ]; then
        while IFS= read -r id; do ids+=("$id"); done < <(awk '
            FNR == 1 && NR > 1 { print id; id = "" }
            $1 == "ident" && !got[FILENAME]++ { id = tolower($2) }
            END { print id }' "${files[@]}")
    fi
    for h in "${HOSTS[@]}"; do
        id=""
        if [ -s "$WORK_DIR/probe/$h" ]; then id=${ids[$i]:-}; i=$((i + 1)); fi
        if [ -n "$id" ]; then
            host_name_v "$h"; out="$out${out:+,}$h=$HOST_NAME/$id"
        else
            out="$out${out:+,}$h=$(host_identity "$h")"
        fi
    done
    printf '%s' "$out"
}

# name=address pairs for the CSV readers, so a row written as
# "client-a/<id>" resolves to the address the run actually uses.
host_alias_env() {   # host_alias_env <host>... -> "name=addr,name=addr"
    # remotely every name is its address: there is nothing to alias
    [ "$LOCAL_MODE" -eq 1 ] || return 0
    local h out=""
    for h in "$@"; do
        host_name_v "$h"
        [ "$HOST_NAME" = "$h" ] || out="$out${out:+,}$HOST_NAME=$h"
    done
    printf '%s' "$out"
}

resolve_targets_file() {
    [ "$TARGETS" -eq 1 ] || return 0
    local candidate cdir
    if [ -n "$TARGETS_PATH" ]; then
        candidate=$TARGETS_PATH
    else
        cdir=$(custom_set_probe_dir)
        candidate=""
        [ -z "$cdir" ] || [ ! -f "$cdir/hostlist.csv" ] || candidate="$cdir/hostlist.csv"
        if [ -z "$candidate" ]; then
            candidate="$SCRIPT_DIR/fio-jobfiles/$WORKLOAD/hostlist.csv"
            [ -f "$candidate" ] || candidate="./fio-jobfiles/$WORKLOAD/hostlist.csv"
            [ -f "$candidate" ] || candidate="./hostlist.csv"
        fi
        if [ ! -f "$candidate" ] && [ "$CUSTOMIZE" -eq 1 ]; then
            TARGETS_FILE=""
            log "host file: none found; it will be created in the custom set"
            return 0
        fi
    fi
    if [ ! -f "$candidate" ]; then
        if [ "$FAST_TRACK" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
            # 5s prompt when a terminal exists; without one, the default
            # (create and continue) applies -- never write to unopened fds
            if try_interactive; then
                if ! confirm_timed 5 yes "host file $candidate does not exist; create it?"; then
                    die "host file $candidate does not exist"
                fi
            else
                log "host file $candidate does not exist; creating it (unattended)"
            fi
        else
            require_interactive "-t"
            if ! confirm_explicit "host file $candidate does not exist; create it?"; then
                die "host file $candidate does not exist"
            fi
        fi
        write_targets_template "$candidate"
    fi
    TARGETS_FILE=$candidate
    log "host file: $TARGETS_FILE"
}

# Per-host resolved values, phase1 (login/dir before auth). Field numbers
# match resolve_targets' output: 2=login 3=engine 4=cpus 5=dir.
targets_field() {   # targets_field <host> <fieldno> [phasefile]
    local f=${3:-$WORK_DIR/targets.phase1} v
    [ -f "$f" ] || return 0
    v=$(awk -F'\t' -v h="$1" -v n="$2" '$1 == h {print $n; exit}' "$f")
    [ "$v" = "-" ] || printf '%s' "$v"
}

# -a writeback: record what the tuner derived into the host file, for
# re-use. Only when a host file is in play (-t, or a -C set which owns one).
# Fill-missing by default: a field the FILE already provides (any line, by
# the folding rules) is left alone. With -g an untimed prompt offers
# overwrite instead -- except under -r, which cannot prompt and assumes
# fill-missing. Updates never edit in place: a superseded host line is
# commented out FIRST, then the new line appended (append-before-comment
# would trip the duplicate-host-fatal rule on the very next parse).
writeback_targets() {
    [ -n "$AUTO_LEVEL" ] || return 0
    local wb="$TARGETS_FILE" mode=fill
    [ -n "$wb" ] || { [ -n "$SET_DIR_OVERRIDE" ] && wb="$SET_DIR_OVERRIDE/hostlist.csv"; }
    [ -n "$wb" ] && [ -f "$wb" ] || return 0
    # -g means the derived and measured values WIN -- no prompt. The three
    # columns the operator owns outright (host, login, allowed_cpus) are
    # protected inside the merge below regardless of mode -- when the HOST'S
    # OWN row provides them. A generic (host-less) row is a default for
    # whoever lacks a value, not that host's setting: it is never edited,
    # and the host line written beside it records what the run resolved --
    # the cpu list fio actually executed on (the generic list minus weka's
    # pinned cores and cpus the host does not have), the proven engine, the
    # resolved destination -- so the file ends up saying, per host, what ran.
    [ "$REGEN_LAYOUT" -eq 0 ] || mode=overwrite
    # --line-rate measured the bandwidth slots again, so in fill mode too
    # their measured tuples replace what the host's row recorded
    # what does each host's OWN row provide? (no CLI merge, no generic rows)
    resolve_targets hostonly "$wb" - - "${WORK_DIR}/engine.results" "${HOSTS[@]}" \
        > "$WORK_DIR/targets.hostrows" || : > "$WORK_DIR/targets.hostrows"
    local h ident=""
    ident=$(host_idents)
    list_staged "$WORK_DIR/staged.list" &&
    WEKATESTER_HOST_ALIAS=$(host_alias_env "${HOSTS[@]}") \
    WEKATESTER_HOST_IDENT=$ident \
    awkrun '
    function slurp(path,    L, n, i, v) {   # open(path).read().strip(); slurped: it exists
        slurped = (n = readlines(path, L)) >= 0; v = ""
        for (i = 1; i <= n; i++) v = v (i > 1 ? "\n" : "") L[i]
        return strip(v)
    }
    # Values compare by what they mean, not how they are spelled: 5G is
    # 5120M, 2-4 is 2,3,4 (but 2,4 is not 2-4) -- a line whose values all
    # hold is left exactly as it is (Frank, 2026-10-02).
    function norm(k, v,    S, b) {
        if (k == "cpus") return parse_cpulist(v, S) ? "c" fmt_cpulist(S) : "s" v
        if (k ~ /_fs$/) return (b = parse_size(v)) != "" ? "n" sprintf("%.0f", b) : "s" v
        if (k ~ /_(nj|nr|qd)$/) return (b = py_int(v)) != "" ? "n" sprintf("%.0f", b) : "s" v
        return "s" v
    }
    function geom(h, slot,    q, v, out, any) {   # nj/fs/nr/qd, the trailing blanks dropped
        out = ""; any = 0
        for (q = 1; q <= 4; q++) {
            v = ((h, slot "_" TUPLE[q]) in WANT) ? WANT[h, slot "_" TUPLE[q]] : ""
            if (v != "") any = 1
            out = out (q > 1 ? "/" : "") v
        }
        if (!any) return ""
        sub(/\/+$/, "", out)
        return out
    }
    function render(h,    cell, row, k, s, n, G) {
        # a row the operator wrote keeps its own spelling of the host,
        # machine-id or not -- automation only names a machine it is adding
        cell = (h in SEEN_CELL) ? SEEN_CELL[h] : (h in IDENT) ? IDENT[h] : h
        row = csv_field(cell)
        for (k = 1; k <= 4; k++) row = row "," csv_field(((h, FIELD[k]) in WANT) ? WANT[h, FIELD[k]] : "")
        for (s = 1; s <= nslot; s++) G[s] = geom(h, SLOT[s])
        n = nslot
        while (n > 6 && G[n] == "") n--   # no 1MiB latency geometry: the row stays in the old width
        for (s = 1; s <= n; s++) row = row "," csv_field(G[s])
        return row
    }
    function own_line(line,    F, h) {   # the address of the host whose own line this is, or ""
        if (!csv_line(line, F)) return ""
        h = strip(F[1])
        if (h == "" || substr(h, 1, 1) == "#" || tolower(h) == "host" || !(host_addr(h, ALIAS) in WANTED)) return ""
        OWN_CELL = h
        return host_addr(h, ALIAS)
    }
    BEGIN {
        wb = ARGV[1]; mode = ARGV[2]; work = ARGV[3]; line_gbps = ARGV[4]
        kv_map(ENVIRON["WEKATESTER_HOST_ALIAS"], ALIAS); kv_map(ENVIRON["WEKATESTER_HOST_IDENT"], IDENT)
        nslot = split(geom_slots(), SLOT, " "); split("nj fs nr qd", TUPLE, " ")
        split("login engine cpus dir", FIELD, " "); nfield = 4
        for (s = 1; s <= nslot; s++) for (q = 1; q <= 4; q++) FIELD[++nfield] = SLOT[s] "_" TUPLE[q]
        n = split(line_rate_slots(), F, " ")
        for (i = 1; i <= n; i++) LINE_RATE[F[i]] = 1
        # what each host OWN row provides (resolve_targets hostonly): the
        # last full-width line per host
        n = readlines(work "/targets.hostrows", L)
        for (i = 1; i <= n; i++) if (split(L[i], F, "\t") == nfield + 1) HROW[F[1]] = L[i]
        for (h in HROW) {
            split(HROW[h], F, "\t")
            for (f = 1; f <= nfield; f++) if (F[f + 1] != "-") HAVE[h, FIELD[f]] = F[f + 1]
        }
        # The measured knees first (cal.results is pure measurement --
        # targets.final would also carry CLI-merged values, which are not
        # calibration to record), then the STAGED variants for whatever was
        # not measured. A malformed line is a schema break, not a skip:
        # apply_cal_results dies on the same seam. CAL_COLS as lib.py
        # derives it: the host, its engine, then (qd nr fs nj) per slot.
        n = readlines(work "/cal.results", L)
        for (i = 1; i <= n; i++) {
            if (!cal_results_split(L[i], F)) continue
            split("", T); got = 0
            for (s = 1; s <= nslot; s++) {
                b = 2 + 4 * (s - 1)
                if (F[b + 1] != "-") { T[SLOT[s] "_qd"] = F[b + 1]; T[SLOT[s] "_nr"] = F[b + 2]; T[SLOT[s] "_fs"] = F[b + 3]; got = 1 }
                # a measured tuple always carries its numjobs: the answer of
                # bandwidth IS a job count (the first to reach line rate), so
                # is that of latency (the widest still at the floor), and the
                # iops re-split may have moved it off one job per cpu. It is
                # also what marks the tuple as MEASURED -- the staged tuples
                # recorded below never carry one, so the cache of calibration
                # cannot mistake a tuned guess for a measurement.
                if (F[b + 4] != "-") { T[SLOT[s] "_nj"] = F[b + 4]; got = 1 }
            }
            if (!got) continue
            for (f = 1; f <= nfield; f++) delete MEAS[F[1], FIELD[f]]
            for (k in T) MEAS[F[1], k] = T[k]
        }
        # each host staged files (the first block of a host listed twice)
        if ((m = readlines(work "/staged.list", M)) < 0) awk_fail("cannot read " work "/staged.list")
        last = ""
        for (i = 1; i <= m; i++) {
            split(M[i], F, "\t")
            if (F[1] != last) { last = F[1]; take = !(last in NJOB); if (take) NJOB[last] = 0 }
            if (take && F[2] != "") JOB[last, ++NJOB[last]] = F[2]
        }
        nup = 0
        for (a = 5; a < ARGC; a++) {
            h = ARGV[a]; split("", D); split("", DP)
            for (f = 1; f <= nfield; f++) if ((h, FIELD[f]) in MEAS) { D[FIELD[f]] = MEAS[h, FIELD[f]]; DP[FIELD[f]] = 1 }
            v = slurp(work "/auth/" h ".user")
            if (slurped) { D["login"] = v; DP["login"] = 1 }
            # the cpu list fio may run on here, as the tuner resolved it: a
            # staged job names only the subset its own job count runs on
            # (physical cores alone at N or fewer jobs), so no single job is
            # the list to record
            v = slurp(work "/usable/" h)
            if (slurped && !("cpus" in DP)) { D["cpus"] = v; DP["cpus"] = 1 }
            for (j = 1; j <= NJOB[h] + 0; j++) {
                p = JOB[h, j]; job = p; sub(/.*\//, "", job)
                if ((n = readlines(p, L)) < 0) awk_fail("cannot read " p)
                if (job == layout_job() || is_layout_marked(L, n)) continue   # the layout is a barrier, not a test: it records nothing
                if (is_floor_marked(L, n)) continue   # its one-job geometry is forced, not something to record
                lat = bw = iops = 0
                for (i = 1; i <= n; i++) {
                    if (index(L[i], "# report") != 1) continue
                    nw = pysplit(L[i], W)
                    for (k = 3; k <= nw; k++) { if (W[k] == "latency") lat = 1; else if (W[k] == "bandwidth") bw = 1; else if (W[k] == "iops") iops = 1 }
                }
                # precedence latency > bandwidth > iops, same as the tuner; a
                # 1MiB latency file (a -b twin) records into the lat1m slot
                kind = lat ? lat_kind(L, n) : bw ? "bw" : iops ? "iops" : ""
                if (!("engine" in DP)) { D["engine"] = first_value(L, n, "ioengine"); DP["engine"] = 1 }
                if (!("cpus" in DP)) { D["cpus"] = first_value(L, n, "cpus_allowed"); DP["cpus"] = 1 }
                if (!("dir" in DP)) { D["dir"] = first_value(L, n, "directory"); DP["dir"] = 1 }
                if (kind == "") continue
                # a measured direction already carries its own tuple, so the
                # staged tuple fills only unmeasured slots. A staged numjobs
                # is never recorded: the tuner re-derives it from the usable
                # cores every run, and a recorded count would only go stale
                # (weka re-pins, cpu list edits) -- and the next calibration
                # would test only that guess, since a recorded value pins its
                # knob.
                file_directions(L, n, DIR)
                for (q = 1; q <= 2; q++) {
                    if (!((q == 1 ? "read" : "write") in DIR)) continue
                    for (t = 2; t <= 4; t++) {
                        v = first_value(L, n, t == 2 ? "filesize" : t == 3 ? "nrfiles" : "iodepth")
                        k = kind "_" (q == 1 ? "r" : "w") "_" TUPLE[t]
                        if (v != "" && !(k in DP)) { D[k] = v; DP[k] = 1 }
                    }
                }
            }
            # The host desired line: its own row, plus what the run derived
            # for whatever that row left unset (or everything, under -g).
            # Values a generic row supplied are not the host own, so a host
            # that ran on a generic cpu list gets its own line carrying the
            # list that actually executed.
            for (f = 1; f <= nfield; f++) {
                k = FIELD[f]; delete WANT[h, k]
                if ((h, k) in HAVE) WANT[h, k] = HAVE[h, k]
            }
            for (f = 1; f <= nfield; f++) {
                k = FIELD[f]
                if (!(k in DP) || D[k] == "") continue
                # identity, credentials and the operator OWN cpu list are
                # never overwritten, -g included
                if ((k == "login" || k == "cpus") && ((h, k) in HAVE)) continue
                if (((h, k) in HAVE) && norm(k, HAVE[h, k]) == norm(k, D[k])) continue   # the row keeps its own spelling
                # the bandwidth tuples --line-rate MEASURED again replace the
                # row; a staged guess for those slots never does
                fresh = line_gbps != "-" && ((h, k) in MEAS) && (substr(k, 1, length(k) - 3) in LINE_RATE)
                if (mode == "overwrite" || !((h, k) in HAVE) || fresh) WANT[h, k] = D[k]
            }
            # an update when the line no longer says what holds
            same = 1; any = 0
            for (f = 1; f <= nfield; f++) {
                k = FIELD[f]
                if ((h, k) in WANT) any = 1
                if (((h, k) in WANT) != ((h, k) in HAVE) || ((h, k) in WANT) && norm(k, WANT[h, k]) != norm(k, HAVE[h, k])) same = 0
            }
            if (any && !same && !(h in WANTED)) { WANTED[h] = 1; nup++ }
        }
        if (!nup) { print "host file: nothing to record"; exit 0 }
        # The host file is only ever added to (Frank, 2026-10-02): a host
        # own line is commented out and its new version written directly
        # below it; a host with no line of its own gets one appended at the
        # end. Nothing is deleted or rewritten in place, and a generic
        # (host-less) row is never touched.
        if ((n = readlines(wb, L)) < 0) awk_fail("cannot read " wb)
        for (i = 1; i <= n; i++)
            if ((addr = own_line(L[i])) != "" && !(addr in SEEN_CELL)) SEEN_CELL[addr] = OWN_CELL
        no = 0
        for (i = 1; i <= n; i++) {
            if ((addr = own_line(L[i])) == "") { O[++no] = L[i]; continue }
            O[++no] = "# superseded by -a: " L[i]
            if (!(addr in PLACED)) { O[++no] = render(addr); PLACED[addr] = 1 }
        }
        for (a = 5; a < ARGC; a++) if ((ARGV[a] in WANTED) && !(ARGV[a] in PLACED)) O[++no] = render(ARGV[a])
        writelines(wb, O, no)
        print "host file: recorded " nup " host line(s) in " wb " (" mode ")"
    }' "$wb" "$mode" "$WORK_DIR" "${LINE_RATE_GBPS:--}" "${HOSTS[@]}" || die "host file writeback failed ($wb)"
}

# The host's destination dir: the finished resolution when it exists, the
# pre-auth phase otherwise, the global -d as the fallback.
host_dir() {   # host_dir <host>
    local d=""
    if [ -f "$WORK_DIR/targets.final" ]; then
        d=$(targets_field "$1" 5 "$WORK_DIR/targets.final")
    elif [ -f "$WORK_DIR/targets.phase1" ]; then
        d=$(targets_field "$1" 5)
    fi
    printf '%s' "${d:-$DIRECTORY}"
}

# One host-file column for many hosts, one line each in the order given
# ("" for no row, or "-"): targets_field's rule -- the first row per host
# counts -- in one awk instead of one per host.
targets_column() {   # targets_column <fieldno> <file> <host>...
    awk 'BEGIN {
        while ((getline line < ARGV[2]) > 0) {
            split(line, F, "\t")
            if (!(F[1] in v)) v[F[1]] = F[ARGV[1] + 0]
        }
        for (a = 3; a < ARGC; a++) {
            x = (ARGV[a] in v) ? v[ARGV[a]] : ""
            if (x == "-") x = ""
            print x
        }
    }' "$@"
}

# Every host's destination in HOSTS order, into HOST_DIRS: host_dir's rule
# (the finished host-file resolution, else the pre-auth phase, else -d) for
# the fleet in one awk. A phase that walks the fleet loads it once rather
# than an awk per host; the resolution can change between phases (phase1,
# then final; -C refreshes it), so each such phase loads it again.
HOST_DIRS=()
load_host_dirs() {
    local f="" d i=0
    HOST_DIRS=()
    if [ -f "$WORK_DIR/targets.final" ]; then f="$WORK_DIR/targets.final"
    elif [ -f "$WORK_DIR/targets.phase1" ]; then f="$WORK_DIR/targets.phase1"
    fi
    if [ -z "$f" ]; then
        for d in "${HOSTS[@]}"; do HOST_DIRS[i]=$DIRECTORY; i=$((i + 1)); done
        return 0
    fi
    while IFS= read -r d; do
        HOST_DIRS[i]=${d:-$DIRECTORY}; i=$((i + 1))
    done < <(targets_column 5 "$f" "${HOSTS[@]}")
    # a host the awk never answered for still gets -d, as host_dir gives it
    while [ "$i" -lt ${#HOSTS[@]} ]; do HOST_DIRS[i]=$DIRECTORY; i=$((i + 1)); done
}

host_priv() {   # host_priv <host> -> passwordless escalator prefix ("" if none)
    # the probe emits a PREFIX ("dzdo -n", "ksu -e", "pbrun"): sites that
    # install an enterprise escalator usually mandate it, so the sweep tests
    # dzdo/pbrun/sesu/pmrun/doas/ksu before sudo, non-interactively, and the
    # first that can run `true` wins -- whatever cannot work as a command
    # prefix fails that same test and self-eliminates
    [ -f "$WORK_DIR/probe/$1" ] || return 0
    awk '/^priv /{sub(/^priv /, ""); print; exit}' "$WORK_DIR/probe/$1"
}

# phase1: before the engine tests (engine selectors cannot apply yet);
# phase2: with engine.results, the finished resolution; hostonly: each
# host's OWN row and nothing else -- what the writeback merges against, so
# a generic (host-less) row's defaults are never mistaken for the host's.
resolve_targets() {   # resolve_targets <phase1|phase2|hostonly> <csv> <cli_engine|-> <cli_dir|-> <results|-> <host>...
    WEKATESTER_HOST_ALIAS=$(host_alias_env "${@:6}") awkrun 'BEGIN {
        phase = ARGV[1]; path = ARGV[2]; cli_engine = ARGV[3]; cli_dir = ARGV[4]; results = ARGV[5]
        kv_map(ENVIRON["WEKATESTER_HOST_ALIAS"], ALIAS)
        nslot = split(geom_slots(), SLOT, " "); split(geom_names(), GNAME, " ")
        split("nj fs nr qd", TUPLE, " "); ncols = 5 + nslot
        split("login engine cpus dir", FIELD, " "); nfield = 4
        for (s = 1; s <= nslot; s++) for (q = 1; q <= 4; q++) FIELD[++nfield] = SLOT[s] "_" TUPLE[q]
        # ---- parse: one entry per row, its fields in the order they count ----
        if ((n = readlines(path, L)) < 0) awk_fail("cannot read host file: " path)
        nrec = csv_read(L, n, CN, CV); ne = 0
        for (r = 1; r <= nrec; r++) {
            all = ""
            for (k = 1; k <= CN[r]; k++) all = all CV[r, k]
            if (!CN[r] || strip(all) == "") continue
            if (substr(strip(CV[r, 1]), 1, 1) == "#") continue
            if (r == 1 && tolower(strip(CV[r, 1])) == "host") continue   # the header
            for (k = 1; k <= ncols; k++) C[k] = k <= CN[r] ? strip(CV[r, k]) : ""
            ne++; nk = 0
            if (C[3] != "") { EK[ne, ++nk] = "engine"; EV[ne, nk] = C[3] }
            if (C[4] != "") { EK[ne, ++nk] = "cpus"; EV[ne, nk] = C[4] }
            if (C[5] != "") { EK[ne, ++nk] = "dir"; EV[ne, nk] = C[5] }
            # geometry: "bandwidthR:12/10G/1/8" or a bare "12/10G/1/8";
            # empty parts are unset
            for (s = 1; s <= nslot; s++) {
                if ((raw = C[5 + s]) == "") continue
                if ((p = index(raw, ":"))) {
                    pfx = substr(raw, 1, p - 1)
                    if (tolower(strip(pfx)) != tolower(GNAME[s]))
                        awk_fail(path ":" r ": column for " GNAME[s] " carries prefix \047" pfx "\047")
                    raw = substr(raw, p + 1)
                }
                np = lsplit(raw, PART, "/")
                for (q = 1; q <= 4 && q <= np; q++)
                    if (strip(PART[q]) != "") { EK[ne, ++nk] = SLOT[s] "_" TUPLE[q]; EV[ne, nk] = strip(PART[q]) }
            }
            ELINE[ne] = r
            if ((EHOST[ne] = host_addr(C[1], ALIAS)) != "") {
                if (C[2] != "") { EK[ne, ++nk] = "login"; EV[ne, nk] = C[2] }
                h = EHOST[ne]
                if (h in HLINE) {
                    # two spellings of one machine -- most likely the same
                    # short name carrying different machine-ids, which the
                    # run cannot tell apart because both resolve to the same
                    # address
                    extra = HCELL[h] == C[1] ? "" : "; \047" HCELL[h] "\047 and \047" C[1] "\047 both resolve to \047" h "\047 -- keep the row for this machine and drop the other"
                    awk_fail(path ":" r ": duplicate definition for host \047" h "\047 (first at line " HLINE[h] ")" extra)
                }
                HLINE[h] = r; HCELL[h] = C[1]; HENT[h] = ne
                ELOGIN[ne] = ""; EENG[ne] = ""; ENSEL[ne] = 3
            } else {
                # host-less: login and engine are SELECTORS; login is never assigned
                ELOGIN[ne] = C[2]; EENG[ne] = C[3]; ENSEL[ne] = (C[2] != "") + (C[3] != "")
                HL[++nhl] = ne   # the host-less lines, in file order
            }
            ENK[ne] = nk
        }
        # ---- phase2 input: the engine test results ----
        if (phase == "phase2" && results != "-") {
            if ((n = readlines(results, L)) < 0) awk_fail("cannot read " results)
            for (i = 1; i <= n; i++) if (pysplit(L[i], F) == 3 && F[3] == "ok") PASSED[F[1], F[2]] = 1
        }
        # ---- resolve per host ----
        for (a = 6; a < ARGC; a++) {
            h = ARGV[a]; split("", CFG); split("", SN); split("", SL)
            # the host line first: the most specific, unique -- looked up,
            # not scanned for: a scan per host was hosts x lines
            if (h in HENT) {
                e = HENT[h]
                for (j = 1; j <= ENK[e]; j++) { k = EK[e, j]; CFG[k] = EV[e, j]; SN[k] = ENSEL[e]; SL[k] = ELINE[e] }
            }
            login = ("login" in CFG) ? CFG["login"] : ""
            # host-less lines, most selectors first, ties to the first line
            # (none in hostonly: their values are defaults, not the host own)
            for (sel = 2; sel >= 0 && phase != "hostonly"; sel--)
                for (q = 1; q <= nhl; q++) {
                    e = HL[q]
                    if (ENSEL[e] != sel) continue
                    if (ELOGIN[e] != "" && ELOGIN[e] != login) continue
                    # an engine selector needs test results; it folds in later
                    if (EENG[e] != "" && (phase != "phase2" || !((h, EENG[e]) in PASSED))) continue
                    for (j = 1; j <= ENK[e]; j++) {
                        k = EK[e, j]; v = EV[e, j]
                        if (k == "login") continue
                        if (!(k in CFG)) { CFG[k] = v; SN[k] = sel; SL[k] = ELINE[e] }
                        else if (SN[k] == sel && CFG[k] != v)
                            print "WARNING: " path ": host \047" h "\047 field \047" k "\047: line " ELINE[e] " conflicts with equally specific line " SL[k] "; keeping line " SL[k] > "/dev/stderr"
                    }
                }
            if (cli_engine != "-") CFG["engine"] = cli_engine   # the CLI beats the file
            if (cli_dir != "-") CFG["dir"] = cli_dir
            line = h
            for (f = 1; f <= nfield; f++) line = line "\t" ((FIELD[f] in CFG) && CFG[FIELD[f]] != "" ? CFG[FIELD[f]] : "-")
            print line
        }
    }' "$@"
}

# --- customize workflow (-C) ------------------------------------------------------
copy_set_into() {   # copy_set_into <srcdir> <dstdir>
    local f
    for f in "$1"/[0-9]*; do
        [ -f "$f" ] || die "no jobfiles to copy from $1"
        cp "$f" "$2/" || die "cannot copy ${f##*/} into $2"
    done
}

# The -w set's directory, resolved exactly the way stage_jobfiles does.
workload_src_dir() {
    local d="$SCRIPT_DIR/fio-jobfiles/$WORKLOAD"
    [ -d "$d" ] || d="./fio-jobfiles/$WORKLOAD"
    [ -d "$d" ] || die "cannot locate fio-jobfiles/$WORKLOAD"
    printf '%s' "$d"
}

# Turn CUSTOM_SET (or its absence) into a directory of jobfiles to edit and
# run. Every branch checks writability before touching anything, because the
# next step is an editor session the operator should not invest in twice.
resolve_custom_set() {
    local src dst created=0
    src=$(workload_src_dir) || exit 1
    case "$CUSTOM_SET" in
        "")
            # No name: a <date>-<time> set under ./fio-jobfiles, reusable later
            # by that name with -w or -C.
            [ -d "./fio-jobfiles" ] && [ -w "./fio-jobfiles" ] || \
                die "cannot create a custom set: ./fio-jobfiles is not writable here"
            printf -v dst './fio-jobfiles/%(%Y%m%d-%H%M%S)T' -1
            mkdir -p "$dst" || die "cannot create $dst"
            copy_set_into "$src" "$dst"
            created=1; TEMP_SET=1
            ;;
        /*|./*)
            dst=$CUSTOM_SET
            if [ -d "$dst" ]; then
                [ -w "$dst" ] || die "custom set $dst is not writable"
            else
                mkdir -p "$dst" || die "cannot create $dst (missing write permission on its parent?)"
                copy_set_into "$src" "$dst"
                created=1
            fi
            ;;
        *)
            # A bare name that names a SHIPPED set is a request to customize a
            # copy of it, never the set itself -- shipped jobfiles are the
            # tool's checked-in baseline and are only ever edited via a copy.
            case " $SHIPPED_SETS " in
                *" $CUSTOM_SET "*)
                    log "'$CUSTOM_SET' ships with wekatester; customizing a copy of it"
                    WORKLOAD=$CUSTOM_SET
                    src=$(workload_src_dir) || exit 1
                    [ -d "./fio-jobfiles" ] && [ -w "./fio-jobfiles" ] || \
                        die "cannot create a custom set: ./fio-jobfiles is not writable here"
                    printf -v dst './fio-jobfiles/%(%Y%m%d-%H%M%S)T' -1
                    mkdir -p "$dst" || die "cannot create $dst"
                    copy_set_into "$src" "$dst"
                    created=1; TEMP_SET=1
                    SET_DIR_OVERRIDE=$dst
                    log "custom set: $dst"
                    return 0
                    ;;
            esac
            # Bare name: same lookup as -w; created under ./fio-jobfiles when new.
            if [ -d "$SCRIPT_DIR/fio-jobfiles/$CUSTOM_SET" ]; then
                dst="$SCRIPT_DIR/fio-jobfiles/$CUSTOM_SET"
                [ -w "$dst" ] || die "custom set $dst is not writable"
            elif [ -d "./fio-jobfiles/$CUSTOM_SET" ]; then
                dst="./fio-jobfiles/$CUSTOM_SET"
                [ -w "$dst" ] || die "custom set $dst is not writable"
            else
                [ -d "./fio-jobfiles" ] && [ -w "./fio-jobfiles" ] || \
                    die "cannot create a custom set: ./fio-jobfiles is not writable here"
                dst="./fio-jobfiles/$CUSTOM_SET"
                mkdir -p "$dst" || die "cannot create $dst"
                copy_set_into "$src" "$dst"
                created=1
            fi
            ;;
    esac
    # An existing set plus an explicit -w is a request to refresh it from that
    # workload -- destructive to its edits, so it needs a real yes with no
    # timeout, and it never happens on an unattended run. A refresh is a
    # REPLACE: the old jobfiles (including any stale layout job describing
    # geometry that no longer exists) are cleared first, not overlaid.
    if [ "$created" -eq 0 ] && [ "$WORKLOAD_EXPLICIT" -eq 1 ] \
            && [ "$FAST_TRACK" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        if confirm_destructive "replace the jobfiles in $dst with a fresh copy of $WORKLOAD?"; then
            local old
            for old in "$dst"/[0-9]*; do
                [ -f "$old" ] && rm -f "$old"
            done
            copy_set_into "$src" "$dst"
        fi
    fi
    SET_DIR_OVERRIDE=$dst
    log "custom set: $dst"
}

# The guided flow: edit each jobfile, sort out layout per the flag matrix,
# decide the temp set's fate. Interactive parts are skipped wholesale by
# -r (fast track) and -n (dry run).
# -C sets own their host file: copy the one this run resolved (or the
# source set's) into the new set, else start it from the template. The
# set's copy is honored whether or not -t was given -- it IS the set's
# customization surface -- and becomes the file in use from here on:
# edits to engines/cpus/dirs/geometry apply THIS run (phase2 has not
# happened yet, and main re-verifies mounts after the editor closes);
# login edits apply from the NEXT run, since connections are already up.
ensure_set_hostfile() {
    local dst="$SET_DIR_OVERRIDE/hostlist.csv" src=""
    if [ -f "$dst" ]; then
        TARGETS=1; TARGETS_FILE=$dst
        return 0
    fi
    if [ -n "$TARGETS_FILE" ] && [ -f "$TARGETS_FILE" ]; then
        src=$TARGETS_FILE
    elif [ -f "$(workload_src_dir)/hostlist.csv" ]; then
        src="$(workload_src_dir)/hostlist.csv"
    fi
    if [ -n "$src" ]; then
        cp "$src" "$dst" || die "cannot copy host file into $SET_DIR_OVERRIDE"
        log "host file copied into the set: $dst"
    else
        write_targets_template "$dst"
    fi
    TARGETS=1; TARGETS_FILE=$dst
    return 0
}

# The host file -C will use, known BEFORE connecting: the set's own copy
# when the set already has one, else the file customizing will copy into it
# (a shipped set's, or the -w set's) -- ensure_set_hostfile's choice, with
# no side effect. A -C set's host file is honored whether or not -t was
# given, and from the first connection on: its logins and destinations
# apply to this run, not only the next (Frank, 2026-09-29). Empty when
# there is none yet: the set then starts from the template.
custom_set_hostfile_early() {
    [ "$CUSTOMIZE" -eq 1 ] || return 0
    local d src
    d=$(custom_set_probe_dir)
    if [ -n "$d" ] && [ -f "$d/hostlist.csv" ]; then
        printf '%s' "$d/hostlist.csv"
        return 0
    fi
    case " $SHIPPED_SETS " in
        *" $CUSTOM_SET "*)
            src="$SCRIPT_DIR/fio-jobfiles/$CUSTOM_SET"
            [ -d "$src" ] || src="./fio-jobfiles/$CUSTOM_SET" ;;
        *)  src=$(workload_src_dir) || return 0 ;;
    esac
    [ ! -f "$src/hostlist.csv" ] || printf '%s' "$src/hostlist.csv"
}

customize_jobfiles() {
    echo
    resolve_custom_set
    ensure_set_hostfile
    local dst=$SET_DIR_OVERRIDE job f interactive=1 had_layout=0
    if [ "$FAST_TRACK" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then interactive=0; fi

    for f in "$dst"/[0-9]*; do
        if is_layout_file "$f"; then had_layout=1; break; fi
    done

    if [ "$interactive" -eq 1 ]; then
        # The host file is the primary editing surface: one CSV carries
        # per-host login/engine/cpus/destination and per-type geometry --
        # most of what once meant editing every jobfile. The jobfiles stay
        # editable behind the prompt.
        [ ! -f "$dst/hostlist.csv" ] || edit_jobfile "$dst/hostlist.csv"
        if confirm_timed 5 no "edit the jobfiles individually too?"; then
            [ -z "$AUTO_LEVEL" ] || log "note: -a $AUTO_LEVEL will override numjobs/iodepth/ioengine (and filesize/nrfiles/filename_format on iops/latency files) in the staged copies of these jobfiles"
            discover_jobfiles "$dst"
            for job in "${JOBFILES[@]}"; do
                is_layout_file "$dst/$job" && continue   # layout editing is prompted below
                edit_jobfile "$dst/$job"
            done
        fi
    fi

    # Layout, per the flag matrix: -g always regenerates; existing layout is
    # otherwise never touched on unattended runs, and prompted (default: keep)
    # on interactive ones; a set without layout gets one generated silently.
    if [ "$had_layout" -eq 1 ]; then
        if [ "$REGEN_LAYOUT" -eq 1 ]; then
            generate_layout "$dst" "$dst" || die "layout generation failed"
        elif [ "$interactive" -eq 1 ] \
                && confirm_timed 5 no "regenerate the existing layout job(s)?"; then
            generate_layout "$dst" "$dst" || die "layout generation failed"
        fi
    else
        generate_layout "$dst" "$dst" || die "layout generation failed"
    fi

    if [ "$interactive" -eq 1 ]; then
        if confirm_timed 5 no "edit the layout job(s)?"; then
            for f in "$dst"/[0-9]*; do
                is_layout_file "$f" && edit_jobfile "$f"
            done
        fi
        if [ "$TEMP_SET" -eq 1 ]; then
            confirm_timed 5 yes "keep $dst for reuse after the run?" || TEMP_REMOVE=1
        fi
    fi
    return 0
}

# Remove a temp custom set only after a fully successful run: every die() path
# exits before reaching this call, so failed or partial runs always keep the
# files -- the operator's edits survive anything that goes wrong.
finish_temp_set() {
    [ "$TEMP_REMOVE" -eq 1 ] || return 0
    log "removing temporary custom set $SET_DIR_OVERRIDE (not kept for reuse)"
    rm -rf "$SET_DIR_OVERRIDE"
}

# -n: everything is resolved, generated and staged -- print what a real run
# would do and stop. Contents are shown from the master's staged variants,
# which is what fio would actually read.
dry_run_report() {
    local job f line
    echo
    log "dry run: nothing was executed; details of what would have run:"
    if cal_mode; then
        local caldir=${SET_DIR_OVERRIDE:-$(workload_src_dir)} call
        call=""
        ! cal_ladders_once || call=$CAL_LADDERS
        if [ -n "$call" ]; then
            log "-a $AUTO_LEVEL would calibrate before staging: $(printf '%s' "$call" | tr '\n' ',' | sed 's/,$//;s/,/, /g') -- per client shape, each shape solo on its first host; the searches need live fio servers, so a dry run only names the shapes:"
            mkdir -p "$WORK_DIR/cal"
            if cal_shapes_once; then
                while IFS= read -r line; do log "  $line"; done < "$WORK_DIR/cal/shapes.txt"
            else
                log "WARNING: could not group the hosts into shapes" >&2
            fi
        else
            log "-a $AUTO_LEVEL: nothing to calibrate in this set"
        fi
    fi
    if [ -n "$SET_DIR_OVERRIDE" ]; then
        log "custom set files (edit these, then re-run without -n):"
        for f in "$SET_DIR_OVERRIDE"/[0-9]*; do
            [ -f "$f" ] && echo "  $(cd "$(dirname "$f")" && pwd)/${f##*/}"
        done
    fi
    log "workload source: $JOBFILE_SRC"
    log "hosts (${#HOSTS[@]}): ${HOSTS[*]} (master: $MASTER)"
    for job in "${JOBFILES[@]}"; do
        echo
        echo "==== $job (staged variant for $MASTER) ===="
        cat "$WORK_DIR/jobs/$MASTER/$job"
    done
    echo
    [ ${#HOSTS[@]} -le 1 ] || \
        log "one variant per host is staged for ${#HOSTS[@]} hosts (shown: $MASTER's)"
    log "would run, per job in the order above: fio --output-format=json --eta=never --client=<host> $TARGET_DIR/<host>/<job>"
    log "results would land in: $OUTPUT_DIR/<date>-<time>.tgz (fio JSON, wekatester.log, fio-jobfiles/)"
}

# --- phase 3: stage jobfiles ---------------------------------------------------
# Discover the workload's jobfiles, build $WORK_DIR/jobs/<host>/<job> for
# every host, copy the whole tree to $TARGET_DIR on $MASTER -- one scp over the
# existing master connection, or a plain cp when the master is this host.
JOBFILES=()      # basenames, in run order
JOBFILE_SRC=""   # local source directory
SET_DIR=""       # merged view actually staged: source files + generated layout

# Single source of truth for what runs and in what order -- the editor loop
# and the runner must never disagree on either.
discover_jobfiles() {   # discover_jobfiles <dir>; sets JOBFILES in run order
    # byte order, whatever the operator's locale: 021-latencyR.job before its
    # -b twin 021b-latencyR-1M.job (en_US collation ignores the dash and
    # would flip them), the same order every python sort here uses
    local job LC_ALL=C
    JOBFILES=()
    for job in "$1"/[0-9]*; do
        [ -f "$job" ] || die "no jobfiles found in $1"
        JOBFILES+=("${job##*/}")
    done
}

# Build $WORK_DIR/jobs/<host>/<job> for every host. Auto mode delegates to
# the tuner; plain mode copies with the directory override (variants are
# identical across hosts, but one layout = one code path).


stage_variants() {
    local srcdir=$1
    if [ -n "$AUTO_LEVEL" ]; then
        # No rules per level (every level calibrates): staging lays the
        # measured tuples and the host file over the jobfiles, per host.
        # Reads go to the fleet-shared read set wherever the format can
        # address it, because that is what the read cells measured.
        local ns
        ns=$(cal_namespace "$srcdir") \
            || die "cannot derive the calibration namespace from $srcdir"
        WEKATESTER_TIER_LABEL=$AUTO_LEVEL \
        WEKATESTER_NS="$ns" \
        WEKATESTER_IOPS_NOLAT=1 \
        auto_tune "$srcdir" "$WORK_DIR" "$AUTO_LEVEL" "$DIRECTORY" \
            "$IGNORE_CAPACITY" "${WORK_DIR}/targets.final" "${HOSTS[@]}" || die "auto tuning failed"
        return
    fi
    stage_hosts plain "$srcdir" "$DIRECTORY" - - "${HOSTS[@]}" \
        || die "per-host jobfile staging failed"
    # host-file engine (final resolution) applies per host, to every staged
    # file including a re-derived layout; the global -e post-pass in
    # stage_jobfiles still runs after this and wins
    [ -f "$WORK_DIR/targets.final" ] || return 0
    stage_host_engines
}

# -a staging: the jobfiles laid over with what calibration and the host
# file say, per host (stage_hosts auto). Every -a level calibrates (Frank,
# 2026-10-05), so there are no rules per level: the level only labels the
# log and the staged files.
#   auto_tune <src> <work> <tier> <directory> <ignore_capacity 0|1> <targets-final|-> <host>...
# The environment carries the rest: WEKATESTER_TIER_LABEL (the label, else
# <tier>), WEKATESTER_NS (unified...: read-only jobs read the fleet-shared
# set) and WEKATESTER_IOPS_NOLAT=1 (iops jobs run with latency accounting
# off, as their cells did). <ignore_capacity> is checked, not used: the
# capacity check is check_capacity's, for every run.
auto_tune() {
    # Validate the flag slot before using the rest: an old-style call would
    # shift a positional into the host list and drop a host from staging,
    # silently. Wrong quietly is worse than not running.
    if [ $# -lt 7 ] || { [ "$5" != 0 ] && [ "$5" != 1 ]; }; then
        echo "ERROR: auto_tune: usage: <src> <work> <tier> <directory> <ignore_capacity 0|1> <targets-final|-> <host>..." >&2
        return 1
    fi
    local src=$1 work=$2 tier=$3 dir=$4 targets=$6
    shift 6
    WORK_DIR=$work stage_hosts auto "$src" "$dir" "${WEKATESTER_TIER_LABEL:-$tier}" "$targets" "$@"
}

# Per-host staging, one awk for the fleet, in both modes: every jobfile of
# <src> becomes jobs/<host>/<file> with the host's destination and its
# host-file geometry (pick_slot: a single-direction file takes its own slot,
# a mixed file the deeper-queued direction's whole tuple, never a blend).
# Under -a (auto) the variants also carry what calibration measured on:
#   - the cpus: probe_cores' rule, in physical cores -- N/2 and N jobs on
#     one thread per core, more on every thread of those cores (what the
#     cell with that job count ran on); the host file's own list is the base
#     when it gives one, a catch-all counting as none;
#   - in the unified namespace a read-only job reads the fleet-shared set
#     ("shared." + its format): the files the read cells calibrated on;
#   - an engine some host cannot run gives way to the best one every host
#     can, and the host-file engine (calibration's, by then) beats both;
#   - a latency test's one-job twin runs at numjobs=iodepth=nrfiles=1, with
#     the data per job of its calibrated original;
#   - iops jobs run with latency accounting off, as their cells did;
#   - a header naming the level and the cores, and usable/<host> (every
#     thread fio may use there) for the host-file writeback.
# Host-file values land after everything derived: the file beats the tuner,
# per type AND direction. Then the layout: a pristine (never-edited) layout
# is re-derived from each host's staged variants (derive_layouts) -- for
# every host under -a, for the hosts whose geometry the host file changed
# otherwise; an edited one is the operator's word and is kept, with a
# warning. Writes $WORK_DIR/staged.kinds: "J <file>" per job, "L <file>"
# per layout job, "H <host>" per host, "C <host>" per host whose geometry
# the host file changed.
stage_hosts() {   # stage_hosts <plain|auto> <src> <directory> <label|-> <targets|-> <host>...
    local mode=$1 src=$2 dir=$3 label=$4 targets=$5 f files=() dirs=() h kind name changed=() pristine=1
    shift 5
    [ -d "$src" ] || { echo "ERROR: staging: no jobfile set at $src" >&2; return 1; }
    for f in "$src"/[0-9]*; do [ -f "$f" ] && files+=("$f"); done
    for h in "$@"; do dirs+=("$WORK_DIR/jobs/$h"); done
    [ "$mode" = plain ] || dirs+=("$WORK_DIR/usable")
    mkdir -p "${dirs[@]}" || return 1
    # Pristineness is judged on the SOURCE layout, once for the fleet: the
    # staged copies always differ from its sha (the directory override
    # edits them)
    layout_variant_pristine "$src" || pristine=0
    awkrun '
    function warn(msg) { print "WARNING: " msg > "/dev/stderr" }
    function warn_once(msg) {   # per-host loops would otherwise repeat the same warning
        if (!(msg in WARNED)) { WARNED[msg] = 1; warn(msg) }
    }
    function ceil_div(a, b,    c) { c = int(a / b); return c * b < a ? c + 1 : c }
    BEGIN {
        mode = ARGV[1]; work = ARGV[2]; directory = ARGV[3]; label = ARGV[4]; targets = ARGV[5]
        pristine = ARGV[6] == "1"; nf = ARGV[7] + 0; auto = mode == "auto"
        ns_unified = auto && index(ENVIRON["WEKATESTER_NS"], "unified") == 1
        nolat = auto && ENVIRON["WEKATESTER_IOPS_NOLAT"] == "1"
        split("nj fs nr qd", TUPLE, " "); split("numjobs filesize nrfiles iodepth", KNOB, " ")
        # the jobfiles in name order, as the set lists them
        for (a = 1; a <= nf; a++) { NM[a] = ARGV[7 + a]; sub(/.*\//, "", NM[a]); PATHOF[NM[a]] = ARGV[7 + a] }
        sort_arr(NM, nf, 0)
        for (j = 1; j <= nf; j++) {
            if ((n = readlines(PATHOF[NM[j]], L)) < 0) awk_fail("cannot read " PATHOF[NM[j]])
            NL[j] = n
            for (k = 1; k <= n; k++) SL[j, k] = L[k]
            LAY[j] = NM[j] == layout_job() || is_layout_marked(L, n)
        }
        nh = 0
        for (a = 8 + nf; a < ARGC; a++) H[++nh] = ARGV[a]
        # the host rows, the first per host: under -a the file named, else
        # the finished resolution when it exists, the pre-auth phase
        # otherwise -- geometry needs the finished one
        if (auto) { has_final = targets != "-" && targets != ""; n = has_final ? readlines(targets, T) : 0 }
        else {
            has_final = (n = readlines(work "/targets.final", T)) >= 0
            if (!has_final) n = readlines(work "/targets.phase1", T)
        }
        for (i = 1; i <= n; i++) { split(T[i], F, "\t"); if (!(F[1] in ROWS)) ROWS[F[1]] = T[i] }
        if (auto) auto_facts()
        kinds = work "/staged.kinds"
        printf "" > kinds
        for (j = 1; j <= nf; j++) print (LAY[j] ? "L " : "J ") NM[j] > kinds
        for (x = 1; x <= nh; x++) print "H " H[x] > kinds
        for (x = 1; x <= nh; x++) {
            h = H[x]; split("", ROW)
            if (h in ROWS) lsplit(ROWS[h], ROW, "\t")
            if ((HD[h] = row_get(ROW, "dir")) == "") HD[h] = directory
        }
        # job by job, host by host: the order the notes come out in
        for (j = 1; j <= nf; j++)
            for (x = 1; x <= nh; x++) {
                h = H[x]; split("", ROW)
                if ((hr = (h in ROWS))) lsplit(ROWS[h], ROW, "\t")
                if (auto && LAY[j] && pristine) continue   # derive_layouts writes it
                n = NL[j]
                for (k = 1; k <= n; k++) L[k] = SL[j, k]
                # directory= wherever it appears; jobfiles without one get it
                # right after [global], and jobfiles with no [global] at all
                # get the section created at the top -- otherwise fio would
                # silently write to the server cwd
                n = override_lines(L, n, "directory", HD[h])
                if (auto) n = auto_job(j, h, ROW, L, n)
                else if (has_final && hr && !LAY[j] && (kind = job_kind(j)) != "") {
                    file_directions_of(j, D)
                    if ((slot = pick_slot(kind, D, ROW)) != "")
                        for (q = 1; q <= 4; q++) {
                            if ((v = row_get(ROW, slot "_" TUPLE[q])) == "") continue
                            n = override_lines(L, n, KNOB[q], v)
                            GEO[h] = 1
                        }
                }
                writelines(work "/jobs/" h "/" NM[j], L, n)
            }
        for (x = 1; x <= nh; x++) if (GEO[H[x]]) print "C " H[x] > kinds
        close(kinds)
        if (!auto) exit 0
        for (j = 1; j <= nf; j++) {
            if (LAY[j]) continue
            k = job_kind(j)
            print "auto[" label "]: " NM[j] " type=" (k == "" ? "all" : k == "bw" ? "bandwidth" : k == "iops" ? "iops" : "latency")
        }
        for (j = 1; j <= nf; j++) {
            if (!LAY[j]) continue
            if (!pristine) warn_once(NM[j] ": user-edited layout staged as-is; it may not match the auto-tuned geometry (regenerate with -g)")
            print "auto[" label "]: " NM[j] " type=layout"
        }
    }
    # A job type by its report directive, precedence latency > bandwidth >
    # iops: a mixed bandwidth+iops file is measuring bandwidth, so it takes
    # the bandwidth slot and keeps its latency accounting. A 1MiB latency
    # file (a -b twin) is lat1m. "" for no directive: it runs as written.
    function job_kind(j,    n, k, L) {
        n = NL[j]
        for (k = 1; k <= n; k++) L[k] = SL[j, k]
        return report_has(L, n, "latency") ? lat_kind(L, n) : report_has(L, n, "bandwidth") ? "bw" : report_has(L, n, "iops") ? "iops" : ""
    }
    function file_directions_of(j, D,    n, k, L) {
        n = NL[j]
        for (k = 1; k <= n; k++) L[k] = SL[j, k]
        file_directions(L, n, D)
    }
    # The facts -a staging needs, per host: its cpus (probe_cores, the host
    # file list its base), engines and weka cores, with the warnings they
    # raise, in host order; usable/<host> for the writeback.
    function auto_facts(    x, h, np, P, i, F, m, c, S, nodes, WK, ISO, R, PHYS, ALL, base, e, ok, y, NC1, NW1, fleet, v, IS) {
        for (x = 1; x <= nh; x++) {
            h = H[x]
            if ((np = readlines(work "/probe/" h, P)) < 0) awk_fail("cannot read " work "/probe/" h)
            PN[h] = np
            for (i = 1; i <= np; i++) PL[h, i] = P[i]
            NCPU[h] = 0; nodes = 0; split("", WK); ENGS[h] = " "; ISOL[h] = ""
            for (i = 1; i <= np; i++) {
                if (!(m = pysplit(P[i], F))) continue
                if (F[1] == "ncpus") { if ((NCPU[h] = py_int(F[2])) == "") awk_fail("probe: " h ": bad ncpus line: " P[i]) }
                else if (F[1] == "wekanode" && m > 1) nodes = py_int(F[2]) + 0
                else if (F[1] == "isolated" && m > 1) ISOL[h] = F[2]
                else if (F[1] == "weka_allowed") {
                    # weka pins each dedicated io thread to exactly one CPU (a
                    # single-CPU task-level mask); utility threads have wide
                    # masks and float across CPUs. Only single-CPU masks are
                    # dedicated cores -- wide masks must be ignored or the
                    # union of every thread mask collapses to "all CPUs" and
                    # usable cores vanish.
                    if (!parse_cpulist(F[2], S)) awk_fail("probe: bad cpu list on a weka_allowed line: " F[2])
                    if (set_size(S) == 1) for (c in S) WK[c] = 1
                }
                else if (F[1] == "engines") { ENGS[h] = " "; for (y = 2; y <= m; y++) ENGS[h] = ENGS[h] F[y] " " }
            }
            NWEKA[h] = set_size(WK); WEKAL[h] = fmt_cpulist(WK)
            probe_cores(P, np, "", R, PHYS, ALL)
            FN[h] = R["n"]
            if (R["weka_core0"])
                warn(h ": weka has pinned a dedicated core on core 0 -- that core and its sibling belong to the OS; fio stays off it regardless")
            # the pin detection is the only thing keeping fio off weka
            # cores; if weka is running and none were found, say so rather
            # than silently handing fio the whole machine
            if (nodes && !NWEKA[h])
                warn(h ": " nodes " wekanode process(es) running but no pinned cores detected -- fio will be allowed on every cpu, including weka\047s; check that this weka pins its io threads")
        }
        NC1 = ""; NW1 = ""; c = 0; y = 0
        for (x = 1; x <= nh; x++) {
            h = H[x]
            if (x > 1 && NCPU[h] != NCPU[H[1]]) c = 1
            if (x > 1 && NWEKA[h] != NWEKA[H[1]]) y = 1
        }
        if (c) { v = ""; for (x = 1; x <= nh; x++) v = v (x > 1 ? ", " : "") H[x] "=" NCPU[H[x]]; warn("system core counts differ between hosts: " v) }
        if (y) { v = ""; for (x = 1; x <= nh; x++) v = v (x > 1 ? ", " : "") H[x] "=" NWEKA[H[x]]; warn("weka core counts differ between hosts: " v) }
        # the best engine every host can run, in ENGINE_ORDER
        m = split(engine_order(), F, " "); COMMON = ""
        for (i = 1; i <= m && COMMON == ""; i++) {
            ok = 1
            for (x = 1; x <= nh && ok; x++) if (!index(ENGS[H[x]], " " F[i] " ")) ok = 0
            if (ok) COMMON = F[i]
        }
        # the nj contract: the operator cpu list is the base when the file
        # gives one -- minus cpus the host does not have, weka cores and
        # core 0 pair --, and probe_cores own rule over every cpu otherwise,
        # including for a list that covers every cpu fio could use (a
        # catch-all counts as no list)
        for (x = 1; x <= nh; x++) {
            h = H[x]; np = PN[h]
            for (i = 1; i <= np; i++) P[i] = PL[h, i]
            base = ""
            if (h in ROWS) { lsplit(ROWS[h], F, "\t"); base = row_get(F, "cpus") }
            probe_cores(P, np, base, R, PHYS, ALL)
            if (base == "" && R["n"] < 1)
                awk_fail(h ": no cpus left for fio -- " cores_summary(R, PHYS, ALL) "; mount weka with fewer cores, use a larger client, or name the cpus in the host file, fewer than fio could use (a narrower list is the operator\047s own reserve)")
            if (base != "" && R["n"] < 1 && R["catchall"])
                awk_fail(h ": the host file\047s cpu list (" base ") covers every cpu fio could use, which counts as no list, and the OS reserve then leaves fio no cpus -- " cores_summary(R, PHYS, ALL) "; mount weka with fewer cores, use a larger client, or list fewer cpus (a narrower list is the operator\047s own reserve)")
            if (base != "" && R["n"] < 1)
                awk_fail(h ": the host file\047s cpu list (" base ") leaves fio no cpus -- every one is weka\047s, core 0\047s pair, or not on this host")
            CN[h] = R["n"]; CPH[h] = fmt_cpulist(PHYS); CAL[h] = fmt_cpulist(ALL); NALL[h] = set_size(ALL)
            CSUM[h] = cores_summary(R, PHYS, ALL)
            if (ISOL[h] != "" && parse_cpulist(ISOL[h], IS) && set_any(IS)) {
                c = 0; y = 0
                for (v in ALL) if (v in IS) c = 1; else y = 1
                if (c && y) print "note: " h ": fio cpus " CAL[h] " span isolated and housekeeping cpus; per-job split affinity keeps each job on its own cpu" > "/dev/stderr"
            }
        }
        for (x = 1; x <= nh; x++) { v = work "/usable/" H[x]; print CAL[H[x]] > v; close(v) }
        # an engine the jobfile names that some host cannot run gives way
        # to the best one every host can
        for (j = 1; j <= nf; j++) {
            MISSING[j] = 0
            for (k = 1; k <= NL[j]; k++) {
                if ((e = key_value(SL[j, k], "ioengine")) == "") continue
                for (x = 1; x <= nh; x++) if (!index(ENGS[H[x]], " " e " ")) MISSING[j] = 1
            }
        }
    }
    # One job variant for one host under -a, on lines L (directory already
    # set): the new line count. The order of the overrides is the order the
    # lines land in.
    function auto_job(j, h, ROW, L, n,    D, kind, floor, fmt, slot, q, v, cap, nn, fs, nr, b, nj, i, O, no, S0) {
        if (LAY[j]) {
            # an edited layout: staged with corrections only
            return override_lines(L, n, "cpus_allowed", CAL[h])
        }
        # usable is the operator list minus weka pinned cores -- the same
        # effective set the calibration cells were measured on. The host
        # file keeps the list AS WRITTEN; only what executes is declared
        # here, so calibration and measurement cannot disagree.
        n = override_lines(L, n, "cpus_allowed", CAL[h])
        file_directions_of(j, D)
        if (ns_unified && ("read" in D) && !("write" in D)) {
            # a read-only job measures the SHARED dataset: the same files for
            # every client, exactly the files the read cells calibrated on;
            # stamp_unique_names leaves "shared." formats alone
            for (i = 1; i <= NL[j]; i++) S0[i] = SL[j, i]
            fmt = first_value(S0, NL[j], "filename_format")
            n = override_lines(L, n, "filename_format", "shared." (fmt != "" ? fmt : "$jobname.$jobnum.$filenum"))
        }
        if (COMMON != "" && MISSING[j]) n = override_lines(L, n, "ioengine", COMMON)
        kind = job_kind(j)
        floor = 0
        for (i = 1; i <= 3 && i <= NL[j]; i++) if (index(SL[j, i], floor_marker()) == 1) floor = 1
        if (kind != "" && (slot = pick_slot(kind, D, ROW)) != "")
            for (q = 1; q <= 4; q++) {
                if ((v = row_get(ROW, slot "_" TUPLE[q])) == "") continue
                if (q == 1 && v ~ /^[0-9]+$/ && !floor) {
                    # The host file is the operator, so this is honoured.
                    # Past every thread of the usable cores is the 4N rung
                    # of a calibration (two jobs per thread on an SMT host)
                    # and gets a note; past 4N it matches no rung and is
                    # probably stale (seen live on field client B: 52 jobs
                    # in a 46-cpu mask), so it gets the warning.
                    cap = NALL[h]; nn = CN[h]
                    if (v + 0 > 4 * nn)
                        warn_once(h ": host-file " slot "_nj=" v " exceeds 4N (" 4 * nn "; N=" nn " usable physical cores) -- split affinity will run " ceil_div(v + 0, cap) " jobs on some cpus")
                    else if (v + 0 > cap)
                        print "note: " h ": " slot "_nj=" v " runs up to " ceil_div(v + 0, cap) " jobs per cpu (" cap " usable threads)" > "/dev/stderr"
                }
                n = override_lines(L, n, KNOB[q], v)
            }
        if (floor) {
            # the one-job twin of a latency test: one stream per client at
            # numjobs=iodepth=nrfiles=1, with the same data per job as its
            # calibrated original (the calibration floor own geometry)
            fs = slot != "" ? row_get(ROW, slot "_fs") : ""
            nr = slot != "" ? row_get(ROW, slot "_nr") : ""
            n = override_lines(L, n, "numjobs", "1"); n = override_lines(L, n, "iodepth", "1"); n = override_lines(L, n, "nrfiles", "1")
            if (fs != "" && nr ~ /^[0-9]+$/ && (b = parse_size(fs)) != "") {
                v = int(b * nr / 1048576)
                n = override_lines(L, n, "filesize", (v > 1 ? v : 1) "M")
            }
        }
        if ((v = row_get(ROW, "engine")) != "") n = override_lines(L, n, "ioengine", v)
        if (kind == "iops" && nolat) {
            # the iops test records no latency, and its calibration cells
            # measured with the accounting off -- the staged job must run
            # what was measured
            n = override_lines(L, n, "disable_lat", "1"); n = override_lines(L, n, "disable_clat", "1")
            n = override_lines(L, n, "disable_slat", "1"); n = override_lines(L, n, "norandommap", "1")
        }
        # the job count is final now: N/2 and N jobs run one per physical
        # core, more spread over the siblings too -- what the calibration
        # cell with this count ran on
        nj = first_value(L, n, "numjobs")
        n = override_lines(L, n, "cpus_allowed", (nj ~ /^[0-9]+$/ ? nj + 0 : 1) <= CN[h] ? CPH[h] : CAL[h])
        no = 0
        O[++no] = "# generated by wekatester auto[" label "] for " h
        O[++no] = "# usable cores: " CSUM[h] " (of " NCPU[h] " cpus, weka: " (WEKAL[h] != "" ? WEKAL[h] : "none") ")"
        for (i = 1; i <= n; i++) O[++no] = L[i]
        split("", L)
        for (i = 1; i <= no; i++) L[i] = O[i]
        return no
    }' "$mode" "$WORK_DIR" "$dir" "$label" "$targets" "$pristine" ${#files[@]} ${files[@]+"${files[@]}"} "$@" \
        || return 1
    while read -r kind name; do [ "$kind" != C ] || changed+=("$name"); done < "$WORK_DIR/staged.kinds"
    if [ "$mode" = auto ]; then
        [ "$pristine" -eq 0 ] || derive_layouts auto "$label" "$dir" "$@" || return 1
    elif [ ${#changed[@]} -gt 0 ]; then
        # host-file geometry changed these hosts' grids: each layout must
        # describe THAT grid
        if [ "$pristine" -eq 1 ]; then
            derive_layouts plain - "$dir" "${changed[@]}" || return 1
        else
            for h in "${changed[@]}"; do
                log "WARNING: $h: hand-edited layout kept as authored; it may not match the host-file geometry" >&2
            done
        fi
    fi
}

# Each host's layout job(s), re-derived from its STAGED variants
# (staged.kinds names them), so the layout covers what will actually run:
# the numjobs, filesize and nrfiles every job runs there. The rules are
# generate_layout's (lay_add, lay_sections). Under -a the shared read set of a
# filesystem group is laid out ONCE, by its first host's layout, for EVERY
# reader in the group -- hosts of different shapes read it with different
# job counts and the widest decides what must exist; N clients racing to
# create (and the sweep to credit) the same files would be N times the
# work. No sha in the marker: it is re-derived every run, so nothing
# compares it.
derive_layouts() {   # derive_layouts <plain|auto> <label|-> <directory> <host>...
    awkrun 'BEGIN {
        mode = ARGV[1]; label = ARGV[2]; directory = ARGV[3]; work = ARGV[4]
        nh = 0
        for (a = 5; a < ARGC; a++) H[++nh] = ARGV[a]
        if ((n = readlines(work "/staged.kinds", K)) < 0) awk_fail("cannot read " work "/staged.kinds")
        nj = 0; nl = 0
        for (i = 1; i <= n; i++) {
            if (substr(K[i], 1, 2) == "J ") JOB[++nj] = substr(K[i], 3)
            else if (substr(K[i], 1, 2) == "L ") LAYN[++nl] = substr(K[i], 3)
        }
        # plain staging always re-derived the layout job, set or no set
        if (!nl) { if (mode == "auto") exit 0; LAYN[++nl] = layout_job() }
        # the whole fleet groups: a group first member lays out its set
        nall = 0
        for (i = 1; i <= n; i++) if (substr(K[i], 1, 2) == "H ") ALLH[++nall] = substr(K[i], 3)
        fs_groups(work, ALLH, nall, GF, GM)
        for (x = 1; x <= nh; x++) {
            h = H[x]; lay_reset(); hdir = ""
            for (j = 1; j <= nj; j++) {
                p = work "/jobs/" h "/" JOB[j]
                if ((m = readlines(p, V)) < 0) awk_fail("cannot read " p)
                if (hdir == "") hdir = first_value(V, m, "directory")
                lay_engine(V, m)
                if (mode == "auto" && index(first_value(V, m, "filename_format"), "shared.") == 1) {
                    if (GF[h] != h) continue   # its group first lays the set out
                    nr = split(GM[h], RD, " ")
                } else { nr = 1; RD[1] = h }
                for (r = 1; r <= nr; r++) {
                    if (RD[r] == h) { lay_add(V, m, JOB[j], p); continue }
                    q = work "/jobs/" RD[r] "/" JOB[j]
                    if ((mr = readlines(q, RL)) < 0) awk_fail("cannot read " q)
                    lay_add(RL, mr, JOB[j], q)
                }
            }
            nb = 0; split("", B)
            B[++nb] = layout_marker() (mode == "auto" ? " (re-derived by wekatester auto[" label "] from this host\047s tuned variants)" : " (re-derived by wekatester from this host\047s staged variants)")
            B[++nb] = "[global]"
            B[++nb] = "directory=" (hdir != "" ? hdir : directory)
            if (mode == "auto") {
                if (readlines(work "/usable/" h, U) < 1) awk_fail("cannot read " work "/usable/" h)
                B[++nb] = "cpus_allowed=" U[1]
            }
            B[++nb] = "create_serialize=0"
            B[++nb] = "fallocate=none"
            B[++nb] = "ioengine=" pick_engine(LAY_TALLY, LAY_EORD, LAY_NE)
            nb = lay_sections(B, nb)
            for (i = 1; i <= nl; i++) writelines(work "/jobs/" h "/" LAYN[i], B, nb)
        }
    }' "$1" "$2" "$3" "$WORK_DIR" "${@:4}"
}

# Each host's host-file engine (targets.final) onto every one of its staged
# files, as an ioengine= line (override_lines). One awk for the fleet.
stage_host_engines() {
    list_staged "$WORK_DIR/staged.list" || die "per-host engine override failed"
    awkrun 'BEGIN {
        if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
        for (i = 1; i <= n; i++) {   # the first row per host, as targets_field reads it
            split(L[i], F, "\t")
            if (!(F[1] in eng)) eng[F[1]] = F[3]
        }
        if ((m = readlines(ARGV[2], M)) < 0) awk_fail("cannot read " ARGV[2])
        for (i = 1; i <= m; i++) {
            split(M[i], F, "\t")
            e = (F[1] in eng) ? eng[F[1]] : ""
            if (e == "" || e == "-") continue
            if (F[2] == "") awk_fail(F[1] ": no staged jobfiles")
            if ((n = readlines(F[2], L)) < 0) awk_fail("cannot read " F[2])
            n = override_lines(L, n, "ioengine", e)
            writelines(F[2], L, n)
        }
    }' "$WORK_DIR/targets.final" "$WORK_DIR/staged.list" || die "per-host engine override failed"
}

# Every host's staged files, one "<host><tab><path>" line each, hosts in
# order and each host's files in byte order; "<host><tab>" alone for a host
# with no staged directory. The fleet-wide awks read this rather than list
# directories of their own: one process for every host, never one per host.
list_staged() {   # list_staged <outfile>
    local host f LC_ALL=C
    for host in "${HOSTS[@]}"; do
        if [ -d "$WORK_DIR/jobs/$host" ]; then
            for f in "$WORK_DIR/jobs/$host"/*; do
                [ -f "$f" ] || continue
                printf '%s\t%s\n' "$host" "$f"
            done
        else
            printf '%s\t\n' "$host"
        fi
    done > "$1"
}

# Is the layout file in this staged dir still the generated original?
layout_variant_pristine() {   # layout_variant_pristine <dir>
    local f want
    for f in "$1"/[0-9]*; do
        is_layout_file "$f" || continue
        # the digest its marker carries (on one of the first three lines),
        # then the body generate_layout took it over
        awkrun 'BEGIN {
            n = readlines(ARGV[1], L)
            for (i = 1; i <= 3 && i <= n; i++) if ((want = marker_sha(L[i])) != "") break
            if (want == "") exit 1
            print want
            printf "%s", layout_body(L, n)
        }' "$f" | { IFS= read -r want && [ "$(sha256_hex)" = "$want" ]; }
        return
    done
    return 0   # no layout staged yet: nothing to preserve
}

# -u: one final job removes every file the layout created. Derived per host
# from the STAGED layout variant -- the one file guaranteed to name exactly
# the union grid this host laid out, whatever the tier or hand edits did --
# by injecting unlink=1: fio opens each file and unlinks it on completion,
# per client, including the client-prefixed names only fio can reconstruct.
# Every sizing line is rewritten to 4k so a missing or partial grid member
# costs a 4k layout before its unlink, never a full-size rewrite (fio's file
# COUNT and names come from numjobs/nrfiles/format, not size). The layout
# marker line is dropped so the unlink job is never mistaken for a layout
# job and pulled to position one; appending to JOBFILES pins it last.
UNLINK_JOB="999-wekatester-unlink.job"
stage_unlink_variants() {
    is_layout_file "$SET_DIR/${JOBFILES[0]}" \
        || die "no layout job at position one; cannot derive the -u unlink job"
    # one awk for the fleet, every host's from its own staged layout variant
    awkrun 'BEGIN {
        lay = ARGV[1]; unl = ARGV[2]; jobs = ARGV[3]
        for (a = 4; a < ARGC; a++) {
            h = ARGV[a]; src = jobs "/" h "/" lay
            if ((n = readlines(src, L)) < 0)
                awk_fail("no staged layout variant for " h "; cannot derive the -u unlink job")
            m = 0; split("", O)
            for (i = 1; i <= n; i++) {
                if (index(L[i], layout_marker()) == 1) continue
                if (L[i] ~ /^filesize=/ || L[i] ~ /^size=/) O[++m] = "filesize=4k"
                else if (L[i] ~ /^(blocksize|bs)=/) O[++m] = "blocksize=4k"
                else O[++m] = L[i]
            }
            # every section must unlink: a hand-written layout may have no
            # [global] at all, and override_lines creates one then
            m = override_lines(O, m, "unlink", "1")
            writelines(jobs "/" h "/" unl, O, m)
        }
    }' "${JOBFILES[0]}" "$UNLINK_JOB" "$WORK_DIR/jobs" "${HOSTS[@]}" \
        || die "cannot derive the -u unlink job"
    JOBFILES+=("$UNLINK_JOB")
}

# Stamp key=value into a staged variant: replace every existing line, or
# insert into [global] (created if missing) so fio cannot quietly fall back
# to a per-file default. Same three cases as the directory override.
override_variant_key() {   # override_variant_key <file> <key> <value>
    awkrun 'BEGIN {
        if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
        n = override_lines(L, n, ARGV[2], ARGV[3])
        writelines(ARGV[1], L, n)
    }' "$@"
}

# The same for every staged variant of the fleet -- or, with "measured",
# every one that is not a layout job -- in one awk: -e and -x stamp each of
# a few hundred hosts' dozen files, and four processes per file and key
# was minutes at that size.
override_staged() {   # override_staged <all|measured> <key> <value> [<key> <value>]...
    list_staged "$WORK_DIR/staged.list" || return 1
    awkrun 'BEGIN {
        which = ARGV[2]; nk = 0
        for (a = 3; a + 1 < ARGC; a += 2) { K[++nk] = ARGV[a]; V[nk] = ARGV[a + 1] }
        if ((m = readlines(ARGV[1], M)) < 0) awk_fail("cannot read " ARGV[1])
        for (i = 1; i <= m; i++) {
            split(M[i], F, "\t")
            if (F[2] == "") continue
            if ((n = readlines(F[2], L)) < 0) awk_fail("cannot read " F[2])
            if (which == "measured") {
                job = F[2]; sub(/.*\//, "", job)
                if (job == layout_job() || is_layout_marked(L, n)) continue
            }
            for (k = 1; k <= nk; k++) n = override_lines(L, n, K[k], V[k])
            writelines(F[2], L, n)
        }
    }' "$WORK_DIR/staged.list" "$@"
}

# fio in client/server mode silently prefixes generated filenames with its
# own idea of the client's identity (unique_filename, on by default, so
# workers sharing a filesystem cannot clobber each other) -- and the rule
# differs by fio version: 3.28 rewrites the format to "<ip>.$filenum/..."
# (probed live), RHEL8's fio prefixes some sections and not others (seen
# live: layout-1 wrote the plain grid, layout-2 opened 127.0.0.1.1/*).
# Nothing downstream can work against names it cannot predict -- the
# pre-created directory grid, the capacity math, the unlink variant and
# the layout grid sweep all need exact paths. So every staged variant is
# stamped with unique_filename=0 and an explicit "<name>." prefix on its
# filename_format (host_name: the address, or the box's short hostname in
# local mode): the same collision safety, deterministic on every fio.
# A format carrying $clientuid keeps its own uniqueness scheme untouched;
# a jobfile with no format at all gets fio's default grid, host-prefixed.
#
# The same pass stamps the cpu spread. isolcpus cores have NO scheduler
# load balancing: threads affined to a RANGE of isolated cpus never
# migrate off the core they forked on (seen live: all 44 layout workers
# timesharing cpu 4 of "4-15,28-55"). cpus_allowed_policy=split assigns
# each job its own cpu explicitly -- no balancer needed -- and wraps
# cleanly when jobs outnumber cpus (probed on fio 3.28). When the host
# has a pinned cpu list, every variant without its own cpus_allowed gets
# the host's list, and any variant with cpus but no explicit policy gets
# split.
stamp_unique_names() {
    local host cpus args=()
    # one awk for the fleet (was one python per host, ~30ms each, serial):
    # per host its name and the recorded cpu list, "-" for none
    for host in "${HOSTS[@]}"; do
        cpus=""
        [ -z "$AUTH_DIR" ] || [ ! -s "$AUTH_DIR/$host.cpus" ] || IFS= read -r cpus < "$AUTH_DIR/$host.cpus" || :
        host_name_v "$host"
        args+=("$host" "$HOST_NAME" "${cpus:--}")
    done
    [ ${#args[@]} -gt 0 ] || return 0
    list_staged "$WORK_DIR/staged.list" && awkrun '
    function stamp(path, name, cpus,    L, n, O, m, i, k, s, hasfmt, hascpus, haspol, INS, ni, g) {
        if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
        hasfmt = 0
        for (i = 1; i <= n; i++) if (index(strip(L[i]), "filename_format=") == 1) hasfmt = 1
        m = 0
        for (i = 1; i <= n; i++) {
            s = strip(L[i])
            if (index(s, "filename_format=") == 1) {
                if (!index(substr(s, 17), "$clientuid") && index(substr(s, 17), "shared.") != 1)
                    L[i] = "filename_format=" name "." substr(s, 17)
            } else if (index(s, "unique_filename=") == 1)
                continue   # replaced by the forced 0 below
            O[++m] = L[i]
        }
        hascpus = 0; haspol = 0
        for (i = 1; i <= m; i++) {
            s = strip(O[i])
            if (index(s, "cpus_allowed=") == 1) hascpus = 1
            if (index(s, "cpus_allowed_policy=") == 1) haspol = 1
        }
        ni = 0; INS[++ni] = "unique_filename=0"
        if (!hasfmt) INS[++ni] = "filename_format=" name ".$jobname.$jobnum.$filenum"
        if (cpus != "" && !hascpus) { INS[++ni] = "cpus_allowed=" cpus; hascpus = 1 }
        if (hascpus && !haspol) INS[++ni] = "cpus_allowed_policy=split"
        g = 0
        for (i = 1; i <= m && !g; i++) if (strip(O[i]) == "[global]") g = i
        split("", L); n = 0
        if (!g) {
            L[++n] = "[global]"
            for (k = 1; k <= ni; k++) L[++n] = INS[k]
        }
        for (i = 1; i <= m; i++) {
            L[++n] = O[i]
            if (i == g) for (k = 1; k <= ni; k++) L[++n] = INS[k]
        }
        writelines(path, L, n)
    }
    BEGIN {
        for (a = 2; a + 2 < ARGC; a += 3) {
            NAME[ARGV[a]] = ARGV[a + 1]
            CPUS[ARGV[a]] = ARGV[a + 2] == "-" ? "" : ARGV[a + 2]
        }
        if ((m = readlines(ARGV[1], M)) < 0) awk_fail("cannot read " ARGV[1])
        for (i = 1; i <= m; i++) {
            split(M[i], F, "\t")
            if (F[2] == "") awk_fail(F[1] ": no staged jobfiles")
            stamp(F[2], NAME[F[1]], CPUS[F[1]])
        }
    }' "$WORK_DIR/staged.list" "${args[@]}" || die "cannot stamp deterministic filenames"
}

# -b: beside every latency jobfile of the staged set, its 1MiB twin -- the
# same file with every bs=/blocksize= line set to 1Mi (bs=1Mi added to
# [global] when the file has none), named after it so it runs right after it
# and is summarized as a test of its own: 021-latencyR.job gains
# 021b-latencyR-1M.job. The twin keeps the file names and section names, so
# it reads and writes the same dataset the 4k test does and the layout
# covers it unchanged. A latency file already at 1MiB gets no twin. Under -a
# the tuner files the twin under its own geometry slot (lat1m, by its block
# size), which is what -a cal/brutal calibrate for it.
stage_bulk_twins() {   # stage_bulk_twins <set-dir>
    set_entries "$1" || return 1
    awkrun 'BEGIN {
        d = ARGV[1]; nf = 0
        for (a = 2; a < ARGC; a++) {   # "f<name>": a file; "o<name>": taken
            name = substr(ARGV[a], 2); EXISTS[name] = 1
            if (substr(ARGV[a], 1, 1) == "f") FILES[++nf] = name
        }
        made = ""
        for (j = 1; j <= nf; j++) {
            name = FILES[j]
            if (name !~ /^[0-9]/ || name == layout_job()) continue
            if ((n = readlines(d "/" name, L)) < 0) awk_fail("cannot read " d "/" name)
            if (is_layout_marked(L, n) || !report_has(L, n, "latency") || job_bs(L, n) >= 1048576) continue
            match(name, /^[0-9]+/)
            twin = substr(name, 1, RLENGTH) "b" substr(name, RLENGTH + 1)
            twin = twin ~ /\.job$/ ? substr(twin, 1, length(twin) - 4) "-1M.job" : twin "-1M"
            if (twin in EXISTS) awk_fail("-b: the set already has a file named " twin)
            hasbs = 0
            for (i = 1; i <= n; i++)
                if (match(L[i], /^(bs|blocksize)=/)) { L[i] = substr(L[i], 1, RLENGTH) "1Mi"; hasbs = 1 }
            if (!hasbs) n = override_lines(L, n, "bs", "1Mi")
            for (i = n; i >= 1; i--) L[i + 1] = L[i]
            L[1] = "# -b: the 1MiB twin of " name ", staged by wekatester"
            writelines(d "/" twin, L, n + 1)
            EXISTS[twin] = 1
            made = made (made == "" ? "" : " ") twin
        }
        print made
    }' "$1" ${SET_ENTRIES[@]+"${SET_ENTRIES[@]}"}
}

# -a cal/brutal: beside every latency jobfile (the -b twins included), a
# one-job twin, 021-latencyR.job gaining 021-latencyR-1job.job, which sorts
# and so runs right before it. The tuner stages the twin at numjobs=iodepth=
# nrfiles=1 on every client with the same data per job as its original, and
# the original at what the search found: one single-threaded stream's
# latency across the fleet, next to every client's latency at its calibrated
# load. Same files and sections as the original, so the layout covers it.
stage_floor_twins() {   # stage_floor_twins <set-dir>
    set_entries "$1" || return 1
    awkrun 'BEGIN {
        d = ARGV[1]; nf = 0
        for (a = 2; a < ARGC; a++) {   # "f<name>": a file; "o<name>": taken
            name = substr(ARGV[a], 2); EXISTS[name] = 1
            if (substr(ARGV[a], 1, 1) == "f") FILES[++nf] = name
        }
        made = ""
        for (j = 1; j <= nf; j++) {
            name = FILES[j]
            if (name !~ /^[0-9]/ || name == layout_job()) continue
            if ((n = readlines(d "/" name, L)) < 0) awk_fail("cannot read " d "/" name)
            if (is_layout_marked(L, n) || is_floor_marked(L, n) || !report_has(L, n, "latency")) continue
            twin = name ~ /\.job$/ ? substr(name, 1, length(name) - 4) "-1job.job" : name "-1job"
            if (twin in EXISTS) awk_fail("the set already has a file named " twin)
            for (i = n; i >= 1; i--) L[i + 1] = L[i]
            L[1] = floor_marker() " " name " at numjobs=iodepth=nrfiles=1 on every client, staged by wekatester"
            writelines(d "/" twin, L, n + 1)
            EXISTS[twin] = 1
            made = made (made == "" ? "" : " ") twin
        }
        print made
    }' "$1" ${SET_ENTRIES[@]+"${SET_ENTRIES[@]}"}
}

# A set directory as the twin stagers see it, in byte order: "f<name>" for
# each regular file, "o<name>" for anything else there -- a twin may take
# neither name. Into SET_ENTRIES.
SET_ENTRIES=()
set_entries() {   # set_entries <dir>
    local f LC_ALL=C
    SET_ENTRIES=()
    [ -d "$1" ] || { log "ERROR: no set directory $1" >&2; return 1; }
    for f in "$1"/*; do
        if [ -f "$f" ]; then
            SET_ENTRIES+=("f${f##*/}")
        elif [ -e "$f" ]; then
            SET_ENTRIES+=("o${f##*/}")
        fi
    done
}

# libaio sets up numjobs x iodepth kernel aio events per job at start
# (io_queue_init) against fs.aio-max-nr; past the room every further job
# fails with EAGAIN, fio error 11 (field client B, 2026-09-25: 128 of 188 jobs at
# iodepth 512 set up, 60 failed). The planner keeps its own cells inside the
# shape's room, but a staged job can come from elsewhere: a host-file tuple
# recorded when the limit was higher, -e libaio over a tuple another engine
# found, or a jobfile the tuner widened. So once every variant is staged,
# each host's libaio jobs are held against that host's probed room. A
# warning, not a stop: the room is the probe's snapshot, and plain runs
# without -t/-e/-a never probe, so they go unchecked.
check_aio_room() {
    [ -d "$WORK_DIR/probe" ] || return 0
    # one awk for the fleet: per host its probed room, then its staged files
    list_staged "$WORK_DIR/staged.list" && awkrun 'BEGIN {
        if ((m = readlines(ARGV[2], M)) < 0) awk_fail("cannot read " ARGV[2])
        nk = 0; last = ""
        for (i = 1; i <= m; i++) {
            split(M[i], F, "\t")
            if (F[1] != last) {
                last = F[1]
                if ((np = readlines(ARGV[1] "/probe/" last, P)) < 0) np = 0
                room = probe_aio_room(P, np)
            }
            if (room == "" || F[2] == "") continue
            if ((n = readlines(F[2], L)) < 0) awk_fail("cannot read " F[2])
            if ((ev = libaio_events(L, n)) <= room) continue
            job = F[2]; sub(/.*\//, "", job)
            key = job SUBSEP sprintf("%.0f", ev) SUBSEP sprintf("%.0f", room)
            if (!(key in nh)) {   # ordered as python sorts (job, events, room)
                K[++nk] = sprintf("%s\001%020.0f\001%020.0f", job, ev, room)
                KEY[K[nk]] = key; JOB[key] = job; EV[key] = ev; ROOM[key] = room
            }
            if (++nh[key] <= 8) names[key] = names[key] (nh[key] > 1 ? " " : "") last
        }
        sort_arr(K, nk, 0)
        for (i = 1; i <= nk; i++) {
            key = KEY[K[i]]
            printf "ERROR: %s: libaio sets up %.0f aio events at once (numjobs x iodepth) on %s, and the kernel has room for %.0f (fs.aio-max-nr less fs.aio-nr, as probed): the jobs past the room would fail io_queue_init with EAGAIN (fio error 11) -- raise fs.aio-max-nr, run another ioengine (-e or the host file), or lower the job\047s numjobs x iodepth\n", JOB[key], EV[key], names[key] (nh[key] > 8 ? sprintf(" (+%d more)", nh[key] - 8) : ""), ROOM[key] > "/dev/stderr"
        }
        exit (nk ? 2 : 0)
    }' "$WORK_DIR" "$WORK_DIR/staged.list"
    case $? in
        0) ;;
        # stop before anything runs (Frank, 2026-10-02); nothing was written
        2) die "the kernel's aio room would be exceeded (above); nothing was run and the host file is unchanged" ;;
        *) log "WARNING: could not check the staged libaio jobs against the kernel's aio room" >&2 ;;
    esac
}

stage_jobfiles() {
    echo
    # -C already resolved a set to run; otherwise -w names one.
    if [ -n "$SET_DIR_OVERRIDE" ]; then
        JOBFILE_SRC=$SET_DIR_OVERRIDE
    else
        JOBFILE_SRC="$SCRIPT_DIR/fio-jobfiles/$WORKLOAD"
        [ -d "$JOBFILE_SRC" ] || JOBFILE_SRC="./fio-jobfiles/$WORKLOAD"
        [ -d "$JOBFILE_SRC" ] || die "cannot locate fio-jobfiles/$WORKLOAD"
    fi

    discover_jobfiles "$JOBFILE_SRC"

    # The staged view is source files plus a layout job. A set that carries its
    # own layout file keeps it (it sorts first by its 000- prefix); every other
    # set gets one generated transiently -- it never touches the source dir.
    SET_DIR="$WORK_DIR/set"
    mkdir -p "$SET_DIR"
    local job has_layout=0 v
    for job in "${JOBFILES[@]}"; do
        cp "$JOBFILE_SRC/$job" "$SET_DIR/$job"
        is_layout_file "$JOBFILE_SRC/$job" && has_layout=1
    done
    if [ "$BULK" -eq 1 ]; then
        local twins
        twins=$(stage_bulk_twins "$SET_DIR") || die "cannot stage the -b 1MiB latency tests"
        if [ -n "$twins" ]; then
            log "-b: staged the 1MiB latency test(s) $twins beside their 4k originals"
        else
            log "WARNING: -b: this set has no 4k latency test to run at 1MiB" >&2
        fi
    fi
    if cal_mode; then
        local floors
        floors=$(stage_floor_twins "$SET_DIR") || die "cannot stage the one-job latency tests"
        [ -z "$floors" ] || log "cal: staged the one-job latency test(s) $floors: one stream per client at numjobs=iodepth=nrfiles=1, beside each calibrated latency test"
    fi
    if [ "$has_layout" -eq 0 ]; then
        generate_layout "$JOBFILE_SRC" "$SET_DIR" || die "layout generation failed"
    fi
    # the staged view is the list that runs: source files, twins, the layout
    discover_jobfiles "$SET_DIR"
    # The layout job must run FIRST or it is not a barrier: a custom set may
    # carry a marker-detected layout file whose numeric prefix sorts it later,
    # so enforce the order rather than trust the name.
    local reordered=() lay=""
    for job in "${JOBFILES[@]}"; do
        if [ -z "$lay" ] && is_layout_file "$SET_DIR/$job"; then
            lay=$job
        else
            reordered+=("$job")
        fi
    done
    if [ -n "$lay" ] && [ "$lay" != "${JOBFILES[0]}" ]; then
        log "layout job $lay moved to run first (a layout job is only a barrier at position one)"
        JOBFILES=("$lay")
        [ ${#reordered[@]} -eq 0 ] || JOBFILES=("$lay" "${reordered[@]}")
    fi
    log "staging ${#JOBFILES[@]} jobfiles from $JOBFILE_SRC to $MASTER:$TARGET_DIR"

    stage_variants "$SET_DIR"
    if [ -n "$ENGINE" ]; then
        # -e is an explicit operator choice: it beats the jobfiles and the
        # tuner in every staged variant -- including the layout job, and so
        # everything derived from it below (rebuild and unlink variants).
        override_staged all ioengine "$ENGINE" \
            || die "cannot stamp -e $ENGINE into the staged jobfiles"
    fi
    # the engine and every job's geometry are final here
    check_aio_room
    if [ -n "$DURATION" ]; then
        # one duration for every MEASURED job; layout and unlink keep their
        # own timing -- they run to completion, not to a clock
        override_staged measured runtime "$DURATION" time_based 1 \
            || die "cannot stamp -x $DURATION into the staged jobfiles"
    fi
    # after every per-host override, before the derived variants inherit it
    stamp_unique_names
    [ "$UNLINK" -eq 0 ] || stage_unlink_variants
    check_client_cmdline

    # A dry run inspects the staged variants without touching the master.
    [ "$DRY_RUN" -eq 1 ] && return 0
    run_host "$MASTER" "rm -rf '$TARGET_DIR' && mkdir -p '$TARGET_DIR'" \
        || die "cannot create $TARGET_DIR on $MASTER"
    copy_to_master "$WORK_DIR"/jobs/* "$TARGET_DIR/" \
        || die "failed to copy jobfiles to $MASTER"
}

# --- phase 4: run + summarize --------------------------------------------------
# '# report <items>' / '#report <items>' comment lines pick the metrics for a
# jobfile. At least one space after 'report' is required, so a prose comment
# ('# reporting notes...') is not mistaken for a directive; a bare '# report'
# matches nothing and the summarizer falls back to reporting everything.
report_directive() {
    sed -n 's/^#[[:space:]]*report[[:space:]]\{1,\}//p' "$1" | tr '\n' ' '
}

# For each jobfile: run the fio coordinator on $MASTER against all hosts,
# capture JSON locally, hand it to the summarizer. One results file per job
# so a crashed suite keeps everything already measured.
# --- run bundle -----------------------------------------------------------------
# Every run gets $OUTPUT_DIR/<date>-<time>/ holding the fio JSON results, a
# wekatester.log of everything the operator saw, and a snapshot of the staged
# jobfiles. At exit -- success, failure or Ctrl-C alike -- the directory is
# folded into <date>-<time>.tgz and removed; -s reads bundles straight from
# the archive, so nothing needs unpacking to stay inspectable.

# Everything printed from here on is also written to $RUN_DIR/wekatester.log.
# Two fifos + two tees rather than >(process substitution): bash before 5.1
# cannot wait on a substituted process, and finalize must drain the log
# before archiving it. stdout and stderr keep their identities on the console.
TEE_PIDS=()
start_run_log() {
    local p="$WORK_DIR/log"
    mkdir "$p" || die "cannot create log pipe dir $p"
    mkfifo "$p/out" "$p/err" || die "cannot create log pipes in $p"
    tee -a "$RUN_DIR/wekatester.log" < "$p/out" &
    TEE_PIDS+=($!)
    tee -a "$RUN_DIR/wekatester.log" >&2 < "$p/err" &
    TEE_PIDS+=($!)
    # 5/6 keep the real console for finalize to restore (3 is the prompt tty,
    # already closed by the time the run phase starts).
    exec 5>&1 6>&2 >"$p/out" 2>"$p/err"
    debug "logging to $RUN_DIR/wekatester.log"
}

# Per-host system context for the bundle, one file per item under
# sysinfo/<host>/ in the run directory. A run's numbers are only
# interpretable against the box they ran on -- every item below has been
# needed after the fact during a real investigation: kernel cmdline and the
# live isolated set (isolcpus), mounts and df (mount modes, capacity),
# lscpu/numactl (topology), lspci and ip (NIC inventory), free/meminfo
# (RAM, hugepages), uname/os-release (kernel/distro), uptime (load at run
# start), fio --version (3.28 vs 3.42 behavior differences bit twice), and
# weka local ps (client container and version). A missing tool or
# unreadable file records "not available" instead of failing the run.
snapshot_sysinfo() {
    local host i pids=() hs=() cmd
    cmd='for it in cmdline mounts meminfo isolated os-release uname uptime df ip lscpu lspci numactl free; do
        echo "=== WEKATESTER_SYSINFO $it ==="
        case $it in
            (cmdline|mounts|meminfo)
                if [ -r "/proc/$it" ]; then cat "/proc/$it"; else echo "not available"; fi ;;
            (isolated)
                if [ -r /sys/devices/system/cpu/isolated ]; then cat /sys/devices/system/cpu/isolated; else echo "not available"; fi ;;
            (os-release)
                if [ -r /etc/os-release ]; then cat /etc/os-release; else echo "not available"; fi ;;
            (uname)   uname -a ;;
            (uptime)  if command -v uptime  >/dev/null; then uptime;            else echo "not available"; fi ;;
            (df)      if command -v df      >/dev/null; then df -kP;            else echo "not available"; fi ;;
            (ip)      if command -v ip      >/dev/null; then ip -o addr;        else echo "not available"; fi ;;
            (numactl) if command -v numactl >/dev/null; then numactl --hardware; else echo "not available"; fi ;;
            (*)
                if command -v "$it" >/dev/null; then "$it"; else echo "$it: not available"; fi ;;
        esac
    done'
    cmd="$cmd; echo '=== WEKATESTER_SYSINFO fio ==='; \
        '$FIO_BIN' --version 2>&1 || echo 'not available'; \
        echo '=== WEKATESTER_SYSINFO weka ==='; \
        if command -v weka >/dev/null; then weka local ps 2>&1 || true; else echo 'weka: not available'; fi"
    for host in "${HOSTS[@]}"; do
        ( run_host "$host" "$cmd" > "$WORK_DIR/sysinfo.$host" ) &
        pids+=($!); hs+=("$host")
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || log "WARNING: could not capture system info on ${hs[$i]}" >&2
    done
    split_sysinfo "$WORK_DIR/sysinfo." ""
}

# Each host's captured "=== WEKATESTER_SYSINFO <item> ===" sections into
# sysinfo/<host>/<item><suffix> under the run directory: one mkdir and one
# awk for the fleet, each output closed as the next opens.
split_sysinfo() {   # split_sysinfo <capture-file-prefix> <suffix>
    local host dirs=() files=()
    for host in "${HOSTS[@]}"; do
        [ -s "$1$host" ] || continue
        dirs+=("$RUN_DIR/sysinfo/$host"); files+=("$1$host")
    done
    [ ${#files[@]} -gt 0 ] || return 0
    mkdir -p "${dirs[@]}" \
        || { log "WARNING: cannot create the per-host directories under $RUN_DIR/sysinfo" >&2; return 0; }
    WT_ROOT="$RUN_DIR/sysinfo" WT_PFX=$1 WT_SFX=$2 awk '
        FNR == 1 { if (out != "") close(out); out = ""; host = substr(FILENAME, length(ENVIRON["WT_PFX"]) + 1) }
        /^=== WEKATESTER_SYSINFO / { if (out != "") close(out); out = ENVIRON["WT_ROOT"] "/" host "/" $3 ENVIRON["WT_SFX"]; next }
        out != "" { print > out }
    ' "${files[@]}"
}

# Pressure and load, captured TWICE per run -- at start and again as the
# run tears down -- so every bundle carries before/after PSI: sustained
# cpu "some avg10" above a few percent during a run means housekeeping
# tasks were queuing (the pinned fio jobs themselves never queue). The end
# capture also pulls the sar log slice covering the run window when
# sysstat keeps one -- coarse cron samples, but they show the whole box.
PRESSURE_END_DONE=0
snapshot_pressure() {   # snapshot_pressure <start|end>
    [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || return 0
    local label=$1 host i pids=() hs=() cmd sar_s sar_e
    cmd='for f in cpu io memory; do
        echo "=== WEKATESTER_SYSINFO pressure-$f ==="
        if [ -r "/proc/pressure/$f" ]; then cat "/proc/pressure/$f"; else echo "not available"; fi
    done
    echo "=== WEKATESTER_SYSINFO loadavg ==="
    if [ -r /proc/loadavg ]; then cat /proc/loadavg; else echo "not available"; fi'
    if [ "$label" = end ] && [ -n "$RUN_STAMP" ]; then
        # the sar slice for the run window (same-day file; a run crossing
        # midnight gets the tail from 00:00:00 -- sar cannot span files)
        sar_s=${RUN_STAMP#*-}; sar_s=${sar_s:0:2}:${sar_s:2:2}:${sar_s:4:2}
        printf -v sar_e '%(%H:%M:%S)T' -1
        cmd="$cmd
    echo '=== WEKATESTER_SYSINFO sar ==='
    if command -v sar >/dev/null; then sar -A -s '$sar_s' -e '$sar_e' 2>&1 || true; else echo 'sar: not available'; fi"
    fi
    for host in "${HOSTS[@]}"; do
        ( run_host "$host" "$cmd" > "$WORK_DIR/pressure.$label.$host" ) &
        pids+=($!); hs+=("$host")
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || log "WARNING: could not capture pressure ($label) on ${hs[$i]}" >&2
    done
    split_sysinfo "$WORK_DIR/pressure.$label." "-$label"
}

# The bundle must show what actually ran: the per-host staged variants. The
# source set may not exist by the time anyone reads the bundle (-C temp sets
# are removed after a clean run), and auto mode rewrites geometry per host at
# staging -- the variants are the execution truth.
snapshot_jobfiles() {
    mkdir "$RUN_DIR/fio-jobfiles" || die "cannot create $RUN_DIR/fio-jobfiles"
    cp -R "$WORK_DIR/jobs/." "$RUN_DIR/fio-jobfiles/" \
        || die "cannot copy the staged jobfiles into $RUN_DIR/fio-jobfiles"
}

# Compress the run directory to <stamp>.tgz and remove it -- for every run,
# failed and interrupted ones included (-s summarizes the archive directly).
# Runs inside the EXIT trap, after cleanup, so the log also holds the
# teardown messages -- which is why it must never die: a tar failure just
# leaves the directory uncompressed and says so.
finalize_run_dir() {
    [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || return 0
    if [ ${#TEE_PIDS[@]} -gt 0 ]; then
        # Restore the console and let the tees drain: their pipes EOF when
        # these redirected fds close, and only a drained log may be archived.
        exec 1>&5 2>&6 5>&- 6>&-
        wait "${TEE_PIDS[@]}"
        TEE_PIDS=()
    fi
    if tar -czf "$OUTPUT_DIR/$RUN_STAMP.tgz" -C "$OUTPUT_DIR" "$RUN_STAMP"; then
        rm -rf "$RUN_DIR"
        log "run bundle: $OUTPUT_DIR/$RUN_STAMP.tgz"
    else
        log "ERROR: could not compress $RUN_DIR; leaving it uncompressed" >&2
    fi
}

# fio --client exits 0 even when every job on every worker failed (a
# long-standing fio quirk: the client's exit code does not carry worker-side
# job errors), so success has to be read out of the results themselves. Two
# signals: a nonzero per-job "error" field, and -- for measured jobs -- a
# last-entry-per-host (the measured section, same rule the summarizer uses)
# that moved zero bytes and zero ios. Layout jobs skip the second signal:
# create_only stats are legitimately all zeros. A layout failure that somehow
# reports neither signal still cannot slip through the run: the first
# measured job then finds no files and trips the zero-IO check itself.
check_fio_errors() {   # check_fio_errors <results-file> <layout|measured>
    local path=$1 mode=$2
    # always a fresh parse: the file was just written; the reader after
    # this check takes the same lines (json_use)
    json_load "$path"
    case $JSON_RC in
        2) echo "$path: no JSON in fio output" >&2; return 1 ;;
        3) [ -z "$JSON_ERR" ] || echo "$JSON_ERR" >&2
           echo "$path: cannot parse fio JSON" >&2; return 1 ;;
    esac
    local bad
    bad=$(printf '%s\n' "$JSON_FLAT" | LC_ALL=C awk -F'\t' -v mode="$mode" '
        function idx(p,   a) { split(p, a, "."); return a[2] }
        $1 ~ /^client_stats\.[0-9]+\.jobname$/ { job[idx($1)] = $2; order[++n] = idx($1) }
        $1 ~ /^client_stats\.[0-9]+\.hostname$/ { host[idx($1)] = $2 }
        $1 ~ /^client_stats\.[0-9]+\.error$/ { err[idx($1)] = $2 }
        # anything a direction moved -- ios, bytes, or (older fio) only a rate
        $1 ~ /^client_stats\.[0-9]+\.(read|write|trim)\.(total_ios|io_bytes|bw_bytes)$/ { moved[idx($1)] += $2 }
        END {
            for (k = 1; k <= n; k++) {
                i = order[k]
                if (job[i] == "All clients") continue
                stats++
                e = err[i] + 0
                if (e) { h = (i in host) ? host[i] : job[i]; printf "E\t%s\t%s\t%d\n", h, job[i], e; anybad = 1 }
                h = (i in host) ? host[i] : job[i]; last[h] = i; hosts[h] = 1
            }
            if (!stats) { print "NONE"; exit }
            if (mode == "measured" && !anybad)
                for (h in hosts) if (moved[last[h]] + 0 == 0) printf "Z\t%s\n", h | "LC_ALL=C sort"
        }')
    [ "$bad" != NONE ] || { echo "$path: fio returned no per-job stats -- the jobs did not run" >&2; return 1; }
    [ -n "$bad" ] || return 0
    local line kind h job e desc
    while IFS=$'\t' read -r kind h job e; do
        case "$kind" in
            E) desc=$(errno_text "$e"); echo "ERROR: $h: job '$job' error $e${desc:+ ($desc)}" >&2 ;;
            Z) echo "ERROR: $h: measured job moved no data (zero bytes, zero ios)" >&2 ;;
        esac
    done <<<"$bad"
    # fio's own log text precedes the JSON and names the underlying cause:
    # everything before the first "{" (where json_flat starts), wherever on
    # its line that falls, matched without regard to case
    LC_ALL=C awk '
        { p = index($0, "{"); s = p ? substr($0, 1, p - 1) : $0; l = tolower(s) }
        index(l, "error") || index(l, "failed") { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); print "ERROR: " s; if (++n == 3) exit }
        p { exit }' "$path" >&2
    return 1
}

# fio cannot be trusted to create the directory tree a filename_format
# implies: create_on_open never mkdirs at all, and create_only's setup pass
# on fio 3.28 mkdirs only each job's FIRST file's directory (seen live on
# two labs: dir 0 created, every 1/* open ENOENTs with filesetup.c:174).
# So the grid's directories are derived from the staged layout variant and
# made here, before any layout job runs. Flat namespaces derive nothing.
ensure_layout_dirs() {   # ensure_layout_dirs <staged layout jobref>
    local host cmd i pids=() hs=() args=() out="$WORK_DIR/layout-dirs.cmd"
    for host in "${HOSTS[@]}"; do args+=("$host" "$WORK_DIR/jobs/$host/$1"); done
    # every directory each section's filename_format implies under its
    # directory=, a section's own keys over [global]'s; mkdir -p lines
    # of 400, so the remote command stays far below ssh's packet limit.
    # One awk for the fleet -- "<host><tab><command>" for each host that
    # needs any -- not one per host ahead of the fan-out.
    awkrun 'BEGIN {
        for (a = 1; a + 1 < ARGC; a += 2) {
            host = ARGV[a]; path = ARGV[a + 1]
            if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
            split("", KV); split("", SN); split("", seen); split("", D)
            ns = 0; cur = ""   # "": before any section, where keys count for nothing
            for (i = 1; i <= n; i++) {
                line = strip(L[i]); c = substr(line, 1, 1)
                if (line == "" || c == "#" || c == ";") continue
                if (c == "[") {
                    name = substr(line, 2, length(line) - 2)
                    if (name == "global") cur = "g"
                    else { SN[++ns] = name; cur = ns }
                    continue
                }
                if ((p = index(line, "=")) && cur != "")
                    KV[cur, strip(substr(line, 1, p - 1))] = strip(substr(line, p + 1))
            }
            nd = 0
            for (s = 1; s <= ns; s++) {
                name = SN[s]
                fmt = ((s, "filename_format") in KV) ? KV[s, "filename_format"] : KV["g", "filename_format"]
                if (!index(fmt, "/")) continue
                pre = replace_all(substr(fmt, 1, match(fmt, /\/[^\/]*$/) - 1), "$jobname", name)
                nc = 1; C[1] = pre
                for (v = 1; v <= 2; v++) {
                    var = v == 1 ? "$filenum" : "$jobnum"; key = v == 1 ? "nrfiles" : "numjobs"
                    if (!index(pre, var)) continue
                    cnt = ((s, key) in KV) ? KV[s, key] : (("g", key) in KV) ? KV["g", key] : 1
                    if ((cnt = py_int(cnt)) == "") awk_fail("[" name "]: " key " is not a number")
                    m = 0
                    for (j = 1; j <= nc; j++) for (k = 0; k < cnt; k++) C2[++m] = replace_all(C[j], var, k)
                    nc = m
                    for (j = 1; j <= nc; j++) C[j] = C2[j]
                }
                for (j = 1; j <= nc; j++) if (index(C[j], "$")) break
                if (j <= nc) {
                    # the same file on every host says it once, not once per host
                    msg = "WARNING: cannot pre-create directories for [" name "]: unsupported variable in " squote(pre)
                    if (!(msg in said)) { said[msg] = 1; print msg > "/dev/stderr" }
                    continue
                }
                base = ((s, "directory") in KV) ? KV[s, "directory"] : KV["g", "directory"]
                for (j = 1; j <= nc; j++)
                    if (!((d = path_join(base, C[j])) in seen)) { seen[d] = 1; D[++nd] = d }
            }
            sort_arr(D, nd, 0)
            out = ""
            for (i = 1; i <= nd; i++)
                out = out ((i - 1) % 400 ? "" : (i > 1 ? " && " : "") "mkdir -p") " " squote(D[i])
            if (out != "") print host "\t" out
        }
    }' "${args[@]}" > "$out" || die "cannot derive the layout directory set"
    while IFS=$'\t' read -r host cmd; do
        run_host "$host" "$cmd" &
        pids+=($!); hs+=("$host")
    done < "$out"
    # scoped wait, as always: the run-log tees are siblings here
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || die "cannot pre-create layout directories on ${hs[$i]}"
    done
}

# Per-namespace grid facts from a staged layout variant, one line each:
#   <file_bytes>\t<path_glob>\t<maxdepth>\t<expected_total_bytes>
# The glob is the filename_format with every $var wildcarded, rooted at the
# host's destination dir by the caller; maxdepth bounds find to the format's
# own depth so nothing outside the grid is ever touched.
# layout_grid_spec <staged layout jobfile>          -> the spec on stdout
# layout_grid_spec -o <dir> <host> <jobfile>...      -> <dir>/<host>.gridspec
#   per host, one awk for the fleet; stdout names each host whose
#   (non-empty) layout job has no fallocate=none line
layout_grid_spec() {
    awkrun '
    # one layout jobfile: its spec lines into OUT[1..n] (n returned), and
    # FA[1], whether a line reads exactly fallocate=none
    function grid_spec(path, OUT, FA,    L, n, SN, KV, ns, s, fmt, fsz, size, nr, nj, glob, no, i) {
        if ((n = readlines(path, L)) < 0) awk_fail("cannot read " path)
        ns = ini_parse(L, n, SN, KV); no = 0
        for (s = 1; s <= ns; s++) {
            fmt = ini_get(KV, s, "filename_format", ""); fsz = ini_get(KV, s, "filesize", "")
            if (fmt == "" || fsz == "") continue   # nothing statable without both; the fio run still covers it
            if ((size = parse_size(fsz)) == "") awk_fail(path ": [" SN[s] "]: filesize=" fsz " is not a byte count")
            nr = py_int(ini_get(KV, s, "nrfiles", "1")); nj = py_int(ini_get(KV, s, "numjobs", "1"))
            if (nr == "" || nj == "") awk_fail(path ": [" SN[s] "]: nrfiles and numjobs must be numbers")
            fmt = replace_all(fmt, "$jobname", SN[s])
            # a singleton counter is an EXACT path component, not a wildcard:
            # with nrfiles=1 the glob $filenum/* would sweep every sibling
            # directory the OTHER sections of the namespace own (seen live:
            # two same-format sections, 1G x 502 dirs + 10G in dir 0, each
            # deleting the files of the other)
            if (nr == 1) fmt = replace_all(fmt, "$filenum", "0")
            if (nj == 1) fmt = replace_all(fmt, "$jobnum", "0")
            glob = vars_to_glob(fmt)
            OUT[++no] = sprintf("%.0f\t%s\t%d\t%.0f", size, glob, 1 + count_char(glob, "/"), size * nr * nj)
        }
        FA[1] = 0
        for (i = 1; i <= n; i++) if (L[i] == "fallocate=none") FA[1] = 1
        return no
    }
    BEGIN {
        if (ARGV[1] != "-o") {
            no = grid_spec(ARGV[1], OUT, FA)
            for (k = 1; k <= no; k++) print OUT[k]
            exit 0
        }
        for (a = 3; a + 1 < ARGC; a += 2) {
            no = grid_spec(ARGV[a + 1], OUT, FA)
            f = path_join(ARGV[2], ARGV[a] ".gridspec")
            printf "" > f
            for (k = 1; k <= no; k++) print OUT[k] > f
            close(f)
            if (no && !FA[1]) print ARGV[a]
        }
    }' "$@"
}

# Evidence over attestation: the completion markers this replaced trusted a
# flag file that could survive its files (unlink) or bless an interrupted
# heal, and any geometry change invalidated EVERY host's grid wholesale --
# a 502->510 nrfiles bump rewrote 22TiB instead of creating 8 files. The
# sweep stats what actually exists: per namespace, one find deletes every
# file whose SIZE deviates from the grid spec and one find counts the bytes
# that match, so create_only then writes exactly what is missing and the
# capacity check credits what already exists.
#
# Size is the whole test, and that is only sound because the layout job
# sets fallocate=none. fio defaults to fallocate=native on Linux, which
# gives a file its full st_size before any data is written -- a layout
# killed part way then leaves a full-size file of zeros that this sweep
# credits as complete and never rewrites, and the run measures reads of
# nothing. With preallocation off, a partial create leaves a SHORT file,
# which fails the size test and is deleted. A set that ships its OWN
# layout job keeps it (only -g regenerates), so a hand-written layout job
# wants fallocate=none too. Runs before the capacity check; a dry run never mutates,
# so it skips the sweep and prices the full grid.
sweep_layout_grid() {
    [ "$DRY_RUN" -eq 0 ] || return 0
    local lay=${JOBFILES[0]}
    [ -n "$lay" ] && is_layout_file "$SET_DIR/$lay" || return 0
    mkdir -p "$WORK_DIR/probe"
    local host hd spec cmd sz glob depth tot pids hs i args=() nofa
    pids=(); hs=()
    # one awk derives every host's grid (was one per host plus a grep,
    # serial, ahead of a fan-out whose floor is one round trip)
    for host in "${HOSTS[@]}"; do args+=("$host" "$WORK_DIR/jobs/$host/$lay"); done
    nofa=$(layout_grid_spec -o "$WORK_DIR/probe" "${args[@]}") \
        || die "cannot derive the layout grid"
    # the size test below is only sound under fallocate=none (see
    # generate_layout); a kept hand-edited or foreign layout job without
    # it can leave full-size hollow files an interruption would hide
    for host in $nofa; do
        log "WARNING: $host: the staged layout job does not set fallocate=none; an interrupted layout could leave full-size hollow files this sweep would credit as complete" >&2
    done
    load_host_dirs
    for i in "${!HOSTS[@]}"; do
        host=${HOSTS[$i]}
        [ -s "$WORK_DIR/probe/$host.gridspec" ] || continue
        hd=${HOST_DIRS[$i]}
        cmd=""
        while IFS=$'\t' read -r sz glob depth tot; do
            [ -n "$sz" ] || continue
            # sufficiency, not equality: a file LARGER than the grid expects
            # still serves every job (fio reads/writes its first N bytes),
            # so only files SMALLER than expected are deviants. Overlapping
            # same-format sections may each count a shared oversize file;
            # the per-section cap keeps that overcredit at nrfiles x size.
            # The calibration scratch is excluded outright: it lives under
            # $hd too and is KEPT between runs, so a nested-format glob
            # (*/*) would otherwise delete its off-size files and credit
            # its matching ones as laid-out grid bytes.
            cmd="$cmd find \"$hd\" -maxdepth $depth -type f -path \"$hd/$glob\" ! -path \"$hd/$CAL_SCRATCH/*\" ! -size +$((sz - 1))c -delete; \
                 find \"$hd\" -maxdepth $depth -type f -path \"$hd/$glob\" ! -path \"$hd/$CAL_SCRATCH/*\" -size +$((sz - 1))c \
                     | awk -v s=$sz -v t=$tot 'END{v=NR*s; print (v<t)?v:t}'; "
        done < "$WORK_DIR/probe/$host.gridspec"
        [ -n "$cmd" ] || continue
        # pipefail: a dead session must fail the sweep, not hand the awk an
        # empty listing it would total as nothing laid out
        ( set -o pipefail
          run_host "$host" "$cmd" | awk '{t+=$1} END{print t+0}' \
            > "$WORK_DIR/probe/$host.laidout" ) &
        pids+=($!); hs+=("$host")
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || die "layout grid sweep failed on ${hs[$i]}"
    done
}

# The coordinator command line for one job: fio on the master, every
# worker as a "--client=<host> <its jobfile>" pair.
# --eta=never: we never display ETA (output goes to a file), and the
# periodic SEND_ETA polls are how a saturated worker gets DROPPED -- a
# full-rate multi-minute layout write starves the fio server's control
# thread past the poll timeout (seen live: "timeout on cmd SEND_ETA ...
# client timed out" 15 minutes into a 3.3TB relayout).
fio_client_cmd() {   # fio_client_cmd <job> [host...]: every host, or the ones named
    local job=$1 host cmd="${COORD_NOFILE:+ulimit -Sn $COORD_NOFILE && }'$FIO_BIN' --output-format=json --eta=never"
    shift
    [ $# -gt 0 ] || set -- "${HOSTS[@]}"
    for host in "$@"; do
        cmd="$cmd --client=$host '$TARGET_DIR/$host/$job'"
    done
    printf '%s' "$cmd"
}

# The hosts whose staged <job> holds a job section, one per line, in host
# order. A layout variant can hold none: a filesystem-group follower whose
# files are all the group's shared read set, which the group's first host
# lays out, is left a [global] alone -- and fio refuses a jobfile with no
# job in it. Such a host sits the layout (and the -u unlink derived from
# it) out; the coordinator still waits for every host that lays out. A
# variant that cannot be read is kept, so fio says what is wrong with it.
job_clients() {   # job_clients <job>
    awkrun 'BEGIN {
        for (a = 3; a < ARGC; a++) {
            n = readlines(ARGV[1] "/" ARGV[a] "/" ARGV[2], L); has = n < 0
            for (i = 1; i <= n && !has; i++) { s = strip(L[i]); if (s ~ /^\[.+\]$/ && s != "[global]") has = 1 }
            if (has) print ARGV[a]
        }
    }' "$WORK_DIR/jobs" "$1" "${HOSTS[@]}"
}

# That command line grows with the fleet, and the master's shell receives
# the whole of it as ONE argument (ssh hands the remote command over as a
# single string; local mode runs it through bash -c). Linux caps one
# argument at MAX_ARG_STRLEN = 128 KiB, and the failure would be an E2BIG
# from the master's shell -- after the layout had already been staged. At
# ~65 bytes plus twice the host name per pair that is roughly 1,100 workers
# of 25-character names, or 700 of 60-character FQDNs. Checked at staging
# with 8 KiB of headroom for the fio options, so a dry run reports it too.
CLIENT_CMD_MAX=122880
check_client_cmdline() {   # check_client_cmdline [what]
    local job cmd n longest=0 worst=""
    for job in "${JOBFILES[@]}"; do
        cmd=$(fio_client_cmd "$job")
        n=${#cmd}
        [ "$n" -le "$longest" ] || { longest=$n; worst=$job; }
    done
    [ "$longest" -gt "$CLIENT_CMD_MAX" ] || return 0
    die "${1:-the fio command line for $worst} is $longest bytes with ${#HOSTS[@]} hosts; the master's shell takes it as one argument, which Linux caps at 128 KiB (MAX_ARG_STRLEN) -- run the fleet as two or more host lists"
}

# The same ceiling before anything starts on the hosts -- the probe's
# engine tests, the fio servers, a calibration that can run for an hour:
# staging only knows the real names afterwards, so this prices the longest
# one it can produce, a set jobfile's name plus the 9 bytes its longest twin
# adds ("021-latencyR.job" -> "021b-latencyR-1M-1job.job"), and never less
# than the 25-byte layout and unlink names. Staging checks again.
early_client_cmdline_check() {
    local f n max=25 JOBFILES
    for f in "${SET_DIR_OVERRIDE:-$(workload_src_dir)}"/*.job; do
        [ -f "$f" ] || continue
        n=${f##*/}; n=$(( ${#n} + 9 ))
        [ "$n" -le "$max" ] || max=$n
    done
    JOBFILES=("$(printf '%*s' "$max" '' | tr ' ' x)")
    check_client_cmdline "the fio command line for the longest job name this set can stage"
}

run_jobs() {
    local job outfile report cmd host t0 lclients=()
    echo
    for job in "${JOBFILES[@]}"; do
        cmd=$(fio_client_cmd "$job")
        # No timestamp in the name: the run directory carries it, and the
        # bundle keeps runs apart better than a filename infix ever did.
        outfile="$RUN_DIR/results_${job%.job}.json"
        if is_layout_file "$SET_DIR/$job"; then
            # The layout job is a barrier, not a measurement: its stats are
            # create-phase zeros, so it gets a duration instead of a summary.
            # The verify sweep already ran at staging (sweep_layout_grid):
            # size-deviant files are gone, complete files remain -- so this
            # plain create_only pass writes exactly the missing files and
            # skips the rest. No markers, no wholesale rebuilds: evidence
            # decided per file.
            ensure_layout_dirs "$job"
            mapfile -t lclients < <(job_clients "$job")
            if [ ${#lclients[@]} -eq 0 ]; then
                log "layout: nothing to lay out ($job)"
                echo
                continue
            fi
            [ ${#lclients[@]} -eq ${#HOSTS[@]} ] \
                || log "layout: $(( ${#HOSTS[@]} - ${#lclients[@]} )) host(s) have nothing of their own to lay out (their group's first host lays out the shared read set)"
            cmd=$(fio_client_cmd "$job" "${lclients[@]}")
            log "laying out files ($job) on ${#lclients[@]} host(s)..."
            t0=$SECONDS
            run_host "$MASTER" "$cmd" > "$outfile" \
                || die "layout failed for $job (partial output in $outfile)"
            if ! check_fio_errors "$outfile" layout; then
                for host in "${lclients[@]}"; do
                    fio_parse_postmortem layout "$host" "$TARGET_DIR/$host/$job" \
                        "$RUN_DIR/parse.${job%.job}.$host.out"
                done
                die "layout $job failed -- the files were not created (raw output in $outfile)"
            fi
            log "layout: complete in $((SECONDS - t0))s across ${#lclients[@]} host(s)"
            echo
            continue
        fi
        if [ "$job" = "$UNLINK_JOB" ]; then
            # Cleanup, not measurement: error-checked like a layout job (its
            # stats are open/unlink zeros), timed instead of summarized.
            mapfile -t lclients < <(job_clients "$job")
            if [ ${#lclients[@]} -eq 0 ]; then
                log "unlink: nothing to remove ($job)"
                echo
                continue
            fi
            cmd=$(fio_client_cmd "$job" "${lclients[@]}")
            log "removing test files ($job) on ${#lclients[@]} host(s)..."
            t0=$SECONDS
            run_host "$MASTER" "$cmd" > "$outfile" \
                || die "unlink failed for $job (partial output in $outfile)"
            check_fio_errors "$outfile" layout \
                || die "unlink $job failed -- test files may remain (raw output in $outfile)"
            log "unlink: test files removed in $((SECONDS - t0))s across ${#lclients[@]} host(s)"
            echo
            continue
        fi
        report=$(report_directive "$SET_DIR/$job")
        log "starting test run for job $job on $MASTER with ${#HOSTS[@]} workers:"
        debug "running on $MASTER: $cmd"
        run_host "$MASTER" "$cmd" > "$outfile" \
            || die "fio run failed for $job (partial output in $outfile)"
        check_fio_errors "$outfile" measured \
            || die "job $job failed on at least one host (raw output in $outfile)"
        # Expected-host guard. Assumption: fio keys each client_stats entry by
        # the name we passed to --client=, not by the worker's own hostname
        # (lab evidence: a multi-host run keys per_host by backend-N while
        # `hostname` there returns the long FQDN form). Local mode rides the
        # same rule -- --client=localhost reports as "localhost" -- so it needs
        # no special case here. The lab gate re-verifies both.
        summarize "$outfile" "$report" "${HOSTS[*]}"
    done
    log "raw fio results: $RUN_DIR/"
    echo
}

# Parse fio JSON results and print the human summary.
# $1 = a results .json file, or a run-bundle .tgz: every results file inside
#      the bundle is summarized in job order, read straight from the archive
#      extracted once to a temp dir that is removed afterwards.
# $2 = report items ("bandwidth iops latency"; empty = all)
# $3 = expected hosts (space-separated; empty = don't check, e.g. -s mode)
summarize() {
    summarize_report "$1" "$2" "${3:-}" || die "failed to summarize $1"
}

summarize_report() {   # summarize_report <path> <items> <expected>
    local path=$1 items=${2:-} expected=${3:-} tmp list
    [ -n "$items" ] || items="bandwidth latency iops"
    # a run bundle is an archive that lists entries: bsdtar takes an empty
    # file for an empty archive, and that is a results file with no JSON
    if [ -s "$path" ] && list=$(tar -tf "$path" 2>&1) && [ -n "$list" ]; then
        tmp=$(mktemp -d "${TMPDIR:-/tmp}/wt.summ.XXXXXX") || return 1
        tar -xf "$path" -C "$tmp" 2> "$tmp/tar.err" || { echo "cannot extract $path" >&2; rm -rf "${tmp:?}"; return 1; }
        local f job skip results
        # layout results are barriers, not measurements: the reserved names,
        # plus any bundled jobfile that carries the layout marker (/dev/null
        # keeps awk off stdin when there is no jobfile at all)
        skip=" ${LAYOUT_JOB%.job} 000-wekatester-relayout ${UNLINK_JOB%.job} "
        skip="$skip$(find "$tmp" -path '*/fio-jobfiles/*' -name '*.job' -type f -print0 \
            | xargs -0 env LC_ALL=C awk -v m="$LAYOUT_MARKER" 'FNR <= 3 && index($0, m) == 1 && !(FILENAME in d) { d[FILENAME] = 1; n = split(FILENAME, p, "/"); sub(/\.job$/, "", p[n]); printf "%s ", p[n] }' /dev/null) "
        results=$(find "$tmp" -name 'results_*.json' -type f | LC_ALL=C awk -F/ '{print $NF "\t" $0}' | LC_ALL=C sort | cut -f2-)
        [ -n "$results" ] || { echo "$path: no results_*.json files in the bundle" >&2; rm -rf "${tmp:?}"; return 1; }
        while IFS= read -r f; do
            job=${f##*/}; job=${job#results_}; job=${job%.json}
            case "$skip" in *" $job "*) continue ;; esac
            echo "==== $job ===="
            summ_one "$f" "${f##*/}" "$items" "" bundle
        done <<<"$results"
        rm -rf "${tmp:?}"; return 0
    fi
    summ_one "$path" "$path" "$items" "$expected" file
}

# summ_one <file> <label> <items> <expected> <file|bundle>: the report for one
# results file. In file mode an error goes to stderr and returns 1; in a
# bundle it prints as "    (reason)" and the next file still gets reported.
summ_one() {
    local f=$1 label=$2 items=$3 expected=$4 mode=$5 out
    json_use "$f"
    case $JSON_RC in
        2) out="ERR	$label: no JSON in fio output" ;;
        3) out="ERR	$label: cannot parse fio JSON: ${JSON_ERR#json: }" ;;
        *) out=$(printf '%s\n' "$JSON_FLAT" | LC_ALL=C awk -F'\t' -v label="$label" -v items=" $items " -v expected="$expected" '
        function idx(p,   a) { split(p, a, "."); return a[2] }
        function key(p,   a, n, k, j) { n = split(p, a, "."); k = a[3]; for (j = 4; j <= n; j++) k = k "." a[j]; return k }
        function fb(n) { if (n >= 2^40) return sprintf("%.2f TiB/s", n / 2^40); if (n >= 2^30) return sprintf("%.2f GiB/s", n / 2^30)
                         if (n >= 2^20) return sprintf("%.2f MiB/s", n / 2^20); if (n >= 2^10) return sprintf("%.2f KiB/s", n / 2^10); return sprintf("%.0f bytes/s", n) }
        function fl(ns) { if (ns >= 1e9) return sprintf("%.1f s", ns / 1e9); if (ns >= 1e6) return sprintf("%.1f ms", ns / 1e6)
                          if (ns >= 1e3) return sprintf("%.1f us", ns / 1e3); return sprintf("%.0f ns", ns) }
        function fi(n,   s, r) { s = sprintf("%.0f", n); r = ""; while (length(s) > 3) { r = "," substr(s, length(s) - 2) r; s = substr(s, 1, length(s) - 3) } return s r "/s" }
        # a value the report needs; the FIRST one missing names the layout
        # error, as the python KeyError did: the direction when it is absent
        # altogether, else the leaf key
        function val(i, k,   kk, n) {
            if ((i "." k) in has) return v[i "." k]
            if (missing == "") { n = split(k, kk, "."); missing = ((i "." kk[1]) in dirhas) ? kk[n] : kk[1] }
            return 0 }
        # per-host min and max of metric m ("bw", "iops", "lat.read", "lat.write"), when they differ
        function spread(m, kind,   h, x, lo, hi, loh, hih, first) {
            if (nh < 2) return ""
            first = 1
            for (h in hosts) {
                i = last[h]
                if (m == "bw") x = val(i, "read.bw_bytes") + val(i, "write.bw_bytes")
                else if (m == "iops") x = val(i, "read.iops") + val(i, "write.iops")
                else x = val(i, substr(m, 5) ".lat_ns.mean")
                if (first || x < lo || (x == lo && h < loh)) { lo = x; loh = h }
                if (first || x > hi || (x == hi && h > hih)) { hi = x; hih = h }
                first = 0
            }
            if (lo == hi) return ""
            if (kind == "bw") return "  (min " fb(lo) " " loh ", max " fb(hi) " " hih ")"
            if (kind == "iops") return "  (min " fi(lo) " " loh ", max " fi(hi) " " hih ")"
            return "  (min " fl(lo) " " loh ", max " fl(hi) " " hih ")"
        }
        $1 ~ /^client_stats\.[0-9]+\./ {
            i = idx($1); k = key($1)
            if (i > maxi) maxi = i
            if (k == "jobname") job[i] = $2
            else if (k == "hostname") host[i] = $2
            else { v[i "." k] = $2 + 0; has[i "." k] = 1; split(k, kk, "."); dirhas[i "." kk[1]] = 1 }
            seen[i] = 1
        }
        END {
            for (i = 0; i <= maxi; i++) {
                if (!(i in seen)) continue
                if (job[i] == "All clients") { alls = i; hasall = 1; continue }
                h = (i in host) ? host[i] : ((i in job) ? job[i] : "?")
                if (!(h in hosts)) { hosts[h] = 1; nh++ }
                last[h] = i
            }
            if (!hasall) {
                if (nh == 1) { for (h in hosts) alls = last[h] }
                else { printf "ERR\t%s: no %sAll clients%s aggregate found\n", label, "\047", "\047"; exit }
            }
            if (expected != "") {
                n = split(expected, ex, " "); miss = ""; nm = 0
                for (j = 1; j <= n; j++) if (ex[j] != "" && !(ex[j] in hosts)) { miss = miss (nm ? ", " : "") ex[j]; nm++ }
                if (nm) { printf "ERR\t%s: no results from %d of %d host(s): %s\n", label, nm, n, miss; exit }
            }
            nl = 0; missing = ""
            if (index(items, " bandwidth ")) {
                r = val(alls, "read.bw_bytes"); w = val(alls, "write.bw_bytes")
                if (r) L[++nl] = "read bandwidth: " fb(r)
                if (w) L[++nl] = "write bandwidth: " fb(w)
                if (r && w) L[++nl] = "total bandwidth: " fb(r + w)
                if (r || w) L[++nl] = "average bandwidth: " fb(nh ? (r + w) / nh : 0) " per host" spread("bw", "bw")
            }
            if (index(items, " iops ")) {
                r = val(alls, "read.iops"); w = val(alls, "write.iops")
                if (r) L[++nl] = "read iops: " fi(r)
                if (w) L[++nl] = "write iops: " fi(w)
                if (r && w) L[++nl] = "total iops: " fi(r + w)
                if (r || w) L[++nl] = "average iops: " fi(nh ? (r + w) / nh : 0) " per host" spread("iops", "iops")
            }
            if (index(items, " latency ")) {
                rl = val(alls, "read.lat_ns.mean"); if (rl) L[++nl] = "read latency: " fl(rl) spread("lat.read", "lat")
                wl = val(alls, "write.lat_ns.mean"); if (wl) L[++nl] = "write latency: " fl(wl) spread("lat.write", "lat")
                ri = val(alls, "read.total_ios"); wi = val(alls, "write.total_ios")
                if (rl && wl && (ri + wi)) L[++nl] = "average latency: " fl((rl * ri + wl * wi) / (ri + wi)) " (IO-weighted)"
            }
            if (missing != "") { printf "ERR\t%s: not the fio JSON layout this summary reads: KeyError(%s%s%s)\n", label, "\047", missing, "\047"; exit }
            if (!nl) L[++nl] = "(no non-zero metrics to report)"
            for (j = 1; j <= nl; j++) print "    " L[j]
        }') ;;
    esac
    case "$out" in
        "ERR	"*)
            if [ "$mode" = bundle ]; then printf '    (%s)\n\n' "${out#ERR	}"; return 0; fi
            printf '%s\n' "${out#ERR	}" >&2; return 1 ;;
    esac
    printf '%s\n\n' "$out"
}

# --- main ----------------------------------------------------------------------
main() {
    # -s: offline re-summarize of an existing results file, no hosts involved
    if [ -n "$SUMMARIZE_FILE" ]; then
        [ -f "$SUMMARIZE_FILE" ] || die "no such file: $SUMMARIZE_FILE"
        summarize "$SUMMARIZE_FILE" ""
        exit 0
    fi

    # A Linux controller: /dev/shm staging, findmnt, GNU userland (-s above
    # reads a bundle anywhere). Plain `uname`, PATH-resolved so the suite can
    # stub it.
    [ "$(uname -s)" = Linux ] \
        || die "wekatester runs on a Linux controller, not $(uname -s); -s summarizes a run bundle anywhere"
    resolve_local_mode
    # -i entries are split and their key paths checked here, before the
    # staging dir exists and long before the first connection: a bad key path
    # costs nothing to report and leaves nothing behind.
    validate_credentials
    # python runs only the calibration planner and the tuner: -a's
    [ -z "$AUTO_LEVEL" ] || command -v python3 >/dev/null \
        || die "python3 is required for -a (the calibration planner and the tuner)"
    # -C's editors and prompts need a terminal; a missing one (or a bogus
    # $EDITOR) costs nothing to report now and everything to discover after
    # ten minutes of setup. Unattended forms (-r, -n) skip the terminal.
    if [ "$CUSTOMIZE" -eq 1 ] && [ "$FAST_TRACK" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        require_interactive "-C"
        resolve_editor
    fi

    log "wekatester $VERSION: ${#HOSTS[@]} worker(s), master $MASTER, workload $WORKLOAD"
    echo

    WORK_DIR=$(mktemp -d "$STAGE_BASE/wt.XXXXXX") || die "cannot create staging dir in $STAGE_BASE"
    make_ctrl_dir
    mkdir -p "$WORK_DIR/jobs"
    # multiplex every ssh/scp in this run over one connection per host.
    # %C hashes host/port/user into a short, safe socket name. Local mode never
    # runs ssh, so there is nothing to multiplex -- and cleanup's socket loop
    # already no-ops on the empty socket dir. The masters persist for the
    # WHOLE run (cleanup's explicit -O exit loop is their teardown): a worker
    # idle past a short persist window would reconnect mid-run -- slow with
    # keys, impossible with -p once the prompt machinery is gone. Kept apart
    # from SSH_OPTS because hosts riding a pre-existing user-owned master get
    # SSH_OPTS but NOT these (host_ssh_opts decides per host).
    [ "$LOCAL_MODE" -eq 1 ] || \
        CONTROL_OPTS="-o ControlMaster=auto -o ControlPath=$CTRL_DIR/%C -o ControlPersist=yes"

    # A bare `trap cleanup INT TERM` runs cleanup and then RESUMES at the next
    # statement, so a Ctrl-C would tear the run down and keep going. Signals
    # exit instead, and the single EXIT trap is the only place cleanup runs
    # (it is idempotent anyway) while preserving the exit status. The bundle
    # is finalized here, after cleanup, so its log holds the teardown too --
    # for every outcome: failed and interrupted runs compress the same way,
    # and -s reads the archive directly so nothing is lost to the fold.
    trap 'rc=$?; cleanup; finalize_run_dir; exit $rc' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # After the traps: half-established masters must still get cleanup's
    # -O exit teardown (which only ever touches OUR socket dir -- masters it
    # did not create are left in place). Before preflight: every later ssh
    # rides the winning credential's session and never sees an auth prompt.
    # Host file (-t): resolve which file applies and compute the pre-auth
    # phase (logins, dirs) -- the auth rounds consume per-host logins from it.
    if [ "$TARGETS" -eq 1 ]; then
        resolve_targets_file
        # empty = the -C defer case: the set's file does not exist yet;
        # the post-customize phase1 refresh picks it up once created
        if [ -n "$TARGETS_FILE" ]; then
            resolve_targets phase1 "$TARGETS_FILE" "${ENGINE:--}" \
                "$([ "$DIRECTORY_EXPLICIT" -eq 1 ] && printf '%s' "$DIRECTORY" || printf -- -)" \
                - "${HOSTS[@]}" > "$WORK_DIR/targets.phase1" \
                || die "host file resolution failed ($TARGETS_FILE)"
        fi
    elif [ "$CUSTOMIZE" -eq 1 ]; then
        # -C without -t: the set's host file is honored as if -t named it,
        # so its logins and destinations reach the connections and the
        # mount check below; customizing then adopts the set's own copy
        local early
        early=$(custom_set_hostfile_early)
        if [ -n "$early" ]; then
            log "host file (the -C set's): $early"
            resolve_targets phase1 "$early" "${ENGINE:--}" \
                "$([ "$DIRECTORY_EXPLICIT" -eq 1 ] && printf '%s' "$DIRECTORY" || printf -- -)" \
                - "${HOSTS[@]}" > "$WORK_DIR/targets.phase1" \
                || die "host file resolution failed ($early)"
        fi
    fi
    check_controller_procs
    [ "$LOCAL_MODE" -eq 1 ] || establish_connections
    preflight
    verify_mount_mode
    # The customize flow sits after host validation (no editing time invested
    # against a broken cluster) and before any daemon exists (nothing to tear
    # down while an editor sits open). The prompt fd closes before the run so
    # no child inherits a readable terminal.
    if [ "$CUSTOMIZE" -eq 1 ]; then
        customize_jobfiles
        # The set's host file just became (or was edited as) the active
        # targets file: refresh the pre-auth resolution and re-verify the
        # mounts, since per-host destinations may have changed. Login edits
        # cannot apply here -- connections are already up; next run.
        resolve_targets phase1 "$TARGETS_FILE" "${ENGINE:--}" \
            "$([ "$DIRECTORY_EXPLICIT" -eq 1 ] && printf '%s' "$DIRECTORY" || printf -- -)" \
            - "${HOSTS[@]}" > "$WORK_DIR/targets.phase1" \
            || die "host file resolution failed ($TARGETS_FILE)"
        verify_mount_mode
    fi
    # Unconditional: -p, a -t host file created on the way, and a destination
    # created by the mount pass open the prompt fd too, not only -C.
    close_interactive
    early_client_cmdline_check
    if [ "$DRY_RUN" -eq 1 ]; then
        # every run probes: only the probe knows where weka's pinned cores
        # are, and fio never lands on them (Frank, 2026-09-29)
        probe_workers
        check_coordinator_limits
        if [ -n "$AUTO_LEVEL" ] || [ "$TARGETS" -eq 1 ] || [ -n "$ENGINE" ]; then
            test_engines
            finalize_targets
        fi
        # what the real run would pin (or die on) -- local set arithmetic
        # on the probe, no remote command
        check_cpu_pinning
        collect_fs_groups
        cal_preflight
        stage_jobfiles
        sweep_layout_grid   # self-gated: a dry run never mutates
        check_capacity
        dry_run_report
        exit 0
    fi
    # After the dry-run exit on purpose: -n predicts the bundle location
    # without creating it. Checked before any daemon starts so an unwritable
    # -o cannot kill the run after the benchmark already burned its minutes.
    mkdir -p -- "$OUTPUT_DIR" || die "cannot create output directory $OUTPUT_DIR"
    [ -w "$OUTPUT_DIR" ] || die "output directory $OUTPUT_DIR is not writable"
    printf -v RUN_STAMP '%(%Y%m%d-%H%M%S)T' -1
    RUN_DIR="$OUTPUT_DIR/$RUN_STAMP"
    mkdir "$RUN_DIR" || die "cannot create run directory $RUN_DIR"
    start_run_log
    replay_prerun_warnings
    snapshot_sysinfo
    snapshot_pressure start
    # every run probes and pins: only the probe knows where weka's pinned
    # cores are, and fio never lands on them (Frank, 2026-09-29)
    probe_workers
    check_coordinator_limits
    if [ -n "$AUTO_LEVEL" ] || [ "$TARGETS" -eq 1 ] || [ -n "$ENGINE" ]; then
        test_engines
        finalize_targets
    fi
    check_cpu_pinning
    # every check but capacity has passed: who shares a destination
    collect_fs_groups
    cal_preflight
    start_fio_servers
    verify_fio_ports
    calibrate
    stage_jobfiles
    sweep_layout_grid
    check_capacity
    writeback_targets
    snapshot_jobfiles
    run_jobs
    [ "$CAL_UNLINK_PENDING" -eq 0 ] || cal_remove_dataset
    finish_temp_set
}

# run only when executed, not when sourced (tests source this file)
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    parse_args "$@"
    main
fi
