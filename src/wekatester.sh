#!/usr/bin/env bash
#
# wekatester - performance test a network/parallel filesystem with distributed fio
#
# Shell rewrite. Orchestration uses the system OpenSSH binary, so agent
# forwarding, certificates, ProxyJump, and ~/.ssh/config behave exactly as
# they do for interactive ssh. Connections are multiplexed over ControlMaster
# sockets: one TCP+auth handshake per host for the whole run. Result parsing
# is delegated to embedded python3 (stdlib only). No installable dependencies.
#
# With no server on the command line the same orchestration runs against the
# local host with the transport swapped for direct execution (see run_host):
# fio still runs client/server, over loopback, so no sshd is needed at all.
#
# All transient staging (jobfiles, control sockets, remote jobfile copies,
# fio pidfiles) lives in tmpfs (/dev/shm), never on disk. The only files
# written to disk are the results_*.json outputs in the output directory
# (./results by default, -o/--output to choose another).

VERSION="2026-09-09"

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

# local staging: prefer tmpfs; fall back for non-Linux (e.g. macOS) dev boxes
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
    STAGE_BASE=/dev/shm
else
    STAGE_BASE=${TMPDIR:-/tmp}
fi

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
log()   { echo "$(date '+%H:%M:%S') $*"; }
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
        printf ' -o User=%s' "$(cat "$AUTH_DIR/$1.user")"
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
# last argument, exactly as cp and scp both expect it.
copy_to_master() {   # copy_to_master <src>... <dst-dir-on-master>
    if [ "$LOCAL_MODE" -eq 1 ]; then
        cp -R "$@"
    else
        # ${!#} is the last positional (the destination), ${@:1:$#-1} is
        # everything before it; both are bash 3.2-safe.
        scp $SSH_OPTS $(host_ssh_opts "$MASTER") -q -r "${@:1:$#-1}" "$MASTER:${!#}"
    fi
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
    # Local mode leans on Linux-only plumbing: findmnt for the mount guard,
    # /dev/shm for staging and the fio pidfile. Say so here rather than letting
    # it surface two phases later as a confusing findmnt failure. Remote runs
    # from a non-Linux box stay supported -- that plumbing is on the workers.
    # Plain `uname`, PATH-resolved on purpose, so the suite can stub it.
    [ "$(uname -s)" = Linux ] || \
        die "local mode is Linux-only (findmnt, /dev/shm); name a server instead"
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
# stdout is never polluted with UI. Every behavior below was probe-verified on
# bash 3.2.57: timeouts are whole seconds only; read -s must consume via fd
# redirection (read -u echoes); partial -n input is DISCARDED on timeout, so the
# escape drain reads one byte at a time.
PROMPT_TTY="${WEKATESTER_PROMPT_TTY:-/dev/tty}"   # test plumbing only, namespaced
PROMPT_OPENED=0      # 1 = we own fd 3 and must close it
PROMPT_IN_FD=""      # read side  -- the suite presets these two and then
PROMPT_OUT_FD=""     # write side -- the tty gate below is a no-op
PROMPT_DRAIN_SECS=1  # bash 3.2 read -t takes whole seconds; 1 is the floor

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
                          derive system-specific fio options from the workers
                          (default level when omitted: max)
                          cal: group the clients into hardware shapes and,
                          solo on one client per shape, search numjobs
                          (N/2, N, 2N, 4N of N usable physical cores),
                          iodepth, nrfiles and the ioengine per test type:
                          bandwidth toward NIC line rate, the most iops,
                          the most jobs at the latency floor
                          brutal: the cal search with no early stops --
                          every rung of every ladder is measured. Slow
                          :secs sets the measured seconds per cell (default
                          30); it does not change
                          how long the measured jobs run -- that is
                          -x/--duration
  --line-rate Gb/s        every client's dataplane line rate, for the -a cal
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
                 test listed on its own (under -a cal/brutal the 1MiB test
                 gets its own calibrated job count)
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

# bash 3.2 has no ${var,,}, so lowercasing goes through tr. The letters are
# spelled out rather than given as A-Z or [:upper:]: both of those are
# locale-dependent in tr, and a Turkish locale would map I to a dotless i.
lower() { printf '%s' "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz'; }

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
#   - portable to macOS awk, gawk and mawk alike: a comparison inside a
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

IFS= read -r -d '' WEKA_AWK <<'AWKLIB' || :
function awk_fail(msg) { print "ERROR: " msg > "/dev/stderr"; exit 1 }

# python's str.strip() and str.split() whitespace, its ASCII part
function strip(s) {
    sub(/^[ \t\n\013\014\r\034\035\036\037]+/, "", s)
    sub(/[ \t\n\013\014\r\034\035\036\037]+$/, "", s)
    return s
}
function rstrip(s) {
    sub(/[ \t\n\013\014\r\034\035\036\037]+$/, "", s)
    return s
}
function pysplit(s, F) {   # str.split(): F[1..n]
    split("", F)
    s = strip(s)
    return s == "" ? 0 : split(s, F, /[ \t\n\013\014\r\034\035\036\037]+/)
}
# int(): the number, or "" where python raises ValueError
function py_int(s) {
    s = strip(s)
    if (s !~ /^[+-]?[0-9]+(_[0-9]+)*$/) return ""
    gsub(/_/, "", s)
    return s + 0 + 0
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
function set_sorted(S, A,    k, n) {
    split("", A); n = 0
    for (k in S) A[++n] = k + 0
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
    n = split(s, P, ",")
    for (i = 1; i <= n; i++) {
        if (index(P[i], "-")) {
            if (split(P[i], ab, "-") != 2) return 0
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
# lib.py's override_lines (override_variant_key's three cases): replace
# every key= line; else insert key=value after the first [global]; else
# create [global] at the top. Into O[1..m].
function override_lines(L, n, key, value, O,    i, m, hit, g) {
    split("", O); m = 0; hit = 0; g = 0
    for (i = 1; i <= n; i++)
        if (index(L[i], key "=") == 1) hit = 1
        else if (!g && index(L[i], "[global]") == 1) g = i
    if (!hit && !g) { O[++m] = "[global]"; O[++m] = key "=" value }
    for (i = 1; i <= n; i++) {
        O[++m] = (hit && index(L[i], key "=") == 1) ? key "=" value : L[i]
        if (!hit && i == g) O[++m] = key "=" value
    }
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

# --- probe facts (the probe snippet's lines, P[1..np]) ---
# lib.py's probe_cpu_fact: the cpus on the first "key <list>" line (none
# for "-", tested and empty); 1 when the line is there, 0 when the probe
# could not test -- never an answer
function probe_cpu_fact(P, np, key, S,    i, F) {
    split("", S)
    for (i = 1; i <= np; i++)
        if (pysplit(P[i], F) > 1 && F[1] == key) {
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
function probe_topology(P, np, TK, TS, TL,    i, F, c, v, pkg, cid, sib, S, key, BY) {
    split("", TK); split("", TS); split("", TL)
    split("", pkg); split("", cid); split("", sib); split("", BY)
    for (i = 1; i <= np; i++) {
        if (pysplit(P[i], F) < 3 || substr(F[1], 1, 5) != "topo_" || F[2] !~ /^[0-9]+$/) continue
        c = F[2] + 0
        if (F[1] == "topo_physical_package_id") { if ((v = py_int(F[3])) != "") pkg[c] = v }
        else if (F[1] == "topo_core_id") { if ((v = py_int(F[3])) != "") cid[c] = v }
        else if (F[1] == "topo_thread_siblings_list") { if (parse_cpulist(F[3], S)) sib[c] = F[3] }
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
        if ((c in sib) && parse_cpulist(sib[c], S) && (c in S)) TL[c] = join_sorted(S, ",")
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
# unlisted, unbound, topo and catchall; PHYS one thread per usable core,
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
        if (pysplit(P[i], F) == 2 && F[2] ~ /^[0-9]+$/) {
            if (F[1] == "aio_max_nr") mx = F[2] + 0
            else if (F[1] == "aio_nr") nr = F[2] + 0
        }
    if (mx == "") return ""
    mx -= (nr == "" ? 0 : nr)
    return mx < 0 ? 0 : mx
}
AWKLIB

awkrun() {   # awkrun <program> <arg>... -- WEKA_AWK prepended, LC_ALL=C
    LC_ALL=C awk "$WEKA_AWK
function geom_slots() { return \"$GEOM_SLOTS\" }
function geom_names() { return \"$GEOM_NAMES\" }
function layout_job() { return \"$LAYOUT_JOB\" }
function layout_marker() { return \"$LAYOUT_MARKER\" }
function floor_marker() { return \"$FLOOR_MARKER\" }
$1" "${@:2}"
}

# stdin's sha256, lowercase hex: sha256sum, or shasum where there is none
# (a macOS controller)
sha256_hex() {
    local out
    if command -v sha256sum >/dev/null; then
        out=$(sha256sum) || return 1
    else
        out=$(shasum -a 256) || return 1
    fi
    printf '%s' "${out%% *}"
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
        case "$lvl" in
            (cal|brutal) ;;
            (*) usage >&2
                die "$flag: a cell duration applies only to cal and brutal, not $lvl" ;;
        esac
        case "$secs" in
            (""|*[!0-9]*|0) usage >&2
                die "$flag: the rung duration must be whole seconds > 0, got: $secs" ;;
        esac
        CAL_RUNTIME=$secs
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
                AUTO_LEVEL="max"
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
        cal_mode || { usage >&2; die "--line-rate sets the bandwidth target of a calibration: it needs -a cal or -a brutal"; }
    fi
}

# Measured levels run a calibration phase before staging; safe/max/off never
# do. Both run the same per-shape search (see calibrate):
#   cal     with its early stops -- a ladder ends when it flattens, bandwidth
#           when it reaches line rate, latency when it leaves the floor band
#   brutal  with none: every rung of every ladder is measured, the re-splits
#           run to their caps, and more top cells are re-measured. When the
#           stopping rules are the suspect, the exhaustive search settles it
cal_mode()    { case "$AUTO_LEVEL" in (cal|brutal) return 0 ;; esac; return 1; }
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
#     the latency search only -- the floor, then the widest numjobs still at
#     it ('# report iops latency' is a latency file). Same rule the tuner
#     applies to the same file (see report_items in auto_tune).
#   - otherwise 'bandwidth' -> bw and 'iops' -> iops, and a directive naming
#     both types contributes both.
#   - NO directive at all -> counted as bandwidth: the summarizer's fallback
#     reports every metric for such a file, so no single type is named, and
#     their shape (large sequential files, no bs=4k) is bandwidth-like.
# This is NOT the tuner's classification, and deliberately so: it asks for a
# superset of the ladders whose knees the tuner can currently apply, in two
# cases.
#   1. No directive: the tuner's report_items falls back to naming all three
#      items, so latency wins there and the file is staged as a latency file
#      (kind_key 'lat'). A bw knee measured for it is cached in hostlist.csv,
#      not applied to that file at staging.
#   2. '# report bandwidth iops': the tuner's precedence is latency > bw >
#      iops, so it stages that file as bandwidth only, and apply_targets_
#      geometry picks bw for it too -- the iops knee this asks for does not
#      land on that file either.
# Over-asking is the safe direction of that mismatch (a knee nobody applies
# costs ~30s per step once; a knee never measured leaves a guessed queue depth
# in place for the whole run), and the knee-application rule at staging
# decides what actually lands -- see the wire-in.
# Direction comes from each job section's effective rw= (the section's own
# value, else [global]'s): read/randread -> read, write/randwrite -> write,
# the mixed forms -> both. A file that names no rw= anywhere contributes no
# direction, hence no ladder.
cal_required() {   # cal_required <setdir> [bulk 0|1]
    pyrun "$1" "${2:-0}" <<'PYEOF' || return 1
#@include py/cal_required.py
PYEOF
}

# Usable cores for ONE host, by the tuner's own rule (probe_cores in the
# shared layer) -- the same arithmetic auto_tune's facts block does for its
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
#   latency    the floor (one job at queue depth 1), then as many jobs as keep
#              the latency within CAL_FLOOR_PCT (5) percent of it: the most
#              IOPS the client does AT the floor. Not a knee. Under -b the
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
CAL_LINE_PCT=${CAL_LINE_PCT:-95}   # bandwidth: line rate counts as reached here
CAL_FLOOR_PCT=${CAL_FLOOR_PCT:-5}  # latency: a rung is "at the floor" within this
CAL_FLOOR_REPS=${CAL_FLOOR_REPS:-3}   # readings of the one-job floor cell; the
                         # floor is the LOWEST of them -- contention only ever
                         # adds latency, the mirror of throughput's best reading
CAL_KNEE_PCT=${CAL_KNEE_PCT:-98.5}   # THE TIE BAND: cells within this percent
                         # of the best reading are tied, and the tie goes to the
                         # least outstanding IO (numjobs x iodepth), then fewer
                         # jobs, the shallower queue, the tabled file count. 98.5 is
                         # measured: on field client B it resolved all four ladders
                         # to a unique rung at 99.5-100% of the peak, while 99.5
                         # destabilised every one -- a band cannot be tighter
                         # than the peak's own measurement error
CAL_SHAPE_THR=${CAL_SHAPE_THR:-2}   # percent a ladder rung must beat the best so
                         # far by to count as progress
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
cal_knobs() {
    local exh=0 conf=$CAL_CONFIRM
    if brutal_mode; then
        exh=1; conf=$BRUTAL_CONFIRM
    fi
    printf '%s ' "exh=$exh" "line=$CAL_LINE_PCT" "floor=$CAL_FLOOR_PCT" \
        "band=$CAL_KNEE_PCT" "thr=$CAL_SHAPE_THR" "stop=$CAL_STOP_BELOW" \
        "confirm=$conf" "rt=$CAL_RUNTIME" "nr=$CAL_NR" \
        "nrc=$(printf '%s' "$CAL_NR_LADDER" | tr -s ' ' ',')" \
        "bwqd=$(printf '%s' "$CAL_BW_QD_LADDER" | tr -s ' ' ',')" \
        "iopsqd=$(printf '%s' "$CAL_IOPS_QD_LADDER" | tr -s ' ' ',')" \
        "floorreps=$CAL_FLOOR_REPS"
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
    python3 - "$1" "$2" <<'PYEOF'
#@include py/cal_values.py
PYEOF
}

# Per-client latency cell result: "<host> <mean-us> <iops>" -- fio's total
# latency (lat_ns: submission plus completion) of the cell's direction, and
# the IOPS delivered at it. Entries of one host are folded together weighted
# by their IO count, so a cell without group_reporting still reads right.
cal_lat_values() {   # cal_lat_values <json> <read|write>
    python3 - "$1" "$2" <<'PYEOF'
#@include py/cal_lat_values.py
PYEOF
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
    pyrun "$WORK_DIR/cal.results" "$WORK_DIR/targets.final" "$REGEN_LAYOUT" \
          "${LINE_RATE_GBPS:--}" <<'PYEOF' || die "cannot apply the calibration results"
#@include py/apply_cal_results.py
PYEOF
}

# Only the cell's own file belongs on the master -- the per-host dirs
# accumulate every staged cell, so shipping whole dirs would grow with every
# cell measured. One staging tree, one scp per push.
cal_push() {   # cal_push <basename> <host>...
    local base=$1 h; shift
    rm -rf "$WORK_DIR/cal/.push" || return 1
    for h in "$@"; do
        mkdir -p "$WORK_DIR/cal/.push/$h" || return 1
        cp "$WORK_DIR/cal/$h/$base" "$WORK_DIR/cal/.push/$h/" || return 1
    done
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
        subdirs=$(cal_scratch_dirs "$(host_name "$host")" "${CAL_SEP:-.cal.}" \
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
    local members="$WORK_DIR/cal/$host/seed.members" m mdir mcpus meng active
    printf '%s\t%s\t%s\t%s\n' "$host" "$root" "$cpus" "$eng" > "$members"
    if [ "$unified" -eq 1 ] && [ "$rnj" -gt 0 ]; then
        for m in $(group_members "$host"); do
            [ "$m" != "$host" ] || continue
            mcpus=$(awk -F'\t' -v h="$m" '$1 == h {print $2; exit}' "$WORK_DIR/cal/hostinfo")
            meng=$(awk -F'\t' -v h="$m" '$1 == h {print $3; exit}' "$WORK_DIR/cal/hostinfo")
            mdir=$(host_dir "$m")
            printf '%s\t%s\t%s\t%s\n' "$m" "$mdir" "$mcpus" "${meng:-$eng}" >> "$members"
        done
    fi
    want=$(pyrun "$(host_name "$host")" "$rnj" "$rnr" "$wnj" "$wnr" "$FILESIZE_MIB" \
               "$job" "$WORK_DIR/cal" "$WORK_DIR/cal/$host/scratch.list" \
               "${CAL_FMT:-\$jobnum.\$filenum}" "${CAL_SEP:-.cal.}" "$unified" "$dense" \
               "$tlist" "$CAL_NR $CAL_NR_LADDER" "$members" \
               "$WORK_DIR/cal/needs.read.$(group_first "$host")" "$WORK_DIR/cal/needs.write.$host" <<'PYEOF'
#@include py/cal_seed_rep.py
PYEOF
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
    cmd="'$FIO_BIN' --output-format=json --eta=never"
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
    WEKATESTER_CAL_NRS="$CAL_NR $CAL_NR_LADDER" WEKATESTER_FSMIB=$FILESIZE_MIB \
    pyrun "$1" "$2" "$WORK_DIR" "${ENGINE:--}" "$REGEN_LAYOUT" "$CAL_MEM_PCT" \
          "${LINE_RATE_GBPS:--}" "${HOSTS[@]}" <<'PYEOF'
#@include py/cal_shapes.py
PYEOF
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
#              Never reached, or line rate unknown: the peak -- the top
#              CAL_CONFIRM cells re-measured, the best reading wins, and
#              inside CAL_KNEE_PCT the least outstanding IO. A reading 5%
#              above line rate means the line rate is not the ceiling, and
#              the search falls back to the peak.
#   iops       N/2 and N at iodepth=1 nrfiles=1 -- no ladder at or below N
#              (Frank, 2026-09-25). Then 2N and 4N: the queue ladder
#              CAL_IOPS_QD_LADDER at nrfiles=1 until it flattens, then nrfiles
#              2 and 4 at that count's winning iodepth and one step deeper; 4N
#              only when 2N beat N. Then the peak rule above. Brutal walks the
#              whole queue ladder at every file count at 2N and 4N, as far
#              as the guards below let it.
#   latency    the floor: CAL_FLOOR_REPS readings of one job at qd1, lowest
#   lat1m      wins. Then numjobs 2, 4 ... N/2, N at qd1 nrfiles=1, and 2N and
#              4N at qd1 with each nrfiles of CAL_NR_LADDER (the lowest counts),
#              while the latency stays within CAL_FLOOR_PCT of the floor; a
#              rung that leaves the band gets one re-measure before it is
#              believed. The answer is the last rung inside the band. lat1m is
#              the same search at 1MiB blocks (-b).
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
# the shape's tightest member). The qd1 rungs, the latency ladders and the
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
    pyrun "$1" "$CAL_KNEE_PCT" <<'PYEOF'
#@include py/cal_engine_pick.py
PYEOF
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
    knobs="$(cal_knobs)aio=${CAL_REP_AIO:--} $(cal_pin_knobs "$sdir" "$type" "$dirn")"
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
        c=$(cal_plan budget "$type" "$dirn" x "$usable" 0 0 /dev/null $(cal_knobs) $(cal_pin_knobs "$sdir" "$type" "$dirn")) \
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
    awkrun 'BEGIN {
        glob = vars_to_glob(ARGV[1] ARGV[2] ARGV[3]); hd = ARGV[4]
        depth = 1 + count_char(glob, "/")
        cmd = sprintf("find %s -maxdepth %d -type f -path %s -delete", squote(hd), depth, squote(hd "/" glob))
        if (index(glob, "/"))
            cmd = cmd sprintf(" && find %s -maxdepth %d -type d -path %s -empty -delete", squote(hd), depth - 1, squote(hd "/" substr(glob, 1, match(glob, /\/[^\/]*$/) - 1)))
        print cmd
    }' "$@"
}

# -u, after the last measured job (main): the calibration dataset -- in the
# unified namespace each host's write set and, from the first host only, the
# fleet-shared read set, by the same glob derivation the sweep uses; in the
# private scratch the whole scratch dir. Never from calibrate itself: the
# measured jobs still use the unified dataset, and a failed run keeps it.
cal_remove_dataset() {
    local host i ucmd pids=() hs=()
    for host in "${HOSTS[@]}"; do
        if [ -z "$CAL_NS_DIR" ]; then
            # unified: this host's write set, and -- from the first host of
            # each filesystem group only -- the group's fleet-shared read
            # set, deleted by the same glob derivation the sweep uses
            if [ "$host" = "$(group_first "$host")" ]; then
                ucmd=$(cal_remove_cmd shared "." "$CAL_FMT" "$(host_dir "$host")") \
                    || die "cannot derive the shared dataset removal command"
                run_host "$host" "$ucmd" \
                    || log "WARNING: could not remove the shared dataset" >&2
            fi
            ucmd=$(cal_remove_cmd "$(host_name "$host")" "${CAL_SEP:-.}" "$CAL_FMT" "$(host_dir "$host")") \
                || die "$host: cannot derive the dataset removal command"
            run_host "$host" "$ucmd" &
        else
            run_host "$host" "rm -rf '$(host_dir "$host")$CAL_NS_DIR'" &
        fi
        pids+=($!); hs+=("$host")
    done
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
    pyrun "$WORK_DIR" "$shapes" "$ladders" "${CAL_NS_DIR-unset}" "${CAL_FMT:-\$jobnum.\$filenum}" \
          "${CAL_SEP:-.cal.}" "$FILESIZE_MIB" "$CAL_NR $CAL_NR_LADDER" "${HOSTS[@]}" \
          > "$WORK_DIR/cal/cap/report" <<'PYEOF'
#@include py/cal_capacity_check.py
PYEOF
    rc=$?
    while IFS= read -r line; do log "$line"; done < "$WORK_DIR/cal/cap/report"
    case $rc in
        0) return 0 ;;
        2) ;;
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
    pyrun "$1" <<'PYEOF'
#@include py/cal_aio_preflight.py
PYEOF
    case $? in
        0) return 0 ;;
        2) die "calibration would exceed the kernel's aio room (above); nothing was run and the host file is unchanged" ;;
        *) die "cannot check the calibration pins against the kernel's aio room" ;;
    esac
}

# Before any fio server starts, and in a dry run (Frank, 2026-10-05): the
# shapes a calibration would measure, and the pins they must run checked
# against each shape's kernel aio room -- everything this needs (the probe,
# the proven engines, the host file, the filesystem groups) is known by then.
# A pin past the room stops the run here; calibrate works the shapes out again.
cal_preflight() {
    cal_mode || return 0
    local capdir=${SET_DIR_OVERRIDE:-$(workload_src_dir)} ladders
    ladders=$(cal_required "$capdir" "$BULK") || die "cannot inspect $capdir for calibration"
    [ -n "$ladders" ] || return 0
    mkdir -p "$WORK_DIR/cal" || die "cannot create $WORK_DIR/cal"
    cal_shapes "$WORK_DIR/cal/shapes" "$ladders" > "$WORK_DIR/cal/shapes.txt" \
        || die "cannot group the hosts into client shapes"
    cal_aio_preflight "$WORK_DIR/cal/shapes"
}

calibrate() {
    cal_mode || return 0
    local capdir=${SET_DIR_OVERRIDE:-$(workload_src_dir)} ladders
    ladders=$(cal_required "$capdir" "$BULK") || die "cannot inspect $capdir for calibration"
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
            [ "$host" != shared ] && [ "$(host_name "$host")" != shared ] \
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
    cal_shapes "$shapes" "$ladders" > "$WORK_DIR/cal/shapes.txt" \
        || die "cannot group the hosts into client shapes"
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
# out of the IO path entirely. Non-wekafs targets are not our call.
classify_mount_line() {
    set -- $1
    local fstype=${1:-} opts=${2:-}
    [ "$fstype" = "wekafs" ] || { echo "skip"; return; }
    case ",$opts," in
        *,forcedirect,*) echo "ok" ;;
        *,writecache,*)  echo "fail writecache" ;;
        *,readcache,*)   echo "fail readcache" ;;
        *)               echo "fail unknown" ;;
    esac
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
    run_host "$1" "p='$2'/.wekatester-write-probe.\$\$; : > \"\$p\" && rm -f \"\$p\"${GROUP_FILE:+ && printf '%s\\n' '$(host_name "$1")' >> '$2/$GROUP_FILE'}"
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
    for i in "${!HOSTS[@]}"; do
        h=${HOSTS[$i]}
        ( run_host "$h" "sha256sum '$(host_dir "$h")/$GROUP_FILE'" > "$WORK_DIR/fsgroup/$i.sum" ) &
        pids[$i]=$!
    done
    : > "$WORK_DIR/fsgroup/sums"
    for i in "${!HOSTS[@]}"; do
        h=${HOSTS[$i]}
        sum=""
        if wait "${pids[$i]}"; then read -r sum _ < "$WORK_DIR/fsgroup/$i.sum" || sum=""; fi
        case "$sum" in
            (*[!0-9a-f]*|"") die "$h: cannot hash the filesystem-group file $(host_dir "$h")/$GROUP_FILE (written by the mount check; the destination must not change after it)" ;;
        esac
        printf '%s %s\n' "$h" "$sum" >> "$WORK_DIR/fsgroup/sums"
    done
    pids=()
    for h in "${HOSTS[@]}"; do
        run_host "$h" "rm -f '$(host_dir "$h")/$GROUP_FILE'" &
        pids+=($!)
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || log "WARNING: ${HOSTS[$i]}: could not remove $(host_dir "${HOSTS[$i]}")/$GROUP_FILE" >&2
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
    [ -n "$GROUP_FILE" ] || GROUP_FILE=".wekatester-group.$(date +%s).$$.lst"
    local host line verdict failed=() mode_fail=0 write_fail=0 hd anc i
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
    for i in "${!HOSTS[@]}"; do
        hds[$i]=$(host_dir "${HOSTS[$i]}")
        ( run_host "${HOSTS[$i]}" "findmnt -T '${hds[$i]}' -n -o FSTYPE,OPTIONS" > "$td/$i.mnt" ) &
        pids[$i]=$!
    done
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}"; rcs[$i]=$?
        lines[$i]=$(cat "$td/$i.mnt")
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
        verdict=$(classify_mount_line "${lines[$i]}")
        case "$verdict" in
            ok)   ;;
            skip) if [ -n "$anc" ]; then
                      msgs[$i]="$host: $hd does not exist, and $anc is not a wekafs mount -- create it yourself, or check that -d names the right directory"
                      continue
                  fi
                  debug "$host: $hd is not wekafs; guard skipped" ;;
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
            for i in "${!missing[@]}"; do
                host=${missing[$i]}; hd=${missing_dirs[$i]}
                if ! run_host "$host" "mkdir -p -- '$hd'"; then
                    failed+=("$host: cannot create $hd -- $(write_fix_hint "${missing_parents[$i]}")")
                    write_fail=1
                    continue
                fi
                log "$host: created $hd"
                probe_writable "$host" "$hd" \
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
        [ ! -s "$AUTH_DIR/$host.priv" ] || priv=$(cat "$AUTH_DIR/$host.priv")
        [ ! -s "$AUTH_DIR/$host.cpus" ] || cpus=$(cat "$AUTH_DIR/$host.cpus")
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
    for host in "${HOSTS[@]}"; do
        [ ! -f "$WORK_DIR/launch.$host" ] \
            || ! grep -q "WEKATESTER_FIO_AS=root" "$WORK_DIR/launch.$host" \
            || log "NOTE: $host: fio runs as root (no runuser drop-back) -- files it creates are root-owned, and a later unprivileged run on them will fail with EACCES" >&2
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
    local h cmd="pids=''; for h in"
    for h in "$@"; do cmd="$cmd '$h'"; done
    cmd="$cmd; do ( timeout 3 bash -c \": </dev/tcp/\$h/$FIO_PORT\" || echo \"FAIL \$h\" ) & pids=\"\$pids \$!\"; done; wait \$pids; echo DONE"
    printf '%s' "$cmd"
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
            [ -z "$AUTH_DIR" ] || [ ! -s "$AUTH_DIR/$host.priv" ] || priv=$(cat "$AUTH_DIR/$host.priv")
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
        for f in "${CTRL_DIR:-$WORK_DIR/c}"/*; do
            [ -S "$f" ] && ssh -q -O exit -o ControlPath="$f" unused-host-arg
        done
        rm -rf "$WORK_DIR"
        # a socket dir of its own (make_ctrl_dir) lives outside the work dir
        case "$CTRL_DIR" in ("$WORK_DIR"/*|"") ;; (*) rm -rf "$CTRL_DIR" ;; esac
    fi
}

# --- connection establishment ----------------------------------------------------

# A unix socket path is capped at 104 bytes on macOS (108 on Linux), and ssh
# binds a master at its ControlPath plus a temporary suffix of about 17
# bytes: with %C's 40 that leaves 46 for the directory. $WORK_DIR/c fits on
# /dev/shm; under macOS's TMPDIR (~50 bytes before wt.XXXXXX) it does not,
# and every connection failed "unix_listener: path too long" -- so there the
# sockets go to a short private dir under /tmp, which cleanup removes.
make_ctrl_dir() {
    CTRL_DIR=$WORK_DIR/c
    if [ ${#CTRL_DIR} -gt 46 ]; then
        CTRL_DIR=$(mktemp -d /tmp/wtc.XXXXXX) || die "cannot create an ssh socket dir under /tmp"
    else
        mkdir -p "$CTRL_DIR" || die "cannot create $CTRL_DIR"
    fi
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
    local host pids=() effs=() left=() i n=0 eff
    for host in "${REMAINING[@]}"; do
        # a credential's own login wins; else the host file pins this host's
        eff=$3
        [ -n "$eff" ] || eff=$(targets_field "$host" 2)
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
    # SSH_ASKPASS_REQUIRE; macOS has no setsid and does not need it.
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
    # WEKATESTER_SYSROOT prefixes /proc and /sys for the suite's fake trees;
    # no worker ever has it set.
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
    printf '%s' "echo \"ncpus \$(getconf _NPROCESSORS_ONLN)\"; \
        echo \"wekanode \$(pgrep -xc wekanode || true)\"; \
        for p in \$(pgrep -x wekanode || true); do cat /proc/\$p/status; done \
        | awk '/^Cpus_allowed_list/ {print \"weka_allowed\", \$2}' | sort -u; \
        echo \"engines \$('$FIO_BIN' --enghelp | tr \"\\n\" \" \")\"; \
        echo \"taskset \$(taskset -cp \$\$ | awk -F': ' '{print \$2}')\"; \
        echo \"isolated \$([ -f /sys/devices/system/cpu/isolated ] && cat /sys/devices/system/cpu/isolated)\"; \
        echo \"online \$([ -r /sys/devices/system/cpu/online ] && cat /sys/devices/system/cpu/online)\"; \
        echo \"ident \$(if [ -r /sys/class/dmi/id/product_uuid ]; then cat /sys/class/dmi/id/product_uuid; elif [ -r /etc/machine-id ]; then cat /etc/machine-id; fi)\"; \
        _pv=; for pc in 'dzdo -n' pbrun sesu pmrun 'doas -n' 'ksu -e' 'sudo -n'; do set -- \$pc; command -v \$1 >/dev/null || continue; if _o=\$(timeout 5 \$pc true </dev/null 2>&1); then echo \"priv \$pc\"; _pv=\$pc; break; fi; done; \
        if command -v taskset >/dev/null; then \
            _on=\$([ -r /sys/devices/system/cpu/online ] && cat /sys/devices/system/cpu/online); \
            _ids=\$(printf '%s' \"\${_on:-0-\$(( \$(getconf _NPROCESSORS_ONLN) - 1 ))}\" | awk 'BEGIN {RS = \",\"} {n = split(\$0, a, \"-\"); if (n == 2) {for (i = a[1]; i <= a[2]; i++) print i} else if (length(\$0)) print \$0 + 0}'); \
            _bd=; _bp=; for c in \$_ids; do \
                if _o=\$(taskset -c \$c true 2>&1); then _bd=\"\$_bd,\$c\"; \
                elif [ -n \"\$_pv\" ] && _o=\$(\$_pv taskset -c \$c true 2>&1); then _bp=\"\$_bp,\$c\"; fi; \
            done; \
            [ -n \"\$_bd\" ] || _bd=,-; [ -n \"\$_bp\" ] || _bp=,-; \
            echo \"bindable \${_bd#,}\"; echo \"bindable_priv \${_bp#,}\"; \
        fi; \
        _m=; if command -v lscpu >/dev/null; then _m=\$(lscpu | awk -F: '/^Model name/ {sub(/^[ \\t]+/, \"\", \$2); print \$2; exit}'); fi; \
        _sr=\${WEKATESTER_SYSROOT:-}; \
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
    for host in "${HOSTS[@]}"; do
        (
            hd=$(host_dir "$host")
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
                        log "WARNING: $host: ioengine $c test is STUCK in uninterruptible IO -- abandoned; direct IO on $(host_dir "$host") may be broken on this host" >&2
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
        local ok none=() c
        for host in "${HOSTS[@]}"; do
            ok=$(awk -v h="$host" '$1 == h && $3 == "ok" {printf " %s", $2}' "$results")
            [ -n "$ok" ] || none+=("$host")
            awk -v ok="$ok" '$1 == "engines" {print "engines" ok; next} {print}' \
                "$WORK_DIR/probe/$host" > "$WORK_DIR/probe/$host.new"
            mv "$WORK_DIR/probe/$host.new" "$WORK_DIR/probe/$host"
        done
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
        for host in "${HOSTS[@]}"; do
            grep -q "^$host $ENGINE ok$" "$results" || {
                # the workdir dies with the process: quote the evidence now
                [ ! -f "$WORK_DIR/et/$host.$ENGINE.out" ] || tail -5 "$WORK_DIR/et/$host.$ENGINE.out" >&2
                die "ioengine '$ENGINE' failed its test job on $host (fio output above)"
            }
        done
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
    for host in "${HOSTS[@]}"; do
        eng=$(targets_field "$host" 3 "$WORK_DIR/targets.final")
        [ -z "$eng" ] && continue
        { [ -f "$WORK_DIR/engine.results" ] \
              && grep -q "^$host $eng ok$" "$WORK_DIR/engine.results"; } || {
            [ ! -f "$WORK_DIR/et/$host.$eng.out" ] || tail -5 "$WORK_DIR/et/$host.$eng.out" >&2
            die "host file assigns ioengine '$eng' to $host but its test job failed (fio output above)"
        }
    done
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
    # One python for every host, not one per host behind six awks: the
    # verdict is set arithmetic on the probe file and the host's row, and
    # ~45ms of process starts per host before any judgment is 20s of serial
    # nothing at 451 hosts. It writes one line per host that has a request,
    # in host order: host, the request, the taskset and cpu count the
    # messages quote back, the four cpu sets, the flags (comma-joined), and
    # the escalator prefix last (it has spaces) -- "-" for an empty field.
    # The bash below still speaks per host, unchanged.
    pyrun "$WORK_DIR/targets.final" "$WORK_DIR/probe" "${AUTO_LEVEL:--}" "${HOSTS[@]}" \
        > "$WORK_DIR/pin.verdicts" <<'PYEOF' || die "cpu pinning check failed"
#@include py/check_cpu_pinning.py
PYEOF
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
        debug "$host: fio server will run ${priv:+$([ "$need_priv" -eq 1 ] && printf 'under %s ' "$priv")}taskset -c $effective"
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
        for host in "${HOSTS[@]}"; do
            grep "^engines " "$WORK_DIR/probe/$host" | grep -qw "$ENGINE" \
                || bad+=("$host")
        done
        [ ${#bad[@]} -eq 0 ] \
            || die "ioengine '$ENGINE' is not available (fio --enghelp) on: ${bad[*]}"
    fi

    # df is the only master-side fact the tuner needs. The backend-RAM query
    # that used to live here is gone with the DRAM ceiling it fed -- see the
    # spec's "Working-set sizing (max tier) -- CORRECTED 2026-08-18": weka
    # backends hold no user data in RAM, so there was never a cache to defeat.
    [ -n "$AUTO_LEVEL" ] || return 0   # df matters to the tuner only
    run_host "$MASTER" "df -kP '$DIRECTORY'" > "$WORK_DIR/probe/_df" \
        || die "cannot df $DIRECTORY on $MASTER"
}

# One-shot tuner: reads all probe facts and all jobfiles, writes every
# per-host variant. Python because the rules are per-section, per-type,
# per-tier -- data transformation, not orchestration.
#
# usage: auto_tune <src> <work> <tier> <directory> <ignore_capacity> <host>...
# where <ignore_capacity> is 1 to downgrade the over-capacity abort to a
# warning (--ignore-capacity), 0 to abort. Returns nonzero on any failure,
# including the capacity check, so the caller aborts before fio starts.
auto_tune() {
    pyrun "$@" <<'PYEOF' || return 1
#@include py/auto_tune.py
PYEOF
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
    for host in "${HOSTS[@]}"; do
        # the fs type rides along (a third line): hosts on one weka
        # filesystem draw from one pool, checked together below
        run_host "$host" "df -kP '$(host_dir "$host")' && { findmnt -T '$(host_dir "$host")' -n -o FSTYPE 2>&1 || :; }" > "$WORK_DIR/df/$host" &
        pids+=($!)
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || log "WARNING: cannot df on ${HOSTS[$i]}; its capacity is unchecked" >&2
    done
    pyrun "$WORK_DIR" "${HOSTS[@]}" <<'PYEOF'
#@include py/check_capacity.py
PYEOF
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
    pyrun "$1" "$2" <<'PYEOF' || return 1
#@include py/generate_layout.py
PYEOF
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
# tests, results in a file as "host engine ok|fail" lines -- NOT stdin,
# the python heredoc owns stdin) = everything.
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
    local n
    if [ "$LOCAL_MODE" -eq 1 ]; then
        n=${LOCAL_NAME:-$(local_short_hostname)}
        printf '%s' "${n:-$1}"
    else
        printf '%s' "$1"
    fi
}

# "<name>/<machine-id>", or just the name when no id could be read.
host_identity() {   # host_identity <host>
    local n id
    n=$(host_name "$1"); id=$(host_machine_id "$1")
    [ -n "$id" ] && printf '%s/%s' "$n" "$id" || printf '%s' "$n"
}

# name=address pairs for the CSV readers, so a row written as
# "client-a/<id>" resolves to the address the run actually uses.
host_alias_env() {   # host_alias_env <host>... -> "name=addr,name=addr"
    local h n out=""
    for h in "$@"; do
        n=$(host_name "$h")
        [ "$n" = "$h" ] || out="$out${out:+,}$n=$h"
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
    for h in "${HOSTS[@]}"; do ident="$ident${ident:+,}$h=$(host_identity "$h")"; done
    WEKATESTER_HOST_ALIAS=$(host_alias_env "${HOSTS[@]}") \
    WEKATESTER_HOST_IDENT=$ident \
    pyrun "$wb" "$mode" "$WORK_DIR" "${LINE_RATE_GBPS:--}" "${HOSTS[@]}" <<'PYEOF' || die "host file writeback failed ($wb)"
#@include py/writeback_targets.py
PYEOF
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
    WEKATESTER_HOST_ALIAS=$(host_alias_env "${@:6}") pyrun "$@" <<'PYEOF'
#@include py/resolve_targets.py
PYEOF
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
            dst="./fio-jobfiles/$(date +%Y%m%d-%H%M%S)"
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
                    dst="./fio-jobfiles/$(date +%Y%m%d-%H%M%S)"
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
        call=$(cal_required "$caldir" "$BULK") || call=""
        if [ -n "$call" ]; then
            log "-a $AUTO_LEVEL would calibrate before staging: $(printf '%s' "$call" | tr '\n' ',' | sed 's/,$//;s/,/, /g') -- per client shape, each shape solo on its first host; the searches need live fio servers, so a dry run only names the shapes:"
            mkdir -p "$WORK_DIR/cal"
            if cal_shapes "$WORK_DIR/cal/shapes" "$call" > "$WORK_DIR/cal/shapes.txt"; then
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
    local srcdir=$1 host tuner_tier
    if [ -n "$AUTO_LEVEL" ]; then
        # Calibration layers its measured tuples on top of max's rules
        # (through targets.final), so cal and brutal size EXACTLY like max
        # otherwise -- the tuner python only knows safe/max, on purpose, so a
        # new tier can never silently fall through its tier=="max" checks as
        # an unrecognized value (engine forcing, small-file namespace)
        # missing both its own handling and max's.
        tuner_tier=$AUTO_LEVEL
        cal_mode && tuner_tier=max
        # The fleet-shared read set exists because calibration's read cells
        # measured it, so only cal and brutal stage reads onto it. safe and
        # max stage every file on the client's own grid, the one plain runs
        # use, so alternating the two never lays out a second read grid.
        local ns=""
        if cal_mode; then
            ns=$(cal_namespace "$srcdir") \
                || die "cannot derive the calibration namespace from $srcdir"
        fi
        WEKATESTER_TIER_LABEL=$AUTO_LEVEL \
        WEKATESTER_NS="$ns" \
        WEKATESTER_IOPS_NOLAT=$(cal_mode && echo 1 || echo 0) \
        auto_tune "$srcdir" "$WORK_DIR" "$tuner_tier" "$DIRECTORY" \
            "$IGNORE_CAPACITY" "${WORK_DIR}/targets.final" "${HOSTS[@]}" || die "auto tuning failed"
        return
    fi
    # Plain staging: one python for every host and jobfile does the
    # directory override and the host-file geometry (pick_slot -- the same
    # resolver the tuner and apply_targets_geometry use), and names the hosts
    # whose geometry changed. Per host and jobfile this was 2-3 grep/awk for
    # the directory, a python plus up to 4 awk/mv for the geometry, then per
    # host a python for pristineness and a grep/awk/mv per file for the
    # engine: ~50 process starts per host and jobfile, serial, none of them
    # waiting on a worker.
    local changed pristine=""
    changed=$(pyrun "$srcdir" "$WORK_DIR" "$DIRECTORY" "$LAYOUT_JOB" "$LAYOUT_MARKER" \
                    "${HOSTS[@]}" <<'PYEOF'
#@include py/stage_variants.py
PYEOF
    ) || die "per-host jobfile staging failed"
    for host in $changed; do
        # host-file geometry changed this host's grid: its layout must
        # describe THAT grid, so re-derive it from the staged variants --
        # unless the operator hand-edited the layout, which is preserved
        # with the same warning the tuner gives. Pristineness is judged on
        # the SOURCE layout, once for the fleet: the staged copies always
        # differ from its sha (the directory override edits them).
        [ -n "$pristine" ] || { layout_variant_pristine "$srcdir" && pristine=1 || pristine=0; }
        if [ "$pristine" -eq 1 ]; then
            generate_layout "$WORK_DIR/jobs/$host" "$WORK_DIR/jobs/$host" >/dev/null \
                || die "per-host layout derivation failed for $host"
        else
            log "WARNING: $host: hand-edited layout kept as authored; it may not match the host-file geometry" >&2
        fi
    done
    # host-file engine (final resolution) applies per host, to every staged
    # file including a re-derived layout; the global -e post-pass in
    # stage_jobfiles still runs after this and wins
    [ -f "$WORK_DIR/targets.final" ] || return 0
    stage_host_engines
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
            n = override_lines(L, n, "ioengine", e, O)
            writelines(F[2], O, n)
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
    local host src
    is_layout_file "$SET_DIR/${JOBFILES[0]}" \
        || die "no layout job at position one; cannot derive the -u unlink job"
    for host in "${HOSTS[@]}"; do
        src="$WORK_DIR/jobs/$host/${JOBFILES[0]}"
        [ -f "$src" ] || die "no staged layout variant for $host; cannot derive the -u unlink job"
        awk -v marker="$LAYOUT_MARKER" '
            index($0, marker) == 1 { next }
            /^filesize=/ { print "filesize=4k"; next }
            /^size=/     { print "filesize=4k"; next }
            /^(blocksize|bs)=/ { print "blocksize=4k"; next }
            { print }
        ' "$src" > "$WORK_DIR/jobs/$host/$UNLINK_JOB" \
            || die "cannot derive the -u unlink job for $host from $src"
        # every section must unlink: a hand-written layout may have no
        # [global] at all, and override_variant_key creates one then
        override_variant_key "$WORK_DIR/jobs/$host/$UNLINK_JOB" unlink 1
    done
    JOBFILES+=("$UNLINK_JOB")
}

# Stamp key=value into a staged variant: replace every existing line, or
# insert into [global] (created if missing) so fio cannot quietly fall back
# to a per-file default. Same three cases as the directory override.
override_variant_key() {   # override_variant_key <file> <key> <value>
    local f=$1 key=$2 val=$3 tmp="$1.tmp.$$"
    if grep -q "^$key=" "$f"; then
        awk -v k="$key" -v v="$val" \
            'index($0, k "=") == 1 { print k "=" v; next } { print }' "$f" > "$tmp"
    elif grep -q '^\[global\]' "$f"; then
        awk -v k="$key" -v v="$val" \
            '{ print } /^\[global\]/ && !ins { print k "=" v; ins = 1 }' "$f" > "$tmp"
    else
        { printf '[global]\n%s=%s\n' "$key" "$val"; cat "$f"; } > "$tmp"
    fi
    mv "$tmp" "$f"
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
    # one python for the fleet (was one per host, ~30ms each, serial): per
    # host its staged dir, its name, and the recorded cpu list, "-" for none
    for host in "${HOSTS[@]}"; do
        cpus=""
        [ -z "$AUTH_DIR" ] || [ ! -s "$AUTH_DIR/$host.cpus" ] || IFS= read -r cpus < "$AUTH_DIR/$host.cpus" || :
        args+=("$WORK_DIR/jobs/$host" "$(host_name "$host")" "${cpus:--}")
    done
    [ ${#args[@]} -gt 0 ] || return 0
    python3 - "${args[@]}" <<'PYEOF' || die "cannot stamp deterministic filenames"
#@include py/stamp_unique_names.py
PYEOF
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
    pyrun "$1" "$LAYOUT_JOB" "$LAYOUT_MARKER" <<'PYEOF' || return 1
#@include py/stage_bulk_twins.py
PYEOF
}

# -a cal/brutal: beside every latency jobfile (the -b twins included), a
# one-job twin, 021-latencyR.job gaining 021-latencyR-1job.job, which sorts
# and so runs right before it. The tuner stages the twin at numjobs=iodepth=
# nrfiles=1 on every client with the same data per job as its original, and
# the original at what the search found: one single-threaded stream's
# latency across the fleet, next to every client's latency at its calibrated
# load. Same files and sections as the original, so the layout covers it.
stage_floor_twins() {   # stage_floor_twins <set-dir>
    pyrun "$1" "$LAYOUT_JOB" "$LAYOUT_MARKER" <<'PYEOF' || return 1
#@include py/stage_floor_twins.py
PYEOF
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
        for v in "$WORK_DIR"/jobs/*/*; do
            [ -f "$v" ] && override_variant_key "$v" ioengine "$ENGINE"
        done
    fi
    # the engine and every job's geometry are final here
    check_aio_room
    if [ -n "$DURATION" ]; then
        # one duration for every MEASURED job; layout and unlink keep their
        # own timing -- they run to completion, not to a clock
        for v in "$WORK_DIR"/jobs/*/*; do
            [ -f "$v" ] || continue
            is_layout_file "$v" && continue
            override_variant_key "$v" runtime "$DURATION"
            override_variant_key "$v" time_based 1
        done
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
# Two fifos + two tees rather than >(process substitution): bash 3.2 cannot
# wait on a substituted process, and finalize must drain the log before
# archiving it. stdout and stderr keep their identities on the console.
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
    for host in "${HOSTS[@]}"; do
        [ -s "$WORK_DIR/sysinfo.$host" ] || continue
        mkdir -p "$RUN_DIR/sysinfo/$host" \
            || { log "WARNING: cannot create $RUN_DIR/sysinfo/$host" >&2; continue; }
        awk -v dir="$RUN_DIR/sysinfo/$host" '
            /^=== WEKATESTER_SYSINFO / { out = dir "/" $3; next }
            out { print > out }
        ' "$WORK_DIR/sysinfo.$host"
    done
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
        sar_s=$(printf '%s' "${RUN_STAMP#*-}" | sed 's/\(..\)\(..\)\(..\)/\1:\2:\3/')
        sar_e=$(date +%H:%M:%S)
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
    for host in "${HOSTS[@]}"; do
        [ -s "$WORK_DIR/pressure.$label.$host" ] || continue
        mkdir -p "$RUN_DIR/sysinfo/$host" || continue
        awk -v dir="$RUN_DIR/sysinfo/$host" -v lbl="$label" '
            /^=== WEKATESTER_SYSINFO / { out = dir "/" $3 "-" lbl; next }
            out { print > out }
        ' "$WORK_DIR/pressure.$label.$host"
    done
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
    python3 - "$1" "$2" <<'PYEOF'
#@include py/check_fio_errors.py
PYEOF
}

# fio cannot be trusted to create the directory tree a filename_format
# implies: create_on_open never mkdirs at all, and create_only's setup pass
# on fio 3.28 mkdirs only each job's FIRST file's directory (seen live on
# two labs: dir 0 created, every 1/* open ENOENTs with filesetup.c:174).
# So the grid's directories are derived from the staged layout variant and
# made here, before any layout job runs. Flat namespaces derive nothing.
ensure_layout_dirs() {   # ensure_layout_dirs <staged layout jobref>
    local host cmd i pids=() hs=()
    for host in "${HOSTS[@]}"; do
        # every directory each section's filename_format implies under its
        # directory=, a section's own keys over [global]'s; mkdir -p lines
        # of 400, so the remote command stays far below ssh's packet limit
        cmd=$(awkrun 'BEGIN {
            if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1])
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
                    print "WARNING: cannot pre-create directories for [" name "]: unsupported variable in " squote(pre) > "/dev/stderr"
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
            print out
        }' "$WORK_DIR/jobs/$host/$1") || die "cannot derive the layout directory set for $host"
        [ -n "$cmd" ] || continue
        run_host "$host" "$cmd" &
        pids+=($!); hs+=("$host")
    done
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
#   per host, one python for the fleet; stdout names each host whose
#   (non-empty) layout job has no fallocate=none line
layout_grid_spec() {
    pyrun "$@" <<'PYEOF'
#@include py/layout_grid_spec.py
PYEOF
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
    # one python derives every host's grid (was one per host plus a grep,
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
    for host in "${HOSTS[@]}"; do
        spec=$(<"$WORK_DIR/probe/$host.gridspec")
        [ -n "$spec" ] || continue
        hd=$(host_dir "$host")
        cmd=""
        while IFS="$(printf '\t')" read -r sz glob depth tot; do
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
        done <<SPECEOF
$spec
SPECEOF
        [ -n "$cmd" ] || continue
        ( run_host "$host" "$cmd" | awk '{t+=$1} END{print t+0}' \
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
fio_client_cmd() {   # fio_client_cmd <job>
    local host cmd="'$FIO_BIN' --output-format=json --eta=never"
    for host in "${HOSTS[@]}"; do
        cmd="$cmd --client=$host '$TARGET_DIR/$host/$1'"
    done
    printf '%s' "$cmd"
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
    local job outfile report cmd host t0 t1
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
            log "laying out files ($job) on ${#HOSTS[@]} host(s)..."
            t0=$(date +%s)
            run_host "$MASTER" "$cmd" > "$outfile" \
                || die "layout failed for $job (partial output in $outfile)"
            if ! check_fio_errors "$outfile" layout; then
                for host in "${HOSTS[@]}"; do
                    fio_parse_postmortem layout "$host" "$TARGET_DIR/$host/$job" \
                        "$RUN_DIR/parse.${job%.job}.$host.out"
                done
                die "layout $job failed -- the files were not created (raw output in $outfile)"
            fi
            t1=$(date +%s)
            log "layout: complete in $((t1 - t0))s across ${#HOSTS[@]} host(s)"
            echo
            continue
        fi
        if [ "$job" = "$UNLINK_JOB" ]; then
            # Cleanup, not measurement: error-checked like a layout job (its
            # stats are open/unlink zeros), timed instead of summarized.
            log "removing test files ($job) on ${#HOSTS[@]} host(s)..."
            t0=$(date +%s)
            run_host "$MASTER" "$cmd" > "$outfile" \
                || die "unlink failed for $job (partial output in $outfile)"
            check_fio_errors "$outfile" layout \
                || die "unlink $job failed -- test files may remain (raw output in $outfile)"
            t1=$(date +%s)
            log "unlink: test files removed in $((t1 - t0))s across ${#HOSTS[@]} host(s)"
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
#      in memory -- nothing is extracted to disk.
# $2 = report items ("bandwidth iops latency"; empty = all)
# $3 = expected hosts (space-separated; empty = don't check, e.g. -s mode)
summarize() {
    python3 - "$1" "$2" "${3:-}" <<'PYEOF' || die "failed to summarize $1"
#@include py/summarize.py
PYEOF
}

# --- main ----------------------------------------------------------------------
main() {
    # -s: offline re-summarize of an existing results file, no hosts involved
    if [ -n "$SUMMARIZE_FILE" ]; then
        [ -f "$SUMMARIZE_FILE" ] || die "no such file: $SUMMARIZE_FILE"
        summarize "$SUMMARIZE_FILE" ""
        exit 0
    fi

    resolve_local_mode
    # -i entries are split and their key paths checked here, before the
    # staging dir exists and long before the first connection: a bad key path
    # costs nothing to report and leaves nothing behind.
    validate_credentials
    command -v python3 >/dev/null || die "python3 is required for result parsing"
    # -C's editors and prompts need a terminal; a missing one (or a bogus
    # $EDITOR) costs nothing to report now and everything to discover after
    # ten minutes of setup. Unattended forms (-r, -n) skip the terminal.
    if [ "$CUSTOMIZE" -eq 1 ] && [ "$FAST_TRACK" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        require_interactive "-C"
        resolve_editor
    fi

    log "wekatester $VERSION: ${#HOSTS[@]} worker(s), master $MASTER, workload $WORKLOAD"
    echo
    [ "$STAGE_BASE" = /dev/shm ] || debug "no /dev/shm here; local staging in $STAGE_BASE"

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
    RUN_STAMP=$(date '+%Y%m%d-%H%M%S')
    RUN_DIR="$OUTPUT_DIR/$RUN_STAMP"
    mkdir "$RUN_DIR" || die "cannot create run directory $RUN_DIR"
    start_run_log
    replay_prerun_warnings
    snapshot_sysinfo
    snapshot_pressure start
    # every run probes and pins: only the probe knows where weka's pinned
    # cores are, and fio never lands on them (Frank, 2026-09-29)
    probe_workers
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
