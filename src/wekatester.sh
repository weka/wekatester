#!/usr/bin/env bash
# wekatester - performance test a network/parallel filesystem with distributed
# fio. Bash and awk, run from a Linux controller with bash 4.4+. README.md has
# the behaviour; comments here keep only what the code cannot say for itself.

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

# -w was named, not defaulted: only then may -C recopy its jobfiles over a set.
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

# Namespaced: cleanup feeds this path to rm -rf on every host, so a stray
# TARGET_DIR export must not move it. Test plumbing only.
TARGET_DIR="${WEKATESTER_TARGET_DIR:-/dev/shm/fio-jobfiles}"   # staging dir on the master
FIO_PIDFILE="/dev/shm/wekatester-fio.pid"
FIO_PORT=8765                           # fio --server listen port

# local staging: tmpfs, which every Linux controller has (the suite, run on a
# development Mac, points WEKATESTER_STAGE_BASE elsewhere)
STAGE_BASE=${WEKATESTER_STAGE_BASE:-/dev/shm}

# Control opts are per host (host_ssh_opts): a host on a user-owned master
# must not get our ControlPath.
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=10"
CONTROL_OPTS=""
CTRL_DIR=""   # the ssh master sockets' directory (make_ctrl_dir)

# Credential order: existing masters, defaults, each -i key, each -p pair.
IDENT_RAW=()        # -i entries as typed ([login:]key, comma lists, repeatable)
IDENT_LOGINS=()     # validated split of IDENT_RAW ("" = ssh's default user)
IDENT_KEYS=()
PW_COUNT=0          # -p [n]: how many login/password pairs to prompt for
PW_LOGINS=()        # prompted pairs ("" login = ssh's default user)
PW_SECRETS=()       # passwords live only here and in the per-attempt fifos
AUTH_DIR=""          # $WORK_DIR/auth: per-host winning-credential state

# Local mode: no server given; the transport runs commands directly.
LOCAL_MODE=0
LOCAL_NAME=""      # local mode: the short hostname data files are prefixed with (host_name)

# Auto mode: derive system-specific fio options
AUTO_LEVEL=""    # "", "safe", "max", "cal", or "brutal"
IGNORE_CAPACITY=0   # 1: run even when the workload does not fit at $DIRECTORY

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
# user-owned master, or when AUTH_DIR is unset.
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
    (
        set -o pipefail
        tar -C "$parent" -cf - -- "${names[@]}" \
            | ssh $SSH_OPTS $(host_ssh_opts "$MASTER") "$MASTER" "mkdir -p '$dst' && tar -xf - -C '$dst'"
    )
}

# For a worker that needs its own copy (the postmortem's fio --parse-only).
copy_to_host() {   # copy_to_host <host> <src>... <dst-dir-on-host>
    local host=$1; shift
    if [ "$LOCAL_MODE" -eq 1 ]; then
        cp -R "$@"
    else
        scp $SSH_OPTS $(host_ssh_opts "$host") -q -r "${@:1:$#-1}" "$host:${!#}"
    fi
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
    command -v "$1" >/dev/null || die "editor not found: $1 (from \$VISUAL/\$EDITOR)"
}

# All three fds go to the terminal: stdout may be a pipe.
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
# A value never starts with a dash: that is a mistyped flag sequence (-f -g
# once made -g the fio binary).
need_arg() {   # need_arg <option-as-typed> <argc> <next-token>
    [ "$2" -ge 2 ] || { usage >&2; die "option $1 requires an argument"; }
    case "$3" in
        -?*) usage >&2; die "option $1 requires an argument, got '$3' (looks like another option)" ;;
    esac
}

# -wsmoke and -w=smoke both mean smoke; attaching passes a value that starts
# with a dash. Sets OPT_VAL so a die fires in the parsing shell.
OPT_VAL=""
opt_val() {   # opt_val <normalized-token> <canonical-option>
    OPT_VAL=${1#"$2"}
    OPT_VAL=${OPT_VAL#=}
    [ -n "$OPT_VAL" ] || { usage >&2; die "option $2 requires a value"; }
}

# Lowercasing under the C locale: a Turkish one would map I to a dotless i.
lower() { local LC_ALL=C; printf '%s' "${1,,}"; }

# Fold an option NAME, never its value: --LOGIN=Ubuntu -> --login=Ubuntu,
# -CMySet -> -cMySet, -VV -> -vv.
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

# --- the shared awk layer ----------------------------------------------------
# Rules more than one program needs, spelled once; awkrun prepends this and the
# constants below. The conventions every program keeps: README, Source.
# Host-file schema: host, four identity columns, eight nj/fs/nr/qd slots, the
# 1MiB latency slots last so older files still line up.
GEOM_SLOTS="bw_r bw_w lat_r lat_w iops_r iops_w lat1m_r lat1m_w"
GEOM_NAMES="bandwidthR bandwidthW latencyR latencyW iopsR iopsW latency1mR latency1mW"
# First line of a latency test's one-job twin (-a): stage_floor_twins writes
# it, staging and the writeback read it.
FLOOR_MARKER="# wekatester-floor:"
# The engine a tie goes to, best first, and the one a set that names none
# gets.
ENGINE_ORDER="io_uring libaio psync"
# Measured again under --line-rate even when pinned: a recorded answer does
# not say which line rate it stopped at.
LINE_RATE_SLOTS="bw_r bw_w"

IFS= read -r -d '' WEKA_AWK <<'AWKLIB' || :
#@include awk/lib/base.awk
#@include awk/lib/jobfiles.awk
#@include awk/lib/probe.awk
#@include awk/lib/hostfile.awk
#@include awk/lib/seed.awk
#@include awk/lib/layout.awk
#@include awk/lib/json.awk
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

# -a level[:secs]: secs is the calibration cell length, independent of -x.
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
    # Whether -- appears anywhere decides a bare token after -C: with it, the
    # set name; without, a client candidate.
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
        # Arms match $opt (folded), never $1; $1 is only for need_arg messages.
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
            # The count is consumed only as a positive integer with no leading
            # zero ("00" -eq 0 would skip the prompts).
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
            # The path is consumed only when it contains / or ends .csv.
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
                # The level is case-folded and consumed only when it is one;
                # :secs rides along.
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
            # Accumulates in order; validate_credentials checks it. An empty
            # =-form is refused here, where need_arg cannot see it.
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
                    # A path separator, a shipped set name or an existing set
                    # directory makes the token the set outright; only an
                    # ambiguous bare word waits for preflight.
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
        # -r used to take a report list: name the change, not demote it to a
        # host.
        [ "$FAST_TRACK" -eq 0 ] || { usage >&2
            die "-r cannot be combined with -s; -s now always prints the full summary (the '-r items' filter was removed)"; }
    fi
    if [ -n "$LINE_RATE_GBPS" ]; then
        case "$LINE_RATE_GBPS" in
            (*[!0-9.]*|*.*.*|.)
                usage >&2; die "--line-rate takes the line rate in Gb/s, a positive number such as 16 or 12.5: '$LINE_RATE_GBPS'" ;;
        esac
        # Bounded: under 8e-9 the target rounds to 0, past ~310 digits it is
        # inf.
        awk -v v="$LINE_RATE_GBPS" 'BEGIN {v += 0; exit !(v >= 0.1 && v <= 100000)}' \
            || { usage >&2; die "--line-rate must be between 0.1 and 100000 Gb/s: '$LINE_RATE_GBPS'"; }
        # only a calibration's bandwidth search has a target to set
        cal_mode || { usage >&2; die "--line-rate sets the bandwidth target of a calibration: it needs -a"; }
    fi
}

# Every -a level calibrates: safe and max search numjobs only, cal and brutal
# walk the ladders, brutal without early stops.
cal_mode()    { case "$AUTO_LEVEL" in (safe|max|cal|brutal) return 0 ;; esac; return 1; }
# the widest job count a level's searches reach, in multiples of N: safe and
# max stop at 2N, cal and brutal climb to 4N (latency stays at N everywhere)
cal_wide()    { case "$AUTO_LEVEL" in (safe|max) echo 2 ;; (*) echo 4 ;; esac; }
brutal_mode() { [ "$AUTO_LEVEL" = brutal ]; }

# Which searches a set needs: unique sorted "<bw|iops|lat|lat1m> <read|write>"
# lines, none when nothing calibrates; calibration and the dry run read them
# verbatim. Type by report directive, direction by rw= (README, Auto mode).
# lat1m: a 1MiB latency file, or under -b beside every 4k one.
cal_required() {   # cal_required <setdir> [bulk 0|1]
    local f files=()
    [ -d "$1" ] || { echo "ERROR: cal_required: not a jobfile set directory: $1" >&2; return 1; }
    for f in "$1"/[0-9]*; do [ -f "$f" ] && files+=("$f"); done
    [ ${#files[@]} -gt 0 ] || return 0
    awkrun '#@awk cal_required' "${2:-0}" "${files[@]}"
}

# N for one host by probe_cores, the staging rule. count = N; phys = one
# thread per usable core (N/2, N jobs); list = every thread (2N, 4N). Fails
# rather than print 0: numjobs=0 is no fio job.
usable_cores() {   # usable_cores <host> [count|phys|list] [cpulist]
                   # an operator cpu list is the base: weka cores and core 0
                   # pair come out of it, unless it covers every usable cpu
                   # (probe_cores)
    [ -f "$WORK_DIR/probe/$1" ] || {
        log "ERROR: usable_cores: no probe facts for $1 ($WORK_DIR/probe/$1)" >&2
        return 1
    }
    awkrun '#@awk usable_cores' "$WORK_DIR/probe/$1" "${2:-count}" "${3:-}" || return 1
}

# Calibration measures on the workload own files when filename_format can
# address the grid ($filenum and $jobnum, no $jobname, which would resolve to
# the cal section name), else in a private scratch. One dataset then serves
# the seed, the cells and the staged jobs. Prints "unified <fmt>" or
# "scratch $jobnum.$filenum".
cal_namespace() {   # cal_namespace <set-dir>
    local f files=() LC_ALL=C
    [ -d "$1" ] || { log "ERROR: cal_namespace: no set directory $1" >&2; return 1; }
    for f in "$1"/[0-9]*; do
        [ -f "$f" ] && files+=("$f")
    done
    # the first jobfile (byte order) with a grid-addressable format decides;
    # the layout job mirrors the measured ones, so it never does
    awkrun '#@awk cal_namespace' ${files[@]+"${files[@]}"}
}

# Every directory the scratch's names imply, relative to the scratch root.
# fio never mkdirs, so the caller creates these before the seed writes.
cal_scratch_dirs() {   # cal_scratch_dirs <host> <sep> <fmt> <nj> <maxfilenum>
    awkrun '#@awk cal_scratch_dirs' "$1" "$2" "$3" "$4" "$5"
}

# fio --client exits 0 on a server-side jobfile rejection and the server
# stderr is gone, so ask the host fio to re-parse the jobfile: a dirty parse
# names the bad option, a clean one means the jobs died at setup.
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

# A failed calibration fio run files its evidence under cal/ in the bundle
# (WORK_DIR is tmpfs, wiped on exit) and has each host fio parse its jobfile.
# say: find the cause in fio own text and say it; quiet: check_fio_errors did.
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
        # One line per distinct error with its job count: how many failed the
        # same way matters most. The pid is normalized for counting only.
        shown=0
        while IFS= read -r l; do
            [ -n "$l" ] || continue
            log "$l" >&2
            shown=$((shown + 1))
        done <<EVIDEOF
$(LC_ALL=C awk -v what="$what" '
    #@awk cal_evidence' "$res")
EVIDEOF
        [ "$shown" -gt 0 ] || log "ERROR: $what: fio printed no error line before exiting; see ${res##*/} in the run bundle under cal/" >&2
    fi
    for h in "$@"; do
        [ -s "$WORK_DIR/cal/$h/$jf" ] || continue
        # cal_push staged the jobfiles on the master only; a worker fio can
        # parse only its own copy.
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
# Per shape: the engine first, then one search per (type, direction); cal_plan
# names each cell, bash runs it. A tuple is (qd nr fs nj), nj always recorded.
# README, Auto mode.
CAL_RUNTIME_FROM_ENV=${CAL_RUNTIME:+1}   # an exported CAL_RUNTIME beats the level default
CAL_RUNTIME=${CAL_RUNTIME:-30}   # seconds per search cell (plus a 2s ramp);
                         # "-a cal:15" sets it per run. It does not change how
                         # long the measured jobs run -- that is -x.
CAL_ENGINE_RUNTIME=${CAL_ENGINE_RUNTIME:-10}   # seconds per engine-comparison
                         # cell: they only have to rank the engines, and the
                         # searches that follow run full length
CAL_SETTLE=${CAL_SETTLE:-10}   # seconds after every write cell and after a
                         # seed: a write leaves a destage backlog the next cell
                         # would otherwise start inside
# One amount of data per job (README, Calibration measures what the test will
# run): FILESIZE_MIB split over the files, so the file ladder moves the file
# count and nothing else.
FILESIZE_MIB=${FILESIZE_MIB:-5120}
CAL_NR=${CAL_NR:-1}      # files per job in the first cell of every search,
                         # and in every latency cell: at iodepth 1 one IO is in
                         # flight per job, so more files add no concurrency
CAL_NR_LADDER=${CAL_NR_LADDER:-"1 2 4"}   # nrfiles tried per job count: at
                         # 2N and 4N for bandwidth, at every count for iops
CAL_BW_QD_LADDER=${CAL_BW_QD_LADDER:-"1 2 4 8 16"}   # bandwidth iodepths at
                         # 2N and 4N; 1 is kept so N x qd1 against 2N x qd1
                         # isolates what the siblings add
CAL_IOPS_QD_LADDER=${CAL_IOPS_QD_LADDER:-"1 2 4 8 16 32 64 128 256 512"}
# -a max searches numjobs at these (README, Auto mode); -a safe at 1 and 1.
CAL_MAX_BW_QD=${CAL_MAX_BW_QD:-16}
CAL_MAX_BW_NR=${CAL_MAX_BW_NR:-4}
CAL_MAX_IOPS_QD=${CAL_MAX_IOPS_QD:-32}
CAL_MAX_IOPS_NR=${CAL_MAX_IOPS_NR:-2}
CAL_LINE_PCT=${CAL_LINE_PCT:-95}   # bandwidth: line rate counts as reached here
CAL_KNEE_PCT=${CAL_KNEE_PCT:-98.5}   # the engine tie band: engines whose reading
                         # is within this percent of the best are tied, and the
                         # tie goes to ENGINE_ORDER
CAL_SHAPE_THR=${CAL_SHAPE_THR:-3}   # THE LEADER RULE (Frank, 2026-10-05): a cell
                         # takes the lead only when this percent better (bw and
                         # iops, every level); latency has no threshold
CAL_STOP_BELOW=${CAL_STOP_BELOW:-2}   # consecutive rungs without progress that
                         # end a ladder (cal only; brutal measures every rung)
CAL_CONFIRM=${CAL_CONFIRM:-3}   # before a peak is picked, the top cells get a
                         # second reading: contention only subtracts, so a
                         # second chance can raise a cell and never lower it
CAL_MEM_PCT=${CAL_MEM_PCT:-25}   # percent of a client's MemTotal that one cell's
                         # in-flight buffers (numjobs x iodepth x bs) may take
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

# One cell for ONE host, every input an argument: time_based, 2s ramp,
# direct=1, group_reporting=1. Always split affinity (an isolcpus range parks
# every job on one cpu). Never creates a file: that measures the extend path,
# so the seed creates. iops cells disable latency accounting, like the staged
# iops jobs.
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
        # Unified reads use the shared dataset; writes own their files per
        # client (leases).
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

# "<host> <value>" per client, read+write: bytes/s (bw) or IOPS (iops). Every
# cal-* entry is summed per host, so a cell with or without group_reporting
# reads right (a last-entry rule once kept 1 job of 28).
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
        #@awk cal_values'
}

# "<host> <mean-us> <iops>": lat_ns of the direction, entries folded by IO
# count.
cal_lat_values() {   # cal_lat_values <json> <read|write>
    [ -r "$1" ] || { echo "ERROR: cal_lat_values: cannot read $1" >&2; return 1; }
    json_use "$1"
    case $JSON_RC in
        2) echo "ERROR: cal_lat_values: no JSON in $1" >&2; return 1 ;;
        3) [ -z "$JSON_ERR" ] || echo "$JSON_ERR" >&2
           echo "ERROR: cal_lat_values: cannot parse fio JSON in $1" >&2; return 1 ;;
    esac
    printf '%s\n' "$JSON_FLAT" | LC_ALL=C awk -F'\t' -v d="$2" -v path="$1" '
        #@awk cal_lat_values'
}

# Fill "-" geometry in targets.final from the tuples: CLI > host file >
# calibration > tuner; the engine likewise. Without a host file, targets.final
# is synthesized so the tuples take the same path.
apply_cal_results() {
    [ -s "$WORK_DIR/cal.results" ] || return 0
    # Re-measures forced by -g, and --line-rate bandwidth, replace host-file
    # values instead of only filling gaps.
    awkrun '#@awk apply_cal_results' "$WORK_DIR/cal.results" "$WORK_DIR/targets.final" "$REGEN_LAYOUT" "${LINE_RATE_GBPS:--}" \
        || die "cannot apply the calibration results"
}

# Only this cell file goes to the master, one copy per push.
cal_push() {   # cal_push <basename> <host>...
    local base=$1 h dirs=(); shift
    rm -rf "$WORK_DIR/cal/.push" || return 1
    for h in "$@"; do dirs+=("$WORK_DIR/cal/.push/$h"); done
    mkdir -p "${dirs[@]}" || return 1
    # one awk copies every host's jobfile: a seed can name the whole fleet,
    # and a cp per host was a process per host
    awkrun '#@awk cal_push' "$WORK_DIR/cal" "$base" "$@" || return 1
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
    #@awk seed_estimate_line'
}

# Seed one representative dataset, jobs j < nj with files f < nr, read and
# write sides apart; a file at or above its size is skipped (fallocate=none
# makes that sound). Unified: reads use the shared set (README, Seeding).
# Prints the estimate first; stops if it cannot fit.
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
    # One session for the listing and df. No error suppression on find: without
    # GNU -printf it must fail loudly, or every run re-seeds everything.
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
    # Writers: the rep, except the unified read side, which its filesystem
    # group seeds round-robin by file (their fio servers are idle). A member
    # line is "<host> <dir> <cpus> <engine>", the rep first.
    local members="$WORK_DIR/cal/$host/seed.members" active i gf=- margs=()
    printf '%s\t%s\t%s\t%s\n' "$host" "$root" "$cpus" "$eng" > "$members"
    if [ "$unified" -eq 1 ] && [ "$rnj" -gt 0 ]; then
        # the rest of the group, one awk for all (a group can be the fleet)
        load_host_dirs
        [ ! -s "$WORK_DIR/groups" ] || gf="$WORK_DIR/groups"
        for i in "${!HOSTS[@]}"; do margs+=("${HOSTS[$i]}" "${HOST_DIRS[$i]}"); done
        awk '#@awk cal_seed_rep.members' "$host" "$eng" "$gf" "$WORK_DIR/cal/hostinfo" "${margs[@]}" >> "$members" \
            || die "$host: cannot list its filesystem group for the shared seed"
    fi
    # each member's seed jobfile lands in its own directory under cal/: one
    # mkdir for the group, whoever ends up with files to write
    local m mdirs=()
    while IFS=$'\t' read -r m _; do mdirs+=("$WORK_DIR/cal/$m"); done < "$members"
    mkdir -p "${mdirs[@]}" || die "$host: cannot create the seed jobfile directories"
    want=$(awkrun '#@awk cal_seed_rep' "$hname" "$rnj" "$rnr" "$wnj" "$wnr" "$FILESIZE_MIB" \
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
        # sparse write canvases by truncate, one pass per size, chunked to keep
        # the command small
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
    # a failed seed leaves its evidence outside the tmpfs workdir
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

# Seed what a cell of nj jobs x nr files needs in one direction; skips the
# listing and df when already covered.
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

# Client shapes in command-line order, the first host the representative
# (README, Client shapes). <out> gets one TSV line per shape (columns at the
# printf below); stdout the human form, stderr warnings. Also writes
# cal/hostinfo and cal/needs.*.
cal_shapes() {   # cal_shapes <out> <ladders>
    local caldir=.
    [[ $1 != */* ]] || caldir=${1%/*}
    # what the pins need from the seed is worked out from scratch below
    rm -f "$caldir"/needs.* || return 1
    awkrun '
    #@awk cal_shapes' "$1" "$2" "$WORK_DIR" "${ENGINE:--}" "$REGEN_LAYOUT" "$CAL_MEM_PCT" "${LINE_RATE_GBPS:--}" \
       "$CAL_NR $CAL_NR_LADDER" "$FILESIZE_MIB" "$(cal_wide)" "${HOSTS[@]}"
}

# Search rules (README, The search), stateless: from one history, print the
# next cell or the verdict:
#   cell <phase> <numjobs> <iodepth> <nrfiles> <runtime>
#   done <numjobs> <iodepth> <nrfiles> <message>
# History: <phase> <engine> <nj> <qd> <nr> <runtime> <value> [aux]; value in
# bytes/s, IOPS or mean us (aux IOPS). budget: the most cells possible.
cal_plan() {   # cal_plan <next|budget> <bw|iops|lat|lat1m> <read|write> <engine> <N> <linerate> <memcap> <history> <k=v>...
    awkrun '
    #@awk cal_plan' "$@"
}

# Per type the best reading wins (lowest for latency), a tie inside
# CAL_KNEE_PCT going to ENGINE_ORDER; pick_engine settles the tally the same
# way. Prints "<engine> <what each type said>".
cal_engine_pick() {   # cal_engine_pick <engine-cells-file>
    awkrun '#@awk cal_engine_pick' "$1" "$CAL_KNEE_PCT"
}

# Run one cell solo on <rep>; the reading lands in cal/reading. Never inside
# $(...): a die there ends only the substitution. Globals from cal_shape_run:
# CAL_SID, CAL_REP_DIR, CAL_REP_NAME, CAL_REP_N, CAL_REP_PHYS, CAL_REP_ALL.
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

# The planner names each cell, bash runs it; the tuple lands in
# cal/s<id>/tuple-<type>-<dirn> as "qd nr fs nj".
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

# One shape, solo: reuse host-file values, seed, pick the engine, search the
# rest. Leaves cal/s<id>/engine and one tuple file per slot.
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
    # engine cells: one per candidate per type (bw, iops, lat; lat1m stands in
    # for lat only when no 4k latency search is asked for)
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

# Removal for the files <name><sep><fmt> names under <hd> (the sweep glob),
# then the directories left empty.
cal_remove_cmd() {   # cal_remove_cmd <name> <sep> <fmt> <hd>
    awkrun 'BEGIN { print dataset_remove_cmd(ARGV[1] ARGV[2] ARGV[3], ARGV[4]) }' "$@"
}

# -u, after the last measured job: each host write set and, from each group
# first host, the shared read set; or the whole scratch. Never from calibrate:
# the measured jobs use the dataset, and a failed run keeps it.
cal_remove_dataset() {
    local i kind host ucmd args=() pids=() hs=() cmds="$WORK_DIR/cal-remove.cmds" gf=-
    load_host_dirs
    if [ -n "$CAL_NS_DIR" ]; then
        for i in "${!HOSTS[@]}"; do
            run_host "${HOSTS[$i]}" "rm -rf '${HOST_DIRS[$i]}$CAL_NS_DIR'" &
            pids+=($!); hs+=("${HOSTS[$i]}")
        done
    else
        # one awk for every command; the shared read set from each group first
        # host
        [ ! -s "$WORK_DIR/groups" ] || gf="$WORK_DIR/groups"
        for i in "${!HOSTS[@]}"; do
            host_name_v "${HOSTS[$i]}"
            args+=("${HOSTS[$i]}" "$HOST_NAME" "${HOST_DIRS[$i]}")
        done
        awkrun '#@awk cal_remove_dataset' "${CAL_SEP:-.}" "$CAL_FMT" "$gf" \
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

# Calibration own writes priced per filesystem before the first cell (README,
# Seeding): shared read sets for the widest reader, each rep write set for its
# widest cell, less what exists, pooled per weka filesystem. Other members are
# left to check_capacity. Over: die, or ask under --ignore-capacity.
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
    #@awk cal_capacity_check' "$WORK_DIR" "$shapes" "$ladders" "${CAL_NS_DIR-unset}" "${CAL_FMT:-\$jobnum.\$filenum}" \
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

# Pins checked against each shape aio room before anything starts: pinned nj
# x pinned qd (1 if open), when libaio is pinned or a candidate. Over: an
# alert and a stop, the host file untouched.
cal_aio_preflight() {   # cal_aio_preflight <shapes>
    awkrun '#@awk cal_aio_preflight' "$1"
    case $? in
        0) return 0 ;;
        3) die "calibration would exceed the kernel's aio room (above); nothing was run and the host file is unchanged" ;;
        *) die "cannot check the calibration pins against the kernel's aio room" ;;
    esac
}

# Before any fio server starts, and in a dry run: the shapes and the pin aio
# check. calibrate and the dry-run report reuse what this works out.
cal_preflight() {
    cal_mode || return 0
    local capdir=${SET_DIR_OVERRIDE:-$(workload_src_dir)}
    cal_ladders_once || die "cannot inspect $capdir for calibration"
    [ -n "$CAL_LADDERS" ] || return 0
    mkdir -p "$WORK_DIR/cal" || die "cannot create $WORK_DIR/cal"
    cal_shapes_once || die "cannot group the hosts into client shapes"
    cal_aio_preflight "$WORK_DIR/cal/shapes"
}

# The ladders (cal_required) and shapes (cal_shapes), worked out once:
# nothing they read changes before calibration.
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
    # NOT local: the seed, every cell and the staged jobs share one namespace.
    # CAL_NS_DIR is the subdirectory under each destination ("" = itself);
    # CAL_SEP joins host to format.
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

    # One cal.results line per member: engine, then (qd nr fs nj) per
    # GEOM_SLOTS slot, "- - - -" for a slot the set does not run.
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

    # Kept by default (re-seeding is the costliest part of a run). -u removes
    # it from main after the last measured job: those jobs use it, and a failed
    # run keeps it for the rerun.
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
# Every host reachable over ssh with $FIO_BIN, checked in parallel, every
# failure reported. Each check opens the host ControlMaster for the run.
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
    # A bare -C candidate that failed ssh is probably the set name: confirm
    # (5s, default yes), or assume so unattended.
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
# wekafs must be forcedirect (direct=1 alone leaves the client cache in the
# path); anything else must be a network filesystem, never a local disk,
# which is also what an unmounted weka mount point is.
NETWORK_FSTYPES="nfs nfs4 cifs smb3 smbfs lustre gpfs beegfs ceph fuse.ceph fuse.ceph-fuse glusterfs fuse.glusterfs panfs pvfs2 orangefs ocfs2 gfs2 afs cvfs quobyte fuse.quobyte fuse.daos fuse.juicefs fuse.mfs ${WEKATESTER_NETWORK_FSTYPES:-}"

# ok, "fail <mode>", network, or "local <type>"; printed and left in
# MOUNT_VERDICT.
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

# Creates a missing destination only when its nearest existing parent is
# wekafs in this same session: a weka client that restarted since the check
# leaves a root-disk mount point. Exit 4: not wekafs now.
create_dest_cmd() {   # create_dest_cmd <dir>
    printf '%s' "p='$1'; while [ ! -e \"\$p\" ]; do q=\$(dirname \"\$p\"); [ \"\$q\" != \"\$p\" ] || exit 4; p=\$q; done; [ \"\$(findmnt -T \"\$p\" -n -o FSTYPE)\" = wekafs ] || exit 4; mkdir -p -- '$1'"
}

# For a missing destination: the nearest existing ancestor, then its findmnt
# FSTYPE,OPTIONS. Nonzero when it does exist, or nothing does. dirname handles
# a trailing slash and stops at /.
missing_dir_probe_cmd() {   # missing_dir_probe_cmd <dir>
    printf '%s' "[ ! -e '$1' ] || exit 1; p='$1'; while [ ! -e \"\$p\" ]; do q=\$(dirname \"\$p\"); [ \"\$q\" != \"\$p\" ] || exit 1; p=\$q; done; printf '%s\\n' \"\$p\"; findmnt -T \"\$p\" -n -o FSTYPE,OPTIONS"
}

# One probe file as the fio user; on a shared filesystem one failing host
# usually means all.
probe_writable() {   # probe_writable <host> <dir>
    # the same session drops the host's name into the run's group file
    # there: collect_fs_groups hashes it once every host is through
    host_name_v "$1"
    run_host "$1" "p='$2'/.wekatester-write-probe.\$\$; : > \"\$p\" && rm -f \"\$p\"${GROUP_FILE:+ && printf '%s\\n' '$HOST_NAME' >> '$2/$GROUP_FILE'}"
}

# --- filesystem groups ---
# Each client appends its name to the run group file in its destination; equal
# sha256 means one directory, one group. Distinct files cannot hash alike: each
# ends with a name only its own clients appended. Writes $WORK_DIR/groups,
# "<host> <group>".
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

# The first host of <host> group lays out, prices and removes its shared read
# set; every host is one group when collect_fs_groups did not run.
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

# Asked once for every host that lacks the destination. -r/-n: 5s, default
# create, and created outright without a terminal; otherwise only a y creates.
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

# All workers: -d must not be a cached-mode wekafs mount, and must be writable
# by the login user (fio reports a worker EACCES so quietly the run "succeeds"
# with zero IO). A missing -d is created only under a wekafs mount, after one
# question (README, Caveats).
verify_mount_mode() {
    log "checking mount mode and writability of the destination on ${#HOSTS[@]} host(s)..."
    # one name per run, so two runs sharing a destination never read each
    # other's group lines (collect_fs_groups)
    [ -n "$GROUP_FILE" ] || printf -v GROUP_FILE '.wekatester-group.%(%s)T.%s.lst' -1 "$$"
    local host line verdict failed=() mode_fail=0 write_fail=0 local_fail=0 gone_fail=0 hd anc i ft
    local missing=() missing_dirs=() missing_parents=()
    local cached_hosts=() cached_modes=() mode who n
    # Three fan-outs: every host gets the same commands in the same order and
    # the messages come back in host order, as a serial walk produced them;
    # only the waiting overlaps. Per-host output goes to files under the work
    # dir, or a temp dir when the suite calls this phase alone.
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
        # Advise a remount only when a mount mode was the problem: when findmnt
        # failed everywhere, -d most likely does not exist.
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
# Daemons are tracked by pidfile only, never pkill by name: the host may run
# fio jobs that are not ours.
FIO_STARTED=0

# Kill the pidfile daemon and wait until every process of ours is gone (TERM
# up to 3s, then KILL). fio --server forks a child per connection, so the
# drain matches the full command line, anchored to the fio binary and
# carrying the pidfile path.
kill_fio_cmd() {   # kill_fio_cmd [priv]
    # An escalated server is root-owned: the kill needs the same escalator. The
    # ^ anchor is load-bearing: this shell carries the pattern in its own
    # cmdline (an unanchored pkill -9 once killed the teardown). taskset execs
    # fio, so argv starts with the binary.
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
        # a cpu list pins the server (children inherit the mask). The
        # escalation is for the taskset only: fio drops back to the login user
        # via runuser, so test files stay user-owned; no runuser means a root
        # fio, and the NOTE says so.
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

# The master must reach every worker on $FIO_PORT (fio would silently benchmark
# the survivors). One remote shell probes all at once; each probe is one
# statement (bash survives a failed exec redirection) printing "FAIL <host>",
# and DONE proves the snippet finished.
port_probe_cmd() {   # port_probe_cmd <host>... -> remote snippet
    local h cmd="${COORD_NPROC:+ulimit -Su $COORD_NPROC; }pids=''; for h in"
    for h in "$@"; do cmd="$cmd '$h'"; done
    cmd="$cmd; do ( timeout 3 bash -c \": </dev/tcp/\$h/$FIO_PORT\" || echo \"FAIL \$h\" ) & pids=\"\$pids \$!\"; done; wait \$pids; echo DONE"
    printf '%s' "$cmd"
}

# --- the limits a run must fit ----------------------------------------------
# Every client runs at once, so the limits that grow with the fleet are
# checked first. A soft limit short of the need is raised when the hard limit
# allows; otherwise the run stops, naming the limit and the host.
limit_short() {   # limit_short <limit|unlimited> <need>: the limit is a number below the need
    case $1 in (unlimited|''|*[!0-9]*) return 1 ;; esac
    [ "$1" -lt "$2" ]
}

# The controller needs an ssh master per host plus, during a fan-out, a
# subshell and an ssh client per host: three per host (302 for 100 measured).
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

# The coordinator: fio --client holds one connection per client and raises no
# limit, and the port check runs three processes per client from one shell.
# The raise rides those commands (COORD_NOFILE, COORD_NPROC).
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

# One ssh session to the master, every probe inside it: one session per
# worker fanned N sessions into one multiplexed connection, past MaxSessions
# (10) and MaxStartups, and 39 of 111 probes read as firewalls.
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
        # On loopback the usual culprit is the name resolving to ::1 while fio
        # listens on IPv4, not a firewall.
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
            # a privileged launch made a root-owned server: the kill needs the
            # same escalator or the run leaks a root fio
            priv=""
            [ -z "$AUTH_DIR" ] || [ ! -s "$AUTH_DIR/$host.priv" ] || IFS= read -r priv < "$AUTH_DIR/$host.priv" || :
            run_host "$host" "$(kill_fio_cmd "$priv"); rm -rf '$TARGET_DIR' '$TARGET_DIR.cal'" &
            pids+=($!)
        done
        # These pids only: a bare wait also waits on the run-log tees, which
        # exit only after cleanup returns. That is a deadlock.
        wait "${pids[@]}" || true
    fi
    if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
        # Close every ControlMaster at once (one at a time was seconds at a few
        # hundred hosts), then drop the work dir. -q silences the banner; a
        # failed -O exit still reports on stderr.
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
# Every credential against every client, first success wins (README,
# Authentication); each round tries the unconnected clients in parallel, and
# nothing dies here. Passwords: a fifo per attempt, a helper reading ONE line,
# NumberOfPasswordPrompts=1. Auth overrides go BEFORE $SSH_OPTS: ssh keeps the
# first value, and BatchMode=yes disables askpass.
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

# One connection attempt. external: is a user-owned master alive (ssh -O
# check, our ControlPath absent)? default/key: a master in our socket dir
# with BatchMode. pw: the same, through askpass.
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
            # Hold the fifo open read-write for the attempt (fd 4 is private to
            # it): a fifo drops its contents when the last fd closes, and the
            # helper open blocks until a writer exists. Our write cannot block;
            # the helper reads ONE line.
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

# The password goes back ONCE per attempt; a second question gets a failure,
# never a second fifo read (that hung the run). A host-key question gets no,
# as BatchMode does. A key passphrase question is refused without using the
# answer up, so ssh moves on to the password.
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
# Dumb by design: raw lines out, all interpretation local.
probe_remote_cmd() {
    # Raw facts out: weka cores from each wekanode PROCESS mask (per task,
    # pinned helper threads read as phantom cores); ident (the machine id);
    # shape facts (cpu_model, memtotal_kb, aio_max_nr, aio_nr, topo_*, nic,
    # weka_net or weka_net_err or weka_cli absent); measured per-cpu bind
    # tests. WEKATESTER_SYSROOT is for the suite only.
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

# Prove engine candidates with a real one-file job on each host destination
# (--enghelp lists only what fio was built with): -e, host-file engines, and
# under -a the tuner list. Results to engine.results ("host engine ok|fail");
# each probe engines line keeps only the engines that passed.
test_engines() {
    local host results="$WORK_DIR/engine.results" csv_engines="" cand et_pids=() _p
    mkdir -p "$WORK_DIR/et"
    : > "$results"
    if [ -n "$TARGETS_FILE" ] && [ -f "$TARGETS_FILE" ]; then
        csv_engines=$(awk -F, '#@awk test_engines.csv' "$TARGETS_FILE" | sort -u | tr '\n' ' ')
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
                # A broken engine can hang, and a direct-IO write on a sick
                # mount parks fio in D state, where SIGKILL and timeout(1) both
                # stall. So: background the bounded job, poll it, and abandon
                # it if it will not die. A working engine takes milliseconds.
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
    # SCOPED wait: a bare wait also waits on the run-log tees, which exit only
    # after finalize; it hangs silently here.
    for _p in "${et_pids[@]}"; do wait "$_p"; done
    # rewrite each probe's engines line to the proven subset (untested
    # engines are dropped only in auto mode, where the list WAS the tests)
    if [ -n "$AUTO_LEVEL" ]; then
        local none=() c nolist
        # one awk for the fleet: each engines line becomes the engines that
        # passed; hosts where none did come back one per line
        nolist=$(awkrun '#@awk test_engines' "$results" "$WORK_DIR/probe" "${HOSTS[@]}") || die "cannot record the proven ioengines"
        while IFS= read -r host; do
            [ -z "$host" ] || none+=("$host")
        done <<<"$nolist"
        # A host with no proven engine would fail later under an error that no
        # longer names the cause, and the workdir dies with the process: quote
        # the evidence now.
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
        host=$(awk '#@awk test_engines.pinned' "$ENGINE" "$results" "${HOSTS[@]}")
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
    bad=$(awk '#@awk finalize_targets' "$WORK_DIR/targets.final" "$WORK_DIR/engine.results" "${HOSTS[@]}")
    if [ -n "$bad" ]; then
        host=${bad%% *}; eng=${bad#* }
        [ ! -f "$WORK_DIR/et/$host.$eng.out" ] || tail -5 "$WORK_DIR/et/$host.$eng.out" >&2
        die "host file assigns ioengine '$eng' to $host but its test job failed (fio output above)"
    fi
}

# cpus_allowed enforcement: a requested list must already be allowed (taskset
# -cp) or need a passwordless escalator to launch fio under taskset -c; an
# overlap with weka cores is fatal without one, a warning with one. The
# decision lands in $WORK_DIR/auth/<host>.priv and <host>.cpus.
check_cpu_pinning() {
    local host req cur priv ncpus
    # local mode never ran establish_connections; the lifecycle still reads
    # the same per-host files
    [ -n "$AUTH_DIR" ] || { AUTH_DIR="$WORK_DIR/auth"; mkdir -p "$AUTH_DIR"; }
    # One awk for every host (six per host took 20s at 451 hosts). Per host
    # with a request, in host order: host, request, taskset, cpu count, four
    # cpu sets, comma-joined flags, then the escalator prefix (it has spaces);
    # "-" for empty.
    awkrun '
    #@awk check_cpu_pinning' "$WORK_DIR/targets.final" "$WORK_DIR/probe" "${AUTO_LEVEL:--}" "${HOSTS[@]}" \
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
                # safe with cpus_allowed_policy=split beside every list: each
                # job holds one cpu, and single-cpu affinity cannot collapse
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
        # escalate ONLY where the effective mask cannot be self-applied:
        # privileges are as-needed, never just because they exist
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

# A weka CLI on the master: as the login user first, ONE retry under the
# escalator on failure, then the caller fallback. No caller at present; kept
# as the tested way to reach the weka CLI for a future master-side fact.
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
    log "probing ${#HOSTS[@]} worker(s)..."
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
        lack=$(awkrun '#@awk probe_workers' "$ENGINE" "$WORK_DIR/probe" "${HOSTS[@]}")
        [ -z "$lack" ] \
            || die "ioengine '$ENGINE' is not available (fio --enghelp) on: $lack"
    fi
}

# --- capacity check (every run) ----------------------------------------------------
# Per host, the staged variants per filename_format namespace, each costing its
# largest footprint (or the staged layout total if larger), against that host
# own df (README). Over: die, or ask under --ignore-capacity. preview (a dry
# run under -a): report, labelled, and stop nothing.
check_capacity() {   # check_capacity [preview]
    local host pids=() i failed=0 preview=${1:-}
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
    #@awk check_capacity' "$WORK_DIR" "$WORK_DIR/staged.list" "$preview" "${HOSTS[@]}"
    case $? in
        0) return 0 ;;
        3) ;;
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
# The layout job runs first: jobfiles run serially and the coordinator waits
# for every client, so it is a cross-client barrier (README, Workloads).
LAYOUT_JOB="000-wekatester-layout.job"
LAYOUT_MARKER="# wekatester-layout: generated"

# A layout job is recognized by its reserved name or its marker line, so a
# renamed copy in a custom set is still treated as layout.
is_layout_file() {   # is_layout_file <path>
    [ -f "$1" ] || return 1
    case "${1##*/}" in "$LAYOUT_JOB") return 0 ;; esac
    head -3 "$1" | grep -q "^${LAYOUT_MARKER}" 2>&1
}

# Group a set jobfiles by namespace, one create_only section per contributor.
# Deterministic, so the embedded sha256 identifies a pristine file, which -a
# may re-derive per host.
generate_layout() {   # generate_layout <setdir> <outdir>
    local f files=() out n body sha path LC_ALL=C
    [ -d "$1" ] || { log "ERROR: generate_layout: no set directory $1" >&2; return 1; }
    for f in "$1"/[0-9]*; do
        [ -f "$f" ] && files+=("$f")
    done
    # prints the namespace count, then the body the marker's digest covers
    out=$(awkrun '#@awk generate_layout' "$1" ${files[@]+"${files[@]}"}) || return 1
    n=${out%%$'\n'*}; body=${out#*$'\n'}
    sha=$(printf '%s' "$body" | sha256_hex) || return 1
    case "$2" in (*/) path="$2$LAYOUT_JOB" ;; (*) path="$2/$LAYOUT_JOB" ;; esac
    { [ -d "$2" ] || mkdir -p "$2"; } && printf '%s sha256=%s\n%s\n' "$LAYOUT_MARKER" "$sha" "$body" > "$path" \
        || return 1
    printf 'layout: generated %s (%s namespace(s))\n' "$path" "$n"
}

# --- host files (-t) --------------------------------------------------------------
# Format and folding: README, Host files. Two phases, since engine selectors
# need test results, tests need auth, auth needs logins: phase1 (pre-auth)
# logins and dirs, phase2 everything. Output per host, tab-separated, "-"
# unset: host login engine cpus dir, then nj/fs/nr/qd per GEOM_SLOTS slot.
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

# The directory an existing -C set name points at, lookup only. Shipped names
# return nothing: they are always customized via a copy.
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

# --- host identity -------------------------------------------------------------
# Internally a host is an ADDRESS (ssh target, fio --client=, a $WORK_DIR
# path): no slash, localhost in local mode. Host files and data files use
# host_name(): the address, or the short hostname locally; auto-written rows
# are <name>/<machine-id>, read back as the address.

# Machine id, cached per host: product_uuid (survives a reinstall, root-only
# on most kernels), else machine-id. Never required.
host_machine_id() {   # host_machine_id <host>
    local host=$1 cache="$WORK_DIR/ident/$1.id" out
    [ -d "$WORK_DIR/ident" ] || mkdir -p "$WORK_DIR/ident"
    if [ ! -f "$cache" ]; then
        # Read from the probe, which carried it: one awk, no round trip;
        # otherwise ask the host. -r tests instead of stderr suppression
        # (absent files are ordinary), and a FAILED run_host is said out loud.
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

# hostname -s, then HOSTNAME (gethostname, no resolution, so it answers where
# hostname -s fails to resolve) to its first label, then hostname. Empty when
# nothing answers.
local_short_hostname() {
    local n
    n=$(hostname -s) || n=""
    [ -n "$n" ] || n=${HOSTNAME%%.*}
    [ -n "$n" ] || n=$(hostname) || n=""
    printf '%s' "$n"
}

# Remote: the address. Local mode: the short hostname (LOCAL_NAME), or
# "localhost" only when the box has no name.
host_name() {   # host_name <host>
    host_name_v "$1"
    printf '%s' "$HOST_NAME"
}
# host_name without the subshell: a fork per host added up over the fleet.
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

# "addr=<host_identity>,..." for the fleet in one awk; only a host whose probe
# has no id makes its own round trip.
host_idents() {
    local h i=0 out="" files=() ids=() id
    for h in "${HOSTS[@]}"; do
        [ ! -s "$WORK_DIR/probe/$h" ] || files+=("$WORK_DIR/probe/$h")
    done
    if [ ${#files[@]} -gt 0 ]; then
        while IFS= read -r id; do ids+=("$id"); done < <(awk '
            #@awk host_idents' "${files[@]}")
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

# -a writeback into the host file, when one is in play (README, What lands in
# the host file). Fill-missing by default; -g overwrites without asking. A
# superseded line is commented out and its new version written directly below
# it: two live lines for one host would trip the duplicate-host check.
writeback_targets() {
    [ -n "$AUTO_LEVEL" ] || return 0
    local wb="$TARGETS_FILE" mode=fill
    [ -n "$wb" ] || { [ -n "$SET_DIR_OVERRIDE" ] && wb="$SET_DIR_OVERRIDE/hostlist.csv"; }
    [ -n "$wb" ] && [ -f "$wb" ] || return 0
    # -g: derived and measured values win, no prompt. host, login and
    # allowed_cpus on the host OWN row are protected in the merge; a generic
    # row is never edited, and the host line beside it records what the run
    # resolved.
    [ "$REGEN_LAYOUT" -eq 0 ] || mode=overwrite
    # --line-rate measured the bandwidth slots again: their tuples replace the
    # row in fill mode too. What does each host OWN row provide?
    resolve_targets hostonly "$wb" - - "${WORK_DIR}/engine.results" "${HOSTS[@]}" \
        > "$WORK_DIR/targets.hostrows" || : > "$WORK_DIR/targets.hostrows"
    local h ident=""
    ident=$(host_idents)
    list_staged "$WORK_DIR/staged.list" &&
    WEKATESTER_HOST_ALIAS=$(host_alias_env "${HOSTS[@]}") \
    WEKATESTER_HOST_IDENT=$ident \
    awkrun '
    #@awk writeback_targets' "$wb" "$mode" "$WORK_DIR" "${LINE_RATE_GBPS:--}" "${HOSTS[@]}" || die "host file writeback failed ($wb)"
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

# targets_field for many hosts in one awk: one line each, "" for no row.
targets_column() {   # targets_column <fieldno> <file> <host>...
    awk '#@awk targets_column' "$@"
}

# host_dir for the fleet in one awk, into HOST_DIRS in HOSTS order. The
# resolution changes between phases, so each phase that walks the fleet loads
# it again.
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
    # the probe emits a PREFIX ("dzdo -n", "ksu -e", "pbrun"), the first of
    # dzdo/pbrun/sesu/pmrun/doas/ksu/sudo that runs true non-interactively
    [ -f "$WORK_DIR/probe/$1" ] || return 0
    awk '/^priv /{sub(/^priv /, ""); print; exit}' "$WORK_DIR/probe/$1"
}

# phase1: before the engine tests (no engine selectors yet); phase2: with
# engine.results, the finished resolution; hostonly: each host OWN row only,
# what the writeback merges against.
resolve_targets() {   # resolve_targets <phase1|phase2|hostonly> <csv> <cli_engine|-> <cli_dir|-> <results|-> <host>...
    WEKATESTER_HOST_ALIAS=$(host_alias_env "${@:6}") awkrun '#@awk resolve_targets' "$@"
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

# CUSTOM_SET to a directory of jobfiles. Writability is checked first: the
# next step is an editor session.
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
            # a shipped set name means customize a copy, never the set itself
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
    # An existing set plus an explicit -w refreshes it from that workload: it
    # destroys edits, so it takes a real yes, never unattended, and it REPLACES
    # the jobfiles (a stale layout job included) rather than overlaying them.
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

# The guided flow (README, Customizing workloads); -r and -n skip its prompts.
# A -C set owns its host file: the one this run resolved, else the source set
# copy, else the template. Edits apply this run, except logins: connections are
# already up.
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

# The host file -C will use, known BEFORE connecting: the set own copy, else
# the file customizing will copy in (ensure_set_hostfile choice, no side
# effect). Empty when there is none yet.
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
        # The host file is the primary editing surface; the jobfiles stay
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

    # -g always regenerates; otherwise an existing layout is kept unattended
    # and prompted (default keep) interactively; a set without one gets one
    # silently.
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

# Every die() path exits before this call, so a failed or partial run keeps
# the set and its edits.
finish_temp_set() {
    [ "$TEMP_REMOVE" -eq 1 ] || return 0
    log "removing temporary custom set $SET_DIR_OVERRIDE (not kept for reuse)"
    rm -rf "$SET_DIR_OVERRIDE"
}

# -n: print what a real run would do, from the master staged variants (what
# fio would read), and stop.
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
# Build $WORK_DIR/jobs/<host>/<job> for every host and copy the tree to
# $TARGET_DIR on $MASTER in one transfer.
JOBFILES=()      # basenames, in run order
JOBFILE_SRC=""   # local source directory
SET_DIR=""       # merged view actually staged: source files + generated layout

# Single source of truth for what runs and in what order -- the editor loop
# and the runner must never disagree on either.
discover_jobfiles() {   # discover_jobfiles <dir>; sets JOBFILES in run order
    # byte order whatever the locale: 021-latencyR.job before its -b twin
    # 021b-latencyR-1M.job (en_US collation would flip them)
    local job LC_ALL=C
    JOBFILES=()
    for job in "$1"/[0-9]*; do
        [ -f "$job" ] || die "no jobfiles found in $1"
        JOBFILES+=("${job##*/}")
    done
}

# Auto mode stages through the tuner; plain mode copies with the directory
# override (one layout, one code path).


stage_variants() {
    local srcdir=$1
    if [ -n "$AUTO_LEVEL" ]; then
        # Every level calibrates, so staging lays the measured tuples and the
        # host file over the jobfiles. Reads go to the shared read set wherever
        # the format can address it: that is what the read cells measured.
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
    # the host-file engine applies per host to every staged file, a re-derived
    # layout included; the -e post-pass in stage_jobfiles runs after and wins
    [ -f "$WORK_DIR/targets.final" ] || return 0
    stage_host_engines
}

# -a staging entry: stage_hosts auto with the old signature.
#   auto_tune <src> <work> <tier> <directory> <ignore_capacity 0|1> <targets-final|-> <host>...
# The environment carries WEKATESTER_TIER_LABEL, WEKATESTER_NS (unified: read
# jobs read the shared set) and WEKATESTER_IOPS_NOLAT=1. <ignore_capacity> is
# validated, not used: capacity is check_capacity, for every run.
auto_tune() {
    # Validate the flag slot first: an old-style call would shift a positional
    # into the host list and silently drop a host.
    if [ $# -lt 7 ] || { [ "$5" != 0 ] && [ "$5" != 1 ]; }; then
        echo "ERROR: auto_tune: usage: <src> <work> <tier> <directory> <ignore_capacity 0|1> <targets-final|-> <host>..." >&2
        return 1
    fi
    local src=$1 work=$2 tier=$3 dir=$4 targets=$6
    shift 6
    WORK_DIR=$work stage_hosts auto "$src" "$dir" "${WEKATESTER_TIER_LABEL:-$tier}" "$targets" "$@"
}

# Per-host staging, one awk for the fleet: each jobfile becomes
# jobs/<host>/<file> with the host destination and host-file geometry; under -a
# also what calibration measured on (README). A pristine layout is re-derived
# per host (derive_layouts). Writes staged.kinds: "J <file>", "L <layout>", "H
# <host>", "C <host the host file changed>".
stage_hosts() {   # stage_hosts <plain|auto> <src> <directory> <label|-> <targets|-> <host>...
    local mode=$1 src=$2 dir=$3 label=$4 targets=$5 f files=() dirs=() h kind name changed=() pristine=1
    shift 5
    [ -d "$src" ] || { echo "ERROR: staging: no jobfile set at $src" >&2; return 1; }
    for f in "$src"/[0-9]*; do [ -f "$f" ] && files+=("$f"); done
    for h in "$@"; do dirs+=("$WORK_DIR/jobs/$h"); done
    [ "$mode" = plain ] || dirs+=("$WORK_DIR/usable")
    mkdir -p "${dirs[@]}" || return 1
    # Pristine is judged on the SOURCE layout, once: the directory override
    # always changes the staged copies.
    layout_variant_pristine "$src" || pristine=0
    awkrun '
    #@awk stage_hosts' "$mode" "$WORK_DIR" "$dir" "$label" "$targets" "$pristine" ${#files[@]} ${files[@]+"${files[@]}"} "$@" \
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

# Each host layout job re-derived from its STAGED variants (staged.kinds), by
# generate_layout rules. Under -a a group shared read set is laid out ONCE, by
# its first host, for the widest reader in the group. No sha in the marker:
# it is re-derived every run.
derive_layouts() {   # derive_layouts <plain|auto> <label|-> <directory> <host>...
    awkrun '#@awk derive_layouts' "$1" "$2" "$3" "$WORK_DIR" "${@:4}"
}

# Each host's host-file engine (targets.final) onto every one of its staged
# files, as an ioengine= line (override_lines). One awk for the fleet.
stage_host_engines() {
    list_staged "$WORK_DIR/staged.list" || die "per-host engine override failed"
    awkrun '#@awk stage_host_engines' "$WORK_DIR/targets.final" "$WORK_DIR/staged.list" || die "per-host engine override failed"
}

# "<host><tab><path>" per staged file, hosts in order, files in byte order;
# "<host><tab>" for a host with none. One process for the fleet.
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
        awkrun '#@awk layout_variant_pristine' "$f" | { IFS= read -r want && [ "$(sha256_hex)" = "$want" ]; }
        return
    done
    return 0   # no layout staged yet: nothing to preserve
}

# -u: a final job unlinks every file the layout created, derived per host from
# the STAGED layout with unlink=1. Sizes become 4k so a missing file never
# costs a full write; the marker is dropped so it does not sort first.
UNLINK_JOB="999-wekatester-unlink.job"
stage_unlink_variants() {
    is_layout_file "$SET_DIR/${JOBFILES[0]}" \
        || die "no layout job at position one; cannot derive the -u unlink job"
    # one awk for the fleet, every host's from its own staged layout variant
    awkrun '#@awk stage_unlink_variants' "${JOBFILES[0]}" "$UNLINK_JOB" "$WORK_DIR/jobs" "${HOSTS[@]}" \
        || die "cannot derive the -u unlink job"
    JOBFILES+=("$UNLINK_JOB")
}

# Stamp key=value into a staged variant: replace every line, else insert into
# [global] (created if missing), as the directory override does.
override_variant_key() {   # override_variant_key <file> <key> <value>
    awkrun '#@awk override_variant_key' "$@"
}

# override_variant_key for the fleet in one awk ("measured": skip layout
# jobs); per file and key it was minutes at a few hundred hosts.
override_staged() {   # override_staged <all|measured> <key> <value> [<key> <value>]...
    list_staged "$WORK_DIR/staged.list" || return 1
    awkrun '#@awk override_staged' "$WORK_DIR/staged.list" "$@"
}

# Predictable paths (README, Workloads): unique_filename=0 and a "<name>."
# prefix on filename_format; a $clientuid format keeps its own scheme. The same
# pass stamps cpus_allowed_policy=split on every cpu list, and gives a pinned
# host list to variants without cpus_allowed.
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
    #@awk stamp_unique_names' "$WORK_DIR/staged.list" "${args[@]}" || die "cannot stamp deterministic filenames"
}

# -b: a 1MiB twin beside every latency jobfile (bs and blocksize set to 1Mi,
# or bs=1Mi added to [global]), same files and sections, named to run right
# after it. A file already at 1MiB gets none. -a files it under lat1m.
stage_bulk_twins() {   # stage_bulk_twins <set-dir>
    set_entries "$1" || return 1
    awkrun '#@awk stage_bulk_twins' "$1" ${SET_ENTRIES[@]+"${SET_ENTRIES[@]}"}
}

# -a: a one-job twin beside every latency jobfile (-b twins included), named
# to sort right before it; same files and sections, so the layout covers it.
stage_floor_twins() {   # stage_floor_twins <set-dir>
    set_entries "$1" || return 1
    awkrun '#@awk stage_floor_twins' "$1" ${SET_ENTRIES[@]+"${SET_ENTRIES[@]}"}
}

# "f<name>" per regular file, "o<name>" for anything else, in byte order: a
# twin may take neither name. Into SET_ENTRIES.
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

# Once everything is staged, each host libaio jobs are held against its probed
# aio room: the planner guards its own cells, but a staged job can come from a
# host-file tuple, -e libaio, or a widened jobfile. Over the room: stop before
# the first test (Frank, 2026-10-02).
check_aio_room() {
    [ -d "$WORK_DIR/probe" ] || return 0
    # one awk for the fleet: per host its probed room, then its staged files
    list_staged "$WORK_DIR/staged.list" && awkrun '#@awk check_aio_room' "$WORK_DIR" "$WORK_DIR/staged.list"
    case $? in
        0) ;;
        # stop before anything runs (Frank, 2026-10-02); nothing was written
        3) die "the kernel's aio room would be exceeded (above); nothing was run and the host file is unchanged" ;;
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

    # Source files plus a layout job: a set own layout file is kept, any other
    # set gets one generated here, never in the source dir.
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
    # The layout job must run FIRST to be a barrier, whatever its name sorts
    # as.
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
        # -e beats the jobfiles and the tuner in every variant, the layout
        # included.
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
# Report directives: "# report <items>" or "#report <items>", at least one
# space after report so prose ("# reporting...") is not one; a bare "# report"
# matches nothing and everything is reported.
report_directive() {
    sed -n 's/^#[[:space:]]*report[[:space:]]\{1,\}//p' "$1" | tr '\n' ' '
}

# One results file per job, so a crashed suite keeps everything measured.
# --- run bundle -----------------------------------------------------------------
# $OUTPUT_DIR/<date>-<time>/, folded into <date>-<time>.tgz at exit for every
# outcome (README, Output).

# Everything printed is also written to $RUN_DIR/wekatester.log. Two fifos
# and two tees, not process substitution: bash before 5.1 cannot wait on a
# substituted process, and finalize must drain the log before archiving.
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

# Per-host system context, one file per item under sysinfo/<host>/ (README,
# Output). A missing tool or file records "not available".
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

# "=== WEKATESTER_SYSINFO <item> ===" sections into
# sysinfo/<host>/<item><suffix>: one awk for the fleet, each output closed as
# the next opens.
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
        #@awk split_sysinfo' "${files[@]}"
}

# PSI and load at start and again at teardown, plus the sar slice covering the
# run when sysstat keeps one.
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

# The staged variants are the execution truth: a -C temp set may be gone, and
# -a rewrites geometry per host.
snapshot_jobfiles() {
    mkdir "$RUN_DIR/fio-jobfiles" || die "cannot create $RUN_DIR/fio-jobfiles"
    cp -R "$WORK_DIR/jobs/." "$RUN_DIR/fio-jobfiles/" \
        || die "cannot copy the staged jobfiles into $RUN_DIR/fio-jobfiles"
}

# Runs in the EXIT trap after cleanup, so it must never die: a tar failure
# leaves the directory and says so.
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

# fio --client exits 0 when worker jobs fail, so read success from the results:
# a nonzero job error, or a measured job whose last entry per host moved
# nothing. Layout jobs skip the second test; a silent layout failure trips the
# next job.
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
        #@awk check_fio_errors')
    [ "$bad" != NONE ] || { echo "$path: fio returned no per-job stats -- the jobs did not run" >&2; return 1; }
    [ -n "$bad" ] || return 0
    local line kind h job e desc
    while IFS=$'\t' read -r kind h job e; do
        case "$kind" in
            E) desc=$(errno_text "$e"); echo "ERROR: $h: job '$job' error $e${desc:+ ($desc)}" >&2 ;;
            Z) echo "ERROR: $h: measured job moved no data (zero bytes, zero ios)" >&2 ;;
        esac
    done <<<"$bad"
    # fio log text before the first "{" names the cause; matched ignoring case
    LC_ALL=C awk '
        #@awk check_fio_errors.cause' "$path" >&2
    return 1
}

# fio does not create the directory tree a filename_format implies
# (create_on_open never mkdirs; create_only on 3.28 only each job first file
# dir), so the grid dirs are made here from the staged layout first.
ensure_layout_dirs() {   # ensure_layout_dirs <staged layout jobref>
    local host cmd i pids=() hs=() args=() out="$WORK_DIR/layout-dirs.cmd"
    for host in "${HOSTS[@]}"; do args+=("$host" "$WORK_DIR/jobs/$host/$1"); done
    # every directory each section filename_format implies, mkdir -p lines of
    # 400 to stay below the ssh packet limit; one awk for the fleet
    awkrun '#@awk ensure_layout_dirs' "${args[@]}" > "$out" || die "cannot derive the layout directory set"
    while IFS=$'\t' read -r host cmd; do
        run_host "$host" "$cmd" &
        pids+=($!); hs+=("$host")
    done < "$out"
    # scoped wait, as always: the run-log tees are siblings here
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || die "cannot pre-create layout directories on ${hs[$i]}"
    done
}

# Per-namespace grid facts from a staged layout, one line each:
# "<file_bytes>\t<path_glob>\t<maxdepth>\t<expected_total_bytes>"; maxdepth
# bounds find.
#   layout_grid_spec <jobfile>                     -> stdout
#   layout_grid_spec -o <dir> <host> <jobfile>...  -> <dir>/<host>.gridspec;
#     stdout names hosts lacking fallocate=none
layout_grid_spec() {
    awkrun '
    #@awk layout_grid_spec' "$@"
}

# Evidence, not markers (README, Workloads): per namespace, delete files whose
# size deviates from the spec and count the bytes that match, so create_only
# writes only what is missing. Sound only under fallocate=none. A dry run skips
# the sweep and prices the full grid.
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
    # a kept layout job without fallocate=none can leave full-size hollow files
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
            # sufficiency, not equality: only files SMALLER than expected are
            # deviants (fio uses the first N bytes); the per-section cap bounds
            # overcredit of a shared oversize file. The kept calibration
            # scratch is excluded, or a nested glob (*/*) would delete and
            # credit its files.
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

# The coordinator command line: fio on the master, "--client=<host> <its
# jobfile>" per worker. --eta=never: the SEND_ETA polls are how a saturated
# worker gets dropped mid-layout.
fio_client_cmd() {   # fio_client_cmd <job> [host...]: every host, or the ones named
    local job=$1 host cmd="${COORD_NOFILE:+ulimit -Sn $COORD_NOFILE && }'$FIO_BIN' --output-format=json --eta=never"
    shift
    [ $# -gt 0 ] || set -- "${HOSTS[@]}"
    for host in "$@"; do
        cmd="$cmd --client=$host '$TARGET_DIR/$host/$job'"
    done
    printf '%s' "$cmd"
}

# Hosts whose staged <job> holds a job section. A group follower whose files
# are all the shared read set has a [global]-only layout, which fio refuses,
# so it sits the layout and its unlink out. An unreadable variant is kept so
# fio says what is wrong.
job_clients() {   # job_clients <job>
    awkrun '#@awk job_clients' "$WORK_DIR/jobs" "$1" "${HOSTS[@]}"
}

# The master shell gets the whole command line as ONE argument, capped at
# MAX_ARG_STRLEN (128 KiB): E2BIG after staging. Checked at staging with 8 KiB
# headroom, so a dry run reports it too (README, Caveats).
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

# The same ceiling before anything starts on the hosts, pricing the longest
# job name staging can produce: a set jobfile plus the 9 bytes of its longest
# twin, never under the 25-byte layout and unlink names.
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
            # The layout job is a barrier: a duration, not a summary. The sweep
            # already ran at staging, so this create_only pass writes only what
            # is missing.
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
        # fio keys client_stats by the --client= name, not the worker hostname;
        # local mode reports as localhost.
        summarize "$outfile" "$report" "${HOSTS[*]}"
    done
    log "raw fio results: $RUN_DIR/"
    echo
}

# $1 a results .json, or a bundle .tgz (every results file in job order,
# extracted once to a temp dir); $2 report items (empty = all); $3 expected
# hosts (empty = unchecked, as in -s).
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
        # layout results are barriers: the reserved names, plus any bundled
        # jobfile with the layout marker (/dev/null keeps awk off stdin without
        # one)
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

# summ_one <file> <label> <items> <expected> <file|bundle>. File mode: an error
# on stderr, return 1; bundle: "    (reason)" and the next file goes on.
summ_one() {
    local f=$1 label=$2 items=$3 expected=$4 mode=$5 out
    json_use "$f"
    case $JSON_RC in
        2) out="ERR	$label: no JSON in fio output" ;;
        3) out="ERR	$label: cannot parse fio JSON: ${JSON_ERR#json: }" ;;
        *) out=$(printf '%s\n' "$JSON_FLAT" | LC_ALL=C awk -F'\t' -v label="$label" -v items=" $items " -v expected="$expected" '
        #@awk summ_one') ;;
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

    # A Linux controller (-s above reads a bundle anywhere). Plain uname, PATH
    # resolved so the suite can stub it.
    [ "$(uname -s)" = Linux ] \
        || die "wekatester runs on a Linux controller, not $(uname -s); -s summarizes a run bundle anywhere"
    resolve_local_mode
    # -i split and key paths checked before anything exists to clean up.
    validate_credentials
    # -C needs a terminal and an editor; say so now, not after setup.
    if [ "$CUSTOMIZE" -eq 1 ] && [ "$FAST_TRACK" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        require_interactive "-C"
        resolve_editor
    fi

    log "wekatester $VERSION: ${#HOSTS[@]} worker(s), master $MASTER, workload $WORKLOAD"
    echo

    WORK_DIR=$(mktemp -d "$STAGE_BASE/wt.XXXXXX") || die "cannot create staging dir in $STAGE_BASE"
    make_ctrl_dir
    mkdir -p "$WORK_DIR/jobs"
    # One connection per host, multiplexed, for the WHOLE run (cleanup -O exit
    # is the teardown): a master that lapsed would reconnect mid-run,
    # impossible with -p. %C hashes host/port/user. Apart from SSH_OPTS: a host
    # on a user-owned master gets SSH_OPTS but not these. Local mode needs
    # none.
    [ "$LOCAL_MODE" -eq 1 ] || \
        CONTROL_OPTS="-o ControlMaster=auto -o ControlPath=$CTRL_DIR/%C -o ControlPersist=yes"

    # A bare trap on INT/TERM runs cleanup and RESUMES. Signals exit instead;
    # the EXIT trap alone runs cleanup (idempotent), keeps the status, and
    # finalizes the bundle after it so the log holds the teardown.
    trap 'rc=$?; cleanup; finalize_run_dir; exit $rc' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # After the traps (half-established masters still get torn down), before
    # preflight (every later ssh rides the winning session). -t: the pre-auth
    # phase supplies the per-host logins the auth rounds use.
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
        # -C without -t: the set host file is honored as if -t named it.
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
    # After host validation (no editing against a broken cluster), before any
    # daemon (nothing to tear down while an editor is open). The prompt fd
    # closes before the run so no child inherits the terminal.
    if [ "$CUSTOMIZE" -eq 1 ]; then
        customize_jobfiles
        # The set host file is now the targets file: refresh phase1 and
        # re-verify mounts; login edits wait for the next run.
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
        # under -a the staged sizes are the jobfiles' own until calibration
        # runs: a preview, not a verdict
        if cal_mode; then check_capacity preview; else check_capacity; fi
        dry_run_report
        exit 0
    fi
    # After the dry-run exit (-n creates no bundle), before any daemon (an
    # unwritable -o must not cost a benchmark).
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
