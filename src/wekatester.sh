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

#@include sh/base.sh

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

#@include sh/awk.sh

#@include sh/fiojson.sh

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

#@include sh/calibrate.sh

#@include sh/preflight.sh

#@include sh/connect.sh

#@include sh/probe.sh

#@include sh/layout.sh

#@include sh/hosts.sh

#@include sh/customize.sh

#@include sh/stage.sh

#@include sh/run.sh

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
