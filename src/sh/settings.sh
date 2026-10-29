# --- settings (WT_*) -------------------------------------------------------------
# README, Settings. Each setting comes from one source: the CLI flag, else the
# environment, else the -t host file, else the default. Kinds: flag (becomes
# its long option and goes through parse_args), switch (0/1), count, default
# (-d/-e: a run-wide default the host rows refine), env (read where used).
# Columns: name kind option help-key.
SETTINGS_TABLE="WT_DIRECTORY default --directory directory
WT_WORKLOAD flag --workload workload
WT_FIO_BIN flag --fio-bin fio_bin
WT_OUTPUT flag --output output
WT_ENGINE default --engine engine
WT_AUTO flag --auto auto
WT_LINE_RATE flag --line-rate line_rate
WT_CAL_CLIENTS flag --cal-clients cal_clients
WT_IGNORE_CAPACITY switch --ignore-capacity ignore_capacity
WT_ANY_FS switch --any-fs any_fs
WT_ALLOW_FIO_MISMATCH switch --allow-fio-mismatch allow_fio_mismatch
WT_IDENTITY flag --identity identity
WT_PASSWORD count --password password
WT_BULK switch --bulk bulk
WT_DURATION flag --duration duration
WT_UNLINK switch --unlink unlink
WT_VERBOSE count -v verbose
WT_ENGINE_TEST_TIMEOUT env - -
WT_SYSINFO_TIMEOUT env - -
WT_SETTLE env - -
WT_STAGE_BASE env - -"
# the built-in values, taken before any parse moves them
declare -gA SETTING_DEFAULT=([WT_DIRECTORY]=$DIRECTORY [WT_WORKLOAD]=$WORKLOAD
    [WT_FIO_BIN]=$FIO_BIN [WT_OUTPUT]=$OUTPUT_DIR [WT_IGNORE_CAPACITY]=0 [WT_ANY_FS]=0
    [WT_ALLOW_FIO_MISMATCH]=0 [WT_PASSWORD]=0 [WT_BULK]=0 [WT_UNLINK]=0 [WT_VERBOSE]=0 [WT_CAL_CLIENTS]=1
    [WT_ENGINE_TEST_TIMEOUT]=15 [WT_SYSINFO_TIMEOUT]=300 [WT_SETTLE]=2 [WT_STAGE_BASE]=shm)
declare -gA SETTING_SRC=()   # name -> where its value came from, for errors
DEFAULT_ENGINE=""            # WT_ENGINE from the environment or the host file

# The template's own help for the settings whose flag text would mislead:
# those with no flag, and -d/-e, which as settings are defaults.
own_setting_help() {   # own_setting_help <name>
    case $1 in
        (WT_DIRECTORY) echo "the default target directory for test files (default ${SETTING_DEFAULT[WT_DIRECTORY]}); a host-file line's destination_folder beats it, and -d beats both" ;;
        (WT_ENGINE) echo "the default fio ioengine (empty: the jobfile's own, else, outside -a, the first of io_uring, libaio, psync that passes its test); a host-file line's ioengine beats it, and -e beats both" ;;
        (WT_ENGINE_TEST_TIMEOUT) echo "seconds an ioengine's test job may run before it is killed and counts as a failure (default 15)" ;;
        (WT_SYSINFO_TIMEOUT) echo "seconds each host's system-information and pressure capture may run before it is cut off; the run carries on (default 300)" ;;
        (WT_SETTLE) echo "seconds to wait after the fio servers start before the first connection to them (default 2)" ;;
        (WT_STAGE_BASE) echo "where the controller keeps its working files: shm (/dev/shm, the default) or mktemp (\$TMPDIR, else /tmp)" ;;
    esac
}

# Which settings the command line sets: a token that starts with - before
# -- is an option (a separate value never does: need_arg). CLI_INFO: -h or
# --version, which read no setting.
declare -gA CLI_SET=()
CLI_INFO=""
cli_settings_seen() {   # cli_settings_seen <arg>...
    local a o
    CLI_SET=(); CLI_INFO=""
    for a in "$@"; do
        [ "$a" != -- ] || break
        case $a in (-*) ;; (*) continue ;; esac
        o=$(normalize_opt "$a")
        case $o in
            (-d*|--directory|--directory=*) CLI_SET[WT_DIRECTORY]=1 ;;
            (-w*|--workload|--workload=*) CLI_SET[WT_WORKLOAD]=1 ;;
            (-f*|--fio-bin|--fio-bin=*|--local-fio|--local-fio=*) CLI_SET[WT_FIO_BIN]=1 ;;
            (-o*|--output|--output=*) CLI_SET[WT_OUTPUT]=1 ;;
            (-e*|--engine|--engine=*) CLI_SET[WT_ENGINE]=1 ;;
            (-a*|--auto|--auto=*) CLI_SET[WT_AUTO]=1 ;;
            (--line-rate|--line-rate=*) CLI_SET[WT_LINE_RATE]=1 ;;
            (--cal-clients|--cal-clients=*) CLI_SET[WT_CAL_CLIENTS]=1 ;;
            (--ignore-capacity) CLI_SET[WT_IGNORE_CAPACITY]=1 ;;
            (--any-fs) CLI_SET[WT_ANY_FS]=1 ;;
            (--allow-fio-mismatch) CLI_SET[WT_ALLOW_FIO_MISMATCH]=1 ;;
            (-i*|--identity|--identity=*) CLI_SET[WT_IDENTITY]=1 ;;
            (-p*|--password|--password=*) CLI_SET[WT_PASSWORD]=1 ;;
            (-b|--bulk) CLI_SET[WT_BULK]=1 ;;
            (-x*|--duration|--duration=*) CLI_SET[WT_DURATION]=1 ;;
            (-u|--unlink) CLI_SET[WT_UNLINK]=1 ;;
            (-v|-vv|-vvv) CLI_SET[WT_VERBOSE]=1 ;;
            (-h|--help|--version) CLI_INFO=1 ;;
        esac
    done
}

# One setting as the arguments parse_args takes, checked by parse_args
# itself in a subshell so an error names its source. -> SETTING_ARGS
setting_args() {   # setting_args <source> <name> <kind> <option> <value>
    local src=$1 name=$2 kind=$3 opt=$4 v=$5 err i
    SETTING_ARGS=()
    case $kind in
        (switch) case $v in
                     (0) ;;
                     (1) SETTING_ARGS=("$opt") ;;
                     (*) die "$src: $name takes 0 or 1, not '$v'" ;;
                 esac ;;
        (count) case $v in
                    (*[!0-9]*) die "$src: $name takes a count (0 for none), not '$v'" ;;
                    (0) ;;
                    (*) if [ "$opt" = -v ]; then
                            [[ $v =~ ^0*[0-3]$ ]] || die "$src: $name takes a count 0..3, not '$v'"
                            for ((i = 0; i < 10#$v; i++)); do SETTING_ARGS+=(-v); done
                        else
                            SETTING_ARGS=("$opt=$v")
                        fi ;;
                esac ;;
        (*) SETTING_ARGS=("$opt=$v") ;;
    esac
    [ ${#SETTING_ARGS[@]} -gt 0 ] || return 0
    err=$( (PARSE_PRECHECK=1; parse_args "${SETTING_ARGS[@]}") 2>&1 ) \
        || die "$src: $name: ${err##*ERROR: }"
}

# -d/-e from a setting: the run-wide default, never the flag's override of
# the host rows (Frank, 2026-10-26).
setting_default() {   # setting_default <name> <value>
    if [ "$1" = WT_DIRECTORY ]; then
        DIRECTORY=$2; trim_directory
    else
        DEFAULT_ENGINE=$2
    fi
}

# The environment's settings, then the command line: one parse, the CLI
# last. A setting the CLI sets is not read. Combinations wait for the host
# file (check_args in main).
settings_parse() {   # settings_parse <arg>...
    local name kind opt key v args=() defs=()
    cli_settings_seen "$@"
    # help and version text never depends on the environment
    if [ -n "$CLI_INFO" ]; then parse_args "$@"; return; fi
    while read -r name kind opt key; do
        v=${!name-}
        [ -n "$v" ] && [ -z "${CLI_SET[$name]:-}" ] || continue
        SETTING_SRC[$name]="environment $name"
        case $kind in
            (env) continue ;;
            (default) setting_args "environment" "$name" "$kind" "$opt" "$v"; defs+=("$name" "$v") ;;
            (*) setting_args "environment" "$name" "$kind" "$opt" "$v"; args+=("${SETTING_ARGS[@]}") ;;
        esac
    done <<<"$SETTINGS_TABLE"
    PARSE_PRECHECK=1 parse_args "${args[@]}" "$@"
    set -- "${defs[@]}"
    while [ $# -gt 0 ]; do setting_default "$1" "$2"; shift 2; done
    # a host file still to read checks them in main
    [ "$TARGETS" -eq 1 ] && [ -z "$SUMMARIZE_FILE" ] || check_args
}

# The host file's settings, for what neither the CLI nor the environment
# set, then the combination checks.
settings_from_file() {
    local out line name v kind opt key args=() defs=()
    out=$(awkrun '#@awk read_settings' "$TARGETS_FILE" "$(settings_names)") \
        || die "host file settings failed ($TARGETS_FILE)"
    while IFS=$'\t' read -r line name v; do
        [ -n "$name" ] || continue
        [ -z "${CLI_SET[$name]:-}" ] && [ -z "${SETTING_SRC[$name]:-}" ] || continue
        SETTING_SRC[$name]="$TARGETS_FILE:$line"
        read -r _ kind opt key < <(grep "^$name " <<<"$SETTINGS_TABLE")
        case $kind in
            (env) printf -v "$name" '%s' "$v" ;;
            (default) setting_args "$TARGETS_FILE:$line" "$name" "$kind" "$opt" "$v"; defs+=("$name" "$v") ;;
            (*) setting_args "$TARGETS_FILE:$line" "$name" "$kind" "$opt" "$v"; args+=("${SETTING_ARGS[@]}") ;;
        esac
    done <<<"$out"
    [ ${#args[@]} -eq 0 ] || PARSE_PRECHECK=1 parse_args "${args[@]}" -- "${HOSTS[@]}"
    set -- "${defs[@]}"
    while [ $# -gt 0 ]; do setting_default "$1" "$2"; shift 2; done
}

# Without a host file there are no rows for WT_ENGINE to default: it is
# the engine for every host, as -e is.
settings_engine_default() {
    [ "$TARGETS" -eq 1 ] || [ -n "$ENGINE" ] || ENGINE=$DEFAULT_ENGINE
}

settings_names() {
    local name rest out=""
    while read -r name rest; do out="$out${out:+,}$name"; done <<<"$SETTINGS_TABLE"
    printf '%s' "$out"
}

# The settings with no flag, wherever they came from: checked once, before
# any of them is used.
settings_check_env() {
    local name kind v src
    while read -r name kind _; do
        [ "$kind" = env ] || continue
        v=${!name-}
        [ -n "$v" ] || continue
        src=${SETTING_SRC[$name]:-environment $name}
        case $name in
            (WT_SETTLE) case $v in (*[!0-9]*) die "$src: $name must be a whole number of seconds, not '$v'" ;; esac ;;
            (WT_STAGE_BASE) case $v in
                                (shm) STAGE_BASE=/dev/shm ;;
                                (mktemp) STAGE_BASE=${TMPDIR:-/tmp}; STAGE_BASE=${STAGE_BASE%/} ;;
                                (*) die "$src: $name takes shm or mktemp, not '$v'" ;;
                            esac ;;
            (*) case $v in (*[!0-9]*|0*) die "$src: $name must be a whole number of seconds above 0, not '$v'" ;; esac ;;
        esac
    done <<<"$SETTINGS_TABLE"
}

# Where a setting came from, as an error prefix ("" for the CLI or the
# default): "environment WT_X: " or "<file>:<line>: WT_X: ".
setting_where() {   # setting_where <name> -> SETTING_WHERE
    local src=${SETTING_SRC[$1]:-}
    case $src in
        ("") SETTING_WHERE="" ;;
        (environment*) SETTING_WHERE="$src: " ;;
        (*) SETTING_WHERE="$src: $1: " ;;
    esac
}

# The value the run uses for a setting, wherever it came from.
setting_value() {   # setting_value <name>
    local IFS=,
    case $1 in
        (WT_DIRECTORY) printf '%s' "$DIRECTORY" ;;
        (WT_WORKLOAD) printf '%s' "$WORKLOAD" ;;
        (WT_FIO_BIN) printf '%s' "$FIO_BIN" ;;
        (WT_OUTPUT) printf '%s' "$OUTPUT_DIR" ;;
        (WT_ENGINE) if [ -n "${CLI_SET[WT_ENGINE]:-}" ]; then printf '%s' "$ENGINE"; else printf '%s' "$DEFAULT_ENGINE"; fi ;;
        (WT_AUTO) printf '%s' "$AUTO_LEVEL" ;;
        (WT_LINE_RATE) printf '%s' "$LINE_RATE_GBPS" ;;
        (WT_CAL_CLIENTS) printf '%s' "$CAL_CLIENTS" ;;
        (WT_IGNORE_CAPACITY) printf '%s' "$IGNORE_CAPACITY" ;;
        (WT_ANY_FS) printf '%s' "$ANY_FS" ;;
        (WT_ALLOW_FIO_MISMATCH) printf '%s' "$ALLOW_FIO_MISMATCH" ;;
        (WT_IDENTITY) printf '%s' "${IDENT_RAW[*]}" ;;
        (WT_PASSWORD) printf '%s' "$PW_COUNT" ;;
        (WT_BULK) printf '%s' "$BULK" ;;
        (WT_DURATION) printf '%s' "$DURATION" ;;
        (WT_UNLINK) printf '%s' "$UNLINK" ;;
        (WT_VERBOSE) printf '%s' "$VERBOSITY" ;;
        (*) printf '%s' "${!1-}" ;;
    esac
}

# For the bundle: "<name><tab><value><tab><source>" for each setting whose
# value is not its default; source is cli, environment or <file>:<line>.
settings_provenance() {
    local name src v
    while read -r name _; do
        v=$(setting_value "$name")
        [ "$v" != "${SETTING_DEFAULT[$name]:-}" ] || continue
        if [ -n "${CLI_SET[$name]:-}" ]; then
            src=cli
        else
            src=${SETTING_SRC[$name]:-}
            case $src in ("") continue ;; (environment*) src=environment ;; esac
        fi
        printf '%s\t%s\t%s\n' "$name" "$v" "$src"
    done <<<"$SETTINGS_TABLE"
}

# The template's settings: each one's help, then the setting at its
# built-in value.
settings_template() {
    local name kind opt key l
    printf '#\n# Settings for the whole run, one WT_NAME=value per line: a command-line\n'
    printf '# flag beats the environment, which beats this file; an empty value sets\n'
    printf '# nothing.\n'
    while read -r name kind opt key; do
        printf '#\n'
        if [ "$kind" = env ] || [ "$kind" = default ]; then
            printf '# %s: %s\n' "$name" "$(own_setting_help "$name")"
        else
            while IFS= read -r l; do printf '# %s\n' "$l"; done < <(
                DIRECTORY=${SETTING_DEFAULT[WT_DIRECTORY]} WORKLOAD=${SETTING_DEFAULT[WT_WORKLOAD]} \
                FIO_BIN=${SETTING_DEFAULT[WT_FIO_BIN]} OUTPUT_DIR=${SETTING_DEFAULT[WT_OUTPUT]} opt_help "$key")
        fi
        printf '%s=%s\n' "$name" "${SETTING_DEFAULT[$name]:-}"
    done <<<"$SETTINGS_TABLE"
    printf '#\n'
}
