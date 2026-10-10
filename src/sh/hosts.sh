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
        if [ -s "$WORK_DIR/probe/$h" ]; then
            # every probe carries its ident line: an empty id there is the
            # answer, with no host_identity round of forks to find it again
            id=${ids[$i]:-}; i=$((i + 1))
            host_name_v "$h"; out="$out${out:+,}$h=$HOST_NAME${id:+/$id}"
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

# host_dir for the fleet in one awk, into HOST_DIRS in HOSTS order and
# HOST_DIR_OF by host. The resolution changes between phases, so each phase
# that walks the fleet loads it again.
HOST_DIRS=(); declare -gA HOST_DIR_OF=(); HOST_DIRS_KEY=""
load_host_dirs() {
    local f="" d i=0
    if [ -f "$WORK_DIR/targets.final" ]; then f="$WORK_DIR/targets.final"
    elif [ -f "$WORK_DIR/targets.phase1" ]; then f="$WORK_DIR/targets.phase1"
    fi
    HOST_DIRS=(); HOST_DIR_OF=(); HOST_DIRS_KEY=$f
    if [ -z "$f" ]; then
        for d in "${HOSTS[@]}"; do HOST_DIRS[i]=$DIRECTORY; i=$((i + 1)); done
        return 0
    fi
    while IFS= read -r d; do
        HOST_DIRS[i]=${d:-$DIRECTORY}; i=$((i + 1))
    done < <(targets_column 5 "$f" "${HOSTS[@]}")
    # a host the awk never answered for still gets -d, as host_dir gives it
    while [ "$i" -lt ${#HOSTS[@]} ]; do HOST_DIRS[i]=$DIRECTORY; i=$((i + 1)); done
    for i in "${!HOSTS[@]}"; do
        [ -n "${HOST_DIR_OF[${HOSTS[$i]}]+set}" ] || HOST_DIR_OF[${HOSTS[$i]}]=${HOST_DIRS[$i]}
    done
}
# host_dir without its subshells and awk: from the last load of targets.final
# (its writers clear HOST_DIRS_KEY), -d when no file resolves dirs
host_dir_v() {   # host_dir_v <host> -> HOST_DIR
    if [ "$HOST_DIRS_KEY" = "$WORK_DIR/targets.final" ] && [ -n "${HOST_DIR_OF[$1]+set}" ]; then
        HOST_DIR=${HOST_DIR_OF[$1]}
    elif [ ! -f "$WORK_DIR/targets.final" ] && [ ! -f "$WORK_DIR/targets.phase1" ]; then
        HOST_DIR=$DIRECTORY
    else
        HOST_DIR=$(host_dir "$1")
    fi
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
