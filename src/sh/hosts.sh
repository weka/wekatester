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
      settings_template
      cat <<'CSVEOF'
# One host per line: the run uses every host named here, with that line's
# settings; lines without a host apply to the hosts their login and/or
# ioengine select. Quote cpu lists: "22,24,26".
# Geometry is per type AND direction: R columns shape read jobs, W columns
# write jobs; a mixed-direction jobfile takes the deeper-queued direction's
# whole tuple.
# Example:  client-1,ubuntu,io_uring,"8,10",/mnt/weka,12/10G/2/8,12/10G/2/4,1/1G/2/1,1/1G/2/1,42/256M/2/16,42/256M/2/8
# Example:  ,,io_uring,,,,,,,,     (io_uring for every host that supports it)
# Example:  gpu-*,ubuntu,,,/mnt/weka,,,,,,   (a glob: every host it matches; * alone is every host)
# A host may be written as <name>/<machine-id>; the id is ignored when the
# row is read and only ever added by wekatester itself, to name a machine it
# is recording for the first time. Plain hostnames are equally valid, and a
# row you wrote keeps the spelling you gave it.
CSVEOF
    } > "$1" || die "cannot create host file $1"
    log "created host file $1"
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

# --- one host under two spellings ------------------------------------------------
# Names whose lower-cased first labels match but whose strings differ
# ("node1", "Node1.lab") may be one machine, which fio would then run twice.
# One address set: the later folds into the first; otherwise the operator
# answers. A file with no such pair looks nothing up.
HOST_FOLD_NEEDS_SAME_ROWS=1   # two file rows fold only when their own settings match
HOST_LOOKUP_S=30              # the getent bound; every name looks up at once
declare -gA HOST_FOLDED_INTO=() HOST_ADDRS_OF=() HOST_ADDRS_WHY_OF=()
HOST_FOLD_ROWS=""   # "<b>=<a>,..." per folded-away FILE row: an -a writeback comments it out

# One name as one line: name, its sorted getent ahosts addresses (of what the
# run dials: ssh -G's hostname, ~/.ssh/config and SSH_OPTS applied), and the
# reason when there are none, \037-separated (tab would fold empty fields).
host_addrs_line() {   # host_addrs_line <name>
    local out hn rc a="" why=""
    out=$(run_bounded 10 ssh $SSH_OPTS -G "$1" 2>&1); rc=$?
    hn=$(printf '%s\n' "$out" | awk '$1 == "hostname" {print $2; exit}')
    if [ -z "$hn" ]; then
        why="ssh -G $1 named no hostname (rc $rc)"
    elif ! out=$(command -v getent); then
        why="getent is not installed"
    else
        out=$(run_bounded "$HOST_LOOKUP_S" getent ahosts "$hn"); rc=$?
        case $rc in
            (0) a=$(printf '%s\n' "$out" | awk 'NF {print $1}' | LC_ALL=C sort -u | tr '\n' ' '); a=${a% } ;;
            (2) why="$hn does not resolve" ;;
            (124|137) why="getent ahosts $hn was cut off after $HOST_LOOKUP_S s" ;;
            (*) why="getent ahosts $hn failed (rc $rc)" ;;
        esac
        [ -n "$a" ] || [ -n "$why" ] || why="getent ahosts $hn gave no address"
    fi
    printf '%s\037%s\037%s\n' "$1" "$a" "$why"
}

# Every name at once, so a slow resolver costs one bound, not one per name
# -> HOST_ADDRS_OF and HOST_ADDRS_WHY_OF by name.
host_addrs_all() {   # host_addrs_all <name>...
    local n a why out
    out=$(pids=(); for n in "$@"; do host_addrs_line "$n" & pids+=($!); done; wait "${pids[@]}")
    for n in "$@"; do HOST_ADDRS_OF[$n]=""; HOST_ADDRS_WHY_OF[$n]="no lookup result"; done
    while IFS=$'\037' read -r n a why; do
        [ -n "$n" ] || continue
        HOST_ADDRS_OF[$n]=$a; HOST_ADDRS_WHY_OF[$n]=$why
    done <<<"$out"
}

# A fold of two file rows needs their own settings equal (resolve_targets
# hostonly, the host column aside): no silent winner. A CLI host has no row.
fold_rows_check() {   # fold_rows_check <a> <b> <b-is-a-file-row:0|1> <a-is-a-file-row:0|1>
    local out ra rb
    [ "$HOST_FOLD_NEEDS_SAME_ROWS" -eq 1 ] && [ "$3" -eq 1 ] && [ "$4" -eq 1 ] || return 0
    out=$(resolve_targets hostonly "$TARGETS_FILE" - - - "$1" "$2") \
        || die "host file resolution failed ($TARGETS_FILE)"
    { IFS= read -r ra; IFS= read -r rb; } <<<"$out"
    [ "${ra#*$'\t'}" = "${rb#*$'\t'}" ] \
        || die "host file $TARGETS_FILE: the rows for $1 and $2 name one host but their settings differ; keep one row"
}

# fold_spellings <file-host-count> <host>...: the hosts kept, in order, ->
# FOLDED, and HOST_FOLDED_INTO[<b>]=<a> per fold. The first <count> are file
# rows. Each name meets the kept names with its label, in order.
fold_spellings() {
    local nf=$1 i=0 a b lb k ka kb fa fb cands names=()
    local -A bylab=() isfile=() nlab=()
    shift
    FOLDED=()
    # host names are ASCII: ${,,} needs no lower() fork per host
    for b in "$@"; do lb=${b%%.*}; lb=${lb,,}; nlab[$lb]=$(( ${nlab[$lb]:-0} + 1 )); done
    for b in "$@"; do lb=${b%%.*}; lb=${lb,,}; [ "${nlab[$lb]}" -lt 2 ] || names+=("$b"); done
    [ ${#names[@]} -eq 0 ] || host_addrs_all "${names[@]}"
    for b in "$@"; do
        i=$((i + 1)); [ "$i" -gt "$nf" ] || isfile[$b]=1
        lb=${b%%.*}; lb=${lb,,}
        k=""
        read -ra cands <<<"${bylab[$lb]-}"
        for a in ${cands[@]+"${cands[@]}"}; do
            fa=${isfile[$a]:-0}; fb=${isfile[$b]:-0}
            ka=${HOST_ADDRS_OF[$a]:-${HOST_ADDRS_WHY_OF[$a]}}
            kb=${HOST_ADDRS_OF[$b]:-${HOST_ADDRS_WHY_OF[$b]}}
            if [ -n "${HOST_ADDRS_OF[$a]}" ] && [ "${HOST_ADDRS_OF[$a]}" = "${HOST_ADDRS_OF[$b]}" ]; then
                fold_rows_check "$a" "$b" "$fb" "$fa"
                log "host $b is $a (same address): folded"
                k=$a; break
            fi
            require_interactive "$a and $b look like one host but resolve differently: choosing to fold or keep them" \
                "drop one of the two rows, or spell the names apart"
            if confirm_explicit "$a and $b look like one host but resolve differently ($a: $ka; $b: $kb): fold them?"; then
                fold_rows_check "$a" "$b" "$fb" "$fa"
                log "host $b is $a (the operator's answer): folded"
                k=$a; break
            fi
        done
        if [ -n "$k" ]; then
            HOST_FOLDED_INTO[$b]=$k
            [ -z "${isfile[$b]:-}" ] || HOST_FOLD_ROWS+=${HOST_FOLD_ROWS:+,}$b=$k
            continue
        fi
        FOLDED+=("$b"); bylab[$lb]+=" $b"
    done
}

# --- host ranges -----------------------------------------------------------------
# A source's names with their ranges multiplied out, through the awk the host
# file's range rows use; a malformed range stops the run naming the source.
expand_host_ranges() {   # expand_host_ranges <source> <name>... -> EXPANDED
    local src=$1 out k i
    shift
    EXPANDED=("$@")
    case "$*" in (*[][{}]*) ;; (*) return 0 ;; esac
    out=$(awkrun '#@awk expand_ranges' "$src" "$@") || die "${out:-$src: the host ranges could not be expanded}"
    mapfile -t EXPANDED <<<"$out"
    k=${EXPANDED[0]}
    for ((i = 1; i <= k; i++)); do debug "${EXPANDED[i]}"; done
    EXPANDED=("${EXPANDED[@]:k+1}")
}

# WT_CLIENTS (settings.sh): servers placed before the command line's, read
# once, from the environment or else the host file.
CLIENT_HOSTS=(); CLIENTS_READ=""
clients_setting() {
    [ -z "$CLIENTS_READ" ] && [ -n "${WT_CLIENTS-}" ] || return 0
    local names=() src from
    CLIENTS_READ=1
    setting_where WT_CLIENTS; src=${SETTING_WHERE%: }
    case $src in
        ("") src=WT_CLIENTS; from="" ;;
        (environment*) from=" (the environment)" ;;
        (*) from=" (${src%: WT_CLIENTS})" ;;
    esac
    read -ra names <<<"$WT_CLIENTS"
    expand_host_ranges "$src" ${names[@]+"${names[@]}"}
    CLIENT_HOSTS=(${EXPANDED[@]+"${EXPANDED[@]}"})
    HOSTS=(${CLIENT_HOSTS[@]+"${CLIENT_HOSTS[@]}"} ${HOSTS[@]+"${HOSTS[@]}"})
    MASTER=${HOSTS[0]:-}
    check_hosts_once
    # under -t the host file's count line carries them
    [ "$TARGETS" -eq 1 ] \
        || log "${#CLIENT_HOSTS[@]} host(s) from WT_CLIENTS$from, $(( ${#HOSTS[@]} - ${#CLIENT_HOSTS[@]} )) more from the command line"
}

resolve_targets_file() {
    [ "$TARGETS" -eq 1 ] || return 0
    targets_path
    [ -f "$TARGETS_FILE" ] || create_targets_file
    log "host file: $TARGETS_FILE"
}

# With -t the file's host lines are the run's hosts, in file order; a CLI
# host is a row with the host cell only, so one the file already names is
# that row, and the rest follow in CLI order (README, Host files). The
# master is the merged list's first. No host anywhere: local mode, as ever.
hosts_from_file() {
    local out h nf=0 nc=0 nw=0 w="" merged=()
    local -A infile=() isclient=()
    out=$(resolve_targets hosts "$TARGETS_FILE" - - -) \
        || die "host file resolution failed ($TARGETS_FILE)"
    while IFS= read -r h; do
        [ -n "$h" ] || continue
        # a range row's count, ahead of its hosts
        case $h in ('#'*) debug "${h#\#}"; continue ;; esac
        merged+=("$h"); infile[$h]=1; nf=$((nf + 1))
    done <<<"$out"
    for h in "${HOSTS[@]}"; do
        [ -n "${infile[$h]+set}" ] || { merged+=("$h"); nc=$((nc + 1)); }
    done
    # a file created this run (the template) names no host: local mode
    # was settled before it was written
    if [ "$LOCAL_MODE" -eq 1 ]; then
        log "host file: $TARGETS_FILE (no host lines; running on the local host)"; return 0
    fi
    fold_spellings "$nf" "${merged[@]}"
    nf=0; nc=0
    for h in ${CLIENT_HOSTS[@]+"${CLIENT_HOSTS[@]}"}; do isclient[$h]=1; done
    for h in ${FOLDED[@]+"${FOLDED[@]}"}; do
        if [ -n "${infile[$h]+set}" ]; then nf=$((nf + 1))
        elif [ -n "${isclient[$h]+set}" ]; then nw=$((nw + 1))
        else nc=$((nc + 1)); fi
    done
    HOSTS=(${FOLDED[@]+"${FOLDED[@]}"})
    MASTER=${HOSTS[0]:-}
    # the WT_CLIENTS clause only when it added a host
    if [ "$nf" -gt 0 ]; then
        [ "$nw" -eq 0 ] || w="$nw from WT_CLIENTS, "
        log "host file: $TARGETS_FILE ($nf host(s) from the file, $w$nc more from the command line)"
    elif [ "$nw" -gt 0 ]; then
        log "host file: $TARGETS_FILE (no host lines; $nw host(s) from WT_CLIENTS, $nc more from the command line)"
    else
        log "host file: $TARGETS_FILE (no host lines; $nc host(s) from the command line)"
    fi
}

# The -t file this run reads, which may not exist yet. -> TARGETS_FILE
targets_path() {
    local candidate
    if [ -n "$TARGETS_PATH" ]; then
        candidate=$TARGETS_PATH
    else
        candidate="$SCRIPT_DIR/fio-jobfiles/$WORKLOAD/hostlist.csv"
        [ -f "$candidate" ] || candidate="./fio-jobfiles/$WORKLOAD/hostlist.csv"
        [ -f "$candidate" ] || candidate="./hostlist.csv"
    fi
    TARGETS_FILE=$candidate
}

# A missing -t file, created from the template once the user agrees.
create_targets_file() {
    local candidate=$TARGETS_FILE
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
    [ -n "$wb" ] && [ -f "$wb" ] || return 0
    # -g: derived and measured values win, no prompt. host, login and
    # allowed_cpus on the host OWN row are protected in the merge; a generic
    # row is never edited, and the host line beside it records what the run
    # resolved.
    [ "$REGEN_LAYOUT" -eq 0 ] || mode=overwrite
    # --line-rate measured the bandwidth slots again: their tuples replace the
    # row in fill mode too. What does each host OWN row provide? A file that
    # no longer resolves (edited mid-run) stops here, its rows never taken
    # as empty: the merge's own-row protection rests on them.
    resolve_targets hostonly "$wb" - - "${WORK_DIR}/engine.results" "${HOSTS[@]}" \
        > "$WORK_DIR/targets.hostrows" || die "host file writeback: cannot read the host rows of $wb (above)"
    local h ident="" tmp="$WORK_DIR/hostfile.writeback"
    [ -w "$wb" ] || die "host file writeback: $wb is not writable; nothing was recorded"
    ident=$(host_idents)
    # The awk writes the whole new content to our temp and checks it; only
    # then does one write go into the host file itself (its inode, mode,
    # owner and any symlink kept). "nothing to record" writes no temp.
    list_staged "$WORK_DIR/staged.list" &&
    WEKATESTER_HOST_ALIAS=$(host_alias_env "${HOSTS[@]}") \
    WEKATESTER_HOST_IDENT=$ident WEKATESTER_WB_TMP=$tmp WEKATESTER_HOST_FOLD=$HOST_FOLD_ROWS \
    awkrun '
    #@awk writeback_targets' "$wb" "$mode" "$WORK_DIR" "${LINE_RATE_GBPS:--}" "${HOSTS[@]}" \
        || { rm -f -- "${tmp:?}"; die "host file writeback failed ($wb)"; }
    [ -e "$tmp" ] || return 0
    cat -- "$tmp" > "$wb" \
        || die "host file writeback: writing $wb failed, it may be cut short; the intended content is in $tmp until the run exits"
    rm -f -- "${tmp:?}"
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

# phase1: before the engine tests (no engine selectors yet); phase2: with
# engine.results, the finished resolution; hostonly: each host OWN row only,
# what the writeback merges against; engines: every line's ioengine, one per
# line; hosts: the file's host lines as addresses, in file order (neither
# needs hosts).
resolve_targets() {   # resolve_targets <phase1|phase2|hostonly|engines> <csv> <cli_engine|-> <cli_dir|-> <results|-> <host>...
    # under -e no host runs WT_ENGINE: it is neither proven nor resolved
    local de=$DEFAULT_ENGINE
    [ -z "$ENGINE" ] || de=""
    WEKATESTER_HOST_ALIAS=$(host_alias_env "${@:6}") WEKATESTER_DEFAULT_ENGINE=$de \
        awkrun '#@awk resolve_targets' "$@"
}
