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
    local l n=0   # the marker in the first three lines, read without head | grep
    while [ "$n" -lt 3 ] && { IFS= read -r l || [ -n "$l" ]; }; do
        n=$((n + 1))
        case $l in "$LAYOUT_MARKER"*) return 0 ;; esac
        l=""
    done < "$1"
    return 1
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
