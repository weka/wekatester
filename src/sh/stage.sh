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
