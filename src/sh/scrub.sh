# --- removal modes: -u all, and --scrub (README, -u/--unlink) -------------------
# private, shared and full at the end of a run are the unlink job (stage.sh)
# and cal_remove_dataset (calibrate.sh). Here: all, which empties the
# destination with find from every host that answers, and --scrub, the removal
# with no benchmark.
removal_on()    { [ "$UNLINK" -eq 1 ] || [ "$SCRUB_ONLY" -eq 1 ]; }
removal_all()   { removal_on && [ "$UNLINK_MODE" = all ]; }
# the shared read set goes too
unlink_shared() { case $UNLINK_MODE in (shared|full) return 0 ;; esac; return 1; }

# --scrub's mode is the run's mode; then what all needs before anything
# exists: a terminal to ask on, unless forced or a dry run.
removal_setup() {
    if [ "$SCRUB_ONLY" -eq 1 ]; then
        UNLINK=0; UNLINK_MODE=$SCRUB_MODE; UNLINK_FORCE=$SCRUB_FORCE
    fi
    removal_all || return 0
    [ "$UNLINK_FORCE" -eq 1 ] || [ "$DRY_RUN" -eq 1 ] || try_interactive \
        || die "all asks before it removes everything in the destination, and there is no terminal to ask on; all:force removes without asking"
}

# all, once the host file is resolved: every host's destination was given by
# someone (never the built-in default), is absolute and not /, and holds
# neither this tool nor its results.
removal_check_destinations() {
    removal_all || return 0
    local i=0 d h o miss=()
    load_host_dirs
    if [ "$DIRECTORY_EXPLICIT" -eq 0 ] && [ -z "${SETTING_SRC[WT_DIRECTORY]:-}" ]; then
        if [ -n "$HOST_DIRS_KEY" ]; then
            while IFS= read -r d; do
                [ -n "$d" ] || miss+=("${HOSTS[$i]}"); i=$((i + 1))
            done < <(targets_column 5 "$HOST_DIRS_KEY" "${HOSTS[@]}")
            while [ "$i" -lt ${#HOSTS[@]} ]; do miss+=("${HOSTS[$i]}"); i=$((i + 1)); done
            [ ${#miss[@]} -eq 0 ] \
                || die "all empties the destination directory, so it is never the built-in default ($DIRECTORY): give -d, or a destination_folder for ${#miss[@]} host(s) that have none in $TARGETS_FILE (${miss[*]})"
        else
            die "all empties the destination directory, so it is never the built-in default ($DIRECTORY): give -d"
        fi
    fi
    case $OUTPUT_DIR in (/*) o=$OUTPUT_DIR ;; (*) o="$(pwd -P)/$OUTPUT_DIR" ;; esac
    for i in "${!HOSTS[@]}"; do
        d=${HOST_DIRS[$i]}; h=${HOSTS[$i]}
        [ "$d" != / ] || die "$h: all never empties /"
        case $d in (/*) ;; (*) die "$h: all needs an absolute destination directory, not '$d'" ;; esac
        case "$o/" in ("$d"/*) die "$h: all would remove this run's results: the output directory $o is inside the destination $d (give -o a directory outside it)" ;; esac
        case "$SCRIPT_DIR/" in ("$d"/*) die "$h: all would remove wekatester itself: $SCRIPT_DIR is inside the destination $d (run it from a copy outside)" ;; esac
    done
}

# --scrub: a host that cannot be reached leaves the list, and the rest go on.
scrub_drop_hosts() {   # scrub_drop_hosts <why> <host>...
    local why=$1 h x keep=()
    shift
    for h in "${HOSTS[@]}"; do
        for x in "$@"; do [ "$h" != "$x" ] || continue 2; done
        keep+=("$h")
    done
    for x in "$@"; do
        host_dir_v "$x"
        log "WARNING: scrub: $x $why: nothing is removed from there; what is in $HOST_DIR stays unless another host in the list shares it" >&2
    done
    [ ${#keep[@]} -gt 0 ] || die "scrub: no host in the list can be reached"
    HOSTS=("${keep[@]}")
    MASTER=${HOSTS[0]}
}

# The filesystem group of a host: its number in the groups file, else the
# host itself (no groups file yet, or a host it does not list).
scrub_groups() {   # scrub_groups <host>... -> "<host>\t<group>" lines
    local gf=""
    [ ! -s "$WORK_DIR/groups" ] || gf="$WORK_DIR/groups"
    printf '%s\n' "$@" | awk -v gf="$gf" 'BEGIN { if (gf != "") while ((getline l < gf) > 0) if (split(l, a, " ") == 2) g[a[1]] = a[2] }
        { print $1 "\t" (($1 in g) ? g[$1] : "h:" $1) }'
}

# all: every host of the run, the excluded ones too, empties its own
# destination; hosts that share one race, and find passes over what another
# removed first. The verdict is a look afterwards from one host of each
# filesystem group, never a find's exit status (racing finds and a nested
# mount point both end nonzero). Never dies: the teardown calls it.
# Returns 1 when a destination could not be emptied or looked at.
scrub_all() {
    SCRUB_DONE=1
    local hosts=() dirs=() h i g d rc=0 t0=$SECONDS out left line n what=""
    local pids=() frc=() cpid=() members=() order=()
    local -A seen=() dseen=() gdir=() gmem=() gok=()
    for h in "${HOSTS[@]}" ${EXCLUDED_HOSTS[@]+"${EXCLUDED_HOSTS[@]}"}; do
        [ -z "${seen[$h]+set}" ] || continue
        seen[$h]=1
        host_dir_v "$h"
        # the checks of removal_check_destinations again, on the very string
        # find is given
        case $HOST_DIR in
            (/|"") log "WARNING: all: $h: its destination resolves to \"$HOST_DIR\", which is never emptied; nothing is removed from there" >&2; rc=1; continue ;;
            (/*) ;;
            (*) log "WARNING: all: $h: its destination $HOST_DIR is not an absolute path; nothing is removed from there" >&2; rc=1; continue ;;
        esac
        hosts+=("$h"); dirs+=("$HOST_DIR")
        [ -n "${dseen[$HOST_DIR]+set}" ] || { dseen[$HOST_DIR]=1; what="$what${what:+, }$HOST_DIR"; }
    done
    [ ${#hosts[@]} -gt 0 ] || return $rc
    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry run: all would remove everything in $what on ${#hosts[@]} host(s)"
        return 0
    fi
    if [ "$UNLINK_FORCE" -eq 0 ]; then
        if ! try_interactive; then
            log "WARNING: all: no terminal to ask on; nothing was removed from $what" >&2
            return 1
        fi
        if ! confirm_explicit "remove EVERYTHING in $what on ${#hosts[@]} host(s)?"; then
            close_interactive
            log "all: not confirmed; nothing was removed from $what"
            return 0
        fi
        close_interactive
    fi
    mkdir -p "$WORK_DIR/scrub" || { log "WARNING: all: cannot create $WORK_DIR/scrub; nothing was removed" >&2; return 1; }
    log "all: removing everything in $what on ${#hosts[@]} host(s)..."
    for i in "${!hosts[@]}"; do
        # the trailing slash: a destination that is a symlink is entered, not skipped
        ( run_host "${hosts[$i]}" "find '${dirs[$i]}/' -mindepth 1 -xdev -ignore_readdir_race -delete" > "$WORK_DIR/scrub/$i.find" 2>&1 ) &
        pids[$i]=$!
    done
    for i in "${!hosts[@]}"; do
        wait "${pids[$i]}" && frc[$i]=0 || frc[$i]=$?
        # 255 is ssh's own "could not connect"; local mode has no ssh
        [ "${frc[$i]}" -ne 255 ] || [ "$LOCAL_MODE" -eq 1 ] || frc[$i]=gone
    done
    # one look per group, at once, from its first host that answered; a look
    # that fails falls to the group's next host below
    i=0
    while IFS=$'\t' read -r h g; do
        [ -n "${gdir[$g]+set}" ] || { order+=("$g"); gdir[$g]=${dirs[$i]}; }
        gmem[$g]+="${gmem[$g]:+ }$i"
        i=$((i + 1))
    done < <(scrub_groups "${hosts[@]}")
    for g in "${order[@]}"; do
        for i in ${gmem[$g]}; do
            [ "${frc[$i]}" != gone ] || continue
            ( scrub_look "${hosts[$i]}" "${dirs[$i]}" > "$WORK_DIR/scrub/$i.look" 2>&1 ) &
            cpid[$i]=$!
            break
        done
    done
    for g in "${order[@]}"; do
        d=${gdir[$g]}; members=(); left=""; n=0
        for i in ${gmem[$g]}; do
            members+=("${hosts[$i]}")
            [ "${frc[$i]}" != gone ] || continue
            n=$((n + 1))
            [ -z "$left" ] || continue
            if [ -n "${cpid[$i]+set}" ]; then wait "${cpid[$i]}" || :
            else scrub_look "${hosts[$i]}" "${dirs[$i]}" > "$WORK_DIR/scrub/$i.look" 2>&1 || :
            fi
            out=$(tail -n 1 "$WORK_DIR/scrub/$i.look")
            case $out in ("left "*[0-9]) left=${out#left }; gok[$g]=$i ;; esac
        done
        if [ "$n" -eq 0 ]; then
            case $g in
                (h:*) log "WARNING: all: ${members[*]} could not be reached, before the filesystem groups were known: what is in $d there stays unless a host above shares it" >&2 ;;
                (*) log "WARNING: all: no host that shares $d could be reached (${members[*]}): its contents stay" >&2 ;;
            esac
            rc=1; continue
        fi
        for i in ${gmem[$g]}; do
            [ "${frc[$i]}" = gone ] || continue
            log "all: ${hosts[$i]} could not be reached; the other host(s) that share $d removed its contents"
        done
        if [ -z "$left" ]; then
            log "WARNING: all: could not look at $d after the removal (${members[*]}); it may not be empty" >&2
            rc=1
        elif [ "$left" -eq 0 ]; then
            log "all: $d is empty (${members[*]})"
        else
            i=${gok[$g]}
            log "WARNING: all: $left entr$([ "$left" -eq 1 ] && echo y || echo ies) could not be removed from $d (seen from ${hosts[$i]}):" >&2
            while IFS= read -r line; do
                case $line in ("left "*) ;; (*) log "  $line" >&2 ;; esac
            done < "$WORK_DIR/scrub/$i.look"
            head -n 3 "$WORK_DIR/scrub/$i.find" | while IFS= read -r line; do log "  find on ${hosts[$i]}: $line" >&2; done
            rc=1
        fi
    done
    log "all: finished in $((SECONDS - t0))s"
    return $rc
}

# What is left in a destination on its own filesystem: the first five
# entries, then "left <count>". No "left" line when the directory cannot be
# entered (missing, a stale mount): that is not an empty one.
scrub_look() {   # scrub_look <host> <dir>
    run_host "$1" "cd '$2/' || exit 1; find '$2/' -mindepth 1 -xdev -print | awk 'NR <= 5 { print } END { print \"left \" NR }'"
}

# --scrub private|shared|full: the files the workload set names, by name
# (scrub_cmds), the shared read sets first as cal_remove_dataset does.
# Returns 1 when a removal failed.
scrub_named() {
    local sd f what files=() args=() i kind host cmd rc=0 t0=$SECONDS gf=-
    local cmds="$WORK_DIR/scrub.cmds"
    sd=${SET_DIR_OVERRIDE:-$(workload_src_dir)} || die "cannot locate the workload set"
    for f in "$sd"/[0-9]*; do [ -f "$f" ] && files+=("$f"); done
    [ ${#files[@]} -gt 0 ] || die "scrub: no jobfile in $sd names the files to remove"
    load_host_dirs
    [ ! -s "$WORK_DIR/groups" ] || gf="$WORK_DIR/groups"
    for i in "${!HOSTS[@]}"; do
        host_name_v "${HOSTS[$i]}"
        args+=("${HOSTS[$i]}" "$HOST_NAME" "${HOST_DIRS[$i]}")
    done
    awkrun '#@awk scrub_cmds' "$UNLINK_MODE" "$gf" "$CAL_SCRATCH" "${#files[@]}" "${files[@]}" "${args[@]}" > "$cmds" \
        || die "cannot derive the scrub commands"
    case $UNLINK_MODE in
        (private) what="each client's own files" ;;
        (shared) what="each client's own files and the shared read sets" ;;
        (*) what="each client's own files, the shared read sets and the calibration scratch" ;;
    esac
    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry run: scrub would remove $what of workload $WORKLOAD on ${#HOSTS[@]} host(s):"
        while IFS=$'\t' read -r kind host cmd; do log "  $host: $cmd"; done < "$cmds"
        return 0
    fi
    log "scrub: removing $what of workload $WORKLOAD on ${#HOSTS[@]} host(s)..."
    scrub_round S "$cmds" "the shared read set (or, under full, the calibration scratch) from" || rc=1
    scrub_round P "$cmds" "the files of" || rc=1
    log "scrub: finished in $((SECONDS - t0))s"
    return $rc
}

# One kind of scrub_cmds' commands, on every host at once. Hosts that share a
# destination race: a find ends nonzero when a directory it listed is gone
# before it gets there (GNU find 4.8, with -ignore_readdir_race too), having
# removed its own files or not. So a command that failed runs again, with the
# others that failed and then alone, and only that last status is a failure.
scrub_round() {   # scrub_round <S|P> <cmds-file> <what, for the warning>
    local kind host cmd i pass rc=0 hs=() cs=() idx=() bad=() pids=() errs=()
    while IFS=$'\t' read -r kind host cmd; do
        [ "$kind" = "$1" ] || continue
        debug "scrub: $host: $cmd"
        idx+=(${#hs[@]}); hs+=("$host"); cs+=("$cmd")
    done < "$2"
    mkdir -p "$WORK_DIR/scrub" || return 1
    for pass in 1 2; do
        [ ${#idx[@]} -gt 0 ] || return 0
        pids=(); bad=()
        for i in "${idx[@]}"; do
            ( run_host "${hs[$i]}" "${cs[$i]}" > "$WORK_DIR/scrub/$1.$i.out" 2>&1 ) &
            pids[$i]=$!
        done
        for i in "${idx[@]}"; do wait "${pids[$i]}" || bad+=("$i"); done
        idx=(${bad[@]+"${bad[@]}"})
    done
    for i in ${idx[@]+"${idx[@]}"}; do
        run_host "${hs[$i]}" "${cs[$i]}" > "$WORK_DIR/scrub/$1.$i.out" 2>&1 && continue
        rc=1
        log "WARNING: scrub: could not remove $3 ${hs[$i]}:" >&2
        head -n 3 "$WORK_DIR/scrub/$1.$i.out" | while IFS= read -r cmd; do log "  $cmd" >&2; done
    done
    return $rc
}

# --scrub's whole run, after the locks and the mount check.
scrub_only() {
    local rc=0
    collect_fs_groups
    SCRUB_ARMED=1
    if [ "$UNLINK_MODE" = all ]; then scrub_all || rc=1
    else scrub_named || rc=1
    fi
    [ "$rc" -eq 0 ] || die "scrub: not everything could be removed (above)"
}

# The teardown's call: all removes after a failed run too, once the locks
# were held and the destinations checked, and never after a signal.
scrub_at_exit() {
    [ "$SCRUB_ARMED" -eq 1 ] && [ "$SCRUB_DONE" -eq 0 ] && removal_all || return 0
    case $RUN_RC in (0|130|143) return 0 ;; esac
    log "all: the run failed; the destination is emptied all the same"
    scrub_all || log "WARNING: all: not everything could be removed (above)" >&2
}

# After the last job, under shared and full: a group whose first host was
# excluded keeps its shared read set, and the run says where.
note_shared_left() {
    unlink_shared && [ -n "$AUTO_LEVEL" ] && [ -z "$CAL_NS_DIR" ] && [ -s "$WORK_DIR/groups" ] \
        && [ ${#EXCLUDED_HOSTS[@]} -gt 0 ] || return 0
    local h x
    while read -r h; do
        for x in "${EXCLUDED_HOSTS[@]}"; do
            [ "$x" = "$h" ] || continue
            host_dir_v "$h"
            log "unlink: the shared read set (shared.*) under $HOST_DIR was not removed: $h, the first host of its filesystem group, was excluded during the run"
        done
    done < <(awk '!($2 in f) { f[$2] = 1; print $1 }' "$WORK_DIR/groups")
}
