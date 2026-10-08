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
