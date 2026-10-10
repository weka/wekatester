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
    # the comma ladders, joined again only when a ladder changed (~16 calls a shape)
    if [ "$CAL_LADDERS_SRC" != "$CAL_NR_LADDER|$CAL_BW_QD_LADDER|$CAL_IOPS_QD_LADDER" ]; then
        CAL_NRC=$(printf '%s' "$CAL_NR_LADDER" | tr -s ' ' ',')
        CAL_BWQDC=$(printf '%s' "$CAL_BW_QD_LADDER" | tr -s ' ' ',')
        CAL_IOPSQDC=$(printf '%s' "$CAL_IOPS_QD_LADDER" | tr -s ' ' ',')
        CAL_LADDERS_SRC="$CAL_NR_LADDER|$CAL_BW_QD_LADDER|$CAL_IOPS_QD_LADDER"
    fi
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
        "nrc=$CAL_NRC" "bwqd=$CAL_BWQDC" "iopsqd=$CAL_IOPSQDC"
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
    [ -d "${f%/*}" ] || mkdir -p "${f%/*}" || die "cannot create ${f%/*}"
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
    json_awk -F'\t' -v key="$key" -v path="$1" '
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
    json_awk -F'\t' -v d="$2" -v path="$1" '
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
    HOST_DIRS_KEY=""   # a host_dir_v map of the old targets.final is stale
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
    host_dir_v "$host"; hd=$HOST_DIR
    root="$hd${CAL_NS_DIR-/$CAL_SCRATCH}"
    host_name_v "$host"
    local hname=$HOST_NAME fmt=${CAL_FMT:-\$jobnum.\$filenum} sep=${CAL_SEP:-.cal.} slashes depth
    slashes=${fmt//[!\/]/}; depth=$(( ${#slashes} + 1 ))
    [ "${CAL_NS_DIR-unset}" != "" ] || unified=1
    mkdir -p "$WORK_DIR/cal/$host" || die "cannot create $WORK_DIR/cal/$host"
    rm -f "$WORK_DIR/cal/$host/truncfail"
    # One session for the listing and df. No error suppression on find: without
    # GNU -printf it must fail loudly, or every run re-seeds everything. Only
    # the names the seed can ask for: a shared destination holds every
    # member's write set.
    run_host "$host" "if [ -d '$root' ]; then find '$root' -maxdepth $depth -type f \\( -path '$root/$hname$sep*' -o -path '$root/shared.*' \\) -printf '%P %s\\n'; fi; echo WEKATESTER_DF; df -Pk '$hd' | awk 'NR==2 {print \$1, \$2, int(\$4/1024)}'" \
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
    # a name with no / needs no directory: skip the awk launch
    if [ "$maxf" -gt 0 ] && [ "$wantnj" -gt 0 ] && [[ $hname${CAL_SEP:-.cal.}${CAL_FMT:-\$jobnum.\$filenum} == */* ]]; then
        subdirs=$(cal_scratch_dirs "$hname" "${CAL_SEP:-.cal.}" \
                      "${CAL_FMT:-\$jobnum.\$filenum}" "$wantnj" $((maxf - 1))) \
            || die "$host: cannot derive the calibration namespace directories"
    fi
    if [ "$unified" -eq 1 ] && [ "$rnj" -gt 0 ] && [ "$rnr" -gt 0 ] && [[ shared.$CAL_FMT == */* ]]; then
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
        # sparse write canvases by truncate: one session for every size, a
        # second only past ~100 KB of names (was one per 64 files)
        while IFS= read -r tchunk; do
            run_host "$host" "cd '$root' && $tchunk" \
                || { echo TRUNCFAIL > "$WORK_DIR/cal/$host/truncfail"; break; }
        done < <(awkrun '#@awk cal_seed_rep.truncate' "$tlist")
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
        CAL_READING="$v $a"
    else
        vals=$(cal_values "$json" "$type") || die "cannot read the throughput of ${json##*/}"
        read -r h v <<<"$vals"
        CAL_READING=$v
    fi
    # the file is the hand-off; CAL_READING spares the callers a cat per cell
    printf '%s\n' "$CAL_READING" > "$WORK_DIR/cal/reading"
    debug "cal: shape $CAL_SID $what ${rt}s: $CAL_READING"
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
                    "$CAL_READING" >> "$hist"
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

# Whether the newline-separated todo list holds this exact line (was a
# printf | grep -qx pipeline per test).
cal_todo_has() {   # cal_todo_has <todo> <line>
    [[ $'\n'$1$'\n' == *$'\n'"$2"$'\n'* ]]
}

# One shape, solo: reuse host-file values, seed, pick the engine, search the
# rest. Leaves cal/s<id>/engine and one tuple file per slot.
cal_shape_run() {   # cal_shape_run <id> <rep> <N> <phys-cpus> <all-cpus> <linerate> <engines> <pinned> <memcap> <aio> <pins> <ladders>
    local sid=$1 rep=$2 usable=$3 phys=$4 allc=$5 linerate=$6 engines=$7 pinned=$8 memcap=$9 aio=${10} pins=${11} ladders=${12}
    local sdir="$WORK_DIR/cal/s$1" type dirn slot kv c todo="" any_read=0 any_write=0
    local eng pick rest etype ctype edirn enj eqd enr pq pn pj e ncand budget wcells mins qmax
    CAL_SID=$sid
    host_dir_v "$rep"; CAL_REP_DIR=$HOST_DIR
    host_name_v "$rep"; CAL_REP_NAME=$HOST_NAME
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
            if cal_todo_has "$todo" "$etype read"; then edirn=read
            elif cal_todo_has "$todo" "$etype write"; then edirn=write
            elif [ "$etype" = lat ]; then
                # only a 1MiB latency search: its cells stand in, tallied as
                # latency, or a set like that has no engine cell at all
                ctype=lat1m
                if cal_todo_has "$todo" "lat1m read"; then edirn=read
                elif cal_todo_has "$todo" "lat1m write"; then edirn=write
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
                printf '%s %s %s\n' "$etype" "$e" "$CAL_READING" >> "$sdir/engines"
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
            cal_todo_has "$todo" "$type $dirn" || continue
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
        # every shared set first, all at once (one at a time was minutes with
        # a group per host), so their pruning ends before the members' starts
        local spids=()
        while IFS=$'\t' read -r kind host ucmd; do
            [ "$kind" = S ] || continue
            run_host "$host" "$ucmd" &
            spids+=($!)
        done < "$cmds"
        for i in "${!spids[@]}"; do
            wait "${spids[$i]}" || log "WARNING: could not remove the shared dataset" >&2
        done
        while IFS=$'\t' read -r kind host ucmd; do
            [ "$kind" != S ] || continue
            run_host "$host" "$ucmd" &
            pids+=($!); hs+=("$host")
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
    local shapes=$1 ladders=$2 rep hd root depth pids=() hs=() i rc line fmt=${CAL_FMT:-\$jobnum.\$filenum} slashes
    slashes=${fmt//[!\/]/}; depth=$(( ${#slashes} + 1 ))
    mkdir -p "$WORK_DIR/cal/cap" || die "cannot create $WORK_DIR/cal/cap"
    : > "$WORK_DIR/cal/cap/names"
    while IFS=$'\t' read -r _ rep _; do
        host_dir_v "$rep"; hd=$HOST_DIR
        root="$hd${CAL_NS_DIR-/$CAL_SCRATCH}"
        host_name_v "$rep"
        printf '%s\t%s\n' "$rep" "$HOST_NAME" >> "$WORK_DIR/cal/cap/names"
        # only the names the check prices: shared. and this rep's own
        ( run_host "$rep" "if [ -d '$root' ]; then find '$root' -maxdepth $depth -type f \\( -path '$root/$HOST_NAME${CAL_SEP:-.cal.}*' -o -path '$root/shared.*' \\) -printf '%P %s\\n'; fi; echo WEKATESTER_DF; df -Pk '$hd' | awk 'NR==2 {print \$1, \$2, int(\$4/1024)}'; findmnt -T '$hd' -n -o FSTYPE 2>&1 || :" > "$WORK_DIR/cal/cap/$rep" ) &
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
    load_host_dirs   # host_dir_v answers from it for every shape and seed below
    while IFS=$'\t' read -r sid rep rest; do
        host_dir_v "$rep"
        run_host "$rep" "mkdir -p '$HOST_DIR${CAL_NS_DIR-/$CAL_SCRATCH}'" &
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
                IFS= read -r m < "$t" || :
                line="$line $m"; any=1
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
