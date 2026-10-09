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
    # the raw captures are dead once split: tmpfs is RAM, and a run-window
    # sar slice per host adds up
    WT_ROOT="$RUN_DIR/sysinfo" WT_PFX=$1 WT_SFX=$2 awk '
        #@awk split_sysinfo' "${files[@]}" && rm -f -- "${files[@]}"
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
    bad=$(json_awk -F'\t' -v mode="$mode" '
        #@awk check_fio_errors')
    [ "$bad" != NONE ] || { echo "$path: fio returned no per-job stats -- the jobs did not run" >&2; return 1; }
    [ -n "$bad" ] || return 0
    local line kind h job e desc
    while IFS=$'\t' read -r kind h job e; do
        case "$kind" in
            E) errno_text_v "$e"; desc=$ERRNO_TEXT; echo "ERROR: $h: job '$job' error $e${desc:+ ($desc)}" >&2 ;;
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
    local host hd spec cmd sz glob depth tot pids hs i args=() nofa lit dep sl
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
            # Start at the glob's literal directories: from the shared $hd every
            # host walked every host's grid. One walk prints the files that
            # count and deletes the deviants.
            lit=${glob%%[*?[]*}; dep=$depth
            case $lit in
                */*) lit=${lit%/*}; sl=${lit//[!\/]/}; dep=$((depth - ${#sl} - 1))
                     cmd="$cmd if [ -d \"$hd/$lit\" ]; then find \"$hd/$lit\"" ;;
                *)   lit=""; cmd="$cmd { find \"$hd\"" ;;
            esac
            cmd="$cmd -maxdepth $dep -type f -path \"$hd/$glob\" ! -path \"$hd/$CAL_SCRATCH/*\" \\( -size +$((sz - 1))c -print -o -delete \\);"
            [ -z "$lit" ] && cmd="$cmd }" || cmd="$cmd fi"
            cmd="$cmd | awk -v s=$sz -v t=$tot 'END{v=NR*s; print (v<t)?v:t}'; "
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
    local job cmd longest=0 worst="" jl=-1
    # the name appears once per host, so the longest name makes the longest
    # command: build that one, not one per job
    [ ${#JOBFILES[@]} -gt 0 ] || return 0
    for job in "${JOBFILES[@]}"; do
        [ "${#job}" -le "$jl" ] || { jl=${#job}; worst=$job; }
    done
    cmd=$(fio_client_cmd "$worst"); longest=${#cmd}
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
        # local mode reports as localhost. A results file, never a bundle: no
        # tar probe (GNU tar reads the whole file looking for a header).
        summ_one "$outfile" "$outfile" "${report:-bandwidth latency iops}" "${HOSTS[*]}" file \
            || die "failed to summarize $outfile"
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
        *) out=$(json_awk -F'\t' -v label="$label" -v items=" $items " -v expected="$expected" '
        #@awk summ_one') ;;
    esac
    case "$out" in
        "ERR	"*)
            if [ "$mode" = bundle ]; then printf '    (%s)\n\n' "${out#ERR	}"; return 0; fi
            printf '%s\n' "${out#ERR	}" >&2; return 1 ;;
    esac
    printf '%s\n\n' "$out"
}
