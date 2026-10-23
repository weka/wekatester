# --- phase 4: run + summarize --------------------------------------------------
# The items a jobfile's "# report" directives give its summary, read by the
# rule staging and -a use (lib report_items; README, Workloads).
report_items() {   # report_items <jobfile>
    awkrun 'BEGIN { if ((n = readlines(ARGV[1], L)) < 0) awk_fail("cannot read " ARGV[1]); print report_items(L, n) }' "$1"
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

# What started the run, for -s: cmdline is the argv shell-quoted, $0 first;
# settings holds what it resolved to, one "<key><tab><value>" per line.
# Missing pieces only cost -s its header lines, never the run.
record_run() {
    local q
    if [ ${#ARGV_TYPED[@]} -gt 0 ]; then
        printf -v q '%q ' "${ARGV_TYPED[@]}"
        printf '%s\n' "${q% }" > "$RUN_DIR/cmdline" \
            || log "WARNING: could not record the command line in $RUN_DIR/cmdline" >&2
    fi
    q=-; ! cal_mode || q=$CAL_RUNTIME
    printf 'version\t%s\nworkload\t%s\nauto\t%s\ncal-seconds\t%s\nmaster\t%s\nhosts\t%s\n' \
        "$VERSION" "$WORKLOAD" "${AUTO_LEVEL:--}" "$q" "$MASTER" "${HOSTS[*]}" > "$RUN_DIR/settings" \
        || log "WARNING: could not record the run settings in $RUN_DIR/settings" >&2
}

# Per-host system context, one file per item under sysinfo/<host>/ (README,
# Output). A missing tool or file records "not available".
snapshot_sysinfo() {
    local cmd
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
            (uptime)  if _o=$(command -v uptime);  then uptime;            else echo "not available"; fi ;;
            (df)      if _o=$(command -v df);      then df -kP;            else echo "not available"; fi ;;
            (ip)      if _o=$(command -v ip);      then ip -o addr;        else echo "not available"; fi ;;
            (numactl) if _o=$(command -v numactl); then numactl --hardware; else echo "not available"; fi ;;
            (*)
                if _o=$(command -v "$it"); then "$it"; else echo "$it: not available"; fi ;;
        esac
    done'
    cmd="$cmd; echo '=== WEKATESTER_SYSINFO fio ==='; \
        '$FIO_BIN' --version 2>&1 || echo 'not available'; \
        echo '=== WEKATESTER_SYSINFO weka ==='; \
        if _o=\$(command -v weka); then weka local ps 2>&1 || true; else echo 'weka: not available'; fi"
    cmd="$cmd
$(sysinfo_nic_cmd)"
    capture_hosts "system info" "$WORK_DIR/sysinfo." "$cmd"
    split_sysinfo "$WORK_DIR/sysinfo." ""
}

# One session per host in parallel, each bounded as a whole at
# WEKATESTER_SYSINFO_TIMEOUT (300 s). A host cut off keeps its partial
# capture, which says where it stopped plus a session-timeout item.
capture_hosts() {   # capture_hosts <what> <capture-file-prefix> <command-string>
    local host i rc o f pids=() hs=() t=${WEKATESTER_SYSINFO_TIMEOUT:-300}
    if ! o=$(command -v timeout); then
        log "WARNING: timeout is not installed on this controller: the $1 sessions are not bounded (WEKATESTER_SYSINFO_TIMEOUT)" >&2
        t=
    fi
    for host in "${HOSTS[@]}"; do
        ( RUN_HOST_TIMEOUT=$t run_host "$host" "$3" > "$2$host" ) &
        pids+=($!); hs+=("$host")
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" && continue
        rc=$?
        if [ -z "$t" ] || { [ $rc -ne 124 ] && [ $rc -ne 137 ]; }; then
            log "WARNING: could not capture $1 on ${hs[$i]}" >&2; continue
        fi
        log "WARNING: $1 on ${hs[$i]} cut off after $t s (WEKATESTER_SYSINFO_TIMEOUT); the partial capture is kept" >&2
        f=$2${hs[$i]}
        # a cut can land mid-line: the marker must start one
        [ ! -s "$f" ] || [ -z "$(tail -c 1 "$f")" ] || echo >> "$f"
        printf 'not available: the session was cut off here, after %s s (WEKATESTER_SYSINFO_TIMEOUT)\n=== WEKATESTER_SYSINFO session-timeout ===\n%s cut off after %s s (WEKATESTER_SYSINFO_TIMEOUT)\n' \
            "$t" "$1" "$t" >> "$f"
    done
}

# Remote helpers for the sysinfo and pressure strings: _nc runs a tool
# bounded (_T seconds, 10), _rd reads a file, _ln names a link's target,
# _nlist sets _nl to the netdevs with a device link (the probe's choice),
# _pci sets _pd to the device whose PCI values a netdev reads: its own, or
# for one that is not a PCI function (virtio) the nearest PCI ancestor (_pb,
# - when none; _pl labels its values). _priv finds the first passwordless
# escalator (the probe's order), once. WEKATESTER_SYSROOT is for the suite.
remote_helpers_cmd() {
    printf '%s' '_sr=${WEKATESTER_SYSROOT:-}
    _nc() {
        if ! _o=$(command -v "$1"); then echo "not available: $1 not installed"; return 1; fi
        _t=; if _o=$(command -v timeout); then _t="timeout ${_T:-10}"; fi
        _x=$($_t "$@" 2>&1); _rc=$?
        [ -z "$_x" ] || printf "%s\n" "$_x"
        if [ -n "$_t" ] && [ $_rc -eq 124 ]; then echo "not available: $1 timed out after ${_T:-10} s"
        elif [ $_rc -ne 0 ]; then echo "($1 exited $_rc)"; fi
        return $_rc
    }
    _rd() { if [ -r "$_sr$1" ]; then cat "$_sr$1"; else echo "not available: $1 not readable"; return 1; fi; }
    _ln() { if [ -e "$_sr$1" ] && _y=$(readlink -f "$_sr$1"); then echo "${_y##*/}"; else echo "not available: $1 links nowhere"; fi; }
    _nlist() { _nl=; for _d in "$_sr"/sys/class/net/*; do [ -e "$_d/device" ] || continue; _nl="$_nl ${_d##*/}"; done; }
    _nlsay() { if [ -n "$_nl" ]; then echo "${_nl# }"; else echo "not available: no netdev in /sys/class/net has a device link"; fi; }
    _pci() {
        _pd=/sys/class/net/$1/device; _pb=; _pl=
        [ -e "$_sr$_pd/subsystem" ] && _y=$(readlink -f "$_sr$_pd/subsystem") && [ "${_y##*/}" != pci ] || return 0
        _y=$(readlink -f "$_sr$_pd") || return 0
        _z=; [ -z "$_sr" ] || _z=$(readlink -f "$_sr") || return 0
        while _y=${_y%/*}; [ -n "$_y" ] && [ "${_y##*/}" != devices ]; do
            [ -e "$_y/subsystem" ] && _w=$(readlink -f "$_y/subsystem") && [ "${_w##*/}" = pci ] || continue
            _pb=${_y##*/}; _pd=${_y#"$_z"}; _pl=" pci_parent=$_pb"; return 0
        done
        _pb=-
    }
    _ps=0; _pv=
    _priv() {
        if [ $_ps -eq 0 ]; then
            _ps=1
            for _pc in "dzdo -n" pbrun sesu pmrun "doas -n" "ksu -e" "sudo -n"; do
                _o=$(command -v "${_pc%% *}") || continue
                if _o=$(timeout 5 $_pc true </dev/null 2>&1); then _pv=$_pc; break; fi
            done
        fi
        [ -n "$_pv" ]
    }
'
}

# The receive path, in the same session: host knobs, then nic-<dev> per
# netdev with a device link (Weka's own NICs are known only after the
# probe). Each tool bounded; anything missing says why.
sysinfo_nic_cmd() {
    # mlnx_qos may need root: a non-root failure is retried once under the
    # escalator.
    remote_helpers_cmd
    printf '%s' '_nlist
    echo "=== WEKATESTER_SYSINFO sysctl ==="
    for _k in net/core/netdev_max_backlog net/ipv4/tcp_rmem; do echo "${_k//\//.} $(_rd /proc/sys/$_k)"; done
    for _c in all default $_nl; do
        for _k in rp_filter arp_filter arp_ignore arp_announce; do echo "net.ipv4.conf.$_c.$_k $(_rd /proc/sys/net/ipv4/conf/$_c/$_k)"; done
    done
    echo "=== WEKATESTER_SYSINFO chrony ==="
    if _o=$(command -v chronyc); then _nc chronyc tracking
    else echo "not available: chronyc not installed; timedatectl instead"; _nc timedatectl status; fi
    echo "=== WEKATESTER_SYSINFO cpu-governor ==="
    if [ -r "$_sr/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor" ]; then
        cat "$_sr"/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor 2>&1 | sort | uniq -c
    else echo "not available: /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor not readable"; fi
    echo "=== WEKATESTER_SYSINFO irqbalance ==="
    if ! _o=$(command -v pgrep); then echo "not available: pgrep not installed"
    elif _o=$(pgrep -x irqbalance); then echo running
    else _rc=$?; if [ $_rc -eq 1 ]; then echo "not running"; else echo "not available: pgrep exited $_rc"; fi; fi
    echo "=== WEKATESTER_SYSINFO nics ==="; _nlsay
    for _n in $_nl; do
        _v=/sys/class/net/$_n/device
        echo "=== WEKATESTER_SYSINFO nic-$_n ==="
        echo "bus $(_ln $_v)"; echo "driver $(_ln $_v/driver)"
        _pci "$_n"; [ "$_pb" != - ] || echo "pci_parent not available: $_v is not a PCI function and no device above it is"
        _v=$_pd; echo "numa_node $(_rd $_v/numa_node)$_pl"
        for _a in current_link_speed current_link_width max_link_speed max_link_width; do
            if _y=$(_rd $_v/$_a); then _y=${_y// /_}; fi; echo "$_a $_y$_pl"
        done
        if [ -d "$_sr$_v/msi_irqs" ]; then
            _c=0; _q=
            for _i in "$_sr$_v"/msi_irqs/*; do
                [ -e "$_i" ] || continue; _i=${_i##*/}; _c=$((_c + 1))
                _y=$(_rd /proc/irq/$_i/smp_affinity_list) || _y=-; _q="$_q $_i:$_y"
            done
            echo "msi_irqs $_c$_pl"; echo "irq_cpus${_q:- -}$_pl"
        else echo "msi_irqs not available: $_v/msi_irqs not readable$_pl"; echo "irq_cpus not available: no msi_irqs$_pl"; fi
        for _a in -g -l -c -a; do echo "--- ethtool $_a"; _nc ethtool $_a "$_n"; done
        echo "--- mlnx_qos -i"
        if _x=$(_nc mlnx_qos -i "$_n") || ! _m=$(command -v mlnx_qos) || [ "$(id -u)" = 0 ]; then printf "%s\n" "$_x"; continue; fi
        printf "%s\n" "$_x"
        if _priv; then echo "--- mlnx_qos -i, again under $_pv"; _nc $_pv "$_m" -i "$_n"
        else echo "not available: mlnx_qos failed as a non-root user and no passwordless escalator works"; fi
    done; true'
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

# Counters taken at both ends of the run, raw (the delta is the reader's):
# TCP/IP (nstat -asz, which leaves nstat's history alone, else /proc/net),
# and per device-backed netdev ethtool -S and the PCIe AER totals.
pressure_counters_cmd() {
    remote_helpers_cmd
    printf '%s' '_nlist
    echo "=== WEKATESTER_SYSINFO nics ==="; _nlsay
    echo "=== WEKATESTER_SYSINFO tcp ==="
    if _o=$(command -v nstat); then _nc nstat -asz
    else echo "not available: nstat not installed; /proc/net/snmp and /proc/net/netstat instead"; _rd /proc/net/snmp; _rd /proc/net/netstat; fi
    for _dv in $_nl; do
        echo "=== WEKATESTER_SYSINFO ethtool-S-$_dv ==="; _nc ethtool -S "$_dv"
        echo "=== WEKATESTER_SYSINFO aer-$_dv ==="
        _pci "$_dv"; [ "$_pb" != - ] || echo "pci_parent not available: /sys/class/net/$_dv/device is not a PCI function and no device above it is"
        for _a in correctable nonfatal fatal; do echo "--- aer_dev_$_a$_pl"; _rd $_pd/aer_dev_$_a; done
    done; true'
}

# The kernel log from the run start (the host's own clock), the last 2000
# lines: dmesg windowed by /proc/uptime, under the escalator when
# dmesg_restrict refuses a non-root user; else journalctl -k --since.
kernel_log_cmd() {   # kernel_log_cmd <run-start-epoch>
    printf '_ks=%s\n' "$1"
    printf '%s' '_kring() { awk -v s="$1" -v m=2000 '\''
        s != "" && match($0, /^\[ *[0-9]+\.[0-9]+\]/) { t = substr($0, 2, RLENGTH - 2) + 0; if (!seen++) first = t; on = (t >= s + 0) }
        s == "" || on { L[n++ % m] = $0 }
        END { if (s != "" && s + 0 < 0) print "(this host booted after the run start: dmesg holds nothing from before the boot)"
            else if (seen && first > s + 0) print "(the oldest line in the buffer is at " first " s, after the run start: earlier lines were overwritten)"
            if (!n) print "(no kernel log line in the window)"; i = n > m ? n - m : 0; if (i) print "(" i " earlier lines dropped: the last " m " kept)"; for (; i < n; i++) print L[i % m] }'\''; }
    echo "=== WEKATESTER_SYSINFO kernel-log ==="
    _kr=; _kw=
    if [ -r "$_sr/proc/uptime" ]; then read -r _up _o < "$_sr/proc/uptime"; _kr=$(( _ks - $(date +%s) + ${_up%.*} - 1 )); fi
    if [ -z "$_kr" ]; then echo "not available: /proc/uptime not readable, so dmesg cannot be windowed"
    elif _x=$(_nc dmesg); then _kw=dmesg
    else
        printf "%s\n" "$_x"
        if [ "$(id -u)" = 0 ]; then :
        elif ! _priv; then echo "not available: dmesg failed as a non-root user and no passwordless escalator works"
        elif _x=$(_nc $_pv dmesg); then _kw="dmesg under $_pv"
        else printf "%s\n" "$_x"; fi
    fi
    if [ -n "$_kw" ]; then
        echo "# $_kw, from $_kr s after boot (the run start)"; printf "%s\n" "$_x" | _kring "$_kr"
    else
        echo "# journalctl -k --since @$_ks (the run start)"
        _x=$(_T=60 _nc journalctl -k --no-pager -o short-iso --since "@$_ks"); printf "%s\n" "$_x" | _kring ""
    fi; true'
}

# PSI and load at start and again at teardown, the counters above at both,
# plus the run window's kernel log and sar slice (when sysstat keeps one).
PRESSURE_END_DONE=0
snapshot_pressure() {   # snapshot_pressure <start|end>
    [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || return 0
    local label=$1 cmd
    cmd='for f in cpu io memory; do
        echo "=== WEKATESTER_SYSINFO pressure-$f ==="
        if [ -r "/proc/pressure/$f" ]; then cat "/proc/pressure/$f"; else echo "not available"; fi
    done
    echo "=== WEKATESTER_SYSINFO loadavg ==="
    if [ -r /proc/loadavg ]; then cat /proc/loadavg; else echo "not available"; fi'
    cmd="$cmd
$(pressure_counters_cmd)"
    if [ "$label" = end ] && [ -n "$RUN_EPOCH" ]; then
        cmd="$cmd
$(kernel_log_cmd "$RUN_EPOCH")"
        # the run window's sar slice, in each worker's own time zone; a run
        # that started on an earlier worker day gets today from 00:00:00
        # (sar reads one day's file)
        cmd="$cmd
    echo '=== WEKATESTER_SYSINFO sar ==='
    if _o=\$(command -v sar); then
        _s=\$(date -d @$RUN_EPOCH '+%F %H:%M:%S'); _n=\$(date '+%F %H:%M:%S')
        if [ \"\${_s% *}\" = \"\${_n% *}\" ]; then _s=\${_s#* }; else _s=00:00:00; fi
        sar -A -s \"\$_s\" -e \"\${_n#* }\" 2>&1 || true
    else echo 'sar: not available'; fi"
    fi
    capture_hosts "pressure ($label)" "$WORK_DIR/pressure.$label." "$cmd"
    split_sysinfo "$WORK_DIR/pressure.$label." "-$label"
}

# -n: print what a real run would do, from the master staged variants (what
# fio would read), and stop.
dry_run_report() {
    local job line call=""
    echo
    log "dry run: nothing was executed; details of what would have run:"
    if cal_mode; then
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
    log "workload source: $JOBFILE_SRC"
    log "hosts (${#HOSTS[@]}): ${HOSTS[*]} (master: $MASTER)"
    [ "$ANY_FS" -eq 0 ] || log "destination: the filesystem-type check was off (--any-fs); the WARNING above names what -d is on"
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

# The staged variants are the execution truth: -a rewrites geometry per host.
snapshot_jobfiles() {
    mkdir "$RUN_DIR/fio-jobfiles" || die "cannot create $RUN_DIR/fio-jobfiles"
    cp -R "$WORK_DIR/jobs/." "$RUN_DIR/fio-jobfiles/" \
        || die "cannot copy the staged jobfiles into $RUN_DIR/fio-jobfiles"
}

# Runs in the EXIT trap after cleanup, so it must never die: a tar failure
# leaves the directory and says so. pigz, when installed, writes the same
# gzip at the same level on every core.
finalize_run_dir() {
    [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ] || return 0
    local zip=-z _o
    if _o=$(command -v pigz); then zip=--use-compress-program=pigz; fi
    if [ ${#TEE_PIDS[@]} -gt 0 ]; then
        # Restore the console and let the tees drain: their pipes EOF when
        # these redirected fds close, and only a drained log may be archived.
        exec 1>&5 2>&6 5>&- 6>&-
        wait "${TEE_PIDS[@]}"
        TEE_PIDS=()
    fi
    if tar "$zip" -cf "$OUTPUT_DIR/$RUN_STAMP.tgz" -C "$OUTPUT_DIR" "$RUN_STAMP"; then
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
# twin, never under the 25-byte layout and unlink names. The files are
# staging's own list (discover_jobfiles).
early_client_cmdline_check() {
    local src job n max=25 JOBFILES
    src=${SET_DIR_OVERRIDE:-$(workload_src_dir)} || exit 1
    discover_jobfiles "$src"
    for job in "${JOBFILES[@]}"; do
        n=$(( ${#job} + 9 ))
        [ "$n" -le "$max" ] || max=$n
    done
    JOBFILES=("$(printf '%*s' "$max" '' | tr ' ' x)")
    check_client_cmdline "the fio command line for the longest job name this set can stage"
}

run_jobs() {
    local job outfile report cmd t0 lclients=()
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
                postmortem_hosts layout "$job" "$WORK_DIR/jobs" "$TARGET_DIR" \
                    "$RUN_DIR/parse.${job%.job}" "${lclients[@]}"
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
        report=$(report_items "$SET_DIR/$job") || die "cannot read the report directive of $job"
        log "starting test run for job $job on $MASTER with ${#HOSTS[@]} workers:"
        debug "running on $MASTER: $cmd"
        run_host "$MASTER" "$cmd" > "$outfile" \
            || die "fio run failed for $job (partial output in $outfile)"
        check_fio_errors "$outfile" measured \
            || die "job $job failed on at least one host (raw output in $outfile)"
        # fio keys client_stats by the --client= name, not the worker hostname;
        # local mode reports as localhost. A results file, never a bundle: no
        # tar probe (GNU tar reads the whole file looking for a header).
        summ_one "$outfile" "$outfile" "$report" "${HOSTS[*]}" file \
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
        local f job skip results e rds=()
        for e in "$tmp"/*; do [ ! -d "$e" ] || rds+=("$e"); done
        if [ ${#rds[@]} -eq 1 ]; then
            summary_header "${rds[0]}" "${path##*/}" || echo "(no synopsis: it could not be read from $path)"
        else
            printf '(no synopsis: %s holds %d top-level directories, where a run bundle has one)\n\n' "$path" ${#rds[@]}
        fi
        # layout results are barriers: the reserved names, plus any bundled
        # jobfile with the layout marker (/dev/null keeps awk off stdin without
        # one)
        skip=" ${LAYOUT_JOB%.job} 000-wekatester-relayout ${UNLINK_JOB%.job} "
        skip="$skip$(find "$tmp" -path '*/fio-jobfiles/*' -name '*.job' -type f -print0 \
            | xargs -0 env LC_ALL=C awk -v m="$LAYOUT_MARKER" 'FNR <= 3 && index($0, m) == 1 && !(FILENAME in d) { d[FILENAME] = 1; n = split(FILENAME, p, "/"); sub(/\.job$/, "", p[n]); printf "%s ", p[n] }' /dev/null) "
        results=$(find "$tmp" -name 'results_*.json' -type f | LC_ALL=C awk -F/ '{print $NF "\t" $0}' | LC_ALL=C sort | cut -f2-)
        [ -z "$results" ] || while IFS= read -r f; do
            job=${f##*/}; job=${job#results_}; job=${job%.json}
            case "$skip" in *" $job "*) continue ;; esac
            echo "==== $job ===="
            summ_one "$f" "${f##*/}" "$items" "" bundle
        done <<<"$results"
        # -v: the hosts over the run, a stopped run's included
        if [ "$VERBOSITY" -ge 1 ] && [ ${#rds[@]} -eq 1 ]; then
            summary_counters "${rds[0]}" || printf '(counters: they could not be read from %s)\n\n' "$path"
            summary_health "${rds[0]}" || printf '(host health: it could not be read from %s)\n\n' "$path"
        fi
        rm -rf "${tmp:?}"
        [ -n "$results" ] || { echo "$path: no results_*.json files in the bundle" >&2; return 1; }
        return 0
    fi
    summ_one "$path" "$path" "$items" "$expected" file
}

# A bundle's synopsis ahead of its jobs (README, Output), from its records
# alone: one awk over every host; a piece the bundle lacks says so.
summary_header() {   # summary_header <run-dir> <bundle-name>
    local rd=$1 lists rc=0 e
    lists=$(mktemp -d "${TMPDIR:-/tmp}/wt.hdr.XXXXXX") || return 1
    : > "$lists/jobs"
    if [ -d "$rd/fio-jobfiles" ]; then
        find "$rd/fio-jobfiles" -mindepth 2 -maxdepth 2 -name '*.job' -type f | LC_ALL=C sort \
            | LC_ALL=C awk -F/ '{print $(NF - 1) "\t" $0}' > "$lists/jobs" || rc=1
    fi
    for e in "$rd"/sysinfo/* "$rd"/fio-jobfiles/*; do [ ! -d "$e" ] || printf '%s\n' "${e##*/}"; done \
        | LC_ALL=C sort -u > "$lists/hosts" || rc=1
    [ "$rc" -ne 0 ] || awkrun '
        #@awk summ_header' "$rd" "$2" "$lists/jobs" "$lists/hosts" "$UNLINK_JOB" || rc=1
    rm -rf "${lists:?}"
    return "$rc"
}

# A bundle's hosts: the recorded order, then any other it has a sysinfo/
# or fio-jobfiles/ directory for.
bundle_hosts() {   # bundle_hosts <run-dir>
    local e
    { [ ! -f "$1/settings" ] || LC_ALL=C awk -F'\t' '$1 == "hosts" { n = split($2, H, " "); for (i = 1; i <= n; i++) print H[i] }' "$1/settings"
      for e in "$1"/sysinfo/* "$1"/fio-jobfiles/*; do [ ! -d "$e" ] || printf '%s\n' "${e##*/}"; done | LC_ALL=C sort -u
    } | LC_ALL=C awk '!($0 in s) { s[$0] = 1; print }'
}

# -s -v: per host and NIC, the counters that rose between the start and
# end captures (README, Output). Lowercase ERE: the names -v lists (-vv
# lists every one that rose; AER always).
SUMMARY_COUNTER_RE=${SUMMARY_COUNTER_RE:-err|drop|discard|retrans|lost|loss|timeout|pause|fail|abort|reset|overflow|overrun|underrun|miss|fifo|crc|bad|prune|collapse|backlog|ofo|zerowindow|memorypressure|out_of_buffer|outofbuffer|nobuf|no_buf|stall|congest|ecn|spuriousrto|undersize|oversize|jabber|fragment|symbol}
summary_counters() {   # summary_counters <run-dir>
    local rd=$1 lists h side f rc=0
    lists=$(mktemp -d "${TMPDIR:-/tmp}/wt.ctr.XXXXXX") || return 1
    bundle_hosts "$rd" > "$lists/hosts" || rc=1
    while IFS= read -r h; do
        for side in start end; do
            for f in "$rd/sysinfo/$h/nics-$side" "$rd/sysinfo/$h/tcp-$side" "$rd/sysinfo/$h"/ethtool-S-*-"$side" "$rd/sysinfo/$h"/aer-*-"$side"; do
                [ ! -f "$f" ] || printf '%s\t%s\t%s\n' "$h" "$side" "$f"
            done
        done
    done < "$lists/hosts" > "$lists/files"
    echo "==== counters over the run: what rose from start to end, per host and NIC ===="
    [ "$rc" -ne 0 ] || awkrun '
        #@awk summ_counters' "$lists/files" "$lists/hosts" "$VERBOSITY" "$SUMMARY_COUNTER_RE" || rc=1
    echo
    rm -rf "${lists:?}"
    return "$rc"
}

# -s -v: per host, what the captures say went wrong around the run (README,
# Output). Thresholds: PSI "some avg10" in percent (io at the start only:
# a benchmark is io pressure by design), 1-minute load per cpu at the start,
# clock offset in ms; the kernel-log ERE is matched lowercased.
SUMMARY_PSI_CPU=${SUMMARY_PSI_CPU:-5}
SUMMARY_PSI_MEMORY=${SUMMARY_PSI_MEMORY:-1}
SUMMARY_PSI_IO=${SUMMARY_PSI_IO:-10}
SUMMARY_LOAD_PER_CPU=${SUMMARY_LOAD_PER_CPU:-0.75}
SUMMARY_CLOCK_MS=${SUMMARY_CLOCK_MS:-100}
SUMMARY_KLOG_RE=${SUMMARY_KLOG_RE:-link is down|link is up|link down|link up|nic link|carrier lost|tx timeout|transmit queue [0-9]+ timed out|netdev watchdog|mlx5.*(err|fail|timeout|health)|(ice|i40e|bnxt|ixgbe|ena|mlx4|igb)[ _].*(err|fail|reset|timeout)|hung_task|blocked for more than|soft lockup|hard lockup|rcu.*stall|aer:|pcie bus error|out of memory|oom-kill|oom_reaper|invoked oom-killer|call trace}
SUMMARY_KLOG_LINES=${SUMMARY_KLOG_LINES:-5}
summary_health() {   # summary_health <run-dir>
    local rd=$1 lists h f k v rc=0
    for k in SUMMARY_PSI_CPU SUMMARY_PSI_MEMORY SUMMARY_PSI_IO SUMMARY_LOAD_PER_CPU SUMMARY_CLOCK_MS SUMMARY_KLOG_LINES; do
        v=${!k}
        case $v in (""|*[!0-9.]*|*.*.*|.) echo "(host health: $k must be a number, not '$v')"; echo; return 0 ;; esac
    done
    lists=$(mktemp -d "${TMPDIR:-/tmp}/wt.hlt.XXXXXX") || return 1
    bundle_hosts "$rd" > "$lists/hosts" || rc=1
    while IFS= read -r h; do
        for f in pressure-cpu-start pressure-cpu-end pressure-memory-start pressure-memory-end pressure-io-start \
                 loadavg-start lscpu kernel-log-end chrony; do
            [ ! -f "$rd/sysinfo/$h/$f" ] || printf '%s\t%s\t%s\n' "$h" "$f" "$rd/sysinfo/$h/$f"
        done
    done < "$lists/hosts" > "$lists/files"
    echo "==== host health: pressure, load, kernel log and clock around the run ===="
    [ "$rc" -ne 0 ] || awkrun '
        #@awk summ_health' "$lists/files" "$lists/hosts" "$SUMMARY_PSI_CPU" "$SUMMARY_PSI_IO" "$SUMMARY_PSI_MEMORY" \
            "$SUMMARY_LOAD_PER_CPU" "$SUMMARY_CLOCK_MS" "$SUMMARY_KLOG_RE" "$SUMMARY_KLOG_LINES" || rc=1
    echo
    rm -rf "${lists:?}"
    return "$rc"
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
