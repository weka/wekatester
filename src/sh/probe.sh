# --- phase 2b: probe workers for auto-mode system info -----------------------
# Dumb by design: raw lines out, all interpretation local.
probe_remote_cmd() {
    # Raw facts out: weka cores from each wekanode PROCESS mask (per task,
    # pinned helper threads read as phantom cores); ident (the machine id);
    # shape facts (cpu_model, memtotal_kb, aio_max_nr, aio_nr, topo_*, nic,
    # weka_net or weka_net_err or weka_cli absent); bindable cpus. WEKATESTER_SYSROOT
    # is for the suite only.
    # Bindable cpus are READ, never trial-bound: sched_setaffinity accepts the
    # cgroup's cpuset. A cgroup without the controller takes its nearest
    # ancestor's, so the read walks up; a v1 cpuset line (hybrid) beats 0::.
    # No cpuset file: the taskset affinity. A failed taskset -cp, or one with
    # no list, is bindable_err and why, whatever the cpuset: fio launches
    # under taskset -c. bindable_priv: what the escalator's cgroup adds, "-"
    # if unknown.
    printf '%s' "_sr=\${WEKATESTER_SYSROOT:-}; echo \"ncpus \$(getconf _NPROCESSORS_ONLN)\"; \
        echo \"limits \$(ulimit -Sn) \$(ulimit -Hn) \$(ulimit -Su) \$(ulimit -Hu)\"; \
        echo \"wekanode \$(pgrep -xc wekanode || true)\"; \
        for p in \$(pgrep -x wekanode || true); do cat /proc/\$p/status; done \
        | awk '/^Cpus_allowed_list/ {print \"weka_allowed\", \$2}' | sort -u; \
        echo \"engines \$('$FIO_BIN' --enghelp | tr \"\\n\" \" \")\"; \
        _ts=; _te=; if _tso=\$(taskset -cp \$\$ 2>&1); then _ts=\$(printf '%s\\n' \"\$_tso\" | awk -F': ' '{print \$2}'); [ -n \"\$_ts\" ] || _te='gave no affinity list'; else _te=failed; fi; echo \"taskset \$_ts\"; \
        echo \"isolated \$([ -f \"\$_sr/sys/devices/system/cpu/isolated\" ] && cat \"\$_sr/sys/devices/system/cpu/isolated\")\"; \
        echo \"online \$([ -r \"\$_sr/sys/devices/system/cpu/online\" ] && cat \"\$_sr/sys/devices/system/cpu/online\")\"; \
        echo \"ident \$(if [ -r /sys/class/dmi/id/product_uuid ]; then cat /sys/class/dmi/id/product_uuid; elif [ -r /etc/machine-id ]; then cat /etc/machine-id; fi)\"; \
        _pv=; for pc in 'dzdo -n' pbrun sesu pmrun 'doas -n' 'ksu -e' 'sudo -n'; do set -- \$pc; _o=\$(command -v \$1) || continue; if _o=\$(timeout 5 \$pc true </dev/null 2>&1); then echo \"priv \$pc\"; _pv=\$pc; break; fi; done; \
        _cpuset() { printf '%s\\n' \"\$1\" | awk -F: '\$2 ~ /(^|,)cpuset(,|\$)/ {v1 = 1; d1 = \"/sys/fs/cgroup/\" \$2; p1 = substr(\$0, length(\$1) + length(\$2) + 3)} \$1 == \"0\" && \$2 == \"\" {v2 = 1; p2 = substr(\$0, 4)} \
            END {if (v1) {d = d1; p = p1} else if (v2) {d = \"/sys/fs/cgroup\"; p = p2} else exit; \
                for (;;) {if (p == \"/\") p = \"\"; if (v1) {print d p \"/cpuset.effective_cpus\"; print d p \"/cpuset.cpus\"} else print d p \"/cpuset.cpus.effective\"; if (p == \"\") break; sub(/\\/[^\\/]*\$/, \"\", p)}}' \
            | while IFS= read -r _f; do [ -r \"\$_sr\$_f\" ] || continue; _v=\$(cat \"\$_sr\$_f\"); [ -z \"\$_v\" ] || { printf '%s\\n' \"\$_v\"; break; }; done; }; \
        _bd=\$(_cpuset \"\$([ -r \"\$_sr/proc/self/cgroup\" ] && cat \"\$_sr/proc/self/cgroup\")\"); _bd=\${_bd:-\$_ts}; \
        if [ -z \"\$_te\" ]; then \
            _bp=; if [ -n \"\$_pv\" ] && _g=\$(timeout 5 \$_pv cat \"\$_sr/proc/self/cgroup\" </dev/null 2>&1); then _bp=\$(_cpuset \"\$_g\"); fi; \
            echo \"bindable \$_bd\"; \
            echo \"bindable_priv \$(awk -v a=\"\$_bp\" -v b=\"\$_bd\" 'function ex(s, S,    n, P, i, r, c) {n = split(s, P, \",\"); for (i = 1; i <= n; i++) if (split(P[i], r, \"-\") == 2) {for (c = r[1] + 0; c <= r[2] + 0; c++) S[c] = 1} else if (P[i] != \"\") S[P[i] + 0] = 1} \
                BEGIN {ex(a, A); ex(b, B); m = -1; for (c in A) if (c + 0 > m) m = c + 0; s = -1; o = \"\"; \
                    for (c = 0; c <= m + 1; c++) {x = (c in A) && !(c in B); if (x && s < 0) s = c; else if (!x && s >= 0) {o = o \",\" (s == c - 1 ? s : s \"-\" (c - 1)); s = -1}} \
                    print (o == \"\" ? \"-\" : substr(o, 2))}')\"; \
        else echo \"bindable_err taskset -cp \$_te: \$(printf '%s\\n' \"\${_tso:-no output}\" | head -1)\"; \
        fi; \
        _m=; if [ -z \"\$_sr\" ] && _o=\$(command -v lscpu); then _m=\$(lscpu | awk -F: '/^Model name/ {sub(/^[ \\t]+/, \"\", \$2); print \$2; exit}'); fi; \
        if [ -z \"\$_m\" ] && [ -r \"\$_sr/proc/cpuinfo\" ]; then _m=\$(awk -F: '/^model name/ {sub(/^[ \\t]+/, \"\", \$2); print \$2; exit}' \"\$_sr/proc/cpuinfo\"); fi; \
        echo \"cpu_model \${_m:--}\"; \
        echo \"memtotal_kb \$([ -r \"\$_sr/proc/meminfo\" ] && awk '/^MemTotal:/ {print \$2; exit}' \"\$_sr/proc/meminfo\")\"; \
        echo \"aio_max_nr \$([ -r \"\$_sr/proc/sys/fs/aio-max-nr\" ] && cat \"\$_sr/proc/sys/fs/aio-max-nr\")\"; \
        echo \"aio_nr \$([ -r \"\$_sr/proc/sys/fs/aio-nr\" ] && cat \"\$_sr/proc/sys/fs/aio-nr\")\"; \
        if [ -r \"\$_sr/sys/devices/system/cpu/cpu0/topology/core_id\" ]; then \
            grep -H . \"\$_sr\"/sys/devices/system/cpu/cpu[0-9]*/topology/physical_package_id \"\$_sr\"/sys/devices/system/cpu/cpu[0-9]*/topology/core_id \"\$_sr\"/sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list \
            | awk -F: '{n = split(\$1, p, \"/\"); c = p[n - 2]; sub(/^cpu/, \"\", c); print \"topo_\" p[n], c, \$2}'; \
        fi; \
        _et=\$(command -v ethtool); \
        for _d in \"\$_sr\"/sys/class/net/*; do \
            [ -e \"\$_d/device\" ] || continue; _n=\${_d##*/}; \
            _s=; if [ -n \"\$_et\" ]; then _s=\$(ethtool \"\$_n\" 2>&1 | awk '\$1 == \"Speed:\" {print \$2; exit}'); fi; \
            case \"\$_s\" in [0-9]*) ;; *) _s=; [ ! -r \"\$_d/speed\" ] || _s=\$(cat \"\$_d/speed\" 2>&1) ;; esac; \
            _p=\$(readlink \"\$_d/device\"); _p=\${_p##*/}; _r=-; _i=-; \
            if [ -e \"\$_d/device/driver\" ]; then _r=\$(readlink \"\$_d/device/driver\"); _r=\${_r##*/}; fi; \
            if [ -r \"\$_d/device/vendor\" ] && [ -r \"\$_d/device/device\" ]; then _i=\$(cat \"\$_d/device/vendor\"):\$(cat \"\$_d/device/device\"); fi; \
            case \"\$_s\" in [0-9]*) ;; *) _s=- ;; esac; \
            echo \"nic \$_n \$_s \${_p:--} \${_r:--} \${_i:--}\"; \
        done; \
        if _o=\$(command -v weka); then \
            _wx=; [ \"\$(id -u)\" = 0 ] || _wx=\$_pv; \
            if ! _cs=\$(timeout 15 weka local ps --no-header -o name 2>&1); then \
                if [ -z \"\$_wx\" ] || ! _cs=\$(timeout 15 \$_wx weka local ps --no-header -o name 2>&1); then \
                    echo \"weka_net_err ps \$(printf '%s' \"\$_cs\" | head -1)\"; _cs=; fi; fi; \
            for _c in \$_cs; do \
                if [ \"\$(id -u)\" = 0 ]; then _j=\$(timeout 15 weka local resources net -C \"\$_c\" -J 2>&1); _rc=\$?; \
                elif [ -n \"\$_wx\" ]; then _j=\$(timeout 15 \$_wx weka local resources net -C \"\$_c\" -J 2>&1); _rc=\$?; \
                else _j='needs root, and no passwordless escalator works here'; _rc=1; fi; \
                if [ \$_rc -eq 0 ]; then echo \"weka_net \$_c \$(printf '%s' \"\$_j\" | tr '\\n' ' ')\"; \
                else echo \"weka_net_err \$_c \$(printf '%s' \"\$_j\" | head -1)\"; fi; \
            done; \
        else echo 'weka_cli absent'; fi; true"
}

# Each engine's real one-file job on one host's destination (--enghelp lists
# only what fio was built with): "host engine ok|fail" lines into
# engine.results, the fio output in et/. "first" stops at the first pass and
# expects failures, so it warns only of a stuck one.
prove_host_engines() {   # prove_host_engines <host> <dir> <all|first> <engine>...
    local host=$1 hd=$2 mode=$3 results="$WORK_DIR/engine.results" avail="" c tmo _w
    shift 3
    # the probe's engines line, near its top: read, not an awk per host
    while read -ra _w; do
        [ "${_w[0]:-}" = engines ] || continue
        avail=" ${_w[*]:1}"; break
    done < "$WORK_DIR/probe/$host"
    for c in "$@"; do
        case " $avail " in
            *" $c "*) ;;
            *) echo "$c: not in this fio's --enghelp list" > "$WORK_DIR/et/$host.$c.out"
               echo "$host $c fail" >> "$results"; continue ;;
        esac
        # A broken engine can hang, and a direct-IO write on a sick
        # mount parks fio in D state, where SIGKILL and timeout(1) both
        # stall. So: the bounded job reports its exit status down a pipe,
        # read the moment it exits; past the read's bound it is killed, and
        # abandoned if it will not die.
        tmo=${WEKATESTER_ENGINE_TEST_TIMEOUT:-15}
        # 137 is timeout's -k KILL: said in the evidence, which a silent
        # hung fio would otherwise leave empty, and unquoted.
        # bash -c: process substitution and read -t are bash's. fio
        # writes to fd 4, the session's stdout: one that will not die holds
        # it until its IO ends, ssh too. -9 goes to timeout's process group,
        # fio's too; _o keeps kill's complaints out of the evidence.
        if run_host "$host" "bash -c 'f=\$1/.wekatester-enginetest.\$\$; exec 4>&1; \
                exec 3< <(timeout -k 5 $tmo \"\$2\" --name=et --ioengine=$c --rw=write --bs=64k \
                --filesize=64k --filename=\"\$f\" --direct=1 \
                --output-format=json >&4 4>&- & echo \$!; wait \$!; echo \$?); \
                read -r p <&3; \
                if read -t $((tmo + 10)) rc <&3; then \
                    [ \$rc -ne 137 ] || echo \"fio ignored TERM, killed at $((tmo + 5)) s\" >&2; \
                    rm -f \"\$f\"; exit \$rc; fi; \
                _o=\$(kill -9 -- -\$p \$p 2>&1); sleep 1; \
                _o=\$(kill -0 -- -\$p 2>&1 || kill -0 \$p 2>&1) && echo WEKATESTER_ENGINE_STUCK; \
                rm -f \"\$f\"; exit 124' et '$hd' '$FIO_BIN'" \
                > "$WORK_DIR/et/$host.$c.out" 2>&1; then
            echo "$host $c ok" >> "$results"
            [ "$mode" = all ] || return 0
        else
            echo "$host $c fail" >> "$results"
            if grep -q WEKATESTER_ENGINE_STUCK "$WORK_DIR/et/$host.$c.out"; then
                log "WARNING: $host: ioengine $c test is STUCK in uninterruptible IO -- abandoned; direct IO on $hd may be broken on this host" >&2
            elif [ "$mode" = all ]; then
                log "WARNING: $host: ioengine $c failed its test job (see $WORK_DIR/et/$host.$c.out)" >&2
            fi
        fi
    done
}

# Prove engine candidates with a real one-file job on each host destination
# (--enghelp lists only what fio was built with): -e, host-file engines, and
# under -a the tuner list. Results to engine.results ("host engine ok|fail");
# each probe engines line keeps only the engines that passed.
test_engines() {
    local host results="$WORK_DIR/engine.results" csv_engines="" cand et_pids=() _p
    mkdir -p "$WORK_DIR/et"
    : > "$results"
    if [ -n "$TARGETS_FILE" ] && [ -f "$TARGETS_FILE" ]; then
        csv_engines=$(awk -F, '#@awk test_engines.csv' "$TARGETS_FILE" | sort -u | tr '\n' ' ')
    fi
    cand="$ENGINE $csv_engines"
    [ -z "$AUTO_LEVEL" ] || cand="$cand io_uring libaio psync"
    cand=$(printf '%s\n' $cand | awk '!seen[$0]++' | tr '\n' ' ')
    [ -n "${cand// /}" ] || return 0
    log "proving ioengine candidates on ${#HOSTS[@]} host(s):$(printf ' %s' $cand)"
    load_host_dirs
    local i
    for i in "${!HOSTS[@]}"; do
        prove_host_engines "${HOSTS[$i]}" "${HOST_DIRS[$i]}" all $cand &
        et_pids+=($!)
    done
    # SCOPED wait: a bare wait also waits on the run-log tees, which exit only
    # after finalize; it hangs silently here.
    for _p in "${et_pids[@]}"; do wait "$_p"; done
    # rewrite each probe's engines line to the proven subset (untested
    # engines are dropped only in auto mode, where the list WAS the tests)
    if [ -n "$AUTO_LEVEL" ]; then
        local none=() c nolist
        # one awk for the fleet: each engines line becomes the engines that
        # passed; hosts where none did come back one per line
        nolist=$(awkrun '#@awk test_engines' "$results" "$WORK_DIR/probe" "${HOSTS[@]}") || die "cannot record the proven ioengines"
        while IFS= read -r host; do
            [ -z "$host" ] || none+=("$host")
        done <<<"$nolist"
        # A host with no proven engine would fail later under an error that no
        # longer names the cause, and the workdir dies with the process: quote
        # the evidence now.
        if [ ${#none[@]} -gt 0 ]; then
            for host in "${none[@]}"; do
                for c in $cand; do
                    [ -s "$WORK_DIR/et/$host.$c.out" ] || continue
                    log "$host: ioengine $c: $(tail -1 "$WORK_DIR/et/$host.$c.out")" >&2
                done
            done
            die "no ioengine passed its test job on ${none[*]} (tried:$(printf ' %s' $cand)); -a $AUTO_LEVEL needs one that works there -- check direct IO on the destination and the fio build"
        fi
    fi
    # a PINNED engine failing anywhere is fatal, naming host and evidence
    if [ -n "$ENGINE" ]; then
        # one awk: the first host, in host order, without a passing test of it
        host=$(awk '#@awk test_engines.pinned' "$ENGINE" "$results" "${HOSTS[@]}")
        if [ -n "$host" ]; then
            # the workdir dies with the process: quote the evidence now
            [ ! -f "$WORK_DIR/et/$host.$ENGINE.out" ] || tail -5 "$WORK_DIR/et/$host.$ENGINE.out" >&2
            die "ioengine '$ENGINE' failed its test job on $host (fio output above)"
        fi
    fi
}

# Finish the host-file resolution with the engine results, then insist any
# host-line engine assignment actually works on its host.
finalize_targets() {
    [ "$TARGETS" -eq 1 ] || return 0
    local host eng
    resolve_targets phase2 "$TARGETS_FILE" "${ENGINE:--}" \
        "$([ "$DIRECTORY_EXPLICIT" -eq 1 ] && printf '%s' "$DIRECTORY" || printf -- -)" \
        "$WORK_DIR/engine.results" "${HOSTS[@]}" > "$WORK_DIR/targets.final" \
        || die "host file resolution failed ($TARGETS_FILE)"
    HOST_DIRS_KEY=""   # a host_dir_v map of an earlier targets.final is stale
    # one awk for the fleet: the first host, in host order, whose host-file
    # engine did not pass its test there
    local bad
    bad=$(awk '#@awk finalize_targets' "$WORK_DIR/targets.final" "$WORK_DIR/engine.results" "${HOSTS[@]}")
    if [ -n "$bad" ]; then
        host=${bad%% *}; eng=${bad#* }
        [ ! -f "$WORK_DIR/et/$host.$eng.out" ] || tail -5 "$WORK_DIR/et/$host.$eng.out" >&2
        die "host file assigns ioengine '$eng' to $host but its test job failed (fio output above)"
    fi
}

# Engine precedence: -e, the host file, the jobfile's own ioengine=, then
# this. Where a source jobfile names none and the host file gives the host
# none, the first of ENGINE_ORDER that passes its test there goes into
# engine.discovered ("host engine"); -a picks its own.
discover_engines() {
    [ -z "$AUTO_LEVEL" ] && [ -z "$ENGINE" ] || return 0
    local src f files=() lacking host need=() i c r pick et_pids=() _p none=() results="$WORK_DIR/engine.results"
    local -A known=() dir_of=()
    src=${SET_DIR_OVERRIDE:-$(workload_src_dir)} || exit 1
    for f in "$src"/[0-9]*; do [ -f "$f" ] && files+=("$f"); done
    [ ${#files[@]} -gt 0 ] || return 0
    lacking=$(awkrun '#@awk discover_engines' "${files[@]}") || die "cannot read the ioengine lines of the jobfiles in $src"
    [ -n "$lacking" ] || return 0
    : > "$WORK_DIR/engine.discovered"
    load_host_dirs
    # a host the host file gives an engine needs none (targets_column: "" for none)
    i=0
    while IFS= read -r c; do
        [ -n "$c" ] || need+=("${HOSTS[$i]}")
        dir_of[${HOSTS[$i]}]=${HOST_DIRS[$i]}; i=$((i + 1))
    done < <(if [ -f "$WORK_DIR/targets.final" ]; then targets_column 3 "$WORK_DIR/targets.final" "${HOSTS[@]}"; else printf '%s\n' "${HOSTS[@]/*/}"; fi)
    [ ${#need[@]} -gt 0 ] || return 0
    log "discovering an ioengine on ${#need[@]} host(s): no ioengine in the host file or the jobfiles for$(printf ' %s' $lacking)"
    mkdir -p "$WORK_DIR/et"; touch "$results"
    # an engine the host file's selector lines already proved is not run again
    while read -r host c r; do known[$host $c]=$r; done < "$results"
    for host in "${need[@]}"; do
        set --
        for c in $ENGINE_ORDER; do
            case ${known[$host $c]:-} in ok) break ;; fail) ;; *) set -- "$@" "$c" ;; esac
        done
        [ $# -eq 0 ] && continue
        prove_host_engines "$host" "${dir_of[$host]}" first "$@" &
        et_pids+=($!)
    done
    # SCOPED wait, as in test_engines: the run-log tees never exit here
    for _p in ${et_pids[@]+"${et_pids[@]}"}; do wait "$_p"; done
    known=()
    while read -r host c r; do [ "$r" != ok ] || known[$host $c]=ok; done < "$results"
    for host in "${need[@]}"; do
        pick=""
        for c in $ENGINE_ORDER; do [ -z "${known[$host $c]:-}" ] || { pick=$c; break; }; done
        if [ -z "$pick" ]; then none+=("$host"); continue; fi
        echo "$host $pick" >> "$WORK_DIR/engine.discovered"
        log "$host: ioengine $pick discovered, the first of $ENGINE_ORDER to pass its test job: no ioengine in the host file or the jobfiles"
    done
    [ ${#none[@]} -gt 0 ] || return 0
    # the workdir dies with the process: quote the evidence now
    for host in "${none[@]}"; do
        for c in $ENGINE_ORDER; do
            [ -s "$WORK_DIR/et/$host.$c.out" ] || continue
            log "$host: ioengine $c: $(tail -1 "$WORK_DIR/et/$host.$c.out")" >&2
        done
    done
    die "no ioengine passed its test job on ${none[*]} (tried: $ENGINE_ORDER); the host file and the jobfiles name none there -- check direct IO on the destination and the fio build"
}

# cpus_allowed enforcement: a requested list must already be allowed (taskset
# -cp) or need a passwordless escalator to launch fio under taskset -c; an
# overlap with weka cores is fatal without one, a warning with one. The
# decision lands in $WORK_DIR/auth/<host>.priv and <host>.cpus.
check_cpu_pinning() {
    local host req cur priv ncpus
    # local mode never ran establish_connections; the lifecycle still reads
    # the same per-host files
    [ -n "$AUTH_DIR" ] || { AUTH_DIR="$WORK_DIR/auth"; mkdir -p "$AUTH_DIR"; }
    # One awk for every host (six per host took 20s at 451 hosts). Per host
    # with a request, in host order: host, request, taskset, cpu count, four
    # cpu sets, comma-joined flags, then the escalator prefix (it has spaces);
    # "-" for empty.
    awkrun '
    #@awk check_cpu_pinning' "$WORK_DIR/targets.final" "$WORK_DIR/probe" "${AUTO_LEVEL:--}" "${HOSTS[@]}" \
        > "$WORK_DIR/pin.verdicts" || die "cpu pinning check failed"
    local dedicated effective phantom unbindable os0 vflags nolist_hosts=() nolist_eff=()
    while read -r host req cur ncpus dedicated effective phantom unbindable os0 vflags priv; do
        [ "$cur" != "-" ] || cur=""
        [ "$ncpus" != "-" ] || ncpus=""
        [ "$priv" != "-" ] || priv=""
        vflags=${vflags//,/ }
        # a host with no list asked for nothing: the notes below all describe
        # a request, so it gets none of them, only the one summary line
        case "$vflags" in
            (*nolist*)
                case "$vflags" in
                    (*allweka*)
                        die "$host: no cpu is left for fio -- each is one of weka's pinned cores, core 0's pair, or one this login cannot bind" ;;
                esac
                nolist_hosts+=("$host"); nolist_eff+=("$effective") ;;
        esac
        case "$vflags" in
            (*nolist*) ;;
            (*allweka*)
                case "$vflags" in
                    (*catchall*)
                        die "$host: the host file's cpu list ($req) covers every cpu fio could use, which counts as no list, and the OS reserve then leaves fio no cpus -- mount weka with fewer cores, use a larger client, or list fewer cpus (a narrower list is the operator's own reserve)" ;;
                esac
                if [ "$unbindable" != none ]; then
                    die "$host: no requested cpu ($req) is usable -- each is a weka dedicated core, a cpu this host does not have, or one it refuses to bind ($unbindable)"
                fi
                if [ "$phantom" != none ]; then
                    die "$host: no requested cpu ($req) is usable -- each is a weka dedicated core or a cpu this host does not have ($phantom; the host has $ncpus cpus: 0-$((ncpus - 1)))"
                fi
                if [ "$os0" != none ]; then
                    die "$host: no requested cpu ($req) is usable -- core 0 and its sibling ($os0) stay with the OS, and the rest are weka dedicated cores"
                fi
                die "$host: every requested cpu ($req) is a weka dedicated core -- nothing left to run fio on" ;;
        esac
        case "$vflags" in
            (*nolist*) ;;
            (*unbindable*)
                log "note: $host: requested cpus ($req) include $unbindable, which this host refuses to bind -- offline, or held by another cgroup's cpuset partition; executing on the remainder ($effective) -- the host file keeps the list as written" ;;
        esac
        case "$vflags" in
            (*nolist*) ;;
            (*catchall*)
                # one note says it all: the phantom, core-0 and weka-overlap
                # notes below would each describe a list that counts as none
                log "note: $host: requested cpus ($req) cover every cpu fio could use, which counts as no list: the OS reserve applies as if the host file gave none; executing on $effective -- the host file keeps the list as written" ;;
            (*phantom*)
                log "note: $host: requested cpus ($req) name cpus this host does not have ($phantom; the host has $ncpus cpus: 0-$((ncpus - 1))); executing on the remainder ($effective) -- the host file keeps the list as written" ;;
        esac
        case "$vflags" in
            (*nolist*) ;;
            (*mixed*)
                # safe with cpus_allowed_policy=split beside every list: each
                # job holds one cpu, and single-cpu affinity cannot collapse
                log "note: $host: requested cpus ($req) span isolated and housekeeping cpus; per-job split affinity keeps each job on its own cpu" ;;
        esac
        case "$vflags" in
            (*nolist*|*catchall*) ;;
            (*core0*)
                log "note: $host: requested cpus ($req) include core 0's pair ($os0), which stays with the OS; executing on the remainder ($effective) -- the host file keeps the list as written" ;;
        esac
        case "$vflags" in
            (*nolist*|*catchall*) ;;
            (*overlap*)
                # the host file keeps the operator's list AS WRITTEN;
                # execution simply never touches weka's own cores
                log "note: $host: requested cpus ($req) overlap weka's dedicated cores ($dedicated); executing on the remainder ($effective) -- the host file keeps the list as written" ;;
        esac
        case "$vflags" in
            (*outside*)
                if [ -z "$priv" ]; then
                    log "ERROR: $host: effective cpus_allowed: $effective (requested: $req)" >&2
                    log "ERROR: $host: current taskset:        ${cur:-unknown}" >&2
                    log "ERROR: $host: weka dedicated cores:   $dedicated" >&2
                    die "$host: the effective cpus are outside the current taskset and no passwordless escalator (dzdo/pbrun/sesu/pmrun/doas/ksu/sudo) works"
                fi ;;
        esac
        # escalate ONLY where the effective mask cannot be self-applied:
        # privileges are as-needed, never just because they exist
        local need_priv=0
        case "$vflags" in (*outside*) need_priv=1 ;; esac
        if [ -n "$priv" ] && [ "$need_priv" -eq 1 ]; then
            printf '%s\n' "$priv" > "$AUTH_DIR/$host.priv"
        fi
        printf '%s\n' "$effective" > "$AUTH_DIR/$host.cpus"
        local under=""
        [ -z "$priv" ] || [ "$need_priv" -ne 1 ] || under="under $priv "
        debug "$host: fio server will run ${under}taskset -c $effective"
    done < "$WORK_DIR/pin.verdicts"
    if [ ${#nolist_hosts[@]} -gt 0 ]; then
        log "note: fio stays off weka's pinned cores and core 0's pair on the ${#nolist_hosts[@]} host(s) the host file gives no cpu list (${nolist_hosts[0]}: ${nolist_eff[0]}$([ ${#nolist_hosts[@]} -eq 1 ] || printf ', ...'))"
    fi
}

# A weka CLI on the master: as the login user first, ONE retry under the
# escalator on failure, then the caller fallback. No caller at present; kept
# as the tested way to reach the weka CLI for a future master-side fact.
run_weka_master() {   # run_weka_master <weka-cmd> <outfile>
    local mpriv
    run_host "$MASTER" "$1" > "$2" && return 0
    mpriv=$(host_priv "$MASTER")
    [ -n "$mpriv" ] || return 1
    run_host "$MASTER" "$mpriv $1" > "$2" || return 1
    log "NOTE: $MASTER: '$1' needed $mpriv (the unprivileged attempt failed)" >&2
}

# Gather per-host facts + master-side extras into $WORK_DIR/probe/.
probe_workers() {
    echo
    log "probing ${#HOSTS[@]} worker(s)..."
    mkdir -p "$WORK_DIR/probe"
    local pids=() failed=() host i bad=() cmd
    cmd=$(probe_remote_cmd)
    for host in "${HOSTS[@]}"; do
        run_host "$host" "$cmd" > "$WORK_DIR/probe/$host" &
        pids+=($!)
    done
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}" || failed+=("${HOSTS[$i]}")
    done
    [ ${#failed[@]} -eq 0 ] || die "probe failed on: ${failed[*]}"

    # fio launches under taskset -c: a host where taskset -cp failed, or
    # whose bindable cpus the probe could not read, cannot be pinned, and
    # nothing is guessed (Frank, 2026-10-11). One awk for the fleet.
    local unread line
    unread=$(awkrun '#@awk probe_workers.bindable' "$WORK_DIR/probe" "${HOSTS[@]}") || die "cannot read the probe results in $WORK_DIR/probe"
    if [ -n "$unread" ]; then
        while IFS= read -r line; do
            log "ERROR: ${line%% *}: cannot pin fio: ${line#* }" >&2
            bad+=("${line%% *}")
        done <<<"$unread"
        die "cannot pin fio on: ${bad[*]} -- fio launches under taskset -c, which needs a working taskset -cp and a known cpu list there; nothing is guessed"
    fi

    # -e names an engine explicitly, and the probe already knows what each
    # worker's fio can load -- refuse now rather than fail at job start.
    if [ -n "$ENGINE" ]; then
        # one awk for the fleet: the hosts whose engines line lacks it
        local lack
        # (an empty or unreadable probe lacks it too, as the grep said)
        lack=$(awkrun '#@awk probe_workers' "$ENGINE" "$WORK_DIR/probe" "${HOSTS[@]}")
        [ -z "$lack" ] \
            || die "ioengine '$ENGINE' is not available (fio --enghelp) on: $lack"
    fi
}
