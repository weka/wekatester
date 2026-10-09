# --- phase 2: fio server lifecycle ---------------------------------------------
# Daemons are tracked by pidfile only, never pkill by name: the host may run
# fio jobs that are not ours.
FIO_STARTED=0

# Kill the pidfile daemon and wait until every process of ours is gone (TERM
# up to 3s, then KILL). fio --server forks a child per connection, so the
# drain matches the full command line, anchored to the fio binary and
# carrying the pidfile path.
kill_fio_cmd() {   # kill_fio_cmd [priv]
    kill_fio_cmd_v "$1"
    printf '%s' "$KILL_FIO_CMD"
}
# Without the subshell: start and cleanup build it once per host. A loop
# that ended before its 15th poll saw no server, so only a timed-out one
# looks again before the -9.
kill_fio_cmd_v() {   # kill_fio_cmd_v [priv] -> KILL_FIO_CMD
    # An escalated server is root-owned: the kill needs the same escalator. The
    # ^ anchor is load-bearing: this shell carries the pattern in its own
    # cmdline (an unanchored pkill -9 once killed the teardown). taskset execs
    # fio, so argv starts with the binary.
    local priv=${1:+$1 }
    local pat="^$FIO_BIN --server --daemonize=$FIO_PIDFILE"
    KILL_FIO_CMD="if [ -f '$FIO_PIDFILE' ]; then _o=\$(${priv}kill \$(cat '$FIO_PIDFILE') 2>&1) || true; ${priv}rm -f '$FIO_PIDFILE'; fi; \
        i=0; while _o=\$(pgrep -f '$pat') && [ \"\$i\" -lt 15 ]; do sleep 0.2; i=\$((i+1)); done; \
        if [ \"\$i\" -ge 15 ] && _o=\$(pgrep -f '$pat'); then ${priv}pkill -9 -f '$pat' || true; fi"
}

start_fio_servers() {
    echo
    log "starting fio servers on ${#HOSTS[@]} host(s)..."
    local pids=() failed=() host i priv cpus launch base
    for host in "${HOSTS[@]}"; do
        priv=""; cpus=""
        [ ! -s "$AUTH_DIR/$host.priv" ] || IFS= read -r priv < "$AUTH_DIR/$host.priv" || :
        [ ! -s "$AUTH_DIR/$host.cpus" ] || IFS= read -r cpus < "$AUTH_DIR/$host.cpus" || :
        base="'$FIO_BIN' --server --daemonize='$FIO_PIDFILE'"
        # a cpu list pins the server (children inherit the mask). The
        # escalation is for the taskset only: fio drops back to the login user
        # via runuser, so test files stay user-owned; no runuser means a root
        # fio, and the NOTE says so.
        launch=$base
        [ -z "$cpus" ] || launch="taskset -c $cpus $launch"
        if [ -n "$priv" ] && [ -n "$cpus" ]; then
            launch="u=\$(id -un); if _o=\$(command -v runuser) && $priv runuser -u \"\$u\" -- true </dev/null; then echo WEKATESTER_FIO_AS=user; $priv taskset -c $cpus runuser -u \"\$u\" -- $base; else echo WEKATESTER_FIO_AS=root; $priv taskset -c $cpus $base; fi"
        elif [ -n "$priv" ]; then
            launch="$priv $launch"
        fi
        kill_fio_cmd_v "$priv"
        run_host "$host" "$KILL_FIO_CMD; $launch" > "$WORK_DIR/launch.$host" &
        pids+=($!)
    done
    FIO_STARTED=1   # set before checking: partial starts must still be torn down
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}" || failed+=("${HOSTS[$i]}")
    done
    # one grep for the fleet: the launches that reported a root fio
    local roots
    roots=$(grep -l "WEKATESTER_FIO_AS=root" "${HOSTS[@]/#/$WORK_DIR/launch.}") || :
    for host in "${HOSTS[@]}"; do
        case $'\n'"$roots"$'\n' in
            (*$'\n'"$WORK_DIR/launch.$host"$'\n'*)
                log "NOTE: $host: fio runs as root (no runuser drop-back) -- files it creates are root-owned, and a later unprivileged run on them will fail with EACCES" >&2 ;;
        esac
    done
    [ ${#failed[@]} -eq 0 ] || die "failed to start fio server on: ${failed[*]}"
    # let the listeners settle before the first coordinator connect; the
    # override exists for the test suite, whose stubbed servers need no settling
    sleep "${WEKATESTER_SETTLE:-2}"
    debug "fio servers running on all hosts"
}

# The master must reach every worker on $FIO_PORT (fio would silently benchmark
# the survivors). One remote shell probes all at once; each probe is one
# statement (bash survives a failed exec redirection) printing "FAIL <host>",
# and DONE proves the snippet finished.
port_probe_cmd() {   # port_probe_cmd <host>... -> remote snippet
    local h cmd="${COORD_NPROC:+ulimit -Su $COORD_NPROC; }pids=''; for h in"
    for h in "$@"; do cmd="$cmd '$h'"; done
    cmd="$cmd; do ( timeout 3 bash -c \": </dev/tcp/\$h/$FIO_PORT\" || echo \"FAIL \$h\" ) & pids=\"\$pids \$!\"; done; wait \$pids; echo DONE"
    printf '%s' "$cmd"
}

# --- the limits a run must fit ----------------------------------------------
# Every client runs at once, so the limits that grow with the fleet are
# checked first. A soft limit short of the need is raised when the hard limit
# allows; otherwise the run stops, naming the limit and the host.
limit_short() {   # limit_short <limit|unlimited> <need>: the limit is a number below the need
    case $1 in (unlimited|''|*[!0-9]*) return 1 ;; esac
    [ "$1" -lt "$2" ]
}

# The controller needs an ssh master per host plus, during a fan-out, a
# subshell and an ssh client per host: three per host (302 for 100 measured).
check_controller_procs() {
    [ "$LOCAL_MODE" -eq 0 ] || return 0
    local n=${#HOSTS[@]} soft hard cur need
    soft=$(ulimit -Su); hard=$(ulimit -Hu)
    cur=$(ps -u "$(id -u)" -o pid= | wc -l)
    need=$(( 3 * n + cur + 64 ))
    limit_short "$soft" "$need" || return 0
    if limit_short "$hard" "$need"; then
        die "this controller allows $(id -un) $hard processes (ulimit -Hu), and $n hosts need about $need at once: an ssh master per host, plus a subshell and an ssh client per host while a phase talks to every host ($cur already running) -- raise nproc for $(id -un) (/etc/security/limits.conf), or run from a controller that allows more"
    fi
    ulimit -Su "$need" || die "cannot raise this run's process limit to $need (ulimit -Su)"
    log "note: raised this run's process limit (ulimit -u) from $soft to $need for $n hosts (the hard limit is $hard)"
}

# The coordinator: fio --client holds one connection per client and raises no
# limit, and the port check runs three processes per client from one shell.
# The raise rides those commands (COORD_NOFILE, COORD_NPROC).
COORD_NOFILE=""; COORD_NPROC=""
check_coordinator_limits() {
    local n=${#HOSTS[@]} tag sn hn su hu need
    read -r tag sn hn su hu < <(awk '$1 == "limits" {print; exit}' "$WORK_DIR/probe/$MASTER")
    if [ "$tag" != limits ]; then
        log "WARNING: $MASTER: its probe reported no limits; the coordinator's open files and processes are unchecked" >&2
        return 0
    fi
    need=$(( n + 64 ))
    if limit_short "$sn" "$need"; then
        limit_short "$hn" "$need" \
            && die "$MASTER: fio's coordinator keeps one connection open per client, so $n clients need about $need open files, and $MASTER allows $hn (ulimit -Hn) -- raise nofile for the login user on $MASTER (/etc/security/limits.conf), or name a host that allows more first"
        COORD_NOFILE=$need
        log "note: $MASTER: fio's coordinator runs with its open-file limit raised from $sn to $need for $n clients (the hard limit is $hn)"
    fi
    need=$(( 3 * n + 64 ))
    if limit_short "$su" "$need"; then
        limit_short "$hu" "$need" \
            && die "$MASTER: the fio port check probes every client at once from one shell, so $n clients need about $need processes there, and $MASTER allows $hu (ulimit -Hu) -- raise nproc for the login user on $MASTER (/etc/security/limits.conf), or name a host that allows more first"
        COORD_NPROC=$need
        log "note: $MASTER: the port check runs with its process limit raised from $su to $need for $n clients (the hard limit is $hu)"
    fi
}

# One ssh session to the master, every probe inside it: one session per
# worker fanned N sessions into one multiplexed connection, past MaxSessions
# (10) and MaxStartups, and 39 of 111 probes read as firewalls.
verify_fio_ports() {
    log "verifying fio port $FIO_PORT reachability from $MASTER..."
    local out rc failed=() host hint line
    out=$(run_host "$MASTER" "$(port_probe_cmd "${HOSTS[@]}")"); rc=$?
    case "$out" in
        (*DONE*) ;;   # the session ran to its end; FAIL lines, not rc, carry the verdict
        (*) die "cannot run the fio port check on $MASTER -- the ssh session to the master failed (rc=$rc), which says nothing about port $FIO_PORT" ;;
    esac
    while IFS= read -r line; do
        case "$line" in ("FAIL "*) failed+=("${line#FAIL }") ;; esac
    done <<PORTEOF
$out
PORTEOF
    if [ ${#failed[@]} -gt 0 ]; then
        # On loopback the usual culprit is the name resolving to ::1 while fio
        # listens on IPv4, not a firewall.
        hint="(host firewall?)"
        [ "$LOCAL_MODE" -eq 0 ] || \
            hint="(loopback resolution? fio binds IPv4 -- check that localhost resolves to 127.0.0.1)"
        for host in "${failed[@]}"; do
            log "ERROR: $MASTER cannot reach $host:$FIO_PORT $hint" >&2
        done
        die "fio port check failed on ${#failed[@]} of ${#HOSTS[@]} host(s), exiting"
    fi
    debug "fio port reachable on all hosts"
}

cleanup() {
    local host f priv pids=() kcmd
    # the end-of-run pressure/sar capture rides the still-open connections;
    # after this function the control masters are gone
    if [ "$PRESSURE_END_DONE" -eq 0 ]; then
        PRESSURE_END_DONE=1
        snapshot_pressure end
    fi
    [ ${#RUN_LOCKS[@]} -eq 0 ] || lock_release_cmd
    if [ "$FIO_STARTED" -eq 1 ]; then
        FIO_STARTED=0   # idempotent: EXIT trap may follow an INT trap
        log "stopping fio servers..."
        for host in "${HOSTS[@]}"; do
            # a privileged launch made a root-owned server: the kill needs the
            # same escalator or the run leaks a root fio
            priv=""
            [ -z "$AUTH_DIR" ] || [ ! -s "$AUTH_DIR/$host.priv" ] || IFS= read -r priv < "$AUTH_DIR/$host.priv" || :
            kill_fio_cmd_v "$priv"
            # the run lock goes in the same session, last
            kcmd="$KILL_FIO_CMD; rm -rf '$TARGET_DIR' '$TARGET_DIR.cal'"
            [ -z "${RUN_LOCKS[$host]:-}" ] || { kcmd="$kcmd; $LOCK_RELEASE"; unset "RUN_LOCKS[$host]"; }
            run_host "$host" "$kcmd" &
            pids+=($!)
        done
        # These pids only: a bare wait also waits on the run-log tees, which
        # exit only after cleanup returns. That is a deadlock.
        wait "${pids[@]}" || true
    fi
    # a run that ended before its fio started: the locks on their own
    if [ ${#RUN_LOCKS[@]} -gt 0 ]; then
        pids=()
        for host in "${!RUN_LOCKS[@]}"; do
            run_host "$host" "$LOCK_RELEASE" &
            pids+=($!)
        done
        RUN_LOCKS=()
        wait "${pids[@]}" || true
    fi
    if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
        # Close every ControlMaster at once (one at a time was seconds at a few
        # hundred hosts), then drop the work dir. -q silences the banner; a
        # failed -O exit still reports on stderr.
        pids=()
        for f in "${CTRL_DIR:-$WORK_DIR/c}"/*; do
            [ -S "$f" ] || continue
            ssh -q -O exit -o ControlPath="$f" unused-host-arg &
            pids+=($!)
        done
        [ ${#pids[@]} -eq 0 ] || wait "${pids[@]}" || true
        rm -rf "$WORK_DIR"
    fi
}

# --- connection establishment ----------------------------------------------------

# The ssh master sockets, in the work dir: /dev/shm/wt.XXXXXX/c plus %C's 40
# and ssh's ~17-byte temporary suffix stays well inside a unix socket path.
make_ctrl_dir() {
    CTRL_DIR=$WORK_DIR/c
    mkdir -p "$CTRL_DIR" || die "cannot create $CTRL_DIR"
}
# Every credential against every client, first success wins (README,
# Authentication); each round tries the unconnected clients in parallel, and
# nothing dies here. Passwords: a fifo per attempt, a helper reading ONE line,
# NumberOfPasswordPrompts=1. Auth overrides go BEFORE $SSH_OPTS: ssh keeps the
# first value, and BatchMode=yes disables askpass.
prompt_password_creds() {
    local j login pw
    require_interactive "-p" "use key-based auth (-i) for unattended runs"
    for ((j = 1; j <= PW_COUNT; j++)); do
        printf 'ssh login %d of %d (empty for %s): ' "$j" "$PW_COUNT" "$(id -un)" >&"$PROMPT_OUT_FD"
        IFS= read -r login <&"$PROMPT_IN_FD" || die "no login read"
        case "$login" in
            *[[:space:]]*) die "logins must not contain whitespace" ;;
        esac
        printf 'password for %s: ' "${login:-the default user}" >&"$PROMPT_OUT_FD"
        IFS= read -r -s pw <&"$PROMPT_IN_FD" || die "no password read"
        printf '\n' >&"$PROMPT_OUT_FD"
        [ -n "$pw" ] || die "empty password (pair $j of $PW_COUNT)"
        PW_LOGINS+=("$login")
        PW_SECRETS+=("$pw")
    done
}

# One connection attempt. external: is a user-owned master alive (ssh -O
# check, our ControlPath absent)? default/key: a master in our socket dir
# with BatchMode. pw: the same, through askpass.
SETSID_BIN=""
attempt_host() {   # attempt_host <mode> <host> <login> <key-or-pw-index>
    local u=() fifo rc
    [ -z "$3" ] || u=(-o "User=$3")
    case "$1" in
        external)
            ssh -O check $SSH_OPTS "$2" > "$AUTH_DIR/$2.extcheck" 2>&1 ;;
        default)
            ssh -n "${u[@]}" $SSH_OPTS $CONTROL_OPTS "$2" true ;;
        key)
            ssh -n "${u[@]}" -o "IdentityFile=$4" -o IdentitiesOnly=yes \
                $SSH_OPTS $CONTROL_OPTS "$2" true ;;
        pw)
            fifo="$AUTH_DIR/$2.fifo"
            mkfifo -m 600 "$fifo" || return 1
            # Hold the fifo open read-write for the attempt (fd 4 is private to
            # it): a fifo drops its contents when the last fd closes, and the
            # helper open blocks until a writer exists. Our write cannot block;
            # the helper reads ONE line.
            exec 4<>"$fifo"
            printf '%s\n' "${PW_SECRETS[$4]}" >&4
            WEKATESTER_PW_FIFO="$fifo" SSH_ASKPASS="$AUTH_DIR/askpass.sh" \
                SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-wekatester}" \
                $SETSID_BIN ssh -o BatchMode=no -o NumberOfPasswordPrompts=1 \
                "${u[@]}" $SSH_OPTS $CONTROL_OPTS "$2" true </dev/null
            rc=$?
            exec 4>&-
            rm -f "$fifo" "$fifo.used"
            return "$rc" ;;
    esac
}

# One round: this credential against every still-unconnected client, in
# parallel. Winners record their per-host transport delta and leave the pool.
REMAINING=()
auth_round() {   # auth_round <label> <mode> <login> <key-or-pw-index>
    [ ${#REMAINING[@]} -gt 0 ] || return 0
    local host pids=() effs=() left=() i n=0 eff logins=()
    # a credential's own login wins; else the host file pins this host's
    # (one awk for the round, not one per host)
    if [ -z "$3" ] && [ -f "$WORK_DIR/targets.phase1" ]; then
        while IFS= read -r eff; do logins+=("$eff"); done \
            < <(targets_column 2 "$WORK_DIR/targets.phase1" "${REMAINING[@]}")
    fi
    for i in "${!REMAINING[@]}"; do
        host=${REMAINING[$i]}
        eff=$3
        [ -n "$eff" ] || eff=${logins[$i]:-}
        effs+=("${eff:-.}")
        attempt_host "$2" "$host" "$eff" "$4" &
        pids+=($!)
    done
    for i in "${!REMAINING[@]}"; do
        host=${REMAINING[$i]}
        if wait "${pids[$i]}"; then
            n=$((n + 1))
            eff=${effs[$i]}; [ "$eff" = "." ] && eff=""
            [ "$2" != external ] || : > "$AUTH_DIR/$host.external"
            [ -z "$eff" ] || printf '%s\n' "$eff" > "$AUTH_DIR/$host.user"
            debug "$host: connected via $1"
        else
            left+=("$host")
        fi
    done
    REMAINING=()
    [ ${#left[@]} -eq 0 ] || REMAINING=("${left[@]}")
    [ "$n" -eq 0 ] || log "auth: $n host(s) connected via $1"
}

# The password goes back ONCE per attempt; a second question gets a failure,
# never a second fifo read (that hung the run). A host-key question gets no,
# as BatchMode does. A key passphrase question is refused without using the
# answer up, so ssh moves on to the password.
write_askpass_helper() {   # write_askpass_helper <path>
    cat > "$1" <<'ASKSH' || die "cannot write the askpass helper"
#!/bin/sh
case "$1" in
    *"continue connecting"*|*"(yes/no"*) echo no; exit 0 ;;
    *[Pp]assphrase*) exit 1 ;;
esac
[ ! -e "$WEKATESTER_PW_FIFO.used" ] || exit 1
: > "$WEKATESTER_PW_FIFO.used"
IFS= read -r pw < "$WEKATESTER_PW_FIFO"
printf '%s\n' "$pw"
ASKSH
    chmod 700 "$1" || die "cannot mark the askpass helper executable"
}

establish_connections() {
    AUTH_DIR="$WORK_DIR/auth"
    mkdir -p "$AUTH_DIR" || die "cannot create $AUTH_DIR"
    [ "$PW_COUNT" -eq 0 ] || prompt_password_creds
    # The helper resolves its fifo at run time from the attempt's environment
    # (single-quoted heredoc-style: no expansion here).
    write_askpass_helper "$AUTH_DIR/askpass.sh"
    # setsid detaches the tty for OpenSSH older than 8.4, which lacks
    # SSH_ASKPASS_REQUIRE.
    SETSID_BIN=$(command -v setsid || true)
    log "connecting to ${#HOSTS[@]} host(s)..."
    REMAINING=("${HOSTS[@]}")
    auth_round "an existing ssh session" external "" ""
    auth_round "default ssh auth" default "" ""
    local i
    for i in "${!IDENT_KEYS[@]}"; do
        auth_round "key ${IDENT_LOGINS[$i]:+${IDENT_LOGINS[$i]}:}${IDENT_KEYS[$i]}" \
            key "${IDENT_LOGINS[$i]}" "${IDENT_KEYS[$i]}"
    done
    for i in "${!PW_SECRETS[@]}"; do
        auth_round "password $((i + 1)) (${PW_LOGINS[$i]:-default user})" \
            pw "${PW_LOGINS[$i]}" "$i"
    done
    PW_SECRETS=()
    [ ${#REMAINING[@]} -eq 0 ] \
        || log "WARNING: no working ssh credentials for: ${REMAINING[*]}" >&2
}
