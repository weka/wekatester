# --- phase 1: preflight --------------------------------------------------------
# One run per host (README): a lock directory in each host's tmpfs whose owner
# line names this run, taken in preflight's own session before anything is
# written, and released by cleanup.
declare -gA RUN_LOCKS=()   # host -> 1 while this run holds its lock
LOCK_TOKEN=""
lock_token() {   # lock_token -> LOCK_TOKEN
    printf -v LOCK_TOKEN '%s pid %s user %s since %(%Y-%m-%d %H:%M:%S)T' \
        "$(local_short_hostname)" "$$" "$(id -un)" -1
    LOCK_TOKEN=${LOCK_TOKEN//\'/}
}

# preflight's remote command: no executable fio exits 1. Another run's traces
# (its lock, staging, or any fio of wekatester's) print "held ..." and exit 75;
# fio wekatester did not start prints "alien ..." and exits 76, and is never
# touched. --break-lock clears the traces first and prints "healed ...".
lock_take_cmd() {   # lock_take_cmd -> LOCK_CMD
    local fb=${FIO_BIN##*/} pg="pgrep -x fio" mine
    fb=${fb:0:15}   # pgrep -x matches the 15-byte process name
    ere_quote_v "$fb"
    [ "$fb" = fio ] || pg="$pg; pgrep -x '$ERE_QUOTED'"
    # wekatester's fio, by its args: its server, the runs that read its
    # staging, its engine tests
    mine="'$FIO_BIN --server --daemonize=$FIO_PIDFILE'*|*'$TARGET_DIR'*|*.wekatester-enginetest.*"
    LOCK_CMD="_o=\$(command -v '$FIO_BIN') && [ -f \"\$_o\" ] && [ -x \"\$_o\" ] || exit 1; lk='$LOCK_DIR'; td='$TARGET_DIR'; ev=; al=; ours=; seen=' '"
    LOCK_CMD+="; if [ -d \"\$lk\" ]; then o=; [ ! -r \"\$lk/owner\" ] || read -r o < \"\$lk/owner\" || :; [ \"\$o\" = '$LOCK_TOKEN' ] || ev=\"\$ev lock(\${o:-no owner})\"; fi"
    LOCK_CMD+="; [ ! -e \"\$td\" ] || ev=\"\$ev staged(\$td)\"; [ ! -e \"\$td.cal\" ] || ev=\"\$ev staged(\$td.cal)\""
    LOCK_CMD+="; for p in \$($pg); do case \"\$seen\" in *\" \$p \"*) continue ;; esac; seen=\"\$seen\$p \""
    LOCK_CMD+="; a=\$(ps -o args= -p \$p) || continue; case \"\$a\" in *'<defunct>') ;; $mine) ours=\"\$ours \$p\" ;; *) al=\"\$al \$p:\${a%% *}\" ;; esac; done"
    LOCK_CMD+="; [ -z \"\$ours\" ] || ev=\"\$ev fio(\${ours# })\"; [ -z \"\$al\" ] || { echo \"alien\$al\"; exit 76; }"
    if [ "$BREAK_LOCK" -eq 1 ]; then
        # TERM, then -9, then -9 under the first escalator that works (the
        # probe's order): a root fio needs one. still() keeps the pids alive
        # and still ours: a zombie is gone, and a reused pid is not ours.
        LOCK_CMD+="; still() { l2=; for p in \$left; do a=\$(ps -o args= -p \$p) || continue; case \"\$a\" in *'<defunct>') ;; $mine) l2=\"\$l2 \$p\" ;; esac; done; left=\$l2; }"
        LOCK_CMD+="; if [ -n \"\$ev\" ]; then left=\$ours; for p in \$left; do _o=\$(kill \$p 2>&1) || :; done"
        LOCK_CMD+="; i=0; while [ -n \"\$left\" ] && [ \$i -lt 5 ]; do sleep 1; i=\$((i+1)); still; done"
        LOCK_CMD+="; if [ -n \"\$left\" ]; then _o=\$(kill -9 \$left 2>&1) || :; sleep 1; still; fi"
        LOCK_CMD+="; if [ -n \"\$left\" ]; then for pc in 'dzdo -n' pbrun sesu pmrun 'doas -n' 'ksu -e' 'sudo -n'; do set -- \$pc; _o=\$(command -v \$1) || continue; _o=\$(timeout 5 \$pc kill -9 \$left 2>&1) && break; done; sleep 1; still; fi"
        LOCK_CMD+="; [ -z \"\$left\" ] || { echo \"held\$ev unkillable(\${left# })\"; exit 75; }"
        LOCK_CMD+="; _o=\$(rm -rf \"\${td:?}\" \"\${td:?}.cal\" \"\${lk:?}\" 2>&1) || :; _o=\$(rm -f '$FIO_PIDFILE' 2>&1) || :; echo \"healed\$ev\"; fi"
    else
        LOCK_CMD+="; [ -z \"\$ev\" ] || { echo \"held\$ev\"; exit 75; }"
    fi
    # mkdir is the atomic take; a host named twice finds this run's own lock
    LOCK_CMD+="; if ! mkdir \"\$lk\"; then [ -d \"\$lk\" ] || { echo nolock; exit 77; }; o=; [ ! -r \"\$lk/owner\" ] || read -r o < \"\$lk/owner\" || :; [ \"\$o\" = '$LOCK_TOKEN' ] && exit 0; echo \"held lock(\${o:-no owner})\"; exit 75; fi"
    LOCK_CMD+="; printf '%s\\n' '$LOCK_TOKEN' > \"\$lk/owner\""
}
# cleanup's half: the lock goes only when it is still this run's
lock_release_cmd() {   # lock_release_cmd -> LOCK_RELEASE
    LOCK_RELEASE="o=; [ ! -r '$LOCK_DIR/owner' ] || read -r o < '$LOCK_DIR/owner' || :; [ \"\$o\" != '$LOCK_TOKEN' ] || rm -rf '$LOCK_DIR'"
}

# Every host reachable over ssh with $FIO_BIN, checked in parallel, every
# failure reported. Each check opens the host ControlMaster for the run, and
# takes the run lock.
preflight() {
    if [ "$LOCAL_MODE" -eq 1 ]; then
        log "checking $FIO_BIN on the local host..."
    else
        log "checking ssh connectivity and $FIO_BIN on ${#HOSTS[@]} host(s)..."
    fi
    local pids=() failed=() host i rc held=0 line
    [ -n "$LOCK_TOKEN" ] || lock_token
    lock_take_cmd
    mkdir -p "$WORK_DIR/lock" || die "cannot create $WORK_DIR/lock"
    for i in "${!HOSTS[@]}"; do
        run_host "${HOSTS[$i]}" "$LOCK_CMD" > "$WORK_DIR/lock/$i" &
        pids+=($!)
    done
    for i in "${!HOSTS[@]}"; do
        host=${HOSTS[$i]}
        wait "${pids[$i]}"
        rc=$?
        line=""; [ ! -s "$WORK_DIR/lock/$i" ] || IFS= read -r line < "$WORK_DIR/lock/$i" || :
        # 255 is ssh's own "could not connect" status. Local mode has no ssh, so
        # a local command that happens to exit 255 is just a missing fio.
        if [ "$rc" -eq 255 ] && [ "$LOCAL_MODE" -eq 0 ]; then
            failed+=("$host: ssh failed")
        elif [ "$rc" -eq 0 ]; then
            RUN_LOCKS[$host]=1
            [ "${line%% *}" != healed ] || log "NOTE: $host: --break-lock cleared another run's${line#healed}" >&2
        elif [ "$rc" -eq 75 ]; then
            held=1; failed+=("$host: another wekatester run is here, or one that did not clean up:${line#held}")
        elif [ "$rc" -eq 76 ]; then
            failed+=("$host: fio that wekatester did not start is running (pid:command${line#alien}); stop it first -- wekatester never kills fio it did not start")
        elif [ "$rc" -eq 77 ]; then
            failed+=("$host: cannot create the run lock $LOCK_DIR")
        else
            failed+=("$host: $FIO_BIN not found, or not an executable file")
        fi
    done
    if [ ${#failed[@]} -gt 0 ]; then
        for host in "${failed[@]}"; do
            log "ERROR: $host" >&2
        done
        [ "$held" -eq 0 ] || log "a run that is gone: rerun with --break-lock, which kills wekatester's own fio on those hosts and clears its lock and staging" >&2
        die "preflight failed on ${#failed[@]} of ${#HOSTS[@]} host(s), exiting"
    fi
    debug "preflight passed on all hosts"
}

# --- phase 1b: mount mode verification ----------------------------------------
# wekafs must be forcedirect (direct=1 alone leaves the client cache in the
# path); anything else must be a network filesystem, never a local disk,
# which is also what an unmounted weka mount point is.
NETWORK_FSTYPES="nfs nfs4 cifs smb3 smbfs lustre gpfs beegfs ceph fuse.ceph fuse.ceph-fuse glusterfs fuse.glusterfs panfs pvfs2 orangefs ocfs2 gfs2 afs cvfs quobyte fuse.quobyte fuse.daos fuse.juicefs fuse.mfs ${WEKATESTER_NETWORK_FSTYPES:-}"

# ok, "fail <mode>", network, or "local <type>", left in MOUNT_VERDICT, from
# a /proc/mounts line: its 3rd field is the type, its 4th the options.
classify_mount_line_v() {   # classify_mount_line_v <proc-mounts-line> -> MOUNT_VERDICT
    local fstype="" opts=""
    read -r _ _ fstype opts _ <<<"$1"
    if [ "$fstype" = "wekafs" ]; then
        case ",$opts," in
            *,forcedirect,*) MOUNT_VERDICT=ok ;;
            *,writecache,*)  MOUNT_VERDICT="fail writecache" ;;
            *,readcache,*)   MOUNT_VERDICT="fail readcache" ;;
            *)               MOUNT_VERDICT="fail unknown" ;;
        esac
    else
        case " $NETWORK_FSTYPES " in
            (*" $fstype "*) MOUNT_VERDICT=network ;;
            (*)             MOUNT_VERDICT="local $fstype" ;;
        esac
        [ -n "$fstype" ] || MOUNT_VERDICT="local "
    fi
}

# One line: the /proc/mounts line of the mount holding <dir> (quoted for the
# remote shell), or an empty one. The last line for its mount point wins, as
# a stacked mount is the visible one; findmnt -T names the point once per
# stacked mount. The check classifies this line, records it and rechecks it.
mount_line_cmd_v() {   # mount_line_cmd_v <quoted-dir> -> MOUNT_LINE_CMD
    local prog='#@awk proc_mount_line'
    MOUNT_LINE_CMD="t=\$(findmnt -T $1 -n -o TARGET) && T=\"\$t\" awk '$prog' /proc/mounts"
}

# <dir>/<i> holds line i, and <dir>/sums one cksum over them all; the names
# are the indexes, so an unchanged line gives an identical sums line.
write_mount_lines() {   # write_mount_lines <dir> <line>...
    local d=$1 i=0 l names=()
    shift
    mkdir -p "$d" || die "cannot create $d"
    for l in "$@"; do
        printf '%s\n' "$l" > "$d/$i" || die "cannot write $d/$i"
        names+=("$i"); i=$((i + 1))
    done
    (cd "$d" && cksum "${names[@]}") > "$d/sums" || die "cannot checksum the mount lines in $d"
}

# Right before the measured run, one parallel round: every host's mount line
# must be the one verify_mount_mode recorded. A change, or a line that cannot
# be read, stops the run, -r included.
check_mounts_unchanged() {
    log "checking that the destination mount is unchanged on ${#HOSTS[@]} host(s)..."
    [ -s "$WORK_DIR/mount/sums" ] || die "no mount record from the mount check in $WORK_DIR/mount"
    local td i line was pids=() rcs=() now=() old=() new=() changed=()
    td=$(mktemp -d "$WORK_DIR/mnt.XXXXXX") || die "cannot create a scratch dir for the mount recheck"
    load_host_dirs
    for i in "${!HOSTS[@]}"; do
        mount_line_cmd_v "'${HOST_DIRS[$i]}'"
        ( run_host "${HOSTS[$i]}" "$MOUNT_LINE_CMD" > "$td/$i.out" ) &
        pids[$i]=$!
    done
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}"; rcs[$i]=$?
        line=""; IFS= read -r line < "$td/$i.out" || :
        now[$i]=$line
    done
    write_mount_lines "$td/now" "${now[@]}"
    mapfile -t old < "$WORK_DIR/mount/sums"
    mapfile -t new < "$td/now/sums"
    for i in "${!HOSTS[@]}"; do
        [ "${rcs[$i]}" -ne 0 ] || [ -z "${now[$i]}" ] || [ "${old[$i]:-}" != "${new[$i]:-}" ] || continue
        was=""; IFS= read -r was < "$WORK_DIR/mount/$i" || :
        if [ "${rcs[$i]}" -ne 0 ]; then line="unreadable (rc=${rcs[$i]})"
        elif [ -z "${now[$i]}" ]; then line="no /proc/mounts line"
        else line="\"${now[$i]}\""; fi
        changed+=("${HOSTS[$i]}: the mount at ${HOST_DIRS[$i]} changed since the mount check -- was \"$was\", now $line")
    done
    rm -rf "${td:?}"
    if [ ${#changed[@]} -gt 0 ]; then
        for line in "${changed[@]}"; do log "ERROR: $line" >&2; done
        die "the destination mount changed on ${#changed[@]} of ${#HOSTS[@]} host(s) after it was verified; the measured run did not start"
    fi
    debug "destination mount unchanged on all hosts"
}

# Creates a missing destination only when its nearest existing parent is
# wekafs in this same session: a weka client that restarted since the check
# leaves a root-disk mount point. Exit 4: not wekafs now. The type is the 3rd
# field of the parent's /proc/mounts line, the line the check classified.
create_dest_cmd() {   # create_dest_cmd <dir>
    mount_line_cmd_v '"$p"'
    printf '%s' "p='$1'; while [ ! -e \"\$p\" ]; do q=\$(dirname \"\$p\"); [ \"\$q\" != \"\$p\" ] || exit 4; p=\$q; done; [ \"\$($MOUNT_LINE_CMD | awk '{print \$3}')\" = wekafs ] || exit 4; mkdir -p -- '$1'"
}

# For a missing destination: the nearest existing ancestor, then its mount's
# /proc/mounts line. Nonzero when it does exist, or nothing does. dirname
# handles a trailing slash and stops at /.
missing_dir_probe_cmd() {   # missing_dir_probe_cmd <dir>
    mount_line_cmd_v '"$p"'
    printf '%s' "[ ! -e '$1' ] || exit 1; p='$1'; while [ ! -e \"\$p\" ]; do q=\$(dirname \"\$p\"); [ \"\$q\" != \"\$p\" ] || exit 1; p=\$q; done; printf '%s\\n' \"\$p\"; $MOUNT_LINE_CMD"
}

# One probe file as the fio user; on a shared filesystem one failing host
# usually means all.
probe_writable() {   # probe_writable <host> <dir>
    # the same session drops the host's name into the run's group file
    # there: collect_fs_groups hashes it once every host is through
    host_name_v "$1"
    run_host "$1" "p='$2'/.wekatester-write-probe.\$\$; : > \"\$p\" && rm -f \"\$p\"${GROUP_FILE:+ && printf '%s\\n' '$HOST_NAME' >> '$2/$GROUP_FILE'}"
}

# --- filesystem groups ---
# Each client appends its name to the run group file in its destination; equal
# sha256 means one directory, one group. Distinct files cannot hash alike: each
# ends with a name only its own clients appended. Writes $WORK_DIR/groups,
# "<host> <group>".
collect_fs_groups() {
    [ -n "$GROUP_FILE" ] || return 0
    local i h pids=() sum n=0 line summary
    local -A at=()
    mkdir -p "$WORK_DIR/fsgroup" || die "cannot create $WORK_DIR/fsgroup"
    load_host_dirs
    for i in "${!HOSTS[@]}"; do
        h=${HOSTS[$i]}
        ( run_host "$h" "sha256sum '${HOST_DIRS[$i]}/$GROUP_FILE'" > "$WORK_DIR/fsgroup/$i.sum" ) &
        pids[$i]=$!
    done
    : > "$WORK_DIR/fsgroup/sums"
    for i in "${!HOSTS[@]}"; do
        h=${HOSTS[$i]}
        sum=""
        if wait "${pids[$i]}"; then read -r sum _ < "$WORK_DIR/fsgroup/$i.sum" || sum=""; fi
        case "$sum" in
            (*[!0-9a-f]*|"") die "$h: cannot hash the filesystem-group file ${HOST_DIRS[$i]}/$GROUP_FILE (written by the mount check; the destination must not change after it)" ;;
        esac
        printf '%s %s\n' "$h" "$sum" >> "$WORK_DIR/fsgroup/sums"
    done
    pids=()
    for i in "${!HOSTS[@]}"; do
        run_host "${HOSTS[$i]}" "rm -f '${HOST_DIRS[$i]}/$GROUP_FILE'" &
        pids+=($!)
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || log "WARNING: ${HOSTS[$i]}: could not remove ${HOST_DIRS[$i]}/$GROUP_FILE" >&2
    done
    awk '!($2 in g) {g[$2] = ++n} {print $1, g[$2]}' "$WORK_DIR/fsgroup/sums" > "$WORK_DIR/groups"
    # the count, then each group's members, from one awk: a pass per group
    # was groups x hosts when every host has its own directory
    summary=$(awk '{ if ($2 in m) m[$2] = m[$2] " " $1; else m[$2] = $1; if ($2 + 0 > n) n = $2 + 0 } END { print n + 0; for (i = 1; i <= n; i++) print i "\t" m[i] }' "$WORK_DIR/groups")
    n=${summary%%$'\n'*}
    if [ "$n" -le 1 ]; then
        debug "filesystem groups: all ${#HOSTS[@]} host(s) share ${HOST_DIRS[0]}"
        return 0
    fi
    for i in "${!HOSTS[@]}"; do [ -n "${at[${HOSTS[$i]}]+set}" ] || at[${HOSTS[$i]}]=$i; done
    log "filesystem groups: $n -- each lays out and is priced for its own fleet-shared read set"
    while IFS=$'\t' read -r i line; do
        h=${line%% *}
        log "  group $i: $line (at ${HOST_DIRS[${at[$h]}]} on $h)"
    done <<<"${summary#*$'\n'}"
}

# The first host of <host> group lays out, prices and removes its shared read
# set; every host is one group when collect_fs_groups did not run.
group_first() {   # group_first <host>
    if [ -s "$WORK_DIR/groups" ]; then
        awk -v h="$1" '$1 == h {g = $2} {if (!($2 in f)) f[$2] = $1} END {print (g != "" ? f[g] : h)}' "$WORK_DIR/groups"
    else
        printf '%s\n' "${HOSTS[0]}"
    fi
}

# Every host of <host>'s filesystem group, in host order, one per line.
group_members() {   # group_members <host>
    if [ -s "$WORK_DIR/groups" ]; then
        awk -v h="$1" 'NR == FNR {if ($1 == h) g = $2; next} $2 == g {print $1}' \
            "$WORK_DIR/groups" "$WORK_DIR/groups"
    else
        printf '%s\n' "${HOSTS[@]}"
    fi
}

write_fix_hint() {   # write_fix_hint <dir> -> how to fix a directory the login user cannot write
    printf '%s' "fix the root's owner/mode (a one-time 'sudo chmod 1777 $1' on any host persists in the filesystem) or run as a user that can write"
}

# Asked once for every host that lacks the destination. -r/-n: 5s, default
# create, and created outright without a terminal; otherwise only a y creates.
confirm_create_dirs() {   # confirm_create_dirs <count>
    local msg="create the missing destination directory on $1 host(s)?"
    if [ "$FAST_TRACK" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
        if try_interactive; then
            confirm_timed 5 yes "$msg" \
                || die "destination directory does not exist on $1 host(s)"
        else
            log "destination directory does not exist on $1 host(s); creating it (unattended)"
        fi
    else
        require_interactive "creating the destination directory" "create it yourself, or use -r"
        confirm_explicit "$msg" \
            || die "destination directory does not exist on $1 host(s)"
    fi
}

# All workers: -d must not be a cached-mode wekafs mount, and must be writable
# by the login user (fio reports a worker EACCES so quietly the run "succeeds"
# with zero IO). A missing -d is created only under a wekafs mount, after one
# question (README, Caveats).
verify_mount_mode() {
    log "checking mount mode and writability of the destination on ${#HOSTS[@]} host(s)..."
    # one name per run, so two runs sharing a destination never read each
    # other's group lines (collect_fs_groups)
    [ -n "$GROUP_FILE" ] || printf -v GROUP_FILE '.wekatester-group.%(%s)T.%s.lst' -1 "$$"
    local host line verdict failed=() mode_fail=0 write_fail=0 local_fail=0 gone_fail=0 proc_fail=0 hd anc i ft pl=()
    local missing=() missing_dirs=() missing_parents=() procs=()
    local cached_hosts=() cached_modes=() mode who n
    # Three fan-outs: every host gets the same commands in the same order and
    # the messages come back in host order, as a serial walk produced them;
    # only the waiting overlaps. Per-host output goes to files under the work
    # dir, or a temp dir when the suite calls this phase alone.
    local td pids=() hds=() rcs=() ancs=() msgs=() probe=()
    td=$(mktemp -d "${WORK_DIR:-${TMPDIR:-/tmp}}/mnt.XXXXXX") \
        || die "cannot create a scratch dir for the mount check"
    load_host_dirs
    for i in "${!HOSTS[@]}"; do
        hds[$i]=${HOST_DIRS[$i]}
        mount_line_cmd_v "'${hds[$i]}'"
        ( run_host "${HOSTS[$i]}" "$MOUNT_LINE_CMD" > "$td/$i.mnt" ) &
        pids[$i]=$!
    done
    for i in "${!HOSTS[@]}"; do
        wait "${pids[$i]}"; rcs[$i]=$?
        line=""; IFS= read -r line < "$td/$i.mnt" || :
        procs[$i]=$line
    done
    # findmnt fails for a path that does not exist: classify the nearest
    # ancestor that does, and remember that the destination is missing
    pids=()
    for i in "${!HOSTS[@]}"; do
        [ "${rcs[$i]}" -ne 0 ] || continue
        ( run_host "${HOSTS[$i]}" "$(missing_dir_probe_cmd "${hds[$i]}")" > "$td/$i.anc" ) &
        pids[$i]=$!
    done
    for i in "${!HOSTS[@]}"; do
        [ "${rcs[$i]}" -ne 0 ] || continue
        pl=()
        # the ancestor, then its mount's /proc/mounts line
        if wait "${pids[$i]}"; then mapfile -t pl < "$td/$i.anc"; fi
        if [ ${#pl[@]} -ge 2 ]; then
            ancs[$i]=${pl[0]}; procs[$i]=${pl[1]}
        else
            msgs[$i]="${HOSTS[$i]}: findmnt failed for ${hds[$i]} -- does it exist? (wrong -d?)"
        fi
    done
    # classification is local, of the line the record keeps and fio sees (a
    # stacked mount's visible one); probe[i] marks the hosts that get the
    # write probe: destination present, mode ok (or -r's warning)
    for i in "${!HOSTS[@]}"; do
        [ -z "${msgs[$i]:-}" ] || continue
        host=${HOSTS[$i]}; hd=${hds[$i]}; anc=${ancs[$i]:-}
        # the line check_mounts_unchanged holds the run to
        if [ -z "${procs[$i]:-}" ]; then
            msgs[$i]="$host: no /proc/mounts line for the mount holding ${anc:-$hd} (findmnt -T TARGET names a mount point /proc/mounts does not list)"
            proc_fail=1
            continue
        fi
        classify_mount_line_v "${procs[$i]}"; verdict=$MOUNT_VERDICT
        case "$verdict" in
            ok)   ;;
            network)
                  if [ -n "$anc" ]; then
                      msgs[$i]="$host: $hd does not exist, and $anc is not a wekafs mount -- create it yourself, or check that -d names the right directory"
                      continue
                  fi
                  debug "$host: $hd is on a network filesystem, not wekafs; the weka mount guard does not apply" ;;
            local*)
                  # refused before anything is written: a local disk is never a target
                  local_fail=1
                  ft=${verdict#local }; [ -n "$ft" ] || ft="a filesystem findmnt did not name"
                  if [ -n "$anc" ]; then
                      msgs[$i]="$host: $hd does not exist, and $anc is on $ft, not a network filesystem -- wekatester never writes to a local disk: check that weka is mounted on this host and that -d names a directory on it"
                  else
                      msgs[$i]="$host: $hd is on $ft, not a network filesystem -- wekatester never writes to a local disk: check that weka (or another network filesystem) is mounted there on this host"
                  fi
                  continue ;;
            fail*) if [ "$FAST_TRACK" -eq 1 ]; then
                       # said once per MODE after the loop: 111 identical
                       # lines is noise, not information (field fleet D, 2026-09-09)
                       cached_hosts+=("$host"); cached_modes+=("${verdict#fail }")
                   else
                       msgs[$i]="$host: wekafs mounted ${verdict#fail } (need forcedirect)"
                       mode_fail=1
                       continue
                   fi ;;
        esac
        if [ -n "$anc" ]; then
            missing+=("$host"); missing_dirs+=("$hd"); missing_parents+=("$anc")
            continue   # created below, once the operator agrees, then probed
        fi
        probe[$i]=1
    done
    pids=()
    for i in "${!HOSTS[@]}"; do
        [ "${probe[$i]:-0}" -eq 1 ] || continue
        ( probe_writable "${HOSTS[$i]}" "${hds[$i]}" ) &
        pids[$i]=$!
    done
    for i in "${!HOSTS[@]}"; do
        [ "${probe[$i]:-0}" -eq 1 ] || continue
        wait "${pids[$i]}" \
            || { msgs[$i]="${HOSTS[$i]}: cannot create files in ${hds[$i]} -- $(write_fix_hint "${hds[$i]}")"
                 write_fail=1; }
    done
    for i in "${!HOSTS[@]}"; do
        [ -z "${msgs[$i]:-}" ] || failed+=("${msgs[$i]}")
    done
    rm -rf "${td:?}"
    # The -r warning, one line per distinct cached mode: the host alone when
    # it is one host, "all N" when it is every host, the list otherwise.
    if [ ${#cached_hosts[@]} -gt 0 ]; then
        for mode in $(printf '%s\n' "${cached_modes[@]}" | sort -u); do
            who=""; n=0
            for i in "${!cached_hosts[@]}"; do
                [ "${cached_modes[$i]}" = "$mode" ] || continue
                who="$who${who:+ }${cached_hosts[$i]}"; n=$((n + 1))
            done
            if [ "$n" -eq 1 ]; then
                warn_prerun "$who: wekafs mounted $mode (need forcedirect); -r continues anyway -- the client cache is in the IO path and the numbers include it"
            elif [ "$n" -eq ${#HOSTS[@]} ]; then
                warn_prerun "wekafs mounted $mode (need forcedirect) on all $n hosts; -r continues anyway -- the client cache is in the IO path and the numbers include it"
            else
                warn_prerun "wekafs mounted $mode (need forcedirect) on $n of ${#HOSTS[@]} hosts ($who); -r continues anyway -- the client cache is in the IO path and the numbers include it"
            fi
        done
    fi
    # Missing destinations are created only when nothing else is wrong: no
    # mutation on a run that is about to stop anyway.
    if [ ${#missing[@]} -gt 0 ]; then
        if [ ${#failed[@]} -gt 0 ]; then
            for i in "${!missing[@]}"; do
                log "${missing[$i]}: ${missing_dirs[$i]} does not exist; not created while other checks fail"
            done
        else
            for i in "${!missing[@]}"; do
                log "${missing[$i]}: ${missing_dirs[$i]} does not exist; ${missing_parents[$i]} is a wekafs mount"
            done
            confirm_create_dirs "${#missing[@]}"
            # one fan-out, each host its mkdir and then its write probe
            local rc
            pids=()
            for i in "${!missing[@]}"; do
                ( run_host "${missing[$i]}" "$(create_dest_cmd "${missing_dirs[$i]}")"
                  case $? in (0) ;; (4) exit 4 ;; (*) exit 2 ;; esac
                  probe_writable "${missing[$i]}" "${missing_dirs[$i]}" || exit 3 ) &
                pids[$i]=$!
            done
            for i in "${!missing[@]}"; do
                host=${missing[$i]}; hd=${missing_dirs[$i]}
                wait "${pids[$i]}"; rc=$?
                if [ "$rc" -eq 4 ]; then
                    failed+=("$host: $hd was not created -- the nearest directory above it is no longer on a wekafs mount (did the weka client restart?)")
                    gone_fail=1
                    continue
                fi
                if [ "$rc" -eq 2 ]; then
                    failed+=("$host: cannot create $hd -- $(write_fix_hint "${missing_parents[$i]}")")
                    write_fail=1
                    continue
                fi
                log "$host: created $hd"
                [ "$rc" -eq 0 ] \
                    || { failed+=("$host: cannot create files in $hd -- $(write_fix_hint "$hd")")
                         write_fail=1; }
            done
        fi
    fi
    if [ ${#failed[@]} -gt 0 ]; then
        for line in "${failed[@]}"; do log "ERROR: $line" >&2; done
        # Advise a remount only when a mount mode was the problem: when findmnt
        # failed everywhere, -d most likely does not exist.
        [ "$mode_fail" -eq 0 ] || \
            die "wekafs at $DIRECTORY must be mounted with forcedirect; remount and re-run"
        [ "$local_fail" -eq 0 ] || \
            die "a destination is on a local filesystem; wekatester writes only to weka or another network filesystem -- nothing was written"
        [ "$gone_fail" -eq 0 ] || \
            die "the weka mount above a missing destination went away before it was created; nothing was created on a local disk -- check the weka client and re-run"
        [ "$write_fail" -eq 0 ] || \
            die "$DIRECTORY is not writable on every host; fio cannot lay out its files there"
        [ "$proc_fail" -eq 0 ] || \
            die "the destination mount's /proc/mounts line was not found on every host; the run is held to that line, so it cannot start"
        die "cannot determine the mount at $DIRECTORY; check that it exists and that -d names the right directory"
    fi
    # the record check_mounts_unchanged compares against; a created
    # destination's line is its parent's, the mount it was created on. The
    # suite calls this phase without a work dir.
    [ -z "${WORK_DIR:-}" ] || write_mount_lines "$WORK_DIR/mount" "${procs[@]}"
    debug "mount mode and writability ok on all hosts"
}
