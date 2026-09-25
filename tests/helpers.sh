# Shared fixtures for tests/test_wekatester.sh.

# --- probe remote snippet stub (Task 4) ---
# taskset refuses cpus 3 and 5, so the snippet's per-cpu bind test has
# something to find; sudo always fails, so the escalator sweep is
# deterministic wherever the suite runs.
probe_stub() {
    stub=$(mktemp -d)   # leaked on purpose; tests are short-lived
    printf '#!/bin/sh\necho 8\n' > "$stub/getconf"
    printf '#!/bin/sh\nexit 1\n' > "$stub/pgrep"     # no wekanode procs
    printf '#!/bin/sh\necho " io_uring libaio"\n' > "$stub/fio"
    printf '#!/bin/sh\nexit 1\n' > "$stub/sudo"
    printf '#!/bin/sh\nshift\nexec "$@"\n' > "$stub/timeout"
    cat > "$stub/taskset" <<'TASKSETEOF'
#!/bin/sh
case "$1" in
  -cp) echo "pid $2's current affinity list: 0-7"; exit 0 ;;
  -c)  case "$2" in 3|5) echo "taskset: failed to set affinity: Invalid argument" >&2; exit 1 ;; esac
       shift 2; exec "$@" ;;
esac
TASKSETEOF
    chmod +x "$stub"/*
    (source ./wekatester; FIO_BIN=fio; PATH="$stub:$PATH" bash -c "$(probe_remote_cmd)")
}
export -f probe_stub

# --- tuner: fabricate probe dir + jobfile, run auto_tune ---
tuner_fixture() {   # $1 = extra probe content variant
    FIX=$(mktemp -d)
    mkdir -p "$FIX/probe" "$FIX/jobs" "$FIX/src"
    # weka's dedicated io threads are single-CPU task masks (0, 1, 2 here);
    # the 0,3-4 line is a wide utility-thread mask and must be ignored.
    printf 'ncpus 8\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nweka_allowed 0,3-4\nengines io_uring libaio psync \n' > "$FIX/probe/h1"
    printf 'ncpus 8\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nweka_allowed 0,3-4\nengines io_uring libaio psync \n' > "$FIX/probe/h2"
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 1073741824 0 1073741824 1%% /mnt/weka\n' > "$FIX/probe/_df"
    printf '# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\ndirectory=/orig\nioengine=libaio\n[create]\ncreate_only=1\n[bw]\nstonewall\nrw=read\niodepth=1\n' > "$FIX/src/011-bw.job"
}

# --- signal handling: park a real run in preflight so it can be signalled ---
# ssh is stubbed with a script that records that it started and then sleeps, so
# the run blocks in preflight's `wait` -- where a real run spends most of its
# time -- with no network and no worker involved.
signal_fixture() {
    SIG=$(mktemp -d)
    printf '#!/bin/sh\ntouch "%s/started"\nexec sleep 5\n' "$SIG" > "$SIG/ssh"
    chmod +x "$SIG/ssh"
    PATH="$SIG:$PATH"
}

# Block until the stubbed ssh has run, so a signal cannot race process startup.
signal_wait_started() {
    local i=0
    while [ ! -e "$SIG/started" ] && [ "$i" -lt 500 ]; do
        sleep 0.01; i=$((i + 1))
    done
    [ -e "$SIG/started" ]
}

# --- local mode: prove the transport never reaches for ssh ---
# ssh and scp stubs that fail loudly, shadowing the real binaries. Without
# them, a local-mode test would still pass on any box where ssh-to-localhost
# happens to work, so the "no sshd required" guarantee would go unverified.
no_ssh_fixture() {
    NOSSH=$(mktemp -d)   # leaked on purpose; tests are short-lived
    printf '#!/bin/sh\necho "ERROR: %s invoked in local mode" >&2\nexit 99\n' ssh > "$NOSSH/ssh"
    printf '#!/bin/sh\necho "ERROR: %s invoked in local mode" >&2\nexit 99\n' scp > "$NOSSH/scp"
    chmod +x "$NOSSH/ssh" "$NOSSH/scp"
    PATH="$NOSSH:$PATH"
}

# --- transport: ssh/scp stubs that echo their argv instead of connecting ---
# Pins the remote command lines the wrappers build, so the local-mode refactor
# cannot quietly change what a real run sends over the wire.
#
# Each argument is bracketed rather than flattened with "$*": argv boundaries
# are the whole point here. "$*" would render `a b` and `a` `b` identically, so
# it could not tell a correctly quoted expansion from one that word-splits --
# exactly the regression these tests exist to catch.
echo_transport_fixture() {
    ECHOT=$(mktemp -d)   # leaked on purpose; tests are short-lived
    printf '#!/bin/sh\nprintf SSH\nprintf "[%%s]" "$@"\nprintf "\\n"\n' > "$ECHOT/ssh"
    printf '#!/bin/sh\nprintf SCP\nprintf "[%%s]" "$@"\nprintf "\\n"\n' > "$ECHOT/scp"
    chmod +x "$ECHOT/ssh" "$ECHOT/scp"
    PATH="$ECHOT:$PATH"
}

# --- local mode is Linux-only: drive the guard both ways ---
# resolve_local_mode calls plain `uname` so it resolves through PATH.
uname_fixture() {   # $1 = kernel name to report
    UNAMED=$(mktemp -d)   # leaked on purpose; tests are short-lived
    printf '#!/bin/sh\necho %s\n' "$1" > "$UNAMED/uname"
    chmod +x "$UNAMED/uname"
    PATH="$UNAMED:$PATH"
}

# --- summarizer: fabricated fio client-mode results ---
# client_stats is a flat list of (host, job) entries plus "All clients"
# aggregates. The create/layout phase runs first in every shipped jobfile, so
# its entries -- including its own "All clients" -- come first here: the
# summarizer must report the LAST entry per host and the last aggregate. The
# create-phase numbers are absurd on purpose, so picking one up is obvious.
#
# Figures chosen so every printed number is exact:
#   bandwidth  vega-1 3.00 + vega-2 4.00 GiB/s -> total 7.00, average 3.50
#   iops       vega-1 3,000 + vega-2 4,000     -> total 7,000, average 3,500
#   latency    200us over 3000 read IOs, 400us over 1000 write IOs
#              -> IO-weighted 250.0us
fio_json_fixture() {   # $1 = file to write
    cat > "$1" <<'JSON'
{
  "fio version": "fio-3.35",
  "client_stats": [
    { "jobname": "create", "hostname": "vega-1",
      "read":  { "bw_bytes": 0, "iops": 0.0, "total_ios": 0, "lat_ns": { "mean": 0.0 } },
      "write": { "bw_bytes": 107374182400, "iops": 900000.0, "total_ios": 900000, "lat_ns": { "mean": 9000000.0 } } },
    { "jobname": "create", "hostname": "vega-2",
      "read":  { "bw_bytes": 0, "iops": 0.0, "total_ios": 0, "lat_ns": { "mean": 0.0 } },
      "write": { "bw_bytes": 107374182400, "iops": 900000.0, "total_ios": 900000, "lat_ns": { "mean": 9000000.0 } } },
    { "jobname": "All clients",
      "read":  { "bw_bytes": 0, "iops": 0.0, "total_ios": 0, "lat_ns": { "mean": 0.0 } },
      "write": { "bw_bytes": 214748364800, "iops": 1800000.0, "total_ios": 1800000, "lat_ns": { "mean": 9000000.0 } } },
    { "jobname": "bw", "hostname": "vega-1",
      "read":  { "bw_bytes": 2147483648, "iops": 2000.0, "total_ios": 1400, "lat_ns": { "mean": 150000.0 } },
      "write": { "bw_bytes": 1073741824, "iops": 1000.0, "total_ios": 400,  "lat_ns": { "mean": 350000.0 } } },
    { "jobname": "bw", "hostname": "vega-2",
      "read":  { "bw_bytes": 2684354560, "iops": 2500.0, "total_ios": 1600, "lat_ns": { "mean": 250000.0 } },
      "write": { "bw_bytes": 1610612736, "iops": 1500.0, "total_ios": 600,  "lat_ns": { "mean": 450000.0 } } },
    { "jobname": "All clients",
      "read":  { "bw_bytes": 4831838208, "iops": 4500.0, "total_ios": 3000, "lat_ns": { "mean": 200000.0 } },
      "write": { "bw_bytes": 2684354560, "iops": 2500.0, "total_ios": 1000, "lat_ns": { "mean": 400000.0 } } }
  ]
}
JSON
}

# Single-client run: fio emits no "All clients" aggregate at all, so the lone
# host entry has to serve as the aggregate. Same latency figures -> 250.0us.
fio_json_single_fixture() {   # $1 = file to write
    cat > "$1" <<'JSON'
{
  "fio version": "fio-3.35",
  "client_stats": [
    { "jobname": "bw", "hostname": "vega-1",
      "read":  { "bw_bytes": 2147483648, "iops": 2000.0, "total_ios": 3000, "lat_ns": { "mean": 200000.0 } },
      "write": { "bw_bytes": 1073741824, "iops": 1000.0, "total_ios": 1000, "lat_ns": { "mean": 400000.0 } } }
  ]
}
JSON
}

# --- README: the fenced block under "# Usage" must equal ./wekatester -h ---
readme_usage_block() {   # $1 = README path (default README.md)
    awk '/^# Usage$/ { in_usage = 1; next }
         in_usage && /^```$/ { fence++; next }
         in_usage && fence == 1 { print }
         fence == 2 { exit }' "${1:-README.md}"
}


# --- interactive prompts: drive prompt_key over a pipe, capture UI on stdout ---
# The prompt fds are variables precisely so the suite can point them at a pipe
# and fd 1 -- no pty involved, nothing blocks waiting for a keystroke.
key_probe() {   # key_probe <timeout>; keystrokes arrive on stdin
    (source ./wekatester
     PROMPT_IN_FD=0
     PROMPT_OUT_FD=1
     prompt_key "$1"
     echo "rc=$? key=$PROMPT_KEY")
}
export -f key_probe

# --- editor stub: records each file it was handed, in order ---
editor_fixture() {   # $1 = exit status for the stub (default 0)
    ED=$(mktemp -d)   # leaked on purpose; tests are short-lived
    printf '#!/bin/sh\nbasename "$1" >> "%s/order"\nexit %s\n' "$ED" "${1:-0}" > "$ED/stub-ed"
    printf '#!/bin/sh\necho VISUAL >> "%s/order"\nexit 0\n' "$ED" > "$ED/stub-visual"
    chmod +x "$ED/stub-ed" "$ED/stub-visual"
    EDITOR="$ED/stub-ed"; unset VISUAL
}

# --- calibration: a fake client that answers every cell from a model ---
# The planner and the orchestrator are driven against a client whose curve is
# known, so every verdict can be checked against the answer the model implies.
# The model, all integers, tuned by CAL_SIM_* variables:
#   bw    numjobs x effective depth x CAL_SIM_STREAM (1 GiB/s) bytes/s, capped
#         at CAL_SIM_BWCAP (default 25 GiB/s); psync's effective depth is 1
#   iops  outstanding x 20,000, capped at CAL_SIM_IOPSCAP (1,000,000), and past
#         CAL_SIM_IOPSKNEE outstanding (4096) it falls with the overshoot;
#         nrfiles=CAL_SIM_NRBEST (unset) earns 3%, and every job adds
#         CAL_SIM_JOBBONUS (0) IOPS -- more jobs at the same outstanding IO win
#   lat   CAL_SIM_FLOOR us (100) up to CAL_SIM_WIDE jobs (8), then 20us more per
#         extra job; IOPS = numjobs x 1e6 / latency
# CAL_SIM_ENGINE_BONUS=<engine> gives that engine 5% more throughput (and 5%
# less latency).
cal_fake_value() {   # cal_fake_value <type> <engine> <nj> <qd> <nr> -> "<value> [aux]"
    local t=$1 e=$2 nj=$3 qd=$4 nr=$5 qe v o lat cap
    case "$e" in (psync|sync|pvsync|pvsync2|vsync) qe=1 ;; (*) qe=$qd ;; esac
    case "$t" in
        (bw)
            v=$(( nj * qe * ${CAL_SIM_STREAM:-1073741824} ))
            cap=${CAL_SIM_BWCAP:-26843545600}
            [ "$v" -le "$cap" ] || v=$cap
            [ "${CAL_SIM_ENGINE_BONUS:-}" != "$e" ] || v=$(( v * 105 / 100 ))
            echo "$v" ;;
        (iops)
            o=$(( nj * qe )); v=$(( o * 20000 ))
            cap=${CAL_SIM_IOPSCAP:-1000000}
            [ "$v" -le "$cap" ] || v=$cap
            if [ "$o" -gt "${CAL_SIM_IOPSKNEE:-4096}" ]; then
                v=$(( v * ${CAL_SIM_IOPSKNEE:-4096} / o ))
            fi
            [ "${CAL_SIM_NRBEST:-0}" != "$nr" ] || v=$(( v * 103 / 100 ))
            v=$(( v + nj * ${CAL_SIM_JOBBONUS:-0} ))
            [ "${CAL_SIM_ENGINE_BONUS:-}" != "$e" ] || v=$(( v * 105 / 100 ))
            echo "$v" ;;
        (lat)
            lat=${CAL_SIM_FLOOR:-100}
            [ "$nj" -le "${CAL_SIM_WIDE:-8}" ] || lat=$(( lat + (nj - ${CAL_SIM_WIDE:-8}) * 20 ))
            [ "${CAL_SIM_ENGINE_BONUS:-}" != "$e" ] || lat=$(( lat * 95 / 100 ))
            echo "$lat $(( nj * 1000000 / lat ))" ;;
    esac
}
export -f cal_fake_value

# fio client JSON for one cell, from the cell jobfile's name
# (cal-<type>-<dirn>-<engine>-nj<n>-qd<n>-nr<n>-<rt>s.job) on host <host>.
cal_fake_fio() {   # cal_fake_fio <cell-basename> <host>
    local b=$1 host=$2 t d e nj qd nr val v a rbw=0 riops=0 rlat=0 wbw=0 wiops=0 wlat=0
    b=${b%.job}; b=${b#cal-}
    t=${b%%-*}; b=${b#*-}; d=${b%%-*}; b=${b#*-}
    e=${b%%-nj*}; b=${b#*-nj}; nj=${b%%-*}; b=${b#*-qd}; qd=${b%%-*}; b=${b#*-nr}; nr=${b%%-*}
    val=$(cal_fake_value "$t" "$e" "$nj" "$qd" "$nr")
    read -r v a <<<"$val"
    case "$t:$d" in
        (bw:read)    rbw=$v; riops=$(( v / 1048576 )) ;;
        (bw:write)   wbw=$v; wiops=$(( v / 1048576 )) ;;
        (iops:read)  riops=$v; rbw=$(( v * 4096 )) ;;
        (iops:write) wiops=$v; wbw=$(( v * 4096 )) ;;
        (lat:read)   rlat=$(( v * 1000 )); riops=$a; rbw=$(( a * 4096 )) ;;
        (lat:write)  wlat=$(( v * 1000 )); wiops=$a; wbw=$(( a * 4096 )) ;;
    esac
    printf '{ "client_stats": [ { "jobname": "cal-%s-%s", "hostname": "%s", "error": 0, "read": { "bw_bytes": %s, "iops": %s, "total_ios": %s, "io_bytes": %s, "lat_ns": { "mean": %s } }, "write": { "bw_bytes": %s, "iops": %s, "total_ios": %s, "io_bytes": %s, "lat_ns": { "mean": %s } } } ] }\n' \
        "$t" "$d" "$host" "$rbw" "$riops" "$(( riops * 30 ))" "$(( rbw * 30 ))" "$rlat" \
        "$wbw" "$wiops" "$(( wiops * 30 ))" "$(( wbw * 30 ))" "$wlat"
}
export -f cal_fake_fio

# A run_host stand-in for calibration runs: the dataset listing answers
# "empty, plenty of room", a seed succeeds, a cell answers from the model,
# everything else (mkdir, rm, truncate) succeeds. Every command is appended
# to $SIMLOG when it is set.
cal_sim_host() {   # cal_sim_host <host> <command>
    local jf h
    [ -z "${SIMLOG:-}" ] || printf '%s|%s\n' "$1" "$2" >> "$SIMLOG"
    case "$2" in
        (*WEKATESTER_DF*)
            echo WEKATESTER_DF; echo "wekafs 999999999 ${CAL_SIM_FREE_MIB:-99999999}" ;;
        (*cal-seed-*)
            h=${2#*--client=}; h=${h%% *}
            printf '{ "client_stats": [ { "jobname": "seed-0-0", "hostname": "%s", "error": 0, "read": { "total_ios": 0, "io_bytes": 0 }, "write": { "total_ios": 10, "io_bytes": 10485760 } } ] }\n' "$h" ;;
        (*--client=*)
            h=${2#*--client=}; h=${h%% *}
            jf=${2##*/}; jf=${jf%\'}
            cal_fake_fio "$jf" "$h" ;;
    esac
    return 0
}
export -f cal_sim_host

# A calibration work dir: one probe file per host argument ("h1" or
# "h1:<ncpus>:<speedMb>"), every host a weka client on one mlx5 NIC.
cal_sim_fixture() {   # cal_sim_fixture <dir> <host[:ncpus[:speed]]>...
    local d=$1 spec h n sp
    shift
    mkdir -p "$d/probe" "$d/auth" "$d/set"
    for spec in "$@"; do
        IFS=: read -r h n sp <<<"$spec"
        { printf 'ncpus %s\nweka_allowed 0\nengines io_uring libaio psync\n' "${n:-4}"
          printf 'cpu_model Test CPU %s-core\nmemtotal_kb 263921664\n' "${n:-4}"
          printf 'nic ens1 %sMb/s 0000:3b:00.0 mlx5_core 0x15b3:0x101d\n' "${sp:-100000}"
          printf 'weka_net client [{"name": "ens1", "identifier": "0000:3b:00.0"}]\n'
        } > "$d/probe/$h"
    done
}
export -f cal_sim_fixture

# Drive cal_plan to its verdict against the model: prints the verdict line;
# every cell it asked for lands in <dir>/asked as "<phase> <nj> <qd> <nr>".
plan_sim() {   # plan_sim <dir> <type> <dirn> <engine> <usable> <linerate> <memcap> [k=v...]
    local d=$1 t=$2 dirn=$3 e=$4 u=$5 lr=$6 mc=$7 act phase nj qd nr rt n=0 knobs
    shift 7
    knobs="exh=0 line=95 floor=5 band=98.5 thr=2 stop=2 confirm=3 rt=30 nr=2 nrc=1,4 bwqd=128 iopsqd=256 njmaxpct=200 floorreps=3 $*"
    : > "$d/hist"; : > "$d/asked"
    while [ "$n" -lt 300 ]; do
        act=$( (source ./wekatester; cal_plan next "$t" "$dirn" "$e" "$u" "$lr" "$mc" "$d/hist" $knobs) ) \
            || { echo "PLANNER FAILED"; return 1; }
        case "$act" in
            ("cell "*) read -r _ phase nj qd nr rt <<<"$act"
                       echo "$phase $nj $qd $nr" >> "$d/asked"
                       echo "$phase $e $nj $qd $nr $rt $(cal_fake_value "$t" "$e" "$nj" "$qd" "$nr")" >> "$d/hist"
                       n=$((n + 1)) ;;
            (*) printf '%s\n' "$act"; return 0 ;;
        esac
    done
    echo "NO VERDICT"; return 1
}
export -f plan_sim

# --- calibration: one ladder step's fio client_stats -------------------------
# Same shape as fio's client-mode output and the same traps: a create-phase
# entry per host FIRST with absurd figures, an "All clients" aggregate that is
# not a client, then the measured entry per host LAST -- the only entry
# cal_gains may count. Picking up either of the others is unmistakable.
cal_json_fixture() {   # cal_json_fixture <file> <host:rbw:riops:wbw:wiops>...
    local out=$1 spec host rbw riops wbw wiops i
    local e=()
    shift
    for spec in "$@"; do
        host=${spec%%:*}
        e+=("$(printf '    { "jobname": "create", "hostname": "%s", "error": 0,
      "read":  { "bw_bytes": 0, "iops": 0.0 },
      "write": { "bw_bytes": 99999999999, "iops": 999999.0 } }' "$host")")
    done
    e+=('    { "jobname": "All clients", "error": 0,
      "read":  { "bw_bytes": 99999999999, "iops": 999999.0 },
      "write": { "bw_bytes": 99999999999, "iops": 999999.0 } }')
    for spec in "$@"; do
        IFS=: read -r host rbw riops wbw wiops <<<"$spec"
        e+=("$(printf '    { "jobname": "cal-step", "hostname": "%s", "error": 0,
      "read":  { "bw_bytes": %s, "iops": %s },
      "write": { "bw_bytes": %s, "iops": %s } }' \
            "$host" "$rbw" "$riops" "$wbw" "$wiops")")
    done
    e+=('    { "jobname": "All clients", "error": 0,
      "read":  { "bw_bytes": 99999999999, "iops": 999999.0 },
      "write": { "bw_bytes": 99999999999, "iops": 999999.0 } }')
    {
        printf '{\n  "fio version": "fio-3.35",\n  "client_stats": [\n'
        for i in $(seq 0 $(( ${#e[@]} - 1 )) ); do
            [ "$i" -eq 0 ] || printf ',\n'
            printf '%s' "${e[$i]}"
        done
        printf '\n  ]\n}\n'
    } > "$out"
}

# --- a small on-disk workload set for generator/customize tests ---
set_fixture() {   # creates $SETFIX with two jobfiles in distinct namespaces
    SETFIX=$(mktemp -d)
    printf '# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\ndirectory=/orig\nioengine=libaio\nfilename_format=big/$jobnum\n[create]\ncreate_only=1\n[bw]\nrw=read\niodepth=1\n' > "$SETFIX/011-bw.job"
    printf '# report iops\n[global]\nfilesize=2G\nnumjobs=8\ndirectory=/orig\nioengine=libaio\nfilename_format=small.$jobnum\nnrfiles=3\n[create]\ncreate_only=1\n[io]\nbs=4k\nrw=randread\niodepth=8\n' > "$SETFIX/031-iops.job"
}
