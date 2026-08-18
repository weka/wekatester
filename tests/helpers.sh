# Shared fixtures for tests/test_wekatester.sh.

# --- probe remote snippet stub (Task 4) ---
probe_stub() {
    stub=$(mktemp -d)   # leaked on purpose; tests are short-lived
    printf '#!/bin/sh\necho 8\n' > "$stub/getconf"
    printf '#!/bin/sh\nexit 1\n' > "$stub/pgrep"     # no wekanode procs
    printf '#!/bin/sh\necho " io_uring libaio"\n' > "$stub/fio"
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

# --- a small on-disk workload set for generator/customize tests ---
set_fixture() {   # creates $SETFIX with two jobfiles in distinct namespaces
    SETFIX=$(mktemp -d)
    printf '# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\ndirectory=/orig\nioengine=libaio\nfilename_format=big/$jobnum\n[create]\ncreate_only=1\n[bw]\nrw=read\niodepth=1\n' > "$SETFIX/011-bw.job"
    printf '# report iops\n[global]\nfilesize=2G\nnumjobs=8\ndirectory=/orig\nioengine=libaio\nfilename_format=small.$jobnum\nnrfiles=3\n[create]\ncreate_only=1\n[io]\nbs=4k\nrw=randread\niodepth=8\n' > "$SETFIX/031-iops.job"
}
