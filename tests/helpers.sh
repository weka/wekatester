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
    printf '[{"ram_allocated": 12335448064}, {"ram_allocated": 12335448064}]\n' > "$FIX/probe/_weka_ram.json"
    printf '# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\ndirectory=/orig\nioengine=libaio\n[create]\ncreate_only=1\n[bw]\nstonewall\nrw=read\niodepth=1\n' > "$FIX/src/011-bw.job"
}
