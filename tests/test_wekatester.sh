#!/usr/bin/env bash
# wekatester unit tests: source the script (source-guard prevents main), test pure functions.
cd "$(dirname "$0")/.."
source ./tests/helpers.sh
PASS=0; FAIL=0

t_assert() {   # t_assert <description> <command...>
    if "${@:2}"; then PASS=$((PASS+1)); echo "ok - $1"
    else FAIL=$((FAIL+1)); echo "FAIL - $1"; fi
}

# --- source-guard: sourcing must not run main (no args → would die) ---
out=$(source ./wekatester 2>&1)
t_assert "sourcing produces no output" test -z "$out"
t_assert "usage function defined after source" bash -c 'source ./wekatester; declare -f usage >/dev/null'

# --- parse_args ---
p() { (source ./wekatester; parse_args "$@"; echo "$AUTO_LEVEL|$DIRECTORY|${HOSTS[*]-}"); }
t_assert "no -a: auto off"            test "$(p -d /x h1)" = "|/x|h1"
t_assert "bare -a defaults to max"    test "$(p -a h1 h2)" = "max|/mnt/weka|h1 h2"
t_assert "-a safe consumed"           test "$(p -a safe h1)" = "safe|/mnt/weka|h1"
t_assert "--auto bare is max"         test "$(p --auto h1)" = "max|/mnt/weka|h1"
t_assert "--auto=safe"                test "$(p --auto=safe h1)" = "safe|/mnt/weka|h1"
t_assert "-vv still counts" bash -c 'source ./wekatester; parse_args -vv h1; [ "$VERBOSITY" -eq 2 ]'
t_assert "--auto=bogus errors" bash -c '! (source ./wekatester; parse_args --auto=bogus h1) '
t_assert "--ignore-capacity sets the override" bash -c '
    source ./wekatester; parse_args --ignore-capacity h1
    [ "$IGNORE_CAPACITY" -eq 1 ] && [ "${HOSTS[*]}" = "h1" ]'
t_assert "capacity override defaults off" bash -c '
    source ./wekatester; parse_args -a h1; [ "$IGNORE_CAPACITY" -eq 0 ]'

# --- parse_args: case-insensitive option names ---
# Only the option NAME is normalized. Values and attached arguments keep the
# case they were given, so a set or a path is never silently mangled.
t_assert "case-insensitive short option"   test "$(p -D /x h1)" = "|/x|h1"
t_assert "case-insensitive long option"    test "$(p --AUTO=MAX h1)" = "max|/mnt/weka|h1"
t_assert "case-insensitive auto level arg" test "$(p -A SAFE h1)" = "safe|/mnt/weka|h1"
t_assert "case-insensitive long name, value untouched" bash -c '
    source ./wekatester; parse_args --ENGINE=Uring h1; [ "$ENGINE" = Uring ]'
# -V used to print the version. It is verbosity now; version is long-only.
# Asserted on the printed line, not just the exit status: the old -V exited 0
# after printing the version, which a bare status check would have called a pass.
t_assert "-V is verbosity, not version" bash -c '
    out=$(source ./wekatester; parse_args -V h1; echo "V=$VERBOSITY H=${HOSTS[*]}")
    [ "$out" = "V=1 H=h1" ] || { echo "$out" >&2; false; }'
t_assert "-VV and -vV both count twice" bash -c '
    source ./wekatester
    ( parse_args -VV h1; [ "$VERBOSITY" -eq 2 ] ) &&
    ( parse_args -vV h1; [ "$VERBOSITY" -eq 2 ] )'
t_assert "--version prints the version and exits 0" bash -c '
    out=$(./wekatester --version) || { echo "$out" >&2; exit 1; }
    case "$out" in *"wekatester version "*) true;; *) echo "$out" >&2; false;; esac'
t_assert "--VERSION works too" bash -c './wekatester --VERSION >/dev/null'

# --- parse_args: -r / -n / -g ---
t_assert "-r/-n/-g default off" bash -c '
    source ./wekatester; parse_args h1
    [ "$FAST_TRACK" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ "$REGEN_LAYOUT" -eq 0 ]'
t_assert "-r sets fast track" bash -c '
    source ./wekatester; parse_args -r h1
    [ "$FAST_TRACK" -eq 1 ] && [ "${HOSTS[*]}" = h1 ]'
t_assert "-n sets dry run" bash -c '
    source ./wekatester; parse_args -n h1; [ "$DRY_RUN" -eq 1 ]'
t_assert "-g forces layout regeneration" bash -c '
    source ./wekatester; parse_args -g h1; [ "$REGEN_LAYOUT" -eq 1 ]'
# -r used to carry the report-items list for -s. That form has to fail loudly:
# parsed as the new boolean it would silently demote "latency" to a hostname.
t_assert "the old -s ... -r items form is refused" bash -c '
    err=$( (source ./wekatester; parse_args -s /tmp/nope.json -r latency) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in *"-r"*"-s"*) true;; *) echo "$err" >&2; false;; esac'

# --- parse_args: -- separator ---
t_assert "-- passes flag-shaped tokens through as servers" bash -c '
    source ./wekatester; parse_args -d /x -- -weird h2
    [ "${HOSTS[*]}" = "-weird h2" ] && [ "$DIRECTORY" = /x ]'

# --- parse_args: -C customize ---
cz() { (source ./wekatester; parse_args "$@"
        echo "$CUSTOMIZE|$CUSTOM_SET|$C_CANDIDATE|${HOSTS[*]-}"); }
t_assert "-C off by default"                 test "$(cz h1)" = "0|||h1"
t_assert "-Cmyset names the set"             test "$(cz -Cmyset h1)" = "1|myset||h1"
t_assert "-c is the same option as -C"       test "$(cz -cmyset h1)" = "1|myset||h1"
t_assert "an attached set name keeps its case" test "$(cz -CMySet h1)" = "1|MySet||h1"
t_assert "--customize=set names the set"     test "$(cz --customize=MySet h1)" = "1|MySet||h1"
t_assert "--customize= with no value errors" bash -c '
    err=$( (source ./wekatester; parse_args --customize= h1) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in *"--customize requires a value"*) true;; *) echo "$err" >&2; false;; esac'
# Bare -C: the following bare token is only a CANDIDATE set name. It stays in
# HOSTS so preflight can try it as a client first (Task 5 resolves it).
t_assert "bare -C records a candidate without consuming it" test "$(cz -C h1)" = "1||h1|h1"
t_assert "bare -C records only the first candidate"         test "$(cz -C h1 h2)" = "1||h1|h1 h2"
t_assert "bare --customize records a candidate too"         test "$(cz --customize h1)" = "1||h1|h1"
# With -- present the client list is unambiguous, so a bare pre--- token
# following -C is the set name outright -- and only one of them may be.
t_assert "-C name -- h1 consumes name as the set" test "$(cz -C name -- h1)" = "1|name||h1"
t_assert "two bare set names before -- is a usage error" bash -c '
    err=$( (source ./wekatester; parse_args -C a b -- h1) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in *"one set name"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "-C with -s is a usage error" bash -c '
    err=$( (source ./wekatester; parse_args -C -s /tmp/nope.json) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in *"-C"*"-s"*) true;; *) echo "$err" >&2; false;; esac'

# --- parse_args: -w explicitness (Task 5 needs it for the recopy rule) ---
t_assert "-w tracked as explicit only when given" bash -c '
    source ./wekatester
    ( parse_args h1; [ "$WORKLOAD_EXPLICIT" -eq 0 ] ) &&
    ( parse_args -w mixed h1
      [ "$WORKLOAD_EXPLICIT" -eq 1 ] && [ "$WORKLOAD" = mixed ] )'

# --- mount guard classifier ---
c() { (source ./wekatester; classify_mount_line "$1"); }
t_assert "wekafs forcedirect ok"   test "$(c 'wekafs rw,relatime,forcedirect,inode_bits=auto')" = "ok"
t_assert "wekafs writecache fails" test "$(c 'wekafs rw,relatime,writecache,readahead_kb=32768')" = "fail writecache"
t_assert "wekafs readcache fails"  test "$(c 'wekafs rw,readcache')" = "fail readcache"
t_assert "wekafs unknown mode"     test "$(c 'wekafs rw,relatime')" = "fail unknown"
t_assert "nfs skipped"             test "$(c 'nfs4 rw,noatime')" = "skip"
t_assert "empty line skipped"      test "$(c '')" = "skip"

# --- probe remote snippet ---
t_assert "probe snippet emits ncpus"   bash -c 'probe_stub | grep -q "ncpus 8"'
t_assert "probe snippet emits engines" bash -c 'probe_stub | grep -q "engines.*io_uring"'

# --- tuner: fabricate probe dir + jobfile, run auto_tune ---
t_assert "tuner writes per-host variants" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null
    test -f "$FIX/jobs/h1/011-bw.job" && test -f "$FIX/jobs/h2/011-bw.job"'
t_assert "directory override applied" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null
    grep -q "^directory=/mnt/weka$" "$FIX/jobs/h1/011-bw.job"'
t_assert "cpus_allowed excludes weka cores" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null
    grep -q "^cpus_allowed=3-7$" "$FIX/jobs/h1/011-bw.job"'
t_assert "wide-only weka_allowed masks are ignored (utility threads)" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nweka_allowed 0,3-4\nweka_allowed 0-7\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    printf "ncpus 8\nweka_allowed 0,3-4\nweka_allowed 0-7\nengines io_uring libaio psync \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null
    grep -q "^cpus_allowed=0-7$" "$FIX/jobs/h1/011-bw.job"'
t_assert "core mismatch warns" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 16\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) 2>&1 >/dev/null )
    case "$err" in *WARNING*"core counts differ"*) true;; *) false;; esac'

# --- tuner: tier rules (Task 6) ---
t_assert "safe: numjobs = min usable cores" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 6\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=3$" "$FIX/jobs/h1/011-bw.job"'   # h2 usable=3 is the min
t_assert "max: numjobs per host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 6\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=5$" "$FIX/jobs/h1/011-bw.job" && grep -q "^numjobs=3$" "$FIX/jobs/h2/011-bw.job"'
t_assert "max: bw ioengine upgraded to io_uring" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=io_uring$" "$FIX/jobs/h1/011-bw.job"'
t_assert "safe: engine untouched when available" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=libaio$" "$FIX/jobs/h1/011-bw.job"'
t_assert "safe: engine fixed when missing on one host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nioengine=io_uring\nnumjobs=2\nfilesize=1G\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    printf "ncpus 8\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines libaio psync \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=libaio$" "$FIX/jobs/h1/011-bw.job"'
t_assert "latency: numjobs/iodepth untouched, small files applied at max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report latency\n[global]\nfilesize=10G\nnumjobs=1\nioengine=libaio\n[lat]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/021-lat.job"
    grep -q "^numjobs=1$" "$v" && grep -q "^iodepth=1$" "$v" &&
    grep -q "^filesize=1G$" "$v" && ! grep -q "wt-small" "$v" &&
    grep -q "^file_service_type=random$" "$v"'
t_assert "mixed report treats file as latency" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops latency\n[global]\nnumjobs=4\nioengine=libaio\nfilesize=1G\n[j]\nrw=randwrite\niodepth=8\n" > "$FIX/src/022-mixed.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=4$" "$FIX/jobs/h1/022-mixed.job"'
t_assert "max: iops iodepth and nrfiles derived" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/031-iops.job"
    # IOPS_NRFILES: two 1G files per job, stated directly
    grep -q "^iodepth=64$" "$v" && grep -q "^filesize=1G$" "$v" && grep -q "^nrfiles=2$" "$v"'
t_assert "mixed bandwidth+iops keeps bandwidth file layout" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=128k\nrw=read\niodepth=1\n" > "$FIX/src/012-mixed-bw.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/012-mixed-bw.job"
    grep -q "^numjobs=5$" "$v" && grep -q "^filesize=10G$" "$v" && ! grep -q "wt-small" "$v"'

# --- capacity check (universal: every run, per host, from staged variants) ---
cap() {   # cap <tier> <ignore 0|1> <host>... -- stages via auto_tune, then checks
    local tier=$1 ign=$2; shift 2
    (export WEKATESTER_PROMPT_TTY=/dev/null
     source ./wekatester
     IGNORE_CAPACITY=$ign; WORK_DIR=$FIX; HOSTS=("$@"); DIRECTORY=/mnt/weka
     run_host() { cat "$FIX/probe/_df"; }
     auto_tune "$FIX/src" "$FIX" "$tier" /mnt/weka 0 - "$@" >/dev/null 2>&1 || exit 9
     check_capacity)
}
export -f cap
t_assert "capacity check dies when oversized" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( cap max 0 h1 h2 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *ERROR*"workload needs"*"available"*"not enough capacity"*"--ignore-capacity"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "capacity check overridden by --ignore-capacity flag arg" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( cap max 1 h1 h2 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc" >&2; false; } &&
    case "$err" in
        *WARNING*"not enough capacity, running anyway (unattended)"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "no capacity warning when it fits" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc" >&2; false; } &&
    case "$err" in *WARNING*available*) false;; *) true;; esac'
t_assert "namespace-aware formula: distinct namespaces sum" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    out=$( cap max 0 h1 h2 2>&1 )
    # bw: 5 jobs x 1 file x 10G = 50GiB; iops (2 files/job): 5 jobs x 2 files x 1G
    # = 10GiB -- distinct namespaces, so the two sum to 60GiB
    case "$out" in *"capacity: h1 needs ~60.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: unusable df reports 0.0GiB available, unchecked, no abort" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "garbage\n" > "$FIX/probe/_df"
    out=$( cap safe 0 h1 h2 2>&1 )
    case "$out" in
        *"has 0.0GiB available"*) grep -q ERROR <<< "$out" && false || true ;;
        *) false ;;
    esac'
# --- stage_variants: per-host jobfile staging (Task 8) ---
t_assert "non-auto staging produces per-host variants" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester
     WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2); AUTO_LEVEL=""
     stage_variants "$FIX/src")
    test -f "$FIX/jobs/h1/011-bw.job" && test -f "$FIX/jobs/h2/011-bw.job" &&
    grep -q "^directory=/mnt/weka$" "$FIX/jobs/h2/011-bw.job"'

# Auto staging at the real call site (wekatester:540). These exercise the
# argument order that stage_variants passes to auto_tune: a dropped or
# reordered positional there shifts the host list, which no direct auto_tune
# test can catch (they build their own argv).
t_assert "staging then check_capacity aborts when the workload does not fit" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2)
            AUTO_LEVEL=max; IGNORE_CAPACITY=0
            run_host() { cat "$FIX/probe/_df"; }
            stage_variants "$FIX/src" && check_capacity) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *ERROR*"workload needs"*"not enough capacity"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "auto staging with override stages every host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( (source ./wekatester
            WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2)
            AUTO_LEVEL=max; IGNORE_CAPACITY=1
            stage_variants "$FIX/src") 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc ($err)" >&2; false; } &&
    { test -f "$FIX/jobs/h1/011-bw.job" ||
      { echo "coordinator h1 not staged: argument shift?" >&2; false; }; } &&
    test -f "$FIX/jobs/h2/011-bw.job"'
# The calibration engine does not exist yet (tasks 3-6), so cal must
# size EXACTLY like max in the meantime: stage_variants normalizes the tier
# it hands to auto_tune, rather than the tuner python learning a third value
# that would silently miss max-gated rules (engine forcing, small-file ns).
t_assert "cal sizes exactly like max: small-file namespace lands via stage_variants" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[io]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester
     WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2); AUTO_LEVEL=cal
     stage_variants "$FIX/src") >/dev/null 2>&1
    v="$FIX/jobs/h1/031-iops.job"
    ! grep -q "wt-small" "$v" &&
    grep -q "^filesize=1G$" "$v" && grep -q "^nrfiles=2$" "$v" &&
    grep -q "^ioengine=io_uring$" "$v"'

# --- signal handling: INT/TERM must end the run, not just clean up ---
# Regression: `trap cleanup EXIT INT TERM` ran cleanup and then CONTINUED at the
# statement after the signal, so a Ctrl-C left later phases running against a
# torn-down world (misleading errors, or an exit 0 that measured nothing).
t_assert "SIGTERM during preflight exits 143" bash -c '
    source ./tests/helpers.sh; signal_fixture
    ./wekatester h1 > "$SIG/log" 2>&1 &
    pid=$!
    signal_wait_started || { echo "stub ssh never started" >&2; exit 1; }
    kill -TERM "$pid"
    wait "$pid"; rc=$?
    [ "$rc" -eq 143 ] || { echo "expected 143, got $rc" >&2; false; }'
# set -m: a non-interactive shell makes its async commands ignore SIGINT, and a
# signal ignored on entry cannot be trapped -- job control puts the run in its
# own process group so the INT trap is reachable at all. Its job-status notice
# goes to stderr, so keep stderr captured and only surface it on failure.
t_assert "SIGINT during preflight exits 130" bash -c '
    source ./tests/helpers.sh; signal_fixture
    noise=$( (set -m
              ./wekatester h1 > "$SIG/log" 2>&1 &
              pid=$!
              signal_wait_started || { echo "stub ssh never started" >&2; exit 1; }
              kill -INT "$pid"
              wait "$pid") 2>&1 )
    rc=$?
    [ "$rc" -eq 130 ] || { echo "expected 130, got $rc ($noise)" >&2; false; }'

# --- staging: jobfiles with no [global] section ---
# Both insert paths (python override(), the awk non-auto branch) used to match
# nothing here, so the staged variant carried no directory= at all and fio wrote
# its files into the fio server'"'"'s cwd instead of -d.
t_assert "non-auto staging creates [global] when the jobfile has none" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[job1]\nrw=read\nfilesize=1G\n" > "$FIX/src/011-bw.job"
    (source ./wekatester
     WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2); AUTO_LEVEL=""
     stage_variants "$FIX/src")
    v="$FIX/jobs/h2/011-bw.job"
    [ "$(head -1 "$v")" = "[global]" ] && grep -q "^directory=/mnt/weka$" "$v" &&
    grep -q "^\[job1\]$" "$v" && grep -q "^rw=read$" "$v"'
t_assert "auto staging creates [global] when the jobfile has none" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[job1]\nrw=read\nfilesize=1G\n" > "$FIX/src/011-bw.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/011-bw.job"
    grep -q "^\[global\]$" "$v" && grep -q "^directory=/mnt/weka$" "$v" &&
    grep -q "^cpus_allowed=3-7$" "$v" && grep -q "^\[job1\]$" "$v"'
t_assert "an existing [global] is never duplicated" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    [ "$(grep -c "^\[global\]$" "$FIX/jobs/h1/011-bw.job")" -eq 1 ]'

# --- capacity model: namespaces, size=, small-file size rewrite ---
# fio expands the default filename_format ($jobname...) per section, so two
# jobfiles that set no filename_format own separate files and must SUM. They
# used to share one literal default key and collapse to a max, under-counting
# the footprint -- the one direction the guard must never fail in.
t_assert "capacity: jobfiles without filename_format sum, not max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/012-bw2.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~100.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: jobfiles sharing one filename_format take the max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    j="# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nfilename_format=shared.\$jobnum.\$filenum\nioengine=libaio\n[j]\nrw=read\n"
    printf "$j" > "$FIX/src/011-bw.job"
    printf "$j" > "$FIX/src/012-bw2.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~50.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: size= without filesize counts numjobs x size" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nsize=4G\nnrfiles=4\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~20.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: a percentage size= contributes 0 instead of crashing" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nsize=50%%\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    out=$( cap safe 0 h1 2>&1 )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc: $out" >&2; false; } &&
    case "$out" in *"capacity: h1 needs ~0.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "max: small-file redirect rewrites size= to nrfiles x 1G" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nsize=40G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/031-iops.job"
    # nrfiles = 2 (IOPS_NRFILES), so size= is rewritten to 2 x 1G
    grep -q "^nrfiles=2$" "$v" && grep -q "^filesize=1G$" "$v" && grep -q "^size=2G$" "$v"'
t_assert "max: latency size= follows the capped nrfiles" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report latency\n[global]\nfilesize=10G\nsize=40G\nnumjobs=1\nioengine=libaio\n[lat]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/021-lat.job"
    grep -q "^nrfiles=8$" "$v" && grep -q "^size=8G$" "$v"'
t_assert "size= is never inserted where the jobfile had none" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    ! grep -q "^size=" "$FIX/jobs/h1/031-iops.job"'

# --- summarizer ---
# Fixture figures are exact by construction (see tests/helpers.sh), so these pin
# the printed numbers, not just their shape.
t_assert "summarize: bandwidth totals are exact" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" 2>&1)
    case "$out" in
        *"read bandwidth: 4.50 GiB/s"*"write bandwidth: 2.50 GiB/s"*"total bandwidth: 7.00 GiB/s"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "summarize: per-host spread names the min and max hosts" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" 2>&1)
    case "$out" in
        *"average bandwidth: 3.50 GiB/s per host  (min 3.00 GiB/s vega-1, max 4.00 GiB/s vega-2)"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "summarize: iops totals and spread are exact" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" 2>&1)
    case "$out" in
        *"total iops: 7,000/s"*"average iops: 3,500/s per host  (min 3,000/s vega-1, max 4,000/s vega-2)"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "summarize: average latency is IO-weighted, not a bare mean" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" 2>&1)
    # bare mean of 200us and 400us would be 300.0us
    case "$out" in
        *"read latency: 200.0 us  (min 150.0 us vega-1, max 250.0 us vega-2)"*"average latency: 250.0 us (IO-weighted)"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "summarize: the create phase is not what gets reported" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" 2>&1)
    case "$out" in *"100.00 GiB/s"*|*"200.00 GiB/s"*|*" 9.0 ms"*) echo "$out" >&2; false;; *) true;; esac'
# The -r CLI filter is gone: -s always prints every metric group.
t_assert "summarize: -s reports every metric group" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" 2>&1)
    case "$out" in *bandwidth*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *iops*)      ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *latency*)   ;; *) echo "$out" >&2; exit 1;; esac'
# The items argument itself lives on: report_directive still feeds it per job.
t_assert "summarize: the items argument still narrows the report" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$( (source ./wekatester; summarize "$d/r.json" latency) 2>&1 )
    case "$out" in *"average latency: 250.0 us"*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *bandwidth*|*iops*) echo "$out" >&2; false;; *) true;; esac'
t_assert "summarize: refuses results that are missing a host, by name" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    err=$( (source ./wekatester; summarize "$d/r.json" "" "vega-1 vega-2 vega-3") 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *"no results from 1 of 3 host(s): vega-3"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "summarize: passes when every expected host reported" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    (source ./wekatester; summarize "$d/r.json" "bandwidth" "vega-1 vega-2") >/dev/null'
t_assert "summarize: a single-client run needs no All clients aggregate" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_single_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc: $out" >&2; false; } &&
    case "$out" in
        *"total bandwidth: 3.00 GiB/s"*"average latency: 250.0 us (IO-weighted)"*) true;;
        *) echo "$out" >&2; false;;
    esac'

# --- report directive parsing ---
# The metric selector needs whitespace after "report", or prose comments get
# parsed as report items.
r() { f=$(mktemp); printf '%b' "$1" > "$f"; (source ./wekatester; report_directive "$f"); }
# the items are newline-joined with tr, so one trailing space is expected
t_assert "report directive: items are parsed" \
    test "$(r '# report bandwidth latency\n[global]\n')" = "bandwidth latency "
t_assert "report directive: no space after # is fine" \
    test "$(r '#report iops\n[global]\n')" = "iops "
t_assert "report directive: prose is not a directive" \
    test -z "$(r '# reporting notes for the field\n[global]\n')"
t_assert "report directive: bare # report means default-all" \
    test -z "$(r '# report\n[global]\n')"

# --- local mode: trigger ---
# With no server on the command line the run happens here, and the transport
# wrappers must never reach for ssh/scp (no_ssh_fixture enforces that: the
# stubs shadow the real binaries and exit 99).
lm() { (uname_fixture Linux   # local mode is Linux-only; the suite also runs on macOS
        source ./wekatester; parse_args "$@"; resolve_local_mode >/dev/null
        echo "$LOCAL_MODE|$MASTER|${HOSTS[*]-}"); }
t_assert "local mode defaults off"          bash -c 'source ./wekatester; [ "$LOCAL_MODE" -eq 0 ]'
t_assert "no servers: local mode on, host and master are localhost" \
    test "$(lm -d /x)" = "1|localhost|localhost"
t_assert "no servers: the run is announced" bash -c '
    source ./tests/helpers.sh; uname_fixture Linux
    out=$(source ./wekatester; parse_args; resolve_local_mode)
    case "$out" in *"local host"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "servers given: local mode stays off, host list untouched" \
    test "$(lm h1 h2)" = "0|h1|h1 h2"
# Local mode needs findmnt and /dev/shm. A remote run from the same machine is
# still fine -- that plumbing lives on the workers -- so the guard must sit
# inside the no-hosts branch, not at the top of the function.
t_assert "local mode refuses to run on a non-Linux host" bash -c '
    source ./tests/helpers.sh; uname_fixture Darwin
    err=$( (source ./wekatester; parse_args; resolve_local_mode) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *"local mode is Linux-only"*"name a server instead"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "a non-Linux host with servers named is unaffected" bash -c '
    source ./tests/helpers.sh; uname_fixture Darwin
    out=$(source ./wekatester; parse_args h1 h2; resolve_local_mode
          echo "$LOCAL_MODE|$MASTER")
    [ "$out" = "0|h1" ] || { echo "$out" >&2; false; }'

# --- local mode: transport wrappers ---
t_assert "run_host local: returns the command output" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    source ./wekatester; LOCAL_MODE=1
    [ "$(run_host localhost "echo hi")" = "hi" ]'
t_assert "run_host local: nonzero rc propagates" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    source ./wekatester; LOCAL_MODE=1
    run_host localhost "exit 7"; [ "$?" -eq 7 ]'
t_assert "copy_to_master local: copies into the destination dir" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d); mkdir "$d/src" "$d/dst"; echo x > "$d/src/f"
    source ./wekatester; LOCAL_MODE=1
    copy_to_master "$d/src/f" "$d/dst/" && [ "$(cat "$d/dst/f")" = x ]'

# The remote branch of the wrappers must still build exactly the ssh/scp command
# lines it built before the refactor -- copy_to_master splits the destination off
# the end of "$@" (${!#} / ${@:1:$#-1}), which no local-mode test exercises.
# The stub brackets every argument, so these assert argv BOUNDARIES, not just
# the concatenated text: the command string must arrive as one argument however
# many spaces it contains, and multiple sources must arrive as separate ones.
t_assert "run_host remote: the command string stays a single argument" bash -c '
    source ./tests/helpers.sh; echo_transport_fixture
    out=$(source ./wekatester
          LOCAL_MODE=0; SSH_OPTS="-o BatchMode=yes"
          run_host vega-1 "df -kP /mnt/weka")
    [ "$out" = "SSH[-n][-o][BatchMode=yes][vega-1][df -kP /mnt/weka]" ] ||
        { echo "$out" >&2; false; }'
t_assert "copy_to_master remote: sources stay separate, last arg is the destination" bash -c '
    source ./tests/helpers.sh; echo_transport_fixture
    out=$(source ./wekatester
          LOCAL_MODE=0; MASTER=vega-1; SSH_OPTS="-o BatchMode=yes"
          copy_to_master /w/jobs/h1 /w/jobs/h2 /w/jobs/h3 /dev/shm/fio-jobfiles/)
    [ "$out" = "SCP[-o][BatchMode=yes][-q][-r][/w/jobs/h1][/w/jobs/h2][/w/jobs/h3][vega-1:/dev/shm/fio-jobfiles/]" ] ||
        { echo "$out" >&2; false; }'

# preflight reads 255 as ssh'"'"'s "could not connect" status, which only means that
# remotely. run_host is stubbed to hand preflight the rc directly: no local
# command exits 255 for the reason preflight would be classifying.
t_assert "preflight: rc 255 in local mode is a missing fio, not a dead ssh" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); FIO_BIN=/usr/bin/fio
            run_host() { return 255; }
            preflight) 2>&1 >/dev/null )
    case "$err" in
        *"localhost: /usr/bin/fio not found"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "preflight: rc 255 in remote mode is still a dead ssh" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(vega-1); FIO_BIN=/usr/bin/fio
            run_host() { return 255; }
            preflight) 2>&1 >/dev/null )
    case "$err" in
        *"vega-1: ssh failed"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# A findmnt failure means the mount mode is UNKNOWN, not wrong. Telling the
# operator to remount forcedirect then points away from the real fault, which
# for a bare run is usually that -d defaults to a /mnt/weka that does not exist.
t_assert "mount guard: findmnt failure blames the directory, not the mount mode" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka
            run_host() { return 1; }
            verify_mount_mode) 2>&1 >/dev/null )
    case "$err" in *forcedirect*) echo "leaked remount advice: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"findmnt failed for /mnt/weka -- does it exist? (wrong -d?)"*"-d names the right directory"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: a genuine cached-mode mount still says remount forcedirect" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka
            run_host() { echo "wekafs rw,relatime,writecache"; }
            verify_mount_mode) 2>&1 >/dev/null )
    case "$err" in
        *"wekafs mounted writecache (need forcedirect)"*"must be mounted with forcedirect; remount"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: one real mode failure outweighs a findmnt failure" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2); DIRECTORY=/mnt/weka
            run_host() { [ "$1" = h1 ] && return 1; echo "wekafs rw,readcache"; }
            verify_mount_mode) 2>&1 >/dev/null )
    case "$err" in
        *"h1: findmnt failed"*"h2: wekafs mounted readcache"*"must be mounted with forcedirect; remount"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# On loopback a firewall is not the plausible cause; ::1-vs-IPv4 is.
t_assert "port check: local mode blames loopback resolution, not a firewall" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost
            run_host() { return 1; }
            verify_fio_ports) 2>&1 >/dev/null )
    case "$err" in
        *"cannot reach localhost:8765 (loopback resolution?"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "port check: remote mode still blames the firewall" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(vega-2); MASTER=vega-1
            run_host() { return 1; }
            verify_fio_ports) 2>&1 >/dev/null )
    case "$err" in
        *"vega-1 cannot reach vega-2:8765 (host firewall?)"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# --- local mode: staging end to end (no ssh, no sshd) ---
# The staging dir is redirected at a tmp dir through the real environment
# override, so both the override and the staging path are exercised: the
# master-side mkdir and the jobfile copy each go through a wrapper. The variable
# is namespaced (WEKATESTER_TARGET_DIR) because a bare TARGET_DIR is common
# enough in build environments to hijack cleanup'"'"'s rm -rf by accident.
t_assert "local staging lands per-host variants under the staging dir" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles) >/dev/null || exit 1
    v="$d/target/localhost/011-smoke-readbw.job"
    test -f "$v" && grep -q "^directory=/mnt/weka$" "$v" &&
    test -f "$d/target/localhost/022-smoke-writeiops.job"'
t_assert "a bare TARGET_DIR in the environment is ignored" bash -c '
    out=$(TARGET_DIR=/tmp/hijacked bash -c "source ./wekatester; echo \$TARGET_DIR")
    [ "$out" = "/dev/shm/fio-jobfiles" ] || { echo "$out" >&2; false; }'

# --- ssh credential pool (-i / -p) ---
# parse_args only accumulates raw entries; validate_credentials splits and
# checks them once local mode is known, so the parse stays pure.
t_assert "-i accumulates repeatable and comma-separated entries in order" bash -c '
    source ./wekatester; parse_args -i a:k1 -i b:k2,k3 --identity=k4 h1 h2
    [ "${IDENT_RAW[*]}" = "a:k1 b:k2,k3 k4" ] && [ "${HOSTS[*]}" = "h1 h2" ]'
t_assert "-i with no value errors; --identity= empty errors" bash -c '
    ! (source ./wekatester; parse_args -i) &&
    ! (source ./wekatester; parse_args --identity= h1)'
t_assert "validate_credentials splits login:key pairs; bare paths get the default user" bash -c '
    d=$(mktemp -d); : > "$d/k1"; : > "$d/k2"; : > "$d/k3"
    (source ./wekatester
     LOCAL_MODE=0; IDENT_RAW=("ubuntu:$d/k1,$d/k2" "root:$d/k3")
     validate_credentials
     [ "${IDENT_LOGINS[*]}" = "ubuntu  root" ] || { echo "logins: ${IDENT_LOGINS[*]}" >&2; exit 1; }
     [ "${IDENT_KEYS[*]}" = "$d/k1 $d/k2 $d/k3" ])'
# A bad key path must be named before the first ssh, not after ssh has already
# failed for a reason the operator has to reverse-engineer from BatchMode noise.
# A directory must be refused too: -i ~/.ssh is the likeliest typo and a
# directory passes a bare -r test.
t_assert "validate_credentials refuses missing keys, directories, and whitespace" bash -c '
    d=$(mktemp -d); k="$d/my key"; : > "$k"
    err=$( (source ./wekatester; LOCAL_MODE=0; IDENT_RAW=(/no/such/key)
            validate_credentials) 2>&1 >/dev/null )
    case "$err" in *"identity file not readable: /no/such/key"*) true;; *) echo "$err" >&2; exit 1;; esac
    err=$( (source ./wekatester; LOCAL_MODE=0; IDENT_RAW=("ubuntu:$d")
            validate_credentials) 2>&1 >/dev/null )
    case "$err" in *"identity file not readable: $d"*) true;; *) echo "$err" >&2; exit 1;; esac
    err=$( (source ./wekatester; LOCAL_MODE=0; IDENT_RAW=("ubuntu:$k")
            validate_credentials) 2>&1 >/dev/null )
    case "$err" in *"must not contain whitespace"*) true;; *) echo "$err" >&2; exit 1;; esac'
# Local mode never runs ssh, so the credential flags are accepted and ignored
# -- including a key path that would be fatal on a remote run.
t_assert "local mode accepts -i/-p as no-ops" bash -c '
    (source ./wekatester
     LOCAL_MODE=1; IDENT_RAW=(/no/such/key); PW_COUNT=2
     validate_credentials
     [ ${#IDENT_KEYS[@]} -eq 0 ])'
t_assert "-s is unaffected by -i" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" -i /no/such/key 2>&1)
    case "$out" in
        *"total bandwidth: 7.00 GiB/s"*) true;;
        *) echo "$out" >&2; false;;
    esac'
# None of the direct calls above would notice the validate step going missing
# from main. This drives the real binary end to end; a named host means the
# key was reported before preflight, since nothing here can reach h1.
t_assert "the real binary validates -i before it contacts a host" bash -c '
    out=$(./wekatester -i /no/such/key h1 2>&1); rc=$?
    [ "$rc" -eq 1 ] || { echo "rc=$rc: $out" >&2; exit 1; }
    case "$out" in
        *"identity file not readable: /no/such/key"*) true;;
        *) echo "$out" >&2; false;;
    esac'

# Per-host transport delta: an external host gets no control opts at all (its
# master belongs to the user); a host we connected gets control opts plus the
# User= its winning credential used, keeping the %C socket hash consistent.
t_assert "host_ssh_opts: external hosts bypass our control opts, ours carry User" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     AUTH_DIR=$d; CONTROL_OPTS="-o ControlPath=/x/%C"
     : > "$d/h1.external"
     printf "ubuntu\n" > "$d/h2.user"
     [ -z "$(host_ssh_opts h1)" ] &&
     [ "$(host_ssh_opts h2)" = "-o ControlPath=/x/%C -o User=ubuntu" ] &&
     [ "$(host_ssh_opts h3)" = "-o ControlPath=/x/%C" ])'
t_assert "the winning login reaches ssh and scp argv per host" bash -c '
    source ./tests/helpers.sh; echo_transport_fixture
    d=$(mktemp -d)
    out=$(source ./wekatester
          LOCAL_MODE=0; MASTER=vega-1; SSH_OPTS="-o BatchMode=yes"
          AUTH_DIR=$d; CONTROL_OPTS="-o CtlDummy=1"
          printf "ubuntu\n" > "$d/vega-1.user"
          run_host vega-1 "df -kP /mnt/weka"
          copy_to_master /w/jobs/h1 /dev/shm/fio-jobfiles/)
    [ "$out" = "SSH[-n][-o][BatchMode=yes][-o][CtlDummy=1][-o][User=ubuntu][vega-1][df -kP /mnt/weka]
SCP[-o][BatchMode=yes][-o][CtlDummy=1][-o][User=ubuntu][-q][-r][/w/jobs/h1][vega-1:/dev/shm/fio-jobfiles/]" ] ||
        { echo "$out" >&2; false; }'

# --- interactive prompt primitive (fd seam; no pty anywhere) ---
t_assert "prompt: timeout takes the default" bash -c '
    source ./tests/helpers.sh
    out=$(key_probe 1 < <(sleep 2)); [ "$out" = "rc=1 key=none" ]'
t_assert "prompt: y is read as y" bash -c '
    source ./tests/helpers.sh
    out=$(printf y | key_probe 5); [ "$out" = "rc=0 key=y" ]'
t_assert "prompt: enter and space are distinct (IFS= regression)" bash -c '
    source ./tests/helpers.sh
    [ "$(printf "\n" | key_probe 5)" = "rc=0 key=enter" ] &&
    [ "$(printf " "  | key_probe 5)" = "rc=0 key=space" ]'
t_assert "prompt: bare Esc is esc" bash -c '
    source ./tests/helpers.sh
    [ "$(printf "\033" | key_probe 5)" = "rc=0 key=esc" ]'
t_assert "prompt: arrow key is escseq and leaves no residue" bash -c '
    source ./tests/helpers.sh
    out=$(printf "\033[A" | (source ./wekatester
        PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        prompt_key 5; k1=$PROMPT_KEY
        prompt_key 1; k2=$PROMPT_KEY
        echo "$k1 $k2"))
    [ "$out" = "escseq none" ]'
t_assert "confirm_timed: esc beats a yes default" bash -c '
    source ./tests/helpers.sh
    ! (source ./wekatester; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
       printf "\033" | { confirm_timed 5 yes "q?" >/dev/null; }) '
t_assert "confirm_timed: timeout yields the stated default" bash -c '
    (source ./wekatester; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
     confirm_timed 1 yes "q?" < <(sleep 2) >/dev/null)'
t_assert "confirm_destructive: enter is NOT yes, y is, EOF dies" bash -c '
    source ./wekatester; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
    ! (printf "\n" | { confirm_destructive "sure?" >/dev/null; }) &&
    (printf "y" | { confirm_destructive "sure?" >/dev/null; }) &&
    ! ( { confirm_destructive "sure?" >/dev/null; } </dev/null )'
t_assert "require_interactive dies without a terminal" bash -c '
    out=$( (source ./wekatester; WEKATESTER_PROMPT_TTY=/dev/null PROMPT_TTY=/dev/null
            require_interactive "-C") 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && case "$out" in *"-C needs a terminal"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "editor: files edited in run order, VISUAL beats EDITOR" bash -c '
    source ./tests/helpers.sh; set_fixture; editor_fixture
    (source ./wekatester; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
     EDITOR="$ED/stub-ed"; unset VISUAL; resolve_editor
     discover_jobfiles "$SETFIX"
     for j in "${JOBFILES[@]}"; do edit_jobfile "$SETFIX/$j"; done) >/dev/null
    [ "$(cat "$ED/order")" = "011-bw.job
031-iops.job" ]'
t_assert "editor: nonzero exit aborts after exactly one file" bash -c '
    source ./tests/helpers.sh; set_fixture; editor_fixture 3
    ! (source ./wekatester; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
       EDITOR="$ED/stub-ed"; unset VISUAL; resolve_editor
       discover_jobfiles "$SETFIX"
       for j in "${JOBFILES[@]}"; do edit_jobfile "$SETFIX/$j"; done) >/dev/null 2>&1
    [ "$(wc -l < "$ED/order")" -eq 1 ]'

# --- layout generator ---
t_assert "generator: one section per namespace with superset geometry" bash -c '
    source ./tests/helpers.sh; set_fixture
    (source ./wekatester; generate_layout "$SETFIX" "$SETFIX") >/dev/null
    f="$SETFIX/000-wekatester-layout.job"
    grep -q "^# wekatester-layout: generated sha256=" "$f" &&
    grep -q "^filename_format=big/\$jobnum$" "$f" &&
    grep -q "^filename_format=small.\$jobnum$" "$f" &&
    grep -q "^nrfiles=3$" "$f" && grep -q "^numjobs=8$" "$f" && grep -q "^numjobs=4$" "$f" &&
    [ "$(grep -c "^create_only=1$" "$f")" -eq 2 ]'
t_assert "generator: deterministic (regeneration is byte-identical)" bash -c '
    source ./tests/helpers.sh; set_fixture
    (source ./wekatester
     generate_layout "$SETFIX" "$SETFIX" >/dev/null
     cp "$SETFIX/000-wekatester-layout.job" /tmp/gen1.$$
     generate_layout "$SETFIX" "$SETFIX" >/dev/null)
    diff -q /tmp/gen1.$$ "$SETFIX/000-wekatester-layout.job" >/dev/null; rc=$?
    rm -f /tmp/gen1.$$; [ "$rc" -eq 0 ]'
t_assert "generator: pristine hash verifies and an edit breaks it" bash -c '
    source ./tests/helpers.sh; set_fixture
    (source ./wekatester; generate_layout "$SETFIX" "$SETFIX") >/dev/null
    f="$SETFIX/000-wekatester-layout.job"
    want=$(sed -n "s/^# wekatester-layout: generated sha256=//p" "$f")
    got=$(grep -v "^# wekatester-layout: generated" "$f" | sed "s/[[:space:]]*$//" |
          python3 -c "import hashlib,sys; print(hashlib.sha256(sys.stdin.read().rstrip(chr(10)).encode()).hexdigest())")
    [ "$want" = "$got" ]'
t_assert "shipped jobfiles all carry the layout note" bash -c '
    n=$(grep -l "auto-generated 000-wekatester-layout" fio-jobfiles/*/[0-9]*.job | wc -l)
    m=$(ls fio-jobfiles/*/[0-9]*.job | wc -l)
    [ "$n" -eq "$m" ]'

# --- layout runtime integration ---
t_assert "staging: layout job is generated and runs first" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    d=$(mktemp -d)
    (source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost
     WORK_DIR=$(mktemp -d); mkdir -p "$WORK_DIR/jobs"
     WEKATESTER_TARGET_DIR="$d/target" TARGET_DIR="$d/target"
     DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
     stage_jobfiles >/dev/null
     [ "${JOBFILES[0]}" = "000-wekatester-layout.job" ] &&
     [ -f "$WORK_DIR/jobs/localhost/000-wekatester-layout.job" ] &&
     grep -q "^directory=/mnt/x$" "$WORK_DIR/jobs/localhost/000-wekatester-layout.job")'
t_assert "staging: a set with its own layout file is not regenerated" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    printf "# wekatester-layout: generated sha256=0000\n[global]\ndirectory=/orig\n[lay]\ncreate_only=1\nfilesize=1G\n" \
        > "$SETFIX/000-wekatester-layout.job"
    d=$(mktemp -d)
    (source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost
     WORK_DIR=$(mktemp -d); mkdir -p "$WORK_DIR/jobs"
     TARGET_DIR="$d/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
     stage_jobfiles >/dev/null
     grep -q "sha256=0000" "$WORK_DIR/set/000-wekatester-layout.job")'
t_assert "tuner: pristine layout at max is re-derived per host (tuned geometry)" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\ndirectory=/orig\n[io]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -q "re-derived by wekatester auto\[max\]" "$v" &&
    ! grep -q "wt-small" "$v" && grep -q "^nrfiles=2$" "$v" &&
    grep -q "^cpus_allowed=3-7$" "$v"'
t_assert "tuner: edited layout at max is staged as-is with a warning" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    echo "# operator note" >> "$FIX/src/000-wekatester-layout.job"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >/dev/null )
    v="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -q "# operator note" "$v" && ! grep -q "re-derived" "$v" &&
    case "$err" in *"user-edited layout staged as-is"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "tuner capacity: layout job does not double the required total" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    out=$( cap safe 0 h1 h2 2>/dev/null )
    case "$out" in *"capacity: h1 needs ~50.0GiB"*) true;; *) echo "$out" >&2; false;; esac'

# --- customize workflow ---
t_assert "resolve: bare name creates under ./fio-jobfiles and copies" bash -c '
    source ./tests/helpers.sh
    tmp=$(mktemp -d); cd "$tmp"
    mkdir -p fio-jobfiles/default
    printf "# report bandwidth\n[global]\nfilesize=1G\n[j]\nrw=read\n" > fio-jobfiles/default/011-x.job
    (source "$OLDPWD/wekatester"
     SCRIPT_DIR=$tmp; WORKLOAD=default; CUSTOM_SET=mynew
     resolve_custom_set >/dev/null
     [ "$SET_DIR_OVERRIDE" = "./fio-jobfiles/mynew" ] && [ -f ./fio-jobfiles/mynew/011-x.job ])'
t_assert "resolve: unwritable fio-jobfiles dies for a new bare name" bash -c '
    source ./tests/helpers.sh
    tmp=$(mktemp -d); cd "$tmp"
    mkdir -p fio-jobfiles/default
    printf "[j]\nrw=read\n" > fio-jobfiles/default/011-x.job
    chmod -w fio-jobfiles
    out=$( (source "$OLDPWD/wekatester"
            SCRIPT_DIR=$tmp; WORKLOAD=default; CUSTOM_SET=mynew
            resolve_custom_set) 2>&1 ); rc=$?
    chmod +w fio-jobfiles
    [ "$rc" -ne 0 ] && case "$out" in *"not writable"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "resolve: existing path is used as-is (no copy)" bash -c '
    source ./tests/helpers.sh; set_fixture
    (source ./wekatester
     WORKLOAD=default; CUSTOM_SET=$SETFIX
     resolve_custom_set >/dev/null
     [ "$SET_DIR_OVERRIDE" = "$SETFIX" ] && [ ! -f "$SETFIX/011-bandwidthR.job" ])'
t_assert "customize -r: layout generated silently, no editor, keep implied" bash -c '
    source ./tests/helpers.sh; set_fixture; editor_fixture
    (source ./wekatester
     FAST_TRACK=1; CUSTOMIZE=1; WORKLOAD=default; CUSTOM_SET=$SETFIX
     EDITOR="$ED/stub-ed"
     customize_jobfiles >/dev/null
     [ -f "$SETFIX/000-wekatester-layout.job" ] && [ "$TEMP_REMOVE" -eq 0 ])
    [ ! -f "$ED/order" ]'
t_assert "customize -r without -g: existing layout untouched" bash -c '
    source ./tests/helpers.sh; set_fixture
    printf "# wekatester-layout: generated sha256=feed\nmine\n" > "$SETFIX/000-wekatester-layout.job"
    (source ./wekatester
     FAST_TRACK=1; CUSTOMIZE=1; WORKLOAD=default; CUSTOM_SET=$SETFIX
     customize_jobfiles >/dev/null)
    grep -q "^mine$" "$SETFIX/000-wekatester-layout.job"'
t_assert "customize -g: existing layout regenerated even fast-tracked" bash -c '
    source ./tests/helpers.sh; set_fixture
    printf "# wekatester-layout: generated sha256=feed\nmine\n" > "$SETFIX/000-wekatester-layout.job"
    (source ./wekatester
     FAST_TRACK=1; REGEN_LAYOUT=1; CUSTOMIZE=1; WORKLOAD=default; CUSTOM_SET=$SETFIX
     customize_jobfiles >/dev/null)
    ! grep -q "^mine$" "$SETFIX/000-wekatester-layout.job" &&
    grep -q "^create_only=1$" "$SETFIX/000-wekatester-layout.job"'
t_assert "temp set removed only when marked and only via finish_temp_set" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d)
    (source ./wekatester; SET_DIR_OVERRIDE=$d; TEMP_REMOVE=0; finish_temp_set)
    [ -d "$d" ] || exit 1
    (source ./wekatester; SET_DIR_OVERRIDE=$d; TEMP_REMOVE=1; finish_temp_set >/dev/null)
    [ ! -d "$d" ]'
t_assert "preflight: unreachable -C candidate becomes the set name (fast track)" bash -c '
    source ./tests/helpers.sh
    stub=$(mktemp -d)
    printf "#!/bin/sh\nexit 255\n" > "$stub/ssh"; chmod +x "$stub/ssh"   # unreachable
    (source ./wekatester
     PATH="$stub:$PATH"
     CUSTOMIZE=1; FAST_TRACK=1; C_CANDIDATE=mysetname
     HOSTS=(mysetname); MASTER=mysetname; FIO_BIN=/usr/bin/true
     uname() { echo Linux; }
     preflight >/dev/null 2>&1
     [ "$CUSTOM_SET" = "mysetname" ] && [ "$LOCAL_MODE" -eq 1 ] && [ "$MASTER" = "localhost" ])'

# --- review fixes: layout union geometry, shipped-set protection, ordering ---
t_assert "generator: divergent geometries yield one section each (union, not grid)" bash -c '
    source ./tests/helpers.sh
    S=$(mktemp -d)
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=4\n[a]\nrw=read\n" > "$S/011-a.job"
    printf "# report iops\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=2\nnrfiles=27\n[b]\nrw=randread\n" > "$S/031-b.job"
    printf "# report iops\n[global]\nfilename_format=x/\$jobnum\nfilesize=15G\nnumjobs=2\nnrfiles=2\n[c]\nrw=randread\n" > "$S/032-c.job"
    (source ./wekatester; generate_layout "$S" "$S") >/dev/null
    f="$S/000-wekatester-layout.job"
    [ "$(grep -c "^create_only=1$" "$f")" -eq 3 ] &&
    ! grep -q "^stonewall$" "$f" &&
    [ "$(grep -c "^wait_for=" "$f")" -eq 2 ]'
t_assert "generator: distinct namespaces lay out in parallel (no ordering between them)" bash -c '
    S=$(mktemp -d)
    printf "# report bandwidth\n[global]\nfilename_format=big/\$jobnum\nfilesize=10G\nnumjobs=4\n[a]\nrw=read\n" > "$S/011-a.job"
    printf "# report iops\n[global]\nfilename_format=small.\$jobnum\nfilesize=1G\nnumjobs=8\n[b]\nrw=randread\n" > "$S/031-b.job"
    (source ./wekatester; generate_layout "$S" "$S") >/dev/null
    f="$S/000-wekatester-layout.job"
    [ "$(grep -c "^create_only=1$" "$f")" -eq 2 ] &&
    ! grep -q "^stonewall$" "$f" && ! grep -q "^wait_for=" "$f"'
t_assert "generator: a jobname namespace with several contributors gets unique chained names" bash -c '
    S=$(mktemp -d)
    printf "[global]\nfilesize=1G\nnumjobs=4\n[shared]\nrw=read\n" > "$S/011-a.job"
    printf "[global]\nfilesize=2G\nnumjobs=2\n[shared]\nrw=read\n" > "$S/012-b.job"
    (source ./wekatester; generate_layout "$S" "$S") >/dev/null
    f="$S/000-wekatester-layout.job"
    [ "$(grep -c "filename_format=shared.\$jobnum.\$filenum" "$f")" -eq 2 ] &&
    [ "$(grep -c "^wait_for=layout-" "$f")" -eq 1 ] &&
    ! grep -q "^\[shared\]$" "$f"'
t_assert "generator: dominated geometry is pruned to one section" bash -c '
    source ./tests/helpers.sh
    S=$(mktemp -d)
    printf "[global]\nfilename_format=x/\$jobnum\nfilesize=10G\nnumjobs=32\n[a]\nrw=read\n" > "$S/011-a.job"
    printf "[global]\nfilename_format=x/\$jobnum\nfilesize=10G\nnumjobs=64\n[b]\nrw=randread\n" > "$S/031-b.job"
    printf "[global]\nfilename_format=x/\$jobnum\nfilesize=10G\nnumjobs=1\n[c]\nrw=randread\n" > "$S/021-c.job"
    (source ./wekatester; generate_layout "$S" "$S") >/dev/null
    f="$S/000-wekatester-layout.job"
    [ "$(grep -c "^create_only=1$" "$f")" -eq 1 ] && grep -q "^numjobs=64$" "$f"'
t_assert "tuner: pristine layout re-derived at SAFE tier too (tuned numjobs)" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -q "re-derived by wekatester auto\[safe\]" "$v" && grep -q "^numjobs=5$" "$v" &&
    ! grep -q "^numjobs=4$" "$v"'
t_assert "capacity: layout union raises required above per-namespace max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    rm -f "$FIX/src/011-bw.job"
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=4\nioengine=libaio\ndirectory=/orig\n[a]\nrw=read\niodepth=1\n" > "$FIX/src/011-a.job"
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=2\nnrfiles=27\nioengine=libaio\ndirectory=/orig\n[b]\nrw=read\niodepth=1\n" > "$FIX/src/012-b.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    out=$( cap safe 0 h1 h2 2>/dev/null )
    # a: numjobs=5 nrfiles=1 -> 5 files; b: numjobs=5 nrfiles=27 -> 135 files;
    # union = 135G/host; namespace max = 135G -- equal here, so assert the
    # per-host requirement is the union value, proving layout_footprint runs
    case "$out" in *"capacity: h1 needs ~135.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "-C with a shipped set name copies it, never edits in place" bash -c '
    source ./tests/helpers.sh
    tmp=$(mktemp -d); cd "$tmp"
    mkdir -p fio-jobfiles/smoke
    printf "# report bandwidth\n[global]\nfilesize=1M\n[j]\nrw=read\n" > fio-jobfiles/smoke/011-x.job
    before=$(ls fio-jobfiles/smoke | md5)
    (source "$OLDPWD/wekatester"
     SCRIPT_DIR=$tmp; CUSTOM_SET=smoke; FAST_TRACK=1; CUSTOMIZE=1
     customize_jobfiles >/dev/null
     [ "$TEMP_SET" -eq 1 ] &&
     case "$SET_DIR_OVERRIDE" in ./fio-jobfiles/2*) true;; *) false;; esac &&
     [ -f "$SET_DIR_OVERRIDE/000-wekatester-layout.job" ])
    after=$(ls fio-jobfiles/smoke | md5)
    [ "$before" = "$after" ]'
t_assert "staging: marker layout with a late-sorting name is forced first" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    (source ./wekatester; generate_layout "$SETFIX" "$SETFIX") >/dev/null
    mv "$SETFIX/000-wekatester-layout.job" "$SETFIX/090-mylayout.job"
    d=$(mktemp -d)
    (source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost
     WORK_DIR=$(mktemp -d); mkdir -p "$WORK_DIR/jobs"
     TARGET_DIR="$d/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
     stage_jobfiles >/dev/null
     [ "${JOBFILES[0]}" = "090-mylayout.job" ] && [ "${#JOBFILES[@]}" -eq 3 ])'
t_assert "recopy replaces: old jobfiles and stale layout are cleared" bash -c '
    source ./tests/helpers.sh
    tmp=$(mktemp -d); cd "$tmp"
    mkdir -p fio-jobfiles/fresh custom
    printf "[global]\nfilesize=1M\n[new]\nrw=read\n" > fio-jobfiles/fresh/011-new.job
    printf "[global]\nfilesize=1M\n[old]\nrw=read\n" > custom/011-old.job
    printf "# wekatester-layout: generated sha256=stale\nSTALE\n" > custom/000-wekatester-layout.job
    (source "$OLDPWD/wekatester"
     PROMPT_IN_FD=0; PROMPT_OUT_FD=1
     SCRIPT_DIR=$tmp; WORKLOAD=fresh; WORKLOAD_EXPLICIT=1; CUSTOM_SET=./custom
     printf "y" | { resolve_custom_set >/dev/null; }
     [ -f ./custom/011-new.job ] && [ ! -f ./custom/011-old.job ] &&
     [ ! -f ./custom/000-wekatester-layout.job ])'

# --- -o/--output and the results directory ---
t_assert "parse: results dir defaults to ./results" bash -c '
    (source ./wekatester; parse_args h1; [ "$OUTPUT_DIR" = results ])'
t_assert "parse: -o detached, --output=, and attached -o all set the output dir" bash -c '
    (source ./wekatester; parse_args -o out1 h1;        [ "$OUTPUT_DIR" = out1 ]) &&
    (source ./wekatester; parse_args --output=out2 h1;  [ "$OUTPUT_DIR" = out2 ]) &&
    (source ./wekatester; parse_args -oout3 h1;         [ "$OUTPUT_DIR" = out3 ]) &&
    (source ./wekatester; parse_args -o=out4 h1;        [ "$OUTPUT_DIR" = out4 ]) &&
    (source ./wekatester; parse_args -Oout5 h1;         [ "$OUTPUT_DIR" = out5 ])'
t_assert "run_jobs: the results file lands in RUN_DIR, no timestamp infix" bash -c '
    source ./tests/helpers.sh
    tmp=$(mktemp -d); mkdir "$tmp/out" "$tmp/set"
    printf "# report bandwidth\n[global]\nfilesize=1M\n[bw]\nrw=read\n" > "$tmp/set/011-bw.job"
    fio_json_single_fixture "$tmp/fixture.json"
    (source ./wekatester
     HOSTS=(vega-1); MASTER=vega-1; FIO_BIN=fio; TARGET_DIR=/dev/shm/x
     SET_DIR=$tmp/set; JOBFILES=(011-bw.job); RUN_DIR=$tmp/out
     run_host() { cat "$tmp/fixture.json"; }
     run_jobs >/dev/null) &&
    test -f "$tmp/out/results_011-bw.json"'

# --- run bundle: log capture, jobfile snapshot, tgz finalize ---
t_assert "run bundle: stdout and stderr both land in wekatester.log; tgz replaces the dir" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     OUTPUT_DIR=$d/res; RUN_STAMP=20260101-000000; RUN_DIR=$d/res/$RUN_STAMP
     WORK_DIR=$d/work; mkdir -p "$RUN_DIR" "$WORK_DIR"
     start_run_log
     log "hello bundle"
     echo "oops goes to stderr" >&2
     finalize_run_dir) >/dev/null 2>&1
    test -f "$d/res/20260101-000000.tgz" &&
    test ! -d "$d/res/20260101-000000" &&
    tar -xzOf "$d/res/20260101-000000.tgz" 20260101-000000/wekatester.log > "$d/log" &&
    grep -q "hello bundle" "$d/log" && grep -q "oops goes to stderr" "$d/log"'
t_assert "run bundle: the console keeps working after finalize restores it" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
            OUTPUT_DIR=$d/res; RUN_STAMP=20260101-000001; RUN_DIR=$d/res/$RUN_STAMP
            WORK_DIR=$d/work; mkdir -p "$RUN_DIR" "$WORK_DIR"
            start_run_log
            log "captured"
            finalize_run_dir) 2>&1 )
    case "$out" in
        *"run bundle: $d/res/20260101-000001.tgz"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "run bundle: cleanup returns while the log tees still run (bare-wait deadlock)" bash -c '
    d=$(mktemp -d)
    # cleanup runs BEFORE finalize_run_dir in the EXIT trap, so the two tee
    # processes are still alive when it waits for its teardown sshs. A bare
    # `wait` there waits on the tees too -- and they cannot EOF until finalize
    # restores the fds after cleanup returns: a deadlock, seen live on shrw
    # when a failed auto-tune died with the run log active. timeout is the
    # assertion: the deadlocked version never returns.
    timeout 10 bash -c "
        source ./wekatester
        OUTPUT_DIR=$d/res; RUN_STAMP=20260101-000002; RUN_DIR=$d/res/20260101-000002
        WORK_DIR=$d/work; mkdir -p \"\$RUN_DIR\" \"\$WORK_DIR\"
        start_run_log
        LOCAL_MODE=1; HOSTS=(localhost); FIO_STARTED=1
        TARGET_DIR=$d/scratch; FIO_BIN=/nonexistent-fio; FIO_PIDFILE=$d/absent.pid
        cleanup
        finalize_run_dir" >/dev/null 2>&1 &&
    test -f "$d/res/20260101-000002.tgz"'
t_assert "run bundle: snapshot copies the per-host staged variants" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d/w; RUN_DIR=$d/r
     mkdir -p "$WORK_DIR/jobs/h1" "$WORK_DIR/jobs/h2" "$RUN_DIR"
     echo geometry-h1 > "$WORK_DIR/jobs/h1/011-a.job"
     echo geometry-h2 > "$WORK_DIR/jobs/h2/011-a.job"
     snapshot_jobfiles)
    grep -q geometry-h1 "$d/r/fio-jobfiles/h1/011-a.job" &&
    grep -q geometry-h2 "$d/r/fio-jobfiles/h2/011-a.job"'
t_assert "run bundle: finalize is a no-op when no run dir was created" bash -c '
    (source ./wekatester; RUN_DIR=""; finalize_run_dir)'

# --- -s reads run bundles straight from the archive (nothing extracted) ---
t_assert "-s summarizes every job in a bundle, in order, skipping layout results" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); b="$d/20260101-000000"; mkdir -p "$b/fio-jobfiles/h1"
    fio_json_single_fixture "$b/results_011-bw.json"
    fio_json_fixture "$b/results_021-mix.json"
    printf "%s sha256=abc\n[l]\ncreate_only=1\n" "# wekatester-layout: generated" \
        > "$b/fio-jobfiles/h1/010-mylayout.job"
    printf "{ \"client_stats\": [] }\n" > "$b/results_010-mylayout.json"
    printf "{ \"client_stats\": [] }\n" > "$b/results_000-wekatester-layout.json"
    printf "{ \"client_stats\": [] }\n" > "$b/results_000-wekatester-relayout.json"
    printf "{ \"client_stats\": [] }\n" > "$b/results_999-wekatester-unlink.json"
    printf "no json here\n" > "$b/results_030-broken.json"
    tar -czf "$d/bundle.tgz" -C "$d" 20260101-000000
    out=$(./wekatester -s "$d/bundle.tgz") || { echo "$out" >&2; exit 1; }
    case "$out" in
        *"==== 010-mylayout ===="*|*"==== 000-wekatester-layout ===="*|*"==== 000-wekatester-relayout ===="*|*"==== 999-wekatester-unlink ===="*)
            echo "layout/cleanup results leaked into the summary:" >&2; echo "$out" >&2; exit 1;;
    esac
    case "$out" in
        *"==== 011-bw ===="*"read bandwidth: 2.00 GiB/s"*"==== 021-mix ===="*"total bandwidth: 7.00 GiB/s"*"==== 030-broken ===="*"no JSON in fio output"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "-s on a bundle with no results files errors" bash -c '
    d=$(mktemp -d); mkdir "$d/x"; echo hi > "$d/x/wekatester.log"
    tar -czf "$d/b.tgz" -C "$d" x
    ! out=$(./wekatester -s "$d/b.tgz" 2>&1) &&
    case "$out" in
        *"no results_*.json files in the bundle"*) true;;
        *) echo "$out" >&2; false;;
    esac'

# --- every value-taking option works attached, detached, and =-attached ---
t_assert "parse: attached values work for -d -w -f -s -i" bash -c '
    (source ./wekatester; parse_args -d/x -wsmoke -f/opt/fio -iubuntu:/k h1
     [ "$DIRECTORY" = /x ] && [ "$WORKLOAD" = smoke ] && [ "$WORKLOAD_EXPLICIT" = 1 ] &&
     [ "$FIO_BIN" = /opt/fio ] && [ "${IDENT_RAW[0]}" = ubuntu:/k ]) &&
    (source ./wekatester; parse_args -sfile.json; [ "$SUMMARIZE_FILE" = file.json ])'
t_assert "parse: =-attached values strip exactly one leading =" bash -c '
    (source ./wekatester; parse_args -d=/x h1;  [ "$DIRECTORY" = /x ]) &&
    (source ./wekatester; parse_args -c=foo h1; [ "$CUSTOM_SET" = foo ])'
t_assert "parse: an attached value keeps its case even when the option is folded" bash -c '
    (source ./wekatester; parse_args -WSmoke h1; [ "$WORKLOAD" = Smoke ])'
t_assert "parse: attaching is the escape hatch for a dash-leading value" bash -c '
    (source ./wekatester; parse_args -w-odd h1; [ "$WORKLOAD" = -odd ])'
t_assert "parse: an empty attached value dies instead of naming nothing" bash -c '
    err=$( (source ./wekatester; parse_args -w= h1) 2>&1 >/dev/null )
    case "$err" in
        *"option -w requires a value"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "parse: -asafe and -a=max set the level; a bogus attached level dies" bash -c '
    (source ./wekatester; parse_args -asafe h1; [ "$AUTO_LEVEL" = safe ]) &&
    (source ./wekatester; parse_args -a=MAX h1; [ "$AUTO_LEVEL" = max ]) &&
    err=$( (source ./wekatester; parse_args -abogus h1) 2>&1 >/dev/null )
    case "$err" in
        *"unknown auto level: bogus (safe|max|cal|brutal)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "parse: -a cal and --auto=cal set the level; cal_mode true only for cal" bash -c '
    (source ./wekatester; parse_args -a cal h1;    [ "$AUTO_LEVEL" = cal ]) &&
    (source ./wekatester; parse_args -ACAL h1;     [ "$AUTO_LEVEL" = cal ]) &&
    (source ./wekatester; parse_args --auto=cal h1; [ "$AUTO_LEVEL" = cal ]) &&
    err=$( (source ./wekatester; parse_args -acalx h1) 2>&1 >/dev/null )
    case "$err" in
        *"unknown auto level: calx (safe|max|cal|brutal)"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    err=$( (source ./wekatester; parse_args -ahybrid h1) 2>&1 >/dev/null )
    case "$err" in
        *"unknown auto level: hybrid"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    (source ./wekatester; AUTO_LEVEL=cal;    cal_mode) &&
    (source ./wekatester; AUTO_LEVEL=brutal; cal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL=safe; cal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL=max;  cal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL="";   cal_mode)'

# The bug that killed brutal on iscg001 (2026-08-24): one seed section per
# file per job = 52 x 128 = 6656 sections, and fio hard-caps a run at 4096
# jobs, so the seed died at parse. Files are grouped into chunked sections
# now; this pins the arithmetic at the widest shipped grid.
t_assert "cal_seed_scratch: a brutal-width seed stays far below the fio 4096-job cap" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/cal/h1"
    printf "ncpus 52\n" > "$d/probe/h1"
    printf "bw read\niops read\n" > "$d/cal/seedplan.h1"
    (source ./wekatester
     AUTO_LEVEL=brutal; WORK_DIR=$d; AUTH_DIR=$d/auth; DIRECTORY=/mnt/weka
     CAL_SETTLE=0; ladders=$(printf "bw read\niops read\n")
     run_host() { case "$2" in
         (*find*) return 0;;
         (*df*)   echo "wekafs 99999999999 999999999";;
         (*)      return 0;;
     esac; }
     cal_seed_scratch h1) >/dev/null 2>&1
    n=$(grep -c "^\[seed-" "$d/cal/h1/cal-seed.job")
    # 52 jobs x 128 files in chunks of 16 = 416 sections, each nrfiles=16
    [ "$n" = 416 ] || { echo "sections: $n" >&2; false; }
    [ "$(grep -c "^nrfiles=16$" "$d/cal/h1/cal-seed.job")" = 416 ] || false
    # and every filename line stays far below the 4096-byte fio parser buffer
    [ "$(awk "/^filename=/ { if (length(\$0) > m) m = length(\$0) } END { print m }" "$d/cal/h1/cal-seed.job")" -lt 1024 ]'

# --- python floor: the workers are older than this laptop ---
# The inline python has to run on the WORKERS, and a Weka client is commonly
# RHEL 8, which ships python 3.6. A developer box running 3.9+ will happily
# execute a 3.8-only call and say nothing, and the failure then lands in the
# field halfway through a calibration -- which is exactly how
# statistics.fmean got in (it is 3.8+, and it took out -a cal:30 on isca224
# after six minutes of measuring). Grep for the ones that would do it again.
t_assert "python floor: no stdlib or syntax newer than 3.6 in the inline python" bash -c '
    # API and syntax added after 3.6, spelled as they would appear here
    pat="statistics\.fmean|st\.fmean"
    pat="$pat|statistics\.quantiles|st\.quantiles|statistics\.multimode|st\.multimode"
    pat="$pat|statistics\.geometric_mean|statistics\.harmonic_mean"
    pat="$pat|math\.prod|math\.dist|math\.perm|math\.comb|math\.isqrt"
    pat="$pat|\.removeprefix\(|\.removesuffix\(|functools\.cached_property"
    pat="$pat|shlex\.join|graphlib|importlib\.metadata"
    hits=$(grep -nE "$pat" ./wekatester | grep -v "^[0-9]*: *#" | grep -v "not statistics\." || true)
    [ -z "$hits" ] || { printf "post-3.6 API in the inline python:\n%s\n" "$hits" >&2; false; }'
# Every inline python block has to at least PARSE. A syntax error in a heredoc
# is invisible until the branch that runs it runs, which for a calibration
# verdict is minutes into a real run on a real client.
t_assert "python floor: every inline python heredoc parses" bash -c '
    d=$(mktemp -d); n=0; bad=0
    # each block is "<<\x27TAG\x27" ... TAG, with the python between; pull them
    # out by tag and compile each one
    for tag in $(grep -oE "<<.[A-Z][A-Z0-9]*EOF." ./wekatester | tr -d "<\x27\"" | sort -u); do
        awk -v t="$tag" "
            \$0 ~ (\"<<.\" t \".\$\") { inb = 1; next }
            inb && \$0 == t             { inb = 0; print \"###SPLIT###\"; next }
            inb                        { print }
        " ./wekatester > "$d/$tag.raw"
        [ -s "$d/$tag.raw" ] || continue
        i=0
        while IFS= read -r line; do
            case "$line" in ("###SPLIT###") i=$((i + 1)); continue;; esac
            printf "%s\n" "$line" >> "$d/$tag.$i.py"
        done < "$d/$tag.raw"
        for f in "$d/$tag".*.py; do
            [ -f "$f" ] || continue
            n=$((n + 1))
            python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f" \
                || { echo "does not parse: $f" >&2; bad=1; }
        done
    done
    [ "$n" -gt 10 ] || { echo "only found $n blocks -- the extractor is broken" >&2; false; }
    [ "$bad" -eq 0 ]'

# --- brutal: the exhaustive grid ---
# Both measured levels gate the calibration phase; only one of them is brutal.
t_assert "parse: -a brutal sets the level, and :secs sets the cell duration" bash -c '
    (source ./wekatester; parse_args -a brutal h1;    [ "$AUTO_LEVEL" = brutal ]) &&
    (source ./wekatester; parse_args -ABRUTAL h1;     [ "$AUTO_LEVEL" = brutal ]) &&
    (source ./wekatester; parse_args --auto=brutal h1; [ "$AUTO_LEVEL" = brutal ]) &&
    (source ./wekatester; parse_args -a brutal:10 h1
     [ "$AUTO_LEVEL" = brutal ] && [ "$CAL_RUNTIME" = 10 ]) &&
    (source ./wekatester; parse_args -a cal:15 h1;    [ "$CAL_RUNTIME" = 15 ]) &&
    # a duration still belongs only to the measured levels
    ! (source ./wekatester; parse_args -a max:10 h1) 2>/dev/null &&
    (source ./wekatester; AUTO_LEVEL=brutal; brutal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL=cal;  brutal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL=max;  brutal_mode)'
# The scratch has to hold the WIDEST cell the grid will open: every file index
# the largest nrfiles reaches, at the fixed per-file size.
t_assert "cal_seed_sizes: brutal sizes the union by its widest nrfiles" bash -c '
    out=$( (source ./wekatester; AUTO_LEVEL=brutal
            BRUTAL_NRS="1 2 4"; BRUTAL_FILESIZE=1024
            cal_seed_sizes "bw read
iops write") | tr "\n" " " )
    [ "$out" = "0 1024 1 1024 2 1024 3 1024 " ] || { echo "$out" >&2; false; }
    # cal seeds the same normalized per-file size at the tabled file count
    out=$( (source ./wekatester; cal_seed_sizes "bw read") | tr "\n" " " )
    [ "$out" = "0 5120 1 5120 " ] || { echo "$out" >&2; false; }'
t_assert "brutal_shortlist: the N cells that reached the highest values, across nj levels" bash -c '
    d=$(mktemp -d)
    printf "read 1 1 100\nread 1 2 900\nread 2 1 500\nread 2 2 700\n" > "$d/grid-bw-read-p100.h1"
    out=$( (source ./wekatester; brutal_shortlist "$d" bw read h1 2) | tr "\n" " " )
    [ "$out" = "100/1/2 100/2/2 " ] || { echo "$out" >&2; false; }
    # a 2x-numjobs pool competes cell for cell: its 1100 beats every 1x cell
    printf "read 1 2 1100\n" > "$d/grid-bw-read-p200.h1"
    out=$( (source ./wekatester; brutal_shortlist "$d" bw read h1 1) )
    [ "$out" = "200/1/2" ] || { echo "2x: $out" >&2; false; }
    # ranked on the best reading, not the average: nr=2/qd=1 touched 1200 once
    # under a quiet moment and that is what it is capable of
    rm "$d/grid-bw-read-p200.h1"
    printf "read 1 1 900\nread 1 1 900\nread 2 1 1200\nread 2 1 300\n" > "$d/grid-bw-read-p100.h1"
    out=$( (source ./wekatester; brutal_shortlist "$d" bw read h1 1) )
    [ "$out" = "100/2/1" ] || { echo "max-vs-mean: $out" >&2; false; }'
# A client cannot exceed its own ceiling, and contention only ever subtracts,
# so the HIGHEST reading a combination reached is the best estimate of what it
# can do. This fixture separates that rule from an averaging one: nr=1/qd=2
# reached 1000 once and 700 under contention (best 1000, mean 850); nr=2/qd=2
# sat at 900 twice (best 900, mean 900). Averaging would crown nr=2; the
# demonstrated ceiling belongs to nr=1.
t_assert "brutal_verdict: the highest reading wins, not the steadiest average" bash -c '
    d=$(mktemp -d); mkdir -p "$d/cal"
    printf "read 1 2 1000\nread 1 2 700\nread 2 2 900\nread 2 2 900\nread 1 1 100\n" \
        > "$d/cal/grid-bw-read-p100.h1"
    out=$( (source ./wekatester; WORK_DIR=$d; brutal_verdict h1 bw read 1024M 4) )
    case "$out" in
        "2 1 100 nrfiles=1 iodepth=2 -> "*"(best of 2 samples; runner-up nrfiles=2 qd=2 at 90.0%; grid spans 10-100% of best over 3 cells)"*) true;;
        *) echo "$out" >&2; false;;
    esac
    # a 2x-numjobs cell that reached higher takes the whole verdict, and the
    # verdict names the actual job count, never a percentage
    printf "read 1 2 1050\n" > "$d/cal/grid-bw-read-p200.h1"
    out=$( (source ./wekatester; WORK_DIR=$d; brutal_verdict h1 bw read 1024M 4) )
    case "$out" in
        "2 1 200 nrfiles=1 iodepth=2 numjobs=8 (2x available cores: 4) -> "*) true;;
        *) echo "2x: $out" >&2; false;;
    esac'
t_assert "brutal_surface: the grid as percent-of-best, each cell at its best" bash -c '
    d=$(mktemp -d)
    printf "read 1 1 500\nread 1 2 1000\nread 2 1 250\nread 2 2 750\n" > "$d/g"
    out=$( (source ./wekatester; brutal_surface "$d/g" bw) )
    printf "%s\n" "$out" | grep -qE "^ +qd1 +qd2$" &&
    printf "%s\n" "$out" | grep -qE "^nr1 +50% +100%$" &&
    printf "%s\n" "$out" | grep -qE "^nr2 +25% +75%$"'
# --- cal_required: which ladders does this set need ---
# The output grammar is a contract shared with the calibration engine and the
# dry-run report: unique sorted lines from {bw read, bw write, iops read,
# iops write}, nothing else, empty when nothing needs calibrating. Asserted on
# the whole pipe-joined output, never with grep, so a spurious extra ladder
# (wasted measurement time) fails the test just like a missing one.
# The exit code is pinned BEFORE the output is transformed: piping cal_required
# straight into tr would discard its status, and a python traceback (rc 1, empty
# stdout) would then be indistinguishable from the valid "nothing to calibrate"
# answer -- the empty-output assertions would pass on a broken function. A
# nonzero rc prints a marker instead, so those assertions fail on it.
cal_set() {   # cal_set <jobfile-body>...; prints cal_required, newlines as |
    local d body out rc n=0
    d=$(mktemp -d)
    for body in "$@"; do
        n=$((n + 1)); printf '%s\n' "$body" > "$d/0${n}1-job.job"
    done
    out=$( (source ./wekatester; cal_required "$d") ); rc=$?
    rm -rf "$d"
    [ "$rc" -eq 0 ] || { echo "ERROR: cal_required exited $rc"; return "$rc"; }
    [ -n "$out" ] || return 0   # a valid empty answer stays empty, not "|"
    printf '%s\n' "$out" | tr '\n' '|'
}
t_assert "cal_required: bandwidth-read + iops-randrw + latency set" \
    test "$(cal_set '# report bandwidth
[global]
directory=/mnt/weka
[bw]
rw=read' '# report iops
[global]
bs=4k
[io]
rw=randrw' '# report latency
[global]
bs=4k
[lat]
rw=randread')" = "bw read|iops read|iops write|lat read|"
t_assert "cal_required: a bw-write-only set needs one ladder" \
    test "$(cal_set '# report bandwidth
[bw]
rw=write')" = "bw write|"
t_assert "cal_required: a latency-only set asks for its floor rung, no ladder" \
    test "$(cal_set '# report latency
[lat]
rw=randread')" = "lat read|"
# latency anywhere in the directive wins, exactly as the tuner classifies it:
# such a file is measured at qd=1 -- no ladder, only the floor rung.
t_assert "cal_required: '# report iops latency' asks only for the latency floor" \
    test "$(cal_set '# report iops latency
[io]
rw=randwrite')" = "lat write|"
# No directive: the summarizer reports everything for such a file and its
# large sequential shape is bandwidth-like, so it counts as bandwidth.
t_assert "cal_required: a file with no report directive counts as bandwidth" \
    test "$(cal_set '[global]
bs=1M
[seq]
rw=write')" = "bw write|"
t_assert "cal_required: one directive naming two types asks for both" \
    test "$(cal_set '# report bandwidth iops
[both]
rw=read')" = "bw read|iops read|"
# Section rw= with the [global] value as the fallback: the un-annotated
# section still contributes the global direction.
t_assert "cal_required: section rw= wins, [global] rw= is the fallback" \
    test "$(cal_set '# report iops
[global]
rw=randread
[inherits]
bs=4k
[overrides]
rw=randwrite')" = "iops read|iops write|"
# A prose comment is not a directive (bare "# report" matches nothing either),
# so such a file falls into the no-directive case rather than being skipped.
t_assert "cal_required: '# reporting notes' is not a directive" \
    test "$(cal_set '# reporting notes: nothing to see
# report
[seq]
rw=read')" = "bw read|"
t_assert "cal_required: layout jobs are skipped, real jobs are not" \
    test "$(cal_set '# wekatester-layout: generated sha256=abc
[layout-1]
create_only=1
rw=write' '# report bandwidth
[bw]
rw=read')" = "bw read|"
t_assert "cal_required: a directive with no rw= anywhere asks for nothing" \
    test "$(cal_set '# report bandwidth
[bw]
bs=1M')" = ""
t_assert "cal_required: the shipped sets ask for the ladders they measure" bash -c '
    r() { local out rc                     # rc pinned before transforming, as above
          out=$( (source ./wekatester; cal_required "fio-jobfiles/$1") ); rc=$?
          [ "$rc" -eq 0 ] || { echo "ERROR: cal_required exited $rc"; return "$rc"; }
          printf "%s\n" "$out" | tr "\n" "|"; }
    [ "$(r default)"    = "bw read|bw write|iops read|iops write|lat read|lat write|" ] &&
    [ "$(r mixed)"      = "bw read|bw write|iops read|iops write|lat read|lat write|" ] &&
    [ "$(r smoke)"      = "bw read|lat write|" ] &&
    [ "$(r wekawithin)" = "bw read|bw write|" ]'
t_assert "cal_required: a missing set directory is an error, not silence" bash -c '
    out=$( (source ./wekatester; cal_required /nonexistent/set) 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && case "$out" in *"cal_required"*"/nonexistent/set"*) true;; *) false;; esac'

# --- usable_cores: the tuner's core arithmetic, callable from bash ---
# The calibration ladder sizes numjobs from this, so it must answer exactly
# what auto_tune's own facts block computes for the same probe file -- a
# divergence would make "the knee arrived below full cores" a lie.
uc() {   # uc <probe-file-content>; prints the count
    local d out rc
    d=$(mktemp -d) || return 1
    mkdir -p "$d/probe"
    printf '%s\n' "$1" > "$d/probe/h1"
    out=$( (source ./wekatester; WORK_DIR=$d; usable_cores h1) ); rc=$?
    rm -rf "$d"
    [ "$rc" -eq 0 ] || { echo "ERROR: usable_cores exited $rc"; return "$rc"; }
    printf '%s' "$out"
}
uc_fails() {   # uc_fails <pattern> [probe-file-content]; empty = no probe file
    local pat=$1 d err rc
    d=$(mktemp -d) || return 1
    mkdir -p "$d/probe"
    [ -z "${2:-}" ] || printf '%s\n' "$2" > "$d/probe/h1"
    err=$( (source ./wekatester; WORK_DIR=$d; usable_cores h1) 2>&1 >/dev/null ); rc=$?
    rm -rf "$d"
    [ "$rc" -ne 0 ] || { echo "usable_cores unexpectedly succeeded" >&2; return 1; }
    case "$err" in (*$pat*) return 0 ;; esac
    echo "$err" >&2; return 1
}
t_assert "usable_cores: weka's single-cpu masks are dedicated cores" \
    test "$(uc 'ncpus 8
weka_allowed 0
weka_allowed 1
weka_allowed 2')" = 5
t_assert "usable_cores: a wide utility-thread mask owns nothing" \
    test "$(uc 'ncpus 8
weka_allowed 0,3-4
weka_allowed 0-7')" = 8
t_assert "usable_cores: no weka at all leaves every core usable" \
    test "$(uc 'ncpus 4')" = 4
# isolcpus does NOT narrow the set: weka's pinned cores are the only thing
# subtracted (saving-calf 2026-08-20 -- isolating cost 4-7% write iops and the
# widest mask won; split affinity makes a cross-partition mask safe).
t_assert "usable_cores: isolcpus does not narrow the set" \
    test "$(uc 'ncpus 8
isolated 4-7
weka_allowed 4
weka_allowed 0
weka_allowed 1')" = 5
t_assert "usable_cores: weka owning every isolated cpu just leaves the rest" \
    test "$(uc 'ncpus 8
isolated 4-7
weka_allowed 4
weka_allowed 5
weka_allowed 6
weka_allowed 7')" = 4
# An empty answer is not a count: fio has no valid numjobs=0, so a probe that
# cannot be read has to fail loudly rather than size a ladder at zero jobs.
t_assert "usable_cores: an unreadable probe is an error, not a zero" \
    uc_fails usable_cores
t_assert "usable_cores: a probe with no ncpus is an error, not a zero" \
    uc_fails "no usable cpus" 'engines psync '

# --- stage_cal_step: one ladder step, staged per host ---
# The step file is the whole measurement contract: geometry (bs/filesize/
# nrfiles/numjobs/iodepth), the timing window, the scratch namespace, and the
# per-host engine/cpu resolution. The bw-read file is compared VERBATIM so a
# stray or missing line fails the test; the variants are asserted line-wise.
cal_fixture
cal_step() {   # cal_step <type> <dir> <qd> <host>...
    (source ./wekatester
     WORK_DIR=$CALFIX; AUTH_DIR="$CALFIX/auth"; DIRECTORY=/mnt/weka
     stage_cal_step "$1" "$2" "$3" "$CALFIX/cal" "${@:4}")
}
cal_staged() {   # cal_staged <type> <dir> <qd> <host>...: stage, confirm names
    local h
    cal_step "$@" || return 1
    for h in "${@:4}"; do
        [ -f "$CALFIX/cal/$h/cal-$1-$2-qd$3.job" ] \
            || { echo "missing: $CALFIX/cal/$h/cal-$1-$2-qd$3.job" >&2; return 1; }
    done
}
cal_lines() {   # cal_lines <file> <expected line>...: every line present verbatim
    local f=$1 l; shift
    [ -f "$f" ] || { echo "no such step file: $f" >&2; return 1; }
    for l in "$@"; do
        grep -qxF "$l" "$f" || { echo "missing from $f: $l" >&2; return 1; }
    done
}
# The file-exists check is the point of half this helper: "no line matches" is
# vacuously true of a file that was never written.
cal_nolines() {   # cal_nolines <file> <regex>...: no line matches any of them
    local f=$1 p; shift
    [ -f "$f" ] || { echo "no such step file: $f" >&2; return 1; }
    for p in "$@"; do
        ! grep -qE "$p" "$f" || { echo "unexpected in $f: $p" >&2; return 1; }
    done
}
cal_step_fails() {   # cal_step_fails <pattern> <stage_cal_step args>...
    local pat=$1 err rc; shift
    err=$(cal_step "$@" 2>&1 >/dev/null); rc=$?
    [ "$rc" -ne 0 ] || { echo "stage_cal_step $* unexpectedly succeeded" >&2; return 1; }
    case "$err" in (*$pat*) return 0 ;; esac
    echo "$err" >&2; return 1
}
# the multi-step assertions below run in `bash -c` subshells, which inherit
# neither shell functions nor plain variables
export CALFIX
export -f cal_step cal_staged cal_lines cal_nolines
t_assert "stage_cal_step: one deterministically named step file per host" \
    cal_staged bw read 8 h1 h2 h3
cat > "$CALFIX/expect-bw-read-h1" <<'EOF'
[global]
directory=/data/h1/.wekatester-cal
unique_filename=0
filename_format=h1.cal.$jobnum.$filenum
ioengine=io_uring
direct=1
bs=1Mi
filesize=1G
nrfiles=2
numjobs=3
iodepth=8
time_based=1
runtime=30
ramp_time=2
cpus_allowed=5-7
cpus_allowed_policy=split
[cal-bw-read]
rw=read
EOF
t_assert "stage_cal_step: the bw read step file is exactly this, no more" \
    diff -u "$CALFIX/expect-bw-read-h1" "$CALFIX/cal/h1/cal-bw-read-qd8.job"
# A read step measures files the seed pass (or the same type's write ladder)
# already wrote: creating anything here would measure a write instead.
t_assert "stage_cal_step: a read step carries no create options at all" \
    cal_nolines "$CALFIX/cal/h1/cal-bw-read-qd8.job" '^create' 'create_on_open' 'create_only'
t_assert "stage_cal_step: numjobs is that host's usable cores, not the master's" \
    cal_lines "$CALFIX/cal/h2/cal-bw-read-qd8.job" numjobs=3
t_assert "stage_cal_step: h3's usable cores size its own step" \
    cal_lines "$CALFIX/cal/h3/cal-bw-read-qd8.job" numjobs=2
# Engine resolution, all three rungs: resolved column, then the first PROVEN
# engine for that host, then psync -- which every fio build has.
t_assert "stage_cal_step: engine from the resolved column, the proven results, then psync" bash -c '
    cal_lines "$CALFIX/cal/h1/cal-bw-read-qd8.job" ioengine=io_uring &&
    cal_lines "$CALFIX/cal/h2/cal-bw-read-qd8.job" ioengine=libaio &&
    cal_lines "$CALFIX/cal/h3/cal-bw-read-qd8.job" ioengine=psync'
t_assert "stage_cal_step: the host with no resolved dir uses the global -d" \
    cal_lines "$CALFIX/cal/h2/cal-bw-read-qd8.job" directory=/mnt/weka/.wekatester-cal
# No recorded cpu list: no pinning AND no policy. A cpus_allowed_policy with
# nothing to split is a silent no-op today and a trap the day fio changes.
t_assert "stage_cal_step: no recorded cpus means the tuner usable set, split policy" \
    cal_lines "$CALFIX/cal/h2/cal-bw-read-qd8.job" 'cpus_allowed=1,2,3' 'cpus_allowed_policy=split'
t_assert "stage_cal_step: the per-host filename_format is host-prefixed and jobnum-keyed" \
    cal_lines "$CALFIX/cal/h2/cal-bw-read-qd8.job" 'filename_format=h2.cal.$jobnum.$filenum'
t_assert "stage_cal_step: a write step measures over existing files, never creating" bash -c '
    cal_staged bw write 2 h1 &&
    cal_lines "$CALFIX/cal/h1/cal-bw-write-qd2.job" \
        "[cal-bw-write]" rw=write bs=1Mi filesize=1G iodepth=2 &&
    cal_nolines "$CALFIX/cal/h1/cal-bw-write-qd2.job" "^create"'
t_assert "stage_cal_step: an iops step is 4k random IO over small files" bash -c '
    cal_staged iops read 32 h1 &&
    cal_lines "$CALFIX/cal/h1/cal-iops-read-qd32.job" \
        "[cal-iops-read]" rw=randread bs=4k filesize=256M nrfiles=2 iodepth=32 &&
    cal_nolines "$CALFIX/cal/h1/cal-iops-read-qd32.job" "^create"'
t_assert "stage_cal_step: an iops write step is randwrite, no create options" bash -c '
    cal_staged iops write 1 h2 &&
    cal_lines "$CALFIX/cal/h2/cal-iops-write-qd1.job" \
        rw=randwrite bs=4k filesize=256M &&
    cal_nolines "$CALFIX/cal/h2/cal-iops-write-qd1.job" "^create"'
t_assert "stage_cal_step: an unknown ladder type dies" \
    cal_step_fails "unknown ladder type" bogus read 8 h1
t_assert "stage_cal_step: an unknown direction dies" \
    cal_step_fails "unknown ladder direction" bw sideways 8 h1
t_assert "stage_cal_step: a non-numeric iodepth dies" \
    cal_step_fails "iodepth" bw read qd8 h1
t_assert "stage_cal_step: no hosts is a caller bug, not a silent no-op" \
    cal_step_fails "no hosts" bw read 8

# --- cal_values: per-client rung values from fio client JSON ---
# Grammar consumed verbatim by the orchestrator: "<host> <value>", one line
# per client in the step, sorted. Value = read+write SUMMED over every cal-*
# job entry for the host (one entry per job in fio client JSON); "All
# clients" aggregates and foreign sections never count. (The percent-gain
# column and the previous-step argument went with the grid: the noise-aware
# climb compares raw values in the orchestrator.)
# rc is pinned BEFORE the output is transformed: piping cal_values into tr
# would discard its status and a python traceback would read as valid output.
CG=$(mktemp -d)
cal_json_fixture "$CG/cur.json" \
    'h1:1610612736:1100.0:0:0.0' 'h2:2133382994:2400.0:100000000:600.0'
cal_g() {   # cal_g <cur> <bw|iops>; prints the lines, newlines as |
    local out rc
    out=$( (source ./wekatester; cal_values "$1" "$2") ); rc=$?
    [ "$rc" -eq 0 ] || { echo "ERROR: cal_values exited $rc"; return "$rc"; }
    [ -n "$out" ] || return 0
    printf '%s\n' "$out" | tr '\n' '|'
}
cal_g_fails() {   # cal_g_fails <pattern> <cal_values args>...
    local pat=$1 err rc; shift
    err=$( (source ./wekatester; cal_values "$@") 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "cal_values $* unexpectedly succeeded" >&2; return 1; }
    case "$err" in (*$pat*) return 0 ;; esac
    echo "$err" >&2; return 1
}
export CG
export -f cal_g cal_g_fails cal_json_fixture
# The values prove only cal-* entries count (the fixture's "create" entry
# carries a poison 99999999999 that would show in any sum).
t_assert "cal_values: read+write summed per client, only cal-* entries" \
    test "$(cal_g "$CG/cur.json" bw)" = "h1 1610612736|h2 2233382994|"
t_assert "cal_values: a multi-job step sums every job entry per host" bash -c '
    cal_json_fixture "'"$CG"'/multi.json" "h1:1000000:10.0:0:0.0" "h1:2000000:20.0:0:0.0"
    test "$(cal_g "'"$CG"'/multi.json" bw)" = "h1 3000000|"'
# Same file, iops mode: different metric, different answer.
t_assert "cal_values: iops mode counts ios, not bytes" \
    test "$(cal_g "$CG/cur.json" iops)" = "h1 1100|h2 3000|"
t_assert "cal_values: fio's log text before the JSON is skipped" bash -c '
    { printf "client <h1>: connected\nfio: terse output\n"; cat "'"$CG"'/cur.json"; } \
        > "'"$CG"'/noisy.json"
    test "$(cal_g "'"$CG"'/noisy.json" bw)" = "h1 1610612736|h2 2233382994|"'
t_assert "cal_values: unparsable output is an error naming the file" bash -c '
    printf "no json here at all\n" > "'"$CG"'/bad.json"
    cal_g_fails bad.json "'"$CG"'/bad.json" bw'
t_assert "cal_values: a results file with no client stats is an error" bash -c '
    printf "{\"client_stats\": [{\"jobname\": \"All clients\"}]}\n" > "'"$CG"'/agg.json"
    cal_g_fails agg.json "'"$CG"'/agg.json" bw'
t_assert "cal_values: an unknown mode is an error" \
    cal_g_fails "unknown mode" "$CG/cur.json" latency
t_assert "cal_values: a missing results file is an error" \
    cal_g_fails nosuch "$CG/nosuch.json" bw

# --- -u/--unlink: a final generated job removes what the layout created ---
t_assert "parse: -u, -U and --unlink arm the unlink job; default off" bash -c '
    (source ./wekatester; parse_args h1;          [ "$UNLINK" = 0 ]) &&
    (source ./wekatester; parse_args -u h1;       [ "$UNLINK" = 1 ]) &&
    (source ./wekatester; parse_args -U h1;       [ "$UNLINK" = 1 ]) &&
    (source ./wekatester; parse_args --UNLINK h1; [ "$UNLINK" = 1 ])'
t_assert "unlink job derives from the staged layout variant: unlink=1, no marker, runs last" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1 h2)
     mkdir -p "$d/jobs/h1" "$d/jobs/h2" "$SET_DIR"
     lay="# wekatester-layout: generated sha256=abc
[global]
directory=/mnt/weka
ioengine=libaio
blocksize=1Mi

[layout-1]
stonewall
create_only=1
filename_format=\$filenum/\$jobnum
filesize=10G
numjobs=16"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     printf "%s\n" "$lay" | sed s/numjobs=16/numjobs=8/ > "$d/jobs/h2/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job 011-bw.job)
     stage_unlink_variants
     u1=$d/jobs/h1/999-wekatester-unlink.job
     u2=$d/jobs/h2/999-wekatester-unlink.job
     [ "${JOBFILES[2]}" = 999-wekatester-unlink.job ] &&
     grep -q "^unlink=1$" "$u1" && grep -q "numjobs=16" "$u1" &&
     grep -q "numjobs=8" "$u2" &&
     grep -q "^filesize=4k$" "$u1" && ! grep -q "filesize=10G" "$u1" &&
     grep -q "^blocksize=4k$" "$u1" && ! grep -q "blocksize=1Mi" "$u1" &&
     ! grep -q "wekatester-layout: generated" "$u1" &&
     ! is_layout_file "$u1" &&
     awk "/^\[global\]/{g=1} /^unlink=1$/{if(g)ok=1} END{exit !ok}" "$u1")'
t_assert "run_jobs: the unlink job is timed, never summarized" bash -c '
    d=$(mktemp -d); mkdir "$d/set" "$d/out"
    cat > "$d/r.json" <<"JSON"
{ "client_stats": [
    { "jobname": "layout-1", "hostname": "h1", "error": 0,
      "read": { "total_ios": 0 }, "write": { "total_ios": 0 } } ] }
JSON
    out=$( (source ./wekatester
            HOSTS=(h1); MASTER=h1; FIO_BIN=fio; TARGET_DIR=/dev/shm/x
            SET_DIR=$d/set; RUN_DIR=$d/out; WORK_DIR=$d; DIRECTORY=/mnt/weka
            mkdir -p "$d/jobs/h1"
            printf "[global]\n[l]\nfilesize=10G\nnumjobs=4\n" > "$d/jobs/h1/999-wekatester-unlink.job"
            JOBFILES=(999-wekatester-unlink.job)
            run_host() { cat "$d/r.json"; }
            run_jobs) 2>&1 )
    case "$out" in
        *"removing test files (999-wekatester-unlink.job)"*"unlink: test files removed in"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    case "$out" in *bandwidth*) echo "unlink job got summarized: $out" >&2; false;; *) true;; esac'
t_assert "staging with -u ships the unlink job to the target, last in run order" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka; UNLINK=1
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles
     [ "${JOBFILES[${#JOBFILES[@]}-1]}" = 999-wekatester-unlink.job ]) >/dev/null || exit 1
    u="$d/target/localhost/999-wekatester-unlink.job"
    test -f "$u" && grep -q "^unlink=1$" "$u"'

# --- -e/--engine: one engine everywhere ---
t_assert "parse: -e in all spellings sets the engine; value case kept; -e= dies" bash -c '
    (source ./wekatester; parse_args -e libaio h1;      [ "$ENGINE" = libaio ]) &&
    (source ./wekatester; parse_args -elibaio h1;       [ "$ENGINE" = libaio ]) &&
    (source ./wekatester; parse_args --engine=io_uring h1; [ "$ENGINE" = io_uring ]) &&
    (source ./wekatester; parse_args -EPsync h1;        [ "$ENGINE" = Psync ]) &&
    ! (source ./wekatester; parse_args -e= h1)'
t_assert "override_variant_key: replaces, inserts into [global], or creates it" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     printf "[global]\nioengine=libaio\n[j]\nrw=read\n" > "$d/a"
     printf "[global]\nfilesize=1G\n[j]\nrw=read\n"     > "$d/b"
     printf "[j]\nrw=read\n"                            > "$d/c"
     override_variant_key "$d/a" ioengine xyzeng
     override_variant_key "$d/b" ioengine xyzeng
     override_variant_key "$d/c" ioengine xyzeng)
    grep -q "^ioengine=xyzeng$" "$d/a" && ! grep -q libaio "$d/a" &&
    grep -q "^ioengine=xyzeng$" "$d/b" &&
    head -2 "$d/c" | grep -q "^\[global\]$" && grep -q "^ioengine=xyzeng$" "$d/c"'
t_assert "-e stamps every staged variant, the generated layout included" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka; ENGINE=xyzeng
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles) >/dev/null || exit 1
    v="$d/target/localhost/011-smoke-readbw.job"
    grep -q "^ioengine=xyzeng$" "$v" && ! grep -q "^ioengine=libaio$" "$v" &&
    grep -q "^ioengine=xyzeng$" "$d/target/localhost/000-wekatester-layout.job"'

# fio defaults to fallocate=native on Linux: full st_size first, data after.
# An interrupted layout would then leave a full-size file of zeros that the
# layout sweep credits as complete, and the run measures reads of nothing.
t_assert "layout: the generated layout job disables preallocation" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src"
    printf "# report bandwidth\n[global]\nioengine=libaio\nfilesize=1G\nnumjobs=1\n[a]\nrw=read\n" > "$d/src/011-a.job"
    (source ./wekatester; generate_layout "$d/src" "$d/src") >/dev/null 2>&1
    grep -q "^fallocate=none$" "$d/src/000-wekatester-layout.job"'
t_assert "cal: the calibration seed disables preallocation" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/cal"
    printf "ncpus 4\n" > "$d/probe/h1"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka
     TARGET_DIR=/dev/shm/x; AUTH_DIR=$d/auth; CAL_SETTLE=0
     ladders="bw read"
     copy_to_master() { :; }
     run_host() { case "$2" in (*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;; esac
         printf "{ \"client_stats\": [ { \"jobname\": \"cal-x\", \"hostname\": \"h1\", \"error\": 0, \"read\": { \"bw_bytes\": 1, \"iops\": 1, \"total_ios\": 1, \"io_bytes\": 1 }, \"write\": { \"bw_bytes\": 1, \"iops\": 1, \"total_ios\": 1, \"io_bytes\": 1 } } ] }\n"; }
     cal_seed_scratch h1) >/dev/null 2>&1
    grep -q "^fallocate=none$" "$d/cal/h1/cal-seed.job"'

# --- engine ranking: a tie goes to io_uring, never to read order ---
# max() over a dict returns the first maximum in INSERTION order, so with one
# io_uring job and one libaio job the winner used to be whichever jobfile the
# scan happened to reach first.
t_assert "layout: an engine tie is broken by ENGINE_ORDER, not jobfile read order" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src"
    # libaio sorts first by filename, so read order favours it
    printf "# report bandwidth\n[global]\nioengine=libaio\nfilesize=1G\nnumjobs=1\n[a]\nrw=read\n" > "$d/src/011-a.job"
    printf "# report iops\n[global]\nioengine=io_uring\nfilesize=1G\nnumjobs=1\n[b]\nrw=randread\n" > "$d/src/031-b.job"
    (source ./wekatester; generate_layout "$d/src" "$d/src") >/dev/null 2>&1
    grep -q "^ioengine=io_uring$" "$d/src/000-wekatester-layout.job"'
t_assert "layout: a genuine majority still wins over ENGINE_ORDER" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src"
    printf "# report bandwidth\n[global]\nioengine=libaio\nfilesize=1G\nnumjobs=1\n[a]\nrw=read\n" > "$d/src/011-a.job"
    printf "# report iops\n[global]\nioengine=libaio\nfilesize=1G\nnumjobs=1\n[b]\nrw=randread\n" > "$d/src/031-b.job"
    printf "# report latency\n[global]\nioengine=io_uring\nfilesize=1G\nnumjobs=1\n[c]\nrw=randread\n" > "$d/src/021-c.job"
    (source ./wekatester; generate_layout "$d/src" "$d/src") >/dev/null 2>&1
    grep -q "^ioengine=libaio$" "$d/src/000-wekatester-layout.job"'

# --- deterministic filenames: unique_filename=0 + <host>. prefix ---
# fio client mode invents its own filename prefix (version-dependent) unless
# unique_filename=0; wekatester needs exact paths for the dir grid, capacity,
# markers and unlink, so it takes over the uniqueness itself.
t_assert "stamping: formats get the host prefix, unique_filename forced 0, defaults filled" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     mkdir -p "$d/jobs/h1"
     printf "[global]\nunique_filename=1\nfilename_format=x/\$jobnum\n[a]\nrw=read\nfilename_format=y.\$filenum\n" > "$d/jobs/h1/011-a.job"
     printf "[global]\nfilesize=1G\n[b]\nrw=read\n" > "$d/jobs/h1/012-b.job"
     printf "[global]\nfilename_format=\$clientuid.\$jobnum\n[c]\nrw=read\n" > "$d/jobs/h1/013-c.job"
     stamp_unique_names)
    a=$d/jobs/h1/011-a.job; b=$d/jobs/h1/012-b.job; c=$d/jobs/h1/013-c.job
    grep -q "^filename_format=h1.x/\$jobnum$" "$a" &&
    grep -q "^filename_format=h1.y.\$filenum$" "$a" &&
    grep -q "^unique_filename=0$" "$a" && ! grep -q "^unique_filename=1$" "$a" &&
    grep -q "^unique_filename=0$" "$b" &&
    grep -q "^filename_format=h1.\$jobname.\$jobnum.\$filenum$" "$b" &&
    grep -q "^filename_format=\$clientuid.\$jobnum$" "$c" &&
    grep -q "^unique_filename=0$" "$c"'
t_assert "stamping: pinned hosts get cpus_allowed filled and policy=split, explicit lines win" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1 h2)
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1" "$d/jobs/h2"
     printf "4-15,28-55" > "$AUTH_DIR/h1.cpus"
     printf "[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/jobs/h1/011-a.job"
     printf "[global]\ncpus_allowed=2,3\ncpus_allowed_policy=shared\n[b]\nrw=read\n" > "$d/jobs/h1/012-b.job"
     printf "[global]\ncpus_allowed=5-9\n[c]\nrw=read\n" > "$d/jobs/h2/013-c.job"
     printf "[global]\nfilesize=1G\n[e]\nrw=read\n" > "$d/jobs/h2/014-e.job"
     stamp_unique_names)
    a=$d/jobs/h1/011-a.job; b=$d/jobs/h1/012-b.job
    c=$d/jobs/h2/013-c.job; e=$d/jobs/h2/014-e.job
    grep -q "^cpus_allowed=4-15,28-55$" "$a" && grep -q "^cpus_allowed_policy=split$" "$a" &&
    grep -q "^cpus_allowed=2,3$" "$b" && grep -q "^cpus_allowed_policy=shared$" "$b" &&
    ! grep -q "4-15" "$b" && ! grep -q "policy=split" "$b" &&
    grep -q "^cpus_allowed=5-9$" "$c" && grep -q "^cpus_allowed_policy=split$" "$c" &&
    ! grep -q "cpus_allowed" "$e"'
t_assert "stamping: staged variants and the generated layout carry it end to end" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles) >/dev/null || exit 1
    v="$d/target/localhost/011-smoke-readbw.job"
    r="$d/target/localhost/000-wekatester-layout.job"
    grep -q "^unique_filename=0$" "$v" &&
    grep -q "^filename_format=localhost\." "$v" &&
    grep -q "^unique_filename=0$" "$r" &&
    grep -q "^filename_format=localhost\." "$r"'
t_assert "probe: -e engine missing from a worker refuses early, naming it" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2); MASTER=h1; AUTO_LEVEL=max
            WORK_DIR=$d; DIRECTORY=/mnt/weka; ENGINE=io_uring
            run_host() { case "$2" in
                (*enghelp*) [ "$1" = h1 ] && echo "engines io_uring libaio psync" \
                                          || echo "engines libaio psync";;
                (*) echo stubbed;;
            esac; }
            probe_workers) 2>&1 >/dev/null )
    case "$err" in
        *"ioengine '\''io_uring'\'' is not available"*"h2"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# --- -p/--password: a count of prompted login/password pairs ---
t_assert "parse: -p count is optional and never eats a hostname" bash -c '
    (source ./wekatester; parse_args h1;      [ "$PW_COUNT" = 0 ]) &&
    (source ./wekatester; parse_args -p h1;   [ "$PW_COUNT" = 1 ] && [ "${HOSTS[*]}" = h1 ]) &&
    (source ./wekatester; parse_args -p 3 h1; [ "$PW_COUNT" = 3 ]) &&
    (source ./wekatester; parse_args -p2 h1;  [ "$PW_COUNT" = 2 ]) &&
    (source ./wekatester; parse_args --password=2 h1; [ "$PW_COUNT" = 2 ]) &&
    (source ./wekatester; parse_args --PASSWORD h1;   [ "$PW_COUNT" = 1 ])'
t_assert "parse: a zero, zero-led, or non-numeric -p count dies" bash -c '
    ! (source ./wekatester; parse_args -p 0 h1) &&
    ! (source ./wekatester; parse_args -p0 h1) &&
    ! (source ./wekatester; parse_args -p 00 h1) &&
    ! (source ./wekatester; parse_args --password=007 h1) &&
    ! (source ./wekatester; parse_args --password=zork h1)'
t_assert "prompt_password_creds collects n pairs; empty password dies" bash -c '
    d=$(mktemp -d)
    (printf "ubuntu\npw1\nroot\npw2\n" | (source ./wekatester
        PW_COUNT=2; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        prompt_password_creds
        [ "${PW_LOGINS[*]}" = "ubuntu root" ] && [ "${PW_SECRETS[*]}" = "pw1 pw2" ]) >/dev/null) &&
    err=$(printf "ubuntu\n\n" | (source ./wekatester
        PW_COUNT=1; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        prompt_password_creds) 2>&1 >/dev/null )
    case "$err" in
        *"empty password"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# --- connection establishment: rounds, in order, only over unconnected hosts ---
# Four hosts, four different winning credentials: h4 has a live user-owned
# master (-O check), h3 works with plain defaults, h1 needs key ubuntu:k1,
# h2 needs password root/pw1. h5 matches nothing. The stub ssh really runs
# the askpass helper, so the fifo plumbing is exercised, and it logs every
# invocation so round ordering and the shrinking host pool are provable.
t_assert "auth rounds: first success per host wins; later rounds skip connected hosts" bash -c '
    d=$(mktemp -d); stub=$d/bin; mkdir -p "$stub"; k1=$d/k1; : > "$k1"
    cat > "$stub/ssh" <<"EOF"
#!/bin/bash
# log the target host as its own leading token: hostnames can occur inside
# key paths too (macOS mktemp lives under /var/folders/h3/...)
host=${!#}; [ "$host" != true ] || host=${@:$#-1:1}
echo "$host $*" >> "$WT_TEST_LOG"
case "$*" in
    *"-O check"*) case "$*" in (*h4*) exit 0;; (*) exit 1;; esac ;;
esac
if [ -n "$SSH_ASKPASS" ]; then
    pw=$("$SSH_ASKPASS") || exit 8
    [ "$pw" = "pw1" ] || exit 7
    case "$*" in (*User=root*h2*) exit 0;; (*) exit 1;; esac
fi
case "$*" in
    (*IdentityFile=*) case "$*" in (*User=ubuntu*h1*) exit 0;; (*) exit 1;; esac ;;
    (*h3*) exit 0 ;;
    (*) exit 1 ;;
esac
EOF
    chmod +x "$stub/ssh"
    err=$(printf "root\npw1\n" | (source ./wekatester
        PATH="$stub:$PATH"; export WT_TEST_LOG=$d/log
        WORK_DIR=$d; HOSTS=(h1 h2 h3 h4 h5); SSH_OPTS="-o BatchMode=yes"
        IDENT_LOGINS=(ubuntu); IDENT_KEYS=("$k1"); PW_COUNT=1
        PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        establish_connections
        [ ${#REMAINING[@]} -eq 1 ] && [ "${REMAINING[0]}" = h5 ]) 2>&1 >/dev/null ) || \
        { echo "engine failed: $err" >&2; exit 1; }
    test -f "$d/auth/h4.external" &&
    [ "$(cat "$d/auth/h1.user")" = ubuntu ] &&
    [ "$(cat "$d/auth/h2.user")" = root ] &&
    test ! -f "$d/auth/h3.user" && test ! -f "$d/auth/h3.external" &&
    case "$err" in
        *"no working ssh credentials for: h5"*) true;;
        *) echo "$err" >&2; exit 1;;
    esac &&
    # the pool shrinks: h4 tried once (external), h3 twice, h1 three times,
    # h2 four, h5 all four rounds
    [ "$(grep -c "^h4 " "$d/log")" -eq 1 ] &&
    [ "$(grep -c "^h3 " "$d/log")" -eq 2 ] &&
    [ "$(grep -c "^h1 " "$d/log")" -eq 3 ] &&
    [ "$(grep -c "^h2 " "$d/log")" -eq 4 ] &&
    [ "$(grep -c "^h5 " "$d/log")" -eq 4 ]'

# --- layout grid: evidence-driven healing (sweep) ---
t_assert "ensure_layout_dirs: \$filenum grid dirs are pre-created, flat names derive nothing" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1 h2)
     mkdir -p "$d/jobs/h1" "$d/jobs/h2"
     printf "[global]\ndirectory=/mnt/weka\nfilename_format=\$filenum/\$jobnum\n[l]\nnrfiles=3\nnumjobs=4\n" > "$d/jobs/h1/000-wekatester-layout.job"
     printf "[global]\ndirectory=/mnt/weka\n[l]\nfilename_format=wt.\$jobnum\nnrfiles=3\nnumjobs=4\n" > "$d/jobs/h2/000-wekatester-layout.job"
     run_host() { echo "$1: $2" >> "$WORK_DIR/oplog"; }
     ensure_layout_dirs 000-wekatester-layout.job)
    grep -q "^h1: mkdir -p ./mnt/weka/0. ./mnt/weka/1. ./mnt/weka/2.$" "$d/oplog" &&
    ! grep -q "^h2:" "$d/oplog"'
t_assert "ensure_layout_dirs: per-section format, directory and \$jobname override the global" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     mkdir -p "$d/jobs/h1"
     printf "[global]\ndirectory=/mnt/weka\nfilename_format=\$filenum/\$jobnum\nnrfiles=2\n[a]\nnumjobs=2\n[b]\ndirectory=/mnt/other\nfilename_format=\$jobname.d/\$jobnum\n" > "$d/jobs/h1/000-wekatester-layout.job"
     run_host() { echo "$1: $2" >> "$WORK_DIR/oplog"; }
     ensure_layout_dirs 000-wekatester-layout.job)
    grep -q "^h1: mkdir -p ./mnt/other/b.d. ./mnt/weka/0. ./mnt/weka/1.$" "$d/oplog"'
t_assert "ensure_layout_dirs: an unsupported format variable warns and skips, never mkdirs a literal" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     mkdir -p "$d/jobs/h1"
     printf "[global]\ndirectory=/mnt/weka\n[a]\nfilename_format=\$clientuid/\$jobnum\nnumjobs=2\n" > "$d/jobs/h1/000-wekatester-layout.job"
     run_host() { echo "$1: $2" >> "$WORK_DIR/oplog"; }
     ensure_layout_dirs 000-wekatester-layout.job) 2>&1 )
    [ ! -f "$d/oplog" ] &&
    case "$out" in *"cannot pre-create directories for [a]"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "cleanup: a privileged host gets a privileged fio kill, an unprivileged one does not" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=""; HOSTS=(h1 h2); FIO_STARTED=1; TARGET_DIR=/dev/shm/x
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR"
     printf "sudo" > "$AUTH_DIR/h1.priv"
     run_host() { echo "$1: $2" >> "$d/oplog"; }
     cleanup)
    grep -q "^h1: .*sudo kill" "$d/oplog" &&
    grep -q "^h2: if \[ -f" "$d/oplog" &&
    ! grep -q "^h2: .*sudo" "$d/oplog"'
t_assert "run_jobs: layout is timed create_only -- no markers, no rebuild selection" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; RUN_DIR=$d/out; HOSTS=(h1); MASTER=h1
     FIO_BIN=fio; TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka
     mkdir -p "$d/jobs/h1" "$SET_DIR" "$RUN_DIR"
     printf "[global]\n[l]\nfilesize=10G\nnumjobs=16\n" > "$d/jobs/h1/000-wekatester-layout.job"
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     printf "{ \"client_stats\": [ { \"jobname\": \"l\", \"hostname\": \"h1\", \"error\": 0, \"read\": {\"total_ios\":0}, \"write\": {\"total_ios\":0} } ] }\n" > "$d/r.json"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { case "$2" in
         (*rm\ -f*|*printf*) echo "MARKER_OP: $2" >> "$WORK_DIR/oplog";;
         (*mkdir*) echo "MK: $2" >> "$WORK_DIR/oplog";;
         (*) echo "FIO: $2" >> "$WORK_DIR/oplog"; cat "$WORK_DIR/r.json";;
     esac; }
     run_jobs) 2>&1 )
    case "$out" in *"layout: complete in "*) true;; *) echo "$out" >&2; false;; esac &&
    grep -q "FIO: .*000-wekatester-layout.job" "$d/oplog" &&
    ! grep -q "MARKER_OP" "$d/oplog" &&
    ! grep -q "relayout" "$d/oplog"'
t_assert "sweep: deviants deleted per namespace, matching bytes credited (capped)" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1); DIRECTORY=/mnt/weka; DRY_RUN=0
     mkdir -p "$d/jobs/h1" "$SET_DIR"
     lay="# wekatester-layout: generated sha256=abc
[global]
directory=/mnt/weka
[l1]
filename_format=h1.\$filenum/\$jobnum
filesize=1G
nrfiles=2
numjobs=4
[l2]
filename_format=h1.wt.\$jobnum.\$filenum
filesize=512M
numjobs=2"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { echo "SWEEP[$1]: $2" >> "$d/oplog"; echo 1073741824; echo 536870912; }
     sweep_layout_grid)
    grep -qF -- "-maxdepth 2 -type f -path \"/mnt/weka/h1.*/*\" ! -path \"/mnt/weka/.wekatester-cal/*\" ! -size +1073741823c -delete" "$d/oplog" &&
    grep -qF -- "-maxdepth 1 -type f -path \"/mnt/weka/h1.wt.*.0\" ! -path \"/mnt/weka/.wekatester-cal/*\" ! -size +536870911c -delete" "$d/oplog" &&
    [ "$(cat "$d/probe/h1.laidout")" = "1610612736" ]'
t_assert "sweep: same-format sections cannot delete each other (exact singleton indices, size floors)" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1); DIRECTORY=/mnt/weka; DRY_RUN=0
     mkdir -p "$d/jobs/h1" "$SET_DIR"
     lay="# wekatester-layout: generated sha256=abc
[global]
directory=/mnt/weka
filename_format=h1.\$filenum/\$jobnum
[l1]
filesize=1G
nrfiles=502
numjobs=44
[l2]
filesize=10G
numjobs=44"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { echo "SWEEP: $2" >> "$d/oplog"; echo 0; echo 0; }
     sweep_layout_grid)
    grep -qF -- "-path \"/mnt/weka/h1.0/*\" ! -path \"/mnt/weka/.wekatester-cal/*\" ! -size +10737418239c -delete" "$d/oplog" &&
    ! grep -qF -- "-path \"/mnt/weka/h1.*/*\" ! -path \"/mnt/weka/.wekatester-cal/*\" ! -size +10737418239c" "$d/oplog" &&
    grep -qF -- "-path \"/mnt/weka/h1.*/*\" ! -path \"/mnt/weka/.wekatester-cal/*\" ! -size +1073741823c -delete" "$d/oplog"'
t_assert "cal steps: no operator pin means the tuner usable set, never unpinned" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/cal"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); DIRECTORY=/mnt/weka
     printf "ncpus 8\nisolated 4-7\nweka_allowed 4\n" > "$d/probe/h1"
     stage_cal_step bw read 8 "$d/cal" h1)
    f=$d/cal/h1/cal-bw-read-qd8.job
    grep -q "^cpus_allowed=0,1,2,3,5,6,7$" "$f" &&
    grep -q "^cpus_allowed_policy=split$" "$f" &&
    grep -q "^numjobs=7$" "$f"'
t_assert "apply_cal_results: -g lets measured knees overwrite host-file qds" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; REGEN_LAYOUT=1
     # cal.results: host + (qd nr fs nj) x (bw_r bw_w iops_r iops_w); nj is
     # a dash unless a CAL_SPLIT re-test won, and bw_r here says one did
     printf "h1 4 2 1024M 2 2 2 1024M - 32 2 256M - 16 2 256M -\n" > "$d/cal.results"
     # 29 columns; bw_r_qd (col 9) and iops_r_qd (col 25) carry old values
     { printf "h1"
       for i in $(seq 2 29); do
          case $i in (9) printf "\t8";; (25) printf "\t64";; (*) printf "\t-";; esac
       done; printf "\n"; } > "$d/targets.final"
     apply_cal_results)
    a=$(awk -F"\t" "\$1==\"h1\" {print \$9, \$13, \$25, \$29, \$6}" "$d/targets.final")
    # cols 9/13/25/29 are the four qds; col 6 is bw_r_nj, the split winner
    [ "$a" = "4 2 32 16 2" ] || { echo "a=$a" >&2; false; }'
t_assert "sweep: dry runs never mutate (no run_host at all)" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1); DRY_RUN=1
     mkdir -p "$SET_DIR"
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { echo TOUCHED >> "$d/oplog"; }
     sweep_layout_grid)
    [ ! -f "$d/oplog" ]'
t_assert "capacity: swept bytes are credited against the requirement" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    d=$(mktemp -d)
    printf "42949672960" > "$FIX/probe/h1.laidout"
    out=$( (source ./wekatester
        WORK_DIR=$FIX; HOSTS=(h1); IGNORE_CAPACITY=0
        WEKATESTER_PROMPT_TTY=/dev/null
        auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 >/dev/null 2>&1
        run_host() { printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 209715200 0 209715200 1%% /mnt/weka\n"; }
        check_capacity) 2>&1 )
    case "$out" in
        *"already laid out"*) true;;
        *) echo "$out" >&2; false;;
    esac'

# The probe runs no weka CLI at all under -a: the DRAM ceiling it fed is
# retired (see the corrected "Working-set sizing (max tier)" spec section),
# so df is the only master-side fact the tuner needs.
t_assert "probe: -a runs no weka CLI on the master, only df" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=max
            WORK_DIR=$d; DIRECTORY=/mnt/weka
            # "weka " with the space matches a CLI invocation only -- the
            # remote probe snippet mentions wekanode/weka_allowed, not "weka "
            run_host() { case "$2" in
                (*"weka "*) echo "WEKA_CALLED: $2" >&2; return 1;;
                (*) echo stubbed;;
            esac; }
            probe_workers) 2>&1 >/dev/null ) || { echo "probe died: $err" >&2; exit 1; }
    test ! -e "$d/probe/_weka_ram.json" && test ! -e "$d/probe/_weka_ram.err" &&
    case "$err" in
        *WEKA_CALLED*) echo "$err" >&2; false;;
        *) true;;
    esac'

# --- host files (-t): the resolution engine ---
# Field layout of a resolved line: host login engine cpus dir bw_nj bw_fs
# bw_nr bw_qd lat_nj lat_fs lat_nr lat_qd iops_nj iops_fs iops_nr iops_qd
rt() {   # rt <phase> <csv> <cli_engine|-> <cli_dir|-> <results|-> hosts...
    (source ./wekatester; resolve_targets "$@")
}
export -f rt
t_assert "targets: a host line assigns login/engine/cpus/dir to its host only" bash -c '
    source ./tests/helpers.sh
    f=$(mktemp)
    printf "h1,ubuntu,libaio,\"22,24\",/mnt/a,,,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1 h2)
    echo "$out" | grep -q "^h1	ubuntu	libaio	22,24	/mnt/a" &&
    echo "$out" | grep -q "^h2	-	-	-	-"'
t_assert "targets: duplicate host lines are fatal, naming both line numbers" bash -c '
    f=$(mktemp)
    printf "h1,ubuntu,,,,,,\nh1,root,,,,,,\n" > "$f"
    err=$( (rt phase1 "$f" - - - h1) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in
        *"duplicate definition for host '\''h1'\''"*"line 1"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "targets: login-selector lines fold into hosts using that login, only" bash -c '
    f=$(mktemp)
    printf "h1,ubuntu,,,,,,\n,ubuntu,,0-7,/mnt/u,,,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1 h2)
    echo "$out" | grep -q "^h1	ubuntu	-	0-7	/mnt/u" &&
    echo "$out" | grep -q "^h2	-	-	-	-"'
t_assert "targets: generic never overrides specific, regardless of order" bash -c '
    f=$(mktemp)
    printf ",,,0-3,,,,\nh1,ubuntu,,8-11,,,,\n,ubuntu,,4-7,,,,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1 h2)
    # h1: host line cpus 8-11 beats login line 4-7 beats global 0-3
    echo "$out" | grep -q "^h1	ubuntu	-	8-11" &&
    # h2: no login -> only the global line applies
    echo "$out" | grep -q "^h2	-	-	0-3"'
t_assert "targets: equal specificity warns naming both lines; first wins; run continues" bash -c '
    f=$(mktemp)
    printf ",,,0-3,,,,\n,,,4-7,,,,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1 2>/dev/null)
    err=$( (rt phase1 "$f" - - - h1) 2>&1 >/dev/null )
    echo "$out" | grep -q "^h1	-	-	0-3" &&
    case "$err" in
        *"WARNING"*"line 2"*"line 1"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "targets: geometry columns parse with or without the type: prefix" bash -c '
    f=$(mktemp)
    printf "h1,,,,,bandwidthR:12/10G//8,12/10G//4,latencyR:1///1,,iopsR:4/1G/56/64,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1)
    want="h1	-	-	-	-	12	10G	-	8	12	10G	-	4	1	-	-	1	-	-	-	-	4	1G	56	64	-	-	-	-"
    [ "$out" = "$want" ] || { echo "got:  $out" >&2; echo "want: $want" >&2; false; }'
t_assert "targets: a wrong type: prefix in a geometry column is fatal" bash -c '
    f=$(mktemp)
    printf "h1,,,,,iopsR:4///,,,,,\n" > "$f"
    ! rt phase1 "$f" - - - h1 2>/dev/null'
t_assert "targets: CLI engine and dir beat the file everywhere" bash -c '
    f=$(mktemp)
    printf "h1,,libaio,,/mnt/file,,,\n" > "$f"
    out=$(rt phase1 "$f" psync /mnt/cli - h1 h2)
    echo "$out" | grep -q "^h1	-	psync	-	/mnt/cli" &&
    echo "$out" | grep -q "^h2	-	psync	-	/mnt/cli"'
t_assert "targets: engine-selector lines wait for phase2 and match only passing hosts" bash -c '
    f=$(mktemp)
    printf ",,io_uring,0-3,,,,\n" > "$f"
    p1=$(rt phase1 "$f" - - - h1 h2)
    echo "$p1" | grep -q "^h1	-	-	-	-" || { echo "phase1 leaked: $p1" >&2; exit 1; }
    r=$(mktemp); printf "h1 io_uring ok\nh2 io_uring fail\n" > "$r"
    p2=$(rt phase2 "$f" - - "$r" h1 h2)
    echo "$p2" | grep -q "^h1	-	io_uring	0-3" &&
    echo "$p2" | grep -q "^h2	-	-	-"'
t_assert "targets: header, comments, blanks are skipped; commented old rows are inert" bash -c '
    f=$(mktemp)
    printf "host,user_login,ioengine\n# h1,root,psync\n\nh1,ubuntu,,,,,,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1)
    echo "$out" | grep -q "^h1	ubuntu	-	-	-"'
t_assert "targets: host-less lines never assign a login" bash -c '
    f=$(mktemp)
    printf ",root,,0-3,,,,\nh1,,,,,,,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1)
    # h1 has no login, so the root-selector line does not match it at all
    echo "$out" | grep -q "^h1	-	-	-	-" || { echo "$out" >&2; false; }'

# --- host files (-t): flag, file resolution, prompts, -C ownership ---
t_assert "parse: -c claims paths, shipped names and existing sets without an ssh probe" bash -c '
    d=$(mktemp -d); cd "$d"; mkdir -p fio-jobfiles/realset
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     parse_args -c realset -d /mnt/x
     [ "$CUSTOM_SET" = realset ] && [ -z "$C_CANDIDATE" ] && [ ${#HOSTS[@]} -eq 0 ]) &&
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     parse_args -c ./someplace/set -d /mnt/x
     [ "$CUSTOM_SET" = ./someplace/set ] && [ -z "$C_CANDIDATE" ]) &&
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     parse_args -c smoke -d /mnt/x
     [ "$CUSTOM_SET" = smoke ] && [ -z "$C_CANDIDATE" ]) &&
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     parse_args -c maybehost -d /mnt/x
     [ -z "$CUSTOM_SET" ] && [ "$C_CANDIDATE" = maybehost ] && [ "${HOSTS[0]}" = maybehost ])'
t_assert "parse: -t consumes an existing file whatever its name" bash -c '
    d=$(mktemp -d); cd "$d"; touch myhosts
    (source "$OLDPWD/wekatester"
     parse_args -t myhosts h1
     [ "$TARGETS_PATH" = myhosts ] && [ "${HOSTS[*]}" = h1 ]) &&
    (source "$OLDPWD/wekatester"
     parse_args -t notafile h1
     [ -z "$TARGETS_PATH" ] && [ "${HOSTS[*]}" = "notafile h1" ])'
t_assert "parse: -t path heuristic -- paths consumed, hostnames left alone" bash -c '
    (source ./wekatester; parse_args -t h1 h2
     [ "$TARGETS" = 1 ] && [ -z "$TARGETS_PATH" ] && [ "${HOSTS[*]}" = "h1 h2" ]) &&
    (source ./wekatester; parse_args -t mine.csv h1;  [ "$TARGETS_PATH" = mine.csv ]) &&
    (source ./wekatester; parse_args -t ./x h1;       [ "$TARGETS_PATH" = ./x ]) &&
    (source ./wekatester; parse_args -tmine.csv h1;   [ "$TARGETS_PATH" = mine.csv ]) &&
    (source ./wekatester; parse_args --targets=a.csv h1; [ "$TARGETS_PATH" = a.csv ]) &&
    (source ./wekatester; parse_args -T h1;           [ "$TARGETS" = 1 ])'
t_assert "targets file: explicit missing path prompts; no creates nothing and quits" bash -c '
    d=$(mktemp -d)
    err=$(printf "n" | (source ./wekatester
        TARGETS=1; TARGETS_PATH=$d/no.csv
        PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        resolve_targets_file) 2>&1 >/dev/null )
    case "$err" in
        *"host file $d/no.csv does not exist"*) true;;
        *) echo "$err" >&2; exit 1;;
    esac
    test ! -f "$d/no.csv"'
t_assert "targets file: yes creates the template and uses it" bash -c '
    d=$(mktemp -d)
    printf "y" | (source ./wekatester
        TARGETS=1; TARGETS_PATH=$d/new.csv
        PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        resolve_targets_file
        [ "$TARGETS_FILE" = "$d/new.csv" ]) >/dev/null
    head -1 "$d/new.csv" | grep -q "^host,user_login"'
t_assert "targets file: under -r a missing path is created after the 5s default" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
        TARGETS=1; TARGETS_PATH=$d/r.csv; FAST_TRACK=1
        PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        printf "\n" | resolve_targets_file) >/dev/null 2>&1
    test -f "$d/r.csv"'
t_assert "targets file: bare -t prefers the source set hostfile, else ./hostlist.csv" bash -c '
    d=$(mktemp -d); cd "$d"
    mkdir -p fio-jobfiles/myset
    printf "[global]\n[j]\nrw=read\n" > fio-jobfiles/myset/011-a.job
    printf "host,user_login\nh1,ubuntu\n" > fio-jobfiles/myset/hostlist.csv
    printf "host,user_login\nh1,root\n" > hostlist.csv
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     TARGETS=1; WORKLOAD=myset; resolve_targets_file
     [ "$TARGETS_FILE" = "$d/fio-jobfiles/myset/hostlist.csv" ]) >/dev/null &&
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     TARGETS=1; WORKLOAD=nosuchset; resolve_targets_file
     [ "$TARGETS_FILE" = "./hostlist.csv" ]) >/dev/null'
t_assert "bare -t: an existing -C set folder's hostlist.csv beats ./hostlist.csv" bash -c '
    d=$(mktemp -d); cd "$d"; mkdir -p fio-jobfiles/mine
    printf "host,user_login\n" > hostlist.csv
    printf "host,user_login\nh7,opc\n" > fio-jobfiles/mine/hostlist.csv
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     TARGETS=1; CUSTOMIZE=1; CUSTOM_SET=mine; WORKLOAD=default
     resolve_targets_file
     [ "$TARGETS_FILE" = "$d/fio-jobfiles/mine/hostlist.csv" ]) >/dev/null'
t_assert "bare -t with -C and no file anywhere defers creation to the set" bash -c '
    d=$(mktemp -d); cd "$d"; mkdir -p fio-jobfiles
    out=$( (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     TARGETS=1; CUSTOMIZE=1; CUSTOM_SET=newset; WORKLOAD=default
     resolve_targets_file
     [ -z "$TARGETS_FILE" ] || exit 1) 2>&1 ) &&
    case "$out" in *"created in the custom set"*) true;; *) echo "$out" >&2; false;; esac &&
    [ ! -f "$d/hostlist.csv" ]'
t_assert "custom_set_probe_dir: shipped names and missing dirs probe to nothing" bash -c '
    d=$(mktemp -d); cd "$d"; mkdir -p fio-jobfiles/real
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     CUSTOMIZE=1
     CUSTOM_SET=default; a=$(custom_set_probe_dir)
     CUSTOM_SET=ghost;   b=$(custom_set_probe_dir)
     CUSTOM_SET=real;    c=$(custom_set_probe_dir)
     [ -z "$a" ] && [ -z "$b" ] && [ "$c" = "$d/fio-jobfiles/real" ])'
t_assert "-C sets own a hostfile: resolved file copied in, template when none" bash -c '
    d=$(mktemp -d); cd "$d"; mkdir -p set1 set2 fio-jobfiles/default
    printf "[global]\n[j]\nrw=read\n" > fio-jobfiles/default/011-a.job
    printf "host,user_login\nh9,opc\n" > mine.csv
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     SET_DIR_OVERRIDE=$d/set1; TARGETS=1; TARGETS_FILE=$d/mine.csv
     ensure_set_hostfile
     grep -q h9,opc "$d/set1/hostlist.csv" && [ "$TARGETS_FILE" = "$d/set1/hostlist.csv" ]) &&
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     SET_DIR_OVERRIDE=$d/set2; TARGETS=0
     ensure_set_hostfile
     head -1 "$d/set2/hostlist.csv" | grep -q "^host,user_login" &&
     [ "$TARGETS" -eq 1 ] && [ "$TARGETS_FILE" = "$d/set2/hostlist.csv" ])'
t_assert "customize: host file opens first; jobfiles only behind the prompt (default no)" bash -c '
    source ./tests/helpers.sh; set_fixture; editor_fixture
    (source ./wekatester
     CUSTOMIZE=1; WORKLOAD=default; CUSTOM_SET=$SETFIX
     EDITOR="$ED/stub-ed"; unset VISUAL; resolve_editor
     exec 9<<<"nnn"
     PROMPT_IN_FD=9; PROMPT_OUT_FD=2
     customize_jobfiles) >/dev/null 2>&1
    head -1 "$ED/order" | grep -q "hostlist.csv" &&
    [ "$(wc -l < "$ED/order")" -eq 1 ]'
t_assert "customize: answering yes to the prompt edits the jobfiles after the host file" bash -c '
    source ./tests/helpers.sh; set_fixture; editor_fixture
    (source ./wekatester
     CUSTOMIZE=1; WORKLOAD=default; CUSTOM_SET=$SETFIX
     EDITOR="$ED/stub-ed"; unset VISUAL; resolve_editor
     exec 9<<<"ynn"
     PROMPT_IN_FD=9; PROMPT_OUT_FD=2
     customize_jobfiles) >/dev/null 2>&1
    head -1 "$ED/order" | grep -q "hostlist.csv" &&
    [ "$(wc -l < "$ED/order")" -gt 1 ] &&
    sed -n 2p "$ED/order" | grep -q "011-"
'
t_assert "auth rounds: the host file pins a host's login when the credential has none" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR"
     printf "h1\tubuntu\t-\t-\t-\n" > "$d/targets.phase1"
     attempt_host() { echo "$2:$3" >> "$d/log"; return 0; }
     REMAINING=(h1 h2)
     auth_round "default ssh auth" default "" "" >/dev/null
     grep -qx "h1:ubuntu" "$d/log" && grep -qx "h2:" "$d/log" &&
     [ "$(cat "$AUTH_DIR/h1.user")" = ubuntu ] && test ! -f "$AUTH_DIR/h2.user")'

# --- engine proving, pinning enforcement, priv lifecycle ---
t_assert "engines: candidates are proven with a real job; auto probe list is rewritten" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; DIRECTORY=/mnt/x; FIO_BIN=fio
     printf "engines io_uring libaio psync\n" > "$d/probe/h1"
     run_host() { case "$2" in (*ioengine=io_uring*) return 1;; (*) return 0;; esac; }
     test_engines
     grep -qx "h1 io_uring fail" "$d/engine.results" &&
     grep -qx "h1 libaio ok" "$d/engine.results" &&
     grep -q "^engines libaio psync$" "$d/probe/h1")'
t_assert "engines: a HANGING test job is killed by the timeout and recorded as fail" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/dest"; stub=$d/bin; mkdir -p "$stub"
    printf "#!/bin/bash\ncase \"\$*\" in (*hangeng*) sleep 300;; (*) exit 0;; esac\n" > "$stub/fio"
    chmod +x "$stub/fio"
    start=$(date +%s)
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(localhost); LOCAL_MODE=1; ENGINE=""; AUTO_LEVEL=""
     DIRECTORY=$d/dest; FIO_BIN=$stub/fio; TARGETS=1; TARGETS_FILE=$d/t.csv
     printf ",,hangeng,,,,,\n" > "$d/t.csv"
     printf "engines hangeng libaio\n" > "$d/probe/localhost"
     WEKATESTER_ENGINE_TEST_TIMEOUT=1 test_engines) >/dev/null 2>&1
    took=$(( $(date +%s) - start ))
    grep -qx "localhost hangeng fail" "$d/engine.results" &&
    [ "$took" -lt 60 ]'
t_assert "engines: test_engines returns while unrelated background children live (bare-wait)" bash -c '
    # the run-log tees are alive while test_engines runs; a bare `wait`
    # there deadlocks on them -- seen live as a silent hang right after the
    # last per-engine warning, with no fio running and no D state
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/dest"; stub=$d/bin; mkdir -p "$stub"
    printf "#!/bin/bash\nexit 0\n" > "$stub/fio"; chmod +x "$stub/fio"
    timeout 30 bash -c "
        source ./wekatester
        WORK_DIR=$d; HOSTS=(localhost); LOCAL_MODE=1; AUTO_LEVEL=max
        DIRECTORY=$d/dest; FIO_BIN=$stub/fio
        printf \"engines libaio\\n\" > \"$d/probe/localhost\"
        sleep 300 & DECOY=\$!
        test_engines >/dev/null 2>&1
        echo TE_RETURNED
        # reap the decoy: an orphaned sleep holds the suite stderr/stdout
        # fds, and a PIPED suite run then waits ~5 minutes for EOF after
        # the last test (seen live as a zero-CPU stall)
        kill \$DECOY" | grep -q TE_RETURNED'
t_assert "engines: an enghelp-missing candidate fails without burning a job" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); ENGINE=exotic; DIRECTORY=/mnt/x; FIO_BIN=fio
     printf "engines libaio psync\n" > "$d/probe/h1"
     run_host() { echo "SHOULD NOT RUN" >> "$d/ran"; return 0; }
     test_engines) 2>&1 | grep -q "ioengine .exotic. failed its test job on h1" &&
    test ! -f "$d/ran"'
t_assert "engines: a pinned -e engine failing its job is fatal, naming the evidence" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1 h2); ENGINE=io_uring; DIRECTORY=/mnt/x; FIO_BIN=fio
        printf "engines io_uring\n" > "$d/probe/h1"
        printf "engines io_uring\n" > "$d/probe/h2"
        run_host() { case "$1" in (h2) return 1;; (*) return 0;; esac; }
        test_engines) 2>&1 >/dev/null )
    case "$err" in
        *"ioengine '\''io_uring'\'' failed its test job on h2"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "finalize: a host-line engine that failed its test dies naming host+evidence" bash -c '
    d=$(mktemp -d); f=$(mktemp)
    printf "h1,,weird_eng,,,,,\n" > "$f"
    printf "h1 weird_eng fail\n" > "$d/engine.results"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); TARGETS=1; TARGETS_FILE=$f
        finalize_targets) 2>&1 >/dev/null )
    case "$err" in
        *"assigns ioengine '\''weird_eng'\'' to h1 but its test job failed"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "pinning: cpus outside the taskset with no escalator dies showing all three" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; mkdir -p "$d/auth"
        printf "taskset 0-3\nweka_allowed 8\nweka_allowed 9\nweka_allowed 0-15\n" > "$d/probe/h1"
        printf "h1\t-\t-\t4-7\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >/dev/null )
    case "$err" in
        *"effective cpus_allowed: 4-7 (requested: 4-7)"*"current taskset:        0-3"*"weka dedicated cores:   8,9"*"outside the current taskset"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "pinning: full weka overlap dies; partial runs on the remainder, file untouched" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "taskset 0-15\nweka_allowed 8\nweka_allowed 10\nweka_allowed 0-15\n" > "$d/probe/h1"
        printf "h1\t-\t-\t8,10\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >/dev/null )
    case "$err" in (*"every requested cpu (8,10) is a weka dedicated core"*) true;; (*) echo "$err" >&2; exit 1;; esac
    out2=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "taskset 0-15\nweka_allowed 8\nweka_allowed 10\npriv sudo\n" > "$d/probe/h1"
        printf "h1\t-\t-\t8,10,12\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 )
    case "$out2" in (*"note"*"overlap weka'\''s dedicated cores (8,10)"*"executing on the remainder (12)"*) true;; (*) echo "$out2" >&2; exit 1;; esac
    test ! -s "$d/auth/h1.priv" && [ "$(cat "$d/auth/h1.cpus")" = "12" ]'
t_assert "pinning: an in-mask request with no escalator records cpus and proceeds" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
     printf "taskset 0-15\nweka_allowed 20\nweka_allowed 0-15\n" > "$d/probe/h1"
     printf "h1\t-\t-\t4-7\t-\n" > "$d/targets.final"
     check_cpu_pinning)
    [ "$(cat "$d/auth/h1.cpus")" = "4-7" ] && test ! -s "$d/auth/h1.priv"'
t_assert "kill_fio_cmd: priv prefixes kill/rm/pkill and the anchor survives" bash -c '
    out=$(source ./wekatester; FIO_BIN=/usr/bin/fio; FIO_PIDFILE=/dev/shm/x.pid
          kill_fio_cmd sudo)
    case "$out" in
        *"sudo kill "*"sudo rm -f"*"sudo pkill -9 -f"*"'\''^/usr/bin/fio --server"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "server launch: priv pins via taskset but fio drops to the login user" bash -c '
    d=$(mktemp -d); mkdir -p "$d/auth"
    printf "sudo -n\n" > "$d/auth/h1.priv"; printf "4-7\n" > "$d/auth/h1.cpus"
    printf "8-9\n" > "$d/auth/h3.cpus"
    (source ./wekatester
     WORK_DIR=$d; AUTH_DIR=$d/auth; HOSTS=(h1 h2 h3); FIO_BIN=fio
     WEKATESTER_SETTLE=0
     run_host() { echo "LAUNCH[$1]: $2"; }
     start_fio_servers) >/dev/null 2>&1
    grep -q "sudo -n runuser -u .* -- true" "$d/launch.h1" &&
    grep -q "sudo -n taskset -c 4-7 runuser -u .* -- '\''fio'\'' --server" "$d/launch.h1" &&
    grep -q "WEKATESTER_FIO_AS=root; sudo -n taskset -c 4-7 '\''fio'\'' --server" "$d/launch.h1" &&
    grep -q "LAUNCH\[h2\]" "$d/launch.h2" && ! grep -q taskset "$d/launch.h2" &&
    grep -q "taskset -c 8-9 '\''fio'\''" "$d/launch.h3" && ! grep -q runuser "$d/launch.h3"'

# --- host files: per-host application to staging ---
t_assert "plain staging: host-file dir/geometry/engine land per host, layout re-derived" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; DIRECTORY=/mnt/global; HOSTS=(h1 h2); mkdir -p "$d/jobs" "$d/set"
     printf "# report iops\n[global]\nfilename_format=x/\$jobnum\ndirectory=/orig\nfilesize=10G\nnumjobs=32\nioengine=libaio\n[j]\nrw=randread\niodepth=8\n" > "$d/set/031-i.job"
     (source ./wekatester; generate_layout "$d/set" "$d/set") >/dev/null
     { printf "h1\t-\tpsync\t-\t/mnt/one"
       for i in $(seq 6 29); do
          case $i in (22) printf "\t4";; (23) printf "\t1G";; (24) printf "\t2";;
                     (25) printf "\t16";; (*) printf "\t-";; esac
       done; printf "\n"
       printf "h2"; for i in $(seq 2 29); do printf "\t-"; done; printf "\n"
     } > "$d/targets.final"
     stage_variants "$d/set"
     v1=$d/jobs/h1/031-i.job; v2=$d/jobs/h2/031-i.job; l1=$d/jobs/h1/000-wekatester-layout.job
     grep -q "^directory=/mnt/one$" "$v1" && grep -q "^directory=/mnt/global$" "$v2" &&
     grep -q "^numjobs=4$" "$v1" && grep -q "^filesize=1G$" "$v1" &&
     grep -q "^nrfiles=2$" "$v1" && grep -q "^iodepth=16$" "$v1" &&
     grep -q "^ioengine=psync$" "$v1" && grep -q "^ioengine=libaio$" "$v2" &&
     grep -q "^numjobs=32$" "$v2" &&
     grep -q "^numjobs=4$" "$l1" && grep -q "^filesize=1G$" "$l1" && grep -q "^nrfiles=2$" "$l1")'
t_assert "tuner: host-file dir/cpus/geometry/engine beat the tuned values per host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    { printf "h1\t-\tpsync\t2,4\t/mnt/pin\t3\t2G\t-\t9"
      for i in $(seq 10 29); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1
    v1="$FIX/jobs/h1/011-bw.job"; v2="$FIX/jobs/h2/011-bw.job"
    grep -q "^directory=/mnt/pin$" "$v1" && grep -q "^directory=/mnt/weka$" "$v2" &&
    # the host file keeps the operator spelling "2,4"; the STAGED job declares
    # what actually executes, and this fixture pins weka on cpus 0-2, so only
    # cpu 4 survives -- the same effective set the calibration ladder measures
    grep -q "^cpus_allowed=4$" "$v1" &&
    grep -q "^numjobs=3$" "$v1" && grep -q "^filesize=2G$" "$v1" && grep -q "^iodepth=9$" "$v1" &&
    grep -q "^ioengine=psync$" "$v1" && grep -q "^ioengine=io_uring$" "$v2"'
t_assert "host_dir: targets dir when resolved, global -d otherwise" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; DIRECTORY=/mnt/g
     [ "$(host_dir h1)" = /mnt/g ] || exit 1
     printf "h1\t-\t-\t-\t/mnt/p1\n" > "$d/targets.phase1"
     [ "$(host_dir h1)" = /mnt/p1 ] || exit 1
     printf "h1\t-\t-\t-\t/mnt/f1\n" > "$d/targets.final"
     [ "$(host_dir h1)" = /mnt/f1 ] && [ "$(host_dir h2)" = /mnt/g ])'

# --- -a writeback into the host file ---
wb_fixture() {   # builds WORK_DIR with staged variants + a host file; echoes dirs
    d=$(mktemp -d)
    mkdir -p "$d/jobs/h1" "$d/auth"
    printf "ubuntu\n" > "$d/auth/h1.user"
    printf "# report iops\ncpus_allowed=0-3\ndirectory=/mnt/w\nioengine=libaio\nnumjobs=4\nfilesize=1G\nnrfiles=8\niodepth=32\nrw=randread\n" > "$d/jobs/h1/031-i.job"
    : > "$d/engine.results"
    echo "$d"
}
export -f wb_fixture
t_assert "writeback: fill mode records derived values, keeps what the file provides" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "host,user_login,ioengine\nh1,,psync,,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    grep -q "^# superseded by -a: h1,,psync" "$f" &&
    tail -1 "$f" | grep -q "^h1,ubuntu,psync,0-3,/mnt/w,,,,,/1G/8/32,$" &&
    (source ./wekatester; resolve_targets phase1 "$f" - - - h1 >/dev/null)'
t_assert "writeback: nothing to record leaves the file untouched" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "h1,ubuntu,libaio,0-3,/mnt/w,,,,,4/1G/8/32,\n" > "$f"
    before=$(cat "$f")
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    [ "$(cat "$f")" = "$before" ]'
t_assert "writeback: -g overwrites without a prompt, but never login or allowed_cpus" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "h1,opc,psync,9-11,,,,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; REGEN_LAYOUT=1
     writeback_targets) >/dev/null
    tail -1 "$f" | grep -q "^h1,opc,libaio,9-11,/mnt/w,,,,,/1G/8/32,$"'
t_assert "writeback: -C set owns the target when -t was not given" bash -c '
    d=$(wb_fixture); mkdir "$d/set"
    (source ./wekatester; write_targets_template "$d/set/hostlist.csv") >/dev/null
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=""; SET_DIR_OVERRIDE=$d/set
     FAST_TRACK=1
     writeback_targets) >/dev/null
    tail -1 "$d/set/hostlist.csv" | grep -q "^h1,ubuntu,libaio,0-3"'
# A mixed-direction file stages ONE direction's tuple, but both directions
# were measured; the writeback must record each measured knee into its own
# slot, never the staged tuple into both.
t_assert "writeback: measured knees land per direction; a mixed file cannot copy one over the other" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs/h1" "$d/auth"
    printf "ubuntu\n" > "$d/auth/h1.user"
    printf "# report bandwidth\ncpus_allowed=0-3\ndirectory=/mnt/w\nioengine=libaio\nnumjobs=4\nfilesize=1024M\nnrfiles=2\niodepth=32\nrw=rw\n" > "$d/jobs/h1/011-b.job"
    : > "$d/engine.results"
    # 17 fields (qd nr fs nj per slot) -- and bw_w carries a measured nj=2,
    # a CAL_SPLIT winner, which must land in the host file with its tuple
    printf "h1 32 2 1024M - 4 2 1024M 2 - - - - - - - -\n" > "$d/cal.results"
    f="$d/host.csv"; printf "host,user_login,ioengine\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=cal; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,/1024M/2/32,2/1024M/2/4,,,,$" ||
        { tail -1 "$f" >&2; false; }'

# The seam that broke on isca224 (2026-08-24): calibrate writes cal.results
# and TWO parsers read it -- apply_cal_results and the writeback. They must
# accept the same width, and the cheapest proof is a row from the shared
# layer's own constants going through both.
t_assert "cal.results: one width, both parsers accept what the shared layer defines" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs" "$d/auth"
    row=$( (source ./wekatester; pyrun <<"PYW"
print("h1 " + " ".join(["4", "2", "1024M", "-"] * len(CAL_SLOTS)))
PYW
    ) )
    printf "%s\n" "$row" > "$d/cal.results"
    : > "$d/engine.results"
    # parser 1: apply_cal_results
    (source ./wekatester; WORK_DIR=$d; REGEN_LAYOUT=0; apply_cal_results) ||
        { echo "apply_cal_results rejected: $row" >&2; false; }
    # parser 2: the writeback
    f="$d/host.csv"; printf "host,user_login,ioengine\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=cal; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null ||
        { echo "writeback rejected: $row" >&2; false; }
    tail -1 "$f" | grep -q "^h1,"'

# --- isolcpus awareness (field: isca224, isolcpus=domain,4-55) ---
t_assert "tuner: isolcpus does not narrow cpus_allowed; only weka is excluded" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "isolated 4-7\n" >> "$FIX/probe/h1"
    printf "isolated 4-7\n" >> "$FIX/probe/h2"
    out=$( (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >/dev/null )
    grep -q "^cpus_allowed=3-7$" "$FIX/jobs/h1/011-bw.job" &&
    case "$out" in *"span isolated and housekeeping"*) true;; *) echo "$out" >&2; false;; esac'
# The pin detection is now the ONLY thing keeping fio off weka's cores, so a
# detection that comes back empty while weka is running has to be audible.
t_assert "tuner: weka running with no pinned cores found warns loudly" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nwekanode 4\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    printf "ncpus 8\nwekanode 4\nengines io_uring libaio psync \n" > "$FIX/probe/h2"
    out=$( (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >/dev/null )
    case "$out" in
        *"wekanode process(es) running but no pinned cores detected"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "tuner: no weka on the host is silent, not a warning" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nwekanode 0\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    printf "ncpus 8\nwekanode 0\nengines io_uring libaio psync \n" > "$FIX/probe/h2"
    out=$( (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >/dev/null )
    case "$out" in
        *"no pinned cores detected"*) echo "$out" >&2; false;;
        *) grep -q "^cpus_allowed=0-7$" "$FIX/jobs/h1/011-bw.job";;
    esac'
# Field regression (isca224, 2026-08-21): weka owned cores 14-27 by its own
# core_id list, but the probe scanned /proc/<pid>/task/*/status and unioned
# every single-cpu THREAD mask, reporting 4-27 -- so an operator asking for
# 4-13,28-55 silently lost 4-13 to ten cores weka does not own. The probe
# reads per-process masks now; one wekanode process owns one core.
t_assert "pinning: only the cores weka's node processes own are excluded (isca224)" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    { printf "ncpus 56\nwekanode 15\ntaskset 0-55\nisolated 4-55\n"
      printf "weka_allowed 0-3\n"
      for c in $(seq 14 27); do printf "weka_allowed %s\n" "$c"; done; } > "$d/probe/h1"
    printf "h1\t-\t-\t4-13,28-55\t-\n" > "$d/targets.final"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        check_cpu_pinning) 2>&1 )
    case "$out" in *overlap*|*"executing on the remainder"*) echo "$out" >&2; false;; *) true;; esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "4-13,28-55" ]'
# The shared python layer is the single encoding of the schema and the
# direction rule; pin its load-bearing numbers so a drift fails here first.
t_assert "pylib: one schema for fields, slot bases, and the direction rule" bash -c '
    source ./wekatester
    a=$(pyrun <<< "print(len(FIELDS), slot_base(\"bw_r\"), slot_base(\"iops_w\"), len(CAL_SLOTS))") &&
    [ "$a" = "28 5 25 4" ] &&
    c=$(pyrun <<< "print(\" \".join(CAL_SLOTS))") &&
    [ "$c" = "bw_r bw_w iops_r iops_w" ] &&
    d=$(mktemp -d) && write_targets_template "$d/t.csv" >/dev/null &&
    head -1 "$d/t.csv" | grep -q "^host,user_login,ioengine,allowed_cpus,destination_folder,bandwidthR:nj/fs/nr/qd,bandwidthW:nj/fs/nr/qd,latencyR:nj/fs/nr/qd,latencyW:nj/fs/nr/qd,iopsR:nj/fs/nr/qd,iopsW:nj/fs/nr/qd$" &&
    b=$(pyrun <<< "print(\" \".join(sorted(file_directions([\"[x]\", \"rw=randrw:8\"]))))") &&
    [ "$b" = "read write" ]'
t_assert "usable_cores: an operator cpu list is the base, minus weka pins" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    printf "ncpus 8\nweka_allowed 2\nweka_allowed 5\n" > "$d/probe/h1"
    (source ./wekatester; WORK_DIR=$d
     [ "$(usable_cores h1)" = 6 ] &&
     [ "$(usable_cores h1 count "0-3")" = 3 ] &&
     [ "$(usable_cores h1 list "0-3")" = "0,1,3" ] &&
     [ "$(usable_cores h1 count "2,5")" = 2 ])'
t_assert "usable_cores: a node's auxiliary threads are not extra weka cores (isca224)" \
    test "$(uc "ncpus 56
weka_allowed 0-3
$(for c in $(seq 14 27); do printf 'weka_allowed %s\n' "$c"; done)")" = 42
# The regression was in WHERE the probe looks, so pin that down directly.
t_assert "probe: weka cpu masks come from the process, not its threads" bash -c '
    out=$(source ./wekatester; probe_remote_cmd)
    case "$out" in
        *"task/*/status"*) echo "probe still scans per-task: $out" >&2; false;;
        *"/proc/\$p/status"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "pinning: a mixed isolated+housekeeping list is allowed with a note (split saves it)" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "taskset 0-3\nisolated 4-15\npriv sudo\n" > "$d/probe/h1"
        printf "h1\t-\t-\t0-15\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 )
    case "$out" in
        *"span isolated and housekeeping"*"split affinity"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "0-15" ] && test ! -s "$d/auth/h1.priv"'
t_assert "pinning: a pure-isolated request needs no escalator (self-affinable)" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
     printf "taskset 0-3\nisolated 4-15\n" > "$d/probe/h1"
     printf "h1\t-\t-\t4-9\t-\n" > "$d/targets.final"
     check_cpu_pinning)
    [ "$(cat "$d/auth/h1.cpus")" = "4-9" ] && test ! -s "$d/auth/h1.priv"'
t_assert "pinning: privileges are as-needed -- self-affinable mask ignores an available escalator" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
     printf "taskset 0-3\nisolated 4-15\npriv dzdo -n\n" > "$d/probe/h1"
     printf "h1\t-\t-\t4-9\t-\n" > "$d/targets.final"
     check_cpu_pinning)
    [ "$(cat "$d/auth/h1.cpus")" = "4-9" ] && test ! -s "$d/auth/h1.priv"'
t_assert "host_priv: a multi-word escalator prefix survives intact" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    (source ./wekatester
     WORK_DIR=$d
     printf "ncpus 8\npriv ksu -e\n" > "$d/probe/h1"
     [ "$(host_priv h1)" = "ksu -e" ] && [ -z "$(host_priv h2)" ])'
t_assert "run_weka_master: user attempt first, one escalated retry, note on success" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    err=$( (source ./wekatester
     WORK_DIR=$d; MASTER=m1
     printf "priv pbrun\n" > "$d/probe/m1"
     run_host() { case "$2" in
         ("pbrun weka status") echo escalated;;
         ("weka status") return 1;;
     esac; }
     run_weka_master "weka status" "$d/out" || echo RC_FAIL >&2) 2>&1 )
    grep -q escalated "$d/out" &&
    case "$err" in *"needed pbrun"*) true;; *) echo "$err" >&2; false;; esac &&
    case "$err" in *RC_FAIL*) false;; *) true;; esac'
t_assert "run_weka_master: weka missing for the user (exit 127) still gets the escalated attempt" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    (source ./wekatester
     WORK_DIR=$d; MASTER=m1
     printf "priv sudo -n\n" > "$d/probe/m1"
     run_host() { case "$2" in
         ("sudo -n weka status") echo escalated;;
         ("weka status") return 127;;
     esac; }
     run_weka_master "weka status" "$d/out") >/dev/null 2>&1
    grep -q escalated "$d/out"'
t_assert "probe sweep: site escalators beat sudo, failing ones are skipped" bash -c '
    d=$(mktemp -d)
    printf "#!/bin/sh\nexit 1\n" > "$d/dzdo"
    printf "#!/bin/sh\nexec \"\$@\"\n" > "$d/pbrun"
    printf "#!/bin/sh\nshift\nexec \"\$@\"\n" > "$d/timeout"
    printf "#!/bin/sh\necho \"pid 0: 0-3\"\n" > "$d/taskset"
    printf "#!/bin/sh\necho libaio\n" > "$d/fio"
    chmod +x "$d"/*
    cmd=$( (source ./wekatester; FIO_BIN=fio; probe_remote_cmd) )
    out=$(PATH="$d:$PATH" bash -c "$cmd" 2>&1)
    case "$out" in *"priv pbrun"*) true;; *) echo "$out" >&2; false;; esac &&
    case "$out" in *"priv dzdo"*|*"priv sudo"*) false;; *) true;; esac'

# --- lab-gate regressions (rebuilt shrw, 2026-08-08) ---
# In the field `-f -g` quietly made "-g" the fio binary; preflight then hunted
# a binary named -g on every host with a bewildering message.
t_assert "parse: an option value that looks like another option is refused" bash -c '
    err=$( (source ./wekatester; parse_args -f -g h1) 2>&1 >/dev/null )
    case "$err" in
        *"option -f requires an argument, got '\''-g'\'' (looks like another option)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "parse: a trailing valueless option still dies asking for an argument" bash -c '
    err=$( (source ./wekatester; parse_args h1 -w) 2>&1 >/dev/null )
    case "$err" in
        *"option -w requires an argument"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# The mount pass now also proves fio can create files under -d: a root-owned
# mount root otherwise fails every job later with an EACCES that fio client
# mode only half-reports. Stubs key off the command string ($2).
t_assert "mount guard: unwritable -d dies with the chmod hint before anything runs" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka
            run_host() { case "$2" in (findmnt*) echo "wekafs rw,forcedirect";; (*) return 1;; esac; }
            verify_mount_mode) 2>&1 >/dev/null )
    case "$err" in
        *"localhost: cannot create files in /mnt/weka"*"chmod 1777"*"/mnt/weka is not writable on every host"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: a mode failure skips the probe and keeps the remount advice" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka
            run_host() { case "$2" in (findmnt*) echo "wekafs rw,writecache";; (*) echo probed >&2; return 1;; esac; }
            verify_mount_mode) 2>&1 >/dev/null )
    case "$err" in *probed*) echo "probe ran after a mode failure: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"must be mounted with forcedirect; remount"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: writable non-wekafs -d passes with the probe" bash -c '
    (source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/data
     run_host() { case "$2" in findmnt*) echo "xfs rw,noatime";; *) return 0;; esac; }
     verify_mount_mode)'

# fio --client exits 0 even when every worker-side job failed; success is read
# from the results. The lab run "succeeded" in 5s per job with zero IO while
# every process died on EACCES.
t_assert "check_fio_errors: a nonzero per-job error field fails the run, naming the host" bash -c '
    tmp=$(mktemp -d)
    cat > "$tmp/r.json" <<"JSON"
<vega-1> fio: failed to create dir (/mnt/weka/vega-1.0): Permission denied
{ "client_stats": [
    { "jobname": "layout-1", "hostname": "vega-1", "error": 13,
      "read": { "total_ios": 0 }, "write": { "total_ios": 0 } } ] }
JSON
    err=$( (source ./wekatester; check_fio_errors "$tmp/r.json" layout) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in
        *"vega-1: job '\''layout-1'\'' error 13"*"Permission denied"*) true;;
        *) echo "rc=$rc $err" >&2; false;;
    esac'
t_assert "check_fio_errors: a measured job that moved zero bytes and ios fails" bash -c '
    tmp=$(mktemp -d)
    cat > "$tmp/r.json" <<"JSON"
{ "client_stats": [
    { "jobname": "create", "hostname": "vega-1",
      "read": { "total_ios": 0 }, "write": { "total_ios": 900 } },
    { "jobname": "bw", "hostname": "vega-1",
      "read": { "total_ios": 0, "bw_bytes": 0 }, "write": { "total_ios": 0, "bw_bytes": 0 } } ] }
JSON
    err=$( (source ./wekatester; check_fio_errors "$tmp/r.json" measured) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in
        *"vega-1: measured job moved no data"*) true;;
        *) echo "rc=$rc $err" >&2; false;;
    esac'
t_assert "check_fio_errors: layout mode accepts all-zero create_only stats" bash -c '
    tmp=$(mktemp -d)
    cat > "$tmp/r.json" <<"JSON"
{ "client_stats": [
    { "jobname": "layout-1", "hostname": "vega-1", "error": 0,
      "read": { "total_ios": 0 }, "write": { "total_ios": 0 } } ] }
JSON
    (source ./wekatester; check_fio_errors "$tmp/r.json" layout)'
t_assert "check_fio_errors: a healthy multi-host results file passes measured mode" bash -c '
    source ./tests/helpers.sh
    tmp=$(mktemp -d); fio_json_fixture "$tmp/r.json"
    (source ./wekatester; check_fio_errors "$tmp/r.json" measured)'
t_assert "check_fio_errors: an empty client_stats list is a failed run, not a pass" bash -c '
    tmp=$(mktemp -d)
    printf "{ \"client_stats\": [] }\n" > "$tmp/r.json"
    err=$( (source ./wekatester; check_fio_errors "$tmp/r.json" layout) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in
        *"no per-job stats"*) true;;
        *) echo "rc=$rc $err" >&2; false;;
    esac'

# --- calibrate(): the ladder orchestrator ---
# A run_host stub answers each rung with fabricated JSON. What the block
# covers: a SHAPE pass that stops after CAL_STOP_BELOW rungs fail to beat the
# best by more than CAL_SHAPE_THR, a DECISION pass of CAL_REPS interleaved
# repeats over the nominated candidates, a verdict that is plateau membership
# against a FIXED CAL_KNEE_PCT band, hysteresis against a recorded qd the
# plateau contains, every rung credited with its best reading, CAL_NOISY_PCT
# warning about a contended window without voiding the ladder,
# per-(type,direction) tuples in cal.results, and a scratch kept unless -u.
cal_json() {   # cal_json <value> -> fio-style client_stats JSON on stdout
    # the value lands in BOTH bw_bytes and iops so the same helper drives a
    # bw-mode ladder (cal_values keys on bw_bytes) and an iops-mode one (iops)
    printf '{ "client_stats": [ { "jobname": "cal-bw-read", "hostname": "h1", "error": 0, "read": { "bw_bytes": %s, "iops": %s, "total_ios": 100, "io_bytes": 1000 }, "write": { "bw_bytes": 0, "iops": 0, "total_ios": 0, "io_bytes": 0 } } ] }\n' "$1" "$1"
}
export -f cal_json
t_assert "brutal_grids: every cell measured, the winner recorded, the surface logged" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=brutal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
     BRUTAL_NRS="1 2"; BRUTAL_QDS="1 2"; BRUTAL_CONFIRM=1; CAL_RUNTIME=10
     BRUTAL_NJ=100
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
         (*MemTotal*) echo 8388608; return 0;;
     esac
     echo "$2" >> "$d/cells"
     case "$2" in
         (*qd2-nr2.job*) cal_json 4000;;
         (*qd2-nr1.job*) cal_json 3000;;
         (*qd1-nr2.job*) cal_json 2000;;
         (*)             cal_json 1000;;
     esac; }
     calibrate) 2>&1 )
    # 2x2 grid plus one confirm cell on the winner
    [ "$(grep -c "qd[0-9]*-nr[0-9]*\.job" "$d/cells")" = 5 ] || { echo "cells: $(grep -c "qd..nr..job" "$d/cells")" >&2; false; }
    grep -q "cal-bw-read-qd1-nr1.job" "$d/cells" &&
    grep -q "cal-bw-read-qd2-nr2.job" "$d/cells" &&
    case "$out" in
        *"bw-read: nrfiles=2 iodepth=2 -> "*"(best of 2 samples"*"grid spans 25-100% of best over 4 cells"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    case "$out" in *"nr2"*"100%"*) true;; *) echo "no surface table" >&2; false;; esac &&
    # the winning tuple lands in cal.results with numjobs left derived
    grep -qx "h1 2 2 5120M - - - - - - - - - - - - -" "$d/cal.results"'
# The numjobs axis: the full grid runs once per BRUTAL_NJ level, a 2x cell is
# staged with twice the jobs, and a 2x winner records its actual job count so
# the staged test runs what measured best.
t_assert "brutal_grids: a 2x-numjobs winner records its job count; a 1x winner a dash" bash -c '
    run_nj() {   # run_nj <p200-value>: prints the cal.results row
        v200=$1
        d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
        printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
        (source ./tests/helpers.sh; source ./wekatester
         AUTO_LEVEL=brutal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
         TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
         SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
         BRUTAL_NRS="1"; BRUTAL_QDS="1 2"; BRUTAL_CONFIRM=0; CAL_RUNTIME=10
         BRUTAL_NJ="100 200"
         printf "ncpus 4\n" > "$d/probe/h1"
         copy_to_master() { :; }
         run_host() { case "$2" in
             (*mkdir*|*rm\ -rf*|*find*) return 0;;
             (*df*) echo "wekafs 999999999 99999999"; return 0;;
             (*MemTotal*) echo 8388608; return 0;;
         esac
         echo "$2" >> "$d/cells"
         case "$2" in
             (*qd2-nr1-nj200.job*) cal_json "$v200";;
             (*qd2-nr1.job*)       cal_json 1000;;
             (*)                   cal_json 500;;
         esac; }
         calibrate) > "$d/log" 2>&1
        # the 2x cells must have been staged with doubled jobs
        grep -q "^numjobs=8$" "$d/cal/h1/cal-bw-read-qd2-nr1-nj200.job" || return 1
        [ "$(grep -c "nj200.job" "$d/cells")" = 2 ] || return 1
        cat "$d/cal.results"
    }
    # 2x pool reached higher -> winner is qd=2 with nj recorded as 8
    # (4 usable cpus x 200%)
    run_nj 1200 | grep -qx "h1 2 1 5120M 8 - - - - - - - - - - - -" &&
    # 1x pool higher -> same qd, nj stays a dash (numjobs derived as always)
    run_nj 900 | grep -qx "h1 2 1 5120M - - - - - - - - - - - - -"'
# A BRUTAL_NJ level above 100 needs seed files for the extra jobs: job n
# opens file n, and a 2x cell with only 1x seed files reads short.
t_assert "cal_seed_scratch: BRUTAL_NJ above 100 widens the seed to the extra jobs" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/cal/h1"
    printf "ncpus 2\n" > "$d/probe/h1"
    printf "bw read\n" > "$d/cal/seedplan.h1"
    (source ./wekatester
     AUTO_LEVEL=brutal; WORK_DIR=$d; AUTH_DIR=$d/auth; DIRECTORY=/mnt/weka
     CAL_SETTLE=0; ladders="bw read"; BRUTAL_NRS="1 2"; BRUTAL_NJ="100 200"
     run_host() { case "$2" in
         (*find*) return 0;;
         (*df*)   echo "wekafs 99999999999 999999999";;
         (*)      return 0;;
     esac; }
     cal_seed_scratch h1) >/dev/null 2>&1
    # 2 cpus x 200% = 4 jobs: the seed covers job 3
    grep -q "^\[seed-3-" "$d/cal/h1/cal-seed.job" &&
    ! grep -q "^\[seed-4-" "$d/cal/h1/cal-seed.job"'

# Write cells stay per-client even in the unified namespace: concurrent
# cross-client writes to shared files measure lease arbitration, not the
# client. And a sequential-write-only plan truncate-seeds its write set,
# while any 4k-random write phase forces the dense seed (the measured 6.7%
# extent-map insert penalty).
t_assert "calibrate: unified write cells are per-host; bw-only write sets truncate-seed" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\n[a]\nrw=write\n" > "$d/set/012-a.job"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { echo "RH: $2" >> "$d/oplog"; case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac; cal_json 1000; }
     calibrate) 2>&1 )
    f=$(ls "$d/cal/h1/"cal-bw-write-qd1*.job | head -1) &&
    grep -q "^filename_format=h1.\$filenum/\$jobnum$" "$f" &&
    # no dense sections were seeded; the write canvas was truncated instead
    [ "$(grep -c "^\[seed-" "$d/cal/h1/cal-seed.job")" = 0 ] &&
    grep -q "^h1.0/0 5120$" "$d/cal/h1/truncate.list" &&
    grep -q "truncate -s 5120M" "$d/oplog" &&
    case "$out" in
        *"truncate-seeded 8 write file(s)"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "calibrate: a 4k-random write phase forces the dense write seed" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report iops\n[global]\nfilename_format=\$filenum/\$jobnum\nbs=4k\n[a]\nrw=randwrite\n" > "$d/set/032-a.job"
    (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac; cal_json 1000; }
     calibrate) >/dev/null 2>&1
    # dense sections for the host write set, and nothing truncated
    grep -q "^filename=h1.0/0:h1.1/0$" "$d/cal/h1/cal-seed.job" &&
    [ ! -s "$d/cal/h1/truncate.list" ]'
# The shared read set is seeded ONCE, sliced evenly across the seeding hosts.
t_assert "cal_seed_scratch: the shared read set is sliced evenly across seeders" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/cal/h1" "$d/cal/h2"
    printf "ncpus 2\n" > "$d/probe/h1"; printf "ncpus 2\n" > "$d/probe/h2"
    printf "bw read\n" > "$d/cal/seedplan.h1"; printf "bw read\n" > "$d/cal/seedplan.h2"
    (source ./wekatester
     WORK_DIR=$d; AUTH_DIR=$d/auth; DIRECTORY=/mnt/weka; CAL_SETTLE=0
     CAL_NS_DIR=""; CAL_SEP="."; CAL_FMT="\$jobnum.\$filenum"
     HOSTS=(h1 h2); ladders="bw read"
     run_host() { case "$2" in
         (*find*) return 0;;
         (*df*)   echo "wekafs 99999999999 999999999";;
         (*)      return 0;;
     esac; }
     cal_seed_scratch h1 h2) >/dev/null 2>&1
    a=$(grep -h "^filename=" "$d/cal/h1/cal-seed.job" | tr "\n" " ")
    b=$(grep -h "^filename=" "$d/cal/h2/cal-seed.job" | tr "\n" " ")
    # 2 jobs x 2 files = 4 shared names, dealt alternately: no overlap, full cover
    [ "$a" = "filename=shared.0.0 filename=shared.1.0 " ] || { echo "h1: [$a]" >&2; false; }
    [ "$b" = "filename=shared.0.1 filename=shared.1.1 " ] || { echo "h2: [$b]" >&2; false; }'
# Staged read-only jobs run on the shared dataset; write jobs stay host-owned.
t_assert "tuner: unified staging sends read-only jobs to the shared dataset" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\nrw=read\n" > "$FIX/src/011-r.job"
    printf "# report bandwidth\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\nrw=write\n" > "$FIX/src/012-w.job"
    (source ./wekatester
     WEKATESTER_NS="unified \$filenum/\$jobnum" \
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "" h1 h2) >/dev/null 2>&1
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$FIX/jobs/h1/011-r.job" &&
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$FIX/jobs/h2/011-r.job" &&
    grep -q "^filename_format=\$filenum/\$jobnum$" "$FIX/jobs/h1/012-w.job"'

# A write cell leaves a destage backlog, and the next cell starts inside it:
# on the first field runs every read surface was smooth while the write
# surfaces carried the previous cell's debt. Write cells settle; reads never.
t_assert "brutal_grids: every write cell settles, read cells never do" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=write\n" > "$d/set/012-a.job"
    (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=brutal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=7
     BRUTAL_NRS="1 2"; BRUTAL_QDS="1 2"; BRUTAL_CONFIRM=1; CAL_RUNTIME=10
     BRUTAL_NJ=100
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     sleep() { echo "settle $1" >> "$d/settles"; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
         (*MemTotal*) echo 8388608; return 0;;
     esac; cal_json 1000; }
     calibrate) >/dev/null 2>&1
    # the cold seed settles once, then 4 grid cells + 1 confirm, all write,
    # one settle each -- and nothing else: a settled write grid owes the next
    # block no settle of its own
    [ "$(grep -c "^settle 7$" "$d/settles")" = 6 ] ||
        { echo "settles: $(cat "$d/settles")" >&2; false; }'
t_assert "brutal_grids: a read-only grid never settles" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=brutal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=7
     BRUTAL_NRS="1 2"; BRUTAL_QDS="1 2"; BRUTAL_CONFIRM=1; CAL_RUNTIME=10
     BRUTAL_NJ=100
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     sleep() { echo "settle $1" >> "$d/settles"; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
         (*MemTotal*) echo 8388608; return 0;;
     esac; cal_json 1000; }
     calibrate) >/dev/null 2>&1
    # exactly the cold seed settle -- no read cell adds one
    [ "$(grep -c "^settle 7$" "$d/settles")" = 1 ] ||
        { echo "settled: $(cat "$d/settles")" >&2; false; }'

# The deep corner of a bw grid can ask for more in-flight buffers than a small
# client has. Skipping is fine; skipping SILENTLY is not.
t_assert "brutal_grids: a cell that cannot fit its in-flight buffers is named, not hidden" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=brutal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
     BRUTAL_NRS="1"; BRUTAL_QDS="1 128"; BRUTAL_CONFIRM=0; CAL_RUNTIME=10
     BRUTAL_NJ=100; BRUTAL_MEM_FRAC=25
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
         (*MemTotal*) echo 1048576; return 0;;   # 1 GiB host
     esac; echo "$2" >> "$d/cells"; cal_json 1000; }
     calibrate) 2>&1 )
    # 4 jobs x qd128 x 1MiB = 512MiB in flight, past 25% of a 1GiB host
    case "$out" in
        *"bw-read nr=1 qd=128 nj=4 SKIPPED"*"512MiB in flight vs 256MiB allowed"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    ! grep -q "qd128" "$d/cells" &&
    grep -q "qd1-nr1.job" "$d/cells"'

t_assert "calibrate: the pick is the shallowest rung on the plateau" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    out=$( (source ./tests/helpers.sh
     source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     # peak 2100 at qd=8; qd=16/32 fall back (early stop after two misses);
     # the pick is qd=8, the shallowest rung on the 98.5% plateau (qd=4 sits
     # at 97.6% of the peak, so it is off it)
     run_host() { case "$2" in
         (*mkdir*) echo "MK: $2" >> "$d/oplog";;
         (*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
         (*rm\ -rf*) echo "RM: $2" >> "$d/oplog";;
         (*cal-seed.job*) cal_json 1000;;
         (*qd1-nr2.job*)  cal_json 1000;;
         (*qd2-nr2.job*)  cal_json 1900;;
         (*qd4-nr2.job*)  cal_json 2050;;
         (*qd8-nr2.job*)  cal_json 2100;;
         (*qd16-nr2.job*) cal_json 2000;;
         (*qd32-nr2.job*) cal_json 1990;;
         (*) echo "UNEXPECTED: $2" >> "$d/oplog"; return 1;;
     esac; }
     calibrate) 2>&1 )
    case "$out" in
        *"bw-read: qd=8 -- plateau qd=8 >=98.5% of best"*"at qd=8 (n=3, cv<=0.0%)"*"[nrfiles=2 fs=5120M]"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    # nj is a dash: no split re-test won, so numjobs stays operator-owned
    grep -q "^h1 8 2 5120M - - - - - - - - - - - - -$" "$d/cal.results" &&
    # early stop: qd=16 and qd=32 both fail to beat 2100 by >CAL_SHAPE_THR,
    # so qd=64 is never staged
    [ ! -f "$d/cal/h1/cal-bw-read-qd64-nr2.job" ] &&
    grep -q "^MK: mkdir -p ./mnt/weka/.wekatester-cal." "$d/oplog" &&
    ! grep -q "^RM: rm -rf ./mnt/weka/.wekatester-cal." "$d/oplog" &&
    case "$out" in *"keeping the calibration scratch"*) true;; *) echo "$out" >&2; false;; esac &&
    grep -q "^filename_format=h1.cal" "$d/cal/h1/cal-bw-read-qd8-nr2.job"'
# The seed is the union of what every ladder needs: file f at the largest
# size any (type, direction) table entry asks of it.
t_assert "cal_seed_sizes: one normalized size, the union is just the widest file count" bash -c '
    out=$( (source ./wekatester; cal_seed_sizes "bw read
bw write
iops read") | tr "\n" " " )
    [ "$out" = "0 5120 1 5120 " ] || { echo "$out" >&2; false; }'
t_assert "cal_seed_sizes: iops seeds the same normalized size as bw" bash -c '
    out=$( (source ./wekatester; cal_seed_sizes "iops read") | tr "\n" " " )
    [ "$out" = "0 5120 1 5120 " ] || { echo "$out" >&2; false; }'
t_assert "cal_seed_sizes: a latency-only set still gets a plan, at the one size" bash -c '
    out=$( (source ./wekatester; cal_seed_sizes "lat read
lat write") | tr "\n" " " )
    [ "$out" = "0 5120 1 5120 " ] || { echo "$out" >&2; false; }'
# Incremental: a file already at or above the needed size is left alone, so a
# warm scratch seeds nothing and a cold one seeds exactly the union.
t_assert "cal_seed_scratch: a warm scratch seeds nothing, a cold one seeds the union" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/cal"
    printf "ncpus 4\n" > "$d/probe/h1"      # -> 4 usable cores, so 4 jobs
    # cold: nothing exists
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka
     TARGET_DIR=/dev/shm/x; AUTH_DIR=$d/auth; CAL_SETTLE=0
     ladders="bw read"
     copy_to_master() { :; }
     run_host() { case "$2" in (*find*) return 0;; (*df*) echo "wekafs 999999999 99999999"; return 0;; esac
         echo "$2" >> "$d/ran"; printf "{ \"client_stats\": [ { \"jobname\": \"cal-x\", \"hostname\": \"h1\", \"error\": 0, \"read\": { \"bw_bytes\": 1, \"iops\": 1, \"total_ios\": 1, \"io_bytes\": 1 }, \"write\": { \"bw_bytes\": 1, \"iops\": 1, \"total_ios\": 1, \"io_bytes\": 1 } } ] }\n"; }
     cal_seed_scratch h1) >/dev/null 2>&1
    # 4 jobs x 2 filenums, grouped per (job, size): 4 sections, each seeding
    # both files of that job through a colon-joined filename list
    [ "$(grep -ac "^\[seed-" "$d/cal/h1/cal-seed.job")" = 4 ] || { echo "sections: $(grep -ac "^.seed-" "$d/cal/h1/cal-seed.job")" >&2; exit 1; }
    grep -q "^filename=h1.cal.0.0:h1.cal.0.1$" "$d/cal/h1/cal-seed.job" || exit 1
    grep -q "^nrfiles=2$" "$d/cal/h1/cal-seed.job" || exit 1
    grep -q "^filesize=5120M$" "$d/cal/h1/cal-seed.job" || exit 1
    # warm: every file already present and big enough -> no fio invocation
    rm -f "$d/ran"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka
     TARGET_DIR=/dev/shm/x; AUTH_DIR=$d/auth; CAL_SETTLE=0
     ladders="bw read"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
         (*find*) for j in 0 1 2 3; do for f in 0 1; do
                      echo "h1.cal.$j.$f 5368709120"; done; done; return 0;;
     esac; echo "$2" >> "$d/ran"; }
     cal_seed_scratch h1) >/dev/null 2>&1
    [ ! -f "$d/ran" ] || { echo "warm scratch still ran: $(cat "$d/ran")" >&2; exit 1; }
    [ "$(grep -ac "^\[seed-" "$d/cal/h1/cal-seed.job")" = 0 ]'
# The scratch is the expensive part of a calibration, so it survives the run
# for the next one to reuse -- unless -u, which removes data files by contract.
# Each host individually fits, but they share one filesystem: the guard
# must sum the group and compare against the SHARED free space.
t_assert "cal_seed_scratch: shared-filesystem seeds are summed against the shared free space" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/cal"
    printf "ncpus 2\n" > "$d/probe/h1"; printf "ncpus 2\n" > "$d/probe/h2"
    out=$( (source ./wekatester
     WORK_DIR=$d; MASTER=h1; FIO_BIN=fio; TARGET_DIR=/dev/shm/x
     DIRECTORY=/mnt/weka; AUTH_DIR=""
     ladders="bw read"
     copy_to_master() { :; }
     # per host: 2 jobs x 2 files x 5120M = 20480MiB against 4096MiB free
     run_host() { case "$2" in
         (*df*) echo "wekafs 999999 4096"; return 0;;
         (*) return 0;;
     esac; }
     cal_seed_scratch h1 h2) 2>&1 )
    case "$out" in
        *"need=40960MiB avail=4096MiB on h1 h2"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    # a host-local source (/dev/*) is never grouped: the same shape passes
    out=$( (source ./wekatester
     WORK_DIR=$d; MASTER=h1; FIO_BIN=fio; TARGET_DIR=/dev/shm/x
     DIRECTORY=/mnt/weka; AUTH_DIR=""
     ladders="bw read"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*df*) echo "/dev/nvme0n1 999999 20480"; return 0;;
         (*cal-seed.job*) printf "{ \"client_stats\": [ { \"jobname\": \"s\", \"hostname\": \"h1\", \"error\": 0, \"write\": { \"bw_bytes\": 1, \"iops\": 1, \"total_ios\": 1, \"io_bytes\": 1 }, \"read\": { \"bw_bytes\": 0, \"iops\": 0, \"total_ios\": 0, \"io_bytes\": 0 } } ] }\n";;
         (*) return 0;;
     esac; }
     CAL_SETTLE=0
     cal_seed_scratch h1 h2) 2>&1 )
    case "$out" in
        *"not enough free space"*) echo "$out" >&2; false;;
        *) true;;
    esac'
t_assert "calibrate: -u removes the calibration scratch, the default keeps it" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    run_one() {   # run_one <unlink> -> the oplog
        rm -rf "$d/oplog" "$d/cal"
        (source ./tests/helpers.sh; source ./wekatester
         AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
         TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
         SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; UNLINK=$1
         printf "ncpus 4\n" > "$d/probe/h1"
         copy_to_master() { :; }
         run_host() { case "$2" in
             (*find*) return 0;;
             (*df*) echo "wekafs 999999999 99999999"; return 0;;
             (*rm\ -rf*) echo "RM: $2" >> "$d/oplog"; return 0;;
         esac; cal_json 1000; }
         calibrate) >/dev/null 2>&1
    }
    run_one 0
    if [ -f "$d/oplog" ] && grep -q "wekatester-cal" "$d/oplog"; then
        echo "default removed it" >&2; exit 1
    fi
    run_one 1; grep -q "^RM: rm -rf ./mnt/weka/.wekatester-cal." "$d/oplog"'

# The ladder stops after CAL_STOP_BELOW rungs that fail to beat the best by
# more than the measured noise -- a turned-over curve is not climbed forever.
t_assert "calibrate: a turned-over curve stops the ladder early" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report iops\n[global]\nfilesize=1G\n[a]\nbs=4k\nrw=randread\n" > "$d/set/031-a.job"
    (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac; echo "$2" >> "$d/cells"
     # qd=1 is best: the curve turned over immediately
     case "$2" in (*qd1-nr*) cal_json 9000;; (*) cal_json 1000;; esac; }
     calibrate) >/dev/null 2>&1
    got=$(grep -o "qd[0-9]*-nr2\." "$d/cells" | sed "s/qd//;s/-nr2.//" | sort -un | tr "\n" " ")
    [ "$got" = "1 2 4 " ] || { echo "qds staged: $got" >&2; false; }'
t_assert "calibrate: a climbing curve is followed to the deepest rung" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report iops\n[global]\nfilesize=1G\n[a]\nbs=4k\nrw=randread\n" > "$d/set/031-a.job"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac
     # value doubles per rung all the way up
     q=$(echo "$2" | grep -o "qd[0-9]*" | head -1 | tr -dc 0-9)
     cal_json $((q * 100)); }
     calibrate) 2>&1 )
    [ -f "$d/cal/h1/cal-iops-read-qd256-nr2.job" ] &&
    case "$out" in
        *"iops-read: qd=256 -- plateau qd=256 >=98.5% of best"*"at qd=256"*) true;;
        *) echo "$out" >&2; false;;
    esac'
# A wide spread is REPORTED, not punished. Contention only ever costs
# throughput, so repeats that disagree mean some of them ran busy -- the rung's
# best reading is still evidence of what the client did, and the ladder records.
t_assert "calibrate: noisy repeats warn and still record, they do not void the ladder" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac
     case "$2" in
         (*qd2-nr2.job*)
             # call 1 is the shape pass; calls 2-4 are the decision repeats,
             # and two of them landed in a contended window
             [ -f "$d/n" ] || echo 0 > "$d/n"; n=$(cat "$d/n"); n=$((n + 1)); echo "$n" > "$d/n"
             case "$n" in (1) cal_json 1350;; (2) cal_json 1000;; (3) cal_json 1400;; (*) cal_json 1200;; esac;;
         (*qd1-nr2.job*) cal_json 1000;;
         (*)             cal_json 900;;
     esac; }
     calibrate) 2>&1 )
    # cv over 1000/1400/1200 is 16.7%, past CAL_NOISY_PCT=8: warned, and the
    # rung is credited with 1400 -- the best it was seen to do
    case "$out" in
        *"WARNING: h1 bw-read: repeats disagree by up to 16.7%"*"contended window"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    case "$out" in
        *"bw-read: qd=2 -- plateau qd=2 >=98.5% of best"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    # recorded, not discarded
    grep -qx "h1 2 2 5120M - - - - - - - - - - - - -" "$d/cal.results"'
# A rung is worth its BEST reading, not the average of its repeats: averaging
# credits it with less than it demonstrably did, and pushes whichever rung
# caught a busy window off the plateau.
t_assert "cal_verdict: a rung is credited with its best reading, not its mean" bash -c '
    d=$(mktemp -d); mkdir -p "$d/cal"
    # qd=16 reached 1000 once and 600 under contention (best 1000, mean 800);
    # qd=32 sat at 900 twice. Averaging puts qd=32 on top and drops qd=16 off
    # a 98.5% band; the best readings put qd=16 on top and it is the pick.
    printf "read 2 16 1000\nread 2 16 600\nread 2 32 900\nread 2 32 900\n" \
        > "$d/cal/hist-bw-read.h1"
    out=$( (source ./wekatester; WORK_DIR=$d; CAL_HYSTERESIS=0
            cal_verdict h1 bw read) 2>/dev/null )
    case "$out" in
        "16 qd=16 -- plateau qd=16 >=98.5% of best "*"at qd=16 "*) true;;
        *) echo "$out" >&2; false;;
    esac'
# The verdict must report real numbers, not just ratios: a ladder that
# measured nothing (reads of a hollow layout) looks identical in percentages.
t_assert "calibrate: the verdict logs absolute values, the plateau and the cv" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac; cal_json 1073741824; }
     calibrate) 2>&1 )
    # a dead-flat ladder IS a plateau: every rung ties, so the pick is the
    # shallowest and the cv is zero
    case "$out" in
        *"bw-read: qd=1 -- plateau qd=1..4 >=98.5% of best 1.00GiB/s at qd=1 (n=3, cv<=0.0%)"*) true;;
        *) echo "$out" >&2; false;;
    esac'
# Hysteresis: two runs that cannot tell one rung from another must not
# disagree about which to write down. A recorded qd the plateau contains is
# kept, and the log says so rather than silently churning the host file.
t_assert "calibrate: a recorded qd the plateau contains is kept, not rewritten" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    # a 29-column row carrying bw_r_qd=2 and nothing else measured
    row=h1; for i in $(seq 2 29); do row="$row	-"; done
    printf "%s\n" "$row" | awk -F"\t" -v OFS="\t" "{ \$9 = 2; print }" > "$d/targets.final"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=1
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac; cal_json 1073741824; }
     calibrate) 2>&1 )
    # flat ladder -> plateau qd=1..4, fresh pick qd=1; the host file already
    # says qd=2, which is on that plateau, so qd=2 stands
    case "$out" in
        *"bw-read: qd=2 (kept: the host file"*"is on this plateau; fresh pick was qd=1)"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    awk "{ print \$2 }" "$d/cal.results" | grep -qx 2'
t_assert "calibrate: CAL_HYSTERESIS=0 takes the fresh pick instead" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    row=h1; for i in $(seq 2 29); do row="$row	-"; done
    printf "%s\n" "$row" | awk -F"\t" -v OFS="\t" "{ \$9 = 2; print }" > "$d/targets.final"
    (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=1
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_HYSTERESIS=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac; cal_json 1073741824; }
     calibrate) >/dev/null 2>&1
    awk "{ print \$2 }" "$d/cal.results" | grep -qx 1'
# The decision pass measures each candidate CAL_REPS times, ROUND-ROBIN: three
# back-to-back cells cannot tell noise from drift.
t_assert "calibrate: the decision pass interleaves its repeats" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac
     echo "$2" | grep -o "qd[0-9]*-nr2" >> "$d/order"
     cal_json 1073741824; }
     calibrate) >/dev/null 2>&1
    # shape pass qd1,qd2,qd4 then THREE round-robins over the candidates --
    # never qd1,qd1,qd1
    tail -9 "$d/order" | tr "\n" " " > "$d/seen"
    grep -qx "qd1-nr2 qd2-nr2 qd4-nr2 qd1-nr2 qd2-nr2 qd4-nr2 qd1-nr2 qd2-nr2 qd4-nr2 " "$d/seen"'
# The shape pass runs SHORT cells and the decision pass full ones: the budget
# goes where the verdict is decided.
t_assert "calibrate: shape cells are short, decision cells are full length" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     CAL_RUNTIME=30; CAL_SHAPE_RUNTIME=7; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac
     case "$2" in (*qd8-nr2.job*) grep "^runtime=" "$d/cal/h1/cal-bw-read-qd8-nr2.job" >> "$d/rt";; esac
     # climbs to qd=8 then flattens: the shape pass stops at qd=32 and
     # nominates qd=8 (the peak) plus its plateau neighbours, so qd=8 is
     # measured in BOTH passes
     q=$(echo "$2" | grep -o "qd[0-9]*" | head -1 | tr -dc 0-9)
     [ "$q" -le 8 ] || q=8
     cal_json $((q * 100)); }
     calibrate) >/dev/null 2>&1
    # the shape cell saw runtime=7, a later decision cell saw runtime=30
    head -1 "$d/rt" | grep -qx "runtime=7" && grep -qx "runtime=30" "$d/rt"'
# CAL_SPLIT re-tests the winning OUTSTANDING io at a different split, and only
# adopts one that beats the pick by more than the decision pass wobbled.
t_assert "calibrate: a split that wins is recorded as numjobs, one that does not is not" bash -c '
    run_split() {   # run_split <split-value> -> the cal.results row
        # named, not $1: inside run_host, $1 is run_host`s own parameter
        sv=$1
        d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
        printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
        (source ./tests/helpers.sh; source ./wekatester
         AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
         TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
         SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
         CAL_SPLIT=1; CAL_SPLIT_PCT=50
         printf "ncpus 4\n" > "$d/probe/h1"
         copy_to_master() { :; }
         run_host() { case "$2" in
             (*mkdir*|*rm\ -rf*|*find*) return 0;;
             (*df*) echo "wekafs 999999999 99999999"; return 0;;
         esac
         case "$2" in
             (*-nj50.job*)  cal_json "$sv";;   # the halved-jobs cell
             (*qd1-nr2.job*) cal_json 1000;;
             (*)             cal_json 900;;
         esac; }
         calibrate) >/dev/null 2>&1
        cat "$d/cal.results"
    }
    # pick is qd=1 at 1000 with a 1% bar; the split runs 2 jobs at qd=2
    # a 3% win is real -> numjobs 2 recorded beside qd=2
    run_split 1030 | grep -qx "h1 2 2 5120M 2 - - - - - - - - - - - -" &&
    # a 0.5% win is inside the bar -> nothing changes, nj stays a dash
    run_split 1005 | grep -qx "h1 1 2 5120M - - - - - - - - - - - - -"'
# One shape for the whole scratch, taken from the workload: a set whose files
# live in subdirectories is measured on files in subdirectories.
# The WIDENING direction of CAL_SPLIT: more jobs than usable cpus at a
# shallower depth. It is the one Frank named (104xqd64 vs 52xqd128), it is
# opt-in because it costs seed capacity, and this is the test that the extra
# capacity is actually seeded and the cell actually runs.
t_assert "calibrate: CAL_SPLIT_PCT above 100 seeds the wider job count and runs its cell" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
     CAL_SPLIT=1; CAL_SPLIT_PCT=200
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() { case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac
     echo "$2" >> "$d/cells"
     case "$2" in
         (*-nj200.job*)  cal_json 1200;;   # 8 jobs at qd=1 beats 4 at qd=2
         (*qd2-nr2.job*) cal_json 1000;;
         (*)             cal_json 900;;
     esac; }
     calibrate) 2>&1 )
    # the pick is qd=2; 200% of numjobs at half the depth is qd=1 with 8 jobs
    grep -q "cal-bw-read-qd1-nr2-nj200.job" "$d/cells" &&
    # the seed covered eight jobs, not four: job 7 has files
    grep -q "^\[seed-7-" "$d/cal/h1/cal-seed.job" &&
    grep -q "^numjobs=8$" "$d/cal/h1/cal-bw-read-qd1-nr2-nj200.job" &&
    case "$out" in
        *"numjobs 8 (200% of available cores: 4) with qd=1 beats the pick by +20.0%"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    grep -qx "h1 1 2 5120M 8 - - - - - - - - - - - -" "$d/cal.results"'
# The shipped verdict against the ladders that motivated it: four runs of the
# same command on one client (iscg001, 2026-08-21/22), replayed through
# cal_verdict itself rather than through an analysis script.
t_assert "cal_verdict: the archived iscg001 ladders all resolve to one setting" bash -c '
    d=$(mktemp -d); mkdir -p "$d/cal"
    # iops-read, qd 1..128, one line per rung per repeat (three identical
    # repeats: the archive holds one sample per rung, and a flat cv is the
    # conservative reading -- it gives the band nothing to hide behind)
    reads="271775 554535 1019299 1612326 2056052 2353459 2358459 2350381
287942 560493 1030853 1652492 2077107 2341663 2331300 2330369
263020 513836 945576 1571938 2059615 2342622 2352450 2331872
265905 514803 965580 1575286 2048699 2317393 2318070 2329622"
    # iops-write, qd 1..256
    writes="268534 525816 971124 1443521 1790673 1944499 2033621 2051369 1883564
270606 538694 964300 1479581 1815145 1945351 2024936 2085846 1895450
238944 473059 881090 1381786 1799140 1906475 2011045 2052253 1877492
247557 487708 867230 1378474 1776357 1939038 2032767 2072587 1871064"
    n=0
    while read -r row; do
        n=$((n + 1)); f="$d/cal/hist-iops-read.h$n"; : > "$f"
        q=1; for v in $row; do
            for r in 1 2 3; do printf "read 2 %s %s\n" "$q" "$v" >> "$f"; done
            q=$((q * 2))
        done
        got=$( (source ./wekatester; WORK_DIR=$d; CAL_HYSTERESIS=0
                cal_verdict "h$n" iops read) | cut -d" " -f1 )
        [ "$got" = 32 ] || { echo "run $n read picked qd=$got, want 32" >&2; exit 1; }
    done <<READLADDERS
$reads
READLADDERS
    [ "$n" = 4 ] || { echo "read: judged $n ladders, want 4" >&2; exit 1; }
    # write: the plateau is qd=64..128 in run 1 and qd=128 alone after that,
    # so a host file already carrying qd=128 keeps it in every run -- which is
    # the whole claim of hysteresis
    n=0
    while read -r row; do
        n=$((n + 1)); f="$d/cal/hist-iops-write.h$n"; : > "$f"
        q=1; for v in $row; do
            for r in 1 2 3; do printf "write 2 %s %s\n" "$q" "$v" >> "$f"; done
            q=$((q * 2))
        done
        # col 29 is iops_w_qd
        printf "h%s\n" "$n" | awk -F"\t" -v OFS="\t" "{ \$1 = \"h$n\"; for (i = 2; i <= 29; i++) if (\$i == \"\") \$i = \"-\"; \$29 = 128; NF = 29; print }" > "$d/targets.final"
        got=$( (source ./wekatester; WORK_DIR=$d; cal_verdict "h$n" iops write) | cut -d" " -f1 )
        [ "$got" = 128 ] || { echo "run $n write picked qd=$got, want 128" >&2; exit 1; }
    done <<WRITELADDERS
$writes
WRITELADDERS
    [ "$n" = 4 ] || { echo "write: judged $n ladders, want 4" >&2; exit 1; }
    true'
# SIZE IS THE ONLY TEST. No marker, no manifest, no per-run bookkeeping: the
# seed lists what is on disk, compares each file against the size this run
# needs, and rewrites exactly the ones that fall short. That is what makes the
# scratch reusable, so it is pinned here for the nested shape too -- with
# subdirectories the listing has to key on the PATH, because h1.cal.0/0 and
# h1.cal.1/0 share a basename and would otherwise mask each other.
t_assert "cal_seed_scratch: sufficiency is the only test, at any shape" bash -c '
    plan() {   # plan <fmt> <find-listing> -> the seed sections planned
        d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/cal/h1"
        printf "ncpus 2\n" > "$d/probe/h1"
        printf "iops read\n" > "$d/cal/seedplan.h1"
        listing=$2
        (source ./wekatester
         WORK_DIR=$d; AUTH_DIR=$d/auth; DIRECTORY=/mnt/weka; CAL_SETTLE=0
         CAL_FMT=$1; ladders="iops read"
         run_host() { case "$2" in
             (*find*) printf "%s" "$listing";;
             (*df*)   echo "wekafs 999999999 99999999";;
         esac; return 0; }
         cal_seed_scratch h1) >/dev/null 2>&1
        [ -f "$d/cal/h1/cal-seed.job" ] || { echo NONE; return 0; }
        got=$(grep "^filename=" "$d/cal/h1/cal-seed.job" | sed "s/^filename=//" | tr "\n" " ")
        printf "%s" "${got:-NONE}"
    }
    # iops read at nr=2 -> two 5G files per job, two jobs
    warm="h1.cal.0/0 5368709120
h1.cal.1/0 5368709120
h1.cal.0/1 5368709120
h1.cal.1/1 5368709120
"
    short="h1.cal.0/0 5368709120
h1.cal.1/0 100
h1.cal.0/1 5368709120
h1.cal.1/1 5368709120
"
    big=$(printf "%s" "$warm" | sed "s/5368709120/10737418240/")
    flat="h1.cal.0.0 5368709120
h1.cal.0.1 5368709120
h1.cal.1.0 5368709120
h1.cal.1.1 5368709120
"
    nested="\$filenum/\$jobnum"
    a=$(plan "$nested" "$warm")   # every file big enough -> nothing to do
    b=$(plan "$nested" "$short")  # one short file -> exactly that one
    c=$(plan "$nested" "$big")    # oversized is still sufficient
    e=$(plan "$nested" "$flat")   # a scratch of another shape matches nothing
    rc=0
    [ "$a" = NONE ]              || { echo "warm planned: [$a]" >&2; rc=1; }
    [ "$b" = "h1.cal.1/0 " ]     || { echo "short planned: [$b]" >&2; rc=1; }
    [ "$c" = NONE ]              || { echo "oversized planned: [$c]" >&2; rc=1; }
    [ "$e" = "h1.cal.0/0:h1.cal.1/0 h1.cal.0/1:h1.cal.1/1 " ] \
                                 || { echo "cross-shape planned: [$e]" >&2; rc=1; }
    exit $rc'
# ONE dataset for calibration and execution: a set whose filename_format can
# address the grid ($filenum AND $jobnum, no $jobname) is measured on the
# workload's own files; anything else falls back to the private scratch.
t_assert "cal_namespace: grid-addressable formats unify, the rest fall back to the scratch" bash -c '
    d=$(mktemp -d); mkdir -p "$d/set" "$d/flat" "$d/named"
    printf "# report iops\n[global]\nfilename_format=\$filenum/\$jobnum\n[a]\nrw=randread\n" > "$d/set/031-a.job"
    printf "# report iops\n[global]\n[a]\nrw=randread\n" > "$d/flat/031-a.job"
    printf "# report iops\n[global]\nfilename_format=\$jobname.\$jobnum.\$filenum\n[a]\nrw=randread\n" > "$d/named/031-a.job"
    a=$( (source ./wekatester; cal_namespace "$d/set") )
    b=$( (source ./wekatester; cal_namespace "$d/flat") )
    c=$( (source ./wekatester; cal_namespace "$d/named") )
    [ "$a" = "unified \$filenum/\$jobnum" ] || { echo "set: $a" >&2; false; }
    [ "$b" = "scratch \$jobnum.\$filenum" ] || { echo "flat: $b" >&2; false; }
    [ "$c" = "scratch \$jobnum.\$filenum" ] || { echo "named: $c" >&2; false; }'
# The unified namespace measures on the exact files the staged jobs run:
# same destination directory, same host-prefixed format, no .wekatester-cal.
t_assert "calibrate: a unified set measures on the workload's own files" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth" "$d/set"
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    out=$( (source ./tests/helpers.sh; source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; CAL_SPLIT=0
     printf "ncpus 4\n" > "$d/probe/h1"
     copy_to_master() { :; }
     run_host() {
         # every command must at least be valid shell: the subdir mkdir once
         # carried a trailing && that only a real bash would have rejected.
         # Plain bash, NOT `command bash`: the command builtin before an
         # external in a backgrounded group exec-replaces the subshell and
         # silently skips everything after it (found the hard way).
         bash -nc "$2" || { echo "MALFORMED COMMAND: $2" >&2; return 1; }
         case "$2" in
         (*mkdir*|*rm\ -rf*|*find*) return 0;;
         (*df*) echo "wekafs 999999999 99999999"; return 0;;
     esac; cal_json 1000; }
     calibrate) 2>&1 )
    case "$out" in
        *"measuring on the workload"*"reads on the shared dataset"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    f=$(ls "$d/cal/h1/"cal-bw-read-qd1*.job | head -1) &&
    grep -q "^directory=/mnt/weka$" "$f" &&
    # read cells measure the fleet-shared dataset, not per-host files
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$f" &&
    # and the seed lays out exactly those shared names, densely, at 5G
    grep -q "^filename=shared.0/0:shared.1/0$" "$d/cal/h1/cal-seed.job" &&
    grep -q "^directory=/mnt/weka$" "$d/cal/h1/cal-seed.job" &&
    grep -q "^filesize=5120M$" "$d/cal/h1/cal-seed.job"'
t_assert "cal_scratch_dirs: every directory the names imply, once" bash -c '
    out=$( (source ./wekatester; cal_scratch_dirs h1 "\$filenum/\$jobnum" 3 1) | tr "\n" " " )
    [ "$out" = "h1.cal.0 h1.cal.1 " ] || { echo "$out" >&2; false; }
    out=$( (source ./wekatester; cal_scratch_dirs h1 "\$jobnum.\$filenum" 3 1) )
    [ -z "$out" ] || { echo "$out" >&2; false; }'
# One rule for (cpus, numjobs), used by the rungs, the seed and the staged
# jobs alike: 52 jobs in a 46-cpu mask is the bug this prevents.
t_assert "cal_cpus_nj: the effective mask and one job per cpu in it" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    printf "ncpus 8\nweka_allowed 0\nweka_allowed 1\n" > "$d/probe/h1"
    out=$( (source ./wekatester; WORK_DIR=$d; AUTH_DIR=$d/auth; cal_cpus_nj h1 bw read) )
    [ "$out" = "2,3,4,5,6,7 6" ] || { echo "derived: $out" >&2; false; }
    printf "4-7\n" > "$d/auth/h1.cpus"
    out=$( (source ./wekatester; WORK_DIR=$d; AUTH_DIR=$d/auth; cal_cpus_nj h1 bw read) )
    [ "$out" = "4-7 4" ] || { echo "auth: $out" >&2; false; }
    out=$( (source ./wekatester; WORK_DIR=$d; AUTH_DIR=$d/auth; cal_cpus_nj h1 lat read) )
    [ "$out" = "4-7 1" ] || { echo "lat: $out" >&2; false; }'
t_assert "cal_cpus_nj: nj wider than the mask -- a multiple is a note, a stray is a warning" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    printf "ncpus 8\n" > "$d/probe/h1"
    printf "4-7\n" > "$d/auth/h1.cpus"
    row=h1; for i in $(seq 2 29); do row="$row	-"; done
    # 52 on 4 usable cpus is an exact multiple -- the shape a BRUTAL_NJ
    # winner records -- so it is a note, and the value stands
    printf "%s\n" "$row" | awk -F"\t" -v OFS="\t" "{ \$6 = 52; print }" > "$d/targets.final"
    err=$( (source ./wekatester; WORK_DIR=$d; AUTH_DIR=$d/auth
            cal_cpus_nj h1 bw read) 2>&1 >/dev/null )
    out=$( (source ./wekatester; WORK_DIR=$d; AUTH_DIR=$d/auth
            cal_cpus_nj h1 bw read) 2>/dev/null )
    [ "$out" = "4-7 52" ] || { echo "got: $out" >&2; false; }
    case "$err" in (*"note: h1:"*"runs 13 jobs per cpu (4 usable)"*) true;; (*) echo "$err" >&2; false;; esac
    # 6 on 4 is not a multiple of anything deliberate: warned, still honoured
    printf "%s\n" "$row" | awk -F"\t" -v OFS="\t" "{ \$6 = 6; print }" > "$d/targets.final"
    err=$( (source ./wekatester; WORK_DIR=$d; AUTH_DIR=$d/auth
            cal_cpus_nj h1 bw read) 2>&1 >/dev/null )
    out=$( (source ./wekatester; WORK_DIR=$d; AUTH_DIR=$d/auth
            cal_cpus_nj h1 bw read) 2>/dev/null )
    [ "$out" = "4-7 6" ] || { echo "got: $out" >&2; false; }
    case "$err" in (*"WARNING"*"exceeds its 4 usable cpu(s)"*"double-book 2"*) true;; (*) echo "$err" >&2; false;; esac'

t_assert "parse: -x/--duration takes whole seconds, rejects junk" bash -c '
    (source ./wekatester; parse_args -x 60 h1;         [ "$DURATION" = 60 ]) &&
    (source ./wekatester; parse_args -x45 h1;          [ "$DURATION" = 45 ]) &&
    (source ./wekatester; parse_args --duration=90 h1; [ "$DURATION" = 90 ]) &&
    (source ./wekatester; parse_args -X 30 h1;         [ "$DURATION" = 30 ]) &&
    ! (source ./wekatester; parse_args -x 0 h1)  2>/dev/null;
    a=$?; ! (source ./wekatester; parse_args -x abc h1) 2>/dev/null; b=$?
    [ "$a" -eq 0 ] && [ "$b" -eq 0 ]'
t_assert "-x stamps runtime+time_based on measured variants, never the layout" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka; DURATION=77
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles) >/dev/null || exit 1
    v="$d/target/localhost/011-smoke-readbw.job"
    l="$d/target/localhost/000-wekatester-layout.job"
    grep -q "^runtime=77$" "$v" && grep -q "^time_based=1$" "$v" &&
    ! grep -q "^runtime=77$" "$l"'
# A COMPLETE recorded tuple (fs, nr, qd) for a direction skips its ladder; a
# partial one does not, because the ladder records the three together and
# half of them is not a geometry anyone measured.
t_assert "calibrate: a complete host-file tuple skips that ladder, a partial one does not" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/set"
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    run_cal() {   # run_cal "<col>=<val> ..." -> 29-column targets.final row
        { printf "h1"
          for i in $(seq 2 29); do
              v="-"
              for kv in $1; do [ "${kv%%=*}" = "$i" ] && v=${kv#*=}; done
              printf "\t%s" "$v"
          done; printf "\n"; } > "$d/targets.final"
        rm -f "$d/cal.results"
        (source ./wekatester
         AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
         TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
         SET_DIR_OVERRIDE=$d/set
         copy_to_master() { :; }
         run_host() { return 0; }
         calibrate) 2>&1
    }
    # bw_r fs/nr/qd (cols 7-9) all present -> complete, skipped
    out=$(run_cal "7=1G 8=2 9=8")
    case "$out" in *"already carries bw read geometry -- reusing"*) true;; *) echo "$out" >&2; false;; esac &&
    [ ! -s "$d/cal.results" ] &&
    # qd alone -> incomplete, must NOT be treated as cached
    out=$(run_cal "9=8")
    case "$out" in
        *"already carries bw read geometry -- reusing"*) echo "$out" >&2; false;;
        *) true;;
    esac'
t_assert "calibrate: no-op below cal" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     AUTO_LEVEL=max; WORK_DIR=$d
     run_host() { echo "TOUCHED" >> "$d/oplog"; }
     calibrate)
    [ ! -f "$d/oplog" ]'
t_assert "apply_cal_results: fills only dashes, operator values survive, synthesizes when no host file" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d
     # h1: bw_r measured (qd 4, nr 8, fs 64M) and iops_r measured (32/2/256M)
     # h2: only bw_r measured (8/1/2048M). Every nj is a dash: no split won.
     printf "h1 4 8 64M - - - - - 32 2 256M - - - - -\nh2 8 1 2048M - - - - - - - - - - - - -\n" > "$d/cal.results"
     # h1 already carries an operator iops_r_qd=64 (col 25): fill must keep it
     { printf "h1"; for i in $(seq 2 29); do
          case $i in (25) printf "\t64";; (*) printf "\t-";; esac
       done; printf "\n"; } > "$d/targets.final"
     apply_cal_results)
    a=$(awk -F"\t" "\$1==\"h1\" {print \$9, \$8, \$7, \$25, \$24, \$23}" "$d/targets.final")
    b=$(awk -F"\t" "\$1==\"h2\" {print \$9, \$8, \$7}" "$d/targets.final")
    [ "$a" = "4 8 64M 64 2 256M" ] && [ "$b" = "8 1 2048M" ] || { echo "a=$a b=$b" >&2; false; }
    (source ./wekatester
     WORK_DIR=$d; rm -f "$d/targets.final"
     printf "h3 16 2 1024M - - - - - - - - - - - - -\n" > "$d/cal.results"
     apply_cal_results)
    c=$(awk -F"\t" "\$1==\"h3\" {print NF, \$9}" "$d/targets.final")
    [ "$c" = "29 16" ]'

# --- sysinfo capture: per-host box context in every bundle ---
t_assert "sysinfo: one file per item per host, missing tools say so" bash -c '
    d=$(mktemp -d); mkdir -p "$d/out"
    (source ./wekatester
     WORK_DIR=$d; RUN_DIR=$d/out; HOSTS=(h1)
     run_host() { printf "%s\n" \
         "=== WEKATESTER_SYSINFO cmdline ===" "BOOT_IMAGE=vmlinuz isolcpus=4-55" \
         "=== WEKATESTER_SYSINFO mounts ===" "wekafs /mnt/weka wekafs rw 0 0" \
         "=== WEKATESTER_SYSINFO uname ===" "Linux isca224 4.18.0" \
         "=== WEKATESTER_SYSINFO lscpu ===" "CPU(s): 56" \
         "=== WEKATESTER_SYSINFO lspci ===" "lspci: not available" \
         "=== WEKATESTER_SYSINFO free ===" "Mem: 512G" \
         "=== WEKATESTER_SYSINFO fio ===" "fio-3.28"; }
     snapshot_sysinfo)
    grep -q "isolcpus=4-55" "$d/out/sysinfo/h1/cmdline" &&
    grep -q "wekafs" "$d/out/sysinfo/h1/mounts" &&
    grep -q "Linux isca224" "$d/out/sysinfo/h1/uname" &&
    grep -q "CPU(s): 56" "$d/out/sysinfo/h1/lscpu" &&
    grep -q "not available" "$d/out/sysinfo/h1/lspci" &&
    grep -q "Mem: 512G" "$d/out/sysinfo/h1/free" &&
    grep -q "fio-3.28" "$d/out/sysinfo/h1/fio"'

t_assert "pressure: start and end land as labeled files, end pulls the sar slice" bash -c '
    d=$(mktemp -d); mkdir -p "$d/out"
    (source ./wekatester
     WORK_DIR=$d; RUN_DIR=$d/out; HOSTS=(h1); RUN_STAMP=20260820-003501
     run_host() { case "$2" in
         (*sar*) printf "%s\n" \
             "=== WEKATESTER_SYSINFO pressure-cpu ===" "some avg10=0.15" \
             "=== WEKATESTER_SYSINFO loadavg ===" "1.20 1.10 0.90" \
             "=== WEKATESTER_SYSINFO sar ===" "00:35:01 CPU %user";;
         (*) printf "%s\n" \
             "=== WEKATESTER_SYSINFO pressure-cpu ===" "some avg10=0.05" \
             "=== WEKATESTER_SYSINFO loadavg ===" "0.50 0.40 0.30";;
     esac; }
     snapshot_pressure start
     snapshot_pressure end)
    grep -q "avg10=0.05" "$d/out/sysinfo/h1/pressure-cpu-start" &&
    grep -q "0.50 0.40" "$d/out/sysinfo/h1/loadavg-start" &&
    grep -q "avg10=0.15" "$d/out/sysinfo/h1/pressure-cpu-end" &&
    grep -q "00:35:01 CPU" "$d/out/sysinfo/h1/sar-end"'
t_assert "pressure: no run dir means no capture, no error" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; RUN_DIR=""; HOSTS=(h1)
     run_host() { echo TOUCHED >> "$d/oplog"; }
     snapshot_pressure start)
    [ ! -f "$d/oplog" ]'

# --- -h documents every option the parser accepts ---
# Drift here is silent: an option added to parse_args works but is invisible,
# which is how -x/--duration shipped undocumented in the synopsis.
t_assert "help: every parsed option appears in -h as its own token" bash -c '
    # Word-boundary matching, not substring: "-c" must not pass because
    # "--ignore-capacity" contains it, and a short option must not pass on
    # the strength of its long form alone.
    h=$(./wekatester -h)
    miss=""
    for o in -d -w -f -s -o -e -p -t -x -r -n -g -u -a -i -C -v -h \
             --output --engine --password --targets --duration --unlink \
             --auto --ignore-capacity --identity --customize --version --help; do
        printf "%s\n" "$h" | grep -qE -- "(^|[[:space:][(])${o}([^-A-Za-z0-9]|$)" ||
            miss="$miss $o"
    done
    [ -z "$miss" ] || { echo "not documented in -h:$miss" >&2; false; }'
t_assert "help: --help is accepted and prints the same text as -h" bash -c '
    diff <(./wekatester -h) <(./wekatester --help)'

# --- host identity: the file names the machine, not "localhost" -------------
# "localhost" identifies nothing and collides the moment a host file is shared,
# so a row automation ADDS carries <short hostname>/<machine-id>. Internally
# the host stays an address: no slash ever reaches a path, a --client=, or a
# data-file prefix.
t_assert "identity: an auto-added local row is named for the machine, not localhost" bash -c '
    d=$(mktemp -d); mkdir -p "$d/ident" "$d/jobs/localhost"
    echo "deadbeefcafe0000deadbeefcafe0000" > "$d/ident/localhost.id"
    printf "# report bandwidth\n[global]\nioengine=libaio\nnumjobs=4\nfilesize=1G\ndirectory=/mnt/weka\n[a]\nrw=read\niodepth=8\n" > "$d/jobs/localhost/011-bw.job"
    (source ./wekatester
     hostname() { echo testbox; }
     LOCAL_MODE=1; HOSTS=(localhost); WORK_DIR=$d; AUTO_LEVEL=cal; REGEN_LAYOUT=0
     TARGETS_FILE=$d/hostlist.csv
     write_targets_template "$d/hostlist.csv"
     writeback_targets) >/dev/null 2>&1
    grep -q "^testbox/deadbeefcafe0000deadbeefcafe0000," "$d/hostlist.csv" ||
        { echo "--- host file ---"; grep -av "^#" "$d/hostlist.csv" >&2; false; }'
# A row a person wrote keeps their spelling; automation only names what it adds.
t_assert "identity: an existing row keeps the operator spelling on update" bash -c '
    d=$(mktemp -d); mkdir -p "$d/ident" "$d/jobs/localhost"
    echo "deadbeefcafe0000deadbeefcafe0000" > "$d/ident/localhost.id"
    printf "# report bandwidth\n[global]\nioengine=libaio\nnumjobs=4\nfilesize=1G\ndirectory=/mnt/weka\n[a]\nrw=read\niodepth=8\n" > "$d/jobs/localhost/011-bw.job"
    (source ./wekatester
     hostname() { echo testbox; }
     LOCAL_MODE=1; HOSTS=(localhost); WORK_DIR=$d; AUTO_LEVEL=cal; REGEN_LAYOUT=0
     TARGETS_FILE=$d/hostlist.csv
     write_targets_template "$d/hostlist.csv"
     printf "localhost,,,,/mnt/weka,,,\n" >> "$d/hostlist.csv"
     writeback_targets) >/dev/null 2>&1
    grep -q "^localhost," "$d/hostlist.csv" &&
    ! grep -q "^testbox/" "$d/hostlist.csv"'
# Reading it back: the id is stripped and the name maps to the address in use.
t_assert "identity: a name/machine-id row resolves to the address the run uses" bash -c '
    d=$(mktemp -d); mkdir -p "$d/ident"
    echo "deadbeefcafe0000deadbeefcafe0000" > "$d/ident/localhost.id"
    printf "host,user_login,ioengine,allowed_cpus,destination_folder,bandwidth,latency,iops\n" > "$d/hl.csv"
    printf "testbox/deadbeefcafe0000deadbeefcafe0000,bob,libaio,,/mnt/other,,,\n" >> "$d/hl.csv"
    out=$( (source ./wekatester
      hostname() { echo testbox; }
      LOCAL_MODE=1; WORK_DIR=$d
      resolve_targets phase1 "$d/hl.csv" - - - localhost) 2>&1 )
    # first field is the address, and the row was applied to it
    case "$out" in
        localhost*bob*libaio*/mnt/other*) true;;
        *) echo "$out" >&2; false;;
    esac'

t_assert "identity: two spellings of one machine are a legible duplicate" bash -c '
    d=$(mktemp -d)
    printf "host,user_login,ioengine,allowed_cpus,destination_folder,bandwidth,latency,iops\n" > "$d/hl.csv"
    printf "node1/aaaa,,,,/mnt/weka,,,\nnode1/bbbb,,,,/mnt/weka,,,\n" >> "$d/hl.csv"
    err=$( (source ./wekatester; WORK_DIR=$d
            resolve_targets phase1 "$d/hl.csv" - - - node1) 2>&1 >/dev/null )
    case "$err" in
        *"both resolve to"*"node1"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# --- README stays in sync with the real help output ---
t_assert "README Usage block matches ./wekatester -h byte for byte" bash -c '
    source ./tests/helpers.sh
    diff <(./wekatester -h) <(readme_usage_block README.md)'

echo; echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
