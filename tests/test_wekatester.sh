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
    grep -q "^filesize=1G$" "$v" && grep -q "wt-small" "$v" &&
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
    # ws = WS_FLOOR = 8GiB, 5 usable cores -> nrfiles = max(2, ceil(8/5)) = 2
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
    # bw: 5 jobs x 1 file x 10G = 50GiB; iops (wt-small): 5 jobs x 2 files x 1G
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
# The calibration engine does not exist yet (tasks 3-6), so cal/hybrid must
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
    grep -q "^filename_format=wt-small.\$jobnum.\$filenum$" "$v" &&
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
    # nrfiles = 2 at the 8GiB floor, so size= is rewritten to 2 x 1G
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
t_assert "tuner: pristine layout at max is re-derived per host (covers wt-small)" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\ndirectory=/orig\n[io]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -q "re-derived by wekatester auto\[max\]" "$v" &&
    grep -q "^filename_format=wt-small.\$jobnum.\$filenum$" "$v" &&
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
        *"unknown auto level: bogus (safe|max|cal|hybrid)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "parse: -a cal, -Ahybrid and --auto=cal set the level; cal_mode true only for cal/hybrid" bash -c '
    (source ./wekatester; parse_args -a cal h1;    [ "$AUTO_LEVEL" = cal ]) &&
    (source ./wekatester; parse_args -Ahybrid h1;  [ "$AUTO_LEVEL" = hybrid ]) &&
    (source ./wekatester; parse_args --auto=cal h1; [ "$AUTO_LEVEL" = cal ]) &&
    err=$( (source ./wekatester; parse_args -acalx h1) 2>&1 >/dev/null )
    case "$err" in
        *"unknown auto level: calx (safe|max|cal|hybrid)"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    (source ./wekatester; AUTO_LEVEL=cal;    cal_mode) &&
    (source ./wekatester; AUTO_LEVEL=hybrid; cal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL=safe; cal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL=max;  cal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL="";   cal_mode)'

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
rw=randread')" = "bw read|iops read|iops write|"
t_assert "cal_required: a bw-write-only set needs one ladder" \
    test "$(cal_set '# report bandwidth
[bw]
rw=write')" = "bw write|"
t_assert "cal_required: a latency-only set needs nothing" \
    test "$(cal_set '# report latency
[lat]
rw=randread')" = ""
# latency anywhere in the directive wins, exactly as the tuner classifies it:
# such a file is measured at qd=1, so it asks for no ladder.
t_assert "cal_required: '# report iops latency' contributes nothing" \
    test "$(cal_set '# report iops latency
[io]
rw=randwrite')" = ""
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
    [ "$(r default)"    = "bw read|bw write|iops read|iops write|" ] &&
    [ "$(r mixed)"      = "bw read|bw write|iops read|iops write|" ] &&
    [ "$(r smoke)"      = "bw read|" ] &&
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
# isolcpus: the isolated set minus weka's own is what the box set aside for
# this work, exactly as the tuner narrows its cpus_allowed.
t_assert "usable_cores: isolcpus narrows to the isolated set minus weka" \
    test "$(uc 'ncpus 8
isolated 4-7
weka_allowed 4
weka_allowed 0
weka_allowed 1')" = 3
t_assert "usable_cores: weka owning every isolated cpu falls back to housekeeping" \
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
numjobs=5
iodepth=8
time_based=1
runtime=10
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
t_assert "stage_cal_step: no recorded cpus means neither cpus line" \
    cal_nolines "$CALFIX/cal/h2/cal-bw-read-qd8.job" '^cpus_allowed' '^cpus_allowed_policy'
t_assert "stage_cal_step: the per-host filename_format is host-prefixed and jobnum-keyed" \
    cal_lines "$CALFIX/cal/h2/cal-bw-read-qd8.job" 'filename_format=h2.cal.$jobnum.$filenum'
t_assert "stage_cal_step: a write step creates its files on open" bash -c '
    cal_staged bw write 2 h1 &&
    cal_lines "$CALFIX/cal/h1/cal-bw-write-qd2.job" \
        "[cal-bw-write]" rw=write create_on_open=1 bs=1Mi filesize=1G iodepth=2'
t_assert "stage_cal_step: an iops step is 4k random IO over small files" bash -c '
    cal_staged iops read 32 h1 &&
    cal_lines "$CALFIX/cal/h1/cal-iops-read-qd32.job" \
        "[cal-iops-read]" rw=randread bs=4k filesize=256M nrfiles=2 iodepth=32 &&
    cal_nolines "$CALFIX/cal/h1/cal-iops-read-qd32.job" "^create"'
t_assert "stage_cal_step: an iops write step is randwrite" bash -c '
    cal_staged iops write 1 h2 &&
    cal_lines "$CALFIX/cal/h2/cal-iops-write-qd1.job" \
        rw=randwrite create_on_open=1 bs=4k filesize=256M'
t_assert "stage_cal_step: an unknown ladder type dies" \
    cal_step_fails "unknown ladder type" bogus read 8 h1
t_assert "stage_cal_step: an unknown direction dies" \
    cal_step_fails "unknown ladder direction" bw sideways 8 h1
t_assert "stage_cal_step: a non-numeric iodepth dies" \
    cal_step_fails "iodepth" bw read qd8 h1
t_assert "stage_cal_step: no hosts is a caller bug, not a silent no-op" \
    cal_step_fails "no hosts" bw read 8

# --- cal_gains: per-client gain between two ladder steps ---
# Grammar consumed verbatim by the orchestrator: "<host> <value> <gain_pct>",
# one line per client in the CURRENT step, sorted. Value = read+write of the
# LAST entry per host (the section that just ran, same rule as
# check_fio_errors and the summarizer); the "All clients" aggregate and the
# create-phase entries are not clients and must never be counted.
# rc is pinned BEFORE the output is transformed: piping cal_gains into tr
# would discard its status and a python traceback would read as valid output.
CG=$(mktemp -d)
cal_json_fixture "$CG/prev.json" \
    'h1:1073741824:1000.0:0:0.0' 'h2:2000000000:2000.0:147483648:500.0'
cal_json_fixture "$CG/cur.json" \
    'h1:1610612736:1100.0:0:0.0' 'h2:2133382994:2400.0:100000000:600.0'
cal_g() {   # cal_g <prev|-> <cur> <bw|iops>; prints the lines, newlines as |
    local out rc
    out=$( (source ./wekatester; cal_gains "$1" "$2" "$3") ); rc=$?
    [ "$rc" -eq 0 ] || { echo "ERROR: cal_gains exited $rc"; return "$rc"; }
    [ -n "$out" ] || return 0
    printf '%s\n' "$out" | tr '\n' '|'
}
cal_g_fails() {   # cal_g_fails <pattern> <cal_gains args>...
    local pat=$1 err rc; shift
    err=$( (source ./wekatester; cal_gains "$@") 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "cal_gains $* unexpectedly succeeded" >&2; return 1; }
    case "$err" in (*$pat*) return 0 ;; esac
    echo "$err" >&2; return 1
}
export CG
export -f cal_g cal_g_fails cal_json_fixture
# First step: nothing to gain over, so every client reports the full 100 --
# and the values prove read+write are summed from the LAST entry only
# (h2 = 2133382994 + 100000000; the create entry's 99999999999 would show).
t_assert "cal_gains: the first step gains 100 and sums read+write per client" \
    test "$(cal_g - "$CG/cur.json" bw)" = "h1 1610612736 100|h2 2233382994 100|"
# 1.0 -> 1.5 GiB/s is a 50% step; h2's 4% is the freeze signal Task 5 acts on.
t_assert "cal_gains: bw gains are percent over the previous step, per client" \
    test "$(cal_g "$CG/prev.json" "$CG/cur.json" bw)" = "h1 1610612736 50|h2 2233382994 4|"
# Same two files, iops mode: different metric, different answer. h1's exact
# 10% is the boundary case -- it must survive as 10, not round to 9 or 11.
t_assert "cal_gains: iops mode counts ios, not bytes" \
    test "$(cal_g "$CG/prev.json" "$CG/cur.json" iops)" = "h1 1100 10|h2 3000 20|"
t_assert "cal_gains: fio's log text before the JSON is skipped" bash -c '
    { printf "client <h1>: connected\nfio: terse output\n"; cat "'"$CG"'/cur.json"; } \
        > "'"$CG"'/noisy.json"
    test "$(cal_g - "'"$CG"'/noisy.json" bw)" = "h1 1610612736 100|h2 2233382994 100|"'
# A client that moved nothing last step has no baseline to gain over, so any
# measurement at all is the whole gain; still nothing measured is no gain.
t_assert "cal_gains: a zero previous step gains 100, zero-to-zero gains 0" bash -c '
    cal_json_fixture "'"$CG"'/zero.json" "h1:0:0.0:0:0.0" "h2:0:0.0:0:0.0"
    [ "$(cal_g "'"$CG"'/zero.json" "'"$CG"'/cur.json" bw)" = "h1 1610612736 100|h2 2233382994 100|" ] &&
    [ "$(cal_g "'"$CG"'/zero.json" "'"$CG"'/zero.json" bw)" = "h1 0 0|h2 0 0|" ]'
# A ladder step can regress once the cluster is saturated. That is real data,
# reported as it is -- and it freezes the knee just as a small gain does.
t_assert "cal_gains: a slower step reports a negative gain" \
    test "$(cal_g "$CG/cur.json" "$CG/prev.json" bw)" = "h1 1073741824 -34|h2 2147483648 -4|"
# A client that only appears in the current step has no previous value: it is
# on its first measured step, so it gains 100 rather than crashing the parse.
t_assert "cal_gains: a client absent from the previous step is on its first step" bash -c '
    cal_json_fixture "'"$CG"'/one.json" "h1:1073741824:1000.0:0:0.0"
    test "$(cal_g "'"$CG"'/one.json" "'"$CG"'/cur.json" bw)" = "h1 1610612736 50|h2 2233382994 100|"'
t_assert "cal_gains: unparsable output is an error naming the file" bash -c '
    printf "no json here at all\n" > "'"$CG"'/bad.json"
    cal_g_fails bad.json - "'"$CG"'/bad.json" bw'
t_assert "cal_gains: a results file with no client stats is an error" bash -c '
    printf "{\"client_stats\": [{\"jobname\": \"All clients\"}]}\n" > "'"$CG"'/agg.json"
    cal_g_fails agg.json - "'"$CG"'/agg.json" bw'
t_assert "cal_gains: an unknown mode is an error" \
    cal_g_fails "unknown mode" - "$CG/cur.json" latency
t_assert "cal_gains: a missing previous file is an error, not a silent 100" \
    cal_g_fails nosuch "$CG/nosuch.json" "$CG/cur.json" bw

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
t_assert "-e stamps every staged variant, and the rebuild variant inherits it" bash -c '
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
    grep -q "^ioengine=xyzeng$" "$d/target/localhost/000-wekatester-relayout.job"'

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
t_assert "stamping: staged variants and the rebuild variant carry it end to end" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles) >/dev/null || exit 1
    v="$d/target/localhost/011-smoke-readbw.job"
    r="$d/target/localhost/000-wekatester-relayout.job"
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

# --- partial-layout healing: rebuild variant + completion markers ---
# fio ftruncates a file to FULL SIZE before writing its layout, so an
# interrupted layout leaves size-complete holes that create_only trusts
# forever (verified against fio 3.42). The rebuild variant writes through.
t_assert "rebuild variant: rw=write + create_on_open replace create_only, geometry kept" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1)
     mkdir -p "$d/jobs/h1" "$SET_DIR"
     printf "%s\n" "# wekatester-layout: generated sha256=abc" "[global]" "directory=/mnt/weka" \
         "[layout-1]" "create_only=1" "blocksize=1Mi" "filesize=10G" "numjobs=16" \
         > "$d/jobs/h1/000-wekatester-layout.job"
     cp "$d/jobs/h1/000-wekatester-layout.job" "$SET_DIR/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     stage_rebuild_variants
     r=$d/jobs/h1/000-wekatester-relayout.job
     # same sections, same geometry; only the layout mode changes (the
     # directory grid comes from ensure_layout_dirs, never from fio)
     grep -q "^\[layout-1\]$" "$r" && ! grep -q "\.dirs" "$r" &&
     grep -q "^rw=write$" "$r" && grep -q "^create_on_open=1$" "$r" &&
     ! grep -q "^create_only=1$" "$r" &&
     grep -q "^filesize=10G$" "$r" && grep -q "^blocksize=1Mi$" "$r" &&
     ! grep -q "wekatester-layout: generated" "$r" &&
     [ "$(grep -c "^numjobs=16$" "$r")" -eq 1 ])'
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
t_assert "geometry hash: host order and cpu steering do not matter, the grid does" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; mkdir -p "$d/jobs/h1" "$d/jobs/h2"
     printf "[global]\ncpus_allowed=0-3\n[l]\nfilesize=10G\nnumjobs=16\n" > "$d/jobs/h1/000-wekatester-layout.job"
     printf "[global]\ncpus_allowed=0-7\n[l]\nfilesize=10G\nnumjobs=8\n"  > "$d/jobs/h2/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     HOSTS=(h1 h2); a=$(layout_geometry_hash)
     HOSTS=(h2 h1); b=$(layout_geometry_hash)
     sed -i.bak "s/cpus_allowed=0-3/cpus_allowed=4-9/" "$d/jobs/h1/000-wekatester-layout.job"
     HOSTS=(h1 h2); c=$(layout_geometry_hash)
     sed -i.bak "s/numjobs=16/numjobs=32/" "$d/jobs/h1/000-wekatester-layout.job"
     HOSTS=(h1 h2); e=$(layout_geometry_hash)
     [ "$a" = "$b" ] && [ "$a" = "$c" ] && [ "$a" != "$e" ])'
run_jobs_marker_case() {   # run_jobs_marker_case <marker-present-rc>; prints output, oplog in $d/oplog
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; RUN_DIR=$d/out; HOSTS=(h1); MASTER=h1
     FIO_BIN=fio; TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka
     mkdir -p "$d/jobs/h1" "$SET_DIR" "$RUN_DIR"
     printf "[global]\n[l]\nfilesize=10G\nnumjobs=16\n" > "$d/jobs/h1/000-wekatester-layout.job"
     printf "[global]\n[l]\nrw=write\nfilesize=10G\nnumjobs=16\n" > "$d/jobs/h1/000-wekatester-relayout.job"
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     printf "{ \"client_stats\": [ { \"jobname\": \"l\", \"hostname\": \"h1\", \"error\": 0, \"read\": {\"total_ios\":0}, \"write\": {\"total_ios\":0} } ] }\n" > "$d/r.json"
     JOBFILES=(000-wekatester-layout.job)
     MARKER_RC=$1
     run_host() { case "$2" in
         ("[ -f "*) return "$MARKER_RC";;
         ("rm -f "*) echo "RM: $2" >> "$WORK_DIR/oplog";;
         (*printf*)  echo "MARK: $2" >> "$WORK_DIR/oplog";;
         (*)         echo "FIO: $2" >> "$WORK_DIR/oplog"; cat "$WORK_DIR/r.json";;
     esac; }
     run_jobs) 2>&1
    echo "OPLOG_DIR=$d"
}
export -f run_jobs_marker_case
t_assert "layout marker present: create_only path, marker cleared then rewritten" bash -c '
    source ./tests/helpers.sh
    out=$(run_jobs_marker_case 0)
    d=${out##*OPLOG_DIR=}
    case "$out" in *"rebuilding every file"*) echo "$out" >&2; false;; *) true;; esac &&
    grep -q "FIO: .*000-wekatester-layout.job" "$d/oplog" &&
    ! grep -q "relayout" "$d/oplog" &&
    grep -q "^RM: rm -f ./mnt/weka/.wekatester-layout-" "$d/oplog" &&
    mline=$(grep -n "^MARK:" "$d/oplog" | head -1 | cut -d: -f1) &&
    fline=$(grep -n "^FIO:" "$d/oplog" | head -1 | cut -d: -f1) &&
    [ "$mline" -gt "$fline" ]'
t_assert "layout marker missing: rebuild variant runs and says why" bash -c '
    source ./tests/helpers.sh
    out=$(run_jobs_marker_case 1)
    d=${out##*OPLOG_DIR=}
    case "$out" in
        *"no completion marker"*"rebuilding every file with full writes"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    grep -q "FIO: .*000-wekatester-relayout.job" "$d/oplog" &&
    grep -q "^MARK: " "$d/oplog"'
t_assert "unlink job removes its geometry marker after the grid is gone" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; RUN_DIR=$d/out; HOSTS=(h1); MASTER=h1
     FIO_BIN=fio; TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka
     mkdir -p "$d/jobs/h1" "$SET_DIR" "$RUN_DIR"
     printf "[global]\n[l]\nfilesize=10G\nnumjobs=16\n" > "$d/jobs/h1/000-wekatester-layout.job"
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     printf "{ \"client_stats\": [ { \"jobname\": \"l\", \"hostname\": \"h1\", \"error\": 0, \"read\": {\"total_ios\":0}, \"write\": {\"total_ios\":0} } ] }\n" > "$d/r.json"
     JOBFILES=(000-wekatester-layout.job 999-wekatester-unlink.job)
     run_host() { case "$2" in
         ("[ -f "*) return 0;;
         ("rm -f "*) echo "RM: $2" >> "$WORK_DIR/oplog";;
         (*printf*)  echo "MARK: $2" >> "$WORK_DIR/oplog";;
         (*)         cat "$WORK_DIR/r.json";;
     esac; }
     run_jobs >/dev/null
     # layout branch: clear + rewrite (1 RM, 1 MARK); unlink branch: 1 more RM
     [ "$(grep -c "^RM: " "$WORK_DIR/oplog")" -eq 2 ] &&
     [ "$(grep -c "^MARK: " "$WORK_DIR/oplog")" -eq 1 ])'

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
    printf "h1,,,,,bandwidth:12/10G//8,latency:1///1,4/1G/56/64\n" > "$f"
    out=$(rt phase1 "$f" - - - h1)
    [ "$out" = "h1	-	-	-	-	12	10G	-	8	1	-	-	1	4	1G	56	64" ] ||
        { echo "$out" >&2; false; }'
t_assert "targets: a wrong type: prefix in a geometry column is fatal" bash -c '
    f=$(mktemp)
    printf "h1,,,,,iops:4///,,\n" > "$f"
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
     WEKATESTER_ENGINE_TEST_TIMEOUT=2 test_engines) >/dev/null 2>&1
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
        sleep 300 &
        test_engines >/dev/null 2>&1
        echo TE_RETURNED" | grep -q TE_RETURNED'
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
        *"requested cpus_allowed: 4-7"*"current taskset:       0-3"*"weka dedicated cores:  8,9"*"outside the current taskset"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "pinning: overlap with weka cores dies without priv, warns and proceeds with it" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "taskset 0-15\nweka_allowed 8\nweka_allowed 10\nweka_allowed 0-15\n" > "$d/probe/h1"
        printf "h1\t-\t-\t8,10\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >/dev/null )
    case "$err" in (*"overlap weka'\''s cores and no passwordless"*) true;; (*) echo "$err" >&2; exit 1;; esac
    err2=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "taskset 0-15\nweka_allowed 8\nweka_allowed 10\npriv sudo\n" > "$d/probe/h1"
        printf "h1\t-\t-\t8,10\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >/dev/null )
    case "$err2" in (*"WARNING"*"overlap weka'\''s dedicated cores (8,10)"*"proceeding under sudo"*) true;; (*) echo "$err2" >&2; exit 1;; esac
    [ "$(cat "$d/auth/h1.priv")" = sudo ] && [ "$(cat "$d/auth/h1.cpus")" = "8,10" ]'
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
     printf "h1\t-\tpsync\t-\t/mnt/one\t-\t-\t-\t-\t-\t-\t-\t-\t4\t1G\t2\t16\nh2\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\n" > "$d/targets.final"
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
    printf "h1\t-\tpsync\t2,4\t/mnt/pin\t3\t2G\t-\t9\t-\t-\t-\t-\t-\t-\t-\t-\n" > "$FIX/targets.final"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1
    v1="$FIX/jobs/h1/011-bw.job"; v2="$FIX/jobs/h2/011-bw.job"
    grep -q "^directory=/mnt/pin$" "$v1" && grep -q "^directory=/mnt/weka$" "$v2" &&
    grep -q "^cpus_allowed=2,4$" "$v1" &&
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
    printf "# report iops\ncpus_allowed=0-3\ndirectory=/mnt/w\nioengine=libaio\nnumjobs=4\nfilesize=1G\nnrfiles=8\niodepth=32\n" > "$d/jobs/h1/031-i.job"
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
    tail -1 "$f" | grep -q "^h1,ubuntu,psync,0-3,/mnt/w,,,4/1G/8/32" &&
    (source ./wekatester; resolve_targets phase1 "$f" - - - h1 >/dev/null)'
t_assert "writeback: nothing to record leaves the file untouched" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "h1,ubuntu,libaio,0-3,/mnt/w,,,4/1G/8/32\n" > "$f"
    before=$(cat "$f")
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    [ "$(cat "$f")" = "$before" ]'
t_assert "writeback: -g interactive overwrite replaces file values with derived ones" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "h1,,psync,9-11,,,,\n" > "$f"
    printf "y" | (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; REGEN_LAYOUT=1
     PROMPT_IN_FD=0; PROMPT_OUT_FD=1
     writeback_targets) >/dev/null
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,,,4/1G/8/32"'
t_assert "writeback: -C set owns the target when -t was not given" bash -c '
    d=$(wb_fixture); mkdir "$d/set"
    (source ./wekatester; write_targets_template "$d/set/hostlist.csv") >/dev/null
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=""; SET_DIR_OVERRIDE=$d/set
     FAST_TRACK=1
     writeback_targets) >/dev/null
    tail -1 "$d/set/hostlist.csv" | grep -q "^h1,ubuntu,libaio,0-3"'

# --- isolcpus awareness (field: isca224, isolcpus=domain,4-55) ---
t_assert "tuner: isolcpus pins usable cores to the isolated set minus weka" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "isolated 4-7\n" >> "$FIX/probe/h1"
    printf "isolated 4-7\n" >> "$FIX/probe/h2"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^cpus_allowed=4-7$" "$FIX/jobs/h1/011-bw.job"'
t_assert "pinning: a mask mixing isolated and housekeeping cpus is fatal" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "taskset 0-3\nisolated 4-15\npriv sudo\n" > "$d/probe/h1"
        printf "h1\t-\t-\t0-15\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >/dev/null )
    case "$err" in
        *"mix isolated and housekeeping"*"silently collapses"*) true;;
        *) echo "$err" >&2; false;;
    esac'
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

# --- README stays in sync with the real help output ---
t_assert "README Usage block matches ./wekatester -h byte for byte" bash -c '
    source ./tests/helpers.sh
    diff <(./wekatester -h) <(readme_usage_block README.md)'

echo; echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
