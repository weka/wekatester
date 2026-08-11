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
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null
    test -f "$FIX/jobs/h1/011-bw.job" && test -f "$FIX/jobs/h2/011-bw.job"'
t_assert "directory override applied" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null
    grep -q "^directory=/mnt/weka$" "$FIX/jobs/h1/011-bw.job"'
t_assert "cpus_allowed excludes weka cores" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null
    grep -q "^cpus_allowed=3-7$" "$FIX/jobs/h1/011-bw.job"'
t_assert "wide-only weka_allowed masks are ignored (utility threads)" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nweka_allowed 0,3-4\nweka_allowed 0-7\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    printf "ncpus 8\nweka_allowed 0,3-4\nweka_allowed 0-7\nengines io_uring libaio psync \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null
    grep -q "^cpus_allowed=0-7$" "$FIX/jobs/h1/011-bw.job"'
t_assert "core mismatch warns" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 16\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) 2>&1 >/dev/null )
    case "$err" in *WARNING*"core counts differ"*) true;; *) false;; esac'

# --- tuner: tier rules (Task 6) ---
t_assert "safe: numjobs = min usable cores" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 6\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=3$" "$FIX/jobs/h1/011-bw.job"'   # h2 usable=3 is the min
t_assert "max: numjobs per host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 6\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=5$" "$FIX/jobs/h1/011-bw.job" && grep -q "^numjobs=3$" "$FIX/jobs/h2/011-bw.job"'
t_assert "max: bw ioengine upgraded to io_uring" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=io_uring$" "$FIX/jobs/h1/011-bw.job"'
t_assert "safe: engine untouched when available" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=libaio$" "$FIX/jobs/h1/011-bw.job"'
t_assert "safe: engine fixed when missing on one host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nioengine=io_uring\nnumjobs=2\nfilesize=1G\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    printf "ncpus 8\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines libaio psync \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null 2>&1
    grep -q "^ioengine=libaio$" "$FIX/jobs/h1/011-bw.job"'
t_assert "latency: numjobs/iodepth untouched, small files applied at max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report latency\n[global]\nfilesize=10G\nnumjobs=1\nioengine=libaio\n[lat]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/021-lat.job"
    grep -q "^numjobs=1$" "$v" && grep -q "^iodepth=1$" "$v" &&
    grep -q "^filesize=1G$" "$v" && grep -q "wt-small" "$v" &&
    grep -q "^file_service_type=random$" "$v"'
t_assert "mixed report treats file as latency" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops latency\n[global]\nnumjobs=4\nioengine=libaio\nfilesize=1G\n[j]\nrw=randwrite\niodepth=8\n" > "$FIX/src/022-mixed.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=4$" "$FIX/jobs/h1/022-mixed.job"'
t_assert "max: iops iodepth and nrfiles derived" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/031-iops.job"
    grep -q "^iodepth=64$" "$v" && grep -q "^filesize=1G$" "$v" && grep -q "^nrfiles=5$" "$v"'
t_assert "mixed bandwidth+iops keeps bandwidth file layout" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=128k\nrw=read\niodepth=1\n" > "$FIX/src/012-mixed-bw.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/012-mixed-bw.job"
    grep -q "^numjobs=5$" "$v" && grep -q "^filesize=10G$" "$v" && ! grep -q "wt-small" "$v"'

# --- tuner: capacity check (Task 7, Task 11) ---
t_assert "capacity check dies when oversized" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *ERROR*"only"*"available (use --ignore-capacity to run anyway)"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "capacity check overridden by --ignore-capacity flag arg" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 1 h1 h2) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc" >&2; false; } &&
    case "$err" in
        *WARNING*"available (--ignore-capacity: running anyway)"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "no capacity warning when it fits" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc" >&2; false; } &&
    case "$err" in *WARNING*available*) false;; *) true;; esac'
t_assert "namespace-aware formula: distinct namespaces sum" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) 2>&1 )
    case "$out" in *"required ~150.0GiB"*) true;; *) false;; esac'
t_assert "capacity: missing _df file reports 0.0GiB available, no warning" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    rm "$FIX/probe/_df"
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) 2>&1 )
    case "$out" in
        *"available 0.0GiB"*) grep -q WARNING <<< "$out" && false || true ;;
        *) false ;;
    esac'
t_assert "weka RAM: memory key fallback (pre-5.1)" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "[{\"memory\": 12335448064}, {\"memory\": 12335448064}]\n" > "$FIX/probe/_weka_ram.json"
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    grep -q "^nrfiles=5$" "$FIX/jobs/h1/031-iops.job"'

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
t_assert "auto staging aborts when the workload does not fit" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( (source ./wekatester
            WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2)
            AUTO_LEVEL=max; IGNORE_CAPACITY=0
            stage_variants "$FIX/src") 2>&1 >/dev/null )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *ERROR*"only"*"available (use --ignore-capacity to run anyway)"*"auto tuning failed"*) true;;
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
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/011-bw.job"
    grep -q "^\[global\]$" "$v" && grep -q "^directory=/mnt/weka$" "$v" &&
    grep -q "^cpus_allowed=3-7$" "$v" && grep -q "^\[job1\]$" "$v"'
t_assert "an existing [global] is never duplicated" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null 2>&1
    [ "$(grep -c "^\[global\]$" "$FIX/jobs/h1/011-bw.job")" -eq 1 ]'

# --- capacity model: namespaces, size=, small-file size rewrite ---
# fio expands the default filename_format ($jobname...) per section, so two
# jobfiles that set no filename_format own separate files and must SUM. They
# used to share one literal default key and collapse to a max, under-counting
# the footprint -- the one direction the guard must never fail in.
t_assert "capacity: jobfiles without filename_format sum, not max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/012-bw2.job"
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1) 2>&1 )
    case "$out" in *"required ~100.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: jobfiles sharing one filename_format take the max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    j="# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nfilename_format=shared.\$jobnum.\$filenum\nioengine=libaio\n[j]\nrw=read\n"
    printf "$j" > "$FIX/src/011-bw.job"
    printf "$j" > "$FIX/src/012-bw2.job"
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1) 2>&1 )
    case "$out" in *"required ~50.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: size= without filesize counts numjobs x size" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nsize=4G\nnrfiles=4\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1) 2>&1 )
    case "$out" in *"required ~20.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: a percentage size= contributes 0 instead of crashing" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nsize=50%%\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1) 2>&1 )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc: $out" >&2; false; } &&
    case "$out" in *"required ~0.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "max: small-file redirect rewrites size= to nrfiles x 1G" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nsize=40G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/031-iops.job"
    grep -q "^nrfiles=5$" "$v" && grep -q "^filesize=1G$" "$v" && grep -q "^size=5G$" "$v"'
t_assert "max: latency size= follows the capped nrfiles" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report latency\n[global]\nfilesize=10G\nsize=40G\nnumjobs=1\nioengine=libaio\n[lat]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/021-lat.job"
    grep -q "^nrfiles=8$" "$v" && grep -q "^size=8G$" "$v"'
t_assert "size= is never inserted where the jobfile had none" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
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
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -q "re-derived by wekatester auto\[max\]" "$v" &&
    grep -q "^filename_format=wt-small.\$jobnum.\$filenum$" "$v" &&
    grep -q "^cpus_allowed=3-7$" "$v"'
t_assert "tuner: edited layout at max is staged as-is with a warning" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    echo "# operator note" >> "$FIX/src/000-wekatester-layout.job"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 h1 h2) 2>&1 >/dev/null )
    v="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -q "# operator note" "$v" && ! grep -q "re-derived" "$v" &&
    case "$err" in *"user-edited layout staged as-is"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "tuner capacity: layout job does not double the required total" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) 2>/dev/null )
    case "$out" in *"required ~100.0GiB"*) true;; *) echo "$out" >&2; false;; esac'

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
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -q "re-derived by wekatester auto\[safe\]" "$v" && grep -q "^numjobs=5$" "$v" &&
    ! grep -q "^numjobs=4$" "$v"'
t_assert "capacity: layout union raises required above per-namespace max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    rm -f "$FIX/src/011-bw.job"
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=4\nioengine=libaio\ndirectory=/orig\n[a]\nrw=read\niodepth=1\n" > "$FIX/src/011-a.job"
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=2\nnrfiles=27\nioengine=libaio\ndirectory=/orig\n[b]\nrw=read\niodepth=1\n" > "$FIX/src/012-b.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 h1 h2) 2>/dev/null )
    # per-namespace max = 2x27x1G=54G/host; union = 5x1 + 5x27 wait: safe tunes numjobs to 5 for both
    # a: numjobs=5 nrfiles=1 -> 5 files; b: numjobs=5 nrfiles=27 -> 135 files; b dominates a
    # union = 135G/host x 2 hosts = 270G; namespace max = 135G x 2 = 270G -- equal here, so
    # assert the required is the union value (270), proving layout_footprint is consulted
    case "$out" in *"required ~270.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
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
    printf "no json here\n" > "$b/results_030-broken.json"
    tar -czf "$d/bundle.tgz" -C "$d" 20260101-000000
    out=$(./wekatester -s "$d/bundle.tgz") || { echo "$out" >&2; exit 1; }
    case "$out" in
        *"==== 010-mylayout ===="*|*"==== 000-wekatester-layout ===="*)
            echo "layout results leaked into the summary:" >&2; echo "$out" >&2; exit 1;;
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
        *"unknown auto level: bogus (safe|max)"*) true;;
        *) echo "$err" >&2; false;;
    esac'

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
t_assert "probe: -e engine missing from a worker refuses early, naming it" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2); MASTER=h1
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
     grep -q "^rw=write$" "$r" && grep -q "^create_on_open=1$" "$r" &&
     ! grep -q "^create_only=1$" "$r" && ! grep -q "wekatester-layout: generated" "$r" &&
     grep -q "^filesize=10G$" "$r" && grep -q "^numjobs=16$" "$r")'
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

# A failed backend-RAM query is survivable (the tuner floors the working
# set), but the operator should hear the one command that usually fixes it.
t_assert "probe: failed weka RAM query hints at weka user login and continues" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost
            WORK_DIR=$d; DIRECTORY=/mnt/weka
            run_host() { case "$2" in
                (*"weka cluster servers list"*) return 1;;
                (*) echo stubbed;;
            esac; }
            probe_workers) 2>&1 >/dev/null ) || { echo "probe died: $err" >&2; exit 1; }
    case "$err" in
        *"could not query weka backend RAM"*"weka user login"*) true;;
        *) echo "$err" >&2; false;;
    esac'

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
