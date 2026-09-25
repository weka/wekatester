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

# --- usable cores: an unbindable cpu is not usable, and numjobs is this count ---
t_assert "usable_cores: cpus the probe measured as unbindable are excluded" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    printf "ncpus 8\nonline 0-7\nbindable 0,1,2,4,6,7\nbindable_priv -\n" > "$d/probe/h1"
    (source ./wekatester; WORK_DIR=$d
     # 0 and 1 are the OS reserve; 3 and 5 refuse the bind
     [ "$(usable_cores h1 count)" = 4 ] || { echo "count: $(usable_cores h1 count)" >&2; false; } &&
     [ "$(usable_cores h1 list)" = "2,4,6,7" ] || { echo "list: $(usable_cores h1 list)" >&2; false; } &&
     # an operator list is its own reserve: only core 0 comes out of it
     [ "$(usable_cores h1 count 0-3)" = 2 ] &&
     [ "$(usable_cores h1 list 0-3)" = "1,2" ])'
t_assert "usable_cores: weka cores and unbindable cpus are both excluded" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    printf "ncpus 8\nonline 0-7\nweka_allowed 1\nweka_allowed 2\nbindable 0,1,2,4,6,7\nbindable_priv -\n" > "$d/probe/h1"
    (source ./wekatester; WORK_DIR=$d
     # weka owns 1 and 2, so the reserve is 0 and 3; 5 refuses the bind
     [ "$(usable_cores h1 list)" = "4,6,7" ] || { echo "$(usable_cores h1 list)" >&2; false; })'
t_assert "usable_cores: an offline cpu id is not conjured from the count" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    # 6 online cpus, ids 0-3 and 6-7: the count alone would have said 0-5
    printf "ncpus 6\nonline 0-3,6-7\nbindable 0,1,2,3,6,7\nbindable_priv -\n" > "$d/probe/h1"
    (source ./wekatester; WORK_DIR=$d
     [ "$(usable_cores h1 list)" = "2,3,6,7" ] || { echo "$(usable_cores h1 list)" >&2; false; })'

# --- probe remote snippet ---
t_assert "probe snippet emits ncpus"   bash -c 'probe_stub | grep -q "ncpus 8"'
t_assert "probe snippet emits engines" bash -c 'probe_stub | grep -q "engines.*io_uring"'
# Whether a cpu can be bound at all is MEASURED, per cpu, not inferred from
# isolcpus: fio answers an unbindable cpus_allowed with err=22
# cpu_set_affinity per job, on the daemonized server, mid-run.
t_assert "probe snippet measures which cpus can actually be bound" bash -c '
    out=$(probe_stub)
    printf "%s\n" "$out" | grep -qx "bindable 0,1,2,4,6,7" &&
    printf "%s\n" "$out" | grep -qx "bindable_priv -" ||
        { printf "%s\n" "$out" >&2; false; }'
t_assert "probe facts: an absent bindable line means UNTESTED, never none" bash -c '
    d=$(mktemp -d)
    printf "ncpus 8\n" > "$d/p"
    (source ./wekatester; pyrun "$d/p" <<"EOF"
import sys
p = sys.argv[1]
s, tested = probe_cpu_fact(p, "bindable")
assert not tested and s == set(), (s, tested)
assert probe_unbindable(p, set(range(8))) == set(), "a guess, not a measurement"
assert probe_universe(p, 8) == set(range(8))
open(p, "a").write("bindable -\nonline 0-3\n")
s, tested = probe_cpu_fact(p, "bindable")
assert tested and s == set(), (s, tested)
assert probe_unbindable(p, set(range(8))) == set(range(8))
assert probe_universe(p, 8) == {0, 1, 2, 3}
EOF
    )'

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
    grep -q "^cpus_allowed=2-4$" "$FIX/jobs/h1/011-bw.job"'
t_assert "wide-only weka_allowed masks are ignored (utility threads)" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nweka_allowed 0,3-4\nweka_allowed 0-7\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    printf "ncpus 8\nweka_allowed 0,3-4\nweka_allowed 0-7\nengines io_uring libaio psync \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null
    grep -q "^cpus_allowed=2-7$" "$FIX/jobs/h1/011-bw.job"'
t_assert "core mismatch warns" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 16\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) 2>&1 >/dev/null )
    case "$err" in *WARNING*"core counts differ"*) true;; *) false;; esac'

# --- tuner: tier rules (Task 6) ---
t_assert "safe: numjobs = min usable cores" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 6\nweka_allowed 3\nweka_allowed 4\nweka_allowed 5\nengines io_uring libaio \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=1$" "$FIX/jobs/h1/011-bw.job"'   # h2: 6 cores - 3 weka - 2 reserved = 1, the min
t_assert "max: numjobs per host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 6\nweka_allowed 3\nweka_allowed 4\nweka_allowed 5\nengines io_uring libaio \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    grep -q "^numjobs=3$" "$FIX/jobs/h1/011-bw.job" && grep -q "^numjobs=1$" "$FIX/jobs/h2/011-bw.job"'
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
    grep -q "^numjobs=3$" "$v" && grep -q "^filesize=10G$" "$v" && ! grep -q "wt-small" "$v"'

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
    # bw: 3 jobs x 1 file x 10G = 30GiB; iops (2 files/job): 3 jobs x 2 files x 1G
    # = 6GiB -- distinct namespaces, so the two sum to 36GiB
    case "$out" in *"capacity: h1 needs ~36.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
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
    grep -q "^cpus_allowed=2-4$" "$v" && grep -q "^\[job1\]$" "$v"'
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
    case "$out" in *"capacity: h1 needs ~60.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: jobfiles sharing one filename_format take the max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    j="# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nfilename_format=shared.\$jobnum.\$filenum\nioengine=libaio\n[j]\nrw=read\n"
    printf "$j" > "$FIX/src/011-bw.job"
    printf "$j" > "$FIX/src/012-bw2.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~30.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: size= without filesize counts numjobs x size" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nsize=4G\nnrfiles=4\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~12.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
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
            run_host() { echo "FAIL localhost"; echo DONE; }
            verify_fio_ports) 2>&1 >/dev/null )
    case "$err" in
        *"cannot reach localhost:8765 (loopback resolution?"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "port check: remote mode still blames the firewall" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(vega-2); MASTER=vega-1
            run_host() { echo "FAIL vega-2"; echo DONE; }
            verify_fio_ports) 2>&1 >/dev/null )
    case "$err" in
        *"vega-1 cannot reach vega-2:8765 (host firewall?)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# 111 workers, one master: one ssh session per worker piled 111 sessions onto
# the master'"'"'s multiplexed connection, sshd refused past MaxSessions, and 39
# probes that never ran were reported as firewalls (yqb01, 2026-09-09). The
# check is ONE session now, and a session that fails is said to be that.
t_assert "port check: one ssh session to the master however many workers there are" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     LOCAL_MODE=0; MASTER=h1; HOSTS=(h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12)
     run_host() { echo "$1" >> "$d/sessions"; echo DONE; }
     verify_fio_ports) >/dev/null &&
    [ "$(wc -l < "$d/sessions")" -eq 1 ] && [ "$(cat "$d/sessions")" = h1 ]'
t_assert "port check: a failed ssh session to the master is not a firewall" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(vega-1 vega-2); MASTER=vega-1
            run_host() { echo "mux_client_request_session: session request failed" >&2; return 255; }
            verify_fio_ports) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *firewall*|*"cannot reach"*) echo "blamed a firewall for a dead session: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"cannot run the fio port check on vega-1"*"ssh session to the master failed (rc=255)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "port check: the remote snippet names every worker, the port, and ends with DONE" bash -c '
    (source ./wekatester; FIO_PORT=8765
     s=$(port_probe_cmd h1 h2 h3)
     case "$s" in
         *"for h in '"'"'h1'"'"' '"'"'h2'"'"' '"'"'h3'"'"';"*"</dev/tcp/\$h/8765"*"echo \"FAIL \$h\""*"wait \$pids; echo DONE") true;;
         *) echo "$s" >&2; false;;
     esac)'
# The snippet is run for real, on this box: a port nothing listens on must
# yield a FAIL line, a port something listens on must not, and DONE ends both.
t_assert "port check: the rendered snippet really probes -- closed port FAILs, open port passes, DONE either way" bash -c '
    d=$(mktemp -d)
    (source ./wekatester; FIO_PORT=1
     out=$(bash -c "$(port_probe_cmd 127.0.0.1)" 2>&1)
     case "$out" in *"FAIL 127.0.0.1"*DONE) true;; *) echo "closed port: $out" >&2; false;; esac) &&
    { python3 -c "import socket,time
s=socket.socket(); s.bind((\"127.0.0.1\",0)); s.listen(5); print(s.getsockname()[1], flush=True); time.sleep(20)" > "$d/port" & echo $! > "$d/pid"; } &&
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "$d/port" ] && break; sleep 0.25; done &&
    [ -s "$d/port" ] &&
    out=$( (source ./wekatester; FIO_PORT=$(cat "$d/port"); bash -c "$(port_probe_cmd 127.0.0.1 127.0.0.1)" 2>&1) ); rc=$?
    kill "$(cat "$d/pid")"
    [ "$rc" -eq 0 ] &&
    case "$out" in *FAIL*) echo "open port: $out" >&2; false;; *DONE) true;; *) echo "open port: $out" >&2; false;; esac'
t_assert "port check: a FAIL line for one worker leaves the others reachable" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(vega-1 vega-2 vega-3); MASTER=vega-1
            run_host() { echo "FAIL vega-2"; echo DONE; }
            verify_fio_ports) 2>&1 >/dev/null )
    case "$err" in
        *"vega-1 cannot reach vega-2:8765"*"failed on 1 of 3 host(s)"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    case "$err" in *"vega-3"*) echo "blamed a reachable host: $err" >&2; false;; *) true;; esac'

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
    grep -q "^cpus_allowed=2-4$" "$v"'
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
    case "$out" in *"capacity: h1 needs ~30.0GiB"*) true;; *) echo "$out" >&2; false;; esac'

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
    grep -q "re-derived by wekatester auto\[safe\]" "$v" && grep -q "^numjobs=3$" "$v" &&
    ! grep -q "^numjobs=4$" "$v"'
t_assert "capacity: layout union raises required above per-namespace max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    rm -f "$FIX/src/011-bw.job"
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=4\nioengine=libaio\ndirectory=/orig\n[a]\nrw=read\niodepth=1\n" > "$FIX/src/011-a.job"
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=2\nnrfiles=27\nioengine=libaio\ndirectory=/orig\n[b]\nrw=read\niodepth=1\n" > "$FIX/src/012-b.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null
    out=$( cap safe 0 h1 h2 2>/dev/null )
    # a: numjobs=3 nrfiles=1 -> 3 files; b: numjobs=3 nrfiles=27 -> 81 files;
    # union = 81G/host; namespace max = 81G -- equal here, so assert the
    # per-host requirement is the union value, proving layout_footprint runs
    case "$out" in *"capacity: h1 needs ~81.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
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

t_assert "seed_estimate_line: complete dataset, unknown free space, and the share of free space" bash -c '
    source ./wekatester
    [ "$(seed_estimate_line 0 0 0 1000 /d)" = "dataset already complete, nothing to write" ] &&
    [ "$(seed_estimate_line 4 2048 0 "" /d)" = "4 dense file(s) = 2.0 GiB to write, 0 sparse truncate(s); free space at /d unknown" ] &&
    [ "$(seed_estimate_line 4 2048 6 8192 /d)" = "4 dense file(s) = 2.0 GiB to write, 6 sparse truncate(s); free 8.0 GiB at /d (25.0% of it)" ] &&
    [ "$(seed_estimate_line 0 0 6 8192 /d)" = "0 dense file(s) = 0.0 GiB to write, 6 sparse truncate(s); free 8.0 GiB at /d (0.0% of it)" ] &&
    [ "$(seed_estimate_line 192 983040 0 402733363 /d)" = "192 dense file(s) = 960.0 GiB to write, 0 sparse truncate(s); free 384.1 TiB at /d (0.2% of it)" ] &&
    [ "$(seed_estimate_line 4 2097152 0 4194304 /d)" = "4 dense file(s) = 2.0 TiB to write, 0 sparse truncate(s); free 4.0 TiB at /d (50.0% of it)" ]'

# A failed rung used to die pointing at /dev/shm/wt.*, wiped on exit (seen
# live: weka-xcpu-344, brutal bw-write qd=1 nr=1). Evidence goes in the
# bundle now, and fio's own error text is said at once.
t_assert "cal_evidence: a failed rung leaves fio output and jobfiles in the bundle and says why" bash -c '
    d=$(mktemp -d); r=$(mktemp -d); mkdir -p "$d/cal/h1"
    printf "[global]\nrw=write\n" > "$d/cal/h1/cal-bw-write-qd1-nr1.job"
    printf "<h1> fio: pid=0, err=28/file:filesetup.c:233, func=write, error=No space left on device\nfio: client: all clients gone\n" > "$d/cal/res-bw-write-qd1-nr1.json"
    out=$( (source ./wekatester
            WORK_DIR=$d; RUN_DIR=$r; TARGET_DIR=/dev/shm/x; FIO_BIN=fio; MASTER=h1
            run_host() { return 0; }
            cal_evidence "rung bw-write qd=1 nr=1" "$d/cal/res-bw-write-qd1-nr1.json" cal-bw-write-qd1-nr1.job say h1) 2>&1 )
    [ -s "$r/cal/res-bw-write-qd1-nr1.json" ] && [ -s "$r/cal/cal-bw-write-qd1-nr1.h1.job" ] && [ -e "$r/cal/parse.h1.out" ] &&
    case "$out" in
        *"ERROR: rung bw-write qd=1 nr=1: fio said: <h1> fio: pid=0, err=28"*"No space left on device"*"parses cleanly"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    case "$out" in *"all clients gone"*) echo "surfaced a non-error line: $out" >&2; false;; *) true;; esac'
# fio --client stages jobfiles on the master only; a WORKER's fio can parse
# only what the worker has. The postmortem stages the worker's copy first,
# and leaves the master (which already holds it) alone.
t_assert "cal_evidence: a non-master worker gets its jobfile staged before its fio parses it" bash -c '
    d=$(mktemp -d); r=$(mktemp -d); mkdir -p "$d/cal/h1" "$d/cal/h2"
    printf "[global]\nrw=write\n" > "$d/cal/h1/x.job"; cp "$d/cal/h1/x.job" "$d/cal/h2/x.job"
    printf "{}\n" > "$d/cal/res-x.json"
    out=$( (source ./wekatester
            WORK_DIR=$d; RUN_DIR=$r; TARGET_DIR=/dev/shm/x; FIO_BIN=fio; MASTER=h1; LOCAL_MODE=0
            run_host() { echo "RUN[$1] $2" >&2; return 0; }
            copy_to_host() { echo "COPY[$1] ${2##*/} -> $3" >&2; return 0; }
            cal_evidence "rung x" "$d/cal/res-x.json" x.job quiet h1 h2) 2>&1 )
    case "$out" in *"COPY[h1]"*|*"RUN[h1] mkdir"*) echo "staged onto the master: $out" >&2; false;; *) true;; esac &&
    case "$out" in
        *"RUN[h2] mkdir -p '"'"'/dev/shm/x.cal/h2'"'"'"*"COPY[h2] x.job -> /dev/shm/x.cal/h2/"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    # the parse call itself is captured into the per-host parse file
    grep -q "RUN\[h2\] '"'"'fio'"'"' --parse-only '"'"'/dev/shm/x.cal/h2/x.job'"'"'" "$r/cal/parse.h2.out" &&
    grep -q "RUN\[h1\] '"'"'fio'"'"' --parse-only '"'"'/dev/shm/x.cal/h1/x.job'"'"'" "$r/cal/parse.h1.out"'
t_assert "cal_evidence: a worker that cannot be staged is warned about, and the others still get parsed" bash -c '
    d=$(mktemp -d); r=$(mktemp -d); mkdir -p "$d/cal/h1" "$d/cal/h2"
    printf "[global]\nrw=write\n" > "$d/cal/h1/x.job"; cp "$d/cal/h1/x.job" "$d/cal/h2/x.job"
    printf "{}\n" > "$d/cal/res-x.json"
    out=$( (source ./wekatester
            WORK_DIR=$d; RUN_DIR=$r; TARGET_DIR=/dev/shm/x; FIO_BIN=fio; MASTER=h1; LOCAL_MODE=0
            run_host() { case "$1:$2" in (h2:mkdir*) return 1;; esac; echo "RUN[$1]" >&2; return 0; }
            copy_to_host() { echo "COPY[$1]" >&2; return 0; }
            cal_evidence "rung x" "$d/cal/res-x.json" x.job quiet h1 h2) 2>&1 )
    case "$out" in *"COPY[h2]"*) echo "copied after a failed mkdir: $out" >&2; false;; *) true;; esac &&
    case "$out" in *"WARNING: h2: cannot stage the rung x jobfile"*) true;; *) echo "$out" >&2; false;; esac &&
    grep -q "RUN\[h1\]" "$r/cal/parse.h1.out" && [ ! -e "$r/cal/parse.h2.out" ]'
# A flat five-line cap hid the one fact that mattered: how many jobs failed
# the same way (weka-xcpu-344 showed five cpu_set_affinity lines out of an
# unknown number). Identical errors collapse to one line with a job count.
t_assert "cal_evidence: identical per-job errors collapse to one line carrying the job count" bash -c '
    d=$(mktemp -d); r=$(mktemp -d); mkdir -p "$d/cal/h1"
    printf "[global]\nrw=write\n" > "$d/cal/h1/x.job"
    : > "$d/cal/res-x.json"
    for p in 1001 1002 1003 1004 1005 1006 1007; do
        printf "<h1> fio: pid=%s, err=22/file:backend.c:1733, func=cpu_set_affinity, error=Invalid argument\n" "$p" >> "$d/cal/res-x.json"
    done
    printf "{}\n" >> "$d/cal/res-x.json"
    out=$( (source ./wekatester
            WORK_DIR=$d; RUN_DIR=$r; TARGET_DIR=/dev/shm/x; FIO_BIN=fio; MASTER=h1
            run_host() { return 0; }
            cal_evidence "rung x" "$d/cal/res-x.json" x.job say h1) 2>&1 )
    [ "$(printf "%s\n" "$out" | grep -c "fio said")" -eq 1 ] &&
    case "$out" in
        *"ERROR: rung x: fio said (7 jobs): <h1> fio: pid=1001, err=22"*"cpu_set_affinity, error=Invalid argument"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "cal_evidence: distinct errors are listed, five at most, with the remainder counted" bash -c '
    d=$(mktemp -d); r=$(mktemp -d); mkdir -p "$d/cal/h1"
    printf "[global]\nrw=write\n" > "$d/cal/h1/x.job"
    : > "$d/cal/res-x.json"
    for i in 1 2 3 4 5 6 7; do
        printf "fio: distinct error number %s\n" "$i" >> "$d/cal/res-x.json"
    done
    out=$( (source ./wekatester
            WORK_DIR=$d; RUN_DIR=$r; TARGET_DIR=/dev/shm/x; FIO_BIN=fio; MASTER=h1
            run_host() { return 0; }
            cal_evidence "rung x" "$d/cal/res-x.json" x.job say h1) 2>&1 )
    [ "$(printf "%s\n" "$out" | grep -c "fio said")" -eq 5 ] &&
    case "$out" in
        *"error number 1"*"error number 5"*"and 2 more distinct error line(s)"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    case "$out" in *"error number 6"*) echo "printed past the cap: $out" >&2; false;; *) true;; esac'
t_assert "cal_evidence: quiet copies but does not repeat what check_fio_errors already said" bash -c '
    d=$(mktemp -d); r=$(mktemp -d); mkdir -p "$d/cal/h1"
    printf "[global]\nrw=write\n" > "$d/cal/h1/x.job"
    printf "fio: failed to create dir\n{}\n" > "$d/cal/res-x.json"
    out=$( (source ./wekatester
            WORK_DIR=$d; RUN_DIR=$r; TARGET_DIR=/dev/shm/x; FIO_BIN=fio; MASTER=h1
            run_host() { return 0; }
            cal_evidence "rung x" "$d/cal/res-x.json" x.job quiet h1) 2>&1 )
    [ -s "$r/cal/res-x.json" ] && [ -s "$r/cal/x.h1.job" ] &&
    case "$out" in *"fio said"*) echo "$out" >&2; false;; *) true;; esac'
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
# --- cal_required: which searches does this set need ---
# The output grammar is a contract shared with the calibration engine and the
# dry-run report: unique sorted lines from {bw read, bw write, iops read,
# iops write, lat read, lat write}, nothing else, empty when nothing needs
# calibrating. Asserted on
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
t_assert "cal_required: a latency-only set asks for the latency search only" \
    test "$(cal_set '# report latency
[lat]
rw=randread')" = "lat read|"
# latency anywhere in the directive wins, exactly as the tuner classifies it:
# such a file is measured at qd=1 -- no ladder, only the floor rung.
t_assert "cal_required: '# report iops latency' asks only for the latency search" \
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
weka_allowed 5
weka_allowed 6
weka_allowed 7')" = 3
t_assert "usable_cores: a wide utility-thread mask owns nothing" \
    test "$(uc 'ncpus 8
weka_allowed 0,3-4
weka_allowed 0-7')" = 6
t_assert "usable_cores: no weka at all leaves every core but the OS reserve" \
    test "$(uc 'ncpus 4')" = 2
# isolcpus does NOT narrow the set: weka's cores and the OS reserve are all
# that is subtracted (saving-calf 2026-08-20 -- confining the OS cost 4-7%
# write iops; split affinity makes a cross-partition mask safe).
t_assert "usable_cores: isolcpus does not narrow the set" \
    test "$(uc 'ncpus 8
isolated 4-7
weka_allowed 4
weka_allowed 5')" = 4
t_assert "usable_cores: weka owning every isolated cpu just leaves the rest" \
    test "$(uc 'ncpus 8
isolated 4-7
weka_allowed 4
weka_allowed 5
weka_allowed 6
weka_allowed 7')" = 2
# An empty answer is not a count: fio has no valid numjobs=0, so a probe that
# cannot be read has to fail loudly rather than size a ladder at zero jobs.
t_assert "usable_cores: an unreadable probe is an error, not a zero" \
    uc_fails usable_cores
t_assert "usable_cores: a probe with no ncpus is an error, not a zero" \
    uc_fails "leaves fio no cpus" 'engines psync '
t_assert "usable_cores: a list naming cpus the host does not have is trimmed" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    printf "ncpus 8\n" > "$d/probe/h1"
    out=$( (source ./wekatester; WORK_DIR=$d; usable_cores h1 list "0-11") )
    [ "$out" = "1,2,3,4,5,6,7" ]'

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
     hostname() { echo testbox; }
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles) >/dev/null || exit 1
    # the staging path keeps the ADDRESS; the data-file prefix is the NAME
    v="$d/target/localhost/011-smoke-readbw.job"
    r="$d/target/localhost/000-wekatester-layout.job"
    grep -q "^unique_filename=0$" "$v" &&
    grep -q "^filename_format=testbox\." "$v" &&
    grep -q "^unique_filename=0$" "$r" &&
    grep -q "^filename_format=testbox\." "$r" &&
    ! grep -q "localhost\." "$v" && ! grep -q "localhost\." "$r"'

# --- host_name: the data-file prefix is a NAME, never "localhost" ---------
# Remote workers are named by their address. In local mode the address stays
# localhost (fio talks to a loopback server) but files on the destination are
# named for the box: hostname -s, then $HOSTNAME's first label, then hostname.
t_assert "host_name: remote is the address, local is the short hostname, LOCAL_NAME wins" bash -c '
    source ./wekatester
    hostname() { echo testbox; }
    [ "$(LOCAL_MODE=0; host_name h1)" = h1 ] &&
    [ "$(LOCAL_MODE=1; host_name localhost)" = testbox ] &&
    [ "$(LOCAL_MODE=1; LOCAL_NAME=fixed; host_name localhost)" = fixed ]'
t_assert "host_name: falls back to \$HOSTNAME first label, then hostname, then the address" bash -c '
    source ./wekatester
    hostname() { case "$1" in (-s) return 1;; (*) echo longbox;; esac; }
    [ "$(HOSTNAME=box.example.com; local_short_hostname)" = box ] &&
    [ "$(HOSTNAME=""; local_short_hostname)" = longbox ] &&
    hostname() { return 1; } &&
    [ "$(HOSTNAME=""; local_short_hostname)" = "" ] &&
    [ "$(HOSTNAME=""; LOCAL_MODE=1; host_name localhost)" = localhost ]'
t_assert "host_name: a local run fixes the name once in resolve_local_mode" bash -c '
    source ./tests/helpers.sh; uname_fixture Linux
    (source ./wekatester
     hostname() { echo testbox; }
     HOSTS=(); resolve_local_mode >/dev/null
     [ "$LOCAL_NAME" = testbox ] && [ "${HOSTS[*]}" = localhost ] && [ "$MASTER" = localhost ])'
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
# An old-format tuple (fs/nr/qd, no nj) is re-measured, and fill mode keeps
# its fields: a mix nobody measured, which the writeback would make permanent.
# The file cannot say whether the operator wrote it, so the run warns.
t_assert "apply_cal_results: an old tuple without numjobs is re-measured, kept, and warned about" bash -c '
    d=$(mktemp -d)
    printf "h1 - 4 2 5120M 6 - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n" > "$d/cal.results"
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (7) printf "\t1G";; (8) printf "\t2";; (9) printf "\t8";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$d/targets.final"
    cp "$d/targets.final" "$d/orig"
    err=$( (source ./wekatester; WORK_DIR=$d; REGEN_LAYOUT=0; apply_cal_results) 2>&1 )
    a=$(awk -F"\t" "\$1==\"h1\" {print \$6, \$7, \$8, \$9}" "$d/targets.final")
    [ "$a" = "6 1G 2 8" ] || { echo "fill: $a" >&2; exit 1; }
    case "$err" in
        *"WARNING: h1: the host file'"'"'s bandwidthR geometry (fs/nr/qd 1G/2/8) has no numjobs, so it was measured again"*"re-run with -g so the measured tuple (6/5120M/2/4) replaces them"*) true;;
        *) echo "$err" >&2; exit 1;;
    esac
    cp "$d/orig" "$d/targets.final"
    err=$( (source ./wekatester; WORK_DIR=$d; REGEN_LAYOUT=1; apply_cal_results) 2>&1 )
    b=$(awk -F"\t" "\$1==\"h1\" {print \$6, \$7, \$8, \$9}" "$d/targets.final")
    [ "$b" = "6 5120M 2 4" ] && [ -z "$err" ] || { echo "-g: $b $err" >&2; false; }'
t_assert "apply_cal_results: -g lets measured tuples and the engine overwrite host-file values" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; REGEN_LAYOUT=1
     # cal.results: host, engine, then (qd nr fs nj) x (bw_r bw_w lat_r lat_w iops_r iops_w)
     printf "h1 libaio 4 2 1024M 2 2 2 1024M 6 1 2 1024M 3 - - - - 32 2 256M 6 16 2 256M 6 - - - - - - - -\n" > "$d/cal.results"
     # 37 columns; the engine (col 3), bw_r_qd (col 9) and iops_r_qd (col 25) carry old values
     { printf "h1"
       for i in $(seq 2 37); do
          case $i in (3) printf "\tpsync";; (9) printf "\t8";; (25) printf "\t64";; (*) printf "\t-";; esac
       done; printf "\n"; } > "$d/targets.final"
     apply_cal_results)
    a=$(awk -F"\t" "\$1==\"h1\" {print \$3, \$9, \$13, \$25, \$29, \$6, \$14, \$17}" "$d/targets.final")
    # the engine, the four qds, bw_r_nj, lat_r_nj and lat_r_qd
    [ "$a" = "libaio 4 2 32 16 2 3 1" ] || { echo "a=$a" >&2; false; }'
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

# No cluster-wide weka CLI runs on the master under -a: the DRAM ceiling it
# fed is retired (see the corrected "Working-set sizing (max tier)" spec
# section), so df is the only master-side fact the tuner needs. The per-host
# probe asks each host's OWN agent one thing -- which NICs it uses (weka
# local ps / weka local resources net), for the calibration shapes.
t_assert "probe: -a runs no weka CLI on the master, only df; per host only weka local" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=max
            WORK_DIR=$d; DIRECTORY=/mnt/weka
            # "weka " with the space matches a CLI invocation only
            run_host() { case "$2" in
                (*cpu_model*) printf "%s" "$2" | grep -o "weka [a-z]* [a-z]*" | sort -u > "$d/wekacalls"
                              echo stubbed;;
                (*"weka "*) echo "WEKA_CALLED: $2" >&2; return 1;;
                (*) echo stubbed;;
            esac; }
            probe_workers) 2>&1 >/dev/null ) || { echo "probe died: $err" >&2; exit 1; }
    test ! -e "$d/probe/_weka_ram.json" && test ! -e "$d/probe/_weka_ram.err" &&
    [ -s "$d/wekacalls" ] && ! grep -v "^weka local " "$d/wekacalls" &&
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
    want="h1	-	-	-	-	12	10G	-	8	12	10G	-	4	1	-	-	1	-	-	-	-	4	1G	56	64	-	-	-	-	-	-	-	-	-	-	-	-"
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
# The failure this exists to prevent (weka-xcpu-344, 2026-09-09): a cpu that
# is online and not weka'"'"'s can still refuse the bind -- offline-but-counted,
# or held by another cgroup'"'"'s cpuset partition -- and fio only says so from
# the daemonized server, per job, after the rung has started.
t_assert "pinning: cpus that refuse the bind are trimmed with a note, list kept as written" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 8
taskset 0-7
online 0-7
bindable 0,1,2,4,6,7
bindable_priv -
" > "$d/probe/h1"
        printf "h1	-	-	0-7	-
" > "$d/targets.final"
        check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    case "$out" in
        *"note: h1: requested cpus (0-7) include 3,5, which this host refuses to bind"*"cgroup"*"executing on the remainder (0-2,4,6-7)"*"keeps the list as written"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "0-2,4,6-7" ] &&
    [ ! -f "$d/auth/h1.priv" ]'
t_assert "pinning: a cpu bindable only under the escalator escalates, it is not trimmed" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 8
taskset 0-3
online 0-7
bindable 0,1,2,3
bindable_priv 4,5,6,7
priv sudo -n
" > "$d/probe/h1"
        printf "h1	-	-	0-7	-
" > "$d/targets.final"
        check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    case "$out" in *"refuses to bind"*) echo "trimmed a cpu the escalator can reach: $out" >&2; false;; *) true;; esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "0-7" ] &&
    [ "$(cat "$d/auth/h1.priv")" = "sudo -n" ]'
t_assert "pinning: bindable only under an escalator that does not exist dies, naming all three" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 8
taskset 0-3
online 0-7
bindable 0,1,2,3
bindable_priv 4,5,6,7
" > "$d/probe/h1"
        printf "h1	-	-	0-7	-
" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in
        *"effective cpus_allowed: 0-7"*"current taskset:        0-3"*"outside the current taskset and no passwordless escalator"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "pinning: every requested cpu refusing the bind dies naming them, not the weka message" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 8
taskset 0-7
online 0-7
bindable 0,1,2,3
bindable_priv -
" > "$d/probe/h1"
        printf "h1	-	-	4,5	-
" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in
        *"no requested cpu (4,5) is usable"*"or one it refuses to bind (4-5)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "pinning: without the measurement the old isolated-is-self-affinable rule still stands" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 8
taskset 0-1
isolated 2-7
" > "$d/probe/h1"
        printf "h1	-	-	0-7	-
" > "$d/targets.final"
        check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    case "$out" in *"refuses to bind"*) echo "invented a measurement: $out" >&2; false;; *) true;; esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "0-7" ] && [ ! -f "$d/auth/h1.priv" ]'
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
# A cpu the host does not have would be rejected by fio -- on the SERVER,
# whose error text is lost, so the run dies later with "the jobs did not
# run" and no evidence (iscg001 2026-08-28: host file said 0-128 on a 64-cpu
# box). Trimmed at row resolution with a note naming them, same contract as
# the weka overlap: the host file keeps the list as written.
t_assert "pinning: cpus the host does not have are trimmed with a note, file untouched" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 64\ntaskset 0-63\nweka_allowed 52\nweka_allowed 53\n" > "$d/probe/h1"
        printf "h1\t-\t-\t0-128\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 )
    case "$out" in
        *"note"*"cpus this host does not have (64-128; the host has 64 cpus: 0-63); executing on the remainder (0-51,54-63)"*) true;;
        *) echo "$out" >&2; exit 1;;
    esac && [ "$(cat "$d/auth/h1.cpus")" = "0-51,54-63" ]'
t_assert "pinning: a list with no real cpu at all still dies" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 64\ntaskset 0-63\n" > "$d/probe/h1"
        printf "h1\t-\t-\t100-128\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >/dev/null )
    case "$err" in
        *"no requested cpu (100-128) is usable"*"(100-128; the host has 64 cpus: 0-63)"*) true;;
        *) echo "$err" >&2; exit 1;;
    esac && test ! -f "$d/auth/h1.cpus"'
t_assert "pinning: a valid list on a probed host still proceeds" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
     printf "ncpus 16\ntaskset 0-15\n" > "$d/probe/h1"
     printf "h1\t-\t-\t4-7\t-\n" > "$d/targets.final"
     check_cpu_pinning)
    [ "$(cat "$d/auth/h1.cpus")" = "4-7" ]'
# The postmortem for a seed whose jobs did not run: fio --client exits 0 and
# the daemonized server keeps the rejection text, so cal_evidence asks the
# host fio to re-parse the jobfile -- a dirty parse is surfaced verbatim, a
# clean one says the death was at setup, and both land in the bundle.
t_assert "cal_evidence: a failed seed asks the host fio why (dirty and clean parse)" bash -c '
    d=$(mktemp -d); r=$(mktemp -d); mkdir -p "$d/cal/h1" "$r"
    echo "{}" > "$d/cal/res-seed.json"
    printf "[global]\ncpus_allowed=0-128\n" > "$d/cal/h1/cal-seed.job"
    out=$( (source ./wekatester
        WORK_DIR=$d; RUN_DIR=$r; FIO_BIN=fio; TARGET_DIR=/dst; MASTER=h1
        run_host() { echo "fio: CPU 128 too large (max=63)"; return 1; }
        cal_evidence seed "$d/cal/res-seed.json" cal-seed.job quiet h1) 2>&1 )
    case "$out" in
        (*"rejects the seed jobfile"*"CPU 128 too large"*) true;;
        (*) echo "$out" >&2; exit 1;;
    esac
    grep -q "CPU 128 too large" "$r/cal/parse.h1.out" || exit 1
    [ -f "$r/cal/cal-seed.h1.job" ] || exit 1
    out2=$( (source ./wekatester
        WORK_DIR=$d; RUN_DIR=$r; FIO_BIN=fio; TARGET_DIR=/dst; MASTER=h1
        run_host() { return 0; }
        cal_evidence seed "$d/cal/res-seed.json" cal-seed.job quiet h1) 2>&1 )
    case "$out2" in
        (*"parses cleanly on its host"*"died at setup"*) true;;
        (*) echo "$out2" >&2; exit 1;;
    esac
    # the fio --client exit-nonzero path (the 05:17 weka-xcpu-344 seed death)
    # says fio'"'"'s own error line, not just "died at setup"
    printf "<h1> fio: pid=0, err=28/file:filesetup.c:233, func=write, error=No space left on device\n{}\n" > "$d/cal/res-seed.json"
    out3=$( (source ./wekatester
        WORK_DIR=$d; RUN_DIR=$r; FIO_BIN=fio; TARGET_DIR=/dst; MASTER=h1
        run_host() { return 0; }
        cal_evidence seed "$d/cal/res-seed.json" cal-seed.job say h1) 2>&1 )
    case "$out3" in
        (*"ERROR: seed: fio said: <h1> fio: pid=0, err=28"*"No space left on device"*"parses cleanly on its host"*) true;;
        (*) echo "$out3" >&2; exit 1;;
    esac'
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
       for i in $(seq 6 37); do
          case $i in (22) printf "\t4";; (23) printf "\t1G";; (24) printf "\t2";;
                     (25) printf "\t16";; (*) printf "\t-";; esac
       done; printf "\n"
       printf "h2"; for i in $(seq 2 37); do printf "\t-"; done; printf "\n"
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
      for i in $(seq 10 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1
    v1="$FIX/jobs/h1/011-bw.job"; v2="$FIX/jobs/h2/011-bw.job"
    grep -q "^directory=/mnt/pin$" "$v1" && grep -q "^directory=/mnt/weka$" "$v2" &&
    # the host file keeps the operator spelling "2,4"; the STAGED job declares
    # what actually executes: weka owns 5-7 and core 0 is the OS, so 2 and 4
    # survive -- the same effective set the calibration ladder measures
    grep -q "^cpus_allowed=2,4$" "$v1" &&
    grep -q "^numjobs=3$" "$v1" && grep -q "^filesize=2G$" "$v1" && grep -q "^iodepth=9$" "$v1" &&
    grep -q "^ioengine=psync$" "$v1" && grep -q "^ioengine=io_uring$" "$v2"'
# The STAGED jobs must never name a cpu the host does not have: the fio
# SERVER rejects the jobfile and its error text is lost, so the layout dies
# with "the jobs did not run" and nothing else (iscg001 2026-08-28 -- the
# cal ladders ran on the trimmed auth/<host>.cpus while the staged variants
# still carried the host file's phantoms).
t_assert "tuner: staged cpus_allowed drops cpus the host does not have" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    { printf "h1\t-\t-\t2,4,9-12\t-"
      for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1
    grep -q "^cpus_allowed=2,4$" "$FIX/jobs/h1/011-bw.job"'
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

# A generic (host-less) row is a default, never the host's own setting. The
# writeback leaves it byte-for-byte alone and gives the host its own line
# carrying what actually ran: the executed cpu list (the staged
# cpus_allowed, i.e. the generic list minus weka's cores), the proven
# engine and the resolved destination -- not copies of the generic values.
t_assert "writeback: a generic cpu list stays as written; the host line records the executed list" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "host,user_login,ioengine,allowed_cpus\n,,,0-127,,,,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    [ "$(sed -n 2p "$f")" = ",,,0-127,,,,,,," ] &&
    ! grep -q "superseded" "$f" &&
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'
t_assert "writeback: generic engine and dir are defaults too; the host line records the proven and resolved ones" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf ",,psync,0-127,/mnt/g,,,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    [ "$(sed -n 1p "$f")" = ",,psync,0-127,/mnt/g,,,,,," ] &&
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'
t_assert "writeback: a host row beside a generic one keeps its own cpu list; the generic row is untouched" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf ",,,0-127,,,,,,,\nh1,opc,,9-11,,,,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; REGEN_LAYOUT=1
     writeback_targets) >/dev/null
    [ "$(sed -n 1p "$f")" = ",,,0-127,,,,,,," ] &&
    grep -q "^# superseded by -a: h1,opc,,9-11" "$f" &&
    tail -1 "$f" | grep -q "^h1,opc,libaio,9-11,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'
t_assert "writeback: a cpu list that differs from the generic one is reason enough for a host line" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf ",ubuntu,libaio,0-127,/mnt/w,,,,,/1G/8/32,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    [ "$(sed -n 1p "$f")" = ",ubuntu,libaio,0-127,/mnt/w,,,,,/1G/8/32," ] &&
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'
t_assert "resolve_targets: hostonly sees the host row and nothing generic; phase1 still folds generics in" bash -c '
    d=$(mktemp -d)
    printf "host,user_login,ioengine,allowed_cpus,destination_folder\n,,,0-127,/mnt/g,,,,,,\nh2,,,4-15,,,,,,,\n" > "$d/hl.csv"
    (source ./wekatester; WORK_DIR=$d
     ho=$(resolve_targets hostonly "$d/hl.csv" - - - h1 h2)
     p1=$(resolve_targets phase1 "$d/hl.csv" - - - h1 h2)
     col() { printf "%s\n" "$1" | grep "^$2	" | cut -f4,5 | tr "\t" " "; }
     [ "$(col "$ho" h1)" = "- -" ] && [ "$(col "$ho" h2)" = "4-15 -" ] &&
     [ "$(col "$p1" h1)" = "0-127 /mnt/g" ] && [ "$(col "$p1" h2)" = "4-15 /mnt/g" ])'
t_assert "writeback: -C set owns the target when -t was not given" bash -c '
    d=$(wb_fixture); mkdir "$d/set"
    (source ./wekatester; write_targets_template "$d/set/hostlist.csv") >/dev/null
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=""; SET_DIR_OVERRIDE=$d/set
     FAST_TRACK=1
     writeback_targets) >/dev/null
    tail -1 "$d/set/hostlist.csv" | grep -q "^h1,ubuntu,libaio,0-3"'
# A mixed-direction file stages ONE direction's tuple, but both directions
# were measured; the writeback must record each measured tuple into its own
# slot, never the staged tuple into both -- numjobs included, since a
# measured tuple always carries its job count.
t_assert "writeback: measured tuples land per direction, numjobs and all; a mixed file cannot copy one over the other" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs/h1" "$d/auth"
    printf "ubuntu\n" > "$d/auth/h1.user"
    printf "# report bandwidth\ncpus_allowed=0-3\ndirectory=/mnt/w\nioengine=libaio\nnumjobs=4\nfilesize=1024M\nnrfiles=2\niodepth=32\nrw=rw\n" > "$d/jobs/h1/011-b.job"
    : > "$d/engine.results"
    printf "h1 libaio 32 2 1024M 4 4 2 1024M 2 - - - - - - - - - - - - - - - - - - - - - - - -\n" > "$d/cal.results"
    f="$d/host.csv"; printf "host,user_login,ioengine\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=cal; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,4/1024M/2/32,2/1024M/2/4,,,,$" ||
        { tail -1 "$f" >&2; false; }'

# The seam that broke on isca224 (2026-08-24): calibrate writes cal.results
# and TWO parsers read it -- apply_cal_results and the writeback. They must
# accept the same width, and the cheapest proof is a row from the shared
# layer's own constants going through both.
t_assert "cal.results: one width, both parsers accept what the shared layer defines" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs" "$d/auth"
    row=$( (source ./wekatester; pyrun <<"PYW"
print("h1 libaio " + " ".join(["4", "2", "1024M", "3"] * len(CAL_SLOTS)))
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

t_assert "tuner: an unbindable cpu never reaches a staged cpus_allowed" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "online 0-7\nbindable 0,1,2,4,6,7\nbindable_priv -\n" >> "$FIX/probe/h1"
    printf "online 0-7\nbindable 0,1,2,4,6,7\nbindable_priv -\n" >> "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    # weka owns 5-7 and the OS 0-1, so 2-4 was usable; 3 refuses the bind
    grep -q "^cpus_allowed=2,4$" "$FIX/jobs/h1/011-bw.job" ||
        { grep "^cpus_allowed=" "$FIX/jobs/h1/011-bw.job" >&2; false; }'
t_assert "tuner: a host-file cpu list is narrowed by the measurement too" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "online 0-7\nbindable 0,1,2,4,6,7\nbindable_priv -\n" >> "$FIX/probe/h1"
    printf "online 0-7\nbindable 0,1,2,4,6,7\nbindable_priv -\n" >> "$FIX/probe/h2"
    { printf "h1\t-\t-\t2-5\t-"
      for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1
    # asked for 2-5: 5 is weka'"'"'s, 3 refuses the bind, 2 and 4 are left
    grep -q "^cpus_allowed=2,4$" "$FIX/jobs/h1/011-bw.job" ||
        { grep "^cpus_allowed=" "$FIX/jobs/h1/011-bw.job" >&2; false; }'

# --- isolcpus awareness (field: isca224, isolcpus=domain,4-55) ---
t_assert "tuner: isolcpus does not narrow cpus_allowed; only weka is excluded" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "isolated 4-7\n" >> "$FIX/probe/h1"
    printf "isolated 4-7\n" >> "$FIX/probe/h2"
    out=$( (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >/dev/null )
    grep -q "^cpus_allowed=2-4$" "$FIX/jobs/h1/011-bw.job" &&
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
        *) grep -q "^cpus_allowed=2-7$" "$FIX/jobs/h1/011-bw.job";;
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
    a=$(pyrun <<< "print(len(FIELDS), slot_base(\"bw_r\"), slot_base(\"iops_w\"), len(CAL_SLOTS), CAL_HEAD, CAL_COLS)") &&
    [ "$a" = "36 5 25 8 2 34" ] &&
    c=$(pyrun <<< "print(\" \".join(CAL_SLOTS))") &&
    [ "$c" = "bw_r bw_w lat_r lat_w iops_r iops_w lat1m_r lat1m_w" ] &&
    d=$(mktemp -d) && write_targets_template "$d/t.csv" >/dev/null &&
    head -1 "$d/t.csv" | grep -q "^host,user_login,ioengine,allowed_cpus,destination_folder,bandwidthR:nj/fs/nr/qd,bandwidthW:nj/fs/nr/qd,latencyR:nj/fs/nr/qd,latencyW:nj/fs/nr/qd,iopsR:nj/fs/nr/qd,iopsW:nj/fs/nr/qd,latency1mR:nj/fs/nr/qd,latency1mW:nj/fs/nr/qd$" &&
    b=$(pyrun <<< "print(\" \".join(sorted(file_directions([\"[x]\", \"rw=randrw:8\"]))))") &&
    [ "$b" = "read write" ]'
t_assert "usable_cores: an operator cpu list is the base, minus weka pins" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    printf "ncpus 8\nweka_allowed 2\nweka_allowed 5\n" > "$d/probe/h1"
    (source ./wekatester; WORK_DIR=$d
     # no list: 8 - weka 2,5 - the reserve 0,1 = 4
     [ "$(usable_cores h1)" = 4 ] &&
     # a list: minus weka and core 0 only
     [ "$(usable_cores h1 count "0-3")" = 2 ] &&
     [ "$(usable_cores h1 list "0-3")" = "1,3" ] &&
     # nothing left is an error naming the arithmetic, never a guess
     ! err=$(usable_cores h1 count "2,5" 2>&1) &&
     case "$err" in (*"leaves fio no cpus"*) true ;; (*) echo "$err" >&2; false ;; esac)'
t_assert "usable_cores: a node's auxiliary threads are not extra weka cores (isca224)" \
    test "$(uc "ncpus 56
weka_allowed 0-3
$(for c in $(seq 14 27); do printf 'weka_allowed %s\n' "$c"; done)")" = 35
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

# -r turns the forcedirect stop into a warning. The write probe still runs
# (a cached mount that is unwritable is still a zero-IO run), and the warning
# is kept for replay into the run log, which does not exist yet at this point.
t_assert "mount guard: -r makes a cached mount mode a warning and still probes writability" bash -c '
    out=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka; FAST_TRACK=1
            run_host() { case "$2" in (findmnt*) echo "wekafs rw,writecache";; (p=*) echo probed >&2;; (*) return 1;; esac; }
            verify_mount_mode && echo "rc=0 kept=${#PRERUN_WARNINGS[@]}") 2>&1 )
    case "$out" in *"must be mounted with forcedirect"*) echo "died: $out" >&2; false;; *) true;; esac &&
    # the warning is said after the loop (one line per mode across hosts), so
    # it may follow the probe; both must have happened, in either order
    case "$out" in
        *"WARNING: localhost: wekafs mounted writecache (need forcedirect); -r continues anyway"*"client cache"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    case "$out" in *probed*"rc=0 kept=1"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "mount guard: -r says a fleet-wide cached mode once, not once per host" bash -c '
    out=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(h1 h2 h3 h4); DIRECTORY=/mnt/weka; FAST_TRACK=1
            run_host() { case "$2" in (findmnt*) echo "wekafs rw,writecache";; (*) return 0;; esac; }
            verify_mount_mode && echo "rc=0 kept=${#PRERUN_WARNINGS[@]}") 2>&1 )
    [ "$(printf "%s\n" "$out" | grep -c "WARNING")" -eq 1 ] &&
    case "$out" in
        *"WARNING: wekafs mounted writecache (need forcedirect) on all 4 hosts; -r continues anyway"*"rc=0 kept=1"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "mount guard: -r names the hosts when only some are cached, one line per mode" bash -c '
    out=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(h1 h2 h3 h4); DIRECTORY=/mnt/weka; FAST_TRACK=1
            run_host() { case "$1:$2" in
                (h1:findmnt*|h3:findmnt*) echo "wekafs rw,writecache";;
                (h2:findmnt*) echo "wekafs rw,readcache";;
                (h4:findmnt*) echo "wekafs rw,forcedirect";;
                (*) return 0;; esac; }
            verify_mount_mode && echo "rc=0 kept=${#PRERUN_WARNINGS[@]}") 2>&1 )
    [ "$(printf "%s\n" "$out" | grep -c "WARNING")" -eq 2 ] &&
    case "$out" in
        *"WARNING: h2: wekafs mounted readcache (need forcedirect); -r continues anyway"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    case "$out" in
        *"WARNING: wekafs mounted writecache (need forcedirect) on 2 of 4 hosts (h1 h3); -r continues anyway"*"rc=0 kept=2"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "mount guard: -r keeps the writability stop on a cached mount" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka; FAST_TRACK=1
            run_host() { case "$2" in (findmnt*) echo "wekafs rw,readcache";; (*) return 1;; esac; }
            verify_mount_mode) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *"must be mounted with forcedirect"*) echo "remount advice under -r: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"WARNING: localhost: wekafs mounted readcache"*"cannot create files in /mnt/weka"*"is not writable on every host"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# Live on the console every time it is raised; kept once per distinct message
# (the mount guard runs twice under -C); replayed into the run log FILE only,
# never back onto the console (seen live: one -r warning printed four times).
t_assert "prerun warnings: logged live, kept deduplicated, replayed into the run log file only" bash -c '
    d=$(mktemp -d); : > "$d/wekatester.log"
    out=$( (source ./wekatester; RUN_DIR=$d
            warn_prerun "a b"; warn_prerun "a b"; warn_prerun "c d"
            echo "kept=${#PRERUN_WARNINGS[@]}"
            replay_prerun_warnings) 2>&1 )
    [ "$(printf "%s\n" "$out" | grep -c "WARNING: a b")" -eq 2 ] &&
    [ "$(printf "%s\n" "$out" | grep -c "WARNING: c d")" -eq 1 ] &&
    case "$out" in *"kept=2"*) true;; *) echo "$out" >&2; false;; esac &&
    [ "$(grep -c "WARNING (before the run log opened): a b" "$d/wekatester.log")" -eq 1 ] &&
    [ "$(grep -c "WARNING (before the run log opened): c d" "$d/wekatester.log")" -eq 1 ] &&
    (source ./wekatester; RUN_DIR=""; replay_prerun_warnings) &&
    x=$( (source ./wekatester; RUN_DIR=$d/nope; warn_prerun x; replay_prerun_warnings) 2>&1 ) &&
    [ ! -e "$d/nope" ] &&
    # the run dir exists but the tee has not created the log yet: the replay
    # must create it rather than skip -- the race a real run has every time
    e=$(mktemp -d) && [ ! -e "$e/wekatester.log" ] &&
    y=$( (source ./wekatester; RUN_DIR=$e; warn_prerun "e f"; replay_prerun_warnings) 2>&1 ) &&
    [ "$(grep -c "WARNING (before the run log opened): e f" "$e/wekatester.log")" -eq 1 ]'

# A missing destination is created when its nearest existing parent is a
# wekafs mount in an acceptable mode. Stubs discriminate the four remote
# commands by their leading token: findmnt, the "[ ! -e" ancestor walk,
# mkdir, and the p= write probe.
t_assert "mount guard: missing -d under forcedirect wekafs is created unattended under -r, then probed" bash -c '
    out=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2); DIRECTORY=/mnt/weka/wt; FAST_TRACK=1
            run_host() { case "$2" in
                (findmnt*)  return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nwekafs rw,relatime,forcedirect\n";;
                (mkdir*)    echo "MKDIR[$1] $2" >&2;;
                (p=*)       echo "PROBE[$1]" >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode && echo rc=0) 2>&1 )
    case "$out" in
        *"h1: /mnt/weka/wt does not exist; /mnt/weka is a wekafs mount"*"h2: /mnt/weka/wt does not exist"*"does not exist on 2 host(s); creating it (unattended)"*"MKDIR[h1] mkdir -p -- '"'"'/mnt/weka/wt'"'"'"*"h1: created /mnt/weka/wt"*"PROBE[h1]"*"MKDIR[h2]"*"PROBE[h2]"*rc=0*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "mount guard: missing -d without -r needs a terminal and creates nothing" bash -c '
    err=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt
            run_host() { case "$2" in
                (findmnt*)  return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nwekafs rw,forcedirect\n";;
                (mkdir*)    echo MKDIR >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *MKDIR*) echo "created without a terminal: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"creating the destination directory needs a terminal; create it yourself, or use -r"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: the create prompt -- y creates, n quits without touching the host" bash -c '
    source ./wekatester; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
    LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt
    run_host() { case "$2" in
        (findmnt*)  return 1;;
        ("[ ! -e"*) printf "/mnt/weka\nwekafs rw,forcedirect\n";;
        (mkdir*)    echo MKDIR >&2;;
        (*)         return 0;; esac; }
    yes_out=$(printf y | { verify_mount_mode; } 2>&1); yes_rc=$?
    no_out=$(printf n | { verify_mount_mode; } 2>&1); no_rc=$?
    [ "$yes_rc" -eq 0 ] || { echo "y: rc=$yes_rc $yes_out" >&2; false; } &&
    case "$yes_out" in *"create the missing destination directory on 1 host(s)? [y = create, n = quit]"*MKDIR*) true;; *) echo "y: $yes_out" >&2; false;; esac &&
    [ "$no_rc" -ne 0 ] || { echo "n: rc=0 $no_out" >&2; false; } &&
    case "$no_out" in *MKDIR*) echo "n created: $no_out" >&2; false;; *"destination directory does not exist on 1 host(s)"*) true;; *) echo "n: $no_out" >&2; false;; esac'
t_assert "mount guard: missing -d whose parent is not wekafs is never created, even under -r" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/wkea; FAST_TRACK=1
            run_host() { case "$2" in
                (findmnt*)  return 1;;
                ("[ ! -e"*) printf "/mnt\nxfs rw,relatime\n";;
                (mkdir*)    echo MKDIR >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *MKDIR*) echo "created under a non-wekafs parent: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"/mnt/wkea does not exist, and /mnt is not a wekafs mount -- create it yourself"*"-d names the right directory"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: missing -d under a cached-mode parent stops without -r and creates nothing" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt
            run_host() { case "$2" in
                (findmnt*)  return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nwekafs rw,writecache\n";;
                (mkdir*)    echo MKDIR >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *MKDIR*) echo "created on a mode failure: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"localhost: wekafs mounted writecache (need forcedirect)"*"must be mounted with forcedirect; remount"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: -r under a cached-mode parent warns, creates and probes" bash -c '
    out=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt; FAST_TRACK=1
            run_host() { case "$2" in
                (findmnt*)  return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nwekafs rw,writecache\n";;
                (mkdir*)    echo MKDIR >&2;;
                (p=*)       echo PROBED >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode && echo rc=0) 2>&1 )
    case "$out" in
        *"WARNING: localhost: wekafs mounted writecache"*"creating it (unattended)"*MKDIR*PROBED*rc=0*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "mount guard: nothing is created while another host fails" bash -c '
    err=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2); DIRECTORY=/mnt/weka/wt; FAST_TRACK=0
            run_host() { case "$1:$2" in
                (h1:findmnt*)  echo "wekafs rw,writecache";;
                (h2:findmnt*)  return 1;;
                (h2:"[ ! -e"*) printf "/mnt/weka\nwekafs rw,forcedirect\n";;
                (*:mkdir*)     echo MKDIR >&2;;
                (*)            return 1;; esac; }
            verify_mount_mode) 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *MKDIR*) echo "mutated before a stop: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"h2: /mnt/weka/wt does not exist; not created while other checks fail"*"h1: wekafs mounted writecache"*"must be mounted with forcedirect"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: a failed mkdir dies with the chmod hint naming the parent" bash -c '
    err=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt; FAST_TRACK=1
            run_host() { case "$2" in
                (findmnt*)  return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nwekafs rw,forcedirect\n";;
                (mkdir*)    return 1;;
                (*)         echo PROBED >&2;; esac; }
            verify_mount_mode) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *PROBED*) echo "probed a directory that was not created: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"localhost: cannot create /mnt/weka/wt -- fix the root'"'"'s owner/mode (a one-time '"'"'sudo chmod 1777 /mnt/weka'"'"'"*"is not writable on every host"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# The ancestor walk itself, against a real filesystem: findmnt is stubbed to
# echo its arguments, so the second line pins which path it was asked about.
t_assert "mount guard: the missing-dir snippet walks up to the nearest existing ancestor" bash -c '
    tmp=$(mktemp -d); stub=$(mktemp -d)
    printf "#!/bin/sh\necho \"stubfs rw,opts \$*\"\n" > "$stub/findmnt"; chmod +x "$stub/findmnt"
    out=$(source ./wekatester; PATH="$stub:$PATH" bash -c "$(missing_dir_probe_cmd "$tmp/a/b/c/")")
    [ "$out" = "$tmp
stubfs rw,opts -T $tmp -n -o FSTYPE,OPTIONS" ] || { echo "$out" >&2; false; }'
t_assert "mount guard: the missing-dir snippet fails when the directory exists" bash -c '
    tmp=$(mktemp -d)
    out=$(source ./wekatester; bash -c "$(missing_dir_probe_cmd "$tmp")"); rc=$?
    [ "$rc" -ne 0 ] && [ -z "$out" ]'

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

# --- calibration: per client shape, solo, one search per test type ---------
# Rulings (2026-09-23): bandwidth = line rate on 1M IO (95% counts), iops =
# the maximum with latency accounting off, latency = the floor then as many
# jobs as stay within 5% of it; clients grouped into hardware shapes, each
# calibrated SOLO on its first host, the answer written for every member.

# The cell file is the whole measurement contract; compared VERBATIM so a
# stray or missing line fails.
t_assert "stage_cal_cell: a bw read cell is exactly this, no more" bash -c '
    d=$(mktemp -d)
    (source ./wekatester; CAL_NS_DIR=/.wekatester-cal; CAL_SEP=.cal.; CAL_FMT="\$jobnum.\$filenum"
     stage_cal_cell "$d/c.job" /mnt/weka h1 "1-3" bw read io_uring 3 2 2 30)
    printf "%s\n" "[global]" "directory=/mnt/weka/.wekatester-cal" "unique_filename=0" \
        "filename_format=h1.cal.\$jobnum.\$filenum" "ioengine=io_uring" "direct=1" "bs=1Mi" \
        "filesize=2560M" "nrfiles=2" "numjobs=3" "iodepth=2" "time_based=1" "runtime=30" \
        "ramp_time=2" "group_reporting=1" "cpus_allowed=1-3" "cpus_allowed_policy=split" \
        "[cal-bw-read]" "rw=read" > "$d/want"
    diff -u "$d/want" "$d/c.job"'
t_assert "stage_cal_cell: iops cells run with latency accounting off, lat and bw cells do not" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     stage_cal_cell "$d/i.job" /mnt/weka h1 "" iops write libaio 4 16 2 30
     stage_cal_cell "$d/l.job" /mnt/weka h1 "" lat read psync 1 1 2 30
     stage_cal_cell "$d/b.job" /mnt/weka h1 "" bw write io_uring 2 1 2 30)
    for k in disable_lat disable_clat disable_slat norandommap; do
        grep -qx "$k=1" "$d/i.job" || { echo "iops lacks $k" >&2; exit 1; }
        ! grep -q "^$k=" "$d/l.job" || { echo "lat has $k" >&2; exit 1; }
        ! grep -q "^$k=" "$d/b.job" || { echo "bw has $k" >&2; exit 1; }
    done
    grep -qx "rw=randwrite" "$d/i.job" && grep -qx "bs=4k" "$d/i.job" &&
    grep -qx "rw=randread" "$d/l.job" && grep -qx "ioengine=psync" "$d/l.job" &&
    ! grep -q "^cpus_allowed" "$d/l.job" && grep -qx "group_reporting=1" "$d/l.job" &&
    ! grep -q "^create" "$d/b.job" && ! grep -q "create_on_open" "$d/b.job"'
t_assert "stage_cal_cell: unified reads open the shared dataset, writes the host own files" bash -c '
    d=$(mktemp -d)
    (source ./wekatester; CAL_NS_DIR=""; CAL_SEP=.; CAL_FMT="\$filenum/\$jobnum"
     stage_cal_cell "$d/r.job" /mnt/weka h1 "" bw read io_uring 2 1 2 30
     stage_cal_cell "$d/w.job" /mnt/weka h1 "" bw write io_uring 2 1 2 30)
    grep -qx "directory=/mnt/weka" "$d/r.job" &&
    grep -qx "filename_format=shared.\$filenum/\$jobnum" "$d/r.job" &&
    grep -qx "filename_format=h1.\$filenum/\$jobnum" "$d/w.job"'
t_assert "stage_cal_cell: a bad type, direction, engine or number dies" bash -c '
    d=$(mktemp -d)
    f() { (source ./wekatester; stage_cal_cell "$d/x.job" /mnt/weka h1 "" "$@") >/dev/null 2>&1; }
    ! f bogus read io_uring 1 1 2 30 && ! f bw sideways io_uring 1 1 2 30 &&
    ! f bw read io_uring 0 1 2 30 && ! f bw read io_uring 1 qd8 2 30 &&
    ! f bw read "" 1 1 2 30 && f bw read io_uring 1 1 2 30'

# --- cal_plan: the search rules, driven against a client with a known curve ---
# N is the shape's usable PHYSICAL cores; the job counts are Frank's
# (2026-09-25): N/2 and N one job per physical core at iodepth=1 nrfiles=1 --
# no queue or file ladder at or below N -- then 2N and 4N with the siblings
# in, where the iodepth and nrfiles ladders run.
K='exh=0 line=95 floor=5 band=98.5 thr=2 stop=2 confirm=3 rt=30 nr=1 nrc=1,2,4 bwqd=1,2,4,8,16 iopsqd=1,2,4,8,16,32,64,128,256,512 floorreps=3'
export K
t_assert "cal_plan bw: the first numjobs at 95% of line rate is the answer, one job per physical core, nothing after it" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_STREAM=2147483648 CAL_SIM_BWCAP=12670000000 plan_sim "$d" bw read io_uring 16 12500000000 0)
    case "$out" in
        "done 8 1 1 numjobs=8 iodepth=1 nrfiles=1 -> 11.80 GiB/s = 101.4% of the 11.64 GiB/s line rate (the first numjobs at >= 95% of line rate, one job per physical core)") true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 1 1 1;numjobs 2 1 1;numjobs 4 1 1;numjobs 8 1 1;" ] ||
        { cat "$d/asked" >&2; false; }'
t_assert "cal_plan bw: short of line rate, 2N walks iodepth for every nrfiles; 2N not beating N skips 4N" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_BWCAP=9663676416 plan_sim "$d" bw write libaio 16 12500000000 0)
    case "$out" in
        "done 16 1 1 numjobs=16 iodepth=1 nrfiles=1 -> 9.00 GiB/s (best of 2) = 77.3% of the 11.64 GiB/s line rate (never reached 95% of line rate; the peak, one job per physical core); 2N (32 jobs, siblings in) did not beat N; 4N was not tried") true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 1 1 1;numjobs 2 1 1;numjobs 4 1 1;numjobs 8 1 1;numjobs 16 1 1;wide 32 1 1;wide 32 2 1;wide 32 4 1;wide 32 1 2;wide 32 2 2;wide 32 4 2;wide 32 1 4;wide 32 2 4;wide 32 4 4;confirm 16 1 1;confirm 32 1 1;confirm 32 1 2;" ] ||
        { cat "$d/asked" >&2; false; }'
t_assert "cal_plan bw: no line rate, the job ladder stops where it flattens" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_BWCAP=4294967296 plan_sim "$d" bw read io_uring 32 0 0)
    case "$out" in "done 4 1 1 numjobs=4 iodepth=1 nrfiles=1 -> 4.00 GiB/s (best of 2) (the peak, one job per physical core); 2N (64 jobs, siblings in) did not beat N; 4N was not tried") true;;
        *) echo "$out" >&2; false;; esac &&
    ! grep -q "^numjobs 32 " "$d/asked" && grep -q "^numjobs 16 " "$d/asked" &&
    grep -q "^wide 64 1 1$" "$d/asked" && ! grep -q "^wide 128 " "$d/asked"'
t_assert "cal_plan bw: a reading well above line rate means line rate is not the ceiling" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" bw read io_uring 16 12500000000 0)
    case "$out" in
        "done 32 1 1 "*"(the peak, siblings in); a reading beat the NIC line rate by more than 5%, so line rate is not this client"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "cal_plan bw: the memory guard ends a queue ladder and says so, once per job count and depth" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_BWCAP=9663676416 plan_sim "$d" bw read io_uring 4 12500000000 8388608)
    grep -q "^wide 8 1 4$" "$d/asked" && ! grep -q "^wide 8 2 " "$d/asked" && ! grep -q "^wide 16 " "$d/asked" &&
    case "$out" in *"the queue ladder stopped short of numjobs=8 iodepth=2: its in-flight buffers exceed the memory guard (CAL_MEM_PCT); the queue ladder stopped short of numjobs=16 iodepth=1: its"*) true;;
        *) echo "$out" >&2; false;; esac &&
    [ "$(printf "%s" "$out" | grep -o "numjobs=8 iodepth=2:" | wc -l | tr -d " ")" = 1 ]'
t_assert "cal_plan iops: N/2 and N at qd1, then 2N and 4N walk the queue ladder, nrfiles at each winner, then the peak" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" iops read io_uring 16 0 0)
    case "$out" in
        "done 32 2 1 numjobs=32 iodepth=2 nrfiles=1 -> 1,000,000 IOPS (best of 2) (8 jobs 160,000 IOPS at iodepth 1, 16 jobs 320,000 IOPS at iodepth 1, 32 jobs 1,000,000 IOPS at iodepth 2 nrfiles 1, 64 jobs 1,000,000 IOPS at iodepth 1 nrfiles 1; siblings in)") true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 8 1 1;numjobs 16 1 1;iodepth 32 1 1;iodepth 32 2 1;iodepth 32 4 1;iodepth 32 8 1;nrfiles 32 2 2;nrfiles 32 4 2;nrfiles 32 2 4;nrfiles 32 4 4;iodepth 64 1 1;iodepth 64 2 1;iodepth 64 4 1;nrfiles 64 1 2;nrfiles 64 2 2;nrfiles 64 1 4;nrfiles 64 2 4;confirm 32 2 1;confirm 32 2 2;confirm 32 2 4;" ] ||
        { cat "$d/asked" >&2; false; }'
t_assert "cal_plan iops: no queue or file ladder at or below N" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    plan_sim "$d" iops write io_uring 16 0 0 >/dev/null
    ! awk "\$2 <= 16 && (\$3 != 1 || \$4 != 1)" "$d/asked" | grep -q . ||
        { awk "\$2 <= 16" "$d/asked" >&2; false; }'
t_assert "cal_plan iops: a file count that wins is recorded" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_IOPSKNEE=64 CAL_SIM_NRBEST=4 plan_sim "$d" iops write io_uring 16 0 0)
    case "$out" in "done 32 2 4 numjobs=32 iodepth=2 nrfiles=4 -> 1,030,000 IOPS"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "cal_plan iops: 2N that does not beat N ends the search before 4N" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_IOPSCAP=100000 plan_sim "$d" iops read io_uring 16 0 0)
    case "$out" in "done 8 1 1 "*"2N (32 jobs, siblings in) did not beat N; 4N was not tried") true;; *) echo "$out" >&2; false;; esac &&
    ! grep -q " 64 " "$d/asked"'
t_assert "cal_plan iops: a sync engine keeps iodepth at 1 and still walks the job counts and files" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" iops read psync 8 0 0)
    case "$out" in "done 32 1 1 numjobs=32 iodepth=1 nrfiles=1 -> 640,000 IOPS"*) true;; *) echo "$out" >&2; false;; esac &&
    ! awk "\$3 != 1" "$d/asked" | grep -q . &&
    grep -q "^numjobs 4 1 1$" "$d/asked" && grep -q "^nrfiles 16 1 4$" "$d/asked"'
t_assert "cal_plan lat: floor from three readings, widen at nrfiles=1 while inside 5%, the last rung inside wins" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" lat read io_uring 16 0 0)
    case "$out" in
        "done 8 1 1 floor 100.0 us (lowest of 3 at numjobs=1), band <= 105.0 us; numjobs=8 nrfiles=1 stays at the floor (one job per physical core): 100.0 us, 80,000 IOPS; numjobs=16 left the band at 260.0 us (re-measured)") true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(tr "\n" ";" < "$d/asked")" = "floor 1 1 1;floor 1 1 1;floor 1 1 1;widen 2 1 1;widen 4 1 1;widen 8 1 1;widen 16 1 1;recheck 16 1 1;" ] ||
        { cat "$d/asked" >&2; false; }'
t_assert "cal_plan lat: past N every nrfiles is tried, and the one that stays at the floor wins" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    # 16 jobs (2N) are 10us out of the band at one file per job; two files
    # per job take 10% off and bring 16 jobs back inside it
    out=$(CAL_SIM_WIDE=14 CAL_SIM_LATSTEP=5 CAL_SIM_LATNRBEST=2 plan_sim "$d" lat read io_uring 8 0 0)
    case "$out" in
        "done 16 1 2 floor 100.0 us (lowest of 3 at numjobs=1), band <= 105.0 us; numjobs=16 nrfiles=2 stays at the floor (siblings in): 99.0 us, 161,616 IOPS; numjobs=32 left the band at 171.0 us (re-measured); numjobs=16: nrfiles 1 110.0 us, nrfiles 2 99.0 us, nrfiles 4 110.0 us; numjobs=32: nrfiles 1 190.0 us, nrfiles 2 171.0 us, nrfiles 4 190.0 us") true;;
        *) echo "$out" >&2; false;;
    esac &&
    ! awk "\$2 <= 8 && \$4 != 1" "$d/asked" | grep -q .'
t_assert "cal_plan lat1m: the same search at 1MiB, with a floor of its own" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" lat1m write io_uring 4 0 0)
    case "$out" in "done 8 1 1 1MiB floor 800.0 us (lowest of 3 at numjobs=1), band <= 840.0 us; numjobs=8 nrfiles=1 stays at the floor (siblings in)"*) true;;
        *) echo "$out" >&2; false;; esac'
# Hand-built histories pin the decisions that a smooth model never exercises.
t_assert "cal_plan lat: the floor is the lowest reading, and a rung that leaves the band gets one re-measure" bash -c '
    d=$(mktemp -d)
    printf "floor psync 1 1 1 30 130 7000\nfloor psync 1 1 1 30 100 9000\nfloor psync 1 1 1 30 120 8000\nwiden psync 2 1 1 30 140 14000\n" > "$d/h"
    a=$(source ./wekatester; cal_plan next lat read psync 8 0 0 "$d/h" $K)
    [ "$a" = "cell recheck 2 1 1 30" ] || { echo "a=$a" >&2; exit 1; }
    # the re-measure came back inside 105us of the 100us floor: keep widening
    printf "recheck psync 2 1 1 30 104 19000\n" >> "$d/h"
    b=$(source ./wekatester; cal_plan next lat read psync 8 0 0 "$d/h" $K)
    [ "$b" = "cell widen 4 1 1 30" ] || { echo "b=$b" >&2; exit 1; }
    # 4 is out twice: the answer is 2, with the IOPS it did at the floor
    printf "widen psync 4 1 1 30 150 25000\nrecheck psync 4 1 1 30 151 25000\n" >> "$d/h"
    c=$(source ./wekatester; cal_plan next lat read psync 8 0 0 "$d/h" $K)
    case "$c" in "done 2 1 1 floor 100.0 us (lowest of 3 at numjobs=1), band <= 105.0 us; numjobs=2 nrfiles=1 stays at the floor (one job per physical core): 104.0 us, 19,000 IOPS; numjobs=4 left the band at 150.0 us (re-measured)") true;;
        *) echo "c=$c" >&2; false;; esac'
t_assert "cal_plan: a confirm reading never reopens a step that is already decided" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    plan_sim "$d" iops read io_uring 16 0 0 >/dev/null
    # a late, much higher confirm reading for a ladder cell changes the pick,
    # but the planner must not go back and measure more ladder or file cells
    printf "confirm io_uring 32 4 1 30 2000000\n" >> "$d/hist"
    a=$(source ./wekatester; cal_plan next iops read io_uring 16 0 0 "$d/hist" $K)
    case "$a" in "done 32 4 1 "*) true;; *) echo "a=$a" >&2; false;; esac'
t_assert "cal_plan brutal: every combination the ladders define is measured, and bandwidth takes the peak" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_STREAM=2147483648 CAL_SIM_BWCAP=12670000000 plan_sim "$d" bw read io_uring 16 12500000000 0 exh=1 confirm=5)
    grep -q "^numjobs 16 1 1$" "$d/asked" && grep -q "^wide 64 16 4$" "$d/asked" &&
    [ "$(grep -c "^wide " "$d/asked")" = 30 ] &&
    case "$out" in "done 8 1 1 "*"(the peak of every rung measured, one job per physical core)") true;; *) echo "$out" >&2; false;; esac &&
    out=$(plan_sim "$d" iops read io_uring 16 0 0 exh=1 confirm=5) &&
    [ "$(grep -c -v "^confirm " "$d/asked")" = 62 ] &&
    out=$(plan_sim "$d" lat read io_uring 32 0 0 exh=1) &&
    grep -q "^widen 32 1 1$" "$d/asked" && grep -q "^nrfiles 128 1 4$" "$d/asked" &&
    case "$out" in "done 8 1 1 "*"numjobs=16 left the band"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "cal_plan budget: the most cells a search can take" bash -c '
    a=$(source ./wekatester; cal_plan budget bw read x 16 0 0 /dev/null $K)
    b=$(source ./wekatester; cal_plan budget lat read x 16 0 0 /dev/null $K)
    c=$(source ./wekatester; cal_plan budget iops read x 16 0 0 /dev/null $K)
    e=$(source ./wekatester; cal_plan budget iops read x 16 0 0 /dev/null $K exh=1 confirm=5)
    [ "$a" = 38 ] && [ "$b" = 23 ] && [ "$c" = 33 ] && [ "$e" = 67 ] ||
        { echo "bw=$a lat=$b iops=$c brutal-iops=$e" >&2; false; }'

# --- N from physical cores (Frank, 2026-09-25): topology, the reserve, placement ---
# topo_fixture <file> <ncpus> <adjacent|split> <weka cpus...>: a probe file with
# one core per sibling pair, numbered 2i/2i+1 (adjacent, as OCI VMs do) or
# i/i+n/2 (split, as most x86 servers do), one socket
topo_fixture() {
    local f=$1 n=$2 how=$3 c k; shift 3
    { printf "ncpus %s\nonline 0-%s\nengines io_uring libaio psync \n" "$n" "$((n - 1))"
      for c in "$@"; do printf "weka_allowed %s\n" "$c"; done
      for c in $(seq 0 $((n - 1))); do
          if [ "$how" = adjacent ]; then k="$(( c / 2 * 2 ))-$(( c / 2 * 2 + 1 ))"
          else k="$(( c % (n / 2) )),$(( c % (n / 2) + n / 2 ))"; fi
          printf "topo_physical_package_id %s 0\ntopo_core_id %s %s\ntopo_thread_siblings_list %s %s\n" "$c" "$c" "$c" "$c" "$k"
      done; } > "$f"
}
export -f topo_fixture
t_assert "probe_cores: N counts physical cores; weka's DPDK cores leave with their siblings, core 0's pair stays with the OS" bash -c '
    d=$(mktemp -d); topo_fixture "$d/p" 16 adjacent 12 14
    (source ./wekatester; pyrun "$d/p" <<"EOF"
import sys
c = probe_cores(sys.argv[1])
assert c["n"] == 4 and c["ncores"] == 8 and c["dpdk"] == 2, c
assert c["phys"] == [4, 6, 8, 10] and c["all"] == list(range(4, 12)), c
assert c["reserved"] == [[0, 1], [2, 3]] and c["smt"] and c["topo"], c
EOF
    )'
t_assert "probe_cores: siblings numbered i and i+8 are found from the topology, not by adjacency" bash -c '
    d=$(mktemp -d); topo_fixture "$d/p" 16 split 6 7
    (source ./wekatester; pyrun "$d/p" <<"EOF"
import sys
c = probe_cores(sys.argv[1])
assert c["n"] == 4 and c["phys"] == [2, 3, 4, 5], c
assert c["all"] == [2, 3, 4, 5, 10, 11, 12, 13], c
assert c["reserved"] == [[0, 8], [1, 9]], c
EOF
    )'
t_assert "probe_cores: two sockets reserve core 0 and the next of socket 0, then the first two of socket 1; 5-8 DPDK cores add one" bash -c '
    d=$(mktemp -d)
    { printf "ncpus 64\nonline 0-63\n"
      for c in $(seq 24 31); do printf "weka_allowed %s\n" "$c"; done
      for c in $(seq 0 63); do k=$(( c % 32 ))
          printf "topo_physical_package_id %s %s\ntopo_core_id %s %s\ntopo_thread_siblings_list %s %s,%s\n" $c $(( k / 16 )) $c $k $c $k $(( k + 32 )); done; } > "$d/p"
    (source ./wekatester; pyrun "$d/p" <<"EOF"
import sys
c = probe_cores(sys.argv[1])
assert c["ncores"] == 32 and c["dpdk"] == 8 and c["sockets"] == 2, c
assert [t[0] for t in c["reserved"]] == [0, 16, 1, 17, 2], c["reserved"]
assert c["n"] == 32 - 8 - 5, c
EOF
    )'
t_assert "reserve rules: 2 up to 24 cores, 4 above, +1 per 4 DPDK past 4, at most 12 and half; round-robin placement" bash -c '
    (source ./wekatester; pyrun <<"EOF"
assert reserve_count(8, 2) == 2 and reserve_count(24, 4) == 2 and reserve_count(25, 4) == 4
assert reserve_count(64, 5) == 5 and reserve_count(64, 8) == 5 and reserve_count(64, 9) == 6
assert reserve_count(200, 64) == 12, "at most 12"
assert reserve_count(4, 8) == 2, "never more than half the cores"
assert reserve_count(2, 0) == 1, "core 0 always"
order = list(range(8))
one = dict((k, 0) for k in order)
assert place_reserve(order, one, set(), 0, 4) == [0, 1, 2, 3]
four = {0: 0, 1: 0, 2: 1, 3: 1, 4: 2, 5: 2, 6: 3, 7: 3}
assert place_reserve(order, four, set(), 0, 4) == [0, 2, 4, 6], "one core per socket"
assert place_reserve(order, one, {0, 1}, 0, 2) == [2, 3], "a DPDK core is never reserved, not even core 0"
EOF
    )'
t_assert "usable_cores: a client too small for its DPDK cores stops, naming the arithmetic" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    # lab 3 as built: 8 cores, 6 of them weka DPDK -- the reserve wants 3, gets 2
    topo_fixture "$d/probe/h1" 16 adjacent 4 6 8 10 12 14
    err=$( (source ./wekatester; WORK_DIR=$d; usable_cores h1) 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && case "$err" in *"leaves fio no cpus: 8 physical core(s) - 6 weka DPDK - 2 reserved for the OS (0-1 2-3) = N=0"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "probe: the cpu topology comes from sysfs as topo lines" bash -c '
    d=$(mktemp -d); r=$d/root
    for c in 0 1; do mkdir -p "$r/sys/devices/system/cpu/cpu$c/topology"
        echo 0 > "$r/sys/devices/system/cpu/cpu$c/topology/physical_package_id"
        echo 0 > "$r/sys/devices/system/cpu/cpu$c/topology/core_id"
        echo 0-1 > "$r/sys/devices/system/cpu/cpu$c/topology/thread_siblings_list"; done
    cmd=$(source ./wekatester; FIO_BIN=fio; probe_remote_cmd)
    out=$(WEKATESTER_SYSROOT=$r bash -c "$cmd" 2>&1)
    printf "%s\n" "$out" | grep -qx "topo_thread_siblings_list 1 0-1" &&
    printf "%s\n" "$out" | grep -qx "topo_core_id 0 0" &&
    printf "%s\n" "$out" | grep -qx "topo_physical_package_id 1 0" || { printf "%s\n" "$out" >&2; false; }'
t_assert "tuner: a job count at or below N runs one job per physical core; above N the siblings join" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    topo_fixture "$FIX/probe/h1" 16 adjacent 12 14; cp "$FIX/probe/h1" "$FIX/probe/h2"
    row() { printf "h1\t-\t-\t-\t-\t%s\t-\t-\t-" "$1"; for i in $(seq 10 37); do printf "\t-"; done; printf "\n"; }
    row 4 > "$FIX/targets.final"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1
    grep -qx "cpus_allowed=4,6,8,10" "$FIX/jobs/h1/011-bw.job" || { grep cpus_allowed "$FIX/jobs/h1/011-bw.job" >&2; exit 1; }
    # h2 has no host-file row: max runs a job on every usable thread, 8 > N
    grep -qx "numjobs=8" "$FIX/jobs/h2/011-bw.job" && grep -qx "cpus_allowed=4-11" "$FIX/jobs/h2/011-bw.job" &&
    row 8 > "$FIX/targets.final" &&
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1 &&
    grep -qx "cpus_allowed=4-11" "$FIX/jobs/h1/011-bw.job"'

# --- -b: every latency test also at 1MiB; -a cal/brutal: a one-job twin beside each ---
t_assert "-b sets bulk; off by default" bash -c '
    source ./wekatester; parse_args h1; [ "$BULK" -eq 0 ] &&
    parse_args -b h1 && [ "$BULK" -eq 1 ] && parse_args --BULK h1 && [ "$BULK" -eq 1 ]'
t_assert "stage_bulk_twins: every 4k latency file gains a 1MiB twin right after it; nothing else does" bash -c '
    d=$(mktemp -d)
    printf "# report latency iops\n[global]\nfilename_format=\$filenum/\$jobnum\n[c]\nblocksize=1Mi\ncreate_only=1\n[l]\nbs=4k\nrw=randread\n" > "$d/021-latencyR.job"
    printf "# report latency\n[global]\n[l]\nrw=randwrite\n" > "$d/022-latencyW.job"
    printf "# report iops\n[global]\n[i]\nbs=4k\nrw=randread\n" > "$d/031-iopsR.job"
    printf "# report latency\n[global]\nbs=1Mi\n[l]\nrw=randread\n" > "$d/023-big.job"
    out=$(source ./wekatester; stage_bulk_twins "$d")
    [ "$out" = "021b-latencyR-1M.job 022b-latencyW-1M.job" ] || { echo "out=$out" >&2; exit 1; }
    t="$d/021b-latencyR-1M.job"; u="$d/022b-latencyW-1M.job"
    grep -qx "bs=1Mi" "$t" && ! grep -q "^bs=4k" "$t" && grep -qx "blocksize=1Mi" "$t" &&
    grep -qx "filename_format=\$filenum/\$jobnum" "$t" && grep -qx "rw=randread" "$t" &&
    grep -qx "bs=1Mi" "$u" && [ ! -e "$d/031b-iopsR-1M.job" ] && [ ! -e "$d/023b-big-1M.job" ] &&
    (source ./wekatester; discover_jobfiles "$d"; [ "${JOBFILES[*]}" = "021-latencyR.job 021b-latencyR-1M.job 022-latencyW.job 022b-latencyW-1M.job 023-big.job 031-iopsR.job" ])'
t_assert "stage_floor_twins: every latency file gains a one-job twin that runs just before it" bash -c '
    d=$(mktemp -d)
    printf "# report latency iops\n[global]\n[l]\nbs=4k\nrw=randread\n" > "$d/021-latencyR.job"
    printf "# report iops\n[global]\n[i]\nrw=randread\n" > "$d/031-iopsR.job"
    out=$(source ./wekatester; stage_floor_twins "$d")
    [ "$out" = "021-latencyR-1job.job" ] && [ ! -e "$d/031-iopsR-1job.job" ] &&
    head -1 "$d/021-latencyR-1job.job" | grep -q "^# wekatester-floor: 021-latencyR.job" &&
    (source ./wekatester; discover_jobfiles "$d"; [ "${JOBFILES[*]}" = "021-latencyR-1job.job 021-latencyR.job 031-iopsR.job" ])'
t_assert "tuner: a one-job latency twin runs numjobs=iodepth=nrfiles=1 with its original's data per job" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    rm -f "$FIX/src/011-bw.job"
    printf "# report latency\n[global]\nfilesize=10G\nnumjobs=1\nioengine=libaio\n[lat]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; stage_floor_twins "$FIX/src") >/dev/null
    # the calibrated lat_r tuple: 3 jobs, 4 files of 1280M, qd 1 (cols 14-17)
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (14) printf "\t3";; (15) printf "\t1280M";; (16) printf "\t4";; (17) printf "\t1";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1
    v="$FIX/jobs/h1/021-lat.job"; f="$FIX/jobs/h1/021-lat-1job.job"
    grep -qx "numjobs=3" "$v" && grep -qx "filesize=1280M" "$v" && grep -qx "nrfiles=4" "$v" &&
    grep -qx "numjobs=1" "$f" && grep -qx "iodepth=1" "$f" && grep -qx "nrfiles=1" "$f" &&
    grep -qx "filesize=5120M" "$f" && grep -qx "cpus_allowed=2-4" "$f" || { cat "$f" >&2; false; }'
t_assert "stage_cal_cell: a lat1m cell reads 1MiB blocks at random, and a job's data is split over its files" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     stage_cal_cell "$d/l.job" /mnt/weka h1 "" lat1m read io_uring 2 1 4 30)
    grep -qx "bs=1Mi" "$d/l.job" && grep -qx "rw=randread" "$d/l.job" &&
    grep -qx "filesize=1280M" "$d/l.job" && grep -qx "nrfiles=4" "$d/l.job" &&
    grep -qx "\[cal-lat1m-read\]" "$d/l.job" && ! grep -q "^disable_lat" "$d/l.job"'
t_assert "cal_required: -b adds a 1MiB latency search beside every 4k one; a 1MiB latency file is its own" bash -c '
    d=$(mktemp -d)
    printf "# report latency\n[global]\n[a]\nbs=4k\nrw=randread\n" > "$d/021-r.job"
    a=$(source ./wekatester; cal_required "$d" | tr "\n" ";")
    b=$(source ./wekatester; cal_required "$d" 1 | tr "\n" ";")
    printf "# report latency\n[global]\nbs=1Mi\n[a]\nrw=randwrite\n" > "$d/022-w.job"
    c=$(source ./wekatester; cal_required "$d" | tr "\n" ";")
    [ "$a" = "lat read;" ] && [ "$b" = "lat read;lat1m read;" ] && [ "$c" = "lat read;lat1m write;" ] ||
        { echo "a=$a b=$b c=$c" >&2; false; }'
t_assert "targets: the 1MiB latency columns come last, and an 11-column row still parses" bash -c '
    f=$(mktemp)
    printf "h1,,,,,,,,,,,latency1mR:2/5120M/1/1,latency1mW:4/5120M/2/1\nh2,,,,,12/10G//8,,,,,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1 h2)
    a=$(printf "%s\n" "$out" | awk -F"\t" "\$1==\"h1\" {print \$30, \$31, \$32, \$33, \$34, \$35, \$36, \$37}")
    b=$(printf "%s\n" "$out" | awk -F"\t" "\$1==\"h2\" {print NF, \$6, \$30}")
    [ "$a" = "2 5120M 1 1 4 5120M 2 1" ] && [ "$b" = "37 12 -" ] || { echo "a=$a b=$b" >&2; false; }'
t_assert "writeback: a measured 1MiB latency tuple lands in its own column" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs/h1" "$d/auth"
    : > "$d/engine.results"
    printf "h1 libaio - - - - - - - - - - - - - - - - - - - - - - - - 1 1 5120M 6 - - - -\n" > "$d/cal.results"
    f="$d/host.csv"; printf "host,user_login,ioengine\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=cal; TARGETS_FILE=$f; FAST_TRACK=1
     writeback_targets) >/dev/null
    tail -1 "$f" | grep -qx "h1,,,,,,,,,,,6/5120M/1/1" || { tail -1 "$f" >&2; false; }'
t_assert "calibrate: under -b a latency set also measures the 1MiB test, into its own slot" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8
    printf "# report latency\n[global]\nfilename_format=\$filenum/\$jobnum\n[a]\nbs=4k\nrw=randread\n" > "$d/set/021-r.job"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; BULK=1; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; ENGINE=io_uring
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; SIMLOG=$d/simlog
     export CAL_SIM_FLOOR1M=1000
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    grep -q "cal-lat1m-read-" "$d/simlog" &&
    case "$out" in *"lat-read: floor 100.0 us"*"lat1m-read: 1MiB floor 1000.0 us"*) true;; *) printf "%s\n" "$out" >&2; false;; esac &&
    # the 4k test holds the floor to N=5 jobs, the 1MiB test to 2N=10
    [ "$(cut -d" " -f11-14,27-30 "$d/cal.results")" = "1 1 5120M 5 1 1 5120M 10" ] || { cat "$d/cal.results" >&2; false; }'

# --- engine choice: one per shape, from the type winners ---
t_assert "cal_engine_pick: per-type winners, ties to io_uring, the tally picks the shape engine" bash -c '
    d=$(mktemp -d)
    printf "bw io_uring 1000\nbw libaio 1000\nbw psync 999\niops io_uring 900\niops libaio 1000\niops psync 200\nlat io_uring 100\nlat libaio 100.5\nlat psync 90\n" > "$d/e"
    a=$(source ./wekatester; cal_engine_pick "$d/e")
    case "$a" in "io_uring bw: "*"-> io_uring; iops: "*"-> libaio; lat: "*"-> psync") true;; *) echo "a=$a" >&2; false;; esac &&
    printf "lat io_uring 100\nlat psync 95\n" > "$d/f" &&
    b=$(source ./wekatester; cal_engine_pick "$d/f") &&
    case "$b" in "psync lat: io_uring 100.0 us, psync 95.0 us -> psync") true;; *) echo "b=$b" >&2; false;; esac'
t_assert "cal_lat_values: latency in us and IOPS per client, entries of one client weighted by IO count" bash -c '
    d=$(mktemp -d)
    printf "%s\n" "{ \"client_stats\": [ { \"jobname\": \"cal-lat-read\", \"hostname\": \"h1\", \"read\": { \"lat_ns\": { \"mean\": 100000 }, \"iops\": 1000, \"total_ios\": 300 } }, { \"jobname\": \"cal-lat-read\", \"hostname\": \"h1\", \"read\": { \"lat_ns\": { \"mean\": 200000 }, \"iops\": 500, \"total_ios\": 100 } }, { \"jobname\": \"All clients\", \"read\": { \"lat_ns\": { \"mean\": 9 } } } ] }" > "$d/r.json"
    a=$(source ./wekatester; cal_lat_values "$d/r.json" read)
    [ "$a" = "h1 125.000 1500" ] || { echo "a=$a" >&2; false; }'

# --- shapes: who is calibrated as whom ---
t_assert "cal_shapes: identical hardware is one shape on its first host, different NICs another" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8 h2:8 h3:8:200000
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2 h3); REGEN_LAYOUT=0; AUTH_DIR=""
            cal_shapes "$d/shapes" "bw read") 2>&1 )
    [ "$(wc -l < "$d/shapes" | tr -d " ")" = 2 ] &&
    a=$(cut -f1-8 "$d/shapes" | head -1 | tr "\t" "|") &&
    [ "$a" = "1|h1|5|2-6|2-6|12500000000|io_uring,libaio,psync|-" ] || { echo "a=$a" >&2; exit 1; }
    [ "$(head -1 "$d/shapes" | cut -f11)" = "h1 h2" ] && [ "$(sed -n 2p "$d/shapes" | cut -f2,6,11 | tr "\t" "|")" = "h3|25000000000|h3" ] &&
    case "$out" in
        *"shape 1 of 2: 2 host(s), calibrated on h1 -- Test CPU 8-core, 8 cpus, 252 GiB, weka NICs ens1: 1 x mlx5_core [0x15b3:0x101d] 100 Gb/s -> line rate 11.64 GiB/s"*"cores: 8 physical core(s) (no topology: one per cpu) - 1 weka DPDK - 2 reserved for the OS (0 1) = N=5: N/2 and N jobs on 2-6, 2N and 4N on 2-6"*"hosts: h1 h2"*"shape 2 of 2"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "cal_shapes: a rep's complete tuple is cached for its shape; partial ones and -g are not" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    # bw_r nj/fs/nr/qd are cols 6-9; iops_r only has its qd (col 25)
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (6) printf "\t4";; (7) printf "\t5120M";; (8) printf "\t2";; (9) printf "\t1";; (25) printf "\t32";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$d/targets.final"
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=0; AUTH_DIR=""
     cal_shapes "$d/shapes" "$(printf "bw read\niops read\n")") >/dev/null 2>&1
    [ "$(cut -f10 "$d/shapes")" = "bw_r=1/2/5120M/4" ] || { cut -f10 "$d/shapes" >&2; exit 1; }
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=1; AUTH_DIR=""
     cal_shapes "$d/shapes" "bw read") >/dev/null 2>&1
    [ "$(cut -f10 "$d/shapes")" = "-" ]'
t_assert "cal_shapes: an engine pinned by -e or the host file splits nothing but is carried" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2
    printf "h1\t-\tlibaio\t-\t-\nh2\t-\t-\t-\t-\n" > "$d/targets.final"
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2); REGEN_LAYOUT=0; AUTH_DIR=""
     cal_shapes "$d/shapes" "bw read") >/dev/null 2>&1
    [ "$(cut -f2,8 "$d/shapes" | tr "\t" "|" | tr "\n" " ")" = "h1|libaio h2|- " ] || { cat "$d/shapes" >&2; exit 1; }
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2); REGEN_LAYOUT=0; AUTH_DIR=""; ENGINE=psync
     cal_shapes "$d/shapes" "bw read") >/dev/null 2>&1
    [ "$(cut -f8 "$d/shapes")" = "psync" ]'
t_assert "cal_shapes: no weka CLI, no root, or UDP mode means no line rate, and a warning says why" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2:6 h3
    sed -i.b "/^weka_net /d" "$d/probe/h1"; echo "weka_cli absent" >> "$d/probe/h1"
    sed -i.b "/^weka_net /d" "$d/probe/h2"; echo "weka_net_err client needs root, and no passwordless escalator works here" >> "$d/probe/h2"
    sed -i.b "s/^weka_net client .*/weka_net client []/" "$d/probe/h3"
    err=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2 h3); REGEN_LAYOUT=0; AUTH_DIR=""
            cal_shapes "$d/shapes" "bw read") 2>&1 >/dev/null )
    [ "$(cut -f6 "$d/shapes" | tr "\n" " ")" = "0 0 0 " ] &&
    case "$err" in
        *"shape 1 (h1): no weka CLI on the host -- the bandwidth search has no line-rate target"*"shape 2 (h2): weka local resources could not be read (client: needs root"*"shape 3 (h3): weka uses no dedicated NIC here (UDP mode)"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# --- the probe: the shape facts, against a fake /sys and stub tools ---
t_assert "probe: cpu model, memory, bus NICs with ethtool speeds, and weka's NIC list" bash -c '
    d=$(mktemp -d); r=$d/root; b=$d/bin
    mkdir -p "$r/sys/class/net/ens1f0" "$r/sys/devices/pci0000:00/0000:3b:00.0" "$r/sys/bus/pci/drivers/mlx5_core" "$r/sys/class/net/veth9" "$r/proc" "$b"
    ln -s "../../../devices/pci0000:00/0000:3b:00.0" "$r/sys/class/net/ens1f0/device"
    ln -s "../../../bus/pci/drivers/mlx5_core" "$r/sys/devices/pci0000:00/0000:3b:00.0/driver"
    echo 0x15b3 > "$r/sys/devices/pci0000:00/0000:3b:00.0/vendor"; echo 0x101d > "$r/sys/devices/pci0000:00/0000:3b:00.0/device"
    printf "MemTotal:       527578372 kB\n" > "$r/proc/meminfo"
    printf "processor\t: 0\nmodel name\t: AMD EPYC 9454 48-Core Processor\n" > "$r/proc/cpuinfo"
    cat > "$b/ethtool" <<"ETH"
#!/bin/sh
printf "\tSpeed: 200000Mb/s\n"
echo "Cannot get wake-on-lan settings: Operation not permitted" >&2
ETH
    cat > "$b/weka" <<"WEKA"
#!/bin/sh
case "$*" in
  "local ps --no-header -o name") echo client ;;
  "local resources net -C client -J") printf "[\n{\"name\": \"ens1f0\", \"identifier\": \"0000:3b:00.0\"}\n]\n" ;;
  *) exit 1 ;;
esac
WEKA
    printf "#!/bin/sh\necho 0\n" > "$b/id"
    printf "#!/bin/sh\nexit 1\n" > "$b/sudo"
    printf "#!/bin/sh\nshift\nexec \"\$@\"\n" > "$b/timeout"
    chmod +x "$b"/*
    cmd=$(source ./wekatester; FIO_BIN=fio; probe_remote_cmd)
    out=$(WEKATESTER_SYSROOT=$r PATH="$b:$PATH" bash -c "$cmd" 2>&1)
    printf "%s\n" "$out" | grep -qx "cpu_model AMD EPYC 9454 48-Core Processor" &&
    printf "%s\n" "$out" | grep -qx "memtotal_kb 527578372" &&
    printf "%s\n" "$out" | grep -qx "nic ens1f0 200000Mb/s 0000:3b:00.0 mlx5_core 0x15b3:0x101d" &&
    ! printf "%s\n" "$out" | grep -q "^nic veth9" &&
    printf "%s\n" "$out" | grep -q "^weka_net client \[ {\"name\": \"ens1f0\", \"identifier\": \"0000:3b:00.0\"} \] *$" &&
    ! printf "%s\n" "$out" | grep -q "wake-on-lan" || { printf "%s\n" "$out" >&2; false; }'
t_assert "probe: no weka CLI says so; no root and no escalator is a named error, not silence" bash -c '
    d=$(mktemp -d); b=$d/bin; mkdir -p "$b"
    printf "#!/bin/sh\nexit 1\n" > "$b/sudo"
    printf "#!/bin/sh\nshift\nexec \"\$@\"\n" > "$b/timeout"
    chmod +x "$b"/*
    cmd=$(source ./wekatester; FIO_BIN=fio; probe_remote_cmd)
    out=$(PATH="$b:$PATH" bash -c "$cmd" 2>&1)
    if command -v weka >/dev/null; then echo "a weka CLI on this box: skipping the absent case" >&2
    else printf "%s\n" "$out" | grep -qx "weka_cli absent" || { printf "%s\n" "$out" >&2; exit 1; }; fi
    printf "#!/bin/sh\necho 1000\n" > "$b/id"
    cat > "$b/weka" <<"WEKA"
#!/bin/sh
case "$*" in
  "local ps --no-header -o name") echo client ;;
  *) echo must be root >&2; exit 1 ;;
esac
WEKA
    chmod +x "$b"/*
    out=$(PATH="$b:$PATH" bash -c "$cmd" 2>&1)
    printf "%s\n" "$out" | grep -qx "weka_net_err client needs root, and no passwordless escalator works here" ||
        { printf "%s\n" "$out" >&2; false; }'

# --- calibrate(): the whole flow against the fake client ---
t_assert "calibrate: each shape is measured solo on its first host, the answer lands for every member" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8 h2:8 h3:16:200000
    cp fio-jobfiles/default/0* "$d/set/"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1 h2 h3); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; SIMLOG=$d/simlog
     export CAL_SIM_BWCAP=12000000000
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    # every cell ran with exactly one client: a representative
    ! grep -q -- "--client=h2" "$d/simlog" &&
    [ "$(grep -o -- "--client=[a-z0-9]*" "$d/simlog" | sort -u | tr "\n" " ")" = "--client=h1 --client=h3 " ] &&
    ! grep -- "--client=" "$d/simlog" | grep -q -- "--client=.*--client=" &&
    # h1 and h2 share the shape, and so its answer
    [ "$(grep "^h1 " "$d/cal.results" | cut -d" " -f2-)" = "$(grep "^h2 " "$d/cal.results" | cut -d" " -f2-)" ] &&
    # h1 (8 cpus, weka on 7, the OS on 0-1): N=5, so bandwidth reaches line
    # rate only at 2N with the siblings in, iops peaks at 2N, latency holds
    # the floor to N; h3 (16 cpus): N=13, bandwidth tops out at N
    grep -qx "h1 io_uring 2 1 5120M 10 2 1 5120M 10 1 1 5120M 5 1 1 5120M 5 8 1 5120M 10 8 1 5120M 10 - - - - - - - -" "$d/cal.results" &&
    grep -qx "h3 io_uring 1 1 5120M 13 1 1 5120M 13 1 1 5120M 8 1 1 5120M 8 2 1 5120M 26 2 1 5120M 26 - - - - - - - -" "$d/cal.results" &&
    # the engine and the tuples reach targets.final, which staging reads
    t=$(awk -F"\t" "\$1==\"h2\" {print \$3, \$6, \$9, \$14, \$17}" "$d/targets.final") &&
    [ "$t" = "io_uring 10 2 5 1" ] &&
    case "$out" in
        *"shape 1 of 2: 2 host(s), calibrated on h1"*"N=5"*"shape 1: ioengine io_uring"*"shape 1 bw-write: numjobs=10 iodepth=2"*"siblings in that did"*"shape 1 lat-read: floor 100.0 us"*"shape 2: measuring"*"solo on h3"*) true;;
        *) printf "%s\n" "$out" >&2; false;;
    esac'
t_assert "calibrate: a rep that already carries a direction reuses it for the whole shape" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (6) printf "\t3";; (7) printf "\t5120M";; (8) printf "\t2";; (9) printf "\t4";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$d/targets.final"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1 h2); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; SIMLOG=$d/simlog
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 )
    ! grep -q -- "--client=" "$d/simlog" &&
    grep -qx "h2 - 4 2 5120M 3 - - - - - - - - - - - - - - - - - - - - - - - - - - - -" "$d/cal.results" &&
    case "$out" in *"shape 1: h1 already carries bw read geometry (qd/nr/fs/nj 4/2/5120M/3) -- the whole shape reuses it"*) true;;
        *) printf "%s\n" "$out" >&2; false;; esac'
t_assert "calibrate: only representatives seed; unified reads seed the shared set, bw-only writes truncate" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-r.job"
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\n[a]\nrw=write\n" > "$d/set/012-w.job"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1 h2); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; SIMLOG=$d/simlog
     export CAL_SIM_BWCAP=12000000000
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    # 4 cpus, weka on 3, the OS on 0-1: N=1, one file per job, and the 2N
    # cells widen the shared read set to two jobs
    ! grep -q "^h2|" "$d/simlog" &&
    grep -qx "filename=shared.0/0" "$d/cal/h1/cal-seed-read.job" &&
    grep -qx "filename=shared.0/1" "$d/cal/h1/cal-seed-read.job" &&
    grep -q "truncate -s 5120M" "$d/simlog" &&
    case "$out" in *"cal: seed estimate: h1 (shared read set, 1x1 read + 0x0 write jobs x files): 1 dense file(s) = 5.0 GiB to write"*"truncate-seeded 1 write file(s)"*) true;;
        *) printf "%s\n" "$out" >&2; false;; esac'
t_assert "calibrate: a 4k-random write search forces the dense write seed" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    printf "# report iops\n[global]\nfilename_format=\$filenum/\$jobnum\nbs=4k\n[a]\nrw=randwrite\n" > "$d/set/032-a.job"
    (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) >/dev/null 2>&1
    grep -q "^filename=h1.0/0:h1.1/0" "$d/cal/h1/cal-seed-write.job" && [ ! -s "$d/cal/h1/truncate.list" ]'
t_assert "calibrate: every write cell settles, read cells never do" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    printf "# report latency\n[global]\n[a]\nrw=randwrite\n" > "$d/set/022-w.job"
    printf "# report latency\n[global]\n[a]\nrw=randread\n" > "$d/set/021-r.job"
    (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; ENGINE=psync
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=7
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; echo "RUN $2" >> "$d/order"; }
     sleep() { echo "SLEEP $1" >> "$d/order"; }
     calibrate) >/dev/null 2>&1
    # after every lat-write cell a settle; never after a lat-read cell
    awk "prev ~ /^RUN.*cal-lat-write-/ { if (\$0 == \"SLEEP 7\") ok++; else bad++ } prev ~ /^RUN.*cal-lat-read-/ { if (\$0 ~ /^SLEEP/) bad++ } { prev = \$0 } END { exit !(ok > 0 && !bad) }" "$d/order" ||
        { cat "$d/order" >&2; false; }'
t_assert "calibrate: a cell failure files its evidence and dies pointing at the bundle, not /dev/shm" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    printf "# report bandwidth\n[global]\n[a]\nrw=read\n" > "$d/set/011-a.job"
    err=$( (source ./wekatester
            AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; ENGINE=libaio
            TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
            SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
            copy_to_master() { :; }
            run_host() { case "$2" in (*cal-bw-*) echo "fio: client: h1 connection failed"; return 1;; esac; cal_sim_host "$@"; }
            cal_evidence() { echo "EVIDENCE[$1|$3|$4|$5]" >&2; }
            calibrate) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in
        *"EVIDENCE[cell bw-read libaio numjobs=1 iodepth=1 nrfiles=1|cal-bw-read-libaio-nj1-qd1-nr1-30s.job|say|h1]"*"calibration cell bw-read libaio numjobs=1 iodepth=1 nrfiles=1 failed on h1 ("*"in the run bundle under cal/)"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    case "$err" in *"/dev/shm/wt"*) echo "points at tmpfs: $err" >&2; false;; *) true;; esac'
t_assert "calibrate: -u removes the calibration scratch, the default keeps it" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    run_one() {
        rm -rf "$d/simlog" "$d/cal"
        (source ./wekatester
         AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; ENGINE=libaio
         TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
         SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; UNLINK=$1; SIMLOG=$d/simlog
         copy_to_master() { :; }
         run_host() { cal_sim_host "$@"; }
         calibrate) >/dev/null 2>&1
    }
    run_one 0
    ! grep -q "rm -rf ./mnt/weka/.wekatester-cal" "$d/simlog" &&
    run_one 1 && grep -q "rm -rf ./mnt/weka/.wekatester-cal." "$d/simlog"'
t_assert "calibrate: a local-mode rep names its data files for the box, not localhost" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" localhost
    printf "# report bandwidth\n[global]\n[a]\nrw=write\n" > "$d/set/012-a.job"
    (source ./wekatester
     hostname() { echo testbox; }
     AUTO_LEVEL=cal; LOCAL_MODE=1; WORK_DIR=$d; HOSTS=(localhost); MASTER=localhost; FIO_BIN=fio; ENGINE=libaio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) >/dev/null 2>&1
    f=$(ls "$d/cal/localhost/"cal-bw-write-*.job | head -1) &&
    grep -qx "filename_format=testbox.cal.\$jobnum.\$filenum" "$f" &&
    ! grep -q "localhost\." "$f" "$d/cal/localhost/cal-seed-write.job"'
t_assert "cal_seed_rep: a wide seed stays far below the fio 4096-job cap, and the estimate comes first" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/cal"
    out=$( (source ./tests/helpers.sh; source ./wekatester
            WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka
            TARGET_DIR=/dev/shm/x; CAL_SETTLE=0; CAL_NS_DIR=/.wekatester-cal; CAL_SEP=.cal.
            copy_to_master() { :; }
            run_host() { cal_sim_host "$@"; }
            cal_seed_rep h1 104 64 0 0 1 libaio "0-51") 2>&1 )
    f=$d/cal/h1/cal-seed-read.job
    n=$(grep -c "^\[seed-" "$f")
    [ "$n" = 416 ] || { echo "sections=$n" >&2; exit 1; }
    [ "$(awk "/^filename=/ { if (length(\$0) > m) m = length(\$0) } END { print m }" "$f")" -lt 1024 ] &&
    grep -qx "fallocate=none" "$f" && grep -qx "filesize=5120M" "$f" &&
    est=$(printf "%s\n" "$out" | grep -n "seed estimate: h1" | cut -d: -f1 | head -1) &&
    seed=$(printf "%s\n" "$out" | grep -n "seeding h1" | cut -d: -f1 | head -1) &&
    [ -n "$est" ] && [ -n "$seed" ] && [ "$est" -lt "$seed" ] || { printf "%s\n" "$out" >&2; false; }'
t_assert "cal_seed_rep: a seed that does not fit stops before writing a byte" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/cal"
    err=$( (source ./tests/helpers.sh; source ./wekatester
            WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka; AUTO_LEVEL=cal
            TARGET_DIR=/dev/shm/x; CAL_SETTLE=0; SIMLOG=$d/simlog; export CAL_SIM_FREE_MIB=10000
            copy_to_master() { :; }
            run_host() { cal_sim_host "$@"; }
            cal_seed_rep h1 8 2 0 0 1 libaio "") 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && ! grep -q "cal-seed-" "$d/simlog" &&
    case "$err" in *"h1: the calibration dataset needs 81920MiB and /mnt/weka has 10000MiB free"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "cal_seed_rep: sufficiency is the only test -- a complete file is never rewritten" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/cal"
    (source ./tests/helpers.sh; source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka
     TARGET_DIR=/dev/shm/x; CAL_SETTLE=0; CAL_NS_DIR=/.wekatester-cal; CAL_SEP=.cal.
     copy_to_master() { :; }
     run_host() { case "$2" in (*WEKATESTER_DF*)
         printf "h1.cal.0.0 5368709120\nh1.cal.0.1 99\nh1.cal.1.0 6000000000\nWEKATESTER_DF\nwekafs 1 99999999\n"; return 0;; esac
         cal_sim_host "$@"; }
     cal_seed_rep h1 2 2 0 0 1 libaio "") >/dev/null 2>&1
    f=$d/cal/h1/cal-seed-read.job
    [ "$(grep "^filename=" "$f" | tr "\n" " ")" = "filename=h1.cal.0.1 filename=h1.cal.1.1 " ] &&
    grep -q "^\[seed-1-0\]$" "$f" || { cat "$f" >&2; false; }'

# --- what the tuner stages from it ---
t_assert "tuner: under -a cal the iops jobs run with latency accounting off, other jobs do not" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[io]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    printf "# report latency iops\n[global]\nnumjobs=1\nioengine=libaio\n[l]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; WEKATESTER_IOPS_NOLAT=1 auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    for k in disable_lat disable_clat disable_slat norandommap; do
        grep -qx "$k=1" "$FIX/jobs/h1/031-iops.job" || { echo "iops lacks $k" >&2; exit 1; }
        ! grep -q "^$k=" "$FIX/jobs/h1/021-lat.job" || { echo "lat has $k" >&2; exit 1; }
        ! grep -q "^$k=" "$FIX/jobs/h1/011-bw.job" || { echo "bw has $k" >&2; exit 1; }
    done
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >/dev/null 2>&1
    ! grep -q "^disable_lat=" "$FIX/jobs/h1/031-iops.job"'
t_assert "tuner: the shared read set is laid out for the widest reader, on the first host only" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\nnumjobs=4\nioengine=libaio\n[a]\nrw=read\n" > "$FIX/src/011-bw.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >/dev/null 2>&1
    # h2 reads the shared set with 9 jobs, h1 with 3
    { printf "h1"; for i in $(seq 2 37); do case $i in (6) printf "\t3";; (*) printf "\t-";; esac; done; printf "\n"
      printf "h2"; for i in $(seq 2 37); do case $i in (6) printf "\t9";; (*) printf "\t-";; esac; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester; WEKATESTER_NS="unified \$filenum/\$jobnum" \
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >/dev/null 2>&1
    l1=$FIX/jobs/h1/000-wekatester-layout.job; l2=$FIX/jobs/h2/000-wekatester-layout.job
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$l1" && grep -qx "numjobs=9" "$l1" &&
    ! grep -q "shared\." "$l2" || { cat "$l1" "$l2" >&2; false; }'
t_assert "shipped sets: the latency jobs report IOPS beside latency" bash -c '
    for f in fio-jobfiles/default/021-latencyR.job fio-jobfiles/default/022-latencyW.job \
             fio-jobfiles/2x400Gb/021-latencyR.job fio-jobfiles/2x400Gb/022-latencyW.job \
             fio-jobfiles/mixed/030-70-30-latency.job; do
        grep -qx "# report latency iops" "$f" || { echo "$f" >&2; exit 1; }
    done'
t_assert "dry run: -a cal names the client shapes it would calibrate" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2
    mkdir -p "$d/jobs/h1"; printf "[global]\n" > "$d/jobs/h1/011-a.job"
    printf "# report bandwidth\n[global]\n[a]\nrw=read\n" > "$d/set/011-a.job"
    out=$( (source ./wekatester
            AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1 h2); MASTER=h1; REGEN_LAYOUT=0
            SET_DIR_OVERRIDE=$d/set; JOBFILE_SRC=$d/set; JOBFILES=(011-a.job); AUTH_DIR=""
            dry_run_report) 2>&1 )
    case "$out" in *"-a cal would calibrate before staging: bw read -- per client shape"*"shape 1 of 1: 2 host(s), calibrated on h1"*"hosts: h1 h2"*) true;;
        *) printf "%s\n" "$out" >&2; false;; esac'

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
# (This test once called the function with its pre-<sep> arity and asserted
# on separate lines, so a Python traceback and an empty result still counted
# as a pass: the LAST line's status is the bash -c status. Chained now.)
t_assert "cal_scratch_dirs: every directory the names imply, once" bash -c '
    out=$( (source ./wekatester; cal_scratch_dirs h1 .cal. "\$filenum/\$jobnum" 3 1) 2>&1 | tr "\n" " " ) &&
    { [ "$out" = "h1.cal.0 h1.cal.1 " ] || { echo "$out" >&2; false; }; } &&
    out=$( (source ./wekatester; cal_scratch_dirs h1 .cal. "\$jobnum.\$filenum" 3 1) 2>&1 ) &&
    { [ -z "$out" ] || { echo "$out" >&2; false; }; } &&
    out=$( (source ./wekatester; cal_scratch_dirs shared . "\$filenum/\$jobnum" 2 1) 2>&1 | tr "\n" " " ) &&
    { [ "$out" = "shared.0 shared.1 " ] || { echo "$out" >&2; false; }; }'
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
     # h2: only bw_r measured (8/1/2048M); neither carries an engine
     printf "h1 - 4 8 64M - - - - - - - - - - - - - 32 2 256M - - - - - - - - - - - - -\nh2 - 8 1 2048M - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n" > "$d/cal.results"
     # h1 already carries an operator iops_r_qd=64 (col 25): fill must keep it
     { printf "h1"; for i in $(seq 2 37); do
          case $i in (25) printf "\t64";; (*) printf "\t-";; esac
       done; printf "\n"; } > "$d/targets.final"
     apply_cal_results)
    a=$(awk -F"\t" "\$1==\"h1\" {print \$9, \$8, \$7, \$25, \$24, \$23}" "$d/targets.final")
    b=$(awk -F"\t" "\$1==\"h2\" {print \$9, \$8, \$7}" "$d/targets.final")
    [ "$a" = "4 8 64M 64 2 256M" ] && [ "$b" = "8 1 2048M" ] || { echo "a=$a b=$b" >&2; false; }
    (source ./wekatester
     WORK_DIR=$d; rm -f "$d/targets.final"
     printf "h3 - 16 2 1024M - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n" > "$d/cal.results"
     apply_cal_results)
    c=$(awk -F"\t" "\$1==\"h3\" {print NF, \$9}" "$d/targets.final")
    [ "$c" = "37 16" ]'

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

# --- efficiency pass (2026-09-23): fan-outs and one-python phases ----------
# The mount guard used to walk the hosts serially, two sessions each. Now
# each round is fanned out: every findmnt before any write probe. The stub
# logs the leading token of each command it receives, in arrival order.
t_assert "mount guard: the rounds fan out -- every findmnt lands before any write probe" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     LOCAL_MODE=0; HOSTS=(h1 h2 h3); DIRECTORY=/mnt/weka
     run_host() { case "$2" in (findmnt*) echo "F $1" >> "$d/order"; echo "wekafs rw,forcedirect";;
                              (p=*) echo "P $1" >> "$d/order";; (*) return 1;; esac; }
     verify_mount_mode) >/dev/null 2>&1 || { echo "guard failed" >&2; exit 1; }
    [ "$(wc -l < "$d/order")" -eq 6 ] &&
    [ "$(head -3 "$d/order" | cut -c1 | sort -u)" = F ] &&
    [ "$(tail -3 "$d/order" | cut -c1 | sort -u)" = P ] || { cat "$d/order" >&2; false; }'
t_assert "mount guard: per-host failures still come out one per host, in host order" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(h1 h2 h3); DIRECTORY=/mnt/weka
            run_host() { case "$1:$2" in
                (h1:findmnt*) echo "wekafs rw,forcedirect";;
                (h1:p=*)      return 1;;
                (h2:findmnt*) echo "wekafs rw,readcache";;
                (h3:*)        return 1;;
                (*)           return 0;; esac; }
            verify_mount_mode) 2>&1 >/dev/null )
    case "$err" in
        *"ERROR: h1: cannot create files in /mnt/weka"*"ERROR: h2: wekafs mounted readcache"*"ERROR: h3: findmnt failed for /mnt/weka"*"must be mounted with forcedirect"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# The machine id rides the probe (one line, no session of its own); a probe
# without the line, or no probe at all, still asks the host as before.
t_assert "identity: the machine id comes from the probe when it carries one, lowercased" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    printf "ncpus 8\nident 4C4C4544-0042-3510-8054-B4C04F4D3732\n" > "$d/probe/h1"
    printf "ncpus 8\n" > "$d/probe/h2"
    (source ./wekatester; WORK_DIR=$d; LOCAL_MODE=0
     run_host() { echo "SSH[$1]" >&2; return 1; }
     [ "$(host_machine_id h1)" = "4c4c4544-0042-3510-8054-b4c04f4d3732" ] || { echo "h1: $(cat "$d/ident/h1.id")" >&2; exit 1; }
     run_host() { echo "DEADBEEF"; }
     [ "$(host_machine_id h2)" = "deadbeef" ] && [ "$(host_machine_id h3)" = "deadbeef" ]) 2>&1'
t_assert "identity: an empty ident line is a box with no readable id, not a failure" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    printf "ncpus 8\nident \n" > "$d/probe/h1"
    out=$( (source ./wekatester; WORK_DIR=$d; LOCAL_MODE=0
            run_host() { echo "SSH[$1]" >&2; return 1; }
            printf "[%s]" "$(host_machine_id h1)"; host_identity h1) 2>&1 )
    [ "$out" = "[]h1" ] || { echo "$out" >&2; false; }'
# One python judges every host; the bash still speaks per host, in order,
# and a host without a request is skipped as before.
t_assert "pinning: one pass over the fleet -- notes in host order, rowless hosts skipped" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    printf "ncpus 8\ntaskset 0-7\nweka_allowed 2\n" > "$d/probe/h1"
    printf "ncpus 8\ntaskset 0-7\n" > "$d/probe/h2"
    printf "ncpus 4\ntaskset 0-3\npriv sudo -n\n" > "$d/probe/h3"
    printf "h1\t-\t-\t0-3\t-\nh3\t-\t-\t0-7\t-\n" > "$d/targets.final"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1 h2 h3); AUTH_DIR=$d/auth
        check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    case "$out" in
        *"note: h1: requested cpus (0-3) overlap weka"*"(2); executing on the remainder (0-1,3)"*"note: h3: requested cpus (0-7) name cpus this host does not have (4-7; the host has 4 cpus: 0-3); executing on the remainder (0-3)"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "0-1,3" ] && [ ! -e "$d/auth/h2.cpus" ] &&
    [ "$(cat "$d/auth/h3.cpus")" = "0-3" ] && [ ! -s "$d/auth/h3.priv" ]'
# The coordinator line is one shell argument on the master; past 128 KiB it
# dies at staging with the count that caused it, and a small fleet passes.
t_assert "staging: a --client list that overflows one shell argument dies before anything runs" bash -c '
    err=$( (source ./wekatester
            FIO_BIN=fio; TARGET_DIR=/dev/shm/fio-jobfiles; JOBFILES=(000-wekatester-layout.job 011-bw.job)
            HOSTS=(); i=0
            while [ $i -lt 1500 ]; do HOSTS+=("client-node-$i.rack.example.internal"); i=$((i + 1)); done
            check_client_cmdline) 2>&1 >/dev/null ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in
        *"the fio command line for 000-wekatester-layout.job is "*" bytes with 1500 hosts"*"128 KiB"*"two or more host lists"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    (source ./wekatester; FIO_BIN=fio; TARGET_DIR=/dev/shm/fio-jobfiles; JOBFILES=(011-bw.job)
     HOSTS=(h1 h2); check_client_cmdline) &&
    # run_jobs builds the very line the guard measures
    c=$( (source ./wekatester; FIO_BIN=/usr/bin/fio; TARGET_DIR=/dev/shm/x; HOSTS=(h1 h2); fio_client_cmd 011-bw.job) ) &&
    [ "$c" = "'"'"'/usr/bin/fio'"'"' --output-format=json --eta=never --client=h1 '"'"'/dev/shm/x/h1/011-bw.job'"'"' --client=h2 '"'"'/dev/shm/x/h2/011-bw.job'"'"'" ] || { echo "$c" >&2; false; }'

echo; echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
