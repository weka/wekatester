#!/usr/bin/env bash
# wekatester unit tests: source the script (source-guard prevents main), test pure functions.
cd "$(dirname "$0")/.."
# The suite needs what wekatester needs, bash 4.4 or later -- its own shell
# and the bash first in PATH, which every bash -c test runs. wekatester is
# Linux-only; the suite also runs on a development Mac with a newer bash
# first in PATH (Homebrew's: PATH=/opt/homebrew/bin:$PATH), standing in a
# Linux kernel name and a staging dir for the /dev/shm macOS lacks.
for b in "$BASH" "$(command -v bash)"; do
    v=$("$b" -c 'echo $(( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] ))')
    [ "$v" -ge 404 ] || { echo "the suite needs bash 4.4 or later, and $b is older -- on a Mac: PATH=/opt/homebrew/bin:\$PATH bash tests/test_wekatester.sh" >&2; exit 2; }
done
# One suite per host (Frank, 2026-10-26): a host-wide mkdir lock, its owner
# named. A holder that is gone (ps, which sees every user) is reclaimed by
# rename, which only one reclaimer wins; a moved lock that is not the one
# read (another reclaimer's fresh one) goes back.
SUITE_LOCK=${SUITE_LOCK:-/tmp/wekatester-suite.lock}
suite_owner="pid $$ user $(id -un) since $(date '+%F %T') repo $PWD"
if ! held=$(mkdir "$SUITE_LOCK" 2>&1); then
    held=$(cat "$SUITE_LOCK/owner") || held=""
    hpid=${held#pid }; hpid=${hpid%% *}
    case $hpid in
        (""|*[!0-9]*) echo "another suite holds $SUITE_LOCK (no owner written; if no suite runs, remove it); not running" >&2; exit 2 ;;
    esac
    if hps=$(ps -p "$hpid" -o pid= 2>&1); then
        echo "another suite holds $SUITE_LOCK: $held; not running" >&2; exit 2
    fi
    stale=$SUITE_LOCK.stale.$$
    why=$(mv -- "$SUITE_LOCK" "$stale" 2>&1) || { echo "cannot take $SUITE_LOCK: $why" >&2; exit 2; }
    if [ "$(cat "$stale/owner" 2>&1)" != "$held" ]; then
        why=$(mv -- "$stale" "$SUITE_LOCK" 2>&1)
        echo "cannot take $SUITE_LOCK: another suite reclaimed it first${why:+ ($why)}" >&2; exit 2
    fi
    why=$(rm -rf -- "${stale:?}" 2>&1 && mkdir "$SUITE_LOCK" 2>&1) || { echo "cannot take $SUITE_LOCK: $why" >&2; exit 2; }
    echo "reclaimed $SUITE_LOCK from a suite that is gone: $held"
fi
printf '%s\n' "$suite_owner" > "$SUITE_LOCK/owner" || { echo "cannot take $SUITE_LOCK: no owner written" >&2; exit 2; }
trap '[ "$(cat "$SUITE_LOCK/owner")" != "$suite_owner" ] || rm -rf -- "${SUITE_LOCK:?}"' EXIT
# A timeout's TERM ends the suite with a count it can stand behind. INT is
# left alone: the tool's own SIGINT tests need it.
trap 'echo; echo "TIMEOUT after $SECONDS s: passed ${PASS:-0}, failed ${FAIL:-0} (incomplete)"
      [ -z "${SUITE_TMP:-}" ] || echo "kept the tests'\'' temporary files: $SUITE_TMP"; exit 124' TERM
# Every mktemp in the suite and its tests lands under one root: removed after
# a passing run, kept after a failing one (each run used to leave hundreds of
# /tmp/tmp.* behind; Frank, 2026-10-11).
SUITE_TMP=$(mktemp -d "${TMPDIR:-/tmp}/wt-suite.XXXXXX") || exit 1
export TMPDIR=$SUITE_TMP
if [ "$(uname -s)" != Linux ]; then
    SUITE_LINUX_SHIM=$(mktemp -d)
    printf '#!/bin/sh\necho Linux\n' > "$SUITE_LINUX_SHIM/uname"; chmod +x "$SUITE_LINUX_SHIM/uname"
    export PATH="$SUITE_LINUX_SHIM:$PATH"
fi
[ -w /dev/shm ] || export WT_STAGE_BASE=mktemp
# A preflight run for real locks this suite's own path, never the host's
# /dev/shm lock that a real run, or a second suite, may hold.
export WEKATESTER_SUITE_LOCK_DIR="$(mktemp -d)/wekatester.lock"
# What a test sends aside goes to SUITE_ASIDE, never /dev/null: a buffer emptied
# before each test, shown when the test fails, and gone after the suite
# (Frank, 2026-10-09).
SUITE_ASIDE=$(mktemp "${TMPDIR:-/tmp}/wt-aside.XXXXXX"); export SUITE_ASIDE
source ./tests/helpers.sh
PASS=0; FAIL=0; SKIP=0

# SUITE_ONLY=<ERE>: run only the tests whose description matches (a fast
# tier); the rest are counted as skipped.
t_assert() {   # t_assert <description> <command...>
    local aside l
    if [ -n "${SUITE_ONLY:-}" ] && ! [[ $1 =~ $SUITE_ONLY ]]; then SKIP=$((SKIP+1)); return 0; fi
    : > "$SUITE_ASIDE"
    if "${@:2}"; then PASS=$((PASS+1)); echo "ok - $1"
    else FAIL=$((FAIL+1)); echo "FAIL - $1"
         aside=$(<"$SUITE_ASIDE")
         [ -z "$aside" ] || while IFS= read -r l; do printf '    | %s\n' "$l"; done <<<"$aside"
    fi
}

# --- source-guard: sourcing must not run main (no args → would die) ---
out=$(source ./wekatester 2>&1)
t_assert "sourcing produces no output" test -z "$out"
t_assert "usage function defined after source" bash -c 'source ./wekatester; declare -f usage >>$SUITE_ASIDE'

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
t_assert "--any-fs (any case) turns the filesystem-type check off; it defaults on" bash -c '
    (source ./wekatester; parse_args h1; [ "$ANY_FS" -eq 0 ]) &&
    (source ./wekatester; parse_args --any-fs h1; [ "$ANY_FS" -eq 1 ] && [ "${HOSTS[*]}" = "h1" ]) &&
    (source ./wekatester; parse_args --ANY-FS h1; [ "$ANY_FS" -eq 1 ])'

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
t_assert "--VERSION works too" bash -c './wekatester --VERSION >>$SUITE_ASIDE'

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
    err=$( (source ./wekatester; parse_args -s /tmp/nope.json -r latency) 2>&1 >>$SUITE_ASIDE )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in *"-r"*"-s"*) true;; *) echo "$err" >&2; false;; esac'

# --- parse_args: -- separator ---
t_assert "-- passes flag-shaped tokens through as servers" bash -c '
    source ./wekatester; parse_args -d /x -- -weird h2
    [ "${HOSTS[*]}" = "-weird h2" ] && [ "$DIRECTORY" = /x ]'

# --- parse_args: a host named twice is refused (review #16, Frank 2026-10-11) ---
# fio got --client=h1 twice and the two lock sessions raced.
t_assert "h1 h1 h2 is refused, naming h1 and only h1" bash -c '
    err=$( (source ./wekatester; parse_args h1 h1 h2) 2>&1 >>$SUITE_ASIDE ) && { echo "accepted" >&2; exit 1; }
    case "$err" in *"h1 is named twice on the command line"*) ;; *) echo "$err" >&2; exit 1;; esac
    case "$err" in *h2*) echo "names h2: $err" >&2; exit 1;; esac'
t_assert "h1 h2 h1 h2 names both repeated hosts" bash -c '
    err=$( (source ./wekatester; parse_args h1 h2 h1 h2) 2>&1 >>$SUITE_ASIDE ) && { echo "accepted" >&2; exit 1; }
    case "$err" in *"h1 is named twice"*"h2 is named twice"*) ;; *) echo "$err" >&2; exit 1;; esac'
t_assert "distinct hosts still pass" bash -c '
    source ./wekatester; parse_args h1 h2 h3; [ "${HOSTS[*]}" = "h1 h2 h3" ]'
t_assert "hosts after -- are checked too" bash -c '
    err=$( (source ./wekatester; parse_args h1 -- h1) 2>&1 >>$SUITE_ASIDE ) && { echo "accepted" >&2; exit 1; }
    case "$err" in *"h1 is named twice"*) ;; *) echo "$err" >&2; exit 1;; esac'

# --- -C was removed (Frank, 2026-10-11): it names the removal, every form ---
t_assert "-C, -cset, --customize and --customize=set say -C was removed" bash -c '
    for a in -C -cmyset --customize --customize=myset; do
        err=$( (source ./wekatester; parse_args "$a" h1) 2>&1 >>$SUITE_ASIDE ) && { echo "$a: accepted" >&2; exit 1; }
        case "$err" in *"-C/--customize was removed"*) ;; *) echo "$a: $err" >&2; exit 1;; esac
    done'

# --- mount guard classifier: a /proc/mounts line, type field 3, options 4 ---
c() { (source ./wekatester; classify_mount_line_v "$1"; echo "$MOUNT_VERDICT"); }
t_assert "wekafs forcedirect ok"   test "$(c 'weka0 /mnt/weka wekafs rw,relatime,forcedirect,inode_bits=auto 0 0')" = "ok"
t_assert "wekafs writecache fails" test "$(c 'weka0 /mnt/weka wekafs rw,relatime,writecache,readahead_kb=32768 0 0')" = "fail writecache"
t_assert "wekafs readcache fails"  test "$(c 'weka0 /mnt/weka wekafs rw,readcache 0 0')" = "fail readcache"
t_assert "wekafs unknown mode"     test "$(c 'weka0 /mnt/weka wekafs rw,relatime 0 0')" = "fail unknown"
t_assert "nfs is not wekafs: other, with its type" test "$(c 'srv:/x /mnt/weka nfs4 rw,noatime 0 0')" = "other nfs4"
t_assert "lustre is not wekafs: other, with its type" test "$(c '10.0.0.1@o2ib:/fs /mnt/weka lustre rw,flock 0 0')" = "other lustre"
t_assert "xfs is other"            test "$(c '/dev/sda1 /mnt/weka xfs rw,noatime 0 0')" = "other xfs"
t_assert "tmpfs is other"          test "$(c 'tmpfs /mnt/weka tmpfs rw,nosuid 0 0')" = "other tmpfs"
t_assert "an unnamed type is other" test "$(c '')" = "other "
t_assert "WEKATESTER_NETWORK_FSTYPES is gone: a type it names is still other, and no list is left" bash -c '
    [ "$(export WEKATESTER_NETWORK_FSTYPES=fuse.myfs; source ./wekatester; classify_mount_line_v "myfs /mnt/weka fuse.myfs rw 0 0"; echo "$MOUNT_VERDICT")" = "other fuse.myfs" ] &&
    ! grep -q NETWORK_FSTYPES ./wekatester'
# The staging and lock paths are fixed (Frank 10-26): no setting moves them,
# old spelling or new; only the suite's own hooks do.
t_assert "settings: the staging and lock paths are fixed; WT_ and old WEKATESTER_ names do not move them" bash -c '
    unset WEKATESTER_SUITE_LOCK_DIR WEKATESTER_SUITE_TARGET_DIR
    old=$(export WEKATESTER_LOCK_DIR=/o/l WEKATESTER_TARGET_DIR=/o/t WT_LOCK_DIR=/w/l WT_TARGET_DIR=/w/t
          source ./wekatester; echo "$LOCK_DIR $TARGET_DIR")
    hook=$(export WEKATESTER_SUITE_LOCK_DIR=/n/l WEKATESTER_SUITE_TARGET_DIR=/n/t
          source ./wekatester; echo "$LOCK_DIR $TARGET_DIR")
    [ "$old" = "/dev/shm/wekatester.lock /dev/shm/fio-jobfiles" ] && [ "$hook" = "/n/l /n/t" ] &&
    ! grep -qE "WEKATESTER_(ENGINE_TEST_TIMEOUT|SYSINFO_TIMEOUT|SETTLE|STAGE_BASE)|WT_(LOCK|TARGET)_DIR" ./wekatester ||
        { echo "old: $old hook: $hook" >&2; false; }'
# --- settings (WT_*): CLI > environment > host file > default ---
# st_run <file line|-> <NAME=env|-> <probe> [cli arg...]: the settings path
# main takes (the environment and CLI, then the -t file), every WT_ the
# suite exports cleared first; prints the probe, expanded.
st_run() {
    local d; d=$(mktemp -d)
    printf "host,user_login\n" > "$d/h.csv"; [ "$1" = - ] || printf "%s\n" "$1" >> "$d/h.csv"
    ( unset $(compgen -v WT_); [ "$2" = - ] || export "$2"
      source ./wekatester
      settings_parse -t "$d/h.csv" ${ST_EXTRA:-} "${@:4}" h1 && TARGETS_FILE=$d/h.csv && settings_from_file &&
      check_args && settings_check_env && eval "echo \"$3\"" ) 2>&1
}
export -f st_run
# st_case <name> <file value> <env value> <probe> <want file> <want env> <want cli> [cli arg...]
st_case() {
    local a b c
    a=$(st_run "$1=$2" - "$4"); b=$(st_run "$1=$2" "$1=$3" "$4")
    c=$(st_run "$1=$2" "$1=$3" "$4" "${@:8}")
    [ "$a" = "$5" ] && [ "$b" = "$6" ] && [ "$c" = "$7" ] ||
        { echo "$1: file [$a] want [$5]; env [$b] want [$6]; cli [$c] want [$7]" >&2; false; }
}
export -f st_case
t_assert "settings: WT_DIRECTORY takes from the file, loses to env and to -d (a default: only -d is CLI_DIR)" \
    st_case WT_DIRECTORY /f/d/ /e/d '$DIRECTORY $CLI_DIR' "/f/d -" "/e/d -" "/c/d /c/d" -d /c/d
t_assert "settings: WT_WORKLOAD takes from the file, loses to env and to -w" \
    st_case WT_WORKLOAD fset eset '$WORKLOAD' fset eset cset -w cset
t_assert "settings: WT_FIO_BIN takes from the file, loses to env and to -f" \
    st_case WT_FIO_BIN /f/fio /e/fio '$FIO_BIN' /f/fio /e/fio /c/fio -f /c/fio
t_assert "settings: WT_OUTPUT takes from the file, loses to env and to -o" \
    st_case WT_OUTPUT fout eout '$OUTPUT_DIR' fout eout cout -o cout
t_assert "settings: WT_ENGINE takes from the file, loses to env and to -e (a default: only -e is ENGINE)" \
    st_case WT_ENGINE psync libaio '$ENGINE|$DEFAULT_ENGINE' "|psync" "|libaio" "io_uring|" -e io_uring
t_assert "settings: WT_AUTO takes from the file, loses to env and to -a" \
    st_case WT_AUTO safe cal:20 '$AUTO_LEVEL $CAL_RUNTIME' "safe 15" "cal 20" "brutal 30" -a brutal
t_assert "settings: WT_LINE_RATE takes from the file, loses to env and to --line-rate" \
    env ST_EXTRA="-a cal" bash -c 'st_case WT_LINE_RATE 10 12.5 "\$LINE_RATE_GBPS" 10 12.5 25 --line-rate=25'
t_assert "settings: WT_DURATION takes from the file, loses to env and to -x" \
    st_case WT_DURATION 30 40 '$DURATION' 30 40 50 -x 50
t_assert "settings: WT_IDENTITY takes from the file, loses to env and to -i (never added together)" \
    st_case WT_IDENTITY f.pem e.pem '${IDENT_RAW[*]}' f.pem e.pem c.pem -i c.pem
t_assert "settings: WT_PASSWORD takes from the file, loses to env and to -p" \
    st_case WT_PASSWORD 2 3 '$PW_COUNT' 2 3 4 -p 4
t_assert "settings: WT_VERBOSE takes from the file, loses to env and to -v (never added together)" \
    st_case WT_VERBOSE 2 1 '$VERBOSITY' 2 1 3 -vvv
t_assert "settings: WT_VERBOSE above 3 stops the run naming the source; 3 is the top" bash -c '
    e=$(st_run - WT_VERBOSE=4 "\$VERBOSITY"); f=$(st_run WT_VERBOSE=4 - "\$VERBOSITY"); t=$(st_run WT_VERBOSE=3 - "\$VERBOSITY")
    # 2^64+3 wraps to 3 in bash arithmetic; leading zeros are still a count
    w=$(st_run - WT_VERBOSE=18446744073709551619 "\$VERBOSITY"); z=$(st_run WT_VERBOSE=0003 - "\$VERBOSITY")
    case "$e" in *"environment: WT_VERBOSE takes a count 0..3, not '\''4'\''"*) ;; *) echo "e: $e" >&2; exit 1;; esac
    case "$f" in *"h.csv:2: WT_VERBOSE takes a count 0..3, not '\''4'\''"*) ;; *) echo "f: $f" >&2; exit 1;; esac
    case "$w" in *"environment: WT_VERBOSE takes a count 0..3, not '\''18446744073709551619'\''"*) ;; *) echo "w: $w" >&2; exit 1;; esac
    [ "$t" = 3 ] && [ "$z" = 3 ] || { echo "t: $t z: $z" >&2; false; }'
# cli_settings_seen keeps its own list of spellings: every one a setting's
# help line names (short, long, --long=value, -Xvalue) must mark that
# setting alone, and every option parse_args takes is a setting or listed
# here as not one.
t_assert "settings: cli_settings_seen knows every spelling of every flag setting, and parse_args has no other" bash -c '
    source ./wekatester; bad=""
    seen() { cli_settings_seen "$@"; printf "%s" "${!CLI_SET[*]}"; }
    while read -r name kind opt key; do
        [ "$kind" != env ] || continue
        sp=$(opt_help "$key" | head -1 | tr -d ,); set -- $sp; sps=()
        for w in "$1" "${2:-}" "${3:-}"; do case $w in (-*) sps+=("$w");; esac; done
        [ ${#sps[@]} -gt 0 ] || bad="$bad [$name: no spelling in its help]"
        for s in "${sps[@]}"; do
            forms=("$s")
            case $kind:$s in
                (switch:*) ;;
                (count:-v) forms+=(-vv -vvv) ;;
                (*:--*) forms+=("$s=x") ;;
                (*) forms+=("${s}x") ;;
            esac
            for f in "${forms[@]}" "${forms[0]^^}"; do
                [ "$(seen "$f")" = "$name" ] || bad="$bad [$f: $(seen "$f") want $name]"
            done
        done
    done <<<"$SETTINGS_TABLE"
    none=" - -- --break-lock --customize --help --load --targets --version -c -g -h -l -n -r -s -t "
    for o in $(awk "/^parse_args\\(\\) /{p=1} p&&/^}/{exit} p" src/wekatester.sh |
               grep -oE "^[[:space:]]+-[-a-zA-Z?*=|]+\\)" | tr -d " )" | tr "|" "\n" | sed "s/[?*]//g; s/=\$//" | sort -u); do
        [ -n "$(seen "$o")" ] || [[ $none == *" $o "* ]] || bad="$bad [$o: parse_args takes it, cli_settings_seen does not]"
    done
    [ -z "$bad" ] || { echo "$bad" >&2; false; }'
for sw in "WT_BULK BULK -b" "WT_UNLINK UNLINK -u" "WT_ANY_FS ANY_FS --any-fs" \
          "WT_ALLOW_FIO_MISMATCH ALLOW_FIO_MISMATCH --allow-fio-mismatch" \
          "WT_IGNORE_CAPACITY IGNORE_CAPACITY --ignore-capacity"; do
    set -- $sw
    t_assert "settings: $1 takes from the file, an env 0 turns it off, $3 turns it on" \
        st_case "$1" 1 0 "\$$2" 1 0 1 "$3"
done
for en in "WT_ENGINE_TEST_TIMEOUT 7 8" "WT_SYSINFO_TIMEOUT 70 80" "WT_SETTLE 5 0"; do
    set -- $en; export STN=$1 STF=$2 STE=$3
    t_assert "settings: $1 takes from the file and loses to env (no flag)" bash -c '
        a=$(st_run "$STN=$STF" - "\$$STN"); b=$(st_run "$STN=$STF" "$STN=$STE" "\$$STN")
        [ "$a" = "$STF" ] && [ "$b" = "$STE" ] || { echo "file [$a] env [$b]" >&2; false; }'
done
t_assert "settings: WT_STAGE_BASE mktemp from the file, shm from env beats it; another value stops naming the source" bash -c '
    # a real TMPDIR: st_run makes its own fixture dir under it
    t=$(mktemp -d); a=$(TMPDIR=$t st_run WT_STAGE_BASE=mktemp - "\$STAGE_BASE"); b=$(st_run WT_STAGE_BASE=mktemp WT_STAGE_BASE=shm "\$STAGE_BASE")
    c=$(st_run - WT_STAGE_BASE=/tmp "\$STAGE_BASE"); f=$(st_run WT_STAGE_BASE=ram - "\$STAGE_BASE")
    [ "$a" = "${t%/}" ] && [ "$b" = /dev/shm ] &&
    case "$c" in *"environment WT_STAGE_BASE: WT_STAGE_BASE takes shm or mktemp, not '\''/tmp'\''"*) true;; *) false;; esac &&
    case "$f" in *"h.csv:2: WT_STAGE_BASE takes shm or mktemp, not '\''ram'\''"*) true;; *) false;; esac ||
        { echo "a [$a] b [$b] c [$c] f [$f]" >&2; false; }'
t_assert "settings: a bad value stops the run naming file:line or the environment, in the flag's own words" bash -c '
    f=$(st_run WT_LINE_RATE=fast - x -a cal); e=$(st_run - WT_AUTO=turbo x); s=$(st_run WT_BULK=yes - x)
    case "$f" in *"h.csv:2: WT_LINE_RATE: --line-rate takes the line rate in Gb/s"*) ;; *) echo "f: $f" >&2; exit 1;; esac
    case "$e" in *"environment: WT_AUTO: unknown auto level: turbo"*) ;; *) echo "e: $e" >&2; exit 1;; esac
    case "$s" in *"h.csv:2: WT_BULK takes 0 or 1, not '\''yes'\''"*) ;; *) echo "s: $s" >&2; exit 1;; esac'
t_assert "settings: an unknown name (WT_TARGET_DIR, WT_LOCK_DIR included), a name set twice and a second cell stop the run" bash -c '
    a=$(st_run WT_TARGET_DIR=/x - x); b=$(st_run WT_LOCK_DIR=/x - x)
    c=$(st_run "WT_BULK=1
WT_BULK=0" - x); d=$(st_run "WT_IDENTITY=a.pem,b.pem" - x)
    case "$a" in *"h.csv:2: unknown setting '\''WT_TARGET_DIR'\''"*) ;; *) echo "a: $a" >&2; exit 1;; esac
    case "$b" in *"h.csv:2: unknown setting '\''WT_LOCK_DIR'\''"*) ;; *) echo "b: $b" >&2; exit 1;; esac
    case "$c" in *"h.csv:3: WT_BULK is set twice (first at line 2)"*) ;; *) echo "c: $c" >&2; exit 1;; esac
    case "$d" in *"h.csv:2: a settings line is one WT_NAME=value cell"*) ;; *) echo "d: $d" >&2; exit 1;; esac'
t_assert "settings: a quoted cell carries a comma; an empty value sets nothing" bash -c '
    a=$(st_run "\"WT_IDENTITY=a.pem,b.pem\"" - "\${IDENT_RAW[*]}"); b=$(st_run "WT_WORKLOAD=" WT_WORKLOAD= "\$WORKLOAD")
    [ "$a" = "a.pem,b.pem" ] && [ "$b" = default ] || { echo "a [$a] b [$b]" >&2; false; }'
t_assert "settings: a WT_LINE_RATE without -a names where it was set" bash -c '
    f=$(st_run WT_LINE_RATE=16 - x); e=$(st_run - WT_LINE_RATE=16 x)
    case "$f" in *"h.csv:2: WT_LINE_RATE: --line-rate sets the bandwidth target of a calibration: it needs -a"*) ;; *) echo "f: $f" >&2; exit 1;; esac
    case "$e" in *"ERROR: environment WT_LINE_RATE: --line-rate sets the bandwidth target"*) ;; *) echo "e: $e" >&2; exit 1;; esac'
t_assert "settings: -h and --version read no setting" bash -c '
    h=$(unset $(compgen -v WT_); WT_DURATION=abc WT_WORKLOAD=eset bash ./wekatester -h 2>&1) &&
    diff tests/golden/usage-h.txt <(printf "%s\n" "$h") >&2 &&
    v=$(WT_AUTO=turbo bash ./wekatester --version 2>&1) && [ "${v#* version }" != "$v" ]'
t_assert "settings: a host cell wt_... is named as not WT_NAME=value, before its other cells" bash -c '
    a=$(st_run "wt_lab1,ubuntu" - x)
    case "$a" in *"h.csv:2: '\''wt_lab1'\'' is not WT_NAME=value"*) ;; *) echo "$a" >&2; false;; esac'
t_assert "settings: --line-rate from the CLI with WT_AUTO from the file passes the combination check" bash -c '
    a=$(st_run WT_AUTO=cal - "\$AUTO_LEVEL \$LINE_RATE_GBPS" --line-rate 16)
    [ "$a" = "cal 16" ] || { echo "$a" >&2; false; }'
# WT_DIRECTORY and WT_ENGINE are run-wide defaults the rows refine; only -d
# and -e beat the rows (Frank, 2026-10-26).
t_assert "settings: a row's dir and engine beat env WT_DIRECTORY/WT_ENGINE; env beats the file's for a host with no row value; -d and -e beat the row" bash -c '
    d=$(mktemp -d); f=$d/h.csv
    printf "host,user_login\nWT_DIRECTORY=/file\nWT_ENGINE=psync\nh1,,io_uring,,/row\n" > "$f"
    r() { ( unset $(compgen -v WT_); export WT_DIRECTORY=/env WT_ENGINE=libaio; source ./wekatester
            settings_parse -t "$f" "$@" h1 h2; TARGETS_FILE=$f; settings_from_file
            resolve_targets phase1 "$f" "${ENGINE:--}" "$CLI_DIR" - h1 h2 | cut -f1,3,5 | tr "\t\n" " ;"
            echo "dir=$DIRECTORY" ); }
    a=$(r); b=$(r -d /cli -e sync)
    [ "$a" = "h1 io_uring /row;h2 libaio -;dir=/env" ] && [ "$b" = "h1 sync /cli;h2 sync /cli;dir=/cli" ] ||
        { echo "a [$a] b [$b]" >&2; false; }'
t_assert "settings: without -t an env WT_ENGINE is every host's engine; -e still beats it" bash -c '
    r() { ( unset $(compgen -v WT_); export WT_ENGINE=libaio; source ./wekatester
            settings_parse "$@" h1; settings_engine_default; echo "$ENGINE" ); }
    a=$(r); b=$(r -e psync)
    [ "$a" = libaio ] && [ "$b" = psync ] || { echo "a [$a] b [$b]" >&2; false; }'
t_assert "settings: WT_PASSWORD with no terminal names where it was set; -p stays as it was" bash -c '
    d=$(mktemp -d); f=$d/h.csv; : > "$d/notatty"
    printf "host,user_login\nWT_PASSWORD=2\n" > "$f"
    r() { ( unset $(compgen -v WT_); [ -z "$1" ] || export "$1"; source ./wekatester
            settings_parse "${@:2}" h1; [ "$TARGETS" -eq 0 ] || { TARGETS_FILE=$f; settings_from_file; }
            PROMPT_TTY=$d/notatty; prompt_password_creds ) 2>&1; }
    a=$(r "" -t "$f"); b=$(r WT_PASSWORD=3); c=$(r "" -p 2)
    case "$a" in *"ERROR: $f:2: WT_PASSWORD: -p needs a terminal; use key-based auth (-i) for unattended runs"*) ;; *) echo "file: $a" >&2; exit 1;; esac
    case "$b" in *"ERROR: environment WT_PASSWORD: -p needs a terminal; use key-based auth (-i)"*) ;; *) echo "env: $b" >&2; exit 1;; esac
    case "$c" in *"ERROR: -p needs a terminal; use key-based auth (-i)"*) ;; *) echo "cli: $c" >&2; exit 1;; esac'
t_assert "settings: the engines phase lists WT_ENGINE with the rows' engines, so it is proven" bash -c '
    f=$(mktemp); printf "h1,,io_uring\n" > "$f"
    out=$( (source ./wekatester; DEFAULT_ENGINE=libaio; resolve_targets engines "$f" - - -) | tr "\n" " ")
    # under -e no host runs it, so it is not proven
    e=$( (source ./wekatester; DEFAULT_ENGINE=libaio; ENGINE=psync; resolve_targets engines "$f" - - -) | tr "\n" " ")
    [ "$out" = "io_uring libaio " ] && [ "$e" = "io_uring " ] || { echo "$out | $e" >&2; false; }'
t_assert "settings: settings lines are never host rows: two WT_FIO_BIN paths resolve, not a duplicate host" bash -c '
    f=$(mktemp); printf "host,user_login\nWT_FIO_BIN=/a/fio\nWT_FIO_BIN=/b/fio\nh1,ubuntu\n" > "$f"
    out=$( (source ./wekatester; resolve_targets phase1 "$f" - - - h1) | cut -f1,2)
    [ "$out" = "h1	ubuntu" ] || { echo "$out" >&2; false; }'
t_assert "settings: -h is byte-identical to the one before the help table (tests/golden/usage-h.txt)" bash -c '
    diff tests/golden/usage-h.txt <(bash ./wekatester -h) >&2'
# WT_DIRECTORY and WT_ENGINE are defaults, so the -d/-e text would mislead:
# they get their own line, as the flagless ones do (Frank, 2026-10-26).
t_assert "settings: the template quotes each flag setting's -h block, gives -d/-e and the flagless ones their own line, and sets every setting to its built-in value" bash -c '
    d=$(mktemp -d)
    (source ./wekatester; write_targets_template "$d/t.csv") >>$SUITE_ASIDE &&
    (unset $(compgen -v WT_); source ./wekatester
     t=$(<"$d/t.csv"); n=0; o=0
     while read -r name kind opt key; do
         if [ "$kind" = env ] || [ "$kind" = default ]; then
             want="# $name: $(own_setting_help "$name")"$'\''\n'\''$name=${SETTING_DEFAULT[$name]:-}
             o=$((o + 1))
         else
             want=$(opt_help "$key" | sed "s/^/# /")$'\''\n'\''$name=${SETTING_DEFAULT[$name]:-}
             n=$((n + 1))
         fi
         [[ $t == *"$want"* ]] || { echo "$name: its help and default are not in the template" >&2; exit 1; }
     done <<<"$SETTINGS_TABLE"
     [ "$n" -eq 14 ] && [ "$o" -eq 6 ] || { echo "$n flag and $o own-help settings checked, want 14 and 6" >&2; exit 1; }
     case $t in *"--directory dir"*|*"--engine eng"*) echo "the -d or -e block is still in the template" >&2; exit 1;; esac
     for nm in WT_DIRECTORY WT_ENGINE; do [ -n "$(own_setting_help "$nm")" ] || { echo "$nm has no help" >&2; exit 1; }; done
     a=$(declare -p DIRECTORY WORKLOAD FIO_BIN OUTPUT_DIR AUTO_LEVEL BULK VERBOSITY PW_COUNT 2>&1)
     settings_parse -t "$d/t.csv" h1; TARGETS_FILE=$d/t.csv; settings_from_file; settings_check_env
     b=$(declare -p DIRECTORY WORKLOAD FIO_BIN OUTPUT_DIR AUTO_LEVEL BULK VERBOSITY PW_COUNT 2>&1)
     [ "$a" = "$b" ] && [ "$STAGE_BASE" = /dev/shm ] && [ -z "$DEFAULT_ENGINE" ] || { echo "before: $a after: $b" >&2; false; })'
t_assert "settings: hostlist.example.csv is what the built tool writes" bash -c '
    d=$(mktemp -d); (source ./wekatester; write_targets_template "$d/t.csv") >>$SUITE_ASIDE &&
    diff hostlist.example.csv "$d/t.csv" >&2'
t_assert "only the type and options fields count: a source or mount point named wekafs or forcedirect does not" test "$(c 'wekafs /mnt/forcedirect xfs rw,noatime 0 0')" = "other xfs"

# --- usable cores (probe_cores): an unbindable cpu is not usable ---
# cores_facts: "n ... | phys | all | reserved"; all is every thread fio gets
t_assert "probe_cores: cpus the probe measured as unbindable are excluded" bash -c '
    d=$(mktemp -d)
    printf "ncpus 8\nonline 0-7\nbindable 0,1,2,4,6,7\nbindable_priv -\n" > "$d/p"
    # 0 and 1 are the OS reserve; 3 and 5 refuse the bind
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p")"
    [ "${head%% *}" = 4 ] && [ "$all" = "2,4,6,7" ] || { echo "no list: $head|$all" >&2; exit 1; }
    # an operator list is its own reserve: only core 0 comes out of it
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p" 0-3)"
    [ "${head%% *}" = 2 ] && [ "$all" = "1,2" ] || { echo "0-3: $head|$all" >&2; exit 1; }'
t_assert "probe_cores: a bindable line in cpuset range syntax reads as its cpus" bash -c '
    d=$(mktemp -d)
    printf "ncpus 8\nonline 0-7\nbindable 0-2,4,6-7\nbindable_priv -\n" > "$d/p"
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p")"
    [ "$all" = "2,4,6,7" ] || { echo "all: $all" >&2; false; }'
t_assert "probe_cores: weka cores and unbindable cpus are both excluded" bash -c '
    d=$(mktemp -d)
    printf "ncpus 8\nonline 0-7\nweka_allowed 1\nweka_allowed 2\nbindable 0,1,2,4,6,7\nbindable_priv -\n" > "$d/p"
    # weka owns 1 and 2, so the reserve is 0 and 3; 5 refuses the bind
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p")"
    [ "$all" = "4,6,7" ] || { echo "all: $all" >&2; false; }'
t_assert "probe_cores: an offline cpu id is not conjured from the count" bash -c '
    d=$(mktemp -d)
    # 6 online cpus, ids 0-3 and 6-7: the count alone would have said 0-5
    printf "ncpus 6\nonline 0-3,6-7\nbindable 0,1,2,3,6,7\nbindable_priv -\n" > "$d/p"
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p")"
    [ "$all" = "2,3,6,7" ] || { echo "all: $all" >&2; false; }'

# --- probe remote snippet ---
t_assert "probe snippet emits ncpus"   bash -c 'probe_stub | grep -q "ncpus 8"'
t_assert "probe snippet emits engines" bash -c 'probe_stub | grep -q "engines.*io_uring"'
# Which cpus can be bound is READ from the cgroup cpuset, never trial-bound
# per cpu (Frank, 2026-10-11): fio answers an unbindable cpus_allowed with
# err=22 cpu_set_affinity per job, on the daemonized server, mid-run.
t_assert "probe: no cpuset to read falls back to the taskset affinity" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); cpuset_fixture "$d" 0-5
    # no /proc/self/cgroup, then one naming a cgroup with no cpuset file
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable 0-5" && printf "%s\n" "$out" | grep -qx "bindable_priv -" ||
        { echo "no cgroup file:"; printf "%s\n" "$out"; exit 1; } >&2
    cg_file "$d" /proc/self/cgroup "0::/user.slice"
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable 0-5" ||
        { echo "no cpuset file:"; printf "%s\n" "$out"; exit 1; } >&2
    out=$(probe_stub)
    printf "%s\n" "$out" | grep -qx "bindable 0-7" || { printf "%s\n" "$out" >&2; false; }'
# fio launches under taskset -c, so a taskset -cp that fails or gives no
# list is no measurement, whatever the cpuset says: the probe says why and
# nothing else (Frank, 2026-10-11). Before, both lines were left out, or the
# cpuset answered alone.
t_assert "probe: a failing taskset -cp prints bindable_err with taskset's words, cpuset or none" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); cpuset_fixture "$d" 0-7
    cat > "$d/bin/taskset" <<TS
#!/bin/sh
echo "taskset: failed to get pid \$2 affinity: Operation not permitted" >&2
exit 1
TS
    want="bindable_err taskset -cp failed: taskset: failed to get pid [0-9]* affinity: Operation not permitted"
    # no /proc/self/cgroup, one naming a cgroup with no cpuset file, then a readable cpuset
    for cg in none no-cpuset-file cpuset; do
        out=$(cpuset_probe "$d")
        printf "%s\n" "$out" | grep -qx "$want" && printf "%s\n" "$out" | grep -qx "taskset " &&
        ! printf "%s\n" "$out" | grep -q "^bindable \|^bindable_priv" ||
            { echo "$cg:"; printf "%s\n" "$out"; exit 1; } >&2
        cg_file "$d" /proc/self/cgroup "0::/user.slice"
        [ "$cg" = none ] || cg_file "$d" /sys/fs/cgroup/user.slice/cpuset.cpus.effective 0-3
    done
    # taskset answers, but with no affinity list to read, beside a readable cpuset
    printf "#!/bin/sh\necho \"no affinity here\"\n" > "$d/bin/taskset"
    cg_file "$d" /proc/self/cgroup "0::/user.slice"
    cg_file "$d" /sys/fs/cgroup/user.slice/cpuset.cpus.effective 0-3
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable_err taskset -cp gave no affinity list: no affinity here" &&
    ! printf "%s\n" "$out" | grep -q "^bindable " ||
        { echo "no list:"; printf "%s\n" "$out"; false; } >&2'
t_assert "probe: no taskset on PATH prints bindable_err naming it, even beside a readable cpuset" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); cpuset_fixture "$d" 0-7
    cg_file "$d" /proc/self/cgroup "0::/user.slice"
    cg_file "$d" /sys/fs/cgroup/user.slice/cpuset.cpus.effective 0-3
    # a PATH of the stubs and the tools the probe needs, taskset left out
    mkdir "$d/nots"; cp "$d/bin/getconf" "$d/bin/pgrep" "$d/bin/fio" "$d/bin/timeout" "$d/bin/sudo" "$d/nots/"
    for t in awk sort cat tr head grep readlink id; do ln -s "$(type -P "$t")" "$d/nots/$t"; done
    ! PATH="$d/nots" "$(type -P bash)" -c "command -v taskset" || { echo "taskset still on the PATH" >&2; exit 1; }
    cmd=$(source ./wekatester; FIO_BIN=fio; probe_remote_cmd)
    out=$(WEKATESTER_SYSROOT=$d/root PATH="$d/nots" "$(type -P bash)" -c "$cmd" 2>&1)
    printf "%s\n" "$out" | grep -qx "bindable_err taskset -cp failed: .*taskset.*not found" &&
    printf "%s\n" "$out" | grep -qx "engines  io_uring libaio " &&
    ! printf "%s\n" "$out" | grep -q "^bindable \|^bindable_priv" ||
        { printf "%s\n" "$out"; exit 1; } >&2'
t_assert "probe: cgroup v2 cpuset is read from the nearest cgroup that has one" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); cpuset_fixture "$d" 0-7
    # c42j as found: no cpuset controller below user.slice
    cg_file "$d" /proc/self/cgroup "0::/user.slice/user-1000.slice/session-1.scope"
    cg_file "$d" /sys/fs/cgroup/cpuset.cpus.effective 0-7
    cg_file "$d" /sys/fs/cgroup/user.slice/cpuset.cpus.effective 0-2,5
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable 0-2,5" && printf "%s\n" "$out" | grep -qx "bindable_priv -" ||
        { echo "from user.slice:"; printf "%s\n" "$out"; exit 1; } >&2
    cg_file "$d" /sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope/cpuset.cpus.effective 1-2
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable 1-2" || { echo "own cgroup:"; printf "%s\n" "$out"; false; } >&2'
t_assert "probe: cgroup v1 reads the cpuset hierarchy, effective_cpus before cpus" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); cpuset_fixture "$d" 0-7
    # hybrid: the cpuset controller is on v1, so the v2 root file is not it
    cg_file "$d" /proc/self/cgroup "$(printf "12:cpuset:/docker/abc\n4:cpu,cpuacct:/docker/abc\n0::/docker/abc")"
    cg_file "$d" /sys/fs/cgroup/cpuset.cpus.effective 0-7
    cg_file "$d" /sys/fs/cgroup/cpuset/cpuset.cpus 0-7
    cg_file "$d" /sys/fs/cgroup/cpuset/docker/abc/cpuset.effective_cpus 2-5
    cg_file "$d" /sys/fs/cgroup/cpuset/docker/abc/cpuset.cpus 1,3-4
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable 2-5" ||
        { echo "effective_cpus:"; printf "%s\n" "$out"; exit 1; } >&2
    rm -f "$d/root/sys/fs/cgroup/cpuset/docker/abc/cpuset.effective_cpus"
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable 1,3-4" || { echo "cpus:"; printf "%s\n" "$out"; false; } >&2'
t_assert "probe: an escalated cgroup with a wider cpuset reads as bindable_priv, the difference" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); cpuset_fixture "$d" 0-7
    cat > "$d/bin/sudo" <<SUDO
#!/bin/sh
echo "sudo \$*" >> "$d/calls"
case "\$*" in
  "-n true") exit 0 ;;
  "-n cat "*) echo "0::/system.slice/ssh.service" ;;
  *) exit 1 ;;
esac
SUDO
    cg_file "$d" /proc/self/cgroup "0::/user.slice/user-1000.slice/session-1.scope"
    cg_file "$d" /sys/fs/cgroup/cpuset.cpus.effective 0-7
    cg_file "$d" /sys/fs/cgroup/user.slice/cpuset.cpus.effective 0-3
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable 0-3" && printf "%s\n" "$out" | grep -qx "bindable_priv 4-7" ||
        { printf "%s\n" "$out"; exit 1; } >&2
    cg_file "$d" /sys/fs/cgroup/user.slice/cpuset.cpus.effective 0-1,4
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable_priv 2-3,5-7" || { echo "gaps:"; printf "%s\n" "$out"; false; } >&2'
t_assert "probe: an escalator that cannot read its cgroup leaves bindable_priv unknown (-), never guessed" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); cpuset_fixture "$d" 0-7
    # sudo runs true and taskset but not cat: the per-cpu trial would have
    # found 4-7 under it
    cat > "$d/bin/sudo" <<SUDO
#!/bin/sh
echo "sudo \$*" >> "$d/calls"
case "\$*" in
  "-n true") exit 0 ;;
  "-n taskset "*) shift; STUB_PRIV=1 exec "\$@" ;;
  *) echo "sudo: a password is required" >&2; exit 1 ;;
esac
SUDO
    cat > "$d/bin/taskset" <<TS
#!/bin/sh
echo "taskset \$*" >> "$d/calls"
case "\$1" in
  -cp) echo "pid \$2'"'"'s current affinity list: 0-7" ;;
  -c) case "\$2" in [4-7]) [ -n "\${STUB_PRIV:-}" ] || exit 1 ;; esac; shift 2; exec "\$@" ;;
esac
TS
    cg_file "$d" /proc/self/cgroup "0::/user.slice"
    cg_file "$d" /sys/fs/cgroup/user.slice/cpuset.cpus.effective 0-3
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable 0-3" && printf "%s\n" "$out" | grep -qx "bindable_priv -" ||
        { echo "cat refused:"; printf "%s\n" "$out"; exit 1; } >&2
    # cat works but names no cgroup: still unknown
    printf "#!/bin/sh\ncase \"\$*\" in \"-n true\") exit 0 ;; \"-n cat \"*) echo \"sudo: unable to resolve host x\" ;; *) exit 1 ;; esac\n" > "$d/bin/sudo"
    out=$(cpuset_probe "$d")
    printf "%s\n" "$out" | grep -qx "bindable_priv -" || { echo "junk cgroup:"; printf "%s\n" "$out"; false; } >&2'
t_assert "probe: one taskset and one escalated cat per host, never a launch per cpu" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); cpuset_fixture "$d" 0-7
    cat > "$d/bin/sudo" <<SUDO
#!/bin/sh
echo "sudo \$*" >> "$d/calls"
case "\$*" in
  "-n true") exit 0 ;;
  "-n cat "*) echo "0::/" ;;
  *) exit 1 ;;
esac
SUDO
    cg_file "$d" /proc/self/cgroup "0::/user.slice"
    cg_file "$d" /sys/fs/cgroup/cpuset.cpus.effective 0-7
    cg_file "$d" /sys/fs/cgroup/user.slice/cpuset.cpus.effective 0-3
    want=$(printf "taskset -cp PID\nsudo -n true\nsudo -n cat $d/root/proc/self/cgroup")
    out=$(cpuset_probe "$d")
    got=$(sed "s/^taskset -cp [0-9]*\$/taskset -cp PID/" "$d/calls")
    [ "$got" = "$want" ] && printf "%s\n" "$out" | grep -qx "bindable_priv 4-7" ||
        { echo "$(wc -l < "$d/calls") launch(es):"; printf "%s\n" "$got" "--- output:" "$out"; exit 1; } >&2'
t_assert "probe facts: an absent bindable line fails, never reads as every cpu bindable" bash -c '
    d=$(mktemp -d)
    printf "ncpus 8\n" > "$d/p"
    facts() { (source ./wekatester; awkrun "BEGIN {
        np = readlines(ARGV[1], P); t = probe_cpu_fact(P, np, \"bindable\", S)
        for (c = 0; c < 8; c++) U8[c] = 1
        probe_unbindable(P, np, U8, UB); probe_universe(P, np, 8, U)
        print t \"|\" join_sorted(S, \",\") \"|\" join_sorted(UB, \",\") \"|\" join_sorted(U, \",\")
    }" "$d/p") 2>&1; }
    # no line: a broken probe -- a guess is not a measurement
    out=$(facts) && { echo "no line passed: $out" >&2; exit 1; }
    case "$out" in (*"no bindable line"*) ;; (*) echo "no line: $out" >&2; exit 1 ;; esac
    printf "bindable -\nonline 0-3\n" >> "$d/p"
    [ "$(facts)" = "1||0,1,2,3,4,5,6,7|0,1,2,3" ] || { echo "tested: $(facts)" >&2; false; }'

# --- tuner: fabricate probe dir + jobfile, run auto_tune ---
t_assert "tuner writes per-host variants" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE
    test -f "$FIX/jobs/h1/011-bw.job" && test -f "$FIX/jobs/h2/011-bw.job"'
t_assert "directory override applied" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE
    grep -q "^directory=/mnt/weka$" "$FIX/jobs/h1/011-bw.job"'
t_assert "cpus_allowed excludes weka cores" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE
    grep -q "^cpus_allowed=2-4$" "$FIX/jobs/h1/011-bw.job"'
t_assert "wide-only weka_allowed masks are ignored (utility threads)" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nbindable 0-7\nbindable_priv -\nweka_allowed 0,3-4\nweka_allowed 0-7\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    printf "ncpus 8\nbindable 0-7\nbindable_priv -\nweka_allowed 0,3-4\nweka_allowed 0-7\nengines io_uring libaio psync \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE
    grep -q "^cpus_allowed=2-7$" "$FIX/jobs/h1/011-bw.job"'
t_assert "core mismatch warns" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 16\nbindable 0-15\nbindable_priv -\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines io_uring libaio \n" > "$FIX/probe/h2"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) 2>&1 >>$SUITE_ASIDE )
    case "$err" in *WARNING*"core counts differ"*) true;; *) false;; esac'

# --- tuner: no rules per level (2026-10-05): the host file and calibration decide ---
t_assert "tuner: no level rule -- where the host file and calibration are silent a job keeps the jobfile geometry and engine" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nsize=40G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    printf "# report latency\n[global]\nfilesize=10G\nnumjobs=1\nioengine=libaio\n[lat]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    printf "# report bandwidth iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=128k\nrw=read\niodepth=1\n" > "$FIX/src/012-mixed-bw.job"
    for lvl in safe max cal brutal; do
        (source ./wekatester; auto_tune "$FIX/src" "$FIX" $lvl /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1 || { echo "-a $lvl: auto_tune failed" >&2; exit 1; }
        for h in h1 h2; do
            b="$FIX/jobs/$h/011-bw.job"; m="$FIX/jobs/$h/012-mixed-bw.job"; i="$FIX/jobs/$h/031-iops.job"; l="$FIX/jobs/$h/021-lat.job"
            if ! { grep -qx "numjobs=4" "$b" && grep -qx "filesize=10G" "$b" && grep -qx "iodepth=1" "$b" &&
                   grep -qx "numjobs=4" "$m" && grep -qx "filesize=10G" "$m" &&
                   grep -qx "numjobs=4" "$i" && grep -qx "iodepth=8" "$i" && grep -qx "filesize=10G" "$i" && grep -qx "size=40G" "$i" &&
                   grep -qx "numjobs=1" "$l" && grep -qx "iodepth=1" "$l" && grep -qx "filesize=10G" "$l" &&
                   [ "$(cat "$b" "$m" "$i" "$l" | grep -c "^ioengine=libaio$")" -eq 4 ] &&
                   ! grep -q "^nrfiles=\|^file_service_type=\|wt-small" "$b" "$m" "$i" "$l"; }; then
                echo "-a $lvl, $h:" >&2; cat "$b" "$m" "$i" "$l" >&2; exit 1
            fi
        done
    done'
t_assert "tuner: a jobfile engine one host lacks gives way to the best engine every host has" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nioengine=io_uring\nnumjobs=2\nfilesize=1G\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    printf "ncpus 8\nbindable 0-7\nbindable_priv -\nweka_allowed 0\nweka_allowed 1\nweka_allowed 2\nengines libaio psync \n" > "$FIX/probe/h2"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1
    grep -q "^ioengine=libaio$" "$FIX/jobs/h1/011-bw.job"'
t_assert "mixed report treats file as latency" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops latency\n[global]\nnumjobs=4\nioengine=libaio\nfilesize=1G\n[j]\nrw=randwrite\niodepth=8\n" > "$FIX/src/022-mixed.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1
    grep -q "^numjobs=4$" "$FIX/jobs/h1/022-mixed.job"'
# override_lines replaced only lines starting "key=", so an authored
# "numjobs = 4" survived -a beside the staged numjobs=, and fio took the
# job's own (Frank, 2026-10-11). Keys now match as fio reads them (jf_key).
t_assert "tuner: blank-spelled and indented key lines are replaced in place as key=value; comments and headers stay" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n  [global]\nfilesize = 10G\n numjobs = 4\ndirectory =/orig\n\tioengine\t= libaio\ncpus_allowed = 0-7\n[create]\ncreate_only=1\n  [bw]\nstonewall\nrw=read\n  iodepth = 1\nnrfiles= 3\n# numjobs = 4\n; iodepth = 9\n" > "$FIX/src/011-bw.job"
    row=(h1); for i in $(seq 1 36); do row+=(-); done
    row[2]=psync; row[5]=3; row[6]=2G; row[7]=2; row[8]=5
    (IFS=$(printf "\t"); echo "${row[*]}") > "$FIX/targets.final"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1 || exit 1
    v="$FIX/jobs/h1/011-bw.job"; w="$FIX/jobs/h2/011-bw.job"
    for kv in numjobs=3 filesize=2G nrfiles=2 iodepth=5 directory=/mnt/weka ioengine=psync cpus_allowed=2-4; do
        k=${kv%%=*}
        [ "$(grep -cE "^[[:space:]]*$k[[:space:]]*=" "$v")" = 1 ] && grep -qx "$kv" "$v" || { echo "$kv:" >&2; cat "$v" >&2; exit 1; }
    done
    for kv in directory=/mnt/weka cpus_allowed=2-4; do
        k=${kv%%=*}
        [ "$(grep -cE "^[[:space:]]*$k[[:space:]]*=" "$w")" = 1 ] && grep -qx "$kv" "$w" || { echo "h2 $kv:" >&2; cat "$w" >&2; exit 1; }
    done
    grep -qxF "# numjobs = 4" "$v" && grep -qxF "; iodepth = 9" "$v" && grep -qxF "  [bw]" "$v" &&
    [ "$(grep -cE "^[[:space:]]*\[global\]" "$v")" = 1 ] || { cat "$v" >&2; false; }'

# A calibrated nrfiles on a format without $filenum made fio open one path
# nrfiles times (wekawithin, smoke; Bugbot, 2026-10-11). fnum stages -a max:
# h1 with a host-file row, h2 without; prints each staged format and nrfiles,
# then the notes.
fnum() {   # fnum <filename_format> <nrfiles>
    (source ./tests/helpers.sh; tuner_fixture
     printf "# report bandwidth\n[global]\nfilesize=4G\nfilename_format=%s\ndirectory=/orig\nnumjobs=32\nioengine=libaio\n[create]\nblocksize=1Mi\ncreate_only=1\n[bw]\nstonewall\nrw=read\niodepth=1\n" "$1" > "$FIX/src/011-bw.job"
     (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE 2>&1 || exit 9
     row=(h1); for i in $(seq 1 36); do row+=(-); done
     row[5]=4; row[6]=1280M; row[7]=$2; row[8]=1
     (IFS=$(printf "\t"); echo "${row[*]}") > "$FIX/targets.final"
     err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) 2>&1 >>$SUITE_ASIDE ) || { echo "$err"; exit 9; }
     for f in h1/011-bw.job h1/000-wekatester-layout.job h2/011-bw.job h2/000-wekatester-layout.job; do
         echo "$f:" $(grep -E "^(filename_format|nrfiles)=" "$FIX/jobs/$f")
     done
     printf "%s\n" "$err" | grep "^note: .*filename_format" || :)
}
export -f fnum
t_assert "-a max: nrfiles 4 on a format without \$filenum stages .\$filenum in the job and its layout, one note; a host without the row is untouched" bash -c '
    out=$(fnum "wekawithin/\$jobnum" 4)
    want="h1/011-bw.job: nrfiles=4 filename_format=wekawithin/\$jobnum.\$filenum
h1/000-wekatester-layout.job: filename_format=wekawithin/\$jobnum.\$filenum nrfiles=4
h2/011-bw.job: filename_format=wekawithin/\$jobnum
h2/000-wekatester-layout.job: filename_format=wekawithin/\$jobnum
note: 011-bw.job: filename_format=wekawithin/\$jobnum has no \$filenum, so nrfiles above 1 would open one file repeatedly; staged as wekawithin/\$jobnum.\$filenum"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
t_assert "-a max: a format that has \$filenum stays as written at nrfiles 4, no note" bash -c '
    out=$(fnum "\$filenum/\$jobnum" 4)
    want="h1/011-bw.job: nrfiles=4 filename_format=\$filenum/\$jobnum
h1/000-wekatester-layout.job: filename_format=\$filenum/\$jobnum nrfiles=4
h2/011-bw.job: filename_format=\$filenum/\$jobnum
h2/000-wekatester-layout.job: filename_format=\$filenum/\$jobnum"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
t_assert "-a max: nrfiles 1 leaves a format without \$filenum as written, no note" bash -c '
    out=$(fnum "wekawithin/\$jobnum" 1)
    want="h1/011-bw.job: nrfiles=1 filename_format=wekawithin/\$jobnum
h1/000-wekatester-layout.job: filename_format=wekawithin/\$jobnum
h2/011-bw.job: filename_format=wekawithin/\$jobnum
h2/000-wekatester-layout.job: filename_format=wekawithin/\$jobnum"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'

# --- capacity check (universal: every run, per host, from staged variants) ---
cap() {   # cap <tier> <ignore 0|1> <host>... -- stages via auto_tune, then checks
    local tier=$1 ign=$2; shift 2
    (export WEKATESTER_PROMPT_TTY=/dev/null
     source ./wekatester
     IGNORE_CAPACITY=$ign; WORK_DIR=$FIX; HOSTS=("$@"); DIRECTORY=/mnt/weka
     run_host() { cat "$FIX/probe/_df"; }
     auto_tune "$FIX/src" "$FIX" "$tier" /mnt/weka 0 - "$@" >>$SUITE_ASIDE 2>&1 || exit 9
     check_capacity)
}
export -f cap
t_assert "capacity check dies when oversized" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( cap max 0 h1 h2 2>&1 >>$SUITE_ASIDE )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *ERROR*"workload needs"*"available"*"not enough capacity"*"--ignore-capacity"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "capacity check overridden by --ignore-capacity flag arg" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( cap max 1 h1 h2 2>&1 >>$SUITE_ASIDE )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc" >&2; false; } &&
    case "$err" in
        *WARNING*"not enough capacity, running anyway (unattended)"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "no capacity warning when it fits" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) 2>&1 >>$SUITE_ASIDE )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc" >&2; false; } &&
    case "$err" in *WARNING*available*) false;; *) true;; esac'
t_assert "namespace-aware formula: distinct namespaces sum" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    out=$( cap max 0 h1 h2 2>&1 )
    # bw: 4 jobs x 1 file x 10G = 40GiB; iops: 4 jobs x 1 file x 10G = 40GiB
    # -- distinct namespaces, so the two sum to 80GiB, not the max 40
    case "$out" in *"capacity: h1 needs ~80.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: unusable df reports 0.0GiB available, unchecked, no abort" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "garbage\n" > "$FIX/probe/_df"
    out=$( cap safe 0 h1 h2 2>&1 ) || { echo "aborted: $out" >&2; exit 1; }
    case "$out" in
        *"has 0.0GiB available"*) ! grep -q ERROR <<< "$out" || { echo "$out" >&2; false; } ;;
        *) echo "$out" >&2; false ;;
    esac'
t_assert "capacity: a full filesystem (Available 0) is a shortfall, not an unread df" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 20971520 0 100%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( cap max 0 h1 h2 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc: $err" >&2; false; } &&
    case "$err" in *ERROR*"h1: workload needs"*"only 0.0GiB is available"*"not enough capacity"*) true;; *) echo "unexpected stderr: $err" >&2; false;; esac'
t_assert "capacity: a df header without its data line stays unchecked" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\n" > "$FIX/probe/_df"
    out=$( cap max 0 h1 h2 2>&1 ) || { echo "aborted: $out" >&2; exit 1; }
    case "$out" in *"capacity: h1 needs"*"has 0.0GiB available"*) ! grep -q ERROR <<< "$out" || { echo "$out" >&2; false; } ;; *) echo "$out" >&2; false ;; esac'
t_assert "capacity: Available 1 is still a shortfall" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 20971519 1 100%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( cap max 0 h1 h2 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc: $err" >&2; false; } &&
    case "$err" in *ERROR*"h1: workload needs"*"only 0.0GiB is available"*"not enough capacity"*) true;; *) echo "unexpected stderr: $err" >&2; false;; esac'

# Geometry is read per job section ([global] the fallback), never the first
# key in the file (Bugbot "Layout geometry uses first key wins", 2026-10-11).
# geo <plain|preview> <jobfile printf format>: h1's staged layout sections on
# one line, then its capacity line.
geo() {
    (source ./tests/helpers.sh; tuner_fixture; rm -f "$FIX/src/011-bw.job"
     [ "$2" = - ] && printf "# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\ndirectory=/orig\nioengine=libaio\n[create]\ncreate_only=1\n[bw]\nstonewall\nrw=read\niodepth=1\n" > "$FIX/src/011-j.job" || printf "$2" > "$FIX/src/011-j.job"
     (export WEKATESTER_PROMPT_TTY=/dev/null; source ./wekatester
      WORK_DIR=$FIX; HOSTS=(h1); DIRECTORY=/mnt/weka; AUTO_LEVEL=""; ENGINE=""; IGNORE_CAPACITY=0
      run_host() { cat "$FIX/probe/_df"; }
      generate_layout "$FIX/src" "$FIX/src" || exit 9
      if [ "$1" = plain ]; then stage_variants "$FIX/src" && check_capacity
      else auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 && check_capacity preview; fi) > "$FIX/out" 2>&1 || { cat "$FIX/out"; exit 9; }
     awk '/^\[/ { s = $0 != "[global]" } s && NF && !/^(blocksize|create_only)=/' "$FIX/jobs/h1/000-wekatester-layout.job" | tr "\n" " " | sed 's/ $//'; echo
     grep "^capacity" "$FIX/out")
}
export -f geo
J1='[global]\ndirectory=/orig\nioengine=libaio\nfilename_format=j1/$jobnum.$filenum\nnumjobs=1\nnrfiles=1\nfilesize=1G\n[create]\ncreate_only=1\n[big]\nnumjobs=4\nnrfiles=8\nfilesize=4G\nrw=read\n'
J2='[global]\ndirectory=/orig\nioengine=libaio\nfilename_format=j2/$jobnum.$filenum\n[a]\nnumjobs=2\nfilesize=2G\nrw=read\n[b]\nnumjobs=8\nnrfiles=2\nfilesize=1G\nrw=read\n'
export J1 J2
t_assert "layout geometry: a section's own numjobs/nrfiles/filesize beat [global] (layout and capacity, plain)" bash -c '
    out=$(geo plain "$J1")
    want="[layout-1] filename_format=j1/\$jobnum.\$filenum filesize=4G nrfiles=8 numjobs=4
capacity: h1 needs ~128.0GiB, has 1024.0GiB available"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
t_assert "layout geometry: the -a preview re-derives the layout per section too" bash -c '
    out=$(geo preview "$J1")
    want="[layout-1] filename_format=j1/\$jobnum.\$filenum filesize=4G nrfiles=8 numjobs=4
capacity before calibration: h1 needs ~128.0GiB, has 1024.0GiB available"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
# [a] and [b] share one namespace: both grids laid out, chained; the measured
# sections cost the larger (16 GiB), the layout its 20 GiB total, which wins
t_assert "layout geometry: two sections of one namespace each get a layout grid; capacity prices them" bash -c '
    out=$(geo plain "$J2")
    want="[layout-1] filename_format=j2/\$jobnum.\$filenum filesize=1G nrfiles=2 numjobs=8 [layout-2] wait_for=layout-1 filename_format=j2/\$jobnum.\$filenum filesize=2G numjobs=2
capacity: h1 needs ~20.0GiB, has 1024.0GiB available"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
# Pruning compares each file's length as fio sizes it: filesize when given
# (size is then an IO cap), else size over nrfiles (Bugbot "Layout prune mixes
# size and filesize", 2026-10-23). lay1 <jobfile printf format>: the generated
# layout's sections on one line.
lay1() {
    local d; d=$(mktemp -d); mkdir -p "$d/set"; printf "$1" > "$d/set/011-x.job"
    (source ./wekatester; generate_layout "$d/set" "$d/out") >>"$SUITE_ASIDE" 2>&1 || { echo "generate_layout failed"; return; }
    awk '/^\[/ { s = $0 != "[global]" } s && NF && !/^(blocksize|create_only)=/' "$d/out/000-wekatester-layout.job" | tr "\n" " " | sed 's/ $//'
}
export -f lay1
L0='[global]\nfilename_format=ns/$jobnum\nioengine=psync\n'
export L0
t_assert "layout prune: a large size= IO cap does not hide a larger filesize= job" bash -c '
    a=$(lay1 "$L0[a]\nrw=read\nfilesize=1M\nsize=64M\n[b]\nrw=read\nfilesize=8M\n")
    b=$(lay1 "$L0[b]\nrw=read\nfilesize=8M\n[a]\nrw=read\nfilesize=1M\nsize=64M\n")
    want="[layout-1] filename_format=ns/\$jobnum filesize=8M numjobs=1"
    [ "$a" = "$want" ] || { echo "a first: $a" >&2; exit 1; }
    [ "$b" = "$want" ] || { echo "b first: $b" >&2; false; }'
t_assert "layout prune: size= equal to another job filesize= is not a duplicate of it" bash -c '
    out=$(lay1 "$L0[a]\nrw=read\nfilesize=1M\nsize=8M\n[b]\nrw=read\nfilesize=8M\n")
    want="[layout-1] filename_format=ns/\$jobnum filesize=8M numjobs=1"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
t_assert "layout prune: a size-only job counts its files as size over nrfiles" bash -c '
    out=$(lay1 "$L0[a]\nrw=read\nnrfiles=8\nsize=64M\n[b]\nrw=read\nnrfiles=8\nfilesize=16M\n")
    want="[layout-1] filename_format=ns/\$jobnum filesize=16M nrfiles=8 numjobs=1"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
t_assert "layout prune: a size-only job with larger files still covers a filesize= job" bash -c '
    out=$(lay1 "$L0[a]\nrw=read\nnrfiles=8\nsize=256M\n[b]\nrw=read\nnrfiles=8\nfilesize=16M\n")
    want="[layout-1] filename_format=ns/\$jobnum size=256M nrfiles=8 numjobs=1"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
t_assert "layout prune: filesize= wins over a smaller size= in the same job" bash -c '
    out=$(lay1 "$L0[a]\nrw=read\nfilesize=8M\nsize=1M\n[b]\nrw=read\nfilesize=4M\n")
    want="[layout-1] filename_format=ns/\$jobnum filesize=8M numjobs=1"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
t_assert "layout geometry: a [global]-only jobfile lays out and prices as before" bash -c '
    out=$(geo plain -)
    want="[bw] filesize=10G numjobs=4
capacity: h1 needs ~40.0GiB, has 1024.0GiB available"
    [ "$out" = "$want" ] || { echo "$out" >&2; false; }'
# --- stage_variants: per-host jobfile staging (Task 8) ---
t_assert "non-auto staging produces per-host variants" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester
     WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2); AUTO_LEVEL=""
     stage_variants "$FIX/src")
    test -f "$FIX/jobs/h1/011-bw.job" && test -f "$FIX/jobs/h2/011-bw.job" &&
    grep -q "^directory=/mnt/weka$" "$FIX/jobs/h2/011-bw.job"'
t_assert "non-auto staging replaces blank-spelled -d, host-file geometry and engine lines in place, and -e after them" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n  [global]\n directory = /orig\nfilesize = 10G\nnumjobs = 4\nioengine = libaio\n  [bw]\nrw=read\n  iodepth = 1\n  nrfiles= 3\n# numjobs = 4\n" > "$FIX/src/011-bw.job"
    row=(h1); for i in $(seq 1 36); do row+=(-); done
    row[2]=psync; row[5]=3; row[6]=2G; row[7]=2; row[8]=5
    (IFS=$(printf "\t"); echo "${row[*]}") > "$FIX/targets.final"
    (source ./wekatester
     WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2); AUTO_LEVEL=""; ENGINE=""
     stage_variants "$FIX/src") >>$SUITE_ASIDE 2>&1 || exit 1
    v="$FIX/jobs/h1/011-bw.job"; w="$FIX/jobs/h2/011-bw.job"
    once() { [ "$(grep -cE "^[[:space:]]*${2%%=*}[[:space:]]*=" "$1")" = 1 ] && grep -qx "$2" "$1" || { echo "$2:" >&2; cat "$1" >&2; false; }; }
    for kv in numjobs=3 filesize=2G nrfiles=2 iodepth=5 directory=/mnt/weka ioengine=psync; do once "$v" "$kv" || exit 1; done
    once "$w" directory=/mnt/weka && grep -qxF "numjobs = 4" "$w" &&
    grep -qxF "# numjobs = 4" "$v" && [ "$(grep -cE "^[[:space:]]*\[global\]" "$v")" = 1 ] || exit 1
    (source ./wekatester; WORK_DIR=$FIX; HOSTS=(h1 h2); override_staged all ioengine sync) >>$SUITE_ASIDE 2>&1 || exit 1
    once "$v" ioengine=sync && once "$w" ioengine=sync'

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
            stage_variants "$FIX/src" && check_capacity) 2>&1 >>$SUITE_ASIDE )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *ERROR*"workload needs"*"not enough capacity"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "capacity: a dry run under -a previews the jobfiles sizes, labelled, and stops nothing -- the run checks again after calibration" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    out=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2)
            AUTO_LEVEL=cal; IGNORE_CAPACITY=0
            run_host() { cat "$FIX/probe/_df"; }
            stage_variants "$FIX/src" >>$SUITE_ASIDE && check_capacity preview) 2>&1 ); rc=$?
    [ "$rc" -eq 0 ] || { echo "preview stopped the run: $rc $out" >&2; exit 1; }
    case "$out" in *ERROR*) echo "preview said ERROR: $out" >&2; exit 1;; esac
    case "$out" in *"capacity before calibration: h1 needs"*"note: h1: the jobfiles as written need"*"checks again after calibration"*) true;; *) echo "unexpected: $out" >&2; false;; esac'
t_assert "auto staging with override stages every host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 20971520 0 20971520 1%% /mnt/weka\n" > "$FIX/probe/_df"
    err=$( (source ./wekatester
            WORK_DIR=$FIX; DIRECTORY=/mnt/weka; HOSTS=(h1 h2)
            AUTO_LEVEL=max; IGNORE_CAPACITY=1
            stage_variants "$FIX/src") 2>&1 >>$SUITE_ASIDE )
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
    source ./tests/helpers.sh; signal_trappable TERM || exit 1; signal_fixture
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
    source ./tests/helpers.sh; signal_trappable INT || exit 1; signal_fixture
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
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1
    v="$FIX/jobs/h1/011-bw.job"
    grep -q "^\[global\]$" "$v" && grep -q "^directory=/mnt/weka$" "$v" &&
    grep -q "^cpus_allowed=2-4$" "$v" && grep -q "^\[job1\]$" "$v"'
t_assert "an existing [global] is never duplicated" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" safe /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1
    [ "$(grep -c "^\[global\]$" "$FIX/jobs/h1/011-bw.job")" -eq 1 ]'

# --- capacity model: namespaces, size= ---
# fio expands the default filename_format ($jobname...) per section, so two
# jobfiles that set no filename_format own separate files and must SUM. They
# used to share one literal default key and collapse to a max, under-counting
# the footprint -- the one direction the guard must never fail in.
t_assert "capacity: jobfiles without filename_format sum, not max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/012-bw2.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~80.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: jobfiles sharing one filename_format take the max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    j="# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nfilename_format=shared.\$jobnum.\$filenum\nioengine=libaio\n[j]\nrw=read\n"
    printf "$j" > "$FIX/src/011-bw.job"
    printf "$j" > "$FIX/src/012-bw2.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~40.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
# One $jobname format in two sections is two sets of files: rd.* and rd2.*.
t_assert "capacity: two sections sharing one jobname format sum, not max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nfilename_format=\$jobname.\$jobnum.\$filenum\nioengine=libaio\n[rd]\nrw=read\n" > "$FIX/src/011-bw.job"
    printf "# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\nfilename_format=\$jobname.\$jobnum.\$filenum\nioengine=libaio\n[rd2]\nrw=read\n" > "$FIX/src/012-bw2.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~80.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: size= without filesize counts numjobs x size" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nsize=4G\nnrfiles=4\nnumjobs=3\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    out=$( cap safe 0 h1 2>&1 )
    case "$out" in *"capacity: h1 needs ~12.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: a percentage size= contributes 0 instead of crashing" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nsize=50%%\nioengine=libaio\n[j]\nrw=read\n" > "$FIX/src/011-bw.job"
    out=$( cap safe 0 h1 2>&1 )
    rc=$?
    [ "$rc" -eq 0 ] || { echo "expected zero exit, got $rc: $out" >&2; false; } &&
    case "$out" in *"capacity: h1 needs ~0.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "size= is never inserted where the jobfile had none" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[j]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1
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
# The items argument itself lives on: report_items still feeds it per job.
t_assert "summarize: the items argument still narrows the report" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    out=$( (source ./wekatester; summarize "$d/r.json" latency) 2>&1 )
    case "$out" in *"average latency: 250.0 us"*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *bandwidth*|*iops*) echo "$out" >&2; false;; *) true;; esac'
t_assert "summarize: refuses results that are missing a host, by name" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    err=$( (source ./wekatester; summarize "$d/r.json" "" "vega-1 vega-2 vega-3") 2>&1 >>$SUITE_ASIDE )
    rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit, got $rc" >&2; false; } &&
    case "$err" in
        *"no results from 1 of 3 host(s): vega-3"*) true;;
        *) echo "unexpected stderr: $err" >&2; false;;
    esac'
t_assert "summarize: passes when every expected host reported" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    (source ./wekatester; summarize "$d/r.json" "bandwidth" "vega-1 vega-2") >>$SUITE_ASIDE'
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
# The Python wekatester wrote {jobname: fio JSON, ...}: -s names that format
# instead of reporting a missing aggregate (review #24).
t_assert "summarize: a Python wekatester results file is named as such" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/inner.json"
    { printf "{ \"011-bw.job\": "; cat "$d/inner.json"; printf "}\n"; } > "$d/py.json"
    ! out=$(./wekatester -s "$d/py.json" 2>&1) &&
    case "$out" in
        *"All clients"*) echo "$out" >&2; false;;
        *"py.json: a results file from the Python wekatester"*"jq '\''.\"011-bw.job\"'\'' $d/py.json > job.json"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "summarize: the Python file's inner object, on its own, still summarizes" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/inner.json"
    out=$(./wekatester -s "$d/inner.json" 2>&1) || { echo "$out" >&2; exit 1; }
    case "$out" in *"total bandwidth: 7.00 GiB/s"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "summarize: this version's results are never taken for the Python format" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"; fio_json_single_fixture "$d/s.json"
    for f in r s; do
        out=$(./wekatester -s "$d/$f.json" 2>&1) || { echo "$f: $out" >&2; exit 1; }
        case "$out" in *Python*) echo "$f: $out" >&2; exit 1;; esac
    done'

# --- report directive parsing ---
# The metric selector needs whitespace after "report", or prose comments get
# parsed as report items.
r() { f=$(mktemp); printf '%b' "$1" > "$f"; (source ./wekatester; report_items "$f"); }
# no directive (or prose) is every item; the known items in a fixed order
t_assert "report directive: items are parsed" \
    test "$(r '# report bandwidth latency\n[global]\n')" = "bandwidth latency"
t_assert "report directive: no space after # is fine" \
    test "$(r '#report iops\n[global]\n')" = "iops"
t_assert "report directive: prose is not a directive" \
    test "$(r '# reporting notes for the field\n[global]\n')" = "bandwidth latency iops"
t_assert "report directive: bare # report means default-all" \
    test "$(r '# report\n[global]\n')" = "bandwidth latency iops"
# The summary reads "# report" by report_has's rule, as staging and -a do
# (N1). rjs: the metric groups run_jobs prints for a jobfile, or "none".
rjs() {   # rjs <directive lines, printf %b>
    local t out g s=""
    t=$(mktemp -d); mkdir "$t/set" "$t/out"
    printf '%b' "$1\n[global]\nfilesize=1M\n[x]\nrw=read\n" > "$t/set/011-x.job"
    fio_json_single_fixture "$t/f.json"
    out=$( (source ./wekatester
            HOSTS=(vega-1); MASTER=vega-1; FIO_BIN=fio; TARGET_DIR=/dev/shm/x
            SET_DIR=$t/set; JOBFILES=(011-x.job); RUN_DIR=$t/out
            run_host() { cat "$t/f.json"; }
            run_jobs) 2>&1 ) || { echo "run_jobs failed: $out" >&2; return 1; }
    for g in bandwidth iops latency; do case "$out" in *"average $g: "*) s="$s $g";; esac; done
    case "$out" in *"(no non-zero metrics to report)"*) s="$s none";; esac
    echo "${s# }"
}
t_assert "report directive: a CRLF jobfile's '# report iops' summarizes iops" \
    test "$(rjs '# report iops\r\n[global]\r')" = "iops"
t_assert "report directive: a tab between items summarizes both" \
    test "$(rjs '# report bandwidth\tiops')" = "bandwidth iops"
t_assert "report directive: \\034 after # is whitespace, as staging reads it" \
    test "$(rjs '#\034report iops')" = "iops"
# Every other spelling summarizes as it did before N1.
while IFS='|' read -r spec want; do
    t_assert "report directive: '$spec' summarizes '$want'" test "$(rjs "$spec")" = "$want"
done <<'EOF'
# no directive|bandwidth iops latency
# report bandwidth latency|bandwidth latency
#report iops|iops
#  report iops|iops
# report iops latency bandwidth|bandwidth iops latency
# report bandwidth\n# report latency|bandwidth latency
# reporting notes for the field|bandwidth iops latency
# report: see the wiki|bandwidth iops latency
## report iops|bandwidth iops latency
  # report iops|bandwidth iops latency
# report|bandwidth iops latency
# report |none
# report bw|none
# report iops,latency|none
EOF

# --- local mode: trigger ---
# With no server on the command line the run happens here, and the transport
# wrappers must never reach for ssh/scp (no_ssh_fixture enforces that: the
# stubs shadow the real binaries and exit 99).
lm() { (uname_fixture Linux
        source ./wekatester; parse_args "$@"; resolve_local_mode >>$SUITE_ASIDE
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
# wekatester runs on a Linux controller (Frank, 2026-10-06): anywhere else a
# run stops before it starts anything, local or remote; -s, which only reads
# a results file, still works.
t_assert "the controller must be Linux: a run stops on another kernel before anything starts; -s still summarizes anywhere" bash -c '
    source ./tests/helpers.sh; uname_fixture Darwin
    for args in "" "h1 h2"; do
        err=$(./wekatester $args 2>&1 >>$SUITE_ASIDE) && { echo "ran on Darwin [$args]" >&2; exit 1; }
        case "$err" in
            *"wekatester runs on a Linux controller, not Darwin"*) ;;
            *) echo "[$args] $err" >&2; exit 1;;
        esac
    done
    d=$(mktemp -d); fio_json_fixture "$d/r.json"
    ./wekatester -s "$d/r.json" | grep -q "total bandwidth: 7.00 GiB/s"'
# An older bash exits 2, the usage-error status (Frank, 2026-10-26).
t_assert "bash floor: the tool, ./build and the suite stop an older bash with exit 2" bash -c '
    for f in ./wekatester ./build ./tests/test_wekatester.sh; do
        g=$(grep -m1 -A1 "needs bash 4.4 or later" "$f" | grep -oE "exit [0-9]+" | head -1)
        [ "$g" = "exit 2" ] || { echo "$f: [$g]" >&2; exit 1; }
    done
    # where an old bash exists (macOS /bin/bash), the tool itself says so
    if [ -x /bin/bash ] && ! /bin/bash -c "[ \$(( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] )) -ge 404 ]"; then
        out=$(/bin/bash ./wekatester -h 2>&1); rc=$?
        [ "$rc" -eq 2 ] && case "$out" in *"needs bash 4.4 or later"*) true;; *) false;; esac || { echo "rc=$rc $out" >&2; exit 1; }
    fi'
t_assert "bash floor: 4.4 and later pass, 4.3 and 3.2 do not" bash -c '
    source ./wekatester
    bash_floor_ok 4 4 && bash_floor_ok 5 0 && bash_floor_ok 5 3 && ! bash_floor_ok 4 3 && ! bash_floor_ok 3 2'

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
t_assert "copy_to_master remote: one tar stream over one ssh to the master, the sources by name, the destination made and unpacked into" bash -c '
    d=$(mktemp -d); mkdir -p "$d/bin" "$d/w/jobs/h1" "$d/w/jobs/h2" "$d/w/jobs/h3" "$d/got"
    for h in h1 h2 h3; do echo "$h" > "$d/w/jobs/$h/011-bw.job"; done
    # the stub records its argv and unpacks what it is sent, as the remote would
    printf "#!/bin/sh\nprintf SSH >> \"%s/argv\"; printf \"[%%s]\" \"\$@\" >> \"%s/argv\"; printf \"\\\\n\" >> \"%s/argv\"\nexec tar -xf - -C \"%s/got\"\n" "$d" "$d" "$d" "$d" > "$d/bin/ssh"
    chmod +x "$d/bin/ssh"
    (export PATH="$d/bin:$PATH"; source ./wekatester
     LOCAL_MODE=0; MASTER=vega-1; SSH_OPTS="-o BatchMode=yes"
     copy_to_master "$d/w/jobs/h1" "$d/w/jobs/h2" "$d/w/jobs/h3" /dev/shm/fio-jobfiles/) || { cat "$d/argv" >&2; exit 1; }
    [ "$(cat "$d/argv")" = "SSH[-o][BatchMode=yes][vega-1][mkdir -p '"'"'/dev/shm/fio-jobfiles/'"'"' && tar -xf - -C '"'"'/dev/shm/fio-jobfiles/'"'"']" ] &&
    [ "$(cat "$d/got/h1/011-bw.job" "$d/got/h3/011-bw.job")" = "h1
h3" ] || { cat "$d/argv" >&2; ls -R "$d/got" >&2; false; }'
t_assert "copy_to_master remote: a failed stream fails the copy, and sources from two directories are refused" bash -c '
    d=$(mktemp -d); mkdir -p "$d/bin" "$d/w/a" "$d/x/b"
    printf "#!/bin/sh\ncat > $d/ssh.stdin; exit 255\n" > "$d/bin/ssh"; chmod +x "$d/bin/ssh"
    (export PATH="$d/bin:$PATH"; source ./wekatester; LOCAL_MODE=0; MASTER=m; copy_to_master "$d/w/a" /dst/) && { echo "a dead ssh passed" >&2; exit 1; }
    err=$( (export PATH="$d/bin:$PATH"; source ./wekatester; LOCAL_MODE=0; MASTER=m; copy_to_master "$d/w/a" "$d/x/b" /dst/) 2>&1 ) && { echo "two dirs passed" >&2; exit 1; }
    case "$err" in *"copy_to_master: $d/x/b is not in $d/w"*) true;; *) echo "$err" >&2; false;; esac'

# preflight reads 255 as ssh'"'"'s "could not connect" status, which only means that
# remotely. run_host is stubbed to hand preflight the rc directly: no local
# command exits 255 for the reason preflight would be classifying.
t_assert "preflight: rc 255 in local mode is a missing fio, not a dead ssh" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); FIO_BIN=/usr/bin/fio; WORK_DIR=$(mktemp -d)
            run_host() { return 255; }
            preflight) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"localhost: /usr/bin/fio not found"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "preflight: rc 255 in remote mode is still a dead ssh" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(vega-1); FIO_BIN=/usr/bin/fio; WORK_DIR=$(mktemp -d)
            run_host() { return 255; }
            preflight) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"vega-1: ssh failed"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# --- one run per host: the lock, the evidence of another run, --break-lock ---
lk_run() {   # lk_run [k=v...]: preflight on the local host in the lock fixture; output on stdout
    (export PATH="$LK/bin:$PATH" WEKATESTER_SUITE_TARGET_DIR="$LK/tgt"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); FIO_BIN=$LK/bin/fio; FIO_PIDFILE=$LK/fio.pid; WORK_DIR=$LK/w
     for kv in "$@"; do eval "$kv"; done
     preflight 2>&1 && read -r o < "$WEKATESTER_SUITE_LOCK_DIR/owner" && [ "$o" = "$LOCK_TOKEN" ] && echo LOCKED-BY-US
     cleanup 2>&1; [ -e "$WEKATESTER_SUITE_LOCK_DIR" ] || echo RELEASED)
}
export -f lk_run
t_assert "run lock: a clean host is locked in preflight with this run's owner line, and cleanup releases it" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    out=$(lk_run)
    case "$out" in *LOCKED-BY-US*RELEASED*) ;; *) echo "$out" >&2; exit 1;; esac'
t_assert "run lock: cleanup leaves a lock another run took meanwhile" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    (export PATH="$LK/bin:$PATH"; source ./wekatester; LOCAL_MODE=1; HOSTS=(localhost); WORK_DIR=$LK/w
     LOCK_TOKEN="ctl-1 pid 1 user a since x"; mkdir "$LK/lock"; echo "ctl-9 pid 7 user b since y" > "$LK/lock/owner"
     RUN_LOCKS[localhost]=1; out=$(cleanup 2>&1) || { echo "$out" >&2; exit 1; })
    grep -qx "ctl-9 pid 7 user b since y" "$LK/lock/owner"'
t_assert "run lock: another run's lock, staging and fio stop this one, each named, and nothing of theirs is touched" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    mkdir -p "$LK/lock" "$LK/tgt"; echo "ctl-9 pid 77 user x since 2026-10-09 01:00:00" > "$LK/lock/owner"
    echo "99999991 $LK/bin/fio --server --daemonize=$LK/fio.pid" > "$LK/procs"
    out=$(lk_run)
    case "$out" in *"localhost: another wekatester run is here, or one that did not clean up: lock(ctl-9 pid 77 user x since 2026-10-09 01:00:00) staged($LK/tgt) fio(99999991)"*"rerun with --break-lock"*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *LOCKED-BY-US*|*RELEASED*) echo "$out" >&2; exit 1;; esac
    grep -q "pid 77" "$LK/lock/owner" && [ -d "$LK/tgt" ]'
t_assert "run lock: any fio wekatester did not start stops the run, --break-lock or not, and is never touched" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    printf "99999995 /usr/bin/fio --name=bench --rw=read\n99999996 [fio] <defunct>\n" > "$LK/procs"; echo 99999995 > "$LK/alive"
    out=$(lk_run BREAK_LOCK=1)
    # a zombie holds nothing and cannot be killed: not evidence
    case "$out" in *"localhost: fio that wekatester did not start is running (pid:command 99999995:/usr/bin/fio); stop it first"*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *99999996*) echo "$out" >&2; exit 1;; esac
    case "$out" in *LOCKED-BY-US*|*cleared*) echo "$out" >&2; exit 1;; esac
    [ ! -e "$LK/lock" ]'
t_assert "run lock: --break-lock kills wekatester's fio, clears its staging and lock, says so, and locks" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    mkdir -p "$LK/lock" "$LK/tgt.cal"; echo "ctl-9 pid 77 user x since then" > "$LK/lock/owner"
    echo "99999991 $LK/bin/fio --client=h1 $LK/tgt.cal/h1/cell.job" > "$LK/procs"
    out=$(lk_run BREAK_LOCK=1)
    case "$out" in *"NOTE: localhost: --break-lock cleared another run'"'"'s lock(ctl-9 pid 77 user x since then) staged($LK/tgt.cal) fio(99999991)"*LOCKED-BY-US*RELEASED*) ;; *) echo "$out" >&2; exit 1;; esac
    [ ! -e "$LK/tgt.cal" ]'
t_assert "run lock: a wekatester fio that survives every kill still stops the run under --break-lock" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    echo "99999991 $LK/bin/fio --server --daemonize=$LK/fio.pid" > "$LK/procs"; echo 99999991 > "$LK/alive"
    out=$(lk_run BREAK_LOCK=1)
    case "$out" in *"another wekatester run is here, or one that did not clean up: fio(99999991) unkillable(99999991)"*) ;; *) echo "$out" >&2; exit 1;; esac
    [ ! -e "$LK/lock" ]'
t_assert "run lock: an -f naming a directory or a non-executable file is no fio" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    mkdir "$LK/fio.d"; : > "$LK/fio.txt"
    for f in "$LK/fio.d" "$LK/fio.txt"; do
        out=$(lk_run "FIO_BIN=$f")
        case "$out" in *"localhost: $f not found, or not an executable file"*) ;; *) echo "$f: $out" >&2; exit 1;; esac
        [ ! -e "$LK/lock" ] || { echo "$f: locked anyway" >&2; exit 1; }
    done'
t_assert "run lock: under --break-lock a fio that turns zombie is gone, and a pid reused after the TERM is never killed" bash -c '
    for after in "[fio] <defunct>" "/usr/sbin/sshd -D"; do
        source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
        echo "99999991 $LK/bin/fio --server --daemonize=$LK/fio.pid" > "$LK/procs"
        echo "99999991 $after" > "$LK/after"
        out=$(lk_run BREAK_LOCK=1)
        case "$out" in *"NOTE: localhost: --break-lock cleared another run"*"fio(99999991)"*LOCKED-BY-US*RELEASED*) ;; *) echo "then \"$after\": $out" >&2; exit 1;; esac
        [ ! -s "$LK/esc" ] || { echo "then \"$after\": escalated: $(cat "$LK/esc")" >&2; exit 1; }
    done'
t_assert "run lock: --break-lock removes earlier runs' group files from the destination, other evidence or not, and nothing else there" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    g=$LK/dest/.wekatester-group.123.456.lst
    mkdir "$LK/dest"; : > "$g"; : > "$g.bak"; : > "$LK/dest/keep.lst"
    # without --break-lock the file stays
    out=$(lk_run "DIRECTORY=$LK/dest")
    case "$out" in *LOCKED-BY-US*RELEASED*) ;; *) echo "$out" >&2; exit 1;; esac
    [ -e "$g" ] || { echo "removed without --break-lock" >&2; exit 1; }
    out=$(lk_run BREAK_LOCK=1 "DIRECTORY=$LK/dest")
    case "$out" in *LOCKED-BY-US*RELEASED*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *cleared*) echo "$out" >&2; exit 1;; esac
    [ ! -e "$g" ] && [ -e "$g.bak" ] && [ -e "$LK/dest/keep.lst" ] || { ls -A "$LK/dest" >&2; false; }'
t_assert "run lock: --break-lock with no group files in the destination still heals and locks" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    mkdir -p "$LK/dest" "$LK/lock"; echo "ctl-9 pid 77 user x since then" > "$LK/lock/owner"; : > "$LK/dest/keep"
    out=$(lk_run BREAK_LOCK=1 "DIRECTORY=$LK/dest")
    case "$out" in *"NOTE: localhost: --break-lock cleared another run'"'"'s lock(ctl-9 pid 77 user x since then)"*LOCKED-BY-US*RELEASED*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *"No such file"*|*wekatester-group*) echo "$out" >&2; exit 1;; esac
    [ "$(ls -A "$LK/dest")" = keep ] || { ls -A "$LK/dest" >&2; false; }'

# --- one fio version across the hosts: read in preflight's own session ---
t_assert "--allow-fio-mismatch (long only) sets the override; it defaults off" bash -c '
    (source ./wekatester; parse_args h1 h2; [ "$ALLOW_FIO_MISMATCH" -eq 0 ]) &&
    (source ./wekatester; parse_args --allow-fio-mismatch h1 h2; [ "$ALLOW_FIO_MISMATCH" -eq 1 ] && [ "${HOSTS[*]}" = "h1 h2" ])'
t_assert "fio version: two versions on three hosts stop preflight, each version named with its hosts, in one session per host" bash -c '
    source ./tests/helpers.sh
    lock_fixture; out=$(fv_preflight 0 h1=fio-3.28 h2=fio-3.35 h3=fio-3.28) && { echo "passed: $out" >&2; exit 1; }
    want="ERROR: fio differs across the hosts, 2 versions on 3 hosts, and fio'"'"'s client/server protocol is version-sensitive
ERROR:   fio-3.28 on 2 host(s): h1 h3
ERROR:   fio-3.35 on 1 host(s): h2
ERROR: fio differs across the hosts (2 versions): the run stopped before any fio server started -- install one fio version on every host, or --allow-fio-mismatch runs anyway"
    diff <(printf "%s\n" "$want") <(printf "%s\n" "$out" | grep "ERROR" | sed "s/^[0-9:]* //") >&2 || exit 1
    for h in h1 h2 h3; do [ "$(grep -c "fio-version" "$LK/sent.$h")" -eq 1 ] && [ "$(wc -l < "$LK/sent.$h")" -eq 1 ] || { echo "$h: not one session carrying the read" >&2; exit 1; }; done'
t_assert "fio version: one version everywhere passes and says which" bash -c '
    source ./tests/helpers.sh
    lock_fixture; out=$(fv_preflight 0 h1=fio-3.35 h2=fio-3.35 h3=fio-3.35) || { echo "$out" >&2; exit 1; }
    printf "%s\n" "$out" | grep -q "fio version: fio-3.35 on all 3 hosts$" &&
    printf "%s\n" "$out" | grep -qx "FIO_VERSION_NOTE=fio-3.35 on all 3 hosts" &&
    ! printf "%s\n" "$out" | grep -q "ERROR\|WARNING\|allow-fio-mismatch" || { echo "$out" >&2; false; }'
t_assert "fio version: a host whose fio --version fails or prints nothing stops the run, named, --allow-fio-mismatch or not" bash -c '
    source ./tests/helpers.sh
    for a in 0 1; do
        lock_fixture; out=$(fv_preflight $a h1=fio-3.35 h2=FAIL h3=EMPTY h4=fio-3.35) && { echo "allow=$a passed: $out" >&2; exit 1; }
        case "$out" in *"ERROR: h2: fio --version exited 3: fio: cannot load libaio"*"ERROR: h3: fio --version printed nothing"*"cannot read the fio version on 2 of 4 host(s), so there is nothing to compare"*) ;;
            *) echo "allow=$a: $out" >&2; exit 1;; esac
        case "$out" in *h1:*|*h4:*|*"fio differs"*) echo "allow=$a: $out" >&2; exit 1;; esac
    done'
t_assert "fio version: --allow-fio-mismatch prints the same grouped table as a WARNING, goes on, and the settings record it" bash -c '
    source ./tests/helpers.sh
    lock_fixture; out=$(fv_preflight 1 h1=fio-3.28 h2=fio-3.35 h3=fio-3.28) || { echo "stopped: $out" >&2; exit 1; }
    case "$out" in *"WARNING: fio differs across the hosts, 2 versions on 3 hosts"*"--allow-fio-mismatch runs anyway"*"WARNING:   fio-3.28 on 2 host(s): h1 h3"*"WARNING:   fio-3.35 on 1 host(s): h2"*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *ERROR*) echo "$out" >&2; exit 1;; esac
    printf "%s\n" "$out" | grep -qx "allow-fio-mismatch	versions differ, run anyway (--allow-fio-mismatch): fio-3.28 on 2 host(s): h1 h3; fio-3.35 on 1 host(s): h2" || { echo "$out" >&2; false; }'
t_assert "fio version: past eight hosts a version names eight and counts the rest" bash -c '
    source ./tests/helpers.sh
    hs=(); for i in $(seq 1 11); do hs+=("h$i=fio-3.35"); done
    lock_fixture; out=$(fv_preflight 0 "${hs[@]}" g1=fio-3.28) && { echo "passed: $out" >&2; exit 1; }
    printf "%s\n" "$out" | grep -q "ERROR:   fio-3.35 on 11 host(s): h1 h2 h3 h4 h5 h6 h7 h8 (+3 more)$" &&
    printf "%s\n" "$out" | grep -q "ERROR:   fio-3.28 on 1 host(s): g1$" || { echo "$out" >&2; false; }'
t_assert "fio version: local mode and a single host read no version and compare nothing" bash -c '
    source ./tests/helpers.sh; lock_fixture; export WEKATESTER_SUITE_LOCK_DIR=$LK/lock
    out=$( (export PATH="$LK/bin:$PATH" WEKATESTER_SUITE_TARGET_DIR="$LK/tgt"; source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); FIO_BIN=$LK/bin/fio; FIO_PIDFILE=$LK/fio.pid; WORK_DIR=$LK/w
            run_host() { printf "%s\n" "$2" >> "$LK/sent"; bash -c "$2"; }
            preflight 2>&1; echo "N=$FIO_VERSION_NOTE") ) || { echo "$out" >&2; exit 1; }
    printf "%s\n" "$out" | grep -qx "N=one host, nothing to compare" || { echo "local: $out" >&2; exit 1; }
    [ -s "$LK/sent" ] && ! grep -q -- "--version" "$LK/sent" || { echo "local mode read a version, or sent nothing" >&2; exit 1; }
    # one remote host whose fio prints nothing: nothing to compare, no stop
    lock_fixture; out=$(fv_preflight 0 h1=EMPTY) || { echo "one host stopped: $out" >&2; exit 1; }
    printf "%s\n" "$out" | grep -qx "FIO_VERSION_NOTE=one host, nothing to compare" &&
    [ -s "$LK/sent.h1" ] && ! grep -q -- "--version" "$LK/sent.h1" || { echo "one host: $out" >&2; false; }'
t_assert "fio version: a dry run runs the check (preflight, before the dry-run branch) and its report prints the result" bash -c '
    sed -n "/^preflight() {/,/^}/p" ./wekatester | grep -q "^    check_fio_versions$" &&
    sed -n "/^main() {/,/^}/p" ./wekatester | awk "/^    preflight$/ {p = NR} /DRY_RUN\" -eq 1/ {d = NR} END {exit !(p && d > p)}" || { echo "check not on the dry-run path" >&2; exit 1; }
    out=$(source ./wekatester; HOSTS=(h1 h2); MASTER=h1; JOBFILES=(); FIO_VERSION_NOTE="fio-3.35 on all 2 hosts"; dry_run_report 2>&1)
    printf "%s\n" "$out" | grep -q "fio version: fio-3.35 on all 2 hosts$" || { echo "$out" >&2; false; }'

# A findmnt failure means the mount mode is UNKNOWN, not wrong. Telling the
# operator to remount forcedirect then points away from the real fault, which
# for a bare run is usually that -d defaults to a /mnt/weka that does not exist.
t_assert "mount guard: findmnt failure blames the directory, not the mount mode" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka
            run_host() { return 1; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE )
    case "$err" in *forcedirect*) echo "leaked remount advice: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"findmnt failed for /mnt/weka -- does it exist? (wrong -d?)"*"-d names the right directory"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: a genuine cached-mode mount still says remount forcedirect" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka
            run_host() { echo "weka0 /mnt/weka wekafs rw,relatime,writecache 0 0"; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"wekafs mounted writecache (need forcedirect)"*"must be mounted with forcedirect; remount"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: one real mode failure outweighs a findmnt failure" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2); DIRECTORY=/mnt/weka
            run_host() { [ "$1" = h1 ] && return 1; echo "weka0 /mnt/weka wekafs rw,readcache 0 0"; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"h1: findmnt failed"*"h2: wekafs mounted readcache"*"must be mounted with forcedirect; remount"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# The port check guesses nothing: the teardown reads each failed host's fio
# server log, and its lines replace the firewall guess (issue #18).
t_assert "port check: a failed host is named without a guess and kept for the teardown report" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(vega-1 vega-2); MASTER=vega-1
            run_host() { echo "FAIL vega-2"; echo DONE; }
            trap "echo \"kept: \${PORT_FAILED[*]}\" >&2" EXIT
            verify_fio_ports) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"vega-1 cannot reach vega-2:8765"*"failed on 1 of 2 host(s), exiting; the fio server log of each follows the teardown"*"kept: vega-2") true;;
        *) echo "$err" >&2; false;;
    esac &&
    case "$err" in *firewall*|*loopback*) echo "guessed: $err" >&2; false;; *) true;; esac'
t_assert "port check report: the unreachable host's fio server log lines replace the firewall guess" bash -c '
    r=$(mktemp -d); mkdir -p "$r/sysinfo/h2"
    printf "%s\n" "# journalctl -t fio --since @1 (the run start): every fio that logged in the window, not only this run'"'"'s" \
        "2026-10-23T21:17:06+0000 h2 fio[2541055]: fio: server listening on 192.0.2.1,8765" \
        "2026-10-23T21:17:06+0000 h2 fio[2541056]: fio: bind: Cannot assign requested address" \
        "2026-10-23T21:17:06+0000 h2 fio[2541056]: fio: failed with IPv4 192.0.2.1" > "$r/sysinfo/h2/fio-server-log-end"
    err=$( (source ./wekatester; LOCAL_MODE=0; RUN_DIR=$r; PORT_FAILED=(h2); port_fail_report) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        (*"ERROR: h2:8765 unreachable; its fio server log says (sysinfo/h2/fio-server-log-end):"*"ERROR: h2:   2026-10-23T21:17:06+0000 h2 fio[2541056]: fio: bind: Cannot assign requested address"*"ERROR: h2:   "*"fio: failed with IPv4 192.0.2.1") true;;
        (*) echo "$err" >&2; false;;
    esac &&
    case "$err" in *firewall*|*"listening on"*|*"# journalctl"*) echo "guessed or echoed noise: $err" >&2; false;; *) true;; esac'
# On loopback a firewall is not the plausible cause; ::1-vs-IPv4 is.
t_assert "port check report: a log with nothing that explains it keeps the hint (firewall remote, loopback local) and says the log showed nothing" bash -c '
    r=$(mktemp -d); mkdir -p "$r/sysinfo/vega-2" "$r/sysinfo/localhost"
    for h in vega-2 localhost; do
        printf "%s\n" "# journalctl -t fio --since @1 (the run start): x" "2026-10-23T21:16:26+0000 $h fio[7]: fio: server listening on 0.0.0.0,8765" > "$r/sysinfo/$h/fio-server-log-end"
    done
    err=$( (source ./wekatester; LOCAL_MODE=0; RUN_DIR=$r; PORT_FAILED=(vega-2); port_fail_report) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        (*"vega-2:8765 unreachable, and its fio server log shows nothing that explains it (sysinfo/vega-2/fio-server-log-end) (host firewall?)") true;;
        (*) echo "remote: $err" >&2; exit 1;;
    esac
    err=$( (source ./wekatester; LOCAL_MODE=1; RUN_DIR=$r; PORT_FAILED=(localhost); port_fail_report) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        (*"localhost:8765 unreachable, and its fio server log shows nothing that explains it"*"(loopback resolution? fio binds IPv4"*) true;;
        (*) echo "local: $err" >&2; false;;
    esac'
t_assert "port check report: a host with no journal says its log could not be read, one with no capture says none was captured" bash -c '
    r=$(mktemp -d); mkdir -p "$r/sysinfo/h2"
    echo "not available: journalctl not installed, so this host keeps no journal to read" > "$r/sysinfo/h2/fio-server-log-end"
    err=$( (source ./wekatester; LOCAL_MODE=0; RUN_DIR=$r; PORT_FAILED=(h2 h3); port_fail_report) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        (*"h2:8765 unreachable, and its fio server log could not be read (not available: journalctl not installed, so this host keeps no journal to read) (host firewall?)"*"h3:8765 unreachable, and no fio server log was captured there (host firewall?)") true;;
        (*) echo "$err" >&2; false;;
    esac'
t_assert "port check report: a failed check's teardown prints it from the end capture, with no session of its own" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            WORK_DIR=$d/work; RUN_DIR=$d/run; mkdir -p "$WORK_DIR" "$RUN_DIR"
            HOSTS=(h1 h2); TARGET_DIR=/dev/shm/x; RUN_EPOCH=1; RUN_RC=1; FIO_STARTED=1; LOCAL_MODE=0; PORT_FAILED=(h2)
            run_host() { echo "$1" >> "$d/sessions"
                case "$2" in (*"WEKATESTER_SYSINFO fio-server-log"*)
                    printf "%s\n" "=== WEKATESTER_SYSINFO fio-server-log ===" "2026-10-23T21:17:06+0000 $1 fio[9]: fio: bind: Cannot assign requested address";; esac; }
            cleanup) 2>&1 >>$SUITE_ASIDE )
    [ "$(wc -l < "$d/sessions")" -eq 4 ] || { echo "sessions: $(cat "$d/sessions")" >&2; exit 1; }
    case "$err" in
        (*"ERROR: h2:   2026-10-23T21:17:06+0000 h2 fio[9]: fio: bind: Cannot assign requested address"*) true;;
        (*) echo "$err" >&2; false;;
    esac &&
    case "$err" in *"h1:8765"*|*firewall*) echo "reported a reachable host or guessed: $err" >&2; false;; *) true;; esac'
# 111 workers, one master: one ssh session per worker piled 111 sessions onto
# the master'"'"'s multiplexed connection, sshd refused past MaxSessions, and 39
# probes that never ran were reported as firewalls (field fleet D, 2026-09-09). The
# check is ONE session now, and a session that fails is said to be that.
t_assert "port check: one ssh session to the master however many workers there are" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     LOCAL_MODE=0; MASTER=h1; HOSTS=(h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12)
     run_host() { echo "$1" >> "$d/sessions"; echo DONE; }
     verify_fio_ports) >>$SUITE_ASIDE &&
    [ "$(wc -l < "$d/sessions")" -eq 1 ] && [ "$(cat "$d/sessions")" = h1 ]'
t_assert "port check: a failed ssh session to the master is not a firewall" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(vega-1 vega-2); MASTER=vega-1
            run_host() { echo "mux_client_request_session: session request failed" >&2; return 255; }
            verify_fio_ports) 2>&1 >>$SUITE_ASIDE ); rc=$?
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
            verify_fio_ports) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"vega-1 cannot reach vega-2:8765"*"failed on 1 of 3 host(s)"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    case "$err" in *"vega-3"*) echo "blamed a reachable host: $err" >&2; false;; *) true;; esac'

# --- local mode: staging end to end (no ssh, no sshd) ---
# The staging dir is redirected at a tmp dir through the real environment
# override, so both the override and the staging path are exercised: the
# master-side mkdir and the jobfile copy each go through a wrapper. The variable
# is namespaced (WEKATESTER_SUITE_TARGET_DIR) because a bare TARGET_DIR is common
# enough in build environments to hijack cleanup'"'"'s rm -rf by accident.
t_assert "local staging lands per-host variants under the staging dir" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_SUITE_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles && push_jobfiles) >>$SUITE_ASIDE || exit 1
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
# The shell expands ~ only at a word's start: in -i ubuntu:~/k it arrives
# literally, and wekatester expands it.
t_assert "validate_credentials expands a leading ~/ in the key path, after a login or alone" bash -c '
    d=$(mktemp -d); : > "$d/k"
    (source ./wekatester
     HOME=$d; LOCAL_MODE=0; IDENT_RAW=("ubuntu:~/k" "~/k")
     validate_credentials
     [ "${IDENT_LOGINS[*]}" = "ubuntu " ] && [ "${IDENT_KEYS[*]}" = "$d/k $d/k" ] ||
         { echo "logins: ${IDENT_LOGINS[*]}; keys: ${IDENT_KEYS[*]}" >&2; false; })'
# A bad key path must be named before the first ssh, not after ssh has already
# failed for a reason the operator has to reverse-engineer from BatchMode noise.
# A directory must be refused too: -i ~/.ssh is the likeliest typo and a
# directory passes a bare -r test.
t_assert "validate_credentials refuses missing keys, directories, and whitespace" bash -c '
    d=$(mktemp -d); k="$d/my key"; : > "$k"
    err=$( (source ./wekatester; LOCAL_MODE=0; IDENT_RAW=(/no/such/key)
            validate_credentials) 2>&1 >>$SUITE_ASIDE )
    case "$err" in *"identity file not readable: /no/such/key"*) true;; *) echo "$err" >&2; exit 1;; esac
    err=$( (source ./wekatester; LOCAL_MODE=0; IDENT_RAW=("ubuntu:$d")
            validate_credentials) 2>&1 >>$SUITE_ASIDE )
    case "$err" in *"identity file not readable: $d"*) true;; *) echo "$err" >&2; exit 1;; esac
    err=$( (source ./wekatester; LOCAL_MODE=0; IDENT_RAW=("ubuntu:$k")
            validate_credentials) 2>&1 >>$SUITE_ASIDE )
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
          mkdir -p "$d/w/jobs/h1"
          run_host vega-1 "df -kP /mnt/weka"
          copy_to_master "$d/w/jobs/h1" /dev/shm/fio-jobfiles/)
    [ "$out" = "SSH[-n][-o][BatchMode=yes][-o][CtlDummy=1][-o][User=ubuntu][vega-1][df -kP /mnt/weka]
SSH[-o][BatchMode=yes][-o][CtlDummy=1][-o][User=ubuntu][vega-1][mkdir -p '"'"'/dev/shm/fio-jobfiles/'"'"' && tar -xf - -C '"'"'/dev/shm/fio-jobfiles/'"'"']" ] ||
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
       printf "\033" | { confirm_timed 5 yes "q?" >>$SUITE_ASIDE; }) '
t_assert "confirm_timed: timeout yields the stated default" bash -c '
    (source ./wekatester; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
     confirm_timed 1 yes "q?" < <(sleep 2) >>$SUITE_ASIDE)'
t_assert "require_interactive dies without a terminal" bash -c '
    out=$( (source ./wekatester; PROMPT_TTY=/dev/null
            require_interactive "-p") 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && case "$out" in *"-p needs a terminal"*) true;; *) echo "$out" >&2; false;; esac'

# --- layout generator ---
t_assert "generator: one section per namespace with superset geometry" bash -c '
    source ./tests/helpers.sh; set_fixture
    (source ./wekatester; generate_layout "$SETFIX" "$SETFIX") >>$SUITE_ASIDE
    f="$SETFIX/000-wekatester-layout.job"
    grep -q "^# wekatester-layout: generated sha256=" "$f" &&
    grep -q "^filename_format=big/\$jobnum$" "$f" &&
    grep -q "^filename_format=small.\$jobnum$" "$f" &&
    grep -q "^nrfiles=3$" "$f" && grep -q "^numjobs=8$" "$f" && grep -q "^numjobs=4$" "$f" &&
    [ "$(grep -c "^create_only=1$" "$f")" -eq 2 ]'
t_assert "generator: deterministic (regeneration is byte-identical)" bash -c '
    source ./tests/helpers.sh; set_fixture
    (source ./wekatester
     generate_layout "$SETFIX" "$SETFIX" >>$SUITE_ASIDE
     cp "$SETFIX/000-wekatester-layout.job" /tmp/gen1.$$
     generate_layout "$SETFIX" "$SETFIX" >>$SUITE_ASIDE)
    diff -q /tmp/gen1.$$ "$SETFIX/000-wekatester-layout.job" >>$SUITE_ASIDE; rc=$?
    rm -f /tmp/gen1.$$; [ "$rc" -eq 0 ]'
t_assert "generator: pristine hash verifies and an edit breaks it" bash -c '
    source ./tests/helpers.sh; set_fixture
    (source ./wekatester; generate_layout "$SETFIX" "$SETFIX") >>$SUITE_ASIDE
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
     WEKATESTER_SUITE_TARGET_DIR="$d/target" TARGET_DIR="$d/target"
     DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
     stage_jobfiles >>$SUITE_ASIDE
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
     stage_jobfiles >>$SUITE_ASIDE
     grep -q "sha256=0000" "$WORK_DIR/set/000-wekatester-layout.job")'
# -g: the set's own layout job gives way to a fresh one in the STAGED copy;
# the source directory is never changed (code review #2, Frank, 2026-10-11).
t_assert "staging: -g stages a regenerated layout for a hand-edited own one, renamed or not; the source stays byte-identical" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    for name in 000-wekatester-layout.job 090-mylayout.job; do
        s=$(mktemp -d); w=$(mktemp -d); o=$(mktemp); cp "$SETFIX"/*.job "$s/"; mkdir -p "$w/jobs"
        (source ./wekatester; generate_layout "$s" "$s") >>$SUITE_ASIDE || exit 1
        [ "$name" = 000-wekatester-layout.job ] || mv "$s/000-wekatester-layout.job" "$s/$name"
        echo "# operator note" >> "$s/$name"; cp "$s/$name" "$o"
        (source ./wekatester
         LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; WORK_DIR=$w; REGEN_LAYOUT=1; DRY_RUN=1
         TARGET_DIR="$w/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$s
         stage_jobfiles >>$SUITE_ASIDE
         [ "${JOBFILES[*]}" = "000-wekatester-layout.job 011-bw.job 031-iops.job" ] &&
         layout_variant_pristine "$w/set") || { echo "$name: not regenerated" >&2; exit 1; }
        v="$w/jobs/localhost/000-wekatester-layout.job"
        cmp "$o" "$s/$name" >>$SUITE_ASIDE && [ "$(ls "$s" | wc -l)" -eq 3 ] &&
        { [ "$name" = 000-wekatester-layout.job ] || [ ! -e "$w/set/$name" ]; } &&
        ! grep -q "operator note" "$v" && grep -qx "directory=/mnt/x" "$v" || { echo "$name:" >&2; cat "$v" >&2; exit 1; }
    done'
t_assert "staging: without -g a hand-edited own layout is staged as written" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    (source ./wekatester; generate_layout "$SETFIX" "$SETFIX") >>$SUITE_ASIDE || exit 1
    l="$SETFIX/000-wekatester-layout.job"; o=$(mktemp); echo "# operator note" >> "$l"; cp "$l" "$o"
    w=$(mktemp -d); mkdir -p "$w/jobs"
    (source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; WORK_DIR=$w; REGEN_LAYOUT=0; DRY_RUN=1
     TARGET_DIR="$w/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
     stage_jobfiles) >>$SUITE_ASIDE || exit 1
    cmp "$o" "$l" >>$SUITE_ASIDE && cmp "$o" "$w/set/000-wekatester-layout.job" >>$SUITE_ASIDE &&
    grep -qx "# operator note" "$w/jobs/localhost/000-wekatester-layout.job"'
t_assert "staging -a -g: a hand-edited own layout is regenerated and re-derived per host, with no edited-layout warning" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE || exit 1
    echo "# operator note" >> "$FIX/src/000-wekatester-layout.job"
    err=$( (source ./wekatester
     HOSTS=(h1 h2); MASTER=h1; WORK_DIR=$FIX; AUTO_LEVEL=max; REGEN_LAYOUT=1; DRY_RUN=1
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; SET_DIR_OVERRIDE=$FIX/src
     stage_jobfiles) 2>&1 >>$SUITE_ASIDE ) || { echo "$err" >&2; exit 1; }
    for h in h1 h2; do
        v="$FIX/jobs/$h/000-wekatester-layout.job"
        grep -q "re-derived by wekatester auto\[max\]" "$v" && ! grep -q "operator note" "$v" || { cat "$v" >&2; exit 1; }
    done
    case "$err" in *"user-edited layout"*) echo "$err" >&2; false;; *) true;; esac'
t_assert "staging -g: a discovered engine reaches the regenerated layout as it reaches a generated one" bash -c '
    d=$(mktemp -d); s=$(mktemp -d); mkdir -p "$d/jobs"
    printf "# report bandwidth\n[global]\nfilesize=1G\nnumjobs=1\n[a]\nrw=read\n" > "$s/011-a.job"
    printf "# report iops\n[global]\nfilesize=1G\nnumjobs=1\n[c]\nioengine=psync\nrw=randwrite\n" > "$s/032-c.job"
    (source ./wekatester; generate_layout "$s" "$s") >>$SUITE_ASIDE || exit 1
    echo "# operator note" >> "$s/000-wekatester-layout.job"
    printf "h1 libaio\n" > "$d/engine.discovered"
    (source ./wekatester
     HOSTS=(h1 h2); MASTER=h1; WORK_DIR=$d; REGEN_LAYOUT=1; DRY_RUN=1; ENGINE=""
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/global; SET_DIR_OVERRIDE=$s
     stage_jobfiles) >>$SUITE_ASIDE 2>&1 || exit 1
    v="$d/jobs/h1/000-wekatester-layout.job"
    grep -qx "ioengine=libaio" "$v" && ! grep -q "operator note" "$v" &&
    grep -qx "ioengine=psync" "$d/jobs/h2/000-wekatester-layout.job" || { cat "$v" >&2; false; }'
t_assert "tuner: a pristine layout is re-derived per host at every level, covering what each host runs" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\ndirectory=/orig\n[io]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE
    # h1 measured 3 bandwidth jobs and 3 iops jobs of two 1G files; h2 has no row
    row=(h1); for i in $(seq 1 36); do row+=(-); done
    row[5]=3; row[21]=3; row[22]=1G; row[23]=2; row[24]=8
    (IFS=$(printf "\t"); echo "${row[*]}") > "$FIX/targets.final"
    for lvl in safe max cal brutal; do
        (source ./wekatester; auto_tune "$FIX/src" "$FIX" $lvl /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
        v1="$FIX/jobs/h1/000-wekatester-layout.job"; v2="$FIX/jobs/h2/000-wekatester-layout.job"
        grep -q "re-derived by wekatester auto\[$lvl\]" "$v1" && grep -q "re-derived by wekatester auto\[$lvl\]" "$v2" &&
        grep -qx "numjobs=3" "$v1" && ! grep -qx "numjobs=4" "$v1" && grep -qx "nrfiles=2" "$v1" && grep -qx "filesize=1G" "$v1" &&
        grep -qx "cpus_allowed=2-4" "$v1" &&
        grep -qx "numjobs=4" "$v2" && ! grep -qx "numjobs=3" "$v2" && ! grep -q "^nrfiles=" "$v2" ||
            { echo "-a $lvl:" >&2; cat "$v1" "$v2" >&2; exit 1; }
    done'
t_assert "tuner: edited layout at max is staged as-is with a warning" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE
    echo "# operator note" >> "$FIX/src/000-wekatester-layout.job"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >>$SUITE_ASIDE )
    v="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -q "# operator note" "$v" && ! grep -q "re-derived" "$v" &&
    case "$err" in *"user-edited layout staged as-is"*) true;; *) echo "$err" >&2; false;; esac'
# The layout lays out where the measured jobs will run: a host-file dir is
# that host's destination for the layout too, never the global -d.
t_assert "tuner: the re-derived layout is marked and lays out at each host's own destination" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE
    { printf "h1\t-\t-\t-\t/mnt/pin"; for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
    l1="$FIX/jobs/h1/000-wekatester-layout.job"; l2="$FIX/jobs/h2/000-wekatester-layout.job"
    head -1 "$l1" | grep -q "^# wekatester-layout: generated (re-derived by wekatester auto\[max\]" &&
    (source ./wekatester; is_layout_file "$l1") &&
    grep -q "^directory=/mnt/pin$" "$l1" && grep -q "^directory=/mnt/weka$" "$l2" &&
    grep -q "^directory=/mnt/pin$" "$FIX/jobs/h1/011-bw.job" &&
    [ "$(cat "$FIX/usable/h1")" = "2-4" ] || { cat "$l1" >&2; false; }'
t_assert "tuner: an edited layout is staged at each host's own destination too" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE
    echo "# operator note" >> "$FIX/src/000-wekatester-layout.job"
    { printf "h1\t-\t-\t-\t/mnt/pin"; for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
    grep -q "^directory=/mnt/pin$" "$FIX/jobs/h1/000-wekatester-layout.job" &&
    grep -q "^directory=/mnt/weka$" "$FIX/jobs/h2/000-wekatester-layout.job"'
# The fleet-shared read set is calibration's: safe and max stage reads on
# the client's own grid, exactly as a plain run does.
t_assert "staging: every -a level calibrates, so every level puts reads on the fleet-shared set" bash -c '
    d=$(mktemp -d); mkdir -p "$d/set"
    printf "ncpus 8\nbindable 0-7\nbindable_priv -\nengines libaio psync\n" > "$d/probe.h1"
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\nnumjobs=2\nioengine=libaio\n[j]\nrw=read\n" > "$d/set/011-r.job"
    for lvl in safe max cal brutal; do
        w=$(mktemp -d); mkdir -p "$w/jobs" "$w/probe"; cp "$d/probe.h1" "$w/probe/h1"
        (source ./wekatester
         WORK_DIR=$w; DIRECTORY=/mnt/w; HOSTS=(h1); AUTO_LEVEL=$lvl
         stage_variants "$d/set") >>$SUITE_ASIDE 2>&1 || { echo "stage_variants failed at -a $lvl" >&2; exit 1; }
        grep -qx "filename_format=shared.\$filenum/\$jobnum" "$w/jobs/h1/011-r.job" ||
            { echo "-a $lvl: $(grep "^filename_format=" "$w/jobs/h1/011-r.job")" >&2; exit 1; }
    done'
t_assert "tuner capacity: layout job does not double the required total" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE
    out=$( cap safe 0 h1 h2 2>&1 )
    case "$out" in *"capacity: h1 needs ~40.0GiB"*) true;; *) echo "$out" >&2; false;; esac'

# --- review fixes: layout union geometry, ordering ---
t_assert "generator: divergent geometries yield one section each (union, not grid)" bash -c '
    source ./tests/helpers.sh
    S=$(mktemp -d)
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=4\n[a]\nrw=read\n" > "$S/011-a.job"
    printf "# report iops\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=2\nnrfiles=27\n[b]\nrw=randread\n" > "$S/031-b.job"
    printf "# report iops\n[global]\nfilename_format=x/\$jobnum\nfilesize=15G\nnumjobs=2\nnrfiles=2\n[c]\nrw=randread\n" > "$S/032-c.job"
    (source ./wekatester; generate_layout "$S" "$S") >>$SUITE_ASIDE
    f="$S/000-wekatester-layout.job"
    [ "$(grep -c "^create_only=1$" "$f")" -eq 3 ] &&
    ! grep -q "^stonewall$" "$f" &&
    [ "$(grep -c "^wait_for=" "$f")" -eq 2 ]'
t_assert "generator: distinct namespaces lay out in parallel (no ordering between them)" bash -c '
    S=$(mktemp -d)
    printf "# report bandwidth\n[global]\nfilename_format=big/\$jobnum\nfilesize=10G\nnumjobs=4\n[a]\nrw=read\n" > "$S/011-a.job"
    printf "# report iops\n[global]\nfilename_format=small.\$jobnum\nfilesize=1G\nnumjobs=8\n[b]\nrw=randread\n" > "$S/031-b.job"
    (source ./wekatester; generate_layout "$S" "$S") >>$SUITE_ASIDE
    f="$S/000-wekatester-layout.job"
    [ "$(grep -c "^create_only=1$" "$f")" -eq 2 ] &&
    ! grep -q "^stonewall$" "$f" && ! grep -q "^wait_for=" "$f"'
t_assert "generator: a jobname namespace with several contributors gets unique chained names" bash -c '
    S=$(mktemp -d)
    printf "[global]\nfilesize=1G\nnumjobs=4\n[shared]\nrw=read\n" > "$S/011-a.job"
    printf "[global]\nfilesize=2G\nnumjobs=2\n[shared]\nrw=read\n" > "$S/012-b.job"
    (source ./wekatester; generate_layout "$S" "$S") >>$SUITE_ASIDE
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
    (source ./wekatester; generate_layout "$S" "$S") >>$SUITE_ASIDE
    f="$S/000-wekatester-layout.job"
    [ "$(grep -c "^create_only=1$" "$f")" -eq 1 ] && grep -q "^numjobs=64$" "$f"'
# fio fills $jobname with the section that runs: a layout section named
# layout-N would lay out layout-N.* while the job opens rd.*, so the layout
# spells the measured section's name out.
t_assert "generator: a jobname format lays out the measured section's own names, set in the section or in [global]" bash -c '
    for where in sec glob; do
        S=$(mktemp -d)
        if [ "$where" = sec ]; then printf "[global]\nfilesize=1G\nnumjobs=2\n[rd]\nrw=read\nfilename_format=\$jobname.\$jobnum.\$filenum\n" > "$S/011-a.job"
        else printf "[global]\nfilesize=1G\nnumjobs=2\nfilename_format=\$jobname.\$jobnum.\$filenum\n[rd]\nrw=read\n" > "$S/011-a.job"; fi
        (source ./wekatester; generate_layout "$S" "$S") >>$SUITE_ASIDE || exit 1
        f="$S/000-wekatester-layout.job"
        grep -qx "filename_format=rd.\$jobnum.\$filenum" "$f" && ! grep -q "\$jobname" "$f" || { echo "$where:" >&2; cat "$f" >&2; exit 1; }
    done'
t_assert "generator: two sections sharing one jobname format lay out one namespace each" bash -c '
    S=$(mktemp -d)
    printf "[global]\nfilesize=1G\nnumjobs=2\nfilename_format=\$jobname.\$jobnum.\$filenum\n[rd]\nrw=read\n" > "$S/011-a.job"
    printf "[global]\nfilesize=1G\nnumjobs=2\nfilename_format=\$jobname.\$jobnum.\$filenum\n[rd2]\nrw=randread\n" > "$S/012-b.job"
    (source ./wekatester; generate_layout "$S" "$S") >>$SUITE_ASIDE || exit 1
    f="$S/000-wekatester-layout.job"
    [ "$(grep -c "^create_only=1$" "$f")" -eq 2 ] &&
    grep -qx "filename_format=rd.\$jobnum.\$filenum" "$f" && grep -qx "filename_format=rd2.\$jobnum.\$filenum" "$f" &&
    ! grep -q "^wait_for=" "$f" || { cat "$f" >&2; false; }'
t_assert "capacity: layout union raises required above per-namespace max" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    rm -f "$FIX/src/011-bw.job"
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=4\nioengine=libaio\ndirectory=/orig\n[a]\nrw=read\niodepth=1\n" > "$FIX/src/011-a.job"
    printf "# report bandwidth\n[global]\nfilename_format=x/\$jobnum\nfilesize=1G\nnumjobs=2\nnrfiles=27\nioengine=libaio\ndirectory=/orig\n[b]\nrw=read\niodepth=1\n" > "$FIX/src/012-b.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE
    out=$( cap safe 0 h1 h2 2>&1 )
    # a: 4 jobs x 1 file = 4G; b: 2 jobs x 27 files = 54G, the namespace max;
    # the layout lays out both sections, 58G/host, so the union raises the
    # per-host requirement above 54G, proving layout_footprint runs
    case "$out" in *"capacity: h1 needs ~58.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
# A hand layout's geometry falls back to [global] (Bugbot "Layout capacity
# ignores global knobs", 2026-10-12): 4 jobs x 2 files x 10G = 80G, above
# the measured 40G, either way it is keyed.
t_assert "capacity: a hand layout keeping numjobs/nrfiles/filesize in [global] is priced" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "[global]\nnumjobs=4\nnrfiles=2\nfilesize=10G\ndirectory=/orig\n[layout-1]\ncreate_only=1\n" > "$FIX/src/000-wekatester-layout.job"
    out=$( cap safe 0 h1 h2 2>&1 )
    case "$out" in *"capacity: h1 needs ~80.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "capacity: a hand layout keyed in its section is priced the same" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "[global]\ndirectory=/orig\n[layout-1]\ncreate_only=1\nnumjobs=4\nnrfiles=2\nfilesize=10G\n" > "$FIX/src/000-wekatester-layout.job"
    out=$( cap safe 0 h1 h2 2>&1 )
    case "$out" in *"capacity: h1 needs ~80.0GiB"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "staging: marker layout with a late-sorting name is forced first" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    (source ./wekatester; generate_layout "$SETFIX" "$SETFIX") >>$SUITE_ASIDE
    mv "$SETFIX/000-wekatester-layout.job" "$SETFIX/090-mylayout.job"
    d=$(mktemp -d)
    (source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost
     WORK_DIR=$(mktemp -d); mkdir -p "$WORK_DIR/jobs"
     TARGET_DIR="$d/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
     stage_jobfiles >>$SUITE_ASIDE
     [ "${JOBFILES[0]}" = "090-mylayout.job" ] && [ "${#JOBFILES[@]}" -eq 3 ])'

# --- -o/--output and the results directory ---
t_assert "parse: results dir defaults to ./results" bash -c '
    (source ./wekatester; parse_args h1; [ "$OUTPUT_DIR" = results ])'
t_assert "parse: -o detached, --output=, and attached -o all set the output dir" bash -c '
    (source ./wekatester; parse_args -o out1 h1;        [ "$OUTPUT_DIR" = out1 ]) &&
    (source ./wekatester; parse_args --output=out2 h1;  [ "$OUTPUT_DIR" = out2 ]) &&
    (source ./wekatester; parse_args -oout3 h1;         [ "$OUTPUT_DIR" = out3 ]) &&
    (source ./wekatester; parse_args -o=out4 h1;        [ "$OUTPUT_DIR" = out4 ]) &&
    (source ./wekatester; parse_args -Oout5 h1;         [ "$OUTPUT_DIR" = out5 ])'

t_assert "parse: CLI_DIR is the trimmed -d directory, or - without -d (resolve_targets' cli-dir)" bash -c '
    (source ./wekatester; parse_args -d /x/ h1; [ "$CLI_DIR" = /x ]) &&
    (source ./wekatester; parse_args h1;        [ "$CLI_DIR" = - ])'
t_assert "parse: -x, -xN and --duration= set DURATION; a bad value dies naming the spelling used" bash -c '
    (source ./wekatester; parse_args -x 30 h1;         [ "$DURATION" = 30 ]) &&
    (source ./wekatester; parse_args -x5 h1;           [ "$DURATION" = 5 ]) &&
    (source ./wekatester; parse_args --duration=45 h1; [ "$DURATION" = 45 ]) &&
    for a in "-x 0" "-x abc" "-xabc" "--duration 1.5" "--duration=" "--duration=-3"; do
        out=$( (source ./wekatester; parse_args $a h1) 2>&1 ) && { echo "accepted: $a" >&2; exit 1; }
        case $a in (--duration=*) want="option --duration needs" ;; (*) want="option -x needs" ;; esac
        case $out in (*"$want a duration in whole seconds"*) ;; (*) echo "$a: [$out]" >&2; exit 1 ;; esac
    done'
# --- the Python wekatester's long names: aliases of -d, -w and -f ---
# (code review #7, Frank, 2026-10-11)
t_assert "parse: --directory, detached or =, sets the -d directory and marks it explicit" bash -c '
    (source ./wekatester; parse_args --directory /x h1;   [ "$DIRECTORY" = /x ] && [ "$DIRECTORY_EXPLICIT" -eq 1 ] && [ "${HOSTS[*]}" = h1 ]) &&
    (source ./wekatester; parse_args --directory=/y/ h1;  [ "$DIRECTORY" = /y ] && [ "$DIRECTORY_EXPLICIT" -eq 1 ] && [ "${HOSTS[*]}" = h1 ]) &&
    (source ./wekatester; parse_args --DIRECTORY=/Z h1;   [ "$DIRECTORY" = /Z ])'
t_assert "parse: --workload, detached or =, sets the -w workload" bash -c '
    (source ./wekatester; parse_args --workload smoke h1;  [ "$WORKLOAD" = smoke ] && [ "${HOSTS[*]}" = h1 ]) &&
    (source ./wekatester; parse_args --workload=Mixed h1;  [ "$WORKLOAD" = Mixed ] && [ "${HOSTS[*]}" = h1 ])'
t_assert "parse: --fio-bin and --local-fio, detached or =, set the -f fio binary" bash -c '
    (source ./wekatester; parse_args --fio-bin /opt/fio h1;     [ "$FIO_BIN" = /opt/fio ] && [ "${HOSTS[*]}" = h1 ]) &&
    (source ./wekatester; parse_args --fio-bin=/opt/fio2 h1;    [ "$FIO_BIN" = /opt/fio2 ]) &&
    (source ./wekatester; parse_args --local-fio /tmp/fio h1;   [ "$FIO_BIN" = /tmp/fio ] && [ "${HOSTS[*]}" = h1 ]) &&
    (source ./wekatester; parse_args --LOCAL-FIO=/tmp/fio2 h1;  [ "$FIO_BIN" = /tmp/fio2 ])'
t_assert "parse: a long alias with no value dies as its short form does" bash -c '
    for o in --directory --workload --fio-bin --local-fio; do
        err=$( (source ./wekatester; parse_args h1 "$o") 2>&1 >>$SUITE_ASIDE ) && { echo "$o: accepted" >&2; exit 1; }
        case "$err" in *"ERROR: option $o requires an argument"*) ;; *) echo "$o: $err" >&2; exit 1;; esac
        err=$( (source ./wekatester; parse_args "$o" -g h1) 2>&1 >>$SUITE_ASIDE ) && { echo "$o -g: accepted" >&2; exit 1; }
        case "$err" in *"option $o requires an argument, got '\''-g'\'' (looks like another option)"*) ;; *) echo "$o -g: $err" >&2; exit 1;; esac
        err=$( (source ./wekatester; parse_args "$o=" h1) 2>&1 >>$SUITE_ASIDE ) && { echo "$o=: accepted" >&2; exit 1; }
        case "$err" in *"ERROR: option $o requires a value"*) ;; *) echo "$o=: $err" >&2; exit 1;; esac
    done'
t_assert "run_jobs: the results file lands in RUN_DIR, no timestamp infix" bash -c '
    source ./tests/helpers.sh
    tmp=$(mktemp -d); mkdir "$tmp/out" "$tmp/set"
    printf "# report bandwidth\n[global]\nfilesize=1M\n[bw]\nrw=read\n" > "$tmp/set/011-bw.job"
    fio_json_single_fixture "$tmp/fixture.json"
    (source ./wekatester
     HOSTS=(vega-1); MASTER=vega-1; FIO_BIN=fio; TARGET_DIR=/dev/shm/x
     SET_DIR=$tmp/set; JOBFILES=(011-bw.job); RUN_DIR=$tmp/out
     run_host() { cat "$tmp/fixture.json"; }
     run_jobs >>$SUITE_ASIDE) &&
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
     finalize_run_dir) >>$SUITE_ASIDE 2>&1
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
        finalize_run_dir" >>$SUITE_ASIDE 2>&1 &&
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
t_assert "run bundle: pigz on PATH compresses the bundle, and -s and tar -xzf read it" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); mkdir -p "$d/bin" "$d/res/20260101-000003"
    printf "#!/bin/bash\necho \"pigz \$*\" >> %q\nexec gzip \"\$@\"\n" "$d/calls" > "$d/bin/pigz"
    chmod +x "$d/bin/pigz"
    fio_json_single_fixture "$d/res/20260101-000003/results_011-bw.json"
    (source ./wekatester
     OUTPUT_DIR=$d/res; RUN_STAMP=20260101-000003; RUN_DIR=$d/res/$RUN_STAMP
     PATH=$d/bin:$PATH; finalize_run_dir) >>$SUITE_ASIDE 2>&1
    test -s "$d/calls" && test ! -d "$d/res/20260101-000003" &&
    mkdir "$d/x" && tar -xzf "$d/res/20260101-000003.tgz" -C "$d/x" &&
    test -f "$d/x/20260101-000003/results_011-bw.json" &&
    out=$(./wekatester -s "$d/res/20260101-000003.tgz") &&
    case "$out" in
        *"==== 011-bw ===="*"read bandwidth: 2.00 GiB/s"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "run bundle: without pigz, tar compresses through plain gzip" bash -c '
    d=$(mktemp -d); mkdir -p "$d/bin" "$d/res/20260101-000004"
    gz=$(command -v gzip) && tr=$(command -v tar) && r=$(command -v rm) || exit 1
    ln -s "$tr" "$d/bin/tar"; ln -s "$r" "$d/bin/rm"
    printf "#!%s\necho \"gzip \$*\" >> %q\nexec %q \"\$@\"\n" "$BASH" "$d/calls" "$gz" > "$d/bin/gzip"
    chmod +x "$d/bin/gzip"
    echo payload > "$d/res/20260101-000004/wekatester.log"
    (source ./wekatester
     OUTPUT_DIR=$d/res; RUN_STAMP=20260101-000004; RUN_DIR=$d/res/$RUN_STAMP
     PATH=$d/bin; finalize_run_dir) >>$SUITE_ASIDE 2>&1
    test -s "$d/calls" && test ! -d "$d/res/20260101-000004" &&
    tar -xzOf "$d/res/20260101-000004.tgz" 20260101-000004/wekatester.log | grep -q payload'
t_assert "run bundle: a failing pigz keeps the directory and says so; finalize returns" bash -c '
    d=$(mktemp -d); mkdir -p "$d/bin" "$d/res/20260101-000005"
    printf "#!/bin/bash\ncat >> %q; exit 1\n" "$d/swallowed" > "$d/bin/pigz"
    chmod +x "$d/bin/pigz"
    echo payload > "$d/res/20260101-000005/wekatester.log"
    out=$( (source ./wekatester
            OUTPUT_DIR=$d/res; RUN_STAMP=20260101-000005; RUN_DIR=$d/res/$RUN_STAMP
            PATH=$d/bin:$PATH; finalize_run_dir; echo "finalize returned") 2>&1 )
    test -f "$d/res/20260101-000005/wekatester.log" &&
    case "$out" in
        *"ERROR: could not compress $d/res/20260101-000005; leaving it uncompressed"*"finalize returned"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "run bundle: cmdline is the argv shell-quoted, \$0 first; settings holds what it resolved to" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     RUN_DIR=$d; ARGV_TYPED=(./wekatester -a cal:15 -w "my set" "" "it'\''s" h1 h2)
     parse_args -a cal:15 -w "my set" h1 h2; record_run) >>$SUITE_ASIDE 2>&1 || exit 1
    eval "a=($(cat "$d/cmdline"))"
    [ ${#a[@]} -eq 9 ] && [ "${a[0]}" = ./wekatester ] && [ "${a[4]}" = "my set" ] && [ -z "${a[5]}" ] &&
    [ "${a[6]}" = "it'\''s" ] && [ "${a[8]}" = h2 ] && [ "$(wc -l < "$d/cmdline")" -eq 1 ] || { cat "$d/cmdline" >&2; exit 1; }
    [ "$(cat "$d/settings")" = "$(printf "version\t%s\nworkload\tmy set\nauto\tcal\ncal-seconds\t15\nmaster\th1\nhosts\th1 h2" \
        "$(./wekatester --version | sed "s/.* //")")" ] || { cat "$d/settings" >&2; false; }'
t_assert "run bundle: no -a records auto and cal-seconds as -; sourced runs (no argv) write no cmdline" bash -c '
    d=$(mktemp -d)
    (source ./wekatester; RUN_DIR=$d; parse_args h1; record_run) >>$SUITE_ASIDE 2>&1 || exit 1
    [ ! -e "$d/cmdline" ] && grep -q "^auto	-$" "$d/settings" && grep -q "^cal-seconds	-$" "$d/settings"'
t_assert "run bundle: settings records each WT_* setting off its default with its source; -s still reads the bundle" bash -c '
    d=$(mktemp -d); r=$d/20260101-000000; printf "host,user_login\nWT_ENGINE=psync\nWT_SETTLE=2\n" > "$d/h.csv"
    (unset $(compgen -v WT_); export WT_DURATION=900
     source ./wekatester
     settings_parse -t "$d/h.csv" -b h1 && TARGETS_FILE=$d/h.csv && settings_from_file && check_args && settings_check_env &&
     RUN_DIR=$r && mkdir "$r" && record_run) >>$SUITE_ASIDE 2>&1 || exit 1
    t=$(printf "\t")
    # WT_SETTLE=2 is its default: not recorded
    grep -qx "WT_DURATION${t}900${t}environment" "$r/settings" && grep -qx "WT_ENGINE${t}psync${t}$d/h.csv:2" "$r/settings" &&
    grep -qx "WT_BULK${t}1${t}cli" "$r/settings" && [ "$(grep -c "^WT_" "$r/settings")" = 3 ] || { cat "$r/settings" >&2; exit 1; }
    source ./tests/helpers.sh; fio_json_single_fixture "$r/results_011-bw.json"
    tar -czf "$d/b.tgz" -C "$d" 20260101-000000
    out=$(./wekatester -s "$d/b.tgz") || { echo "$out" >&2; exit 1; }
    case "$out" in *"==== 011-bw ===="*) ;; *) echo "$out" >&2; false;; esac'
t_assert "run bundle: the run records argv and settings right after the run dir exists, before the log starts" bash -c '
    m=$(sed -n "/^main() {/,/^}/p" ./wekatester)
    seq=$(printf "%s\n" "$m" | grep -A2 "mkdir \"\$RUN_DIR\"" | sed "s/^ *//;s/ *||.*//" | tr "\n" "|")
    [ "$seq" = "mkdir \"\$RUN_DIR\"|record_run|start_run_log|" ] || { echo "$seq" >&2; exit 1; }
    g=$(grep -A3 "BASH_SOURCE\[0\]" ./wekatester | sed "s/^ *//" | tr "\n" "|")
    case "$g" in *"|ARGV_TYPED=(\"\$0\" \"\$@\")|settings_parse \"\$@\"|main|") true;; *) echo "$g" >&2; false;; esac'
t_assert "run bundle: fs groups are kept as fs-groups when a run dir exists, and not in a dry run" bash -c '
    w=$(mktemp -d); r=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$w; RUN_DIR=$r; HOSTS=(h1 h2 h3); GROUP_FILE=.g.lst; DIRECTORY=/mnt/x
     run_host() { case "$2" in (sha256sum*) case "$1" in (h3) echo "bbbb  f";; (*) echo "aaaa  f";; esac;; esac; }
     collect_fs_groups
     WORK_DIR=$(mktemp -d); RUN_DIR=""; collect_fs_groups; ls "$WORK_DIR" > "$w/dry") >>$SUITE_ASIDE 2>&1 || exit 1
    [ "$(tr "\n" " " < "$r/fs-groups")" = "h1 1 h2 1 h3 2 " ] && grep -q "^groups$" "$w/dry"'

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
# The layout is now a sequential write of what was missing: its results are
# a measurement, reported like a test, run and -s alike.
t_assert "-s: a layout staged as a dense write reports as the layout's sequential write; a run with nothing to write says so" bash -c '
    d=$(mktemp -d); b="$d/20260101-000000"; mkdir -p "$b/fio-jobfiles/h1"
    w() { printf "{ \"jobname\": \"%s\", \"hostname\": \"%s\", \"error\": 0, \"read\": { \"bw_bytes\": 0, \"iops\": 0, \"total_ios\": 0, \"io_bytes\": 0, \"lat_ns\": { \"mean\": 0 } }, \"write\": { \"bw_bytes\": %s, \"iops\": 1, \"total_ios\": 1, \"io_bytes\": %s, \"lat_ns\": { \"mean\": 1 } } }" "$1" "$2" "$3" "$4"; }
    printf "{ \"client_stats\": [ %s, %s, %s ] }\n" "$(w lay-0 h1 1073741824 10737418240)" "$(w lay-0 h2 2147483648 21474836480)" \
        "$(w "All clients" "" 3221225472 32212254720)" > "$b/results_000-wekatester-layout.json"
    printf "# wekatester-layout: generated as a dense write\n[global]\n[lay-0]\nrw=write\nfilename=h1.0\n" > "$b/fio-jobfiles/h1/000-wekatester-layout.job"
    tar -czf "$d/bundle.tgz" -C "$d" 20260101-000000
    out=$(./wekatester -s "$d/bundle.tgz") || { echo "$out" >&2; exit 1; }
    want="==== 000-wekatester-layout (layout sequential write) ====
    write bandwidth: 3.00 GiB/s
    average bandwidth: 1.50 GiB/s per host  (min 1.00 GiB/s h1, max 2.00 GiB/s h2)
    written: 30.00 GiB, 15.00 GiB per host  (min 10.00 GiB h1, max 20.00 GiB h2)"
    case "$out" in *"$want"*) true;; *) printf "%s\n--- want:\n%s\n" "$out" "$want" >&2; exit 1;; esac
    # every file complete: no layout ran, and the settings record says so
    rm "$b/results_000-wekatester-layout.json"
    printf "{ \"client_stats\": [ %s ] }\n" "$(w bw h1 1073741824 1073741824)" > "$b/results_011-bw.json"
    printf "version\tx\nlayout\tnothing to write (files reused)\n" > "$b/settings"
    tar -czf "$d/bundle2.tgz" -C "$d" 20260101-000000
    out=$(./wekatester -s "$d/bundle2.tgz") || { echo "$out" >&2; exit 1; }
    case "$out" in *"layout: nothing to write (files reused)"*"==== 011-bw ===="*) true;; *) echo "$out" >&2; false;; esac'
t_assert "-s: a result in another JSON layout is named; the rest of the bundle still summarizes" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); b="$d/20260101-000000"; mkdir -p "$b"
    printf "{ \"client_stats\": [ { \"jobname\": \"All clients\", \"read\": {} } ] }\n" > "$b/results_011-odd.json"
    fio_json_single_fixture "$b/results_012-bw.json"
    tar -czf "$d/bundle.tgz" -C "$d" 20260101-000000
    out=$(./wekatester -s "$d/bundle.tgz") || { echo "$out" >&2; exit 1; }
    case "$out" in
        *"==== 011-odd ===="*"results_011-odd.json: not the fio JSON layout this summary reads"*"==== 012-bw ===="*"read bandwidth: 2.00 GiB/s"*) true;;
        *) echo "$out" >&2; exit 1;;
    esac
    cp "$b/results_011-odd.json" "$d/odd.json"
    ! out=$(./wekatester -s "$d/odd.json" 2>&1) &&
    case "$out" in
        *"odd.json: not the fio JSON layout this summary reads"*) true;;
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

# --- -s synopsis: the bundle's own record of the run, ahead of its jobs ---
t_assert "-s synopsis: an -a bundle shows each shape's representative and the parameters its staged jobs ran" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" cal
    out=$(summ_out "$d") || { echo "$out" >&2; exit 1; }
    hdr=$(printf "%s\n" "$out" | awk "/^==== /{exit} {print}")
    exp=$(cat <<"X"
run      2026-10-23 14:10:02 (bundle b.tgz)
version  wekatester 2026-10-11, fio 3.36, weka 4.4.2 (2 hosts), no weka CLI (1 host)
command  ./wekatester -a cal -w default h1 h2 h3
clients  3 (master h1), 2 shapes, 1 filesystem group
workload default; -a cal (30 s cells); dest /mnt/weka/wt (wekafs)

shape 1: 2 hosts, rep h1, N=26, line rate 400 Gb/s
  Example CPU, 64 cpus, 512 GiB, weka NICs ens1 ens2: 2 x mlx5_core [0x15b3:0x101d] 200 Gb/s -> line rate 46.57 GiB/s
  engine libaio
  bw-read          nj 4     qd 2     nr 1     bs 1Mi     011-bw
  lat-read 1job    nj 1     qd 1     nr 1     bs 4k      021-lat-1job
  lat-read         nj 16    qd 1     nr -     bs 4k      021-lat
shape 2: 1 host, rep h3, N=12, line rate unknown
  Example CPU, 32 cpus, 256 GiB, weka NICs: no line rate
  engine libaio
  bw-read          nj 2     qd 2     nr 1     bs 1Mi     011-bw
  lat-read 1job    nj 1     qd 1     nr 1     bs 4k      021-lat-1job
  lat-read         nj 16    qd 1     nr -     bs 4k      021-lat
X
)
    [ "$hdr" = "$exp" ] || { printf "%s\n" "$out" >&2; exit 1; }
    case "$out" in *"==== 011-bw ===="*"read bandwidth: 2.00 GiB/s"*"==== 021-lat ===="*) true;; *) echo "$out" >&2; false;; esac'
t_assert "-s synopsis: a run without -a shows one line per distinct parameter set, with its host count" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" plain
    out=$(summ_out "$d") || { echo "$out" >&2; exit 1; }
    hdr=$(printf "%s\n" "$out" | awk "/^==== /{exit} {print}")
    exp=$(cat <<"X"
run      2026-10-23 14:10:02 (bundle b.tgz)
version  wekatester 2026-10-11, fio 3.36, weka 4.4.2
command  ./wekatester -w default h1 h2 h3
clients  3 (master h1), no shapes (no -a), 1 filesystem group
workload default; no -a; dest /mnt/weka/wt (wekafs)

parameters: the staged jobs per host (3 hosts)
  engine libaio
  bw-read          nj 4     qd 2     nr 1     bs 1Mi     011-bw         2 hosts: h1 h2
  bw-read          nj 8     qd 2     nr 1     bs 1Mi     011-bw         1 host: h3
  lat-read 1job    nj 1     qd 1     nr 1     bs 4k      021-lat-1job   all 3 hosts
  lat-read         nj 16    qd 1     nr -     bs 4k      021-lat        all 3 hosts
X
)
    [ "$hdr" = "$exp" ] || { printf "%s\n" "$out" >&2; false; }'
t_assert "-s synopsis: an older bundle says what it does not record, and reads the master from the log" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" old
    out=$(summ_out "$d") || { echo "$out" >&2; exit 1; }
    hdr=$(printf "%s\n" "$out" | sed -n 1,5p)
    exp=$(cat <<"X"
run      2026-10-23 14:10:02 (bundle b.tgz)
version  wekatester not recorded, fio 3.36, weka 4.4.2
command  not recorded
clients  2 (master h1), shapes not recorded, filesystem groups not recorded
workload not recorded; -a not recorded; dest /mnt/weka/wt (wekafs)
X
)
    [ "$hdr" = "$exp" ] || { printf "%s\n" "$out" >&2; false; }'
t_assert "-s synopsis: a bundle missing sysinfo, jobfiles and log says not recorded, never a guess" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" old
    b=$d/20261023-141002; rm -rf "$b/sysinfo" "$b/fio-jobfiles" "$b/wekatester.log"
    out=$(summ_out "$d") || { echo "$out" >&2; exit 1; }
    hdr=$(printf "%s\n" "$out" | awk "/^==== /{exit} {print}")
    exp=$(cat <<"X"
run      2026-10-23 14:10:02 (bundle b.tgz)
version  wekatester not recorded, fio not recorded, weka not recorded
command  not recorded
clients  0 (master not recorded), shapes not recorded, filesystem groups not recorded
workload not recorded; -a not recorded; dest not recorded

parameters: the staged jobs per host (0 hosts)
  staged jobfiles: none in the bundle
X
)
    [ "$hdr" = "$exp" ] || { printf "%s\n" "$out" >&2; false; }'
t_assert "-s -v counters: what rose per host and NIC; a reset is flagged, never counted; a NIC on one side is named" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" plain; summ_counters_fixture "$d"
    out=$(summ_out "$d" -v) || { echo "$out" >&2; exit 1; }
    sec=$(printf "%s\n" "$out" | awk "/^==== counters/ {on = 1} /^==== host health/ {exit} on")
    exp=$(cat <<"X"
==== counters over the run: what rose from start to end, per host and NIC ====
h1
  tcp: 2 counters, 2 rose; 1 of them match SUMMARY_COUNTER_RE:
    TcpRetransSegs                           +1,234
  eth0: 3 counters, 2 rose; 1 of them match SUMMARY_COUNTER_RE:
    rx_discards_phy                          +3,000,000,000
    1 went down, a reset, not counted: rx_out_of_buffer 77 -> 4
  eth0 aer: 2 counters, 1 rose:
    correctable.TOTAL_ERR_COR                +2
  eth1: at the end only, so no delta
h2: nothing to flag, none matching SUMMARY_COUNTER_RE rose and none went down (tcp 2 counters, 1 rose; eth0 2 counters, 1 rose)
h3: not recorded (no counter captures in sysinfo/h3)
X
)
    [ "$sec" = "$exp" ] || { printf "%s\n" "$out" >&2; exit 1; }
    plain=$(summ_out "$d") || { echo "$plain" >&2; exit 1; }
    case "$plain" in *"==== counters"*) echo "counters without -v" >&2; false;; esac'
t_assert "-s -v counters: a flagged host still lists its quiet NICs; a NIC without AER says not available; a missing fio is not a version" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" plain; summ_counters_fixture "$d"
    s=$d/20261023-141002/sysinfo
    printf "NIC statistics:\n     rx_packets: 1\n" > "$s/h1/ethtool-S-eth2-start"
    printf "NIC statistics:\n     rx_packets: 9\n" > "$s/h1/ethtool-S-eth2-end"
    for e in start end; do printf -- "--- aer_dev_correctable\nnot available: /sys/class/net/eth0/device/aer_dev_correctable not readable\n" > "$s/h2/aer-eth0-$e"; done
    printf "bash: line 18: fio: command not found\nnot available\n" > "$s/h3/fio"
    out=$(summ_out "$d" -v) || { echo "$out" >&2; exit 1; }
    case "$out" in
        *"version  wekatester 2026-10-11, fio 3.36 (2 hosts), not available (1 host), weka 4.4.2"*) ;;
        *) echo "$out" >&2; exit 1;;
    esac
    case "$out" in
        *"  eth1: at the end only, so no delta"*"  eth2: 1 counter, 1 rose; none match SUMMARY_COUNTER_RE, none went down"*"h2"*"  eth0: 2 counters, 1 rose; none match SUMMARY_COUNTER_RE, none went down"*"  eth0 aer: not available (not available: /sys/class/net/eth0/device/aer_dev_correctable not readable)"*"h3: not recorded"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "-s -vv counters: every counter that rose, traffic included" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" plain; summ_counters_fixture "$d"
    out=$(summ_out "$d" -vv) || { echo "$out" >&2; exit 1; }
    sec=$(printf "%s\n" "$out" | sed -n "/^==== counters/,\$p")
    case "$sec" in
        *"  tcp: 2 counters, 2 rose:"*"TcpInSegs "*"+899,000"*"TcpRetransSegs "*"rx_discards_phy "*"rx_packets "*"+89,900"*"h2"*"  tcp: 2 counters, 1 rose:"*"TcpInSegs "*"+20"*) true;;
        *) printf "%s\n" "$out" >&2; false;;
    esac'
t_assert "-s -v health: each flag shows the value that tripped it; a clean host says so on one line; gaps are named" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" plain; summ_health_fixture "$d"
    out=$(summ_out "$d" -v) || { echo "$out" >&2; exit 1; }
    sec=$(printf "%s\n" "$out" | sed -n "/^==== host health/,\$p")
    exp=$(cat <<"X"
==== host health: pressure, load, kernel log and clock around the run ====
h1
  cpu pressure at the end: some avg10 12.50% (over SUMMARY_PSI_CPU 5)
  load at the start: 14.00 on 16 cpus = 0.88 per cpu (over SUMMARY_LOAD_PER_CPU 0.75)
  kernel log: 6 of 7 lines in the run window match SUMMARY_KLOG_RE:
    [  950.000000] mlx5_core 0000:17:00.0 eth0: Link down
    [  951.000000] mlx5_core 0000:17:00.0 eth0: Link up
    [  952.000000] NETDEV WATCHDOG: eth0 (mlx5_core): transmit queue 3 timed out
    [  953.000000] INFO: task kworker/3:1:123 blocked for more than 120 seconds.
    [  954.000000] pcieport 0000:00:01.0: AER: Corrected error received: 0000:17:00.0
    (+1 more; SUMMARY_KLOG_LINES shows 5)
  clock: 250.0 ms off NTP time (over SUMMARY_CLOCK_MS 100)
h2: nothing to flag (cpu PSI start, cpu PSI end, memory PSI start, memory PSI end, io PSI start, load start, kernel log 0 lines, clock 0.01 ms off)
h3
  kernel log: this host booted during the run
  clock: not synchronised to NTP
  not recorded: cpu PSI start, cpu PSI end, memory PSI start, memory PSI end, io PSI start, load start
X
)
    [ "$sec" = "$exp" ] || { printf "%s\n" "$out" >&2; exit 1; }'
t_assert "-s -v health: the thresholds and the pattern are settings; a bad number is named, not used" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" plain; summ_health_fixture "$d"
    out=$(SUMMARY_PSI_CPU=20 SUMMARY_LOAD_PER_CPU=1 SUMMARY_CLOCK_MS=300 SUMMARY_KLOG_RE="out of memory" SUMMARY_KLOG_LINES=1 summ_out "$d" -v) || { echo "$out" >&2; exit 1; }
    sec=$(printf "%s\n" "$out" | sed -n "/^==== host health/,/^h2/p")
    exp=$(cat <<"X"
==== host health: pressure, load, kernel log and clock around the run ====
h1
  kernel log: 1 of 7 lines in the run window match SUMMARY_KLOG_RE:
    [  956.000000] Out of memory: Killed process 4242 (fio)
h2: nothing to flag (cpu PSI start, cpu PSI end, memory PSI start, memory PSI end, io PSI start, load start, kernel log 0 lines, clock 0.01 ms off)
X
)
    [ "$sec" = "$exp" ] || { printf "%s\n" "$out" >&2; exit 1; }
    out=$(SUMMARY_PSI_CPU=lots summ_out "$d" -v) || { echo "$out" >&2; exit 1; }
    case "$out" in *"(host health: SUMMARY_PSI_CPU must be a number, not '\''lots'\'')"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "-s -v on an older bundle: counters and health say not recorded per host" bash -c '
    d=$(mktemp -d); summ_bundle_fixture "$d" old
    out=$(summ_out "$d" -v) || { echo "$out" >&2; exit 1; }
    case "$out" in
        *"==== counters"*"h1: not recorded (no counter captures in sysinfo/h1)"*"h2: not recorded"*"==== host health"*"h1: not recorded (no pressure, load, kernel log or clock capture in sysinfo/h1)"*"h2: not recorded"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "-s synopsis: a single results .json keeps today's output, no synopsis" bash -c '
    d=$(mktemp -d); fio_json_single_fixture "$d/r.json"
    out=$(./wekatester -s "$d/r.json" 2>&1) || { echo "$out" >&2; exit 1; }
    [ "$(printf "%s\n" "$out" | head -1)" = "    read bandwidth: 2.00 GiB/s" ] || { echo "$out" >&2; false; }'

# --- every value-taking option works attached, detached, and =-attached ---
t_assert "parse: attached values work for -d -w -f -s -i" bash -c '
    (source ./wekatester; parse_args -d/x -wsmoke -f/opt/fio -iubuntu:/k h1
     [ "$DIRECTORY" = /x ] && [ "$WORKLOAD" = smoke ] &&
     [ "$FIO_BIN" = /opt/fio ] && [ "${IDENT_RAW[0]}" = ubuntu:/k ]) &&
    (source ./wekatester; parse_args -sfile.json; [ "$SUMMARIZE_FILE" = file.json ])'
t_assert "parse: =-attached values strip exactly one leading =" bash -c '
    (source ./wekatester; parse_args -d=/x h1;  [ "$DIRECTORY" = /x ]) &&
    (source ./wekatester; parse_args -w=foo h1; [ "$WORKLOAD" = foo ])'
t_assert "parse: an attached value keeps its case even when the option is folded" bash -c '
    (source ./wekatester; parse_args -WSmoke h1; [ "$WORKLOAD" = Smoke ])'
t_assert "parse: attaching is the escape hatch for a dash-leading value" bash -c '
    (source ./wekatester; parse_args -w-odd h1; [ "$WORKLOAD" = -odd ])'
t_assert "parse: an empty attached value dies instead of naming nothing" bash -c '
    err=$( (source ./wekatester; parse_args -w= h1) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"option -w requires a value"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "parse: -asafe and -a=max set the level; a bogus attached level dies" bash -c '
    (source ./wekatester; parse_args -asafe h1; [ "$AUTO_LEVEL" = safe ]) &&
    (source ./wekatester; parse_args -a=MAX h1; [ "$AUTO_LEVEL" = max ]) &&
    err=$( (source ./wekatester; parse_args -abogus h1) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"unknown auto level: bogus (safe|max|cal|brutal)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "parse: -a cal and --auto=cal set the level; every level calibrates" bash -c '
    (source ./wekatester; parse_args -a cal h1;    [ "$AUTO_LEVEL" = cal ]) &&
    (source ./wekatester; parse_args -ACAL h1;     [ "$AUTO_LEVEL" = cal ]) &&
    (source ./wekatester; parse_args --auto=cal h1; [ "$AUTO_LEVEL" = cal ]) &&
    err=$( (source ./wekatester; parse_args -acalx h1) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"unknown auto level: calx (safe|max|cal|brutal)"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    err=$( (source ./wekatester; parse_args -ahybrid h1) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"unknown auto level: hybrid"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    (source ./wekatester; AUTO_LEVEL=cal;    cal_mode) &&
    (source ./wekatester; AUTO_LEVEL=brutal; cal_mode) &&
    (source ./wekatester; AUTO_LEVEL=safe;   cal_mode) &&
    (source ./wekatester; AUTO_LEVEL=max;    cal_mode) &&
    ! (source ./wekatester; AUTO_LEVEL="";   cal_mode)'

t_assert "seed_estimate_line: complete dataset, unknown free space, and the share of free space" bash -c '
    source ./wekatester
    [ "$(seed_estimate_line 0 0 1000 /d)" = "dataset already complete, nothing to write" ] &&
    [ "$(seed_estimate_line 4 2048 "" /d)" = "4 file(s) = 2.0 GiB to write; free space at /d unknown" ] &&
    [ "$(seed_estimate_line 4 2048 8192 /d)" = "4 file(s) = 2.0 GiB to write; free 8.0 GiB at /d (25.0% of it)" ] &&
    [ "$(seed_estimate_line 192 983040 402733363 /d)" = "192 file(s) = 960.0 GiB to write; free 384.1 TiB at /d (0.2% of it)" ] &&
    [ "$(seed_estimate_line 4 2097152 4194304 /d)" = "4 file(s) = 2.0 TiB to write; free 4.0 TiB at /d (50.0% of it)" ]'

# A failed rung used to die pointing at /dev/shm/wt.*, wiped on exit (seen
# live: field client C, brutal bw-write qd=1 nr=1). Evidence goes in the
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
# The same fan-out as a failed layout's: every host at once, host order kept.
t_assert "cal_evidence: every host's parse check runs at once" bash -c '
    d=$(mktemp -d); r=$(mktemp -d)
    for h in h1 h2 h3; do mkdir -p "$d/cal/$h"; printf "[global]\nrw=write\n" > "$d/cal/$h/x.job"; done
    printf "{}\n" > "$d/cal/res-x.json"
    out=$( (source ./wekatester
            WORK_DIR=$d; RUN_DIR=$r; TARGET_DIR=/dev/shm/x; FIO_BIN=fio; MASTER=h1; LOCAL_MODE=0
            run_host() { case "$2" in (*--parse-only*)
                echo "S $1 ${EPOCHREALTIME//[!0-9]/}" >> "$d/times"; sleep 1
                echo "E $1 ${EPOCHREALTIME//[!0-9]/}" >> "$d/times";; esac; }
            copy_to_host() { :; }
            cal_evidence "rung x" "$d/cal/res-x.json" x.job quiet h1 h2 h3) 2>&1 )
    case "$out" in *"note: h3: the rung x jobfile parses cleanly"*) ;; *) echo "$out" >&2; exit 1;; esac
    spans_overlap "$d/times" 6'
t_assert "cal_evidence: the parse checks print in host order when the hosts finish out of order" bash -c '
    d=$(mktemp -d); r=$(mktemp -d)
    for h in h1 h2 h3; do mkdir -p "$d/cal/$h"; printf "[global]\nrw=write\n" > "$d/cal/$h/x.job"; done
    printf "{}\n" > "$d/cal/res-x.json"
    out=$( (source ./wekatester
            WORK_DIR=$d; RUN_DIR=$r; TARGET_DIR=/dev/shm/x; FIO_BIN=fio; MASTER=h1; LOCAL_MODE=0
            # h1 (the master) parses slowest, h2 cannot be staged, h3 fio rejects
            run_host() { case "$2" in
                ("mkdir -p '"'"'/dev/shm/x.cal/h2'"'"'") echo h2 >> "$d/done"; return 1;;
                (*--parse-only*) [ "$1" != h1 ] || sleep 1; echo "$1" >> "$d/done"
                                 [ "$1" != h3 ] || { echo "fio: bad option xyz"; return 1; };;
            esac; }
            copy_to_host() { :; }
            cal_evidence "rung x" "$d/cal/res-x.json" x.job quiet h1 h2 h3) 2>&1 )
    [ "$(wc -l < "$d/done")" -eq 3 ] && [ "$(tail -1 "$d/done")" = h1 ] \
        || { echo "finish order:" $(cat "$d/done") >&2; exit 1; }
    got=$(printf "%s\n" "$out" | sed -n "s/^[0-9:]* \(.*: h[123]: .*\)/\1/p")
    want=$(printf "%s\n" \
        "note: h1: the rung x jobfile parses cleanly on its host -- the jobs died at setup, not at option parsing" \
        "WARNING: h2: cannot stage the rung x jobfile for a parse check on that host" \
        "ERROR: h3: the host'"'"'s own fio rejects the rung x jobfile (full text: parse.h3.out in the run bundle):" \
        "ERROR: h3:   fio: bad option xyz")
    [ "$got" = "$want" ] || { printf "got:\n%s\nwant:\n%s\nout:\n%s\n" "$got" "$want" "$out" >&2; exit 1; }'
# A flat five-line cap hid the one fact that mattered: how many jobs failed
# the same way (field client C showed five cpu_set_affinity lines out of an
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
# --- no python: bash and awk only ---
# The script once carried 3,480 lines of python, every one of them added
# without being asked for (Frank, 2026-10-05: bash first is binding); the
# last of it went 2026-10-06. Keep it that way.
t_assert "no python: the script runs none" bash -c '
    hits=$(grep -nE "python3|pyrun|PYEOF|#@include" ./wekatester || true)
    [ -z "$hits" ] || { printf "python in the script:\n%s\n" "$hits" >&2; false; }'

# The suite's own lock: a stale one is reclaimed by rename, and a reclaimer
# whose rename fails takes nothing. A nested suite gets its own SUITE_LOCK.
dead_owner() {   # dead_owner <lockdir>: a lock owned by a pid that is gone
    local p; bash -c : & p=$!; wait "$p"
    mkdir "$1" && echo "pid $p user x since y repo z" > "$1/owner"
}
export -f dead_owner
t_assert "suite lock: a reclaimer whose rename fails says cannot take, exits 2, and leaves the lock" bash -c '
    d=$(mktemp -d); dead_owner "$d/lock"
    mv() { echo "mv: cannot stat: gone" >&2; return 1; }; export -f mv
    out=$(SUITE_LOCK=$d/lock SUITE_ONLY="^build: every file under src/" bash tests/test_wekatester.sh 2>&1); rc=$?
    [ "$rc" = 2 ] && [ -d "$d/lock" ] || { echo "rc=$rc [$out]" >&2; exit 1; }
    case "$out" in *"cannot take $d/lock: mv: cannot stat: gone"*) ;; *) echo "[$out]" >&2; exit 1;; esac
    case "$out" in *reclaimed*) echo "reclaimed: [$out]" >&2; false;; esac'
t_assert "suite lock: two reclaimers of a stale lock started together: one runs, one exits 2, the lock is gone after" bash -c '
    for round in 1 2 3; do
        d=$(mktemp -d); dead_owner "$d/lock"
        SUITE_LOCK=$d/lock SUITE_ONLY="^build: every file under src/" bash tests/test_wekatester.sh > "$d/a" 2>&1 & pa=$!
        SUITE_LOCK=$d/lock SUITE_ONLY="^build: every file under src/" bash tests/test_wekatester.sh > "$d/b" 2>&1 & pb=$!
        wait "$pa"; ra=$?; wait "$pb"; rb=$?
        [ "$(printf "%s\n" "$ra" "$rb" | sort | tr "\n" " ")" = "0 2 " ] &&
        [ "$(cat "$d/a" "$d/b" | grep -c "^reclaimed $d/lock")" = 1 ] &&
        [ ! -e "$d/lock" ] && [ -z "$(compgen -G "$d/lock.stale.*")" ] ||
            { { echo "round $round: rc $ra $rb"; cat "$d/a" "$d/b"; ls -la "$d"; } >&2; exit 1; }
    done'

# An apostrophe in a comment inside a bash -c '...' body closes the string
# early: the rest of the body becomes arguments to bash, and the test passes
# whatever the code does (a new pinning test did, 2026-09-27). Every body
# has to run to its own closing quote.
t_assert "suite: every bash -c test body runs to its own closing quote" python3 -c '
import sys
SQ, DQ = "\x27", "\x22"
s = open("tests/test_wekatester.sh").read()
mark = DQ + " bash -c " + SQ
bad, i = [], s.find(mark)
while i >= 0:
    j = i + len(mark)
    while True:
        k = s.index(SQ, j)
        if s.startswith(SQ + "\\" + SQ + SQ, k):       # close, an escaped quote, reopen
            j = k + 4; continue
        if s.startswith(SQ + DQ + SQ + DQ + SQ, k):    # close, a quoted quote, reopen
            j = k + 5; continue
        if s[k + 1:k + 2] == DQ:                        # close, a double-quoted splice, reopen
            q = k + 2
            while s[q] != DQ or s[q - 1] == "\\":
                q += 1
            if s[q + 1:q + 2] == SQ:
                j = q + 2; continue
        break
    rest = s[k + 1:s.find("\n", k)].strip()
    if rest and not rest.startswith("#"):
        bad.append(s.count("\n", 0, i) + 1)
    i = s.find(mark, k)
if bad:
    sys.exit("test bodies a stray quote ends early, at lines %s" % bad)
'

# A failed check that only runs `false` counts for nothing unless it is the
# body's last command: bash -c returns the LAST status, so a later line that
# passes hides it (two tests had this, 2026-09-28). Mid-body checks exit.
t_assert "suite: no test body lets a later line hide a failed check" python3 -c '
import re, sys
SQ, DQ = "\x27", "\x22"
s = open("tests/test_wekatester.sh").read()
mark = DQ + " bash -c " + SQ
bad, i = [], s.find(mark)
while i >= 0:
    j = i + len(mark)
    while True:
        k = s.index(SQ, j)
        if s.startswith(SQ + "\\" + SQ + SQ, k):
            j = k + 4; continue
        if s.startswith(SQ + DQ + SQ + DQ + SQ, k):
            j = k + 5; continue
        if s[k + 1:k + 2] == DQ:
            q = k + 2
            while s[q] != DQ or s[q - 1] == "\\":
                q += 1
            if s[q + 1:q + 2] == SQ:
                j = q + 2; continue
        break
    lines = s[i + len(mark):k].split("\n")
    for n, l in enumerate(lines):
        if re.search(r"(\|\|\s*\{[^}]*;\s*false;\s*\}|\|\|\s*false)$", l.rstrip()):
            if [x for x in lines[n + 1:] if x.strip() and not x.strip().startswith("#")]:
                bad.append(s.count("\n", 0, i) + 1 + n)
    i = s.find(mark, k)
if bad:
    sys.exit("mid-body checks that end in false, at lines %s" % bad)
'

t_assert "askpass: -p answers the password once, a second question fails at once, and host-key and passphrase questions do not use it up" bash -c '
    d=$(mktemp -d)
    (source ./wekatester; write_askpass_helper "$d/ask.sh") || exit 1
    fifo=$d/pw.fifo; mkfifo "$fifo" || exit 1; exec 4<>"$fifo"; printf "s3cret\n" >&4
    export WEKATESTER_PW_FIFO=$fifo
    a=$("$d/ask.sh" "Are you sure you want to continue connecting (yes/no/[fingerprint])? ") || exit 1
    [ "$a" = no ] || { echo "host key: $a" >&2; exit 1; }
    if "$d/ask.sh" "Enter passphrase for key /home/u/.ssh/id_ed25519: " > "$d/pp"; then echo "passphrase answered: $(cat "$d/pp")" >&2; exit 1; fi
    a=$("$d/ask.sh" "ubuntu@h1'"'"'s password: ") || exit 1
    [ "$a" = s3cret ] || { echo "password: $a" >&2; exit 1; }
    # the fifo is held open, so a second read would block forever: the
    # second question has to fail at once (the old helper hung here)
    "$d/ask.sh" "Password: " > "$d/second" & pid=$!
    n=0; while ps -p "$pid" > "$d/ps" && [ "$n" -lt 10 ]; do sleep 0.3; n=$((n + 1)); done
    if ps -p "$pid" > "$d/ps"; then kill "$pid"; echo "the second question blocked" >&2; exit 1; fi
    wait "$pid" && { echo "the second question was answered: $(cat "$d/second")" >&2; exit 1; }
    [ ! -s "$d/second" ]'
t_assert "ssh: the master sockets live in the work dir, and cleanup removes them with it" bash -c '
    w=$(mktemp -d)
    out=$( (source ./wekatester; WORK_DIR=$w; make_ctrl_dir; printf "%s" "$CTRL_DIR"; cleanup) ) || exit 1
    [ "$out" = "$w/c" ] && [ ! -e "$w" ] || { echo "[$out]" >&2; false; }'
t_assert "capacity: hosts on one weka filesystem are checked against it together, not one at a time" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    # 50 GiB free on one weka filesystem; each host alone needs ~40
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\n10.0.1.1,10.0.1.2/default 104857600 0 52428800 1%% /mnt/weka\nwekafs\n" > "$FIX/probe/_df"
    err=$( cap max 0 h1 h2 2>&1 >>$SUITE_ASIDE ) && { echo "passed: $err" >&2; exit 1; }
    case "$err" in *"ERROR: weka filesystem default: its 2 hosts (h1 h2) need ~80.0GiB together but only 50.0GiB is available"*) ;; *) echo "$err" >&2; exit 1;; esac
    # the same df without the wekafs line: local disks, one per host, each fits
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/nvme0n1 104857600 0 52428800 1%% /mnt/weka\n" > "$FIX/probe/_df"
    out=$( cap max 0 h1 h2 2>&1 ) || { echo "failed: $out" >&2; false; }'
t_assert "client list: a fleet the fio command line cannot carry stops before anything starts on the hosts" bash -c '
    d=$(mktemp -d); mkdir -p "$d/set"
    printf "# report latency\n[global]\n[a]\nrw=randread\n" > "$d/set/021-latencyR.job"
    hosts=(); for i in $(seq 1 1500); do hosts+=("worker-$i.example.com"); done
    err=$( (source ./wekatester; HOSTS=("${hosts[@]}"); SET_DIR_OVERRIDE=$d/set; TARGET_DIR=/dev/shm/fio-jobfiles
            early_client_cmdline_check) 2>&1 ) && { echo "passed with 1500 hosts" >&2; exit 1; }
    case "$err" in *"the fio command line for the longest job name this set can stage is "*" bytes with 1500 hosts"*) ;; *) echo "$err" >&2; exit 1;; esac
    (source ./wekatester; HOSTS=(h1 h2 h3); SET_DIR_OVERRIDE=$d/set; TARGET_DIR=/dev/shm/fio-jobfiles
     early_client_cmdline_check) || exit 1
    # main runs it before the probe, the fio servers and calibration, dry runs included
    m=$(sed -n "/^main() {/,/^}/p" ./wekatester)
    e=$(printf "%s\n" "$m" | grep -n "early_client_cmdline_check" | head -1 | cut -d: -f1)
    p=$(printf "%s\n" "$m" | grep -n "probe_workers" | head -1 | cut -d: -f1)
    [ -n "$e" ] && [ -n "$p" ] && [ "$e" -lt "$p" ] || { echo "early=$e probe=$p" >&2; false; }'
t_assert "client list: the early check prices every jobfile staging runs, a long name without .job included" bash -c '
    d=$(mktemp -d); mkdir -p "$d/set"
    printf "[global]\n[a]\nrw=read\n" > "$d/set/011-$(printf "%250s" "" | tr " " x)"
    printf "[global]\n[a]\nrw=write\n" > "$d/set/012-s.job"
    hosts=(); for i in $(seq 1 450); do hosts+=("worker-$i.example.com"); done
    err=$( (source ./wekatester; HOSTS=("${hosts[@]}"); SET_DIR_OVERRIDE=$d/set; TARGET_DIR=/dev/shm/fio-jobfiles
            early_client_cmdline_check) 2>&1 ) && { echo "passed with a 254-byte name and 450 hosts: $err" >&2; exit 1; }
    case "$err" in *"the fio command line for the longest job name this set can stage is "*" bytes with 450 hosts"*) ;; *) echo "$err" >&2; exit 1;; esac'
t_assert "client list: the early check skips what staging skips, a long name without a digit prefix" bash -c '
    d=$(mktemp -d); mkdir -p "$d/set"
    printf "[global]\n[a]\nrw=randread\n" > "$d/set/021-latencyR.job"
    x=$(printf "%246s" "" | tr " " x)
    printf "notes\n" > "$d/set/notes$x.job"; printf "notes\n" > "$d/set/README$x"
    hosts=(); for i in $(seq 1 450); do hosts+=("worker-$i.example.com"); done
    out=$( (source ./wekatester; HOSTS=("${hosts[@]}"); SET_DIR_OVERRIDE=$d/set; TARGET_DIR=/dev/shm/fio-jobfiles
            early_client_cmdline_check) 2>&1 ) || { echo "$out" >&2; exit 1; }'
# A blank in filename_format: the seed and layout readers cut the name there;
# refused (Frank, 2026-10-11).
t_assert "staging: a filename_format with a space dies naming the jobfile and the value, before the probe and calibration" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    printf "# report iops\n[global]\nfilename_format=a b.\$jobnum.\$filenum\n[io]\nrw=randread\n" > "$SETFIX/041-sp.job"
    w=$(mktemp -d); mkdir -p "$w/jobs"
    err=$( (source ./wekatester
        LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; WORK_DIR=$w; DRY_RUN=1
        TARGET_DIR="$w/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
        stage_jobfiles) 2>&1 >>$SUITE_ASIDE ) && { echo "staged: $err" >&2; exit 1; }
    case "$err" in *"ERROR: $SETFIX/041-sp.job: filename_format must not contain whitespace: '"'"'a b.\$jobnum.\$filenum'"'"'"*) ;; *) echo "$err" >&2; exit 1;; esac
    [ ! -e "$w/set/041-sp.job" ] || { echo "copied before the check" >&2; exit 1; }
    m=$(sed -n "/^main() {/,/^}/p" ./wekatester)
    printf "%s\n" "$m" | awk "/check_jobfile_lines/ && !c {c = NR} /probe_workers/ && !p {p = NR} /^    calibrate\$/ {k = NR} END {exit !(c && p > c && k > c)}"'
t_assert "staging: a filename_format with a tab, in a job section, dies the same way" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    t=$(printf "\t")
    printf "# report iops\n[global]\nnumjobs=1\n[io]\nfilename_format=a\tb\nrw=randread\n" > "$SETFIX/041-tab.job"
    w=$(mktemp -d); mkdir -p "$w/jobs"
    err=$( (source ./wekatester
        LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; WORK_DIR=$w; DRY_RUN=1
        TARGET_DIR="$w/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
        stage_jobfiles) 2>&1 >>$SUITE_ASIDE ) && { echo "staged: $err" >&2; exit 1; }
    case "$err" in *"ERROR: $SETFIX/041-tab.job: filename_format must not contain whitespace: '"'"'a${t}b'"'"'"*) ;; *) echo "$err" >&2; exit 1;; esac'
t_assert "staging: a filename_format without blanks still stages, host-prefixed" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    w=$(mktemp -d); mkdir -p "$w/jobs"
    (source ./wekatester
     HOSTS=(h1); MASTER=h1; WORK_DIR=$w; DRY_RUN=1
     TARGET_DIR="$w/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
     stage_jobfiles) >>$SUITE_ASIDE 2>&1 || exit 1
    grep -qx "filename_format=h1.small.\$jobnum" "$w/jobs/h1/031-iops.job" &&
    grep -qx "filename_format=h1.big/\$jobnum" "$w/jobs/h1/011-bw.job" ||
    { cat "$w/jobs/h1/031-iops.job" >&2; false; }'
# cpumask and numa_cpu_nodes can place fio on weka's cores or core 0's pair,
# and staging trims only cpus_allowed: refused before anything runs (Frank,
# 2026-10-11). gtod_cpu pins only the clock thread, and is kept.
t_assert "staging: a cpumask line dies naming the jobfile and the line, pointing at cpus_allowed" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    printf "# report iops\n[global]\nnumjobs=1\n[io]\ncpumask=0xf\nrw=randread\n" > "$SETFIX/041-mask.job"
    w=$(mktemp -d); mkdir -p "$w/jobs"
    err=$( (source ./wekatester
        LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; WORK_DIR=$w; DRY_RUN=1
        TARGET_DIR="$w/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
        stage_jobfiles) 2>&1 >>$SUITE_ASIDE ) && { echo "staged: $err" >&2; exit 1; }
    case "$err" in *"ERROR: $SETFIX/041-mask.job: '"'"'cpumask=0xf'"'"': cpumask can place fio on weka"*"use cpus_allowed"*) ;; *) echo "$err" >&2; exit 1;; esac
    [ ! -e "$w/set/041-mask.job" ] || { echo "copied before the check" >&2; exit 1; }'
t_assert "staging: a numa_cpu_nodes line with blanks around the key dies the same way" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    printf "# report iops\n[global]\n  numa_cpu_nodes = 0\n[io]\nrw=randread\n" > "$SETFIX/041-numa.job"
    w=$(mktemp -d); mkdir -p "$w/jobs"
    err=$( (source ./wekatester
        LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; WORK_DIR=$w; DRY_RUN=1
        TARGET_DIR="$w/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
        stage_jobfiles) 2>&1 >>$SUITE_ASIDE ) && { echo "staged: $err" >&2; exit 1; }
    case "$err" in *"ERROR: $SETFIX/041-numa.job: '"'"'numa_cpu_nodes = 0'"'"': numa_cpu_nodes can place fio on weka"*"use cpus_allowed"*) ;; *) echo "$err" >&2; exit 1;; esac
    [ ! -e "$w/set/041-numa.job" ] || { echo "copied before the check" >&2; exit 1; }'
t_assert "staging: a commented cpumask and a gtod_cpu line still stage, as written" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    printf "# report iops\n[global]\n# cpumask=0xf\n; numa_cpu_nodes=0\ngtod_cpu=1\n[io]\nrw=randread\n" > "$SETFIX/041-ok.job"
    w=$(mktemp -d); mkdir -p "$w/jobs"
    (source ./wekatester
     HOSTS=(h1); MASTER=h1; WORK_DIR=$w; DRY_RUN=1
     TARGET_DIR="$w/target"; DIRECTORY=/mnt/x; SET_DIR_OVERRIDE=$SETFIX
     stage_jobfiles) >>$SUITE_ASIDE 2>&1 || exit 1
    v=$w/jobs/h1/041-ok.job
    grep -qx "# cpumask=0xf" "$v" && grep -qx "gtod_cpu=1" "$v" || { cat "$v" >&2; false; }'
t_assert "dry run: -n runs the pinning check, so what the real run pins -- or dies on -- shows up first" bash -c '
    m=$(sed -n "/^main() {/,/^}/p" ./wekatester)
    dry=$(printf "%s\n" "$m" | sed -n "/if \[ \"\$DRY_RUN\" -eq 1 \]; then/,/exit 0/p")
    printf "%s\n" "$dry" | grep -q "finalize_targets" || { echo "no dry-run block found" >&2; exit 1; }
    f=$(printf "%s\n" "$dry" | grep -n "finalize_targets" | cut -d: -f1)
    c=$(printf "%s\n" "$dry" | grep -n "check_cpu_pinning" | cut -d: -f1)
    [ -n "$c" ] && [ "$c" -gt "$f" ] || { printf "%s\n" "$dry" >&2; false; }'

t_assert "sets: every shipped jobfile says what it reports, so calibration measures what staging applies" bash -c '
    for f in fio-jobfiles/*/*.job; do
        grep -qE "^#[[:space:]]*report[[:space:]]+[a-z]" "$f" || { echo "no # report line: $f" >&2; exit 1; }
    done
    # wekawithin had none: calibration measured bandwidth and staging applied it to nothing
    out=$(source ./wekatester; cal_required fio-jobfiles/wekawithin) || exit 1
    [ "$out" = "bw read
bw write
iops read
iops write" ] || { echo "$out" >&2; false; }'
# --- brutal: the exhaustive grid ---
# Both measured levels gate the calibration phase; only one of them is brutal.
t_assert "parse: -a brutal sets the level, and :secs sets the cell duration" bash -c '
    (source ./wekatester; parse_args -a brutal h1;    [ "$AUTO_LEVEL" = brutal ]) &&
    (source ./wekatester; parse_args -ABRUTAL h1;     [ "$AUTO_LEVEL" = brutal ]) &&
    (source ./wekatester; parse_args --auto=brutal h1; [ "$AUTO_LEVEL" = brutal ]) &&
    (source ./wekatester; parse_args -a brutal:10 h1
     [ "$AUTO_LEVEL" = brutal ] && [ "$CAL_RUNTIME" = 10 ]) &&
    (source ./wekatester; parse_args -a cal:15 h1;    [ "$CAL_RUNTIME" = 15 ]) &&
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
# No directive names no type: such a file is not calibrated and runs as
# written (Frank, 2026-10-06) -- the tuner lays no slot over it either.
t_assert "cal_required: a file with no report directive is not calibrated" \
    test "$(cal_set '[global]
bs=1M
[seq]
rw=write')" = ""
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
# A create_only section only lays out: its rw=, inherited or its own, is no
# direction to calibrate.
t_assert "cal_required: a create_only section's rw= asks for no search" \
    test "$(cal_set '# report iops
[global]
rw=randwrite
[create]
create_only=1
[readjob]
rw=randread' '# report bandwidth
[create]
create_only
rw=write
[readjob]
rw=read')" = "bw read|iops read|"
# A prose comment is not a directive (bare "# report" matches nothing either),
# so such a file is the no-directive case -- not calibrated -- even when the
# comment names a type a loose parser would take for one.
t_assert "cal_required: '# reporting notes' is not a directive" \
    test "$(cal_set '# reporting bandwidth notes: nothing to see
# report
[seq]
rw=read')" = ""
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
    [ "$(r wekawithin)" = "bw read|bw write|iops read|iops write|" ]'
t_assert "cal_required: a missing set directory is an error, not silence" bash -c '
    out=$( (source ./wekatester; cal_required /nonexistent/set) 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && case "$out" in *"cal_required"*"/nonexistent/set"*) true;; *) false;; esac'

# --- probe_cores: N, the tuner's core arithmetic ---
# The calibration ladder and staging size numjobs from this; staging and
# calibration stop on N < 1 (the tuner tests below).
pc() {   # pc <probe-file-content>; prints probe_cores' N
    local d out rc
    d=$(mktemp -d) || return 1
    # every probe carries a bindable line; this one refuses no cpu
    printf '%s\nbindable 0-63\nbindable_priv -\n' "$1" > "$d/p"
    out=$(cores_facts "$d/p"); rc=$?
    rm -rf -- "${d:?}"
    [ "$rc" -eq 0 ] || { echo "ERROR: probe_cores exited $rc"; return "$rc"; }
    printf '%s' "${out%% *}"
}
t_assert "probe_cores: weka's single-cpu masks are dedicated cores" \
    test "$(pc 'ncpus 8
weka_allowed 5
weka_allowed 6
weka_allowed 7')" = 3
t_assert "probe_cores: a wide utility-thread mask owns nothing" \
    test "$(pc 'ncpus 8
weka_allowed 0,3-4
weka_allowed 0-7')" = 6
t_assert "probe_cores: no weka at all leaves every core but the OS reserve" \
    test "$(pc 'ncpus 4')" = 2
# isolcpus does NOT narrow the set: weka's cores and the OS reserve are all
# that is subtracted (saving-calf 2026-08-20 -- confining the OS cost 4-7%
# write iops; split affinity makes a cross-partition mask safe).
t_assert "probe_cores: isolcpus does not narrow the set" \
    test "$(pc 'ncpus 8
isolated 4-7
weka_allowed 4
weka_allowed 5')" = 4
t_assert "probe_cores: weka owning every isolated cpu just leaves the rest" \
    test "$(pc 'ncpus 8
isolated 4-7
weka_allowed 4
weka_allowed 5
weka_allowed 6
weka_allowed 7')" = 2
# A probe with no ncpus names no cpu: N=0, which staging and calibration stop
# on, never a ladder sized at zero jobs.
t_assert "probe_cores: a probe with no ncpus counts no cpus" \
    test "$(pc 'engines psync')" = 0
t_assert "probe_cores: a probe with no bindable line is an error, never a guess" bash -c '
    d=$(mktemp -d); printf "ncpus 8\n" > "$d/p"
    err=$(cores_facts "$d/p" 2>&1 >>$SUITE_ASIDE) && { echo "no error" >&2; exit 1; }
    case "$err" in (*"no bindable line"*) ;; (*) echo "$err" >&2; exit 1 ;; esac'
t_assert "probe_cores: a list naming cpus the host does not have is trimmed; one covering every cpu fio could use counts as none" bash -c '
    d=$(mktemp -d)
    printf "ncpus 8\nbindable 0-7\nbindable_priv -\n" > "$d/p"
    # 3-11 is an operator list with phantoms: trimmed to 3-7, and only core
    # 0 comes out of it (the operator-list exemption)
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p" 3-11)"
    [ "$all" = "3,4,5,6,7" ] || { echo "3-11: $all" >&2; exit 1; }
    # 0-11 names every cpu the box has, 1-11 every one but core 0, which fio
    # never gets: no choice either way, so the full reserve (0 and 1) applies
    for l in 0-11 1-11; do
        IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p" "$l")"
        [ "$all" = "2,3,4,5,6,7" ] || { echo "$l: $all" >&2; exit 1; }
    done'
t_assert "cores_summary: cores a host-file list leaves out, or the host cannot bind, get terms of their own so the sum adds up" bash -c '
    d=$(mktemp -d); printf "ncpus 8\nbindable 0-7\nbindable_priv -\n" > "$d/p"
    # lab 3, 2026-09-27: a list written back by a calibration printed
    # "16 physical - 6 weka DPDK - 1 reserved (0-1) = N=7"
    out=$(cores_line "$d/p" 4-11)
    case "$out" in "8 physical core(s) (no topology: one per cpu) - 0 weka DPDK - 1 reserved for the OS (0) - 3 outside the host-file cpu list = N=4: "*) ;; *) echo "4-11: $out" >&2; exit 1;; esac
    printf "ncpus 8\nonline 0-7\nbindable 0,1,2,4,6,7\nbindable_priv -\n" > "$d/p"
    out=$(cores_line "$d/p")
    case "$out" in "8 physical core(s) (no topology: one per cpu) - 0 weka DPDK - 2 reserved for the OS (0 1) - 2 unbindable = N=4: "*) ;; *) echo "unbindable: $out" >&2; false;; esac'

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
    err=$( (source ./wekatester; cal_values "$@") 2>&1 >>$SUITE_ASIDE ); rc=$?
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
t_assert "-u: a hand-written layout with no [global] still unlinks every section" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); mkdir -p "$d/jobs/h1" "$d/set"; SET_DIR=$d/set
     lay="# wekatester-layout: generated sha256=0000
[lay]
directory=/mnt/x
create_only=1
filesize=5G
numjobs=2"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     stage_unlink_variants
     u=$d/jobs/h1/999-wekatester-unlink.job
     [ "$(head -2 "$u" | tr "\n" " ")" = "[global] unlink=1 " ] &&
     grep -q "^\[lay\]$" "$u" && grep -q "^filesize=4k$" "$u" ||
         { cat "$u" >&2; false; })'
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
    (WEKATESTER_SUITE_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka; UNLINK=1
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles && push_jobfiles
     [ "${JOBFILES[${#JOBFILES[@]}-1]}" = 999-wekatester-unlink.job ]) >>$SUITE_ASIDE || exit 1
    u="$d/target/localhost/999-wekatester-unlink.job"
    test -f "$u" && grep -q "^unlink=1$" "$u"'
# A jobname format end to end: what the job opens is what the layout creates,
# the sweep looks for and -u removes.
t_assert "staging: a jobname format's layout, unlink job and grid spec all name the job's own files" bash -c '
    s=$(mktemp -d); d=$(mktemp -d); mkdir -p "$d/jobs"
    printf "# report bandwidth\n[global]\nfilesize=1M\nnumjobs=2\nnrfiles=2\nioengine=psync\n[rd]\nrw=read\nfilename_format=\$jobname.\$jobnum.\$filenum\n" > "$s/011-rd.job"
    (source ./wekatester
     HOSTS=(h1); MASTER=h1; WORK_DIR=$d; DRY_RUN=1; UNLINK=1; ENGINE=""
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/w; SET_DIR_OVERRIDE=$s
     stage_jobfiles) >>$SUITE_ASIDE 2>&1 || exit 1
    l="$d/jobs/h1/000-wekatester-layout.job"; u="$d/jobs/h1/999-wekatester-unlink.job"
    g=$(source ./wekatester; layout_grid_spec "$l") || exit 1
    grep -qx "filename_format=h1.\$jobname.\$jobnum.\$filenum" "$d/jobs/h1/011-rd.job" &&
    grep -qx "filename_format=h1.rd.\$jobnum.\$filenum" "$l" && grep -qx "filename_format=h1.rd.\$jobnum.\$filenum" "$u" &&
    [ "$(printf "%s\n" "$g" | cut -f2)" = "h1.rd.*.*" ] &&
    ! grep -q "^filename_format=.*layout-" "$l" "$u" && ! grep -q "\$jobname" "$l" "$u" ||
        { cat "$l" "$u" >&2; printf "%s\n" "$g" >&2; false; }'
t_assert "staging: host-file geometry re-derives a jobname format's layout with the job's own names" bash -c '
    d=$(mktemp -d); s=$(mktemp -d); mkdir -p "$d/jobs"
    printf "# report bandwidth\n[global]\nfilesize=1G\nnumjobs=1\nfilename_format=\$jobname.\$jobnum.\$filenum\n[rd]\nrw=read\n" > "$s/011-rd.job"
    { printf "h1\t-\t-\t-\t-\t3\t2G\t2\t4"; for i in $(seq 10 37); do printf "\t-"; done; printf "\n"; } > "$d/targets.final"
    (source ./wekatester; WORK_DIR=$d; stage_hosts plain "$s" /mnt/w - - h1) >>$SUITE_ASIDE 2>&1 || exit 1
    l="$d/jobs/h1/000-wekatester-layout.job"
    grep -qx "numjobs=3" "$d/jobs/h1/011-rd.job" && grep -qx "numjobs=3" "$l" &&
    grep -qx "filename_format=rd.\$jobnum.\$filenum" "$l" && ! grep -q "\$jobname" "$l" || { cat "$l" >&2; false; }'

# --- -e/--engine: one engine everywhere ---
t_assert "parse: -e in all spellings sets the engine; value case kept; -e= dies" bash -c '
    (source ./wekatester; parse_args -e libaio h1;      [ "$ENGINE" = libaio ]) &&
    (source ./wekatester; parse_args -elibaio h1;       [ "$ENGINE" = libaio ]) &&
    (source ./wekatester; parse_args --engine=io_uring h1; [ "$ENGINE" = io_uring ]) &&
    (source ./wekatester; parse_args -EPsync h1;        [ "$ENGINE" = Psync ]) &&
    ! (source ./wekatester; parse_args -e= h1)'
t_assert "override_staged: replaces, inserts into [global], or creates it" bash -c '
    d=$(mktemp -d); j=$d/jobs/h1; mkdir -p "$j"
    printf "[global]\nioengine=libaio\n[j]\nrw=read\n" > "$j/011-a.job"
    printf "[global]\nfilesize=1G\n[j]\nrw=read\n"     > "$j/012-b.job"
    printf "[j]\nrw=read\n"                            > "$j/013-c.job"
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); override_staged all ioengine xyzeng) || exit 1
    grep -q "^ioengine=xyzeng$" "$j/011-a.job" && ! grep -q libaio "$j/011-a.job" &&
    [ "$(sed -n 2p "$j/012-b.job")" = "ioengine=xyzeng" ] &&
    [ "$(head -2 "$j/013-c.job" | tr "\n" "|")" = "[global]|ioengine=xyzeng|" ]'
t_assert "-e stamps every staged variant, the generated layout included" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_SUITE_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka; ENGINE=xyzeng
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles && push_jobfiles) >>$SUITE_ASIDE || exit 1
    v="$d/target/localhost/011-smoke-readbw.job"
    grep -q "^ioengine=xyzeng$" "$v" && ! grep -q "^ioengine=libaio$" "$v" &&
    grep -q "^ioengine=xyzeng$" "$d/target/localhost/000-wekatester-layout.job"'

# fio defaults to fallocate=native on Linux: full st_size first, data after.
# An interrupted layout would then leave a full-size file of zeros that the
# layout sweep credits as complete, and the run measures reads of nothing.
t_assert "layout: the generated layout job disables preallocation" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src"
    printf "# report bandwidth\n[global]\nioengine=libaio\nfilesize=1G\nnumjobs=1\n[a]\nrw=read\n" > "$d/src/011-a.job"
    (source ./wekatester; generate_layout "$d/src" "$d/src") >>$SUITE_ASIDE 2>&1
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
    (source ./wekatester; generate_layout "$d/src" "$d/src") >>$SUITE_ASIDE 2>&1
    grep -q "^ioengine=io_uring$" "$d/src/000-wekatester-layout.job"'
t_assert "layout: a genuine majority still wins over ENGINE_ORDER" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src"
    printf "# report bandwidth\n[global]\nioengine=libaio\nfilesize=1G\nnumjobs=1\n[a]\nrw=read\n" > "$d/src/011-a.job"
    printf "# report iops\n[global]\nioengine=libaio\nfilesize=1G\nnumjobs=1\n[b]\nrw=randread\n" > "$d/src/031-b.job"
    printf "# report latency\n[global]\nioengine=io_uring\nfilesize=1G\nnumjobs=1\n[c]\nrw=randread\n" > "$d/src/021-c.job"
    (source ./wekatester; generate_layout "$d/src" "$d/src") >>$SUITE_ASIDE 2>&1
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
t_assert "stamping: pinned hosts get cpus_allowed filled and policy=split; a jobfile list inside the host's cpus, any policy, and an unpinned host's list win" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1 h2)
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1" "$d/jobs/h2"
     printf "4-15,28-55" > "$AUTH_DIR/h1.cpus"
     printf "[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/jobs/h1/011-a.job"
     printf "[global]\ncpus_allowed=5,6\ncpus_allowed_policy=shared\n[b]\nrw=read\n" > "$d/jobs/h1/012-b.job"
     printf "[global]\ncpus_allowed=5-9\n[c]\nrw=read\n" > "$d/jobs/h2/013-c.job"
     printf "[global]\nfilesize=1G\n[e]\nrw=read\n" > "$d/jobs/h2/014-e.job"
     stamp_unique_names)
    a=$d/jobs/h1/011-a.job; b=$d/jobs/h1/012-b.job
    c=$d/jobs/h2/013-c.job; e=$d/jobs/h2/014-e.job
    grep -q "^cpus_allowed=4-15,28-55$" "$a" && grep -q "^cpus_allowed_policy=split$" "$a" &&
    grep -q "^cpus_allowed=5,6$" "$b" && grep -q "^cpus_allowed_policy=shared$" "$b" &&
    ! grep -q "4-15" "$b" && ! grep -q "policy=split" "$b" &&
    grep -q "^cpus_allowed=5-9$" "$c" && grep -q "^cpus_allowed_policy=split$" "$c" &&
    ! grep -q "cpus_allowed" "$e"'
# A jobfile's own cpus_allowed survived staging as written, so a plain run
# could land on core 0's pair or weka's cores: fio's sched_setaffinity is
# bounded by the cgroup cpuset, not by the server's taskset (2026-10-11).
t_assert "stamping: a jobfile cpus_allowed reaching outside the host's cpus is trimmed, every line, with a note" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1"
     printf "2-5\n" > "$AUTH_DIR/h1.cpus"
     printf "[global]\ncpus_allowed=0-3\n[a]\nrw=read\n[b]\nrw=write\n  cpus_allowed = 4-7\n" > "$d/jobs/h1/011-a.job"
     stamp_unique_names) 2>&1 >>$SUITE_ASIDE ) || { echo "stamp failed: $err" >&2; exit 1; }
    a=$d/jobs/h1/011-a.job
    grep -qx "cpus_allowed=2-3" "$a" && grep -qx "cpus_allowed=4-5" "$a" &&
    ! grep -q "0-3" "$a" && ! grep -q "4-7" "$a" && grep -qx "cpus_allowed_policy=split" "$a" || { cat "$a" >&2; exit 1; }
    case "$err" in
        *"note: h1: jobfile 011-a.job: cpus_allowed (0-3) includes cpus outside this host"*"s fio cpus (2-5); executing on the remainder (2-3)"*) ;;
        *) echo "0-3: $err" >&2; exit 1 ;;
    esac
    case "$err" in (*"cpus_allowed (4-7) includes"*"(4-5)"*) ;; (*) echo "4-7: $err" >&2; exit 1 ;; esac'
t_assert "stamping: a jobfile cpus_allowed inside the host's cpus stages unchanged, with no note" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1"
     printf "2-5\n" > "$AUTH_DIR/h1.cpus"
     printf "[global]\ncpus_allowed=3,4\n[a]\nrw=read\n" > "$d/jobs/h1/011-a.job"
     stamp_unique_names) 2>&1 >>$SUITE_ASIDE ) || { echo "stamp failed: $err" >&2; exit 1; }
    [ -z "$err" ] || { echo "a note: $err" >&2; exit 1; }
    [ "$(grep -c "^cpus_allowed=" "$d/jobs/h1/011-a.job")" = 1 ] && grep -qx "cpus_allowed=3,4" "$d/jobs/h1/011-a.job"'
# fio reads "2-5, 7" whole (atoi per item); the trim read it only to the
# first blank, so cpus after it were dropped or never checked (Bugbot).
t_assert "stamping: a jobfile cpu list with blanks is read whole: inside the host's cpus it stages canonically, with no note" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1"
     printf "0-15\n" > "$AUTH_DIR/h1.cpus"
     printf "[global]\ncpus_allowed=2-5, 7\n[a]\nrw=read\n" > "$d/jobs/h1/011-a.job"
     stamp_unique_names) 2>&1 >>$SUITE_ASIDE ) || { echo "stamp failed: $err" >&2; exit 1; }
    [ -z "$err" ] || { echo "a note: $err" >&2; exit 1; }
    a=$d/jobs/h1/011-a.job
    [ "$(grep -c "cpus_allowed=" "$a")" = 1 ] && grep -qx "cpus_allowed=2-5,7" "$a" || { cat "$a" >&2; exit 1; }'
t_assert "stamping: a jobfile cpu list with blanks reaching outside the host's cpus keeps every cpu after the blank, with the note" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1"
     printf "2-15\n" > "$AUTH_DIR/h1.cpus"
     printf "[global]\ncpus_allowed=0-3, 8\n[a]\nrw=read\n" > "$d/jobs/h1/011-a.job"
     stamp_unique_names) 2>&1 >>$SUITE_ASIDE ) || { echo "stamp failed: $err" >&2; exit 1; }
    a=$d/jobs/h1/011-a.job
    [ "$(grep -c "cpus_allowed=" "$a")" = 1 ] && grep -qx "cpus_allowed=2-3,8" "$a" || { cat "$a" >&2; exit 1; }
    case "$err" in
        *"note: h1: jobfile 011-a.job: cpus_allowed (0-3, 8) includes cpus outside this host"*"s fio cpus (2-15); executing on the remainder (2-3,8)"*) ;;
        *) echo "note: $err" >&2; exit 1 ;;
    esac'
t_assert "stamping: a jobfile cpus_allowed that is not a cpu list still stops the run, blanks or not" bash -c '
    for v in "0-3 foo" "2 5"; do
        d=$(mktemp -d)
        err=$( (source ./wekatester
         WORK_DIR=$d; HOSTS=(h1)
         AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1"
         printf "0-15\n" > "$AUTH_DIR/h1.cpus"
         printf "[global]\ncpus_allowed=%s\n[a]\nrw=read\n" "$v" > "$d/jobs/h1/011-a.job"
         stamp_unique_names) 2>&1 >>$SUITE_ASIDE ) && { echo "$v: no stop" >&2; exit 1; }
        case "$err" in
            *"h1: jobfile 011-a.job: cpus_allowed ($v) is not a cpu list"*) ;;
            *) echo "$v: $err" >&2; exit 1 ;;
        esac
    done'
t_assert "stamping: blank-spelled filename_format, unique_filename and cpus_allowed_policy lines are read as fio reads them" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1"
     printf "2-5\n" > "$AUTH_DIR/h1.cpus"
     printf "[global]\nfilename_format = y.\$filenum\n[a]\n  unique_filename = 1\ncpus_allowed = 3,4\n cpus_allowed_policy = shared\n# unique_filename = 1\nrw=read\n" > "$d/jobs/h1/011-a.job"
     stamp_unique_names) >>$SUITE_ASIDE 2>&1 || exit 1
    a=$d/jobs/h1/011-a.job
    [ "$(grep -cE "^[[:space:]]*filename_format[[:space:]]*=" "$a")" = 1 ] && grep -qx "filename_format=h1.y.\$filenum" "$a" &&
    [ "$(grep -cE "^[[:space:]]*unique_filename[[:space:]]*=" "$a")" = 1 ] && grep -qx "unique_filename=0" "$a" &&
    grep -qxF "# unique_filename = 1" "$a" && grep -qxF "cpus_allowed = 3,4" "$a" &&
    ! grep -q "policy=split" "$a" || { cat "$a" >&2; false; }'
t_assert "stamping: a jobfile cpus_allowed with no cpu in the host's cpus stops the run, naming the jobfile, its list and the host's cpus" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1)
     AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR" "$d/jobs/h1"
     printf "2-5\n" > "$AUTH_DIR/h1.cpus"
     printf "[global]\ncpus_allowed=0-1,6-7\n[a]\nrw=read\n" > "$d/jobs/h1/011-a.job"
     stamp_unique_names) 2>&1 >>$SUITE_ASIDE ) && { echo "no stop" >&2; exit 1; }
    case "$err" in
        *"h1: jobfile 011-a.job: cpus_allowed (0-1,6-7) names no cpu fio may use on this host (2-5) -- list cpus"*) ;;
        *) echo "$err" >&2; exit 1 ;;
    esac'
# Under -a, stage_hosts already writes every cpus_allowed from the set
# check_cpu_pinning records, so the trim must change nothing; a narrower
# recorded set proves it still reads auth/<host>.cpus.
t_assert "stamping: under -a the trim is a no-op, with or without a host-file list, and says nothing" bash -c '
    source ./tests/helpers.sh
    for list in - 1-6 3-6; do
        tuner_fixture
        printf "# report iops\n[global]\nfilesize=1G\nnumjobs=2\ncpus_allowed=0-7\n[io]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
        (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE 2>&1 || exit 1
        { printf "h1\t-\t-\t%s\t-" "$list"; for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
        (source ./wekatester; WORK_DIR=$FIX; HOSTS=(h1 h2); AUTO_LEVEL=max; check_cpu_pinning) >>$SUITE_ASIDE 2>&1 || exit 1
        [ -s "$FIX/auth/h1.cpus" ] && [ -s "$FIX/auth/h2.cpus" ] || { echo "$list: no auth cpus" >&2; exit 1; }
        (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1 || exit 1
        before=$(grep -r "^cpus_allowed=" "$FIX/jobs" | sort)
        err=$( (source ./wekatester; WORK_DIR=$FIX; HOSTS=(h1 h2); AUTH_DIR=$FIX/auth; stamp_unique_names) 2>&1 >>$SUITE_ASIDE ) ||
            { echo "$list: stamp failed: $err" >&2; exit 1; }
        after=$(grep -r "^cpus_allowed=" "$FIX/jobs" | sort)
        [ -z "$err" ] && [ "$(printf "%s\n" "$before" | wc -l)" -eq 6 ] && [ "$before" = "$after" ] &&
            ! printf "%s\n" "$before" | grep -q "=0-7$" ||
            { echo "$list: auth h1 $(cat "$FIX/auth/h1.cpus"), h2 $(cat "$FIX/auth/h2.cpus"); note: $err"
              echo "before:"; echo "$before"; echo "after:"; echo "$after"; exit 1; } >&2
    done
    printf "3\n" > "$FIX/auth/h1.cpus"
    err=$( (source ./wekatester; WORK_DIR=$FIX; HOSTS=(h1 h2); AUTH_DIR=$FIX/auth; stamp_unique_names) 2>&1 >>$SUITE_ASIDE )
    case "$err" in (*"note: h1: jobfile 031-iops.job: cpus_allowed ("*") includes cpus outside"*"executing on the remainder (3)"*) ;; (*) echo "control: $err" >&2; exit 1 ;; esac'
t_assert "stamping: staged variants and the generated layout carry it end to end" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_SUITE_TARGET_DIR="$d/target"
     source ./wekatester
     hostname() { echo testbox; }
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles && push_jobfiles) >>$SUITE_ASIDE || exit 1
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
     HOSTS=(); resolve_local_mode >>$SUITE_ASIDE
     [ "$LOCAL_NAME" = testbox ] && [ "${HOSTS[*]}" = localhost ] && [ "$MASTER" = localhost ])'
t_assert "probe: -e engine missing from a worker refuses early, naming it" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2); MASTER=h1; AUTO_LEVEL=max
            WORK_DIR=$d; DIRECTORY=/mnt/weka; ENGINE=io_uring
            run_host() { case "$2" in
                (*enghelp*) [ "$1" = h1 ] && printf "engines io_uring libaio psync\nbindable 0-7\n" \
                                          || printf "engines libaio psync\nbindable 0-7\n";;
                (*) echo stubbed;;
            esac; }
            probe_workers) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"ioengine '\''io_uring'\'' is not available"*"h2"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# fio launches under taskset -c, so a host whose bindable cpus are unknown
# cannot be pinned: the run stops, naming every such host and why, before
# any engine test (Frank, 2026-10-11).
t_assert "probe: hosts with no bindable cpus stop the run, each named with its reason" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2 h3); MASTER=h1; AUTO_LEVEL=""
            WORK_DIR=$d; DIRECTORY=/mnt/weka; ENGINE=""
            run_host() { case "$1" in
                (h1) printf "ncpus 8\ntaskset 0-7\nbindable 0-7\nbindable_priv -\n";;
                (h2) printf "ncpus 8\ntaskset \nbindable_err taskset -cp failed: taskset: Operation not permitted\n";;
                (h3) printf "ncpus 8\n";;
            esac; }
            probe_workers) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "probe_workers passed: $err" >&2; exit 1; }
    case "$err" in
        *"h2: cannot pin fio: taskset -cp failed: taskset: Operation not permitted"*"h3: cannot pin fio: its probe printed no bindable line"*"cannot pin fio on: h2 h3 --"*"taskset -c"*) ;;
        *) echo "$err" >&2; exit 1 ;;
    esac
    case "$err" in *"h1:"*|*"h1 "*) echo "named h1: $err" >&2; false ;; esac'

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
        [ "${PW_LOGINS[*]}" = "ubuntu root" ] && [ "${PW_SECRETS[*]}" = "pw1 pw2" ]) >>$SUITE_ASIDE) &&
    err=$(printf "ubuntu\n\n" | (source ./wekatester
        PW_COUNT=1; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        prompt_password_creds) 2>&1 >>$SUITE_ASIDE )
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
echo "$host $*" >> "$SUITE_TEST_LOG"
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
        PATH="$stub:$PATH"; export SUITE_TEST_LOG=$d/log
        WORK_DIR=$d; HOSTS=(h1 h2 h3 h4 h5); SSH_OPTS="-o BatchMode=yes"
        IDENT_LOGINS=(ubuntu); IDENT_KEYS=("$k1"); PW_COUNT=1
        PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        establish_connections
        [ ${#REMAINING[@]} -eq 1 ] && [ "${REMAINING[0]}" = h5 ]) 2>&1 >>$SUITE_ASIDE ) || \
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
# Review #19: an aborted run's fio must not load the cluster through the
# fleet-wide end pressure/sar round trip.
t_assert "cleanup: the fio kill comes before the end pressure/sar capture" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d/work; RUN_DIR=$d/run; mkdir -p "$WORK_DIR" "$RUN_DIR"
     HOSTS=(h1 h2); FIO_STARTED=1; TARGET_DIR=/dev/shm/x; RUN_EPOCH=1
     run_host() { case "$2" in
         (*WEKATESTER_SYSINFO*) echo "PRESSURE $1" >> "$d/oplog";;
         (*) echo "KILL $1" >> "$d/oplog";;
     esac; }
     cleanup) >>$SUITE_ASIDE 2>&1
    cat "$d/oplog" >>$SUITE_ASIDE
    awk "/^KILL/ { k++; last = NR } /^PRESSURE/ { p++; if (!first) first = NR }
         END { exit !(k == 2 && p == 2 && last < first) }" "$d/oplog"'
t_assert "cleanup: the run lock is held through the end capture and released after it, in its own session" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d/work; RUN_DIR=$d/run; mkdir -p "$WORK_DIR" "$RUN_DIR"
     HOSTS=(h1 h2); FIO_STARTED=1; TARGET_DIR=/dev/shm/x; RUN_EPOCH=1
     LOCK_DIR=/dev/shm/wt-lock-test; LOCK_TOKEN=tok; RUN_LOCKS=([h1]=1 [h2]=1)
     run_host() { case "$2" in
         (*wt-lock-test*) echo "LOCK $1" >> "$d/oplog";;
         (*WEKATESTER_SYSINFO*) echo "PRESSURE $1" >> "$d/oplog";;
         (*) echo "KILL $1" >> "$d/oplog";;
     esac; }
     cleanup; [ ${#RUN_LOCKS[@]} -eq 0 ]) >>$SUITE_ASIDE 2>&1 || exit 1
    cat "$d/oplog" >>$SUITE_ASIDE
    awk "/^KILL/ { k++; lk = NR } /^PRESSURE/ { p++; lp = NR; if (!fp) fp = NR } /^LOCK/ { l++; if (!fl) fl = NR }
         END { exit !(k == 2 && p == 2 && l == 2 && lk < fp && lp < fl) }" "$d/oplog"'
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
# fio --client reads the jobfiles on the master, so staging copies them there
# only. A worker's fio parsed a file it lacked, and the postmortem blamed it
# for rejecting the layout jobfile. Now a worker gets its own copy first.
t_assert "run_jobs: a failed layout stages each worker's jobfile before that worker's fio parses it" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; RUN_DIR=$d/out; HOSTS=(h1 h2 h3); MASTER=h1; LOCAL_MODE=0
     FIO_BIN=fio; TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka
     mkdir -p "$SET_DIR" "$RUN_DIR"
     for h in h1 h2 h3; do
         mkdir -p "$d/jobs/$h"
         printf "[global]\n[l]\nfilesize=10G\n" > "$d/jobs/$h/000-wekatester-layout.job"
     done
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     # the master holds every jobfile, a worker only what was copied to it;
     # h3 cannot be staged
     run_host() { echo "RUN[$1] $2" >> "$d/oplog"; case "$2" in
         (*--client=*) echo "{}";;
         (*--parse-only*) [ "$1" = h1 ] || grep -q "^COPY\[$1\]" "$d/oplog" ||
             { echo "fio: unable to open job file"; return 1; };;
         ("mkdir -p '"'"'/dev/shm/x/h3'"'"'") return 1;;
     esac; }
     copy_to_host() { echo "COPY[$1] ${2#"$d/"} -> $3" >> "$d/oplog"; }
     run_jobs) 2>&1 ) && { echo "a failed layout passed: $out" >&2; exit 1; }
    case "$out" in
        *"note: h1: the layout jobfile parses cleanly"*"note: h2: the layout jobfile parses cleanly"*"WARNING: h3: cannot stage the layout jobfile for a parse check on that host"*"layout 000-wekatester-layout.job failed -- the files were not created"*) true;;
        *) echo "$out" >&2; exit 1;;
    esac
    case "$out" in *rejects*) echo "blamed a worker fio: $out" >&2; exit 1;; esac
    want=$(printf "%s\n" "RUN[h2] mkdir -p '"'"'/dev/shm/x/h2'"'"'" \
        "COPY[h2] jobs/h2/000-wekatester-layout.job -> /dev/shm/x/h2/" \
        "RUN[h2] '"'"'fio'"'"' --parse-only '"'"'/dev/shm/x/h2/000-wekatester-layout.job'"'"'")
    [ "$(grep "\[h2\]" "$d/oplog")" = "$want" ] || { cat "$d/oplog" >&2; exit 1; }
    ! grep -q -e "^COPY\[h1\]" -e "mkdir -p '"'"'/dev/shm/x/h1'"'"'" "$d/oplog" &&
    ! grep -q "^RUN\[h3\] .*--parse-only" "$d/oplog" &&
    [ -e "$d/out/parse.000-wekatester-layout.h2.out" ] &&
    [ ! -e "$d/out/parse.000-wekatester-layout.h3.out" ]'
# One host after another, the postmortem was ~3 ssh sessions a host: 30-50 s
# at 451 hosts before the run said why it failed (Frank, 2026-10-11). Every
# host's staging and parse run at once now; the messages keep host order.
t_assert "run_jobs: a failed layout's parse checks run on every host at once" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; RUN_DIR=$d/out; HOSTS=(h1 h2 h3); MASTER=h1; LOCAL_MODE=0
     FIO_BIN=fio; TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka
     mkdir -p "$SET_DIR" "$RUN_DIR"
     for h in h1 h2 h3; do
         mkdir -p "$d/jobs/$h"
         printf "[global]\n[l]\nfilesize=10G\n" > "$d/jobs/$h/000-wekatester-layout.job"
     done
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { case "$2" in
         (*--client=*) echo "{}";;
         (*--parse-only*) echo "S $1 ${EPOCHREALTIME//[!0-9]/}" >> "$d/times"; sleep 1
                          echo "E $1 ${EPOCHREALTIME//[!0-9]/}" >> "$d/times";;
     esac; }
     copy_to_host() { :; }
     run_jobs) 2>&1 ) && { echo "a failed layout passed: $out" >&2; exit 1; }
    case "$out" in *"note: h3: the layout jobfile parses cleanly"*) ;; *) echo "$out" >&2; exit 1;; esac
    spans_overlap "$d/times" 6'
t_assert "run_jobs: a failed layout's postmortem prints in host order when the hosts finish out of order" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; RUN_DIR=$d/out; HOSTS=(h1 h2 h3); MASTER=h1; LOCAL_MODE=0
     FIO_BIN=fio; TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka
     mkdir -p "$SET_DIR" "$RUN_DIR"
     for h in h1 h2 h3; do
         mkdir -p "$d/jobs/$h"
         printf "[global]\n[l]\nfilesize=10G\n" > "$d/jobs/$h/000-wekatester-layout.job"
     done
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     # h1 (the master) parses slowest, h2 cannot be staged, h3 fio rejects
     run_host() { case "$2" in
         (*--client=*) echo "{}";;
         ("mkdir -p '"'"'/dev/shm/x/h2'"'"'") echo h2 >> "$d/done"; return 1;;
         (*--parse-only*) [ "$1" != h1 ] || sleep 1; echo "$1" >> "$d/done"
                          [ "$1" != h3 ] || { echo "fio: bad option xyz"; return 1; };;
     esac; }
     copy_to_host() { :; }
     run_jobs) 2>&1 ) && { echo "a failed layout passed: $out" >&2; exit 1; }
    # the precondition: h1 did finish last
    [ "$(wc -l < "$d/done")" -eq 3 ] && [ "$(tail -1 "$d/done")" = h1 ] \
        || { echo "finish order:" $(cat "$d/done") >&2; exit 1; }
    got=$(printf "%s\n" "$out" | sed -n "s/^[0-9:]* \(.*: h[123]: .*\)/\1/p")
    want=$(printf "%s\n" \
        "note: h1: the layout jobfile parses cleanly on its host -- the jobs died at setup, not at option parsing" \
        "WARNING: h2: cannot stage the layout jobfile for a parse check on that host" \
        "ERROR: h3: the host'"'"'s own fio rejects the layout jobfile (full text: parse.000-wekatester-layout.h3.out in the run bundle):" \
        "ERROR: h3:   fio: bad option xyz")
    [ "$got" = "$want" ] || { printf "got:\n%s\nwant:\n%s\nout:\n%s\n" "$got" "$want" "$out" >&2; exit 1; }
    case "$out" in
        *"h3:   fio: bad option xyz"*"ERROR: layout 000-wekatester-layout.job failed -- the files were not created"*) true;;
        *) echo "$out" >&2; false;;
    esac'
# The sweep deleted every file short of its size, so an interrupted layout
# started that file over; now it lists sizes and the layout extends.
t_assert "sweep: one listing per namespace into the host's sizes file, nothing deleted" bash -c '
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
     run_host() { echo "SWEEP[$1]: $2" >> "$d/oplog"; echo "1073741824 /mnt/weka/h1.0/0"; }
     sweep_layout_grid) >>$SUITE_ASIDE 2>&1
    cat "$d/oplog" >>$SUITE_ASIDE
    grep -qF -- "SWEEP[h1]: find \"/mnt/weka\" -maxdepth 2 -type f -path \"/mnt/weka/h1.*/*\" ! -path \"/mnt/weka/.wekatester-cal/*\" -printf '"'"'%s %p\\n'"'"' && find \"/mnt/weka\" -maxdepth 1 -type f -path \"/mnt/weka/h1.wt.*.0\" ! -path \"/mnt/weka/.wekatester-cal/*\" -printf '"'"'%s %p\\n'"'"'" "$d/oplog" &&
    ! grep -q -- "-delete\|rm -f" "$d/oplog" &&
    [ "$(cat "$d/probe/h1.sizes")" = "1073741824 /mnt/weka/h1.0/0" ]'
t_assert "sweep: same-format sections list from exact singleton indices (no walk over the other sections)" bash -c '
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
     run_host() { echo "SWEEP: $2" >> "$d/oplog"; }
     sweep_layout_grid) >>$SUITE_ASIDE 2>&1
    cat "$d/oplog" >>$SUITE_ASIDE
    grep -qF -- "if [ -d \"/mnt/weka/h1.0\" ]; then find \"/mnt/weka/h1.0\" -maxdepth 1 -type f -path \"/mnt/weka/h1.0/*\" ! -path \"/mnt/weka/.wekatester-cal/*\" -printf '"'"'%s %p\\n'"'"'; fi" "$d/oplog" &&
    [ "$(grep -o -- "-path \"/mnt/weka/h1.\*/\*\"" "$d/oplog" | wc -l)" -eq 1 ]'
# Run for real: with -d <dir>/ the joined pattern held "//", find printed one
# slash, and the sweep credited nothing. Short files were deleted and laid
# out whole by a create_only pass that ftruncates to full size first.
t_assert "stage_layout_writes: a trailing-slash -d; short files are kept and extended, complete and larger ones reused, the bytes present credited (find run for real)" bash -c '
    d=$(mktemp -d); t=$d/dest
    mkdir -p "$t/h1.0" "$t/h1.1"
    mk() { head -c "$2" /dev/zero > "$t/$1"; }
    # flat 12K: complete, short on its 4K block, missing; nested 8K: larger,
    # short off its 8K block (rewritten from 0), complete, missing
    mk h1.wt.0.0 12288; mk h1.wt.1.0 4096; mk h1.0/0 16384; mk h1.0/1 1000; mk h1.1/0 8192
    out=$( (source ./wekatester
     parse_args -d "$t/" h1
     WORK_DIR=$d; SET_DIR=$d/set; DRY_RUN=0; RUN_DIR=$d/run; mkdir -p "$RUN_DIR"
     mkdir -p "$d/jobs/h1" "$SET_DIR"
     lay="# wekatester-layout: generated sha256=abc
[global]
directory=$t
fallocate=none
ioengine=psync
unique_filename=0
[flat]
create_only=1
filename_format=h1.wt.\$jobnum.\$filenum
filesize=12K
numjobs=3
[nested]
create_only=1
filename_format=h1.\$filenum/\$jobnum
filesize=8K
nrfiles=2
numjobs=2"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { bash -c "$2"; }
     sweep_layout_grid && stage_layout_writes) 2>&1 ) || { echo "$out" >&2; exit 1; }
    left=$(cd "$t" && find . -type f | LC_ALL=C sort | tr "\n" " ")
    # present: 12K + 4K + 0 + 8K (of 16K) + 1000 + 8K + 0
    [ "$(cat "$d/probe/h1.laidout")" = 33768 ] && [ "$left" = "./h1.0/0 ./h1.0/1 ./h1.1/0 ./h1.wt.0.0 ./h1.wt.1.0 " ] ||
        { echo "credited $(cat "$d/probe/h1.laidout"); left: $left; $out" >&2; exit 1; }
    want="# wekatester-layout: generated as a dense write
# Staged per run from the layout grid, after the sweep: every file missing
# or short of its size is written sequentially from its end, so a stopped
# layout leaves a short file, never a full-size one with a hole (README).
[global]
directory=$t
fallocate=none
ioengine=psync
unique_filename=0
group_reporting=1

[lay-1-8192-w1]
rw=write
bs=8192
direct=1
create_on_open=1
file_append=0
numjobs=1
nrfiles=1
filesize=8192
filename=h1.0/1

[lay-1-8192-a2]
rw=write
bs=8192
direct=1
create_on_open=1
file_append=1
numjobs=1
nrfiles=1
filesize=8192
filename=h1.1/1

[lay-1-12288-a3]
rw=write
bs=4096
direct=1
create_on_open=1
file_append=1
numjobs=1
nrfiles=1
filesize=12288
filename=h1.wt.1.0

[lay-2-12288-a4]
rw=write
bs=4096
direct=1
create_on_open=1
file_append=1
numjobs=1
nrfiles=1
filesize=12288
filename=h1.wt.2.0"
    [ "$(cat "$d/jobs/h1/000-wekatester-layout.job")" = "$want" ] ||
        { diff <(printf "%s\n" "$want") "$d/jobs/h1/000-wekatester-layout.job" >&2; exit 1; }
    # the grid is kept for the directory pass and the capacity check
    grep -qx "filename_format=h1.\$filenum/\$jobnum" "$d/grid/h1/000-wekatester-layout.job" &&
    grep -qx "layout	4 file(s), 36864 bytes to write on 1 host(s)" "$d/run/settings" &&
    case "$out" in *"layout: h1: 4 file(s) missing or short, 0.0 GiB to write (3 reused)"*) true;;
        *) echo "$out" >&2; false;; esac'
# Overlapping grids were chained with wait_for so no file was laid out twice
# at once; each file now sits in exactly one section, at its largest size.
t_assert "stage_layout_writes: overlapping grids write each file once at its largest size, 16 to a section, colons escaped" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1); DRY_RUN=1
     mkdir -p "$d/jobs/h1" "$SET_DIR" "$d/probe"
     lay="# wekatester-layout: generated sha256=abc
[global]
directory=/w
[a]
create_only=1
filename_format=h1.\$filenum/\$jobnum
filesize=8K
nrfiles=20
numjobs=1
[b]
wait_for=a
create_only=1
filename_format=h1.\$filenum/\$jobnum
filesize=16K
numjobs=2
[c]
create_only=1
filename_format=h1:c.\$jobnum
filesize=4K"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     : > "$d/probe/h1.sizes"
     JOBFILES=(000-wekatester-layout.job)
     stage_layout_writes) 2>&1 ) || { echo "$out" >&2; exit 1; }
    l=$d/jobs/h1/000-wekatester-layout.job
    f=$(grep "^filename=" "$l" | tr "\n" "|")
    want="filename=h1\:c.0|filename=h1.1/0:h1.2/0:h1.3/0:h1.4/0:h1.5/0:h1.6/0:h1.7/0:h1.8/0:h1.9/0:h1.10/0:h1.11/0:h1.12/0:h1.13/0:h1.14/0:h1.15/0:h1.16/0|filename=h1.17/0:h1.18/0:h1.19/0|filename=h1.0/0|filename=h1.0/1|"
    [ "$f" = "$want" ] || { printf "got  %s\nwant %s\n" "$f" "$want" >&2; cat "$l" >&2; exit 1; }
    # h1.0/0 is in both grids: written once, at 16K
    grep -A9 -x "\[lay-0-16384-a4\]" "$l" | grep -qx "filesize=16384" &&
    grep -A9 -x "\[lay-0-8192-a2\]" "$l" | grep -qx "nrfiles=16" &&
    ! grep -q "^wait_for=\|^create_only" "$l" &&
    case "$out" in *"layout: h1: 22 file(s) missing or short, 0.0 GiB to write (0 reused)"*) true;;
        *) echo "$out" >&2; false;; esac'
t_assert "stage_layout_writes: a namespace the sweep cannot size keeps its create_only sections, wait_for chain and all, earns no credit, and says so" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1); DRY_RUN=1
     mkdir -p "$d/jobs/h1" "$SET_DIR" "$d/probe"
     lay="# wekatester-layout: generated sha256=abc
[global]
directory=/w
[l1]
create_only=1
filename_format=h1.\$clientuid.\$jobnum
filesize=4K
numjobs=2
[l2]
wait_for=l1
create_only=1
filename_format=h1.\$clientuid.\$jobnum
filesize=8K
[l3]
create_only=1
filename_format=h1.odd.\$jobnum
filesize=1000
[l4]
create_only=1
filename_format=h1.ok.\$jobnum
filesize=4K
numjobs=2"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     printf "4096 /w/h1.ok.0\n4096 /w/h1.odd.0\n" > "$d/probe/h1.sizes"
     JOBFILES=(000-wekatester-layout.job)
     stage_layout_writes) 2>&1 ) || { echo "$out" >&2; exit 1; }
    l=$d/jobs/h1/000-wekatester-layout.job
    tail -n 16 "$l" > "$d/kept"
    printf "[l1]\ncreate_only=1\nfilename_format=h1.\$clientuid.\$jobnum\nfilesize=4K\nnumjobs=2\n\n[l2]\nwait_for=l1\ncreate_only=1\nfilename_format=h1.\$clientuid.\$jobnum\nfilesize=8K\n\n[l3]\ncreate_only=1\nfilename_format=h1.odd.\$jobnum\nfilesize=1000\n" > "$d/want"
    cmp "$d/kept" "$d/want" >>$SUITE_ASIDE || { diff "$d/want" "$d/kept" >&2; exit 1; }
    # only the complete h1.ok.0 counts; h1.ok.1 is the one file written
    [ "$(cat "$d/probe/h1.laidout")" = 4096 ] && grep -qx "filename=h1.ok.1" "$l" &&
    case "$out" in *"WARNING: h1: 3 layout section(s) the sweep cannot size stay create_only"*) true;;
        *) echo "$out" >&2; false;; esac'
t_assert "stage_layout_writes: a set's own layout job is staged as written; only its credit counts" bash -c '
    d=$(mktemp -d)
    lay="[global]
directory=/w
[mine]
create_only=1
filename_format=h1.\$jobnum
filesize=4K
numjobs=2"
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1); DRY_RUN=1; LAYOUT_OWN=1; RUN_DIR=$d/run
     mkdir -p "$d/jobs/h1" "$SET_DIR" "$d/probe" "$RUN_DIR"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     printf "4096 /w/h1.0\n" > "$d/probe/h1.sizes"
     JOBFILES=(000-wekatester-layout.job)
     stage_layout_writes) 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cat "$d/jobs/h1/000-wekatester-layout.job")" = "$lay" ] && [ "$(cat "$d/probe/h1.laidout")" = 4096 ] &&
    [ ! -s "$d/run/settings" ] || { echo "$out" >&2; cat "$d/jobs/h1/000-wekatester-layout.job" >&2; false; }'
t_assert "run_jobs: a staged layout with nothing to write runs no fio and says so" bash -c '
    d=$(mktemp -d); : > "$d/oplog"
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; RUN_DIR=$d/out; HOSTS=(h1 h2); MASTER=h1
     FIO_BIN=fio; TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka
     mkdir -p "$d/jobs/h1" "$d/jobs/h2" "$SET_DIR" "$RUN_DIR"
     printf "%s\n[global]\ndirectory=/mnt/weka\ngroup_reporting=1\n" "$LAYOUT_WRITE_MARKER" | tee "$d/jobs/h1/000-wekatester-layout.job" > "$d/jobs/h2/000-wekatester-layout.job"
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { echo "RUN: $2" >> "$d/oplog"; }
     run_jobs) 2>&1 ) || { echo "$out" >&2; exit 1; }
    ! grep -q "000-wekatester-layout.job" "$d/oplog" &&
    case "$out" in *"layout: nothing to write (files reused)"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "run_jobs: the layout's sequential write prints a block like a test: bandwidth, the host spread and the bytes written" bash -c '
    d=$(mktemp -d)
    w() { printf "{ \"jobname\": \"%s\", \"hostname\": \"%s\", \"error\": 0, \"read\": { \"bw_bytes\": 0, \"iops\": 0, \"total_ios\": 0, \"io_bytes\": 0, \"lat_ns\": { \"mean\": 0 } }, \"write\": { \"bw_bytes\": %s, \"iops\": 1, \"total_ios\": 1, \"io_bytes\": %s, \"lat_ns\": { \"mean\": 1 } } }" "$1" "$2" "$3" "$4"; }
    printf "{ \"client_stats\": [ %s, %s, %s ] }\n" "$(w lay-0 h1 1073741824 10737418240)" "$(w lay-0 h2 2147483648 21474836480)" \
        "$(w "All clients" "" 3221225472 32212254720)" > "$d/r.json"
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; RUN_DIR=$d/out; HOSTS=(h1 h2); MASTER=h1
     FIO_BIN=fio; TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka
     mkdir -p "$d/jobs/h1" "$d/jobs/h2" "$SET_DIR" "$RUN_DIR"
     for h in h1 h2; do printf "%s\n[global]\n[lay-0]\nrw=write\nfilename=%s.0\n" "$LAYOUT_WRITE_MARKER" "$h" > "$d/jobs/$h/000-wekatester-layout.job"; done
     printf "# wekatester-layout: generated sha256=abc\n[l]\ncreate_only=1\n" > "$SET_DIR/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { cat "$d/r.json"; }
     run_jobs) 2>&1 ) || { echo "$out" >&2; exit 1; }
    want="layout sequential write (000-wekatester-layout.job), the data the sweep found missing, on 2 host(s):
    write bandwidth: 3.00 GiB/s
    average bandwidth: 1.50 GiB/s per host  (min 1.00 GiB/s h1, max 2.00 GiB/s h2)
    written: 30.00 GiB, 15.00 GiB per host  (min 10.00 GiB h1, max 20.00 GiB h2)"
    case "$out" in *"layout: complete in "*"$want"*) true;; *) printf "%s\n--- want:\n%s\n" "$out" "$want" >&2; false;; esac'
t_assert "main: the layout is staged from the sweep, before the capacity check and the push; a dry run stages it too" bash -c '
    body=$(source ./wekatester; declare -f main)
    case "$body" in
        *"stage_jobfiles;"*"sweep_layout_grid;"*"stage_layout_writes;"*"check_capacity"*"dry_run_report;"*"exit 0;"*"stage_jobfiles;"*"sweep_layout_grid;"*"stage_layout_writes;"*"check_capacity;"*"push_jobfiles;"*"run_jobs;"*) true;;
        *) echo "$body" >&2; false;;
    esac &&
    ! declare -f stage_jobfiles | grep -q copy_to_master'
t_assert "-u: the unlink job is derived from the layout grid and the layout staging leaves it alone" bash -c '
    source ./tests/helpers.sh; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_SUITE_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""; DRY_RUN=1
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka; UNLINK=1
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles && cp "$WORK_DIR/jobs/localhost/999-wekatester-unlink.job" "$d/before" &&
     run_host() { :; } && sweep_layout_grid && stage_layout_writes) >>$SUITE_ASIDE 2>&1 || exit 1
    u="$d/work/jobs/localhost/999-wekatester-unlink.job"; l="$d/work/jobs/localhost/000-wekatester-layout.job"
    cmp "$d/before" "$u" && grep -q "^unlink=1$" "$u" && grep -q "^create_only=1$" "$u" && grep -q "^filename_format=" "$u" &&
    grep -q "^filename=" "$l" && grep -q "^file_append=1$" "$l" || { cat "$u" "$l" >&2; false; }'
# An old-format tuple (fs/nr/qd, no nj) is re-measured, and fill mode keeps
# its fields: a mix nobody measured, which the writeback would make permanent.
# The file cannot say whether the operator wrote it, so the run warns.
t_assert "apply_cal_results: fill keeps the host file's pinned fields and adds what was searched; -g replaces" bash -c '
    d=$(mktemp -d)
    printf "h1 - 4 2 5120M 6 - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n" > "$d/cal.results"
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (7) printf "\t1G";; (8) printf "\t2";; (9) printf "\t8";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$d/targets.final"
    cp "$d/targets.final" "$d/orig"
    err=$( (source ./wekatester; WORK_DIR=$d; REGEN_LAYOUT=0; apply_cal_results) 2>&1 )
    a=$(awk -F"\t" "\$1==\"h1\" {print \$6, \$7, \$8, \$9}" "$d/targets.final")
    # the fields pinned the search, so the tuple was measured with them: no warning
    [ "$a" = "6 1G 2 8" ] && [ -z "$err" ] || { echo "fill: $a $err" >&2; exit 1; }
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
t_assert "apply_cal_results: --line-rate lets the measured bandwidth tuples replace host-file values; the rest only fill gaps" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; REGEN_LAYOUT=0; LINE_RATE_GBPS=16
     # cal.results: host, engine, then (qd nr fs nj) x (bw_r bw_w lat_r lat_w iops_r iops_w lat1m_r lat1m_w)
     printf "h1 libaio 4 2 1024M 2 2 2 1024M 6 1 2 1024M 3 - - - - 32 2 256M 6 16 2 256M 6 - - - - - - - -\n" > "$d/cal.results"
     # 37 columns; the engine (col 3), bw_r_qd (col 9) and iops_r_qd (col 25) carry old values
     { printf "h1"
       for i in $(seq 2 37); do
          case $i in (3) printf "\tpsync";; (9) printf "\t8";; (25) printf "\t64";; (*) printf "\t-";; esac
       done; printf "\n"; } > "$d/targets.final"
     apply_cal_results) || exit 1
    a=$(awk -F"\t" "\$1==\"h1\" {print \$3, \$9, \$13, \$25, \$29, \$6}" "$d/targets.final")
    # bw_r is replaced (qd 4, nj 2); the engine and iops_r_qd keep the file values
    [ "$a" = "psync 4 2 64 16 2" ] || { echo "a=$a" >&2; false; }'
# A dry run skipped the sweep, so it could not say what the layout writes.
t_assert "sweep: a dry run only lists, and stages the layout it would write" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1); MASTER=h1; DRY_RUN=1; DIRECTORY=/mnt/weka; ANY_FS=0
     mkdir -p "$SET_DIR" "$d/jobs/h1"
     lay="# wekatester-layout: generated sha256=abc
[global]
directory=/mnt/weka
[l]
create_only=1
filename_format=h1.\$jobnum
filesize=1M
numjobs=2"
     printf "%s\n" "$lay" > "$SET_DIR/000-wekatester-layout.job"
     printf "%s\n" "$lay" > "$d/jobs/h1/000-wekatester-layout.job"
     JOBFILES=(000-wekatester-layout.job)
     run_host() { echo "RUN: $2" >> "$d/oplog"; echo "1048576 /mnt/weka/h1.0"; }
     sweep_layout_grid && stage_layout_writes && dry_run_report) 2>&1 ) || { echo "$out" >&2; exit 1; }
    cat "$d/oplog" >>$SUITE_ASIDE
    [ "$(wc -l < "$d/oplog")" -eq 1 ] && grep -q "^RUN: find .*-printf" "$d/oplog" && ! grep -q -- "-delete\|rm " "$d/oplog" &&
    grep -qx "filename=h1.1" "$d/jobs/h1/000-wekatester-layout.job" &&
    case "$out" in *"layout: h1: 1 file(s) missing or short, 0.0 GiB to write (1 reused)"*"layout: would write 0.0 GiB across the hosts"*"filename=h1.1"*) true;;
        *) echo "$out" >&2; false;; esac'
t_assert "capacity: swept bytes are credited against the requirement" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    d=$(mktemp -d)
    printf "42949672960" > "$FIX/probe/h1.laidout"
    out=$( (export WEKATESTER_PROMPT_TTY=/dev/null; source ./wekatester
        WORK_DIR=$FIX; HOSTS=(h1); IGNORE_CAPACITY=0
        auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 >>$SUITE_ASIDE 2>&1
        run_host() { printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 209715200 0 209715200 1%% /mnt/weka\n"; }
        check_capacity) 2>&1 )
    case "$out" in
        *"already laid out"*) true;;
        *) echo "$out" >&2; false;;
    esac'
# The staged layout is the run's write of what is missing: pricing it would
# count only the missing files, less the credit for the present ones again.
t_assert "capacity: the layout is priced from the grid the sweep kept, not the staged write of what is missing" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs/h1" "$d/grid/h1" "$d/probe"
    printf "%s\n[global]\ndirectory=/w\n[lay-0-1-a1]\nrw=write\nnumjobs=1\nnrfiles=1\nfilesize=1G\nfilename=h1.7\n" "# wekatester-layout: generated as a dense write" > "$d/jobs/h1/000-wekatester-layout.job"
    printf "# wekatester-layout: generated sha256=abc\n[global]\ndirectory=/w\n[l]\ncreate_only=1\nfilename_format=h1.\$jobnum\nfilesize=1G\nnumjobs=8\n" > "$d/grid/h1/000-wekatester-layout.job"
    printf "7516192768\n" > "$d/probe/h1.laidout"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); IGNORE_CAPACITY=0
        run_host() { printf "Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 209715200 0 209715200 1%% /w\n"; }
        check_capacity) 2>&1 )
    case "$out" in
        *"capacity: h1 needs ~1.0GiB (~7.0GiB already laid out)"*) true;;
        *) echo "$out" >&2; false;;
    esac'

# No cluster-wide weka CLI runs on the master under -a: the DRAM ceiling it
# fed is retired (weka backends hold no user data in RAM, so there is no
# cache to defeat), so df is the only master-side fact the tuner needs. The per-host
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
                              printf "stubbed\nbindable 0-7\n";;
                (*"weka "*) echo "WEKA_CALLED: $2" >&2; return 1;;
                (*) echo stubbed;;
            esac; }
            probe_workers) 2>&1 >>$SUITE_ASIDE ) || { echo "probe died: $err" >&2; exit 1; }
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
    err=$( (rt phase1 "$f" - - - h1) 2>&1 >>$SUITE_ASIDE ); rc=$?
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
    out=$(rt phase1 "$f" - - - h1 2>&1)
    err=$( (rt phase1 "$f" - - - h1) 2>&1 >>$SUITE_ASIDE )
    echo "$out" | grep -q "^h1	-	-	0-3" &&
    case "$err" in
        *"WARNING"*"line 2"*"line 1"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# Pattern rows: a host cell with *, ? or [ is a shell glob over the host as
# given (case-insensitive, no DNS); a bare * covers every host.
t_assert "targets: glob rows match names, IPs (dots literal), FQDNs, ? and [..], any case; * matches all" bash -c '
    f=$(mktemp)
    printf "cg-*,,,,/mnt/cg\n10.0.0.1*,,,,/mnt/ip\nNODE?.LAB.example,,,,/mnt/fq\nr[ab]x,,,,/mnt/c\nr[!ab]y,,,,/mnt/n\n*,,,,/mnt/all\n" > "$f"
    out=$(rt phase1 "$f" - - - cg-01 CG-02.lab 10.0.0.12 10x0x0x1 node7.lab.example node77.lab.example rax rbx rcx rcy ray zz 2>>$SUITE_ASIDE | cut -f1,5 | tr "\t\n" " ;")
    want="cg-01 /mnt/cg;CG-02.lab /mnt/cg;10.0.0.12 /mnt/ip;10x0x0x1 /mnt/all;node7.lab.example /mnt/fq;node77.lab.example /mnt/all;rax /mnt/c;rbx /mnt/c;rcx /mnt/all;rcy /mnt/n;ray /mnt/all;zz /mnt/all;"
    [ "$out" = "$want" ] || { echo "got:  $out" >&2; echo "want: $want" >&2; false; }'
t_assert "targets: a [..] class holding [ is refused, naming the line" bash -c '
    f=$(mktemp)
    printf "h1,,,,\nc[[a]x,,,,\n" > "$f"
    err=$( (rt phase1 "$f" - - - h1) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in *":2: host pattern '\''c[[a]x'\''"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "targets: a [..] class with a backwards range is refused, naming the line; a forward one matches" bash -c '
    f=$(mktemp)
    printf "h1,,,,\nc[z-a]*,u,,,\n" > "$f"
    err=$( (rt phase1 "$f" - - - h1) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in *":2: host pattern '\''c[z-a]*'\''"*"backwards range"*) true;; *) echo "$err" >&2; false;; esac &&
    printf "c[a-c]*,u,,,\n" > "$f" && out=$(rt phase1 "$f" - - - cb-1 | cut -f1,2) &&
    [ "$out" = "cb-1	u" ] || { echo "forward: $out" >&2; false; }'
t_assert "targets: host line beats name glob beats * beats selector lines, field by field" bash -c '
    f=$(mktemp)
    printf ",,,,/mnt/sel,1/1G/1/1\n*,,,0-1,/mnt/all,2/2G/2/2\ncg-*,,,2-3,,,\ncg-01,,,,/mnt/own,,\n" > "$f"
    out=$(rt phase1 "$f" - - - cg-01 cg-02 zz | cut -f1,4,5,6 | tr "\t\n" " ;")
    want="cg-01 2-3 /mnt/own 2;cg-02 2-3 /mnt/all 2;zz 0-1 /mnt/all 2;"
    [ "$out" = "$want" ] || { echo "got:  $out" >&2; echo "want: $want" >&2; false; }'
t_assert "targets: two name globs tie: the first wins and the warning names both lines" bash -c '
    f=$(mktemp)
    printf "h1,,,,\ncg-*,,,0-3,,\ncg-0?,,,4-7,,\n" > "$f"
    out=$(rt phase1 "$f" - - - cg-01 2>>$SUITE_ASIDE | cut -f1,4)
    err=$( (rt phase1 "$f" - - - cg-01) 2>&1 >>$SUITE_ASIDE )
    [ "$out" = "cg-01	0-3" ] &&
    case "$err" in
        *"WARNING: $f: host '\''cg-01'\'' field '\''cpus'\'': line 3 conflicts with equally specific line 2; keeping line 2"*) true;;
        *) echo "out: $out err: $err" >&2; false;;
    esac'
t_assert "targets: a glob row assigns its login (phase1 field 2, what the auth rounds read); a login selector then folds in" bash -c '
    d=$(mktemp -d)
    printf "cg-*,ubuntu,,,\n,ubuntu,,0-3,,\n" > "$d/hl.csv"
    (source ./wekatester; WORK_DIR=$d
     resolve_targets phase1 "$d/hl.csv" - - - cg-01 h2 > "$d/targets.phase1"
     got=$(targets_column 2 "$d/targets.phase1" cg-01 h2 | tr "\n" ";")
     cpus=$(targets_field cg-01 4)
     [ "$got" = "ubuntu;;" ] && [ "$cpus" = 0-3 ] || { echo "logins: $got cpus: $cpus" >&2; false; })'
t_assert "targets: a name glob matching no host warns with file:line:pattern; the run goes on" bash -c '
    f=$(mktemp)
    printf "h1,,,,\nnomatch-*,,,0-3,\nh?,,,4-7,\n" > "$f"
    err=$( (rt phase1 "$f" - - - h1) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -eq 0 ] &&
    case "$err" in
        *"WARNING: $f:2: host pattern '\''nomatch-*'\'' matches none of this run'\''s hosts"*) true;;
        *) echo "$err" >&2; exit 1;;
    esac &&
    # the matching glob on line 3 is not named
    case "$err" in *"'\''h?'\''"*) echo "$err" >&2; false;; *) true;; esac'
t_assert "targets: in local mode a glob matches the short hostname as well as localhost" bash -c '
    f=$(mktemp)
    printf "cg-*,,,,/mnt/cg\nloc*,,,,/mnt/lo\n" > "$f"
    out=$( (source ./wekatester; LOCAL_MODE=1; LOCAL_NAME=cg-01
            resolve_targets phase1 "$f" - - - localhost) 2>>$SUITE_ASIDE | cut -f1,5)
    [ "$out" = "localhost	/mnt/cg" ] || { echo "got: $out" >&2; false; }'
t_assert "targets: hostonly leaves pattern rows out: they are not the host own" bash -c '
    f=$(mktemp)
    printf "cg-*,ubuntu,,0-3,/mnt/g\n*,root,,,/mnt/a\n" > "$f"
    ho=$(rt hostonly "$f" - - - cg-01 | cut -f1-5)
    p1=$(rt phase1 "$f" - - - cg-01 | cut -f1-5)
    [ "$ho" = "cg-01	-	-	-	-" ] && [ "$p1" = "cg-01	ubuntu	-	0-3	/mnt/g" ] ||
        { echo "ho: $ho p1: $p1" >&2; false; }'
t_assert "targets: geometry columns parse with or without the type: prefix" bash -c '
    f=$(mktemp)
    printf "h1,,,,,bandwidthR:12/10G//8,12/10G//4,latencyR:1///1,,iopsR:4/1G/56/64,\n" > "$f"
    out=$(rt phase1 "$f" - - - h1)
    want="h1	-	-	-	-	12	10G	-	8	12	10G	-	4	1	-	-	1	-	-	-	-	4	1G	56	64	-	-	-	-	-	-	-	-	-	-	-	-"
    [ "$out" = "$want" ] || { echo "got:  $out" >&2; echo "want: $want" >&2; false; }'
t_assert "targets: a wrong type: prefix in a geometry column is fatal" bash -c '
    f=$(mktemp)
    printf "h1,,,,,iopsR:4///,,,,,\n" > "$f"
    ! out=$(rt phase1 "$f" - - - h1 2>&1)'
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

# --- host files (-t): flag, file resolution, prompts ---
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
        resolve_targets_file) 2>&1 >>$SUITE_ASIDE )
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
        [ "$TARGETS_FILE" = "$d/new.csv" ]) >>$SUITE_ASIDE
    head -1 "$d/new.csv" | grep -q "^host,user_login"'
t_assert "targets file: a missing one is created only after the checks that need no file pass (a bad -i key leaves none)" bash -c '
    d=$(mktemp -d); mkdir "$d/bin"; printf "#!/bin/sh\necho Linux\n" > "$d/bin/uname"
    # the control run goes on past the file: ssh and scp never leave this box
    printf "#!/bin/sh\necho \"\$0 stub: \$*\" >&2; exit 255\n" > "$d/bin/ssh"; cp "$d/bin/ssh" "$d/bin/scp"
    chmod +x "$d/bin/uname" "$d/bin/ssh" "$d/bin/scp"
    out=$(unset $(compgen -v WT_); PATH=$d/bin:$PATH WEKATESTER_PROMPT_TTY=$d/no-tty \
          bash ./wekatester -r -t "$d/new.csv" -i /no/such/key h1 2>&1); rc=$?
    [ "$rc" -ne 0 ] && [ ! -e "$d/new.csv" ] || { echo "rc=$rc new.csv: $(ls "$d"); $out" >&2; exit 1; }
    case "$out" in *"identity file not readable: /no/such/key"*) ;; *) echo "$out" >&2; exit 1;; esac
    # control: with a readable key the same command line creates the file
    touch "$d/k"; out=$(unset $(compgen -v WT_); PATH=$d/bin:$PATH WEKATESTER_PROMPT_TTY=$d/no-tty \
          bash ./wekatester -r -n -t "$d/new.csv" -i "$d/k" h1 2>&1)
    head -1 "$d/new.csv" | grep -q "^host,user_login" || { echo "control: $out" >&2; exit 1; }
    case "$out" in *"/bin/ssh stub: "*) ;; *) echo "control reached no ssh stub: $out" >&2; false;; esac'
t_assert "validate_credentials runs once: a second call adds no key" bash -c '
    d=$(mktemp -d); touch "$d/k"
    (source ./wekatester; LOCAL_MODE=0; IDENT_RAW=("u:$d/k")
     validate_credentials; validate_credentials
     [ ${#IDENT_KEYS[@]} -eq 1 ] && [ ${#IDENT_LOGINS[@]} -eq 1 ] || { echo "keys ${IDENT_KEYS[*]} logins ${IDENT_LOGINS[*]}" >&2; false; })'
t_assert "targets file: under -r a missing path is created after the 5s default" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
        TARGETS=1; TARGETS_PATH=$d/r.csv; FAST_TRACK=1
        PROMPT_IN_FD=0; PROMPT_OUT_FD=1
        printf "\n" | resolve_targets_file) >>$SUITE_ASIDE 2>&1
    test -f "$d/r.csv"'
t_assert "targets file: bare -t prefers the source set hostfile, else ./hostlist.csv" bash -c '
    d=$(mktemp -d); cd "$d"
    mkdir -p fio-jobfiles/myset
    printf "[global]\n[j]\nrw=read\n" > fio-jobfiles/myset/011-a.job
    printf "host,user_login\nh1,ubuntu\n" > fio-jobfiles/myset/hostlist.csv
    printf "host,user_login\nh1,root\n" > hostlist.csv
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     TARGETS=1; WORKLOAD=myset; resolve_targets_file
     [ "$TARGETS_FILE" = "$d/fio-jobfiles/myset/hostlist.csv" ]) >>$SUITE_ASIDE &&
    (source "$OLDPWD/wekatester"; SCRIPT_DIR=$d
     TARGETS=1; WORKLOAD=nosuchset; resolve_targets_file
     [ "$TARGETS_FILE" = "./hostlist.csv" ]) >>$SUITE_ASIDE'
t_assert "auth rounds: the host file pins a host's login when the credential has none" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; AUTH_DIR=$d/auth; mkdir -p "$AUTH_DIR"
     printf "h1\tubuntu\t-\t-\t-\n" > "$d/targets.phase1"
     attempt_host() { echo "$2:$3" >> "$d/log"; return 0; }
     REMAINING=(h1 h2)
     auth_round "default ssh auth" default "" "" >>$SUITE_ASIDE
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
     WT_ENGINE_TEST_TIMEOUT=1 test_engines) >>$SUITE_ASIDE 2>&1
    took=$(( $(date +%s) - start ))
    grep -qx "localhost hangeng fail" "$d/engine.results" &&
    [ "$took" -lt 60 ]'
t_assert "engines: a working engine's test returns the moment fio exits, well under a second each" bash -c '
    # a poll would sleep a full second per candidate before its first look
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/dest" "$d/bin"
    printf "#!/bin/bash\nexit 0\n" > "$d/bin/fio"; chmod +x "$d/bin/fio"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(localhost); LOCAL_MODE=1; ENGINE=""; AUTO_LEVEL=max
     DIRECTORY=$d/dest; FIO_BIN=$d/bin/fio
     printf "engines io_uring libaio psync\n" > "$d/probe/localhost"
     t0=$(date +%s%N); test_engines >>$SUITE_ASIDE 2>&1 || exit 1; t1=$(date +%s%N)
     ms=$(( (t1 - t0) / 1000000 ))
     [ "$(grep -c " ok$" "$d/engine.results")" = 3 ] || { cat "$d/engine.results" >&2; exit 1; }
     [ "$ms" -lt 1000 ] || { echo "three engine tests took $ms ms" >&2; exit 1; })'
t_assert "engines: a failing job's exit status is a fail; fio's stdout and stderr land in the evidence" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/dest" "$d/bin"
    cat > "$d/bin/fio" <<"EOF"
#!/bin/bash
case "$*" in (*ioengine=broken*) echo "fio: io_u error: Invalid argument" >&2; exit 1;; esac
echo "{\"fio version\": \"stub\"}"
EOF
    chmod +x "$d/bin/fio"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(localhost); LOCAL_MODE=1; ENGINE=""; AUTO_LEVEL=""
        DIRECTORY=$d/dest; FIO_BIN=$d/bin/fio; TARGETS=1; TARGETS_FILE=$d/t.csv
        printf ",,broken,,,,,\n,,libaio,,,,,\n" > "$d/t.csv"
        printf "engines broken libaio\n" > "$d/probe/localhost"
        test_engines) 2>&1 ) || { echo "$out" >&2; exit 1; }
    grep -qx "localhost broken fail" "$d/engine.results" &&
    grep -qx "localhost libaio ok" "$d/engine.results" &&
    grep -qx "fio: io_u error: Invalid argument" "$d/et/localhost.broken.out" &&
    grep -q "fio version" "$d/et/localhost.libaio.out" &&
    case "$out" in
        *"localhost: ioengine broken failed its test job"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "engines: a job ignoring TERM is killed at the timeout bound, recorded as fail and said so in its quoted evidence, its test file gone" bash -c '
    # a silent fio killed by timeout -k once left an empty evidence file,
    # which the operator-facing quote skips
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/dest" "$d/bin"
    cat > "$d/bin/fio" <<"EOF"
#!/bin/bash
for a; do case $a in --filename=*) : > "${a#--filename=}";; esac; done
trap "" TERM; sleep 30
EOF
    chmod +x "$d/bin/fio"
    start=$(date +%s)
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(localhost); LOCAL_MODE=1; ENGINE=stubborn; AUTO_LEVEL=""
        DIRECTORY=$d/dest; FIO_BIN=$d/bin/fio
        printf "engines stubborn\n" > "$d/probe/localhost"
        WT_ENGINE_TEST_TIMEOUT=1 test_engines) 2>&1 )
    took=$(( $(date +%s) - start ))
    # timeout -k 5: TERM at 1 s, KILL at 6 s
    [ "$took" -ge 5 ] && [ "$took" -lt 15 ] || { echo "took $took s" >&2; exit 1; }
    grep -qx "localhost stubborn fail" "$d/engine.results" &&
    grep -qx "fio ignored TERM, killed at 6 s" "$d/et/localhost.stubborn.out" &&
    ! grep -q WEKATESTER_ENGINE_STUCK "$d/et/localhost.stubborn.out" &&
    [ -z "$(ls -A "$d/dest")" ] &&
    case "$out" in
        *"localhost: ioengine stubborn failed its test job"*"fio ignored TERM, killed at 6 s"*"ioengine '\''stubborn'\'' failed its test job on localhost"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "engines: a job alive at the read bound is killed, recorded as fail, its test file gone" bash -c '
    # a timeout(1) that never returns: only the read bound (timeout + 10 s) ends it
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/dest" "$d/bin"
    printf "#!/bin/bash\nexit 0\n" > "$d/bin/fio"
    cat > "$d/bin/timeout" <<"EOF"
#!/bin/bash
for a; do case $a in --filename=*) : > "${a#--filename=}";; esac; done
echo $$ > "${0%/*}/tpid"; trap "" TERM; exec sleep 300
EOF
    chmod +x "$d/bin/fio" "$d/bin/timeout"
    start=$(date +%s)
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(localhost); LOCAL_MODE=1; ENGINE=""; AUTO_LEVEL=""
        DIRECTORY=$d/dest; FIO_BIN=$d/bin/fio; TARGETS=1; TARGETS_FILE=$d/t.csv
        printf ",,libaio,,,,,\n" > "$d/t.csv"
        printf "engines libaio\n" > "$d/probe/localhost"
        PATH=$d/bin:$PATH WT_ENGINE_TEST_TIMEOUT=1 test_engines) 2>&1 )
    took=$(( $(date +%s) - start ))
    [ "$took" -ge 11 ] && [ "$took" -lt 25 ] || { echo "took $took s" >&2; exit 1; }
    # the -9 reached it: exit 124 and the rm happen either way
    tp=$(cat "$d/bin/tpid") || exit 1
    if _o=$(kill -0 "$tp" 2>&1); then echo "the hung timeout $tp outlived the read bound" >&2; kill -9 "$tp"; exit 1; fi
    grep -qx "localhost libaio fail" "$d/engine.results" &&
    ! grep -q WEKATESTER_ENGINE_STUCK "$d/et/localhost.libaio.out" &&
    [ -z "$(ls -A "$d/dest")" ] &&
    case "$out" in
        *"localhost: ioengine libaio failed its test job"*) true;;
        *) echo "$out" >&2; false;;
    esac'
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
        test_engines >>$SUITE_ASIDE 2>&1
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
        test_engines) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"ioengine '\''io_uring'\'' failed its test job on h2"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "engines: under -a a host where no engine passes stops the run, quoting each engine's evidence" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1 h2); AUTO_LEVEL=max; DIRECTORY=/mnt/x; FIO_BIN=fio
        printf "engines io_uring libaio psync\n" > "$d/probe/h1"
        printf "engines io_uring libaio psync\n" > "$d/probe/h2"
        run_host() { case "$1" in (h2) echo "fio: io_u error: Invalid argument"; return 1;; (*) return 0;; esac; }
        test_engines) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected a nonzero exit" >&2; exit 1; }
    case "$err" in
        *"h2: ioengine libaio: fio: io_u error: Invalid argument"*"no ioengine passed its test job on h2 (tried: io_uring libaio psync)"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    grep -q "^engines io_uring libaio psync$" "$d/probe/h1"'
t_assert "finalize: a host-line engine that failed its test dies naming host+evidence" bash -c '
    d=$(mktemp -d); f=$(mktemp)
    printf "h1,,weird_eng,,,,,\n" > "$f"
    printf "h1 weird_eng fail\n" > "$d/engine.results"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); TARGETS=1; TARGETS_FILE=$f
        finalize_targets) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"assigns ioengine '\''weird_eng'\'' to h1 but its test job failed"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "engines: the candidates are read by the CSV reader: quotes, comments and the header as host-file parsing has them" bash -c '
    f=$(mktemp)
    printf "host,user_login,ioengine\n# h0,,\"commented\"\nh1,,\"io_uring\",\"8,10\"\n,,\" libaio \"\n,ubuntu,,,/mnt/x\n" > "$f"
    out=$(source ./wekatester; resolve_targets engines "$f" - - -) || { echo "$out" >&2; exit 1; }
    [ "$out" = "$(printf "io_uring\nlibaio")" ] || { echo "got: $out" >&2; false; }'
t_assert "engines: a quoted host-file ioengine on a host line and a selector line is proven as itself and finalize keeps it" bash -c '
    # a naive comma split kept the quotes: fio knew no "io_uring" and
    # finalize_targets died on the host line
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/dest" "$d/bin"
    printf "#!/bin/bash\nexit 0\n" > "$d/bin/fio"; chmod +x "$d/bin/fio"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(localhost); LOCAL_MODE=1; ENGINE=""; AUTO_LEVEL=""
        DIRECTORY=$d/dest; FIO_BIN=$d/bin/fio; TARGETS=1; TARGETS_FILE=$d/t.csv
        printf "host,user_login,ioengine\nlocalhost,,\"io_uring\",,,,,\n,,\"io_uring\",,,,,\n" > "$d/t.csv"
        printf "engines io_uring libaio\n" > "$d/probe/localhost"
        test_engines && finalize_targets) 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cat "$d/engine.results")" = "localhost io_uring ok" ] &&
    [ "$(cut -f3 "$d/targets.final")" = io_uring ] || { cat "$d/engine.results" "$d/targets.final" >&2; echo "$out" >&2; false; }'
# --- ioengine discovery: -e > host file > the jobfile's own > discovered ---
# A jobfile naming no engine used to run fio's default (psync) silently.
t_assert "discovery: where a jobfile names no engine, each host gets the first of ENGINE_ORDER that passes, logged with the reason" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/set"
    printf "[global]\nioengine=libaio\n[a]\nrw=read\n" > "$d/set/011-a.job"
    printf "[global]\nnumjobs=1\n[b]\nrw=read\n" > "$d/set/012-b.job"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1 h2); ENGINE=""; AUTO_LEVEL=""; DIRECTORY=/mnt/x; FIO_BIN=fio
        SET_DIR_OVERRIDE=$d/set
        printf "engines io_uring libaio psync\n" > "$d/probe/h1"
        printf "engines io_uring libaio psync\n" > "$d/probe/h2"
        run_host() { case "$2" in (*ioengine=*) echo "$1 ${2#*ioengine=}" | cut -d" " -f1,2 >> "$d/ran";; esac
                     case "$1:$2" in (h1:*ioengine=io_uring*) return 1;; (*) return 0;; esac; }
        discover_engines) 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(sort "$d/engine.discovered" | tr "\n" "|")" = "h1 libaio|h2 io_uring|" ] &&
    # the first that passes ends the search: no psync anywhere, no libaio on h2
    [ "$(sort "$d/ran" | tr "\n" "|")" = "h1 io_uring|h1 libaio|h2 io_uring|" ] &&
    case "$out" in
        *"h1: ioengine libaio discovered"*"no ioengine in the host file or the jobfiles"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    # an expected miss is no warning: the WARNING text is for engines asked for
    case "$out" in *WARNING*) echo "$out" >&2; false;; *) true;; esac'
t_assert "discovery: costs nothing when every jobfile names an engine, under -e, and under -a" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/set" "$d/bare"
    printf "[global]\nnumjobs=1\n[a]\nioengine=psync\nrw=read\n" > "$d/set/011-a.job"
    printf "[global]\nnumjobs=1\n[b]\nrw=read\n" > "$d/bare/011-b.job"
    printf "engines io_uring libaio psync\n" > "$d/probe/h1"
    for c in "$d/set||" "$d/bare|libaio|" "$d/bare||max"; do
        IFS="|" read -r set eng lvl <<<"$c"
        (source ./wekatester
         WORK_DIR=$d; HOSTS=(h1); ENGINE=$eng; AUTO_LEVEL=$lvl; DIRECTORY=/mnt/x; FIO_BIN=fio
         SET_DIR_OVERRIDE=$set
         run_host() { echo "$1" >> "$d/ran"; return 0; }
         discover_engines) >>$SUITE_ASIDE 2>&1 || { echo "failed: $c" >&2; exit 1; }
    done
    test ! -e "$d/ran" && test ! -e "$d/engine.discovered"'
t_assert "discovery: a host the host file gives an engine is left alone; one a selector line already proved is not tested again" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/set"
    printf "[global]\nnumjobs=1\n[b]\nrw=read\n" > "$d/set/012-b.job"
    printf "h1\t-\tpsync\t-\t-\nh2\t-\t-\t-\t-\n" > "$d/targets.final"
    printf "h1 io_uring fail\nh2 io_uring fail\n" > "$d/engine.results"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1 h2); ENGINE=""; AUTO_LEVEL=""; DIRECTORY=/mnt/x; FIO_BIN=fio
     SET_DIR_OVERRIDE=$d/set
     printf "engines io_uring libaio psync\n" > "$d/probe/h1"
     printf "engines io_uring libaio psync\n" > "$d/probe/h2"
     run_host() { echo "$1 ${2#*ioengine=}" | cut -d" " -f1,2 >> "$d/ran"; return 0; }
     discover_engines) >>$SUITE_ASIDE 2>&1 || exit 1
    [ "$(cat "$d/engine.discovered")" = "h2 libaio" ] && [ "$(cat "$d/ran")" = "h2 libaio" ]'
t_assert "discovery: a host where no engine passes stops the run, naming it and quoting each test" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/set"
    printf "[global]\nnumjobs=1\n[b]\nrw=read\n" > "$d/set/012-b.job"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1 h2); ENGINE=""; AUTO_LEVEL=""; DIRECTORY=/mnt/x; FIO_BIN=fio
        SET_DIR_OVERRIDE=$d/set
        printf "engines io_uring libaio psync\n" > "$d/probe/h1"
        printf "engines libaio psync\n" > "$d/probe/h2"
        run_host() { case "$1" in (h2) echo "fio: io_u error: Invalid argument"; return 1;; (*) return 0;; esac; }
        discover_engines) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected a nonzero exit" >&2; exit 1; }
    case "$err" in
        *"h2: ioengine io_uring: io_uring: not in this fio"*"h2: ioengine psync: fio: io_u error: Invalid argument"*"no ioengine passed its test job on h2 (tried: io_uring libaio psync)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "discovery: the engine lands only in the host's files naming none; the generated layout follows it" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; DIRECTORY=/mnt/global; HOSTS=(h1 h2); ENGINE=""; mkdir -p "$d/jobs" "$d/set"
     printf "# report bandwidth\n[global]\nfilesize=1G\nnumjobs=1\n[a]\nrw=read\n" > "$d/set/011-a.job"
     printf "# report iops\n[global]\nfilesize=1G\nnumjobs=1\n[b]\nrw=randread\n" > "$d/set/031-b.job"
     printf "# report iops\n[global]\nfilesize=1G\nnumjobs=1\n[c]\nioengine=psync\nrw=randwrite\n" > "$d/set/032-c.job"
     generate_layout "$d/set" "$d/set" >>$SUITE_ASIDE || exit 1
     # psync is the only engine named: the generated layout takes it
     grep -qx "ioengine=psync" "$d/set/000-wekatester-layout.job" || exit 1
     printf "h1 libaio\n" > "$d/engine.discovered"
     stage_variants "$d/set" >>$SUITE_ASIDE 2>&1) || exit 1
    j=$d/jobs/h1
    [ "$(sed -n 3p "$j/011-a.job")" = "ioengine=libaio" ] && grep -qx "ioengine=libaio" "$j/031-b.job" &&
    [ "$(grep -c "^ioengine=" "$j/032-c.job")" = 1 ] && grep -qx "ioengine=psync" "$j/032-c.job" &&
    grep -qx "ioengine=libaio" "$j/000-wekatester-layout.job" &&
    # a host with no discovered engine keeps the set as it is
    ! grep -q "^ioengine=" "$d/jobs/h2/011-a.job" && grep -qx "ioengine=psync" "$d/jobs/h2/000-wekatester-layout.job"'
t_assert "discovery: main runs it after the host-file engines and before pinning and staging, dry runs included" bash -c '
    m=$(sed -n "/^main() {/,/^}/p" ./wekatester)
    dry=$(printf "%s\n" "$m" | sed -n "/if \[ \"\$DRY_RUN\" -eq 1 \]; then/,/exit 0/p")
    printf "%s\n" "$dry" | awk "/finalize_targets/ {f = NR} /discover_engines/ {e = NR} /check_cpu_pinning/ {p = NR} END {exit !(f && e > f && p > e)}" &&
    printf "%s\n" "$m" | awk "/exit 0/ {x = NR} x && /finalize_targets/ {f = NR} x && /discover_engines/ {e = NR} x && /stage_jobfiles/ {s = NR} END {exit !(f && e > f && s > e)}"'
t_assert "pinning: cpus outside the taskset with no escalator dies showing all three" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; mkdir -p "$d/auth"
        # 4-7 bind only in another cgroup, and no escalator reaches it
        printf "taskset 0-3\nbindable 0-3\nbindable_priv 4-15\nweka_allowed 8\nweka_allowed 9\nweka_allowed 0-15\n" > "$d/probe/h1"
        printf "h1\t-\t-\t4-7\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"effective cpus_allowed: 4-7 (requested: 4-7)"*"current taskset:        0-3"*"weka dedicated cores:   8,9"*"outside the current taskset"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# The failure this exists to prevent (field client C, 2026-09-09): a cpu that
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
        *"note: h1: requested cpus (0-7) include 3,5, which this host refuses to bind"*"cgroup"*"executing on the remainder (1-2,4,6-7)"*"keeps the list as written"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "1-2,4,6-7" ] &&
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
    [ "$(cat "$d/auth/h1.cpus")" = "1-7" ] &&
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
        check_cpu_pinning) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in
        *"effective cpus_allowed: 1-7"*"current taskset:        0-3"*"outside the current taskset and no passwordless escalator"*) true;;
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
        check_cpu_pinning) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in
        *"no requested cpu (4,5) is usable"*"or one it refuses to bind (4-5)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# Without the measurement nothing is assumed (Frank, 2026-10-11): the old
# rule called isolated cpus self-affinable and pinned 1-7 here.
t_assert "pinning: without a bindable line the check fails naming the host, never assumes isolated cpus bind" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 8
taskset 0-1
isolated 2-7
" > "$d/probe/h1"
        printf "h1	-	-	0-7	-
" > "$d/targets.final"
        check_cpu_pinning) 2>&1 ) && { echo "pinned without a measurement: $out" >&2; exit 1; }
    case "$out" in *"h1: the probe has no bindable line"*) true;; *) echo "$out" >&2; false;; esac &&
    [ ! -f "$d/auth/h1.cpus" ] && [ ! -f "$d/auth/h1.priv" ]'
t_assert "pinning: full weka overlap dies; partial runs on the remainder, file untouched" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "taskset 0-15\nbindable 0-15\nbindable_priv -\nweka_allowed 8\nweka_allowed 10\nweka_allowed 0-15\n" > "$d/probe/h1"
        printf "h1\t-\t-\t8,10\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >>$SUITE_ASIDE )
    case "$err" in (*"every requested cpu (8,10) is a weka dedicated core"*) true;; (*) echo "$err" >&2; exit 1;; esac
    out2=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "taskset 0-15\nbindable 0-15\nbindable_priv -\nweka_allowed 8\nweka_allowed 10\npriv sudo\n" > "$d/probe/h1"
        printf "h1\t-\t-\t8,10,12\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 )
    case "$out2" in (*"note"*"overlap weka'\''s dedicated cores (8,10)"*"executing on the remainder (12)"*) true;; (*) echo "$out2" >&2; exit 1;; esac
    test ! -s "$d/auth/h1.priv" && [ "$(cat "$d/auth/h1.cpus")" = "12" ]'
t_assert "pinning: an in-mask request with no escalator records cpus and proceeds" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
     printf "taskset 0-15\nbindable 0-15\nbindable_priv -\nweka_allowed 20\nweka_allowed 0-15\n" > "$d/probe/h1"
     printf "h1\t-\t-\t4-7\t-\n" > "$d/targets.final"
     check_cpu_pinning)
    [ "$(cat "$d/auth/h1.cpus")" = "4-7" ] && test ! -s "$d/auth/h1.priv"'
# A cpu the host does not have would be rejected by fio -- on the SERVER,
# whose error text is lost, so the run dies later with "the jobs did not
# run" and no evidence (field client B 2026-08-28: host file said 0-128 on a 64-cpu
# box). Trimmed at row resolution with a note naming them, same contract as
# the weka overlap: the host file keeps the list as written.
t_assert "pinning: cpus the host does not have are trimmed with a note, file untouched" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 64\ntaskset 0-63\nbindable 0-63\nbindable_priv -\nweka_allowed 52\nweka_allowed 53\n" > "$d/probe/h1"
        printf "h1\t-\t-\t0-128\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 )
    case "$out" in
        *"note"*"cpus this host does not have (64-128; the host has 64 cpus: 0-63); executing on the remainder (1-51,54-63)"*) true;;
        *) echo "$out" >&2; exit 1;;
    esac && [ "$(cat "$d/auth/h1.cpus")" = "1-51,54-63" ]'
t_assert "pinning: a list with no real cpu at all still dies" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    err=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
        printf "ncpus 64\ntaskset 0-63\nbindable 0-63\nbindable_priv -\n" > "$d/probe/h1"
        printf "h1\t-\t-\t100-128\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"no requested cpu (100-128) is usable"*"(100-128; the host has 64 cpus: 0-63)"*) true;;
        *) echo "$err" >&2; exit 1;;
    esac && test ! -f "$d/auth/h1.cpus"'
t_assert "pinning: a valid list on a probed host still proceeds" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
     printf "ncpus 16\ntaskset 0-15\nbindable 0-15\nbindable_priv -\n" > "$d/probe/h1"
     printf "h1\t-\t-\t4-7\t-\n" > "$d/targets.final"
     check_cpu_pinning)
    [ "$(cat "$d/auth/h1.cpus")" = "4-7" ]'
# Bugbot "Spaced CPU lists break pinning": a quoted host-file cell keeps its
# blank, and the verdict split on blanks recorded weka's core (9) instead.
t_assert "pinning: a spaced list records the same cpus as the unspaced one" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    printf "ncpus 16\ntaskset 0-15\nbindable 0-15\nbindable_priv -\nweka_allowed 9\n" > "$d/probe/h1"
    for req in "2-5,7" "2-5, 7"; do
        printf "h1\t-\t-\t%s\t-\n" "$req" > "$d/targets.final"
        (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; check_cpu_pinning) >>$SUITE_ASIDE 2>&1 || exit 1
        [ "$(cat "$d/auth/h1.cpus")" = "2-5,7" ] || { echo "$req: $(cat "$d/auth/h1.cpus")" >&2; exit 1; }
    done'
t_assert "pinning: a spaced list needing the escalator records cpus and the escalator" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    printf "ncpus 16\ntaskset 0-3\nbindable 0-3\nbindable_priv 4-15\nweka_allowed 9\npriv sudo -n\n" > "$d/probe/h1"
    printf "h1\t-\t-\t2-5, 10\t-\n" > "$d/targets.final"
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; check_cpu_pinning) >>$SUITE_ASIDE 2>&1 || exit 1
    [ "$(cat "$d/auth/h1.cpus")" = "2-5,10" ] && [ "$(cat "$d/auth/h1.priv")" = "sudo -n" ]'
t_assert "pinning: a spaced list overlapping weka trims it and says so" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    printf "ncpus 16\ntaskset 0-15\nbindable 0-15\nbindable_priv -\nweka_allowed 9\n" > "$d/probe/h1"
    printf "h1\t-\t-\t8-10, 12\t-\n" > "$d/targets.final"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    case "$out" in (*"requested cpus (8-10,12) overlap weka'\''s dedicated cores (9); executing on the remainder (8,10,12)"*) true;; (*) echo "$out" >&2; exit 1;; esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "8,10,12" ]'
# The postmortem for a seed whose jobs did not run: a server-side rejection
# reaches the coordinator as "<host> ..." lines (fio 3.28 exits 1), and
# cal_evidence also asks the host fio to re-parse the jobfile -- a dirty parse
# is surfaced verbatim, a clean one says the death was at setup, and both land
# in the bundle.
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
    # the fio --client exit-nonzero path (the 05:17 field client C seed death)
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
t_assert "ere_quote_v: the regex matches its own text exactly, ERE metacharacters and all" bash -c '
    s="/opt/fio-3.38+git/b.in/[x](y){2}|z^q\$w*v?u\\t"
    q=$(source ./wekatester; ere_quote_v "$s"; printf "%s" "$ERE_QUOTED")
    printf "%s\n" "$s" | grep -Eqx "$q" &&
    ! printf "%s\n" "${s/b.in/bXin}" | grep -Eqx "$q" || { echo "string $s, regex $q" >&2; false; }'
t_assert "fio server kill: the pidfile pid gets the TERM only while it is our server, and a path with regex characters still drains" bash -c '
    d=$(mktemp -d); b="$d/fio+1.2[x]"; mkdir -p "$b"; cp "$(type -P sleep)" "$b/fio"; pf=$d/fio.pid; bad=0
    cat > "$d/srv" <<"SRV"
#!/bin/bash
# srv <args0> <binary> [ignore-term]: <binary> as a process whose args read "<args0> 300"
[ -z "${3:-}" ] || trap "" TERM
exec -a "$1" "$2" 300
SRV
    chmod +x "$d/srv"
    cmd=$(source ./wekatester; FIO_BIN=$b/fio; FIO_PIDFILE=$pf; kill_fio_cmd_v; printf "%s" "$KILL_FIO_CMD")
    # each fake is orphaned at once: init reaps it, and no job notice prints
    start() { "$d/srv" "$b/fio --server --daemonize=$pf" "$b/fio" "$@" >>"$SUITE_ASIDE" 2>&1 & echo $!; }
    alive() { [ -n "$(ps -o pid= -p "$1")" ]; }
    p=$(start); q=$(sleep 300 >>"$SUITE_ASIDE" 2>&1 & echo $!); echo "$p" > "$pf"; sleep 0.3
    bash -c "$cmd" >>"$SUITE_ASIDE" 2>&1; sleep 0.3
    if alive "$p" || [ -e "$pf" ]; then echo "our server or its pidfile outlived the kill" >&2; bad=1; fi
    echo "$q" > "$pf"; bash -c "$cmd" >>"$SUITE_ASIDE" 2>&1; sleep 0.3
    alive "$q" || { echo "a stale pidfile got an unrelated process killed" >&2; bad=1; }
    kill -9 "$p" "$q" >>"$SUITE_ASIDE" 2>&1
    p=$(start ignore); echo "$p" > "$pf"; sleep 0.3
    bash -c "$cmd" >>"$SUITE_ASIDE" 2>&1; sleep 0.3
    if alive "$p"; then echo "a server that ignores TERM outlived the -9" >&2; kill -9 "$p" >>"$SUITE_ASIDE" 2>&1; bad=1; fi
    exit "$bad"'
t_assert "server launch: priv pins via taskset but fio drops to the login user" bash -c '
    d=$(mktemp -d); mkdir -p "$d/auth"
    printf "sudo -n\n" > "$d/auth/h1.priv"; printf "4-7\n" > "$d/auth/h1.cpus"
    printf "8-9\n" > "$d/auth/h3.cpus"
    (source ./wekatester
     WORK_DIR=$d; AUTH_DIR=$d/auth; HOSTS=(h1 h2 h3); FIO_BIN=fio
     WT_SETTLE=0
     run_host() { echo "LAUNCH[$1]: $2"; }
     start_fio_servers) >>$SUITE_ASIDE 2>&1
    grep -q "sudo -n runuser -u .* -- true" "$d/launch.h1" &&
    grep -q "sudo -n taskset -c 4-7 runuser -u .* -- '\''fio'\'' --server" "$d/launch.h1" &&
    grep -q "WEKATESTER_FIO_AS=root; sudo -n taskset -c 4-7 '\''fio'\'' --server" "$d/launch.h1" &&
    grep -q "LAUNCH\[h2\]" "$d/launch.h2" && ! grep -q taskset "$d/launch.h2" &&
    grep -q "taskset -c 8-9 '\''fio'\''" "$d/launch.h3" && ! grep -q runuser "$d/launch.h3"'
# What the launch prints before fio forks reaches the log tagged with its
# host, and stays out of the stdout the root NOTE reads (issue #18).
t_assert "server launch: a launch error is tagged with its host, the run stops naming it, and stdout stays the NOTE's alone" bash -c '
    d=$(mktemp -d); mkdir -p "$d/auth"
    err=$( (source ./wekatester
            WORK_DIR=$d; AUTH_DIR=$d/auth; HOSTS=(h1 h2); FIO_BIN=fio; FIO_PIDFILE=/dev/shm/x.pid; WT_SETTLE=0
            run_host() { if [ "$1" = h1 ]; then echo "fio: pidfile /dev/shm/x.pid exists and server appears alive" >&2; return 1; fi
                         echo WEKATESTER_FIO_AS=root; echo "taskset: a warning" >&2; }
            start_fio_servers) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in
        (*" h1: fio: pidfile /dev/shm/x.pid exists and server appears alive"*" h2: taskset: a warning"*"NOTE: h2: fio runs as root"*"failed to start fio server on: h1") true;;
        (*) echo "$err" >&2; false;;
    esac &&
    ! grep -q "taskset: a warning" "$d/launch.h2" || { echo "launch.h2: $(cat "$d/launch.h2")" >&2; false; }'
t_assert "server launch, run for real: with runuser fio drops to the login user, without it fio runs as root" bash -c '
    d=$(mktemp -d); b=$d/bin; mkdir -p "$b" "$d/auth"
    printf "sudo -n\n" > "$d/auth/h1.priv"; printf "4-7\n" > "$d/auth/h1.cpus"
    for c in cat id pgrep ps rm sleep true; do p=$(type -P "$c") || { echo "no $c on this host" >&2; exit 1; }; ln -s "$p" "$b/$c"; done
    # sudo, taskset and runuser pass straight through to the command; fio says how it was run
    printf "#!/bin/sh\n[ \"\$1\" != -n ] || shift\nexec \"\$@\"\n" > "$b/sudo"
    printf "#!/bin/sh\nshift 2\nexec \"\$@\"\n" > "$b/taskset"
    printf "#!/bin/sh\nshift 3\nexec \"\$@\"\n" > "$b/runuser"
    printf "#!/bin/sh\necho \"fio ran: \$*\"\n" > "$b/fio"
    chmod +x "$b/sudo" "$b/taskset" "$b/runuser" "$b/fio"
    (source ./wekatester; WORK_DIR=$d; AUTH_DIR=$d/auth; HOSTS=(h1); FIO_BIN=fio; FIO_PIDFILE=$d/fio.pid; WT_SETTLE=0
     run_host() { printf "%s" "$2" > "$d/cmd.$1"; }
     start_fio_servers) >>"$SUITE_ASIDE" 2>&1
    [ -s "$d/cmd.h1" ] || { echo "no launch string captured" >&2; exit 1; }
    bash=$(type -P bash)
    u=$(PATH=$b "$bash" -c "$(cat "$d/cmd.h1")" 2>&1)
    mv "$b/runuser" "$d/runuser.off"; r=$(PATH=$b "$bash" -c "$(cat "$d/cmd.h1")" 2>&1); mv "$d/runuser.off" "$b/runuser"
    case "$u" in *"WEKATESTER_FIO_AS=user"*"fio ran: --server --daemonize=$d/fio.pid"*) ;; *) echo "with runuser: $u" >&2; exit 1;; esac
    case "$r" in *"WEKATESTER_FIO_AS=root"*"fio ran: --server --daemonize=$d/fio.pid"*) ;; *) echo "no runuser: $r" >&2; exit 1;; esac'

# --- host files: per-host application to staging ---
t_assert "plain staging: host-file dir/geometry/engine land per host, layout re-derived" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; DIRECTORY=/mnt/global; HOSTS=(h1 h2); mkdir -p "$d/jobs" "$d/set"
     printf "# report iops\n[global]\nfilename_format=x/\$jobnum\ndirectory=/orig\nfilesize=10G\nnumjobs=32\nioengine=libaio\n[j]\nrw=randread\niodepth=8\n" > "$d/set/031-i.job"
     (source ./wekatester; generate_layout "$d/set" "$d/set") >>$SUITE_ASIDE
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
# Plain staging writes the host file nrfiles too, so it extends the format as
# -a does; a jobfile's own nrfiles stays the operator's.
t_assert "plain staging: a host-file nrfiles 2 on x/\$jobnum stages x/\$jobnum.\$filenum in the job and layout; the host without a row and a jobfile's own nrfiles keep theirs" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; DIRECTORY=/mnt/global; HOSTS=(h1 h2); mkdir -p "$d/jobs" "$d/set"
     printf "# report iops\n[global]\nfilename_format=x/\$jobnum\ndirectory=/orig\nfilesize=10G\nnumjobs=32\nioengine=libaio\n[j]\nrw=randread\niodepth=8\n" > "$d/set/031-i.job"
     printf "# report bandwidth\n[global]\nfilename_format=y/\$jobnum\nnrfiles=3\ndirectory=/orig\nfilesize=1G\nnumjobs=2\nioengine=libaio\n[b]\nrw=read\n" > "$d/set/011-b.job"
     (source ./wekatester; generate_layout "$d/set" "$d/set") >>$SUITE_ASIDE
     { printf "h1\t-\t-\t-\t-"
       for i in $(seq 6 37); do
          case $i in (22) printf "\t4";; (23) printf "\t1G";; (24) printf "\t2";;
                     (25) printf "\t16";; (*) printf "\t-";; esac
       done; printf "\n"
       printf "h2"; for i in $(seq 2 37); do printf "\t-"; done; printf "\n"
     } > "$d/targets.final"
     stage_variants "$d/set") 2>"$d/err" >>$SUITE_ASIDE || { cat "$d/err" >&2; exit 1; }
    has() { [ "$(grep -c "^filename_format=" "$d/jobs/$1")" = 1 ] && grep -qxF "filename_format=$2" "$d/jobs/$1" || { echo "$1 wants $2:" >&2; cat "$d/jobs/$1" >&2; false; }; }
    has h1/031-i.job "x/\$jobnum.\$filenum" && has h2/031-i.job "x/\$jobnum" &&
    has h1/011-b.job "y/\$jobnum" && has h2/011-b.job "y/\$jobnum" &&
    grep -qxF "filename_format=x/\$jobnum.\$filenum" "$d/jobs/h1/000-wekatester-layout.job" &&
    grep -qxF "filename_format=y/\$jobnum" "$d/jobs/h1/000-wekatester-layout.job" &&
    [ "$(grep -c "has no \$filenum" "$d/err")" = 1 ] || { cat "$d/jobs/h1/000-wekatester-layout.job" "$d/err" >&2; false; }'
t_assert "tuner: host-file dir/cpus/geometry/engine land per host; a host without a row keeps the jobfile values" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    { printf "h1\t-\tpsync\t2,4\t/mnt/pin\t3\t2G\t-\t9"
      for i in $(seq 10 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
    v1="$FIX/jobs/h1/011-bw.job"; v2="$FIX/jobs/h2/011-bw.job"
    grep -q "^directory=/mnt/pin$" "$v1" && grep -q "^directory=/mnt/weka$" "$v2" &&
    # the host file keeps the operator spelling "2,4"; the STAGED job declares
    # what actually executes: weka owns 5-7 and core 0 is the OS, so 2 and 4
    # survive -- the same effective set the calibration ladder measures
    grep -q "^cpus_allowed=2,4$" "$v1" &&
    grep -q "^numjobs=3$" "$v1" && grep -q "^filesize=2G$" "$v1" && grep -q "^iodepth=9$" "$v1" &&
    grep -q "^ioengine=psync$" "$v1" && grep -q "^ioengine=libaio$" "$v2"'
# The STAGED jobs must never name a cpu the host does not have: the fio
# SERVER rejects the jobfile and its error text is lost, so the layout dies
# with "the jobs did not run" and nothing else (field client B 2026-08-28 -- the
# cal ladders ran on the trimmed auth/<host>.cpus while the staged variants
# still carried the host file's phantoms).
t_assert "tuner: staged cpus_allowed drops cpus the host does not have" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    { printf "h1\t-\t-\t2,4,9-12\t-"
      for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
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
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    grep -q "^# superseded by -a: h1,,psync" "$f" &&
    tail -1 "$f" | grep -q "^h1,ubuntu,psync,0-3,/mnt/w,,,,,/1G/8/32,$" &&
    (source ./wekatester; resolve_targets phase1 "$f" - - - h1 >>$SUITE_ASIDE)'
t_assert "writeback: nothing to record leaves the file untouched" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "h1,ubuntu,libaio,0-3,/mnt/w,,,,,4/1G/8/32,\n" > "$f"
    before=$(cat "$f")
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    [ "$(cat "$f")" = "$before" ]'
t_assert "writeback: -g overwrites without a prompt, but never login or allowed_cpus" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "h1,opc,psync,9-11,,,,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; REGEN_LAYOUT=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    tail -1 "$f" | grep -q "^h1,opc,libaio,9-11,/mnt/w,,,,,/1G/8/32,$"'
# The layout job sorts first, so before it carried the marker its engine,
# cpu list and directory won the record. It records nothing now; the cpu
# list is the tuner's usable list, which no single job names whole.
t_assert "writeback: the layout records nothing; the cpu list is the tuner's usable list, not one job's subset" bash -c '
    d=$(wb_fixture); f="$d/host.csv"; mkdir -p "$d/usable"
    printf "# wekatester-layout: generated (re-derived)\n[global]\ndirectory=/mnt/elsewhere\ncpus_allowed=0-7\nioengine=psync\n[layout-1]\ncreate_only=1\n" \
        > "$d/jobs/h1/000-wekatester-layout.job"
    printf "0-5\n" > "$d/usable/h1"
    printf "host,user_login,ioengine\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-5,/mnt/w," || { tail -1 "$f" >&2; false; }'

t_assert "settings: the -a writeback leaves settings lines byte-identical" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "host,user_login,ioengine\nWT_WORKLOAD=default\n\"WT_IDENTITY=a.pem,b.pem\"\nh1,,psync,,,,,\n" > "$f"
    before=$(sed -n 2,3p "$f")
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }
     writeback_targets) >>$SUITE_ASIDE
    [ "$(sed -n 2,3p "$f")" = "$before" ] && grep -q "^# superseded by -a: h1,,psync" "$f" || { cat "$f" >&2; false; }'
# A pattern row is a host line for what it matches but never the host's
# own: its values differ here from what ran, and the new line records what
# ran (as for a generic row below).
t_assert "writeback: glob and * rows stay byte-identical; the matched host gets its own new line" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "host,user_login,ioengine,allowed_cpus,destination_folder\nh*,ubuntu,psync,0-1,/mnt/g,,,,,,\n*,root,psync,,,,,,,,\n" > "$f"
    before=$(sed -n 2,3p "$f")
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    [ "$(sed -n 2,3p "$f")" = "$before" ] && [ "$(wc -l < "$f")" -eq 4 ] &&
    ! grep -q "superseded" "$f" &&
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'

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
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    [ "$(sed -n 2p "$f")" = ",,,0-127,,,,,,," ] &&
    ! grep -q "superseded" "$f" &&
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'
t_assert "writeback: generic engine and dir are defaults too; the host line records the proven and resolved ones" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf ",,psync,0-127,/mnt/g,,,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    [ "$(sed -n 1p "$f")" = ",,psync,0-127,/mnt/g,,,,,," ] &&
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'
t_assert "writeback: a host row beside a generic one keeps its own cpu list; the generic row is untouched" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf ",,,0-127,,,,,,,\nh1,opc,,9-11,,,,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; REGEN_LAYOUT=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    [ "$(sed -n 1p "$f")" = ",,,0-127,,,,,,," ] &&
    grep -q "^# superseded by -a: h1,opc,,9-11" "$f" &&
    tail -1 "$f" | grep -q "^h1,opc,libaio,9-11,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'
t_assert "writeback: a cpu list that differs from the generic one is reason enough for a host line" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf ",ubuntu,libaio,0-127,/mnt/w,,,,,/1G/8/32,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    [ "$(sed -n 1p "$f")" = ",ubuntu,libaio,0-127,/mnt/w,,,,,/1G/8/32," ] &&
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1G/8/32,$" ||
        { cat "$f" >&2; false; }'
# The writeback reads the directive through report_has, as staging does:
# every spelling the README accepts fills its slot, and prose does not.
wb_directive() {   # wb_directive <directive line>: the host line it records
    d=$(wb_fixture); f="$d/host.csv"; printf "host,user_login,ioengine\n" > "$f"
    printf "%s\ncpus_allowed=0-3\ndirectory=/mnt/w\nioengine=libaio\nnumjobs=4\nfilesize=1G\nnrfiles=8\niodepth=32\nrw=randread\n" "$1" > "$d/jobs/h1/031-i.job"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    tail -1 "$f"
}
export -f wb_directive
t_assert "writeback: #report iops and #  report iops fill the iops slot" bash -c '
    for s in "#report iops" "#  report iops"; do
        got=$(wb_directive "$s")
        [ "$got" = "h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1G/8/32," ] || { echo "$s: $got" >&2; exit 1; }
    done'
t_assert "writeback: prose (# reporting notes: iops) is no directive and fills no slot" bash -c '
    got=$(wb_directive "# reporting notes: iops")
    [ "$got" = "h1,ubuntu,libaio,0-3,/mnt/w,,,,,," ] || { echo "$got" >&2; false; }'
t_assert "resolve_targets: hostonly sees the host row and nothing generic; phase1 still folds generics in" bash -c '
    d=$(mktemp -d)
    printf "host,user_login,ioengine,allowed_cpus,destination_folder\n,,,0-127,/mnt/g,,,,,,\nh2,,,4-15,,,,,,,\n" > "$d/hl.csv"
    (source ./wekatester; WORK_DIR=$d
     ho=$(resolve_targets hostonly "$d/hl.csv" - - - h1 h2)
     p1=$(resolve_targets phase1 "$d/hl.csv" - - - h1 h2)
     col() { printf "%s\n" "$1" | grep "^$2	" | cut -f4,5 | tr "\t" " "; }
     [ "$(col "$ho" h1)" = "- -" ] && [ "$(col "$ho" h2)" = "4-15 -" ] &&
     [ "$(col "$p1" h1)" = "0-127 /mnt/g" ] && [ "$(col "$p1" h2)" = "4-15 /mnt/g" ])'
# A trailing slash doubled every "$hd/$glob" join, which find never prints:
# both entry points drop it once, so no join has to.
t_assert "destinations lose trailing slashes where they enter: -d /x/ and a host-file /x// are /x; / stays /" bash -c '
    d=$(mktemp -d)
    printf "host,user_login,ioengine,allowed_cpus,destination_folder\nh1,,,,/x//\nh2,,,,//\n" > "$d/hl.csv"
    (source ./wekatester; WORK_DIR=$d
     parse_args -d /x/ h1; [ "$DIRECTORY" = /x ] || { echo "-d /x/: $DIRECTORY" >&2; exit 1; }
     parse_args -d=/ h1; [ "$DIRECTORY" = / ] || { echo "-d=/: $DIRECTORY" >&2; exit 1; }
     out=$(resolve_targets phase1 "$d/hl.csv" - - - h1 h2 | cut -f1,5 | tr "\t\n" " ;")
     [ "$out" = "h1 /x;h2 /;" ] || { echo "host file: $out" >&2; false; })'
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
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
    tail -1 "$f" | grep -q "^h1,ubuntu,libaio,0-3,/mnt/w,4/1024M/2/32,2/1024M/2/4,,,,$" ||
        { tail -1 "$f" >&2; false; }'
t_assert "writeback: with --line-rate a measured bandwidth tuple replaces the host row, even in fill mode; nothing else does" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs/h1" "$d/auth"
    printf "ubuntu\n" > "$d/auth/h1.user"
    printf "# report bandwidth\ncpus_allowed=0-3\ndirectory=/mnt/w\nioengine=libaio\nnumjobs=4\nfilesize=5120M\nnrfiles=1\niodepth=1\nrw=read\n" > "$d/jobs/h1/011-b.job"
    : > "$d/engine.results"
    # measured (qd nr fs nj): bw_r 2 jobs at qd1 nrfiles 1, iops_r 10 jobs x 16
    printf "h1 libaio 1 1 5120M 2 - - - - - - - - - - - - 16 1 5120M 10 - - - - - - - - - - - -\n" > "$d/cal.results"
    f="$d/host.csv"
    run() { printf "h1,ubuntu,libaio,0-3,/mnt/w,9/5120M/1/1,,,,3/5120M/1/64,\n" > "$f"
            (source ./wekatester
             WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=cal; TARGETS_FILE=$f; FAST_TRACK=1; LINE_RATE_GBPS=$1
             host_machine_id() { :; }   # no ssh to a fixture host
             writeback_targets) >>$SUITE_ASIDE; }
    run 16 && [ "$(tail -1 "$f")" = "h1,ubuntu,libaio,0-3,/mnt/w,2/5120M/1/1,,,,3/5120M/1/64," ] ||
        { tail -1 "$f" >&2; exit 1; }
    run "" && [ "$(cat "$f")" = "h1,ubuntu,libaio,0-3,/mnt/w,9/5120M/1/1,,,,3/5120M/1/64," ] ||
        { cat "$f" >&2; false; }'

# The seam that broke on field client A (2026-08-24): calibrate writes cal.results
# and TWO parsers read it -- apply_cal_results and the writeback. They must
# accept the same width, and the cheapest proof is a row from the shared
# layer's own constants going through both.
t_assert "cal.results: one width, both parsers accept what the shared layer defines" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs" "$d/auth"
    row=$(source ./wekatester; r="h1 libaio"; for s in $GEOM_SLOTS; do r="$r 4 2 1024M 3"; done; echo "$r")
    printf "%s\n" "$row" > "$d/cal.results"
    : > "$d/engine.results"
    # parser 1: apply_cal_results
    (source ./wekatester; WORK_DIR=$d; REGEN_LAYOUT=0; apply_cal_results) ||
        { echo "apply_cal_results rejected: $row" >&2; false; }
    # parser 2: the writeback
    f="$d/host.csv"; printf "host,user_login,ioengine\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=cal; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE ||
        { echo "writeback rejected: $row" >&2; false; }
    tail -1 "$f" | grep -q "^h1,"'

t_assert "tuner: an unbindable cpu never reaches a staged cpus_allowed" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    for h in h1 h2; do
        sed -i.b "s/^bindable 0-7\$/bindable 0,1,2,4,6,7/" "$FIX/probe/$h"; printf "online 0-7\n" >> "$FIX/probe/$h"
    done
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1
    # weka owns 5-7 and the OS 0-1, so 2-4 was usable; 3 refuses the bind
    grep -q "^cpus_allowed=2,4$" "$FIX/jobs/h1/011-bw.job" ||
        { grep "^cpus_allowed=" "$FIX/jobs/h1/011-bw.job" >&2; false; }'
t_assert "tuner: a host-file cpu list is narrowed by the measurement too" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    for h in h1 h2; do
        sed -i.b "s/^bindable 0-7\$/bindable 0,1,2,4,6,7/" "$FIX/probe/$h"; printf "online 0-7\n" >> "$FIX/probe/$h"
    done
    { printf "h1\t-\t-\t2-5\t-"
      for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
    # asked for 2-5: 5 is weka'"'"'s, 3 refuses the bind, 2 and 4 are left
    grep -q "^cpus_allowed=2,4$" "$FIX/jobs/h1/011-bw.job" ||
        { grep "^cpus_allowed=" "$FIX/jobs/h1/011-bw.job" >&2; false; }'

# --- isolcpus awareness (field client A: isolcpus=domain,4-55) ---
t_assert "tuner: isolcpus does not narrow cpus_allowed; only weka is excluded" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "isolated 4-7\n" >> "$FIX/probe/h1"
    printf "isolated 4-7\n" >> "$FIX/probe/h2"
    out=$( (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >>$SUITE_ASIDE )
    grep -q "^cpus_allowed=2-4$" "$FIX/jobs/h1/011-bw.job" &&
    case "$out" in *"span isolated and housekeeping"*) true;; *) echo "$out" >&2; false;; esac'
# The pin detection is now the ONLY thing keeping fio off weka's cores, so a
# detection that comes back empty while weka is running has to be audible.
t_assert "tuner: weka running with no pinned cores found warns loudly" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nwekanode 4\nbindable 0-7\nbindable_priv -\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    printf "ncpus 8\nwekanode 4\nbindable 0-7\nbindable_priv -\nengines io_uring libaio psync \n" > "$FIX/probe/h2"
    out=$( (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >>$SUITE_ASIDE )
    case "$out" in
        *"wekanode process(es) running but no pinned cores detected"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "tuner: no weka on the host is silent, not a warning" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nwekanode 0\nbindable 0-7\nbindable_priv -\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    printf "ncpus 8\nwekanode 0\nbindable 0-7\nbindable_priv -\nengines io_uring libaio psync \n" > "$FIX/probe/h2"
    out=$( (source ./wekatester
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 >>$SUITE_ASIDE )
    case "$out" in
        *"no pinned cores detected"*) echo "$out" >&2; false;;
        *) grep -q "^cpus_allowed=2-7$" "$FIX/jobs/h1/011-bw.job";;
    esac'
# Field regression (field client A, 2026-08-21): weka owned cores 14-27 by its own
# core_id list, but the probe scanned /proc/<pid>/task/*/status and unioned
# every single-cpu THREAD mask, reporting 4-27 -- so an operator asking for
# 4-13,28-55 silently lost 4-13 to ten cores weka does not own. The probe
# reads per-process masks now; one wekanode process owns one core.
t_assert "pinning: only the cores weka's node processes own are excluded (field client A)" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    { printf "ncpus 56\nwekanode 15\ntaskset 0-55\nisolated 4-55\nbindable 0-55\nbindable_priv -\n"
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
t_assert "schema: one spelling of the fields, the slot columns and the direction rule" bash -c '
    source ./wekatester
    a=$(awkrun "BEGIN { n = split(geom_slots(), S, \" \"); print 4 + 4 * n, field_col(\"bw_r_nj\"), field_col(\"iops_w_nj\"), field_col(\"lat1m_w_qd\"), n, 2 + 4 * n }") &&
    [ "$a" = "36 6 26 37 8 34" ] &&
    [ "$GEOM_SLOTS" = "bw_r bw_w lat_r lat_w iops_r iops_w lat1m_r lat1m_w" ] &&
    d=$(mktemp -d) && write_targets_template "$d/t.csv" >>$SUITE_ASIDE &&
    head -1 "$d/t.csv" | grep -q "^host,user_login,ioengine,allowed_cpus,destination_folder,bandwidthR:nj/fs/nr/qd,bandwidthW:nj/fs/nr/qd,latencyR:nj/fs/nr/qd,latencyW:nj/fs/nr/qd,iopsR:nj/fs/nr/qd,iopsW:nj/fs/nr/qd,latency1mR:nj/fs/nr/qd,latency1mW:nj/fs/nr/qd$" &&
    b=$(awkrun "BEGIN { L[1] = \"[x]\"; L[2] = \"rw=randrw:8\"; file_directions(L, 2, D); print ((\"read\" in D) ? \"read\" : \"-\"), ((\"write\" in D) ? \"write\" : \"-\") }") &&
    [ "$b" = "read write" ]'
# The jobfile rules, held to the answers the python gave them before it went
# (tests/golden/jobfile-rules.txt), input for input. One answer differs since
# jf_key: e's "filename_format= y" reads y, as fio reads it (python skipped
# it for z). h-k came later: a create_only section's rw= (own or [global]'s)
# is no direction unless no measured section is left.
t_assert "jobfile rules: parse_size, first_value, last_section, job_bs, lat_kind, file_directions, pick_slot and pick_engine give the recorded answers" bash -c '
    d=$(mktemp -d)
    printf "# report latency\n[global]\nbs=4k\nrw=randread\n[lat]\nbs=1M\n" > "$d/a"
    printf "[global]\nrw=randrw:8\nblocksize=1Mi,4k\n[x]\n[y]\nrw=write\n" > "$d/b"
    printf "[ global ]\nreadwrite=READ\n[j] \nbs=64k:1M\nfilename_format=\$filenum/\$jobnum\nfilename_format=x\n" > "$d/c"
    printf "rw=trim\nbs=x\nfilename_format= y\nfilename_format=z w\n" > "$d/e"
    printf "\n" > "$d/f"
    printf "[a]]\nrw=rw\n[b]x\nbs=2M\n[global]\n" > "$d/g"
    printf "[global]\nrw=randwrite\n[create]\ncreate_only=1\n[readjob]\nrw=randread\n" > "$d/h"
    printf "[create]\ncreate_only\nrw=write\n[readjob]\nrw=randread\n" > "$d/i"
    printf "[global]\ncreate_only=1\nrw=write\n[lay]\n[r]\ncreate_only=0\nrw=read\n" > "$d/j"
    printf "[global]\nrw=randwrite\n[c]\ncreate_only=1\nrw=read\n" > "$d/k"
    sizes="5G 1.5GiB 4k 4096 512m 1Mi 2MiB 1Gb 1GIB 50%% 1G-2G x .5G 5. 10T 7i 0 3.99k"
    aw=$(source ./wekatester; awkrun "BEGIN {
        n = split(\"$sizes\", Z, \" \")
        for (i = 1; i <= n; i++) print ((v = parse_size(Z[i])) == \"\" ? \"ValueError\" : sprintf(\"%.0f\", v))
        for (a = 1; a < ARGC; a++) {
            n = readlines(ARGV[a], L); file_directions(L, n, D)
            dirs = ((\"read\" in D) ? \"read\" : \"\") ((\"read\" in D) && (\"write\" in D) ? \" \" : \"\") ((\"write\" in D) ? \"write\" : \"\")
            v = first_value(L, n, \"filename_format\"); s = last_section(L, n)
            printf \"%.0f %s %s %s %s\n\", job_bs(L, n), lat_kind(L, n), (dirs == \"\" ? \"-\" : dirs), (v == \"\" ? \"-\" : v), (s == \"\" ? \"-\" : s)
        }
        ROW[field_col(\"bw_r_qd\")] = 8; ROW[field_col(\"bw_w_qd\")] = 16; ROW[field_col(\"lat_r_nj\")] = 4
        ROW[field_col(\"iops_w_fs\")] = \"1G\"; ROW[field_col(\"lat1m_w_qd\")] = \"x\"
        split(\"bw lat iops lat1m\", K, \" \"); split(\"read|write|read write|-\", DS, \"|\")
        for (k = 1; k <= 4; k++) for (j = 1; j <= 4; j++) {
            split(\"\", D); if (DS[j] ~ /read/) D[\"read\"] = 1; if (DS[j] ~ /write/) D[\"write\"] = 1
            s = pick_slot(K[k], D, ROW); print K[k], DS[j], (s == \"\" ? \"-\" : s)
        }
        print pick_engine(T0, O0, 0)
        T1[\"libaio\"] = 2; T1[\"io_uring\"] = 1; O1[1] = \"libaio\"; O1[2] = \"io_uring\"; print pick_engine(T1, O1, 2)
        T2[\"psync\"] = 1; T2[\"libaio\"] = 1; O2[1] = \"psync\"; O2[2] = \"libaio\"; print pick_engine(T2, O2, 2)
        T3[\"mmap\"] = 1; T3[\"sync\"] = 1; O3[1] = \"mmap\"; O3[2] = \"sync\"; print pick_engine(T3, O3, 2)
        T4[\"mmap\"] = 2; T4[\"libaio\"] = 2; O4[1] = \"mmap\"; O4[2] = \"libaio\"; print pick_engine(T4, O4, 2)
        print engine_order()
    }" "$d"/[a-k])
    want=$(cat tests/golden/jobfile-rules.txt) && [ -n "$aw" ] && [ "$aw" = "$want" ] || { printf "want:\n%s\nawk:\n%s\n" "$want" "$aw" >&2; false; }'
t_assert "jobfile rules: jf_key reads a key as fio does; override_lines replaces by it and finds an indented [global]" bash -c '
    aw=$(source ./wekatester; awkrun "BEGIN {
        n = split(\"numjobs=4|  numjobs = 4|\tnumjobs\t=\t4|# numjobs = 4|; numjobs=4|  [job]|[a=b]||stonewall|=4\", T, \"|\")
        for (i = 1; i <= n; i++) printf \"%s;\", jf_key(T[i])
        print \"\"
        L[1] = \"  ioengine = psync  \"; print first_value(L, 1, \"ioengine\"), key_value(L[1], \"ioengine|bs\")
        L[1] = \"[global]\"; L[2] = \"# numjobs = 4\"; L[3] = \"  [job]\"; L[4] = \"  numjobs = 4\"
        n = override_lines(L, 4, \"numjobs\", 1); for (i = 1; i <= n; i++) printf \"%s|\", L[i]
        print \"\"
        L[1] = \"# numjobs = 4\"; L[2] = \"  [global]\"; L[3] = \"[job]\"
        n = override_lines(L, 3, \"numjobs\", 1); for (i = 1; i <= n; i++) printf \"%s|\", L[i]
        print \"\"
    }")
    want="numjobs;numjobs;numjobs;;;;;;;;
psync psync
[global]|# numjobs = 4|  [job]|numjobs=1|
# numjobs = 4|  [global]|numjobs=1|[job]|"
    [ "$aw" = "$want" ] || { printf "want:\n%s\nawk:\n%s\n" "$want" "$aw" >&2; false; }'
# The host file is read and written by awk now, and python's csv module is
# the behaviour it keeps: held to the module itself, record for record.
t_assert "awk and python agree: the host-file CSV, read and written" bash -c '
    d=$(mktemp -d)
    printf "h1,ubuntu,io_uring,\"8,10,12\",/mnt/w\nh2, \"8,10\",x\"y,\"a\"\"b\",\"q\"tail\n\n   \n,,,,\r\nh3,\"multi\nline\",z\n#c,\"x\",\"open\nh4,\"last\n" > "$d/hl.csv"
    py=$(python3 -c "
import csv, sys
for row in csv.reader(open(sys.argv[1], newline=\"\")):
    print(len(row), \"|\".join(row).replace(chr(10), \"<nl>\"))
for row in ([\"h1\", \"8,10\", \"a\\\"b\", \"\", \" s \"], [\"x\", \"\"]):
    w = csv.writer(sys.stdout, lineterminator=\"\"); w.writerow(row); print()
" "$d/hl.csv")
    aw=$(source ./wekatester; awkrun "BEGIN {
        n = readlines(ARGV[1], L); r = csv_read(L, n, CN, CV)
        for (i = 1; i <= r; i++) {
            out = \"\"
            for (k = 1; k <= CN[i]; k++) out = out (k > 1 ? \"|\" : \"\") CV[i, k]
            gsub(/\n/, \"<nl>\", out); print CN[i], out
        }
        print csv_field(\"h1\") \",\" csv_field(\"8,10\") \",\" csv_field(\"a\\\"b\") \",\" csv_field(\"\") \",\" csv_field(\" s \")
        print csv_field(\"x\") \",\" csv_field(\"\")
    }" "$d/hl.csv")
    [ -n "$py" ] && [ "$py" = "$aw" ] || { printf "python:\n%s\nawk:\n%s\n" "$py" "$aw" >&2; false; }'
# The schema, the floor marker, the engine order and the line-rate slots
# are spelled in bash; the awk layer reads them from there.
t_assert "schema: the awk layer reads the schema, the floor marker, the engine order and the line-rate slots from bash" bash -c '
    source ./wekatester
    aw=$(awkrun "BEGIN { print geom_slots(); print floor_marker(); print engine_order(); print line_rate_slots() }") &&
    [ "$aw" = "$GEOM_SLOTS
$FLOOR_MARKER
$ENGINE_ORDER
$LINE_RATE_SLOTS" ] || { printf "%s\n" "$aw" >&2; false; }'
t_assert "probe_cores: an operator cpu list is the base, minus weka pins" bash -c '
    d=$(mktemp -d)
    printf "ncpus 8\nbindable 0-7\nbindable_priv -\nweka_allowed 2\nweka_allowed 5\n" > "$d/p"
    # no list: 8 - weka 2,5 - the reserve 0,1 = 4
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p")"
    [ "${head%% *}" = 4 ] || { echo "no list: $head" >&2; exit 1; }
    # a list: minus weka and core 0 only
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p" 0-3)"
    [ "${head%% *}" = 2 ] && [ "$all" = "1,3" ] || { echo "0-3: $head|$all" >&2; exit 1; }
    # weka cores only: nothing left (staging stops on it: the next test)
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p" 2,5)"
    [ "${head%% *}" = 0 ] && [ -z "$all" ] || { echo "2,5: $head|$all" >&2; exit 1; }'
t_assert "tuner: a host-file cpu list of only weka's cores stops, naming the list, never a guess" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "ncpus 8\nbindable 0-7\nbindable_priv -\nweka_allowed 2\nweka_allowed 5\nengines io_uring libaio psync \n" > "$FIX/probe/h1"
    cp "$FIX/probe/h1" "$FIX/probe/h2"
    rows() { for h in h1 h2; do printf "%s\t-\t-\t%s\t-" "$h" "$1"; for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; done; }
    rows 2,5 > "$FIX/targets.final"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) 2>&1 ) && { echo "no stop" >&2; exit 1; }
    case "$err" in (*"h1: the host file"*"cpu list (2,5) leaves fio no cpus"*) ;; (*) echo "$err" >&2; exit 1 ;; esac'
t_assert "probe_cores: a node's auxiliary threads are not extra weka cores (field client A)" \
    test "$(pc "ncpus 56
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
        printf "taskset 0-3\nisolated 4-15\nbindable 0-15\nbindable_priv -\npriv sudo\n" > "$d/probe/h1"
        printf "h1\t-\t-\t0-15\t-\n" > "$d/targets.final"
        check_cpu_pinning) 2>&1 )
    case "$out" in
        *"span isolated and housekeeping"*"split affinity"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "1-15" ] && test ! -s "$d/auth/h1.priv"'
t_assert "pinning: a pure-isolated request needs no escalator (self-affinable)" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
     printf "taskset 0-3\nisolated 4-15\nbindable 0-15\nbindable_priv -\n" > "$d/probe/h1"
     printf "h1\t-\t-\t4-9\t-\n" > "$d/targets.final"
     check_cpu_pinning)
    [ "$(cat "$d/auth/h1.cpus")" = "4-9" ] && test ! -s "$d/auth/h1.priv"'
t_assert "pinning: privileges are as-needed -- self-affinable mask ignores an available escalator" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth
     printf "taskset 0-3\nisolated 4-15\nbindable 0-15\nbindable_priv -\npriv dzdo -n\n" > "$d/probe/h1"
     printf "h1\t-\t-\t4-9\t-\n" > "$d/targets.final"
     check_cpu_pinning)
    [ "$(cat "$d/auth/h1.cpus")" = "4-9" ] && test ! -s "$d/auth/h1.priv"'
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
    err=$( (source ./wekatester; parse_args -f -g h1) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"option -f requires an argument, got '\''-g'\'' (looks like another option)"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "parse: a trailing valueless option still dies asking for an argument" bash -c '
    err=$( (source ./wekatester; parse_args h1 -w) 2>&1 >>$SUITE_ASIDE )
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
            run_host() { case "$2" in (t=*) echo "weka /mnt/weka wekafs rw,forcedirect 0 0";; (*) return 1;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE )
    case "$err" in
        *"localhost: cannot create files in /mnt/weka"*"chmod 1777"*"/mnt/weka is not writable on every host"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: a mode failure skips the probe and keeps the remount advice" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka
            run_host() { case "$2" in (t=*) echo "weka /mnt/weka wekafs rw,writecache 0 0";; (*) echo probed >&2; return 1;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE )
    case "$err" in *probed*) echo "probe ran after a mode failure: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"must be mounted with forcedirect; remount"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# wekafs only (Frank, 2026-10-23): every other type is refused, naming it
# and --any-fs, before anything is written or probed.
mg_type() {   # mg_type <fstype> [ANY_FS]: verify_mount_mode on a -d of that type
    (source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/data; ANY_FS=${2:-0}; FT=$1
     run_host() { case "$2" in (t=*) echo "src /data $FT rw,noatime 0 0";; (p=*) echo PROBED >&2;; (*) return 0;; esac; }
     verify_mount_mode && echo "rc=0 kept=${#PRERUN_WARNINGS[@]}") 2>&1
}
export -f mg_type
t_assert "mount guard: a -d on nfs is refused without --any-fs, naming the type and the flag, before anything is probed" bash -c '
    out=$(mg_type nfs4)
    case "$out" in *rc=0*|*PROBED*) echo "nfs passed or was probed: $out" >&2; exit 1;; esac
    case "$out" in
        *"localhost: /data is on nfs4, not wekafs"*"--any-fs"*"checks for wekafs only, and --any-fs turns that check off -- nothing was written"*) ;;
        *) echo "$out" >&2; exit 1;;
    esac'
t_assert "mount guard: a -d on a local filesystem is refused without --any-fs, naming the type and the flag" bash -c '
    out=$(mg_type xfs)
    case "$out" in *rc=0*|*PROBED*) echo "xfs passed or was probed: $out" >&2; exit 1;; esac
    case "$out" in
        *"localhost: /data is on xfs, not wekafs"*"--any-fs"*"nothing was written"*) ;;
        *) echo "$out" >&2; exit 1;;
    esac'
t_assert "mount guard: --any-fs accepts nfs and a local disk, probes them, and keeps a WARNING naming the type for the run log" bash -c '
    for ft in nfs4 xfs; do
        out=$(mg_type "$ft" 1)
        case "$out" in
            *"WARNING: localhost: the destination is on $ft; the filesystem-type check is off (--any-fs)"*) ;;
            *) echo "$ft: $out" >&2; exit 1;;
        esac
        case "$out" in *PROBED*"rc=0 kept=1"*) ;; *) echo "$ft: $out" >&2; exit 1;; esac
    done'
t_assert "mount guard: the --any-fs WARNING lands in the run log, one line per type" bash -c '
    d=$(mktemp -d); : > "$d/wekatester.log"
    (source ./wekatester
     LOCAL_MODE=0; HOSTS=(h1 h2 h3); DIRECTORY=/data; ANY_FS=1
     run_host() { case "$1:$2" in (h3:t=*) echo "/dev/sda1 /data xfs rw 0 0";; (*:t=*) echo "srv:/data /data nfs4 rw 0 0";; (*) return 0;; esac; }
     verify_mount_mode; RUN_DIR=$d; replay_prerun_warnings) >>$SUITE_ASIDE 2>&1
    [ "$(grep -c "filesystem-type check is off" "$d/wekatester.log")" -eq 2 ] &&
    grep -q "WARNING (before the run log opened): the destination is on nfs4 on 2 of 3 hosts (h1 h2); the filesystem-type check is off (--any-fs)" "$d/wekatester.log" &&
    grep -q "WARNING (before the run log opened): h3: the destination is on xfs; the filesystem-type check is off (--any-fs)" "$d/wekatester.log" ||
        { cat "$d/wekatester.log" >&2; false; }'

# -r turns the forcedirect stop into a warning. The write probe still runs
# (a cached mount that is unwritable is still a zero-IO run), and the warning
# is kept for replay into the run log, which does not exist yet at this point.
t_assert "mount guard: -r makes a cached mount mode a warning and still probes writability" bash -c '
    out=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka; FAST_TRACK=1
            run_host() { case "$2" in (t=*) echo "weka /mnt/weka wekafs rw,writecache 0 0";; (p=*) echo probed >&2;; (*) return 1;; esac; }
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
            run_host() { case "$2" in (t=*) echo "weka /mnt/weka wekafs rw,writecache 0 0";; (*) return 0;; esac; }
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
                (h1:t=*|h3:t=*) echo "weka /mnt/weka wekafs rw,writecache 0 0";;
                (h2:t=*) echo "weka /mnt/weka wekafs rw,readcache 0 0";;
                (h4:t=*) echo "weka /mnt/weka wekafs rw,forcedirect 0 0";;
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
            run_host() { case "$2" in (t=*) echo "weka /mnt/weka wekafs rw,readcache 0 0";; (*) return 1;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *"must be mounted with forcedirect"*) echo "remount advice under -r: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"WARNING: localhost: wekafs mounted readcache"*"cannot create files in /mnt/weka"*"is not writable on every host"*) true;;
        *) echo "$err" >&2; false;;
    esac'

# The mount verified is the mount measured (Frank, 2026-10-11): the check
# records the destination mount's /proc/mounts line and its cksum, and right
# before the measured run every host reads it again; any change to that line
# stops the run, -r included.
t_assert "mount recheck: the mount check classifies and records each host's full /proc/mounts line and its cksum from one session, with no findmnt FSTYPE,OPTIONS" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     LOCAL_MODE=0; HOSTS=(h1 h2 h3); DIRECTORY=/mnt/weka; WORK_DIR=$d; ANY_FS=1
     run_host() { f=no; t=no; p=no
         case "$2" in (*FSTYPE*) f=yes;; esac
         case "$2" in (*"-o TARGET"*) t=yes;; esac
         case "$2" in (*/proc/mounts*) p=yes;; esac
         echo "$1 $f $t $p" >> "$d/calls"
         case "$1:$2" in
         (h1:t=*) echo "weka0 /mnt/weka wekafs rw,relatime,forcedirect 0 0";;
         (h2:t=*) echo "srv:/x /mnt/weka nfs4 rw,noatime,vers=4.2 0 0";;
         (h3:t=*) echo "weka1 /mnt/weka wekafs rw,relatime,forcedirect 0 0";;
         (*) return 0;; esac; }
     verify_mount_mode) >>$SUITE_ASIDE 2>&1 || { echo "the mount check failed" >&2; exit 1; }
    [ "$(cat "$d/mount/0")" = "weka0 /mnt/weka wekafs rw,relatime,forcedirect 0 0" ] &&
    [ "$(cat "$d/mount/1")" = "srv:/x /mnt/weka nfs4 rw,noatime,vers=4.2 0 0" ] &&
    [ "$(cat "$d/mount/2")" = "weka1 /mnt/weka wekafs rw,relatime,forcedirect 0 0" ] &&
    [ "$(wc -l < "$d/mount/sums")" -eq 3 ] &&
    [ "$(cat "$d/mount/sums")" = "$(cd "$d/mount" && cksum 0 1 2)" ] &&
    [ "$(grep -c "^h[123] no yes yes\$" "$d/calls")" -eq 3 ] &&
    [ "$(grep -c " yes" "$d/calls")" -eq 3 ] &&
    [ "$(grep -c "^h[123] yes" "$d/calls")" -eq 0 ] ||
        { echo "record: $(head "$d"/mount/* 2>&1); calls: $(cat "$d/calls")" >&2; false; }'
t_assert "mount recheck: a created destination is recorded with the /proc/mounts line of the mount it was created on" bash -c '
    d=$(mktemp -d)
    (export WEKATESTER_PROMPT_TTY=/dev/null
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(h1); DIRECTORY=/mnt/weka/wt; FAST_TRACK=1; WORK_DIR=$d
     run_host() { case "$2" in
         (t=*)       return 1;;
         ("[ ! -e"*) case "$2" in (*"/proc/mounts") ;; (*) return 1;; esac
                     printf "/mnt/weka\nweka0 /mnt/weka wekafs rw,relatime,forcedirect 0 0\n";;
         (*)         return 0;; esac; }
     verify_mount_mode) >>$SUITE_ASIDE 2>&1 || { echo "the mount check failed" >&2; exit 1; }
    [ "$(cat "$d/mount/0")" = "weka0 /mnt/weka wekafs rw,relatime,forcedirect 0 0" ] ||
        { echo "record: $(head "$d"/mount/* 2>&1)" >&2; false; }'
t_assert "mount recheck: a destination whose /proc/mounts line is not found stops the mount check" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(h1 h2); DIRECTORY=/mnt/weka
            run_host() { case "$1:$2" in
                (h1:t=*) echo "weka0 /mnt/weka wekafs rw,forcedirect 0 0";;
                (h2:t=*) echo;;
                (*) return 0;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; exit 1; }
    case "$err" in *"h1:"*) echo "blamed h1: $err" >&2; exit 1;; esac
    case "$err" in
        *"h2: no /proc/mounts line for the mount holding /mnt/weka"*"/proc/mounts line was not found on every host"*) ;;
        *) echo "$err" >&2; exit 1;;
    esac'
t_assert "mount recheck: unchanged lines pass, one read per host, and both reads send the one builder's command, byte for byte" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(h1 h2); DIRECTORY=/mnt/weka; WORK_DIR=$d
            q=$(printf "\047"); mount_line_cmd_v "$q/mnt/weka$q"; printf "%s" "$MOUNT_LINE_CMD" > "$d/expect"
            # PH names the phase: the two reads now send the same command
            run_host() { case "$2" in
                ("t="*) printf "%s" "$2" > "$d/$PH.$1"; echo "$1 $PH" >> "$d/calls"
                        echo "weka0 /mnt/weka wekafs rw,forcedirect 0 0";;
                (*) return 0;; esac; }
            PH=verify; verify_mount_mode && PH=recheck && check_mounts_unchanged && echo rc=0) 2>&1 )
    case "$out" in *ERROR*|*WARNING*) echo "$out" >&2; exit 1;; *rc=0*) ;; *) echo "$out" >&2; exit 1;; esac
    for h in h1 h2; do
        [ "$(cat "$d/recheck.$h")" = "$(cat "$d/expect")" ] &&
        [ "$(cat "$d/verify.$h")" = "$(cat "$d/expect")" ] ||
            { echo "$h: verify [$(cat "$d/verify.$h")] recheck [$(cat "$d/recheck.$h")] expect [$(cat "$d/expect")]" >&2; exit 1; }
    done
    [ "$(grep -c " recheck\$" "$d/calls")" -eq 2 ] && [ "$(grep -c " verify\$" "$d/calls")" -eq 2 ] ||
        { echo "calls: $(cat "$d/calls")" >&2; false; }'
t_assert "mount recheck: under -r a change to only an option, only the source or only dump/pass, an unreadable host, or a missing line each stop the run with the old and new line" bash -c '
    d=$(mktemp -d)
    r="weka0 /mnt/weka wekafs rw,relatime,forcedirect 0 0"
    printf "%s\n" "$r" > "$d/rec"
    printf "%s\n" "$r" > "$d/now.h1"
    printf "%s\n" "weka0 /mnt/weka wekafs rw,relatime,forcedirect,noatime 0 0" > "$d/now.h2"
    printf "%s\n" "weka1 /mnt/weka wekafs rw,relatime,forcedirect 0 0" > "$d/now.h3"
    printf "%s\n" "weka0 /mnt/weka wekafs rw,relatime,forcedirect 1 2" > "$d/now.h4"
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(h1 h2 h3 h4 h5 h6); DIRECTORY=/mnt/weka; WORK_DIR=$d; FAST_TRACK=1
            # PH names the phase: the check and the recheck send one command
            run_host() { case "$PH:$1:$2" in
                (verify:*:t=*)  cat "$d/rec";;
                (recheck:h5:t=*) return 1;;
                (recheck:h6:t=*) ;;
                (recheck:*:t=*) cat "$d/now.$1";;
                (*)             return 0;; esac; }
            PH=verify; verify_mount_mode || exit 9
            PH=recheck; check_mounts_unchanged; echo "survived rc=$?") 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -eq 1 ] || { echo "rc=$rc: $err" >&2; exit 1; }
    case "$err" in *"ERROR: h1:"*) echo "named an unchanged host: $err" >&2; exit 1;; esac
    w="the mount at /mnt/weka changed since the mount check -- was \"$r\", now"
    for want in "h2: $w \"weka0 /mnt/weka wekafs rw,relatime,forcedirect,noatime 0 0\"" \
                "h3: $w \"weka1 /mnt/weka wekafs rw,relatime,forcedirect 0 0\"" \
                "h4: $w \"weka0 /mnt/weka wekafs rw,relatime,forcedirect 1 2\"" \
                "h5: $w unreadable (rc=1)" \
                "h6: $w no /proc/mounts line" \
                "the destination mount changed on 5 of 6 host(s) after it was verified; the measured run did not start"; do
        case "$err" in *"$want"*) ;; *) echo "missing [$want] in: $err" >&2; exit 1;; esac
    done'
# The remote string itself, run for real by bash: findmnt is stubbed
# to name the mount point, and a fixture stands in for /proc/mounts.
t_assert "mount recheck: the real snippet -- a \\040 mount point matches, a stacked mount gives the last line, \\134 decodes, no match prints nothing" bash -c '
    d=$(mktemp -d); mkdir "$d/bin"
    printf "#!/bin/sh\necho \"\$*\" >> \"%s/asked\"\ncat \"%s/target\"\n" "$d" "$d" > "$d/bin/findmnt"; chmod +x "$d/bin/findmnt"
    printf "%s\n" "rootfs / ext4 rw 0 0" "weka0 /mnt/my\\040weka wekafs rw,forcedirect 0 0" \
        "weka0 /mnt/my\\040wekaX wekafs rw 0 0" "weka0 /mnt/stack wekafs rw,readcache 0 0" \
        "weka1 /mnt/stack wekafs rw,forcedirect 0 0" "bs /mnt/a\\134b wekafs rw 0 0" > "$d/mounts"
    cmd=$(source ./wekatester; mount_line_cmd_v "\"/x/y\""; printf "%s" "$MOUNT_LINE_CMD")
    case "$cmd" in *" /proc/mounts") ;; *) echo "does not read /proc/mounts last: $cmd" >&2; exit 1;; esac
    cmd="${cmd% /proc/mounts} $d/mounts"
    for c in "/mnt/my weka|weka0 /mnt/my\\040weka wekafs rw,forcedirect 0 0" \
             "/mnt/stack|weka1 /mnt/stack wekafs rw,forcedirect 0 0" \
             "/mnt/a\\b|bs /mnt/a\\134b wekafs rw 0 0" "/mnt/none|"; do
        printf "%s\n" "${c%%|*}" > "$d/target"
        out=$(PATH="$d/bin:$PATH" bash -c "$cmd"); rc=$?
        [ "$rc" -eq 0 ] && [ "$out" = "${c#*|}" ] || { echo "target [${c%%|*}]: rc=$rc out [$out]" >&2; exit 1; }
    done
    # findmnt -T names a stacked mount point once per mount
    printf "%s\n" /mnt/stack /mnt/stack > "$d/target"
    out=$(PATH="$d/bin:$PATH" bash -c "$cmd"); rc=$?
    [ "$rc" -eq 0 ] && [ "$out" = "weka1 /mnt/stack wekafs rw,forcedirect 0 0" ] ||
        { echo "stacked findmnt: rc=$rc out [$out]" >&2; exit 1; }
    grep -qx -- "-T /x/y -n -o TARGET" "$d/asked" || { cat "$d/asked" >&2; exit 1; }'
# A stacked mount (Frank, 2026-10-11): findmnt lists the hidden mount first;
# the check judges the visible /proc/mounts line, the one recorded and written
# to. The real snippets run; findmnt is stubbed, /proc/mounts a fixture.
t_assert "mount guard: a stacked mount is judged by its visible line, not the hidden one findmnt lists first, -d present or created" bash -c '
    d=$(mktemp -d); mkdir "$d/bin" "$d/stack" "$d/wA" "$d/wB" "$d/wC" "$d/wD"
    cat > "$d/bin/findmnt" <<EOF
#!/bin/sh
[ -e "\$2" ] || exit 1
case "\$*" in
    (*" TARGET") echo "$d/stack"; echo "$d/stack";;
    (*",OPTIONS") cat "$d/fsopts";;
    (*) cut -d" " -f1 "$d/fsopts";;
esac
EOF
    chmod +x "$d/bin/findmnt"
    W="weka0 $d/stack wekafs rw,relatime,forcedirect 0 0"; X="/dev/sda1 $d/stack xfs rw,noatime 0 0"
    try() {   # try <hidden line> <visible line> <-d> <work dir>
        printf "%s\n" "rootfs / ext4 rw 0 0" "$1" "$2" > "$d/mounts"
        printf "%s\n" "$1" "$2" | cut -d" " -f3,4 > "$d/fsopts"
        (export WEKATESTER_PROMPT_TTY=/dev/null
         source ./wekatester
         LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=$3; FAST_TRACK=1; WORK_DIR=$4
         run_host() { PATH="$d/bin:$PATH" bash -c "${2//\/proc\/mounts/$d/mounts}" </dev/null; }
         verify_mount_mode && echo rc=0) 2>&1
    }
    out=$(try "$W" "$X" "$d/stack" "$d/wA")
    case "$out" in
        *rc=0*) echo "hidden wekafs over a visible xfs passed: $out" >&2; exit 1;;
        *"localhost: $d/stack is on xfs, not wekafs"*) ;;
        *) echo "A: $out" >&2; exit 1;;
    esac
    out=$(try "$X" "$W" "$d/stack" "$d/wB")
    case "$out" in *rc=0*) ;; *) echo "visible wekafs over a hidden xfs refused: $out" >&2; exit 1;; esac
    [ "$(cat "$d/wB/mount/0")" = "$W" ] || { echo "B record: $(cat "$d/wB/mount/0")" >&2; exit 1; }
    out=$(try "$W" "$X" "$d/stack/wt" "$d/wC")
    [ ! -e "$d/stack/wt" ] || { echo "created under a visible xfs: $out" >&2; exit 1; }
    case "$out" in
        *rc=0*) echo "C passed: $out" >&2; exit 1;;
        *"$d/stack/wt does not exist, and $d/stack is on xfs, not wekafs"*) ;;
        *) echo "C: $out" >&2; exit 1;;
    esac
    out=$(try "$X" "$W" "$d/stack/wt" "$d/wD")
    case "$out" in *"localhost: created $d/stack/wt"*rc=0*) ;; *) echo "D: $out" >&2; exit 1;; esac
    [ -d "$d/stack/wt" ] && [ "$(cat "$d/wD/mount/0")" = "$W" ] || { echo "D record: $(cat "$d/wD/mount/0")" >&2; exit 1; }'
t_assert "mount recheck: main runs it once, after the dry-run exit, right before run_jobs" bash -c '
    body=$(source ./wekatester; declare -f main)
    [ "$(printf "%s\n" "$body" | grep -c check_mounts_unchanged)" -eq 1 ] &&
    case "$body" in *"dry_run_report;"*"exit 0;"*"check_mounts_unchanged;"*) true;; *) false;; esac &&
    printf "%s\n" "$body" | grep -A1 check_mounts_unchanged | tail -n 1 | grep -q "^ *run_jobs;" ||
        { echo "$body" >&2; false; }'
# Live on the console every time it is raised; kept once per distinct
# message; replayed into the run log FILE only,
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
# commands: the t= mount-line read, the "[ ! -e" ancestor walk, the mkdir
# (its "mkdir -p --") and the p= write probe.
t_assert "mount guard: missing -d under forcedirect wekafs is created unattended under -r, then probed" bash -c '
    out=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(h1 h2); DIRECTORY=/mnt/weka/wt; FAST_TRACK=1
            run_host() { case "$2" in
                (t=*)       return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,relatime,forcedirect 0 0\n";;
                (*"mkdir -p --"*) echo "MKDIR[$1] ${2##*; }" >&2;;
                (p=*)       echo "PROBE[$1]" >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode && echo rc=0) 2>&1 )
    # the hosts are created in parallel: each its mkdir, then its probe
    case "$out" in
        *"h1: /mnt/weka/wt does not exist; /mnt/weka is a wekafs mount"*"h2: /mnt/weka/wt does not exist"*"does not exist on 2 host(s); creating it (unattended)"*"MKDIR["*rc=0*) ;;
        *) echo "$out" >&2; exit 1;;
    esac
    for h in h1 h2; do
        case "$out" in
            *"MKDIR[$h] mkdir -p -- "?"/mnt/weka/wt"?*"PROBE[$h]"*) ;;
            *) echo "$h: $out" >&2; exit 1;;
        esac
        case "$out" in *"$h: created /mnt/weka/wt"*) ;; *) echo "$h: $out" >&2; exit 1;; esac
    done'
t_assert "mount guard: missing -d without -r needs a terminal and creates nothing" bash -c '
    err=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt
            run_host() { case "$2" in
                (t=*)       return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,forcedirect 0 0\n";;
                (*"mkdir -p --"*) echo MKDIR >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE ); rc=$?
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
        (t=*)       return 1;;
        ("[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,forcedirect 0 0\n";;
        (*"mkdir -p --"*) echo MKDIR >&2;;
        (*)         return 0;; esac; }
    yes_out=$(printf y | { verify_mount_mode; } 2>&1); yes_rc=$?
    no_out=$(printf n | { verify_mount_mode; } 2>&1); no_rc=$?
    [ "$yes_rc" -eq 0 ] || { echo "y: rc=$yes_rc $yes_out" >&2; false; } &&
    case "$yes_out" in *"create the missing destination directory on 1 host(s)? [y/N]"*MKDIR*) true;; *) echo "y: $yes_out" >&2; false;; esac &&
    [ "$no_rc" -ne 0 ] || { echo "n: rc=0 $no_out" >&2; false; } &&
    case "$no_out" in *MKDIR*) echo "n created: $no_out" >&2; false;; *"destination directory does not exist on 1 host(s)"*) true;; *) echo "n: $no_out" >&2; false;; esac'
t_assert "prompts: an untimed question whose yes changes something takes a y -- Enter, space or any other key say no" bash -c '
    source ./wekatester; PROMPT_IN_FD=0; PROMPT_OUT_FD=1
    for k in "" " " n x; do
        if printf "%s\n" "$k" | confirm_explicit "go ahead?" >>$SUITE_ASIDE; then echo "key [$k] said yes" >&2; exit 1; fi
    done
    printf "y" | confirm_explicit "go ahead?" >>$SUITE_ASIDE && printf "Y" | confirm_explicit "go ahead?" >>$SUITE_ASIDE || exit 1
    # the create prompt for a missing -d: Enter no longer creates it
    LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt
    run_host() { case "$2" in
        (t=*)       return 1;;
        ("[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,forcedirect 0 0\n";;
        (*"mkdir -p --"*) echo MKDIR >&2;;
        (*)         return 0;; esac; }
    out=$(printf "\n" | { verify_mount_mode; } 2>&1) && { echo "Enter went ahead: $out" >&2; exit 1; }
    case "$out" in *MKDIR*) echo "Enter created: $out" >&2; false;; *) true;; esac'
t_assert "mount guard: missing -d whose parent is not wekafs is never created without --any-fs, even under -r -- local and nfs parents alike are refused by type" bash -c '
    try() { (source ./wekatester
             LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/wkea; FAST_TRACK=1; PARENT=$1
             run_host() { case "$2" in
                 (t=*)       return 1;;
                 ("[ ! -e"*) printf "/mnt\nsrc /mnt %s rw,relatime 0 0\n" "$PARENT";;
                 (*"mkdir -p --"*) echo MKDIR >&2;;
                 (*)         return 1;; esac; }
             verify_mount_mode) 2>&1 >>$SUITE_ASIDE; }
    for p in xfs nfs4; do
        err=$(try "$p") && { echo "passed under a $p parent: $err" >&2; exit 1; }
        case "$err" in *MKDIR*) echo "created under a $p parent: $err" >&2; exit 1;; esac
        case "$err" in
            *"/mnt/wkea does not exist, and /mnt is on $p, not wekafs -- check that weka is mounted on this host"*"--any-fs"*"nothing was written"*) ;;
            *) echo "$p: $err" >&2; exit 1;;
        esac
    done'
t_assert "mount guard: --any-fs creates a missing -d under a non-wekafs parent, with no wekafs re-check, then probes it" bash -c '
    out=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/scratch/wt; FAST_TRACK=1; ANY_FS=1
            run_host() { case "$2" in
                (t=*)       return 1;;
                ("[ ! -e"*) printf "/scratch\n/dev/sda1 /scratch xfs rw,relatime 0 0\n";;
                ("mkdir -p -- '"'"'/scratch/wt'"'"'") echo MKDIR >&2;;
                (*"mkdir -p --"*) echo "GUARDED: $2" >&2; return 4;;
                (p=*)       echo PROBED >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode && echo rc=0) 2>&1 )
    case "$out" in
        *"WARNING: localhost: the destination is on xfs; the filesystem-type check is off (--any-fs)"*"/scratch/wt does not exist; /scratch is on xfs (--any-fs)"*"creating it (unattended)"*MKDIR*PROBED*"created /scratch/wt"*rc=0*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "mount guard: missing -d under a cached-mode parent stops without -r and creates nothing" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt
            run_host() { case "$2" in
                (t=*)       return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,writecache 0 0\n";;
                (*"mkdir -p --"*) echo MKDIR >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE ); rc=$?
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
                (t=*)       return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,writecache 0 0\n";;
                (*"mkdir -p --"*) echo MKDIR >&2;;
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
                (h1:t=*)       echo "weka /mnt/weka wekafs rw,writecache 0 0";;
                (h2:t=*)       return 1;;
                (h2:"[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,forcedirect 0 0\n";;
                (*"mkdir -p --"*) echo MKDIR >&2;;
                (*)            return 1;; esac; }
            verify_mount_mode) 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *MKDIR*) echo "mutated before a stop: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"h2: /mnt/weka/wt does not exist; not created while other checks fail"*"h1: wekafs mounted writecache"*"must be mounted with forcedirect"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# findmnt is stubbed to name the mount point; a fixture stands in for /proc/mounts.
t_assert "mount guard: the create snippet makes the destination only while its nearest existing parent's /proc/mounts line is wekafs, checked in the same session" bash -c '
    tmp=$(mktemp -d); stub=$(mktemp -d)
    printf "#!/bin/sh\necho \"\$*\" >> \"%s/asked\"\necho \"%s\"\n" "$stub" "$tmp" > "$stub/findmnt"; chmod +x "$stub/findmnt"
    cmd=$(source ./wekatester; create_dest_cmd "$tmp/a/b")
    case "$cmd" in *" /proc/mounts |"*) ;; *) echo "does not read /proc/mounts: $cmd" >&2; exit 1;; esac
    cmd=${cmd//\/proc\/mounts/$stub/mounts}
    printf "%s\n" "/dev/sda1 $tmp xfs rw,noatime 0 0" > "$stub/mounts"
    PATH="$stub:$PATH" bash -c "$cmd"; rc=$?
    [ "$rc" -eq 4 ] && [ ! -e "$tmp/a" ] || { echo "rc=$rc under xfs" >&2; exit 1; }
    grep -qx -- "-T $tmp -n -o TARGET" "$stub/asked" || { cat "$stub/asked" >&2; exit 1; }
    printf "%s\n" "weka0 $tmp wekafs rw,forcedirect 0 0" > "$stub/mounts"
    PATH="$stub:$PATH" bash -c "$cmd" && [ -d "$tmp/a/b" ]'
t_assert "mount guard: under --any-fs the create snippet is a plain mkdir -p, so a missing -d under an xfs parent is created" bash -c '
    tmp=$(mktemp -d); stub=$(mktemp -d)
    printf "#!/bin/sh\necho \"%s\"\n" "$tmp" > "$stub/findmnt"; chmod +x "$stub/findmnt"
    cmd=$(source ./wekatester; ANY_FS=1; create_dest_cmd "$tmp/a/b")
    cmd=${cmd//\/proc\/mounts/$stub/mounts}
    printf "%s\n" "/dev/sda1 $tmp xfs rw,noatime 0 0" > "$stub/mounts"
    PATH="$stub:$PATH" bash -c "$cmd" && [ -d "$tmp/a/b" ] || { echo "not created: $cmd" >&2; false; }'
t_assert "mount guard: a parent that stops being wekafs before the create leaves nothing created, probed or written, and says why" bash -c '
    err=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt; FAST_TRACK=1
            run_host() { case "$2" in
                (t=*)       return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,forcedirect 0 0\n";;
                (*"mkdir -p --"*) return 4;;
                (p=*)       echo PROBED >&2;;
                (*)         return 1;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE ) && { echo "passed: $err" >&2; exit 1; }
    case "$err" in *PROBED*) echo "probed: $err" >&2; exit 1;; esac
    case "$err" in
        *"localhost: /mnt/weka/wt was not created -- the nearest directory above it is no longer on a wekafs mount"*"nothing was created on a local disk"*) true;;
        *) echo "$err" >&2; false;;
    esac'
t_assert "mount guard: a failed mkdir dies with the chmod hint naming the parent" bash -c '
    err=$( (export WEKATESTER_PROMPT_TTY=/dev/null
            source ./wekatester
            LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=/mnt/weka/wt; FAST_TRACK=1
            run_host() { case "$2" in
                (t=*)       return 1;;
                ("[ ! -e"*) printf "/mnt/weka\nweka /mnt/weka wekafs rw,forcedirect 0 0\n";;
                (*"mkdir -p --"*) return 1;;
                (*)         echo PROBED >&2;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] || { echo "expected nonzero exit" >&2; false; } &&
    case "$err" in *PROBED*) echo "probed a directory that was not created: $err" >&2; false;; *) true;; esac &&
    case "$err" in
        *"localhost: cannot create /mnt/weka/wt -- fix the root'"'"'s owner/mode (a one-time '"'"'sudo chmod 1777 /mnt/weka'"'"'"*"is not writable on every host"*) true;;
        *) echo "$err" >&2; false;;
    esac'
# The ancestor walk itself, against a real filesystem: findmnt is stubbed to
# log what it was asked and name the mount point; a fixture is /proc/mounts.
t_assert "mount guard: the missing-dir snippet walks up to the nearest existing ancestor and prints its mount's /proc/mounts line" bash -c '
    tmp=$(mktemp -d); stub=$(mktemp -d)
    printf "#!/bin/sh\necho \"\$*\" >> \"%s/asked\"\necho \"%s\"\n" "$stub" "$tmp" > "$stub/findmnt"; chmod +x "$stub/findmnt"
    printf "%s\n" "rootfs / ext4 rw 0 0" "weka0 $tmp wekafs rw,forcedirect 0 0" > "$stub/mounts"
    cmd=$(source ./wekatester; missing_dir_probe_cmd "$tmp/a/b/c/")
    out=$(PATH="$stub:$PATH" bash -c "${cmd//\/proc\/mounts/$stub/mounts}")
    [ "$out" = "$tmp
weka0 $tmp wekafs rw,forcedirect 0 0" ] && grep -qx -- "-T $tmp -n -o TARGET" "$stub/asked" ||
        { echo "out [$out] asked [$(cat "$stub/asked")]" >&2; false; }'
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
    err=$( (source ./wekatester; check_fio_errors "$tmp/r.json" layout) 2>&1 >>$SUITE_ASIDE )
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
    err=$( (source ./wekatester; check_fio_errors "$tmp/r.json" measured) 2>&1 >>$SUITE_ASIDE )
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
    err=$( (source ./wekatester; check_fio_errors "$tmp/r.json" layout) 2>&1 >>$SUITE_ASIDE )
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
    f() { (source ./wekatester; stage_cal_cell "$d/x.job" /mnt/weka h1 "" "$@") >>$SUITE_ASIDE 2>&1; }
    ! f bogus read io_uring 1 1 2 30 && ! f bw sideways io_uring 1 1 2 30 &&
    ! f bw read io_uring 0 1 2 30 && ! f bw read io_uring 1 qd8 2 30 &&
    ! f bw read "" 1 1 2 30 && f bw read io_uring 1 1 2 30'

# --- cal_plan: the search rules, driven against a client with a known curve ---
# N is the shape's usable PHYSICAL cores; the job counts are Frank's
# (2026-09-25): N/2 and N one job per physical core at iodepth=1 nrfiles=1 --
# no queue or file ladder at or below N -- then 2N and 4N with the siblings
# in, where the iodepth and nrfiles ladders run.
K='exh=0 line=95 band=98.5 thr=3 stop=2 confirm=3 rt=30 nr=1 nrc=1,2,4 bwqd=1,2,4,8,16 iopsqd=1,2,4,8,16,32,64,128,256,512'
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
t_assert "cal_plan bw: short of line rate, 2N and 4N walk iodepth for every nrfiles; 4N runs though 2N did not beat N" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_BWCAP=9663676416 plan_sim "$d" bw write libaio 16 12500000000 0)
    case "$out" in
        "done 64 4 4 numjobs=64 iodepth=4 nrfiles=4 -> 9.00 GiB/s = 77.3% of the 11.64 GiB/s line rate (never reached 95% of line rate; the best reading wins, ties go heavier, siblings in)") true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 1 1 1;numjobs 2 1 1;numjobs 4 1 1;numjobs 8 1 1;numjobs 16 1 1;wide 32 1 1;wide 32 2 1;wide 32 4 1;wide 32 1 2;wide 32 2 2;wide 32 4 2;wide 32 1 4;wide 32 2 4;wide 32 4 4;wide 64 1 1;wide 64 2 1;wide 64 4 1;wide 64 1 2;wide 64 2 2;wide 64 4 2;wide 64 1 4;wide 64 2 4;wide 64 4 4;confirm 16 1 1;confirm 32 1 1;confirm 32 1 2;" ] ||
        { cat "$d/asked" >&2; false; }'
t_assert "cal_plan bw: no line rate, a flat job ladder still measures N/2 and N" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_BWCAP=4294967296 plan_sim "$d" bw read io_uring 32 0 0)
    case "$out" in "done 128 4 4 numjobs=128 iodepth=4 nrfiles=4 -> 4.00 GiB/s (the best reading wins, ties go heavier, siblings in)") true;;
        *) echo "$out" >&2; false;; esac &&
    grep -q "^numjobs 32 " "$d/asked" && grep -q "^numjobs 16 " "$d/asked" &&
    grep -q "^wide 64 1 1$" "$d/asked" && grep -q "^wide 128 1 1$" "$d/asked"'
t_assert "cal_plan bw: a plateau skips the rungs below N/2 only (flat from 1 job, N=32: 1 2 4 16 32)" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    CAL_SIM_BWCAP=1073741824 plan_sim "$d" bw read io_uring 32 0 0 >>$SUITE_ASIDE
    [ "$(awk "\$1 == \"numjobs\" { printf \"%s \", \$2 }" "$d/asked")" = "1 2 4 16 32 " ] || { cat "$d/asked" >&2; false; }'
t_assert "cal_plan bw: flat from 1 job at N=16, no line rate, still measures 8 and 16" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    CAL_SIM_BWCAP=1073741824 plan_sim "$d" bw read io_uring 16 0 0 >>$SUITE_ASIDE
    [ "$(awk "\$1 == \"numjobs\" { printf \"%s \", \$2 }" "$d/asked")" = "1 2 4 8 16 " ] || { cat "$d/asked" >&2; false; }'
t_assert "cal_plan bw: flat from 1 job at N=16, a reading beat the line rate, still measures 8 and 16" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_BWCAP=1073741824 plan_sim "$d" bw read io_uring 16 500000000 0)
    case "$out" in *"a reading beat the line rate by more than 5%"*) true;; *) echo "$out" >&2; false;; esac &&
    [ "$(awk "\$1 == \"numjobs\" { printf \"%s \", \$2 }" "$d/asked")" = "1 2 4 8 16 " ] || { cat "$d/asked" >&2; false; }'
t_assert "cal_plan bw: a reading well above line rate means line rate is not the ceiling" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" bw read io_uring 16 12500000000 0)
    case "$out" in
        "done 64 4 4 "*"(the best reading wins, ties go heavier, siblings in); a reading beat the line rate by more than 5%, so line rate is not this client"*) true;;
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
        "done 64 8 4 numjobs=64 iodepth=8 nrfiles=4 -> 1,000,000 IOPS (8 jobs 160,000 IOPS at iodepth 1, 16 jobs 320,000 IOPS at iodepth 1, 32 jobs 1,000,000 IOPS at iodepth 16 nrfiles 4, 64 jobs 1,000,000 IOPS at iodepth 8 nrfiles 4; siblings in)") true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 8 1 1;numjobs 16 1 1;iodepth 32 1 1;iodepth 32 2 1;iodepth 32 4 1;iodepth 32 8 1;nrfiles 32 8 2;nrfiles 32 16 2;nrfiles 32 8 4;nrfiles 32 16 4;iodepth 64 1 1;iodepth 64 2 1;iodepth 64 4 1;nrfiles 64 4 2;nrfiles 64 8 2;nrfiles 64 4 4;nrfiles 64 8 4;confirm 32 2 1;confirm 64 1 1;confirm 32 4 1;" ] ||
        { cat "$d/asked" >&2; false; }'
t_assert "cal_plan iops: no queue or file ladder at or below N" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    plan_sim "$d" iops write io_uring 16 0 0 >>$SUITE_ASIDE
    ! awk "\$2 <= 16 && (\$3 != 1 || \$4 != 1)" "$d/asked" | grep -q . ||
        { awk "\$2 <= 16" "$d/asked" >&2; false; }'
t_assert "cal_plan iops: a file count that wins is recorded" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_IOPSKNEE=64 CAL_SIM_NRBEST=4 plan_sim "$d" iops write io_uring 16 0 0)
    case "$out" in "done 64 1 4 numjobs=64 iodepth=1 nrfiles=4 -> 1,030,000 IOPS"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "cal_plan iops: 4N runs though 2N did not beat N" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(CAL_SIM_IOPSCAP=100000 plan_sim "$d" iops read io_uring 16 0 0)
    case "$out" in "done 64 8 4 "*"32 jobs 100,000 IOPS at iodepth 8 nrfiles 4, 64 jobs 100,000 IOPS at iodepth 8 nrfiles 4; siblings in)") true;; *) echo "$out" >&2; false;; esac &&
    grep -q "^iodepth 64 1 1$" "$d/asked"'
t_assert "cal_plan iops: a sync engine keeps iodepth at 1 and still walks the job counts and files" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" iops read psync 8 0 0)
    case "$out" in "done 32 1 4 numjobs=32 iodepth=1 nrfiles=4 -> 640,000 IOPS"*) true;; *) echo "$out" >&2; false;; esac &&
    ! awk "\$3 != 1" "$d/asked" | grep -q . &&
    grep -q "^numjobs 4 1 1$" "$d/asked" && grep -q "^nrfiles 16 1 4$" "$d/asked"'
t_assert "cal_plan lat: N jobs at iodepth 1, one cell per nrfiles, and the lowest mean wins" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    # 16 jobs: 100us + 8 x 20us over the 8-job knee = 260us; two files per job take 10% off
    out=$(CAL_SIM_LATNRBEST=2 plan_sim "$d" lat read io_uring 16 0 0)
    case "$out" in
        "done 16 1 2 numjobs=16 iodepth=1 nrfiles=2 -> 234.0 us, 68,376 IOPS (the lowest mean of nrfiles 1 260.0 us, 2 234.0 us, 4 260.0 us at 16 jobs, one job per physical core)") true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(tr "\n" ";" < "$d/asked")" = "nrfiles 16 1 1;nrfiles 16 1 2;nrfiles 16 1 4;" ] ||
        { cat "$d/asked" >&2; false; }'
t_assert "cal_plan lat: no threshold -- any lower mean wins, and equal means keep the fewer files" bash -c '
    d=$(mktemp -d)
    printf "nrfiles psync 8 1 1 30 100.0 80000\nnrfiles psync 8 1 2 30 99.6 80300\nnrfiles psync 8 1 4 30 99.6 80300\n" > "$d/h"
    a=$(source ./wekatester; cal_plan next lat read psync 8 0 0 "$d/h" $K)
    case "$a" in "done 8 1 2 numjobs=8 iodepth=1 nrfiles=2 -> 99.6 us, 80,300 IOPS "*) true;; *) echo "a=$a" >&2; false;; esac'
t_assert "cal_plan lat1m: the same nrfiles ladder at 1MiB" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" lat1m write io_uring 4 0 0)
    case "$out" in "done 4 1 1 1MiB numjobs=4 iodepth=1 nrfiles=1 -> 800.0 us, 5,000 IOPS (the lowest mean of nrfiles 1 800.0 us, 2 800.0 us, 4 800.0 us at 4 jobs, one job per physical core)") true;;
        *) echo "$out" >&2; false;; esac &&
    [ "$(tr "\n" ";" < "$d/asked")" = "nrfiles 4 1 1;nrfiles 4 1 2;nrfiles 4 1 4;" ]'
# Hand-built histories pin the decisions that a smooth model never exercises.
t_assert "cal_plan: a confirm reading never reopens a step that is already decided" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    plan_sim "$d" iops read io_uring 16 0 0 >>$SUITE_ASIDE
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
    case "$out" in "done 64 16 4 "*"(every rung measured; the best reading wins, ties go heavier, siblings in)") true;; *) echo "$out" >&2; false;; esac &&
    out=$(plan_sim "$d" iops read io_uring 16 0 0 exh=1 confirm=5) &&
    [ "$(grep -c -v "^confirm " "$d/asked")" = 62 ] &&
    out=$(plan_sim "$d" lat read io_uring 32 0 0 exh=1) &&
    [ "$(tr "\n" ";" < "$d/asked")" = "nrfiles 32 1 1;nrfiles 32 1 2;nrfiles 32 1 4;" ] &&
    case "$out" in "done 32 1 1 "*) true;; *) echo "$out" >&2; false;; esac'
# The pick (Frank, 2026-10-23): the best reading wins, ties go heavier, no
# threshold; the 3% stop rule and the cells measured are unchanged.
t_assert "cal_plan brutal: the best reading wins whatever the order, a heavier cell 2.3% ahead included, and a tie goes heavier" bash -c '
    d=$(mktemp -d)
    # N=2, every cell measured: 8 jobs x iodepth 2 nrfiles 1 (16 outstanding)
    # is measured before 8 x 1 nrfiles 2 (8 outstanding)
    for t in bw iops; do
        for pair in "1023 1000 8 2 1" "1000 1000 8 2 1" "1000 1023 8 1 2"; do
            set -- $pair; heavy=$1 light=$2 want="$3 $4 $5"
            : > "$d/h"
            for c in "numjobs 1 1 1" "numjobs 2 1 1" "w 4 1 1" "w 4 2 1" "w 4 1 2" "w 4 2 2" "w 8 1 1" "w 8 2 1" "w 8 1 2" "w 8 2 2"; do
                set -- $c; v=100
                case "$2 $3 $4" in ("8 2 1") v=$heavy;; ("8 1 2") v=$light;; esac
                echo "$1 io_uring $2 $3 $4 30 $v" >> "$d/h"
            done
            a=$(source ./wekatester; cal_plan next $t read io_uring 2 0 0 "$d/h" $K lvl=brutal exh=1 confirm=0 nrc=1,2 bwqd=1,2 iopsqd=1,2)
            case "$a" in "done $want "*) ;; *) echo "$t $pair: $a" >&2; exit 1;; esac
        done
    done'
t_assert "cal_plan safe and max: no threshold -- a heavier rung 1% ahead wins, an exact tie goes heavier, a heavier rung behind never wins" bash -c '
    d=$(mktemp -d)
    for t in bw iops; do
        for lv in "safe 1 1" "max 16 4"; do
            set -- $lv; l=$1 q=$2 r=$3
            for row in "1000 1010 1005 16" "1000 1000 1000 32" "1000 999 990 8" "1000 1029 1029 32"; do
                set -- $row
                printf "numjobs io_uring %s $q $r 15 %s\n" 8 $1 16 $2 32 $3 > "$d/h"
                a=$(source ./wekatester; cal_plan next $t read io_uring 16 0 0 "$d/h" $K lvl=$l fq=$q fn=$r confirm=0)
                case "$a" in "done $4 $q $r "*"(-a $l: "*"the best reading wins, ties go heavier;"*) ;; *) echo "$t $l $row: $a" >&2; exit 1;; esac
            done
        done
    done'
t_assert "cal_plan cal: the 3% stop rule still ends a ladder; the pick is the best reading" bash -c '
    d=$(mktemp -d)
    # 32 jobs: iodepth 2 and 4 are each under 3% past iodepth 1, so the
    # ladder stops after 4 and 64 jobs come next; the best reading, 32 x 4, wins
    k="$K nrc=1 iopsqd=1,2,4,8 confirm=0"
    printf "numjobs io_uring 8 1 1 30 50000\nnumjobs io_uring 16 1 1 30 60000\niodepth io_uring 32 1 1 30 100000\niodepth io_uring 32 2 1 30 102000\niodepth io_uring 32 4 1 30 102900\n" > "$d/h"
    a=$(source ./wekatester; cal_plan next iops read io_uring 16 0 0 "$d/h" $k)
    [ "$a" = "cell iodepth 64 1 1 30" ] || { echo "next: $a" >&2; exit 1; }
    printf "iodepth io_uring 64 1 1 30 100000\niodepth io_uring 64 2 1 30 101000\niodepth io_uring 64 4 1 30 101500\n" >> "$d/h"
    a=$(source ./wekatester; cal_plan next iops read io_uring 16 0 0 "$d/h" $k)
    case "$a" in "done 32 4 1 "*"32 jobs 102,900 IOPS at iodepth 4 nrfiles 1, 64 jobs 101,500 IOPS at iodepth 4 nrfiles 1;"*) true;; *) echo "done: $a" >&2; false;; esac'
t_assert "cal_plan cal: the nrfiles rungs run at the iodepth the pick chooses, not the shallower one the 3% walk led with" bash -c '
    d=$(mktemp -d)
    # 32 jobs: iodepth 4 reads best but never led by 3%; files 2 go to 4 and 8
    k="$K nrc=1,2 iopsqd=1,2,4,8 confirm=0"
    printf "numjobs io_uring 8 1 1 30 50000\nnumjobs io_uring 16 1 1 30 60000\niodepth io_uring 32 1 1 30 100000\niodepth io_uring 32 2 1 30 102000\niodepth io_uring 32 4 1 30 102900\n" > "$d/h"
    a=$(source ./wekatester; cal_plan next iops read io_uring 16 0 0 "$d/h" $k)
    [ "$a" = "cell nrfiles 32 4 2 30" ] || { echo "first: $a" >&2; exit 1; }
    printf "nrfiles io_uring 32 4 2 30 101000\n" >> "$d/h"
    a=$(source ./wekatester; cal_plan next iops read io_uring 16 0 0 "$d/h" $k)
    [ "$a" = "cell nrfiles 32 8 2 30" ] || { echo "second: $a" >&2; false; }'
t_assert "cal_plan budget: the most cells a search can take" bash -c '
    a=$(source ./wekatester; cal_plan budget bw read x 16 0 0 /dev/null $K)
    b=$(source ./wekatester; cal_plan budget lat read x 16 0 0 /dev/null $K)
    c=$(source ./wekatester; cal_plan budget iops read x 16 0 0 /dev/null $K)
    e=$(source ./wekatester; cal_plan budget iops read x 16 0 0 /dev/null $K exh=1 confirm=5)
    f=$(source ./wekatester; cal_plan budget bw read x 16 0 0 /dev/null $K lvl=safe confirm=0)
    g=$(source ./wekatester; cal_plan budget lat read x 16 0 0 /dev/null $K lvl=max confirm=0)
    [ "$a" = 38 ] && [ "$b" = 3 ] && [ "$c" = 33 ] && [ "$e" = 67 ] && [ "$f" = 3 ] && [ "$g" = 3 ] ||
        { echo "bw=$a lat=$b iops=$c brutal-iops=$e safe-bw=$f max-lat=$g" >&2; false; }'
t_assert "cal_plan cal: 4N runs when 2N did not lead N, and a search with no early stop takes exactly its budget" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    # flat at 100,000 IOPS: 2N leads nothing; two-rung ladders cannot plateau
    out=$(CAL_SIM_IOPSCAP=100000 plan_sim "$d" iops read io_uring 16 0 0 nrc=1 iopsqd=1,2) || { echo "$out" >&2; exit 1; }
    grep -q "^iodepth 32 2 1$" "$d/asked" && grep -q "^iodepth 64 1 1$" "$d/asked" && grep -q "^iodepth 64 2 1$" "$d/asked" || { cat "$d/asked" >&2; exit 1; }
    b=$(source ./wekatester; cal_plan budget iops read x 16 0 0 /dev/null $K nrc=1 iopsqd=1,2)
    [ "$b" = 9 ] && [ "$(wc -l < "$d/asked" | tr -d " ")" = "$b" ] || { echo "budget $b"; cat "$d/asked"; false; } >&2'

# -a safe and -a max (Frank, 2026-10-05): numjobs N/2, N and 2N only, at one
# iodepth and nrfiles per type; every rung measured; the best reading wins,
# ties go heavier (Frank, 2026-10-23).
t_assert "cal_plan safe: N/2, N and 2N at iodepth 1 nrfiles 1, every rung measured, no line-rate stop" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" bw read io_uring 16 12500000000 0 lvl=safe fq=1 fn=1 confirm=0)
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 8 1 1;numjobs 16 1 1;numjobs 32 1 1;" ] &&
    case "$out" in "done 32 1 1 numjobs=32 iodepth=1 nrfiles=1 -> 25.00 GiB/s = 214.7% of the 11.64 GiB/s line rate (-a safe: numjobs 8, 16, 32 at iodepth 1 nrfiles 1, the best reading wins, ties go heavier; siblings in)") true;;
        *) echo "$out" >&2; false;; esac'
t_assert "cal_plan safe: no threshold in the pick -- a rung 2% ahead wins, as does one 3% ahead" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    # 16 jobs read 16 GiB/s; 32 jobs are capped 2% above that, and win
    out=$(CAL_SIM_BWCAP=17523466567 plan_sim "$d" bw read io_uring 16 0 0 lvl=safe fq=1 fn=1 confirm=0)
    case "$out" in "done 32 1 1 "*) ;; *) echo "2%: $out" >&2; exit 1;; esac
    out=$(CAL_SIM_BWCAP=17695265479 plan_sim "$d" bw read io_uring 16 0 0 lvl=safe fq=1 fn=1 confirm=0)
    case "$out" in "done 32 1 1 "*) true;; *) echo "3%: $out" >&2; false;; esac'
t_assert "cal_plan max: iops at the fixed iodepth and nrfiles; equal readings go to the heaviest rung" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" iops read io_uring 16 0 0 lvl=max fq=32 fn=2 confirm=0)
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 8 32 2;numjobs 16 32 2;numjobs 32 32 2;" ] &&
    case "$out" in "done 32 32 2 "*"(-a max: numjobs 8, 16, 32 at iodepth 32 nrfiles 2, the best reading wins, ties go heavier; siblings in)") true;;
        *) echo "$out" >&2; false;; esac'
t_assert "cal_plan max: the guards still stop a job count the fixed iodepth cannot fit; pins replace the fixed values" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" iops read libaio 16 0 0 lvl=max fq=32 fn=2 confirm=0 aio=600)
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 8 32 2;numjobs 16 32 2;" ] &&
    case "$out" in *"the job ladder stopped short of numjobs=32 iodepth=32: libaio would set up 1024 aio events and the kernel has room for 600"*) ;; *) echo "$out" >&2; exit 1;; esac
    out=$(plan_sim "$d" bw read io_uring 16 0 0 lvl=safe fq=1 fn=1 confirm=0 pin_qd=4 pin_nj=12)
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 12 4 1;" ] || { cat "$d/asked" >&2; false; }'
t_assert "cal_plan max: a sync engine runs the job counts at iodepth 1, as the ladders give it" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" bw read psync 16 0 0 lvl=max fq=16 fn=4 confirm=0)
    [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 8 1 4;numjobs 16 1 4;numjobs 32 1 4;" ] || { cat "$d/asked" >&2; false; }'

# --- cal_plan batch: every cell the walk can name at once (wtCal, 2026-10-28) ---
# The same model as plan_sim, every cell of a batch read at once. The verdict
# must be next's, and each batch's first line what next would name
# (batch_sim checks that every round).
t_assert "cal_plan batch: cal bw with a target -- the low walk one cell at a time, then the first rung of all six wide ladders" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); p=$(mktemp -d)
    out=$(CAL_SIM_BWCAP=9663676416 batch_sim "$d" bw write libaio 16 12500000000 0) || { echo "$out" >&2; exit 1; }
    ref=$(CAL_SIM_BWCAP=9663676416 plan_sim "$p" bw write libaio 16 12500000000 0)
    [ "$out" = "$ref" ] && case "$out" in "done 64 4 4 "*) true;; *) false;; esac || { echo "batch [$out] next [$ref]" >&2; exit 1; }
    [ "$(sed -n 1,5p "$d/batches" | tr "\n" "|")" = "numjobs 1 1 1|numjobs 2 1 1|numjobs 4 1 1|numjobs 8 1 1|numjobs 16 1 1|" ] &&
    [ "$(sed -n 6p "$d/batches")" = "wide 32 1 1;wide 32 1 2;wide 32 1 4;wide 64 1 1;wide 64 1 2;wide 64 1 4" ] &&
    # the confirm re-reads come as one batch, last
    [ "$(tail -1 "$d/batches")" = "confirm 16 1 1;confirm 32 1 1;confirm 32 1 2" ] &&
    # the same cells as next asked for, fewer rounds
    [ "$(sort "$d/asked")" = "$(sort "$p/asked")" ] && [ "$(wc -l < "$d/batches" | tr -d " ")" -lt "$(wc -l < "$p/asked" | tr -d " ")" ] ||
        { cat "$d/batches" >&2; false; }'
t_assert "cal_plan batch: cal iops -- N/2, N and both queue ladders'\'' first rungs together, a ladder'\''s nrfiles rungs only after its whole ladder" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); p=$(mktemp -d)
    out=$(batch_sim "$d" iops read io_uring 16 0 0) || { echo "$out" >&2; exit 1; }
    ref=$(plan_sim "$p" iops read io_uring 16 0 0)
    [ "$out" = "$ref" ] && case "$out" in "done 64 8 4 "*) true;; *) false;; esac || { echo "batch [$out] next [$ref]" >&2; exit 1; }
    [ "$(sed -n 1p "$d/batches")" = "numjobs 8 1 1;numjobs 16 1 1;iodepth 32 1 1;iodepth 64 1 1" ] &&
    [ "$(sed -n 2p "$d/batches")" = "iodepth 32 2 1;iodepth 64 2 1" ] || { cat "$d/batches" >&2; exit 1; }
    # no batch mixes a job count'\''s nrfiles rungs with its queue rungs, and the
    # last queue rung is asked before the first nrfiles rung, for 32 and for 64
    ! grep -E "iodepth 32 .*nrfiles 32 |nrfiles 32 .*iodepth 32 |iodepth 64 .*nrfiles 64 |nrfiles 64 .*iodepth 64 " "$d/batches" &&
    for nj in 32 64; do
        [ "$(grep -n "^iodepth $nj " "$d/asked" | tail -1 | cut -d: -f1)" -lt "$(grep -n "^nrfiles $nj " "$d/asked" | head -1 | cut -d: -f1)" ] || { cat "$d/asked" >&2; exit 1; }
    done &&
    [ "$(sort "$d/asked")" = "$(sort "$p/asked")" ] || { cat "$d/batches" >&2; false; }'
t_assert "cal_plan batch: lat -- the whole nrfiles ladder in one batch, then done" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); p=$(mktemp -d)
    out=$(CAL_SIM_LATNRBEST=2 batch_sim "$d" lat read io_uring 16 0 0) || { echo "$out" >&2; exit 1; }
    ref=$(CAL_SIM_LATNRBEST=2 plan_sim "$p" lat read io_uring 16 0 0)
    [ "$out" = "$ref" ] && [ "$(cat "$d/batches")" = "nrfiles 16 1 1;nrfiles 16 1 2;nrfiles 16 1 4" ] || { echo "[$out] [$ref]"; cat "$d/batches"; false; } >&2'
t_assert "cal_plan batch: brutal bw and iops -- the whole grid in one batch, the confirm set in the next, then done" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); p=$(mktemp -d)
    for t in bw iops; do
        out=$(batch_sim "$d" $t read io_uring 2 0 0 lvl=brutal exh=1 confirm=3 nrc=1,2 bwqd=1,2 iopsqd=1,2) || { echo "$t: $out" >&2; exit 1; }
        ref=$(plan_sim "$p" $t read io_uring 2 0 0 lvl=brutal exh=1 confirm=3 nrc=1,2 bwqd=1,2 iopsqd=1,2)
        [ "$out" = "$ref" ] || { echo "$t: batch [$out] next [$ref]" >&2; exit 1; }
        b=$(source ./wekatester; cal_plan budget $t read x 2 0 0 /dev/null $K lvl=brutal exh=1 confirm=3 nrc=1,2 bwqd=1,2 iopsqd=1,2)
        # the grid is the budget less the confirm set; two batches in all
        [ "$(wc -l < "$d/batches" | tr -d " ")" = 2 ] &&
        [ "$(sed -n 1p "$d/batches" | tr ";" "\n" | wc -l | tr -d " ")" = "$((b - 3))" ] &&
        [ "$(sed -n 2p "$d/batches" | tr ";" "\n" | grep -c "^confirm ")" = 3 ] &&
        [ "$(sed -n 2p "$d/batches" | tr ";" "\n" | wc -l | tr -d " ")" = 3 ] || { echo "$t: budget $b"; cat "$d/batches"; false; } >&2 || exit 1
    done'
t_assert "cal_plan batch: safe and max -- the three job counts in one batch, then done" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); p=$(mktemp -d)
    out=$(batch_sim "$d" bw read io_uring 16 12500000000 0 lvl=safe fq=1 fn=1 confirm=0) || { echo "$out" >&2; exit 1; }
    ref=$(plan_sim "$p" bw read io_uring 16 12500000000 0 lvl=safe fq=1 fn=1 confirm=0)
    [ "$out" = "$ref" ] && [ "$(cat "$d/batches")" = "numjobs 8 1 1;numjobs 16 1 1;numjobs 32 1 1" ] || { echo "safe [$out] [$ref]"; cat "$d/batches"; false; } >&2 || exit 1
    out=$(batch_sim "$d" iops read io_uring 16 0 0 lvl=max fq=32 fn=2 confirm=0) || { echo "$out" >&2; exit 1; }
    ref=$(plan_sim "$p" iops read io_uring 16 0 0 lvl=max fq=32 fn=2 confirm=0)
    [ "$out" = "$ref" ] && [ "$(cat "$d/batches")" = "numjobs 8 32 2;numjobs 16 32 2;numjobs 32 32 2" ] || { echo "max [$out] [$ref]"; cat "$d/batches"; false; } >&2'
t_assert "cal_plan batch: control -- a batch that names only its first cell fails the bw, lat and brutal checks" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    # the mutant: batch behaves as next (sourcing the tool restores the real
    # cal_plan, so the stand-in wraps it by another name)
    cal_plan_mut() { if [ "$1" = batch ]; then cal_plan "$@" | sed 1q; else cal_plan "$@"; fi; }
    export -f cal_plan_mut; export BATCH_PLAN=cal_plan_mut
    out=$(CAL_SIM_BWCAP=9663676416 batch_sim "$d" bw write libaio 16 12500000000 0) && [ "$(sed -n 6p "$d/batches")" = "wide 32 1 1;wide 32 1 2;wide 32 1 4;wide 64 1 1;wide 64 1 2;wide 64 1 4" ] && { echo "bw check passed under the mutant" >&2; exit 1; }
    out=$(CAL_SIM_LATNRBEST=2 batch_sim "$d" lat read io_uring 16 0 0) && [ "$(cat "$d/batches")" = "nrfiles 16 1 1;nrfiles 16 1 2;nrfiles 16 1 4" ] && { echo "lat check passed under the mutant" >&2; exit 1; }
    out=$(batch_sim "$d" bw read io_uring 2 0 0 lvl=brutal exh=1 confirm=3 nrc=1,2 bwqd=1,2 iopsqd=1,2) && [ "$(wc -l < "$d/batches" | tr -d " ")" = 2 ] && { echo "brutal check passed under the mutant" >&2; exit 1; }
    # the mutant still reaches a verdict: the checks failed on the batches, not on a broken planner
    case "$out" in "done "*) true;; *) echo "mutant: $out" >&2; false;; esac'

# --- N from physical cores (Frank, 2026-09-25): topology, the reserve, placement ---
# topo_fixture <file> <ncpus> <adjacent|split> <weka cpus...>: a probe file with
# one core per sibling pair, numbered 2i/2i+1 (adjacent, as OCI VMs do) or
# i/i+n/2 (split, as most x86 servers do), one socket
topo_fixture() {
    local f=$1 n=$2 how=$3 c k; shift 3
    { printf "ncpus %s\nonline 0-%s\nbindable 0-%s\nbindable_priv -\nengines io_uring libaio psync \n" "$n" "$((n - 1))" "$((n - 1))"
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
    # n ncores dpdk catchall unlisted unbound topo weka_core0 | phys | all | reserved
    out=$(cores_facts "$d/p")
    [ "$out" = "4 8 2 0 0 0 1 0|4,6,8,10|4,5,6,7,8,9,10,11|0-1 2-3" ] || { echo "$out" >&2; false; }'
t_assert "probe_cores: siblings numbered i and i+8 are found from the topology, not by adjacency" bash -c '
    d=$(mktemp -d); topo_fixture "$d/p" 16 split 6 7
    IFS="|" read -r head phys all res <<< "$(cores_facts "$d/p")"
    [ "${head%% *}" = 4 ] && [ "$phys" = 2,3,4,5 ] && [ "$all" = 2,3,4,5,10,11,12,13 ] && [ "$res" = "0,8 1,9" ] || { echo "$head|$phys|$all|$res" >&2; false; }'
t_assert "cores_summary: with weka on core 0, a host-file list reserves nothing more and the sum still adds up" bash -c '
    d=$(mktemp -d); printf "ncpus 8\nbindable 0-7\nbindable_priv -\nweka_allowed 0\nweka_allowed 7\n" > "$d/p"
    out=$(cores_line "$d/p" 2-6)
    case "$out" in "8 physical core(s) (no topology: one per cpu) - 2 weka DPDK - 0 reserved for the OS (none) - 1 outside the host-file cpu list = N=5: "*) true;; *) echo "$out" >&2; false;; esac'
t_assert "probe_cores: a list covering every cpu fio could use counts as none, however it is spelled; a narrower one is the operator reserve" bash -c '
    d=$(mktemp -d)
    # lab 3: 16 cores, siblings adjacent, weka DPDK on 6 of them (2-13): N=7
    # on 18-31, with 0-1 14-15 16-17 reserved
    topo_fixture "$d/p" 32 adjacent 2 4 6 8 10 12
    # field client B: 64 cores without SMT, weka on 48-63: N=41
    { printf "ncpus 64\nbindable 0-63\nbindable_priv -\n"; for c in $(seq 48 63); do printf "weka_allowed %s\n" "$c"; done; } > "$d/q"
    # n ncores dpdk catchall unlisted unbound topo weka_core0 | phys | all | reserved
    all="18,19,20,21,22,23,24,25,26,27,28,29,30,31"
    for l in "" 0-31 1-31 14-31 0-63; do
        IFS="|" read -r head _ a _ <<< "$(cores_facts "$d/p" "$l")"; read -r n _ _ ca _ <<< "$head"
        [ "$n" = 7 ] && [ "$a" = "$all" ] && [ "$ca" = "$([ -n "$l" ] && echo 1 || echo 0)" ] || { echo "list [$l]: $head $a" >&2; exit 1; }
    done
    # the list a calibration writes back leaves the rest of the reserve out: it
    # stays an operator list, and the log line says where the 2 cores went
    IFS="|" read -r head _ _ _ <<< "$(cores_facts "$d/p" 18-31)"; read -r n _ _ ca ul _ <<< "$head"
    [ "$n" = 7 ] && [ "$ca" = 0 ] && [ "$ul" = 2 ] || { echo "18-31: $head" >&2; exit 1; }
    case "$(cores_line "$d/p" 18-31)" in *"- 1 reserved for the OS (0-1) - 2 outside the host-file cpu list = N=7"*) ;; *) echo "18-31 summary" >&2; exit 1;; esac
    # leaving out a cpu fio could use is a choice: 16-31 gets 14-15 back
    [ "$(cores_facts "$d/p" 16-31 | cut -d" " -f1)" = 8 ] || { echo "16-31" >&2; exit 1; }
    for l in 0-255 0-47 1-255 1-47; do
        IFS="|" read -r head _ _ _ <<< "$(cores_facts "$d/q" "$l")"; read -r n _ _ ca _ <<< "$head"
        [ "$n" = 41 ] && [ "$ca" = 1 ] || { echo "q [$l]: $head" >&2; exit 1; }
    done
    [ "$(cores_facts "$d/q" 2-47 | cut -d" " -f1)" = 46 ] || { echo "2-47" >&2; false; }'
t_assert "probe_cores: two sockets reserve core 0 and the next of socket 0, then the first two of socket 1; 5-8 DPDK cores add one" bash -c '
    d=$(mktemp -d)
    { printf "ncpus 64\nonline 0-63\nbindable 0-63\nbindable_priv -\n"
      for c in $(seq 24 31); do printf "weka_allowed %s\n" "$c"; done
      for c in $(seq 0 63); do k=$(( c % 32 ))
          printf "topo_physical_package_id %s %s\ntopo_core_id %s %s\ntopo_thread_siblings_list %s %s,%s\n" $c $(( k / 16 )) $c $k $c $k $(( k + 32 )); done; } > "$d/p"
    # 32 cores, 8 of them DPDK, 5 reserved: 0 and 1 of socket 0, 16 and 17 of
    # socket 1, then 2 -- each with its sibling
    IFS="|" read -r head _ _ res <<< "$(cores_facts "$d/p")"; read -r n nc dp _ <<< "$head"
    [ "$nc" = 32 ] && [ "$dp" = 8 ] && [ "$n" = 19 ] && [ "$res" = "0,32 16,48 1,33 17,49 2,34" ] || { echo "$head|$res" >&2; false; }'
# The core rule, held to the answers the python gave it before it went
# (tests/golden/probe-cores.txt) on every probe shape the suite knows -- topology or
# none, SMT adjacent or split, two sockets, offline and unbindable cpus,
# weka on core 0 -- for no list, operator lists, and catch-alls.
t_assert "probe_cores, cores_summary, reserve_count and probe_aio_room give the recorded answers, probe for probe and list for list" bash -c '
    d=$(mktemp -d)
    topo_fixture "$d/p1" 32 adjacent 2 4 6 8 10 12
    topo_fixture "$d/p2" 16 split 6 7
    { printf "ncpus 64\nbindable 0-63\nbindable_priv -\n"; for c in $(seq 48 63); do printf "weka_allowed %s\n" "$c"; done; } > "$d/p3"
    { printf "ncpus 64\nonline 0-63\nbindable 0-63\nbindable_priv -\n"
      for c in $(seq 24 31); do printf "weka_allowed %s\n" "$c"; done
      for c in $(seq 0 63); do k=$(( c % 32 ))
          printf "topo_physical_package_id %s %s\ntopo_core_id %s %s\ntopo_thread_siblings_list %s %s,%s\n" $c $(( k / 16 )) $c $k $c $k $(( k + 32 )); done; } > "$d/p4"
    printf "ncpus 6\nonline 0-3,6-7\nbindable 0,1,2,3,6\nbindable_priv 7\naio_max_nr 65536\naio_nr 1024\n" > "$d/p5"
    printf "ncpus 8\nbindable 0-7\nbindable_priv -\nweka_allowed 0\nweka_allowed 7\nweka_allowed 0-7\nisolated 4-7\naio_max_nr 100\naio_nr 200\n" > "$d/p6"
    printf "engines psync \nbindable -\n" > "$d/p7"
    { printf "ncpus 6\nonline 2-7\nbindable 2-7\nbindable_priv -\n"
      for c in 2 3 4 5 6 7; do printf "topo_physical_package_id %s %s\ntopo_core_id %s %s\n" $c $(( c / 4 )) $c $(( c / 2 )); done; } > "$d/p8"
    aw=$(source ./wekatester; awkrun "BEGIN {
        nl = split(\"-|0-3|2-6|4-11|18-31|16-31|0-63|1-255\", LS, \"|\")
        for (i = 1; i < ARGC; i++) {
            np = readlines(ARGV[i], P)
            for (j = 1; j <= nl; j++) {
                probe_cores(P, np, LS[j] == \"-\" ? \"\" : LS[j], R, PH, AL); room = probe_aio_room(P, np)
                print R[\"n\"], join_sorted(PH, \",\"), join_sorted(AL, \",\"), R[\"catchall\"], (room == \"\" ? \"None\" : room), cores_summary(R, PH, AL)
            }
        }
        for (n = 1; n < 70; n++) for (k = 0; k < 20; k++) out = out (out == \"\" ? \"\" : \" \") reserve_count(n, k)
        print out
    }" "$d"/p*)
    want=$(cat tests/golden/probe-cores.txt) && [ -n "$aw" ] && [ "$aw" = "$want" ] || { printf "want:\n%s\nawk:\n%s\n" "$want" "$aw" >&2; false; }'
t_assert "reserve rules: 2 up to 24 cores, 4 above, +1 per 4 DPDK past 4, at most 12 and half; round-robin placement" bash -c '
    out=$(source ./wekatester; awkrun "
    function placed(SOCK, DP, want,    n, R, i, s) {
        n = place_reserve(ORD, 8, SOCK, DP, 0, want, R); s = \"\"
        for (i = 1; i <= n; i++) s = s (i > 1 ? \",\" : \"\") R[i]
        return s
    }
    BEGIN {
        print reserve_count(8, 2), reserve_count(24, 4), reserve_count(25, 4), reserve_count(64, 5), reserve_count(64, 8), reserve_count(64, 9), reserve_count(200, 64), reserve_count(4, 8), reserve_count(2, 0)
        for (k = 0; k < 8; k++) { ORD[k + 1] = k; ONE[k] = 0; FOUR[k] = int(k / 2) }
        split(\"\", NONE); D01[0] = 1; D01[1] = 1
        print placed(ONE, NONE, 4); print placed(FOUR, NONE, 4); print placed(ONE, D01, 2)
    }")
    # at most 12, never more than half the cores, core 0 always; one core per
    # socket; a DPDK core is never reserved, not even core 0
    [ "$out" = "2 2 4 5 5 6 12 2 1
0,1,2,3
0,2,4,6
2,3" ] || { echo "$out" >&2; false; }'
t_assert "tuner: a client too small for its DPDK cores stops, naming the arithmetic" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    # lab 3 as built: 8 cores, 6 of them weka DPDK -- the reserve wants 3, gets 2
    topo_fixture "$FIX/probe/h1" 16 adjacent 4 6 8 10 12 14; cp "$FIX/probe/h1" "$FIX/probe/h2"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 ) && { echo "no stop" >&2; exit 1; }
    case "$err" in *"h1: no cpus left for fio -- 8 physical core(s) - 6 weka DPDK - 2 reserved for the OS (0-1 2-3) = N=0"*) true;; *) echo "$err" >&2; false;; esac'
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
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
    grep -qx "cpus_allowed=4,6,8,10" "$FIX/jobs/h1/011-bw.job" || { grep cpus_allowed "$FIX/jobs/h1/011-bw.job" >&2; exit 1; }
    # h2 has no host-file row: it keeps the jobfile 4 jobs, N here, one per physical core
    grep -qx "numjobs=4" "$FIX/jobs/h2/011-bw.job" && grep -qx "cpus_allowed=4,6,8,10" "$FIX/jobs/h2/011-bw.job" &&
    row 8 > "$FIX/targets.final" &&
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1 &&
    grep -qx "cpus_allowed=4-11" "$FIX/jobs/h1/011-bw.job"'

t_assert "tuner: a narrower host-file cpu list rescues a client the default rule leaves no cpus; one covering them all does not" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    # 8 cores, 5 of them weka DPDK (6-15): the default reserve takes 0-1, 2-3
    # and 4-5, and nothing is left
    topo_fixture "$FIX/probe/h1" 16 adjacent 6 8 10 12 14; cp "$FIX/probe/h1" "$FIX/probe/h2"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) 2>&1 ) && { echo "no list: no stop" >&2; exit 1; }
    case "$err" in *"h1: no cpus left for fio"*"or name the cpus in the host file"*) ;; *) echo "$err" >&2; exit 1;; esac
    rows() { for h in h1 h2; do printf "%s\t-\t-\t%s\t-" "$h" "$1"; for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; done; }
    # 2-5 is every cpu fio could use: no list, so the same reserve and stop
    rows 2-5 > "$FIX/targets.final"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) 2>&1 ) && { echo "2-5: no stop" >&2; exit 1; }
    case "$err" in *"h1: the host file'"'"'s cpu list (2-5) covers every cpu fio could use, which counts as no list"*"list fewer cpus"*) ;; *) echo "$err" >&2; exit 1;; esac
    # 4-5 leaves 2-3 out, so it is an operator reserve: only core 0 is held back
    rows 4-5 > "$FIX/targets.final"
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) 2>&1 ) || { echo "$out" >&2; exit 1; }
    grep -qx "cpus_allowed=4-5" "$FIX/jobs/h1/011-bw.job" || { grep cpus_allowed "$FIX/jobs/h1/011-bw.job" >&2; false; }'
t_assert "pinning: core 0 and its sibling never execute, whatever the host-file list says" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    topo_fixture "$d/probe/h1" 8 adjacent 6
    printf "taskset 0-7\n" >> "$d/probe/h1"
    printf "h1\t-\t-\t0-5\t-\n" > "$d/targets.final"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; check_cpu_pinning) 2>&1 )
    [ "$(cat "$d/auth/h1.cpus")" = "2-5" ] &&
    case "$out" in *"requested cpus (0-5) include core 0'"'"'s pair (0-1), which stays with the OS; executing on the remainder (2-5)"*) true;; *) echo "$out" >&2; false;; esac &&
    printf "h1\t-\t-\t0-1\t-\n" > "$d/targets.final" &&
    err=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; check_cpu_pinning) 2>&1 ); [ $? -ne 0 ] &&
    case "$err" in *"core 0 and its sibling (0-1) stay with the OS"*) true;; *) echo "$err" >&2; false;; esac'

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
    (source ./wekatester; stage_floor_twins "$FIX/src") >>$SUITE_ASIDE
    # the calibrated lat_r tuple: 3 jobs, 4 files of 1280M, qd 1 (cols 14-17)
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (14) printf "\t3";; (15) printf "\t1280M";; (16) printf "\t4";; (17) printf "\t1";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
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
# An unquoted "0-3, 8" splits into a cell and shifts every later column: a
# full row grows past the last column, a short one moves " 8" into the dir.
t_assert "targets: an unquoted cpu list stops the run, naming the line and asking for quotes" bash -c '
    f=$(mktemp); g=$(mktemp)
    printf "host,user_login,ioengine,allowed_cpus,destination_folder\nh1,ubuntu,io_uring,0-3, 8,/mnt/weka,12/10G/2/8,12/10G/2/4,1/1G/2/1,1/1G/2/1,42/256M/2/16,42/256M/2/8,1/1G/1/1,1/1G/1/1\n" > "$f"
    printf "# a short row\nh1,ubuntu,io_uring,0-3, 8,/mnt/weka\n" > "$g"
    e1=$( (rt phase1 "$f" - - - h1) 2>&1 >>$SUITE_ASIDE ); r1=$?
    e2=$( (rt phase1 "$g" - - - h1) 2>&1 >>$SUITE_ASIDE ); r2=$?
    [ "$r1" -ne 0 ] && [ "$r2" -ne 0 ] &&
    case "$e1" in (*"$f:2: 14 cells"*"at most 13"*"quote cpu lists"*) true;; (*) false;; esac &&
    case "$e2" in (*"$g:2: destination dir '\''8'\''"*"quote cpu lists"*) true;; (*) false;; esac ||
        { echo "r1=$r1 e1=$e1 r2=$r2 e2=$e2" >&2; false; }'
t_assert "targets: the same cpu list quoted parses, as do trailing empty cells and the template with its example row" bash -c '
    f=$(mktemp); d=$(mktemp -d)
    printf "host,user_login,ioengine,allowed_cpus,destination_folder\nh1,ubuntu,io_uring,\"0-3, 8\",/mnt/weka,12/10G/2/8,12/10G/2/4,1/1G/2/1,1/1G/2/1,42/256M/2/16,42/256M/2/8,1/1G/1/1,1/1G/1/1,,\n" > "$f"
    a=$(rt phase1 "$f" - - - h1 | awk -F"\t" "{print NF \"|\" \$4 \"|\" \$5 \"|\" \$6 \"|\" \$37}")
    (source ./wekatester; write_targets_template "$d/t.csv") >>$SUITE_ASIDE 2>&1 &&
    sed -n "s/^# Example:  \(client-1,.*\)/\1/p" "$d/t.csv" >> "$d/t.csv" &&
    b=$(rt phase1 "$d/t.csv" - - - client-1 | awk -F"\t" "{print \$3 \"|\" \$4 \"|\" \$5 \"|\" \$30}")
    [ "$a" = "37|0-3, 8|/mnt/weka|12|1" ] && [ "$b" = "io_uring|8,10|/mnt/weka|-" ] || { echo "a=$a b=$b" >&2; false; }'
t_assert "targets: the template glob example, uncommented, resolves for a host it matches" bash -c '
    d=$(mktemp -d)
    (source ./wekatester; write_targets_template "$d/t.csv") >>$SUITE_ASIDE 2>&1 &&
    sed -n "s/^# Example:  \(gpu-\*,[^ ]*\).*/\1/p" "$d/t.csv" >> "$d/t.csv" &&
    b=$(rt phase1 "$d/t.csv" - - - gpu-01 h1 | cut -f1,2,5 | tr "\t\n" " ;")
    [ "$b" = "gpu-01 ubuntu /mnt/weka;h1 - -;" ] || { echo "b=$b" >&2; false; }'
t_assert "writeback: a measured 1MiB latency tuple lands in its own column" bash -c '
    d=$(mktemp -d); mkdir -p "$d/jobs/h1" "$d/auth"
    : > "$d/engine.results"
    printf "h1 libaio - - - - - - - - - - - - - - - - - - - - - - - - 1 1 5120M 6 - - - -\n" > "$d/cal.results"
    f="$d/host.csv"; printf "host,user_login,ioengine\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=cal; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }   # no ssh to a fixture host
     writeback_targets) >>$SUITE_ASIDE
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
    case "$out" in *"lat-read: numjobs=5 iodepth=1 nrfiles=1 -> 100.0 us"*"lat1m-read: 1MiB numjobs=5 iodepth=1 nrfiles=1 -> 1000.0 us"*) true;; *) printf "%s\n" "$out" >&2; false;; esac &&
    # both latency tests run at N=5 jobs; only nrfiles is searched
    [ "$(cut -d" " -f11-14,27-30 "$d/cal.results")" = "1 1 5120M 5 1 1 5120M 5" ] || { cat "$d/cal.results" >&2; false; }'

# --- --line-rate, the libaio aio room, and catch-all cpu lists ---
t_assert "--line-rate takes 0.1 to 100000 Gb/s, attached or separate, and needs -a" bash -c '
    (source ./wekatester; parse_args -a cal --line-rate 16 h1; [ "$LINE_RATE_GBPS" = 16 ]) &&
    (source ./wekatester; parse_args -a brutal --LINE-RATE=12.5 h1; [ "$LINE_RATE_GBPS" = 12.5 ]) &&
    (source ./wekatester; parse_args --line-rate=0.1 -a cal h1; [ "$LINE_RATE_GBPS" = 0.1 ]) || exit 1
    for v in 0 abc 1.2.3 -5 0.05 100001 1e3; do
        if err=$( (source ./wekatester; parse_args -a cal "--line-rate=$v" h1) 2>&1 ); then echo "accepted $v" >&2; exit 1; fi
        case "$err" in *"ERROR: --line-rate"*) ;; *) echo "$v: $err" >&2; exit 1;; esac
    done
    # an empty value, as an unset variable in a wrapper gives, is no override
    if err=$( (source ./wekatester; parse_args -a cal --line-rate "" h1) 2>&1 ); then echo "accepted an empty value" >&2; exit 1; fi
    case "$err" in *"ERROR: option --line-rate requires a value"*) ;; *) echo "$err" >&2; exit 1;; esac
    (source ./wekatester; parse_args -a max --line-rate 16 h1; [ "$LINE_RATE_GBPS" = 16 ]) || exit 1
    if err=$( (source ./wekatester; parse_args --line-rate 16 h1) 2>&1 ); then echo "accepted without -a" >&2; exit 1; fi
    case "$err" in *"ERROR: --line-rate sets the bandwidth target of a calibration: it needs -a"*) ;; *) echo "$err" >&2; exit 1;; esac'
t_assert "cal_shapes: --line-rate replaces ethtool's figure, and gives a host with no weka CLI a target" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8 h3:8
    sed -i.b "/^weka_net /d" "$d/probe/h3"; echo "weka_cli absent" >> "$d/probe/h3"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h3); REGEN_LAYOUT=0; LINE_RATE_GBPS=16
            cal_shapes "$d/shapes" "bw read") 2>&1 )
    [ "$(cut -f6 "$d/shapes" | tr "\n" " ")" = "2000000000 2000000000 " ] || { cat "$d/shapes" >&2; exit 1; }
    case "$out" in *"100 Gb/s -> line rate 11.64 GiB/s; line rate 1.86 GiB/s from --line-rate 16 Gb/s in place of ethtool'"'"'s"*"no weka CLI on the host; line rate 1.86 GiB/s from --line-rate 16 Gb/s"*) true;;
        *) echo "$out" >&2; exit 1;; esac
    # with no weka CLI there is no ethtool figure to stand in for
    case "$out" in *"no weka CLI on the host; line rate 1.86 GiB/s from --line-rate 16 Gb/s in place of"*) echo "$out" >&2; exit 1;; esac
    case "$out" in *"no line-rate target"*) echo "$out" >&2; false;; *) true;; esac'
t_assert "cal_shapes: --line-rate measures a bandwidth answer the host file carries again; the others still pin" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8
    # bw_r nj/fs/nr/qd are cols 6-9, iops_r cols 22-25
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (6) printf "\t3";; (7|23) printf "\t5120M";; (8|9|24) printf "\t1";; (22) printf "\t10";; (25) printf "\t16";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$d/targets.final"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=0; LINE_RATE_GBPS=16
            cal_shapes "$d/shapes" "$(printf "bw read\niops read\n")") 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cut -f11 "$d/shapes")" = "iops_r=16/1/5120M/10" ] || { cut -f11 "$d/shapes" >&2; exit 1; }
    case "$out" in *"--line-rate: the host file'"'"'s bandwidth answer (bw_r) is measured again against it and replaced; its other values still pin their knobs"*) ;; *) echo "$out" >&2; exit 1;; esac
    # without the flag the recorded answer stands, and nothing says otherwise
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=0
            cal_shapes "$d/shapes" "$(printf "bw read\niops read\n")") 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cut -f11 "$d/shapes")" = "bw_r=1/1/5120M/3 iops_r=16/1/5120M/10" ] || { cut -f11 "$d/shapes" >&2; exit 1; }
    case "$out" in *"measured again"*) echo "$out" >&2; false;; *) true;; esac'
t_assert "cal_shapes: a shape's aio room is its tightest member's, and unknown when no probe could tell" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8 h2:8 h3:8
    printf "aio_max_nr 1048576\naio_nr 0\n" >> "$d/probe/h1"
    printf "aio_max_nr 65536\naio_nr 1024\n" >> "$d/probe/h2"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2 h3); REGEN_LAYOUT=0
            cal_shapes "$d/shapes" "iops write") 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cut -f2,10,12 "$d/shapes" | tr "\t" "|")" = "h1|64512|h1 h2 h3" ] || { cat "$d/shapes" >&2; exit 1; }
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h3); REGEN_LAYOUT=0
            cal_shapes "$d/shapes" "iops write") 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cut -f10 "$d/shapes")" = "-" ] || { cat "$d/shapes" >&2; false; }'
t_assert "cal_shapes: reads the host file's cpu list as written, so a catch-all is seen as one" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8
    printf "h1\t-\t-\t0-255\t-\n" > "$d/targets.final"
    # check_cpu_pinning trimmed the same list to 1-6 for the fio server: read
    # instead, it would keep the operator-list exemption (N=6) while the tuner
    # staged the full reserve (N=5)
    printf "1-6\n" > "$d/auth/h1.cpus"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=0; AUTH_DIR=$d/auth
            cal_shapes "$d/shapes" "bw read") 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cut -f3-5 "$d/shapes" | tr "\t" "|")" = "5|2-6|2-6" ] || { cat "$d/shapes" >&2; false; }'
t_assert "probe: the kernel's aio limit and use come along as aio_max_nr and aio_nr" bash -c '
    d=$(mktemp -d); r=$d/root; mkdir -p "$r/proc/sys/fs"
    echo 65536 > "$r/proc/sys/fs/aio-max-nr"; echo 1024 > "$r/proc/sys/fs/aio-nr"
    cmd=$(source ./wekatester; FIO_BIN=fio; probe_remote_cmd)
    out=$(WEKATESTER_SYSROOT=$r bash -c "$cmd" 2>&1)
    printf "%s\n" "$out" | grep -qx "aio_max_nr 65536" && printf "%s\n" "$out" | grep -qx "aio_nr 1024" &&
    printf "%s\n" "$out" > "$d/p" &&
    room() { (source ./wekatester; awkrun "BEGIN { np = readlines(ARGV[1], P); r = probe_aio_room(P, np); print (r == \"\" ? \"None\" : r) }" "$1"); }
    [ "$(room "$d/p")" = 64512 ] &&
    printf "ncpus 4\n" > "$d/q" &&
    [ "$(room "$d/q")" = None ]'
t_assert "cal_plan: libaio stops a queue ladder at the kernel's aio room, and says how to go deeper" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    # field client B, 2026-09-25: 188 jobs x 512 set up more aio events than 65,536;
    # the ladder is cut to its deep end, where the room bites
    out=$(plan_sim "$d" iops write libaio 47 0 0 exh=1 aio=65536 iopsqd=256,512) || { echo "$out" >&2; exit 1; }
    ! awk "\$2 * \$3 > 65536" "$d/asked" | grep -q . || { awk "\$2 * \$3 > 65536" "$d/asked" >&2; exit 1; }
    grep -q "^iodepth 188 256 1$" "$d/asked" || { cat "$d/asked" >&2; exit 1; }
    case "$out" in *"the queue ladder stopped short of numjobs=188 iodepth=512: libaio would set up 96256 aio events and the kernel has room for 65536 (raise fs.aio-max-nr and re-measure with -g to search deeper)"*) true;;
        *) echo "$out" >&2; exit 1;; esac
    # io_uring owes the aio limit nothing
    plan_sim "$d" iops write io_uring 47 0 0 exh=1 aio=65536 iopsqd=256,512 >>$SUITE_ASIDE &&
    grep -q "^iodepth 188 512 1$" "$d/asked"'
t_assert "cal_plan bw: a guard that refuses 2N outright is not reported as 2N losing" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" bw read libaio 47 0 0 aio=50) || { echo "$out" >&2; exit 1; }
    ! grep -Eq "^wide (94|188) " "$d/asked" || { cat "$d/asked" >&2; exit 1; }
    case "$out" in *"stopped short of numjobs=94 iodepth=1: libaio would set up 94 aio events and the kernel has room for 50"*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *"did not beat N"*) echo "$out" >&2; false;; *) true;; esac'
t_assert "cal_plan: a cell both guards refuse names both, with no advice to raise the aio limit alone" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    # 150 MiB of in-flight buffers, room for 100 aio events: 94 x 2 fails both
    out=$(plan_sim "$d" bw write libaio 47 0 157286400 exh=1 aio=100) || { echo "$out" >&2; exit 1; }
    case "$out" in *"stopped short of numjobs=94 iodepth=2: its in-flight buffers exceed the memory guard (CAL_MEM_PCT) and libaio would set up 188 aio events and the kernel has room for 100"*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *"raise fs.aio-max-nr"*) echo "$out" >&2; false;; *) true;; esac'
t_assert "cal_plan cal and brutal: when a guard refuses every cell the search stops naming it, never a zero tuple" bash -c '
    d=$(mktemp -d); : > "$d/h"
    no_fit() {   # no_fit <bw|iops> <engine> <memcap> <want> <k=v>...
        local t=$1 e=$2 mc=$3 want=$4 l out what=bandwidth; shift 4
        [ "$t" = bw ] || what=IOPS
        for l in "cal exh=0 confirm=3" "brutal exh=1 confirm=5"; do
            out=$( (source ./wekatester; cal_plan next "$t" read "$e" 8 0 "$mc" "$d/h" $K lvl=$l "$@") 2>&1 ) &&
                { echo "no stop ($t $e $l $*): $out" >&2; return 1; }
            case "$out" in *"ERROR: cal_plan: -a ${l%% *}: no $what cell fits (pinned by the host file: numjobs="*"$want"*) ;;
                *) echo "$t $e $l $*: $out" >&2; return 1;; esac
        done
    }
    no_fit bw libaio 0 "stopped short of numjobs=32 iodepth=1: libaio would set up 32 aio events and the kernel has room for 16" pin_nj=32 aio=16 &&
    no_fit iops libaio 0 "stopped short of numjobs=32 iodepth=1: libaio would set up 32 aio events and the kernel has room for 16" pin_nj=32 aio=16 &&
    no_fit iops libaio 0 "stopped short of numjobs=32 iodepth=8: libaio would set up 256 aio events and the kernel has room for 100" pin_nj=32 aio=100 iopsqd=8,16 &&
    no_fit bw psync 33554432 "stopped short of numjobs=64 iodepth=1: its in-flight buffers exceed the memory guard (CAL_MEM_PCT)" pin_nj=64 &&
    no_fit iops psync 131072 "stopped short of numjobs=64 iodepth=1: its in-flight buffers exceed the memory guard (CAL_MEM_PCT)" pin_nj=64'
t_assert "cal_plan: the aio guard holds at or below N too -- no job count runs past the room, and none wider is tried" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    over() { ! awk -v r="$1" "\$2 * \$3 > r" "$d/asked" | grep -q . || { cat "$d/asked" >&2; false; }; }
    # Bugbot "Aio guard skipped on low rungs": iodepth 64 pinned, room 256
    out=$(plan_sim "$d" iops read libaio 8 0 0 pin_qd=64 aio=256) || { echo "$out" >&2; exit 1; }
    over 256 && [ "$(tr "\n" ";" < "$d/asked")" = "numjobs 4 64 1;confirm 4 64 1;" ] || exit 1
    case "$out" in "done 4 64 1 "*"the job ladder stopped short of numjobs=8 iodepth=64: libaio would set up 512 aio events and the kernel has room for 256 (raise fs.aio-max-nr"*) ;; *) echo "$out" >&2; exit 1;; esac
    out=$(CAL_SIM_BWCAP=1125899906842624 plan_sim "$d" bw read libaio 8 0 0 pin_qd=64 aio=256) || { echo "$out" >&2; exit 1; }
    over 256 && grep -q "^numjobs 4 64 1$" "$d/asked" && ! grep -q "^wide " "$d/asked" || exit 1
    # nothing pinned: N=64 at iodepth 1 is past a room of 32
    out=$(plan_sim "$d" iops read libaio 64 0 0 aio=32) || { echo "$out" >&2; exit 1; }
    over 32 && grep -q "^numjobs 32 1 1$" "$d/asked" || exit 1
    # no room even for one job: the search stops, naming the guard
    err=$( (source ./wekatester; : > "$d/e"; cal_plan next bw read libaio 8 0 0 "$d/e" $K aio=0) 2>&1 ) && { echo "no stop: $err" >&2; exit 1; }
    case "$err" in *"no bandwidth cell fits (the job ladder stopped short of numjobs=1 iodepth=1: libaio would set up 1 aio events and the kernel has room for 0"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "libaio_events:numjobs x iodepth per section, summed while sections run together, a stonewall starting a new group" bash -c '
    d=$(mktemp -d)
    printf "[global]\nioengine=libaio\nnumjobs=4\n[create]\ncreate_only=1\n[io]\nstonewall\niodepth=32\n" > "$d/a"
    printf "[global]\nioengine=libaio\n[r]\nnumjobs=3\niodepth=8\n[w]\nnumjobs=2\niodepth=16\n" > "$d/b"
    printf "[global]\nioengine=io_uring\nnumjobs=64\niodepth=512\n[x]\n" > "$d/c"
    out=$(source ./wekatester; awkrun "BEGIN { for (i = 1; i < ARGC; i++) { n = readlines(ARGV[i], L); printf \"%s%s\", (i > 1 ? \" \" : \"\"), libaio_events(L, n) } print \"\" }" "$d/a" "$d/b" "$d/c")
    [ "$out" = "128 56 0" ] || { echo "$out" >&2; false; }'
t_assert "check_aio_room: a staged libaio job past its host's aio room stops the run before it starts, naming fs.aio-max-nr" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/jobs/h1" "$d/jobs/h2"
    printf "aio_max_nr 65536\naio_nr 0\n" > "$d/probe/h1"
    printf "aio_max_nr 1048576\naio_nr 0\n" > "$d/probe/h2"
    for h in h1 h2; do
        printf "[global]\nioengine=libaio\nnumjobs=188\n[create]\ncreate_only=1\n[io]\nstonewall\niodepth=512\n" > "$d/jobs/$h/032-iopsW.job"
        printf "[global]\nioengine=libaio\nnumjobs=4\n[r]\niodepth=16\n" > "$d/jobs/$h/011-bw.job"
    done
    err=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2); check_aio_room) 2>&1 ) && { echo "no stop: $err" >&2; exit 1; }
    case "$err" in *"ERROR: 032-iopsW.job: libaio sets up 96256 aio events at once (numjobs x iodepth) on h1, and the kernel has room for 65536"*"raise fs.aio-max-nr"*"nothing was run and the host file is unchanged"*) ;; *) echo "$err" >&2; exit 1;; esac
    case "$err" in *"011-bw.job"*|*" on h2"*|*"h1 h2"*) echo "$err" >&2; false;; *) true;; esac'
t_assert "tuner: a catch-all cpu list the OS reserve empties says so, and how to keep an own reserve" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    # 8 cores, 6 of them weka DPDK: 0-15 covers every cpu fio could use, so
    # the reserve takes 0-1 and 2-3 and nothing is left
    topo_fixture "$FIX/probe/h1" 16 adjacent 4 6 8 10 12 14; cp "$FIX/probe/h1" "$FIX/probe/h2"
    { printf "h1\t-\t-\t0-15\t-"; for i in $(seq 6 37); do printf "\t-"; done; printf "\n"
      printf "h2\t-\t-\t0-15\t-"; for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; } > "$FIX/targets.final"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && case "$err" in *"h1: the host file'"'"'s cpu list (0-15) covers every cpu fio could use, which counts as no list"*"list fewer cpus (a narrower list is the operator"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "pinning: under -a a list covering every cpu fio could use follows the tuner -- one note, the reserve out of the effective set" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    printf "ncpus 64\ntaskset 0-63\nbindable 0-63\nbindable_priv -\nweka_allowed 52\nweka_allowed 53\n" > "$d/probe/h1"
    # every cpu the host has and more, or every cpu but weka and core 0: the same
    for l in 0-128 1-51,54-63; do
        printf "h1\t-\t-\t%s\t-\n" "$l" > "$d/targets.final"
        out=$( (source ./wekatester
            WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; AUTO_LEVEL=cal
            check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
        case "$out" in *"note: h1: requested cpus ($l) cover every cpu fio could use, which counts as no list: the OS reserve applies as if the host file gave none; executing on 4-51,54-63"*) ;; *) echo "$out" >&2; exit 1;; esac
        case "$out" in *"does not have"*|*"core 0"*|*"overlap"*) echo "$out" >&2; exit 1;; esac
        [ "$(cat "$d/auth/h1.cpus")" = "4-51,54-63" ] || { echo "$l: $(cat "$d/auth/h1.cpus")" >&2; exit 1; }
    done'
t_assert "pinning: weka's dedicated cores leave with their siblings, whatever the list says" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    # the weka io thread on 4: its sibling 5 is weka too (a plain run, no reserve)
    topo_fixture "$d/probe/h1" 8 adjacent 4
    printf "taskset 0-7\n" >> "$d/probe/h1"
    printf "h1\t-\t-\t2-7\t-\n" > "$d/targets.final"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cat "$d/auth/h1.cpus")" = "2-3,6-7" ] || { cat "$d/auth/h1.cpus" >&2; echo "$out" >&2; false; }'
t_assert "pinning: a host with no cpu list is pinned off weka's cores and core 0's pair too, every run" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    # 4 cores, siblings adjacent, weka on core 2 (cpus 4 and 5); no host file at all
    topo_fixture "$d/probe/h1" 8 adjacent 4
    printf "taskset 0-7\n" >> "$d/probe/h1"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2); AUTH_DIR=$d/auth; check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cat "$d/auth/h1.cpus")" = "2-3,6-7" ] || { echo "plain: $(cat "$d/auth/h1.cpus") $out" >&2; exit 1; }
    case "$out" in *"note: fio stays off weka'"'"'s pinned cores and core 0'"'"'s pair on the 1 host(s) the host file gives no cpu list (h1: 2-3,6-7)"*) ;; *) echo "$out" >&2; exit 1;; esac
    case "$out" in *"requested cpus"*) echo "a request note for no request: $out" >&2; exit 1;; esac
    # h2 was never probed: nothing to pin against
    [ ! -e "$d/auth/h2.cpus" ] || { echo "h2 pinned blind" >&2; exit 1; }
    # a probe that cannot say which cpus exist pins nothing and kills nothing
    printf "taskset 0-7\n" > "$d/probe/h3"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h3); AUTH_DIR=$d/auth; check_cpu_pinning) 2>&1 ) || { echo "partial probe died: $out" >&2; exit 1; }
    [ ! -e "$d/auth/h3.cpus" ] || { echo "h3 pinned on nothing: $(cat "$d/auth/h3.cpus")" >&2; exit 1; }
    # under -a the tuner set, reserve and all: N=1 on core 3
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); AUTH_DIR=$d/auth; AUTO_LEVEL=cal; check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cat "$d/auth/h1.cpus")" = "6-7" ] || { echo "auto: $(cat "$d/auth/h1.cpus") $out" >&2; exit 1; }
    # and main probes and pins on every run, not only under -a, -t or -e
    m=$(sed -n "/^main() {/,/^}/p" ./wekatester)
    run=$(printf "%s\n" "$m" | sed -n "/RUN_DIR=/,/start_fio_servers/p")
    printf "%s\n" "$run" | grep -q "^    probe_workers$" && printf "%s\n" "$run" | grep -q "^    check_cpu_pinning$" ||
        { printf "%s\n" "$run" >&2; false; }'
t_assert "tuner: a one-job latency twin prints no numjobs note of its own" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    rm -f "$FIX/src/011-bw.job"
    printf "# report latency\n[global]\nfilesize=10G\nnumjobs=1\nioengine=libaio\n[lat]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; stage_floor_twins "$FIX/src") >>$SUITE_ASIDE
    # lat_r (cols 14-17): 6 jobs past the 3 usable threads -- the original
    # gets the note once, its one-job twin none
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (14) printf "\t6";; (15) printf "\t1280M";; (16) printf "\t4";; (17) printf "\t1";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$FIX/targets.final"
    err=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) 2>&1 >>$SUITE_ASIDE ) || { echo "$err" >&2; exit 1; }
    [ "$(printf "%s\n" "$err" | grep -c "lat_r_nj=6 runs up to 2 jobs per cpu")" = 1 ] || { echo "$err" >&2; false; }'

# --- engine choice: one per shape, from the type winners ---
t_assert "cal_engine_pick: per-type winners, ties to io_uring, the tally picks the shape engine" bash -c '
    d=$(mktemp -d)
    printf "bw io_uring 1000\nbw libaio 1000\nbw psync 999\niops io_uring 900\niops libaio 1000\niops psync 200\nlat io_uring 100\nlat libaio 100.5\nlat psync 90\n" > "$d/e"
    a=$(source ./wekatester; cal_engine_pick "$d/e")
    case "$a" in "io_uring bw: "*"-> io_uring; iops: "*"-> libaio; lat: "*"-> psync") true;; *) echo "a=$a" >&2; false;; esac &&
    printf "lat io_uring 100\nlat psync 95\n" > "$d/f" &&
    b=$(source ./wekatester; cal_engine_pick "$d/f") &&
    case "$b" in "psync lat: io_uring 100.0 us, psync 95.0 us -> psync") true;; *) echo "b=$b" >&2; false;; esac'
# Frank, 2026-10-23: no band; the best reading wins, an exact tie by ENGINE_ORDER
t_assert "cal_engine_pick: the best reading wins with no band -- 1% ahead is enough, for latency too" bash -c '
    d=$(mktemp -d)
    printf "bw io_uring 990\nbw libaio 1000\niops io_uring 1000\niops psync 1001\nlat io_uring 100\nlat libaio 99.5\n" > "$d/e"
    a=$(source ./wekatester; cal_engine_pick "$d/e")
    case "$a" in "libaio bw: "*"-> libaio; iops: "*"-> psync; lat: "*"-> libaio") true;; *) echo "a=$a" >&2; false;; esac'
t_assert "cal_engine_pick: an exact tie goes by ENGINE_ORDER, in a type and in the tally" bash -c '
    d=$(mktemp -d)
    printf "bw psync 1000\nbw libaio 1000\niops psync 900\niops libaio 900\niops io_uring 800\nlat psync 90\nlat libaio 95\n" > "$d/e"
    a=$(source ./wekatester; cal_engine_pick "$d/e")
    case "$a" in "libaio bw: "*"-> libaio; iops: "*"-> libaio; lat: "*"-> psync") true;; *) echo "a=$a" >&2; false;; esac &&
    printf "bw psync 1000\nbw libaio 900\niops libaio 1000\niops psync 900\n" > "$d/f" &&
    b=$(source ./wekatester; cal_engine_pick "$d/f") &&
    case "$b" in "libaio bw: "*"-> psync; iops: "*"-> libaio") true;; *) echo "b=$b" >&2; false;; esac'
t_assert "cal_shape_run: engine cells on a pinned 32-job x 64-file shape seed it first (review #17)" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     WORK_DIR=$d; DIRECTORY=/mnt/weka; CAL_SETTLE=0
     cal_ensure_seed() { echo "seed $*" >> "$d/calls"; }
     cal_run_cell() { echo "cell $*" >> "$d/calls"; CAL_READING=1000; }
     cal_search() { echo "search $*" >> "$d/calls"; }
     cal_shape_run 1 h1 8 0-7 0-15 0 libaio,psync - 0 64 "bw_r=1/64/-/32" "bw read") >>$SUITE_ASIDE 2>&1 ||
        { echo "cal_shape_run failed" >&2; exit 1; }
    # the seed covering 32 jobs x 64 files lands before the first engine cell
    awk "/^seed h1 read 32 64\$/ && !s {s = NR} /^cell / && !c {c = NR} END {exit !(s && c && s < c)}" "$d/calls" &&
    [ "$(grep -c "^cell h1 bw read [a-z]* 32 1 64 " "$d/calls")" = 2 ] || { cat "$d/calls" >&2; false; }'
t_assert "cal_shape_run: a libaio engine cell past the aio room is skipped and the engine chosen from the others" bash -c '
    d=$(mktemp -d)
    # room 16: the bw cell (8 jobs x iodepth 1) fits, the iops one (8 x 16) does not
    out=$( (source ./wekatester
     WORK_DIR=$d; DIRECTORY=/mnt/weka; CAL_SETTLE=0
     cal_ensure_seed() { :; }
     cal_run_cell() { echo "cell $*" >> "$d/calls"; CAL_READING=1000; }
     cal_search() { :; }
     cal_shape_run 1 h1 8 0-7 0-15 0 libaio,psync - 0 16 "" "$(printf "bw read\niops read")") 2>&1 ) ||
        { echo "cal_shape_run failed: $out" >&2; exit 1; }
    [ "$(cut -d" " -f3,5 "$d/calls" | tr "\n" ";")" = "bw libaio;bw psync;iops psync;" ] || { cat "$d/calls" >&2; exit 1; }
    case "$out" in *"no iops engine cell for libaio: numjobs=8 iodepth=16 would set up 128 aio events and the kernel has room for 16 (fs.aio-max-nr less fs.aio-nr, as probed)"*) true;; *) echo "$out" >&2; false;; esac'
# PR #47 Bugbot: one mkdir argument had made cal/<rep> a path under cal/s<N>
t_assert "cal_shape_run: creates cal/s<N> and cal/<rep> side by side, nothing under the shape dir" bash -c '
    d=$(mktemp -d)
    out=$( (source ./wekatester
     WORK_DIR=$d; DIRECTORY=/mnt/weka; CAL_SETTLE=0
     cal_ensure_seed() { :; }; cal_run_cell() { :; }; cal_search() { :; }
     cal_shape_run 1 h1 8 0-7 0-15 0 libaio - 0 64 "" "") 2>&1 ) ||
        { echo "cal_shape_run failed: $out" >&2; exit 1; }
    [ -d "$d/cal/s1" ] && [ -d "$d/cal/h1" ] && [ -z "$(ls -A "$d/cal/s1")" ] ||
        { find "$d" >&2; false; }'
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
    [ "$(head -1 "$d/shapes" | cut -f12)" = "h1 h2" ] && [ "$(sed -n 2p "$d/shapes" | cut -f2,6,12 | tr "\t" "|")" = "h3|25000000000|h3" ] &&
    case "$out" in
        *"shape 1 of 2: 2 host(s), calibrated on h1 -- Test CPU 8-core, 8 cpus, 252 GiB, weka NICs ens1: 1 x mlx5_core [0x15b3:0x101d] 100 Gb/s -> line rate 11.64 GiB/s"*"cores: 8 physical core(s) (no topology: one per cpu) - 1 weka DPDK - 2 reserved for the OS (0 1) = N=5: N/2 and N jobs on 2-6, 2N and 4N on 2-6"*"hosts: h1 h2"*"shape 2 of 2"*) true;;
        *) echo "$out" >&2; false;;
    esac'
t_assert "cal_shapes: a rep's host-file values pin its shape's searches, a partial row too; -g pins nothing" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    # bw_r nj/fs/nr/qd are cols 6-9; iops_r only has its qd (col 25)
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (6) printf "\t4";; (7) printf "\t5120M";; (8) printf "\t2";; (9) printf "\t1";; (25) printf "\t32";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$d/targets.final"
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=0; AUTH_DIR=""
     cal_shapes "$d/shapes" "$(printf "bw read\niops read\n")") >>$SUITE_ASIDE 2>&1
    [ "$(cut -f11 "$d/shapes")" = "bw_r=1/2/5120M/4 iops_r=32/-/-/-" ] || { cut -f11 "$d/shapes" >&2; exit 1; }
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=1; AUTH_DIR=""
     cal_shapes "$d/shapes" "bw read") >>$SUITE_ASIDE 2>&1
    [ "$(cut -f11 "$d/shapes")" = "-" ]'
t_assert "cal_shapes: an engine pinned by -e or the host file splits nothing but is carried" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2
    printf "h1\t-\tlibaio\t-\t-\nh2\t-\t-\t-\t-\n" > "$d/targets.final"
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2); REGEN_LAYOUT=0; AUTH_DIR=""
     cal_shapes "$d/shapes" "bw read") >>$SUITE_ASIDE 2>&1
    [ "$(cut -f2,8 "$d/shapes" | tr "\t" "|" | tr "\n" " ")" = "h1|libaio h2|- " ] || { cat "$d/shapes" >&2; exit 1; }
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2); REGEN_LAYOUT=0; AUTH_DIR=""; ENGINE=psync
     cal_shapes "$d/shapes" "bw read") >>$SUITE_ASIDE 2>&1
    [ "$(cut -f8 "$d/shapes")" = "psync" ]'
t_assert "cal_shapes: no weka CLI, no root, or UDP mode means no line rate, and a warning says why" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2:6 h3
    sed -i.b "/^weka_net /d" "$d/probe/h1"; echo "weka_cli absent" >> "$d/probe/h1"
    sed -i.b "/^weka_net /d" "$d/probe/h2"; echo "weka_net_err client needs root, and no passwordless escalator works here" >> "$d/probe/h2"
    sed -i.b "s/^weka_net client .*/weka_net client []/" "$d/probe/h3"
    err=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2 h3); REGEN_LAYOUT=0; AUTH_DIR=""
            cal_shapes "$d/shapes" "bw read") 2>&1 >>$SUITE_ASIDE )
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
    if command -v weka >>$SUITE_ASIDE; then echo "a weka CLI on this box: skipping the absent case" >&2
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
t_assert "probe: no ethtool, or one that prints no Speed line, leaves a NIC its sysfs speed" bash -c '
    d=$(mktemp -d); r=$d/root
    mkdir -p "$r/sys/class/net/eth0/device" "$r/proc" "$d/none" "$d/nospeed"
    echo 25000 > "$r/sys/class/net/eth0/speed"
    for c in cat awk grep sort tr head readlink getconf pgrep id; do
        p=$(type -P "$c") || { echo "no $c on this host" >&2; exit 1; }
        ln -s "$p" "$d/none/$c"; ln -s "$p" "$d/nospeed/$c"
    done
    printf "#!/bin/sh\necho \"Link detected: yes\"\n" > "$d/nospeed/ethtool"; chmod +x "$d/nospeed/ethtool"
    cmd=$(source ./wekatester; FIO_BIN=fio; probe_remote_cmd)
    for b in "$d/none" "$d/nospeed"; do
        out=$(WEKATESTER_SYSROOT=$r PATH=$b "$(type -P bash)" -c "$cmd" 2>&1)
        printf "%s\n" "$out" | grep -qx "nic eth0 25000 - - -" ||
            { echo "PATH ${b##*/}:"; printf "%s\n" "$out"; exit 1; } >&2
    done'

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
    # every cell ran with exactly one client: a representative (the seeds
    # are not cells: the shared read set is seeded by the whole group)
    grep -v cal-seed- "$d/simlog" > "$d/cells" &&
    ! grep -q -- "--client=h2" "$d/cells" &&
    [ "$(grep -o -- "--client=[a-z0-9]*" "$d/cells" | sort -u | tr "\n" " ")" = "--client=h1 --client=h3 " ] &&
    ! grep -- "--client=" "$d/cells" | grep -q -- "--client=.*--client=" &&
    grep cal-seed-read "$d/simlog" | grep -q -- "--client=h2 " &&
    # h1 and h2 share the shape, and so its answer
    [ "$(grep "^h1 " "$d/cal.results" | cut -d" " -f2-)" = "$(grep "^h2 " "$d/cal.results" | cut -d" " -f2-)" ] &&
    # h1 (8 cpus, weka on 7, the OS on 0-1): N=5, so bandwidth reaches line
    # rate only at 2N with the siblings in, iops is flat at its cap from 2N
    # and the tie goes heaviest (4N iodepth 32, 4 files), latency runs at N; h3 (16
    # cpus): N=13, bandwidth and iops flat at the cap from N, ties to 4N
    grep -qx "h1 io_uring 2 1 5120M 10 2 1 5120M 10 1 1 5120M 5 1 1 5120M 5 32 4 1280M 20 32 4 1280M 20 - - - - - - - -" "$d/cal.results" &&
    grep -qx "h3 io_uring 4 4 1280M 52 4 4 1280M 52 1 1 5120M 13 1 1 5120M 13 8 4 1280M 52 8 4 1280M 52 - - - - - - - -" "$d/cal.results" &&
    # the engine and the tuples reach targets.final, which staging reads
    t=$(awk -F"\t" "\$1==\"h2\" {print \$3, \$6, \$9, \$14, \$17}" "$d/targets.final") &&
    [ "$t" = "io_uring 10 2 5 1" ] &&
    case "$out" in
        *"shape 1 of 2: 2 host(s), calibrated on h1"*"N=5"*"shape 1: ioengine io_uring"*"shape 1 bw-write: numjobs=10 iodepth=2"*"siblings in that did"*"shape 1 lat-read: numjobs=5 iodepth=1 nrfiles=1 -> 100.0 us"*"shape 2: measuring"*"solo on h3"*) true;;
        *) printf "%s\n" "$out" >&2; false;;
    esac'
t_assert "calibrate: with --line-rate the bandwidth answer the host file carries is measured again and replaces it; iops is measured at its pins" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8
    printf "# report bandwidth\n[global]\n[a]\nrw=read\n" > "$d/set/011-r.job"
    printf "# report iops\n[global]\nbs=4k\n[a]\nrw=randread\n" > "$d/set/031-i.job"
    # recorded: bw_r (cols 6-9) 9/5120M/1/1 and iops_r (cols 22-25) 3/5120M/1/64
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (6) printf "\t9";; (7|23) printf "\t5120M";; (8|9|24) printf "\t1";; (22) printf "\t3";; (25) printf "\t64";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$d/targets.final"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; ENGINE=libaio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0; LINE_RATE_GBPS=16
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; SIMLOG=$d/simlog
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    grep -q "cal-bw-read-" "$d/simlog" || { printf "%s\n" "$out" >&2; exit 1; }
    # iops is pinned (3/5120M/1/64): measured again, at exactly those values
    grep -q "cal-iops-read-" "$d/simlog" || { echo "no iops cell ran" >&2; exit 1; }
    ! grep -o "cal-iops-read-[a-z_]*-nj[0-9]*-qd[0-9]*-nr[0-9]*" "$d/simlog" | grep -qv -- "-nj3-qd64-nr1$" ||
        { echo "an iops cell left its pins" >&2; exit 1; }
    bw=$(awk -F"\t" "\$1==\"h1\" {print \$6\"/\"\$7\"/\"\$8\"/\"\$9}" "$d/targets.final")
    io=$(awk -F"\t" "\$1==\"h1\" {print \$22\"/\"\$23\"/\"\$24\"/\"\$25}" "$d/targets.final")
    [ "$io" = "3/5120M/1/64" ] || { echo "iops_r: $io" >&2; exit 1; }
    case "$bw" in ("9/5120M/1/1"|*-*) echo "bw_r: $bw" >&2; false;; (*) true;; esac'
t_assert "calibrate: host-file values are the only ones a search tries, measured again; a host without them is a shape of its own" bash -c '
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
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    # h1 is pinned to 3 jobs x iodepth 4 x 2 files: every bw cell on it runs
    # exactly that, the engine cells too; h2 has no row, so it is a shape of
    # its own with the full search
    c1=$(grep -- "--client=h1 " "$d/simlog" | grep -o "cal-bw-read-[a-z_]*-nj[0-9]*-qd[0-9]*-nr[0-9]*" | sort -u)
    [ -n "$c1" ] && ! printf "%s\n" "$c1" | grep -qv -- "-nj3-qd4-nr2$" || { echo "h1 cells: $c1" >&2; exit 1; }
    [ "$(grep -- "--client=h2 " "$d/simlog" | grep -o "cal-bw-read-[a-z_]*-nj[0-9]*-qd[0-9]*-nr[0-9]*" | sort -u | wc -l)" -gt 3 ] || { echo "h2 not searched" >&2; exit 1; }
    grep "^h1 " "$d/cal.results" | grep -q "^h1 [a-z_]* 4 2 5120M 3 " &&
    case "$out" in *"bw read is pinned by h1"*"host-file row (qd/nr/fs/nj 4/2/5120M/3): only those values are tested"*) true;;
        *) printf "%s\n" "$out" >&2; false;; esac'
t_assert "calibrate: the shared read seed is split across the filesystem group; writes stay on the representative" bash -c '
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
    # cells widen the shared read set to two jobs -- one each for h1 and h2,
    # both driven from the master, while the write set stays on h1
    ! grep -q "^h2|" "$d/simlog" &&
    grep -qx "filename=shared.0/0" "$d/cal/h1/cal-seed-read.job" &&
    grep -qx "filename=shared.0/1" "$d/cal/h2/cal-seed-read.job" &&
    grep cal-seed-read "$d/simlog" | grep -q -- "--client=h1 .*--client=h2 " &&
    grep cal-seed-write "$d/simlog" | grep -q -- "--client=h1 " &&
    ! grep cal-seed-write "$d/simlog" | grep -q -- "--client=h2" &&
    case "$out" in *"cal: seed estimate: h1 (shared read set, 1x1 read + 0x0 write jobs x files): 1 file(s) = 5.0 GiB to write"*"2x1 read + 0x0 write jobs x files across 2 client(s) of its filesystem group"*) true;;
        *) printf "%s\n" "$out" >&2; false;; esac'
t_assert "calibrate: a 4k-random write seed has a section per job and size" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    printf "# report iops\n[global]\nfilename_format=\$filenum/\$jobnum\nbs=4k\n[a]\nrw=randwrite\n" > "$d/set/032-a.job"
    (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) >>$SUITE_ASIDE 2>&1
    # a section per job and size: 5G for file 0, 2.5G for file 1, 1.25G for files 2-3
    f=$d/cal/h1/cal-seed-write.job
    grep -A2 -x "filename=h1.0/0" "$f" | grep -qx "filesize=5120M" &&
    grep -A2 -x "filename=h1.1/0" "$f" | grep -qx "filesize=2560M" &&
    grep -A2 -x "filename=h1.2/0:h1.3/0" "$f" | grep -qx "filesize=1280M" || { cat "$f" >&2; false; }'
# Frank, 2026-10-24: calibration always seeds dense. A sequential-only write
# set was seeded sparse, by truncate, and the run had to find those files.
t_assert "calibrate: a sequential-only write set under -a seeds dense, by fio, never by truncate" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\n[a]\nrw=write\n" > "$d/set/012-w.job"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; SIMLOG=$d/simlog
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    f=$d/cal/h1/cal-seed-write.job
    ! grep -q truncate "$d/simlog" &&
    grep cal-seed-write "$d/simlog" | grep -q -- "--client=h1 " &&
    grep -qx "rw=write" "$f" && grep -qx "create_on_open=1" "$f" &&
    grep -A2 -x "filename=h1.0/0" "$f" | grep -qx "filesize=5120M" &&
    case "$out" in *"cal: seed estimate: h1 (write set, 0x0 read + 1x1 write jobs x files): 1 file(s) = 5.0 GiB to write"*) true;;
        *) printf "%s\n" "$out" >&2; false;; esac &&
    case "$out" in *sparse*|*truncate*) printf "%s\n" "$out" >&2; false;; *) true;; esac'
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
     calibrate) >>$SUITE_ASIDE 2>&1
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
            calibrate) 2>&1 >>$SUITE_ASIDE ); rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in
        *"EVIDENCE[cell bw-read libaio numjobs=1 iodepth=1 nrfiles=1|cal-bw-read-libaio-nj1-qd1-nr1-30s.job|say|h1]"*"calibration cell bw-read libaio numjobs=1 iodepth=1 nrfiles=1 failed on h1 ("*"in the run bundle under cal/)"*) true;;
        *) echo "$err" >&2; false;;
    esac &&
    case "$err" in *"/dev/shm/wt"*) echo "points at tmpfs: $err" >&2; false;; *) true;; esac'
t_assert "calibrate: -u removes the calibration scratch after the last job, never during calibration; the default keeps it" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1
    printf "# report bandwidth\n[global]\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-a.job"
    run_one() {   # run_one <unlink> <then>: calibrate, then <then> in the same shell
        rm -rf "$d/simlog" "$d/cal"
        out=$( (source ./wekatester
         AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; ENGINE=libaio
         TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
         SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; UNLINK=$1; SIMLOG=$d/simlog
         copy_to_master() { :; }
         run_host() { cal_sim_host "$@"; }
         calibrate; echo "PENDING=$CAL_UNLINK_PENDING" >> "$d/simlog"; $2) 2>&1 ) || { echo "$out" >&2; exit 1; }
    }
    run_one 0 : && ! grep -q "rm -rf ./mnt/weka/.wekatester-cal" "$d/simlog" && grep -qx "PENDING=0" "$d/simlog" || exit 1
    # under -u calibrate only marks the removal; main runs it after the last job
    run_one 1 : && ! grep -q "rm -rf ./mnt/weka/.wekatester-cal" "$d/simlog" && grep -qx "PENDING=1" "$d/simlog" || exit 1
    run_one 1 cal_remove_dataset && grep -q "rm -rf ./mnt/weka/.wekatester-cal." "$d/simlog"'
t_assert "calibrate: under -u the workload files it measured on outlive calibration; the removal after the last job takes them" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2
    # a unified set: calibration measures on the workload own files
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\n[a]\nrw=read\n" > "$d/set/011-r.job"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1 h2); MASTER=h1; FIO_BIN=fio; ENGINE=libaio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; UNLINK=1; SIMLOG=$d/simlog
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate; echo "@@CAL_DONE" >> "$d/simlog"; cal_remove_dataset) 2>&1 ) || { echo "$out" >&2; exit 1; }
    before=$(sed -n "1,/^@@CAL_DONE$/p" "$d/simlog"); after=$(sed -n "/^@@CAL_DONE$/,\$p" "$d/simlog")
    ! printf "%s\n" "$before" | grep -Eq "(shared|h1|h2)\.\*/\*" || { printf "%s\n" "$before" | grep -E "(shared|h1|h2)\.\*/\*" >&2; exit 1; }
    printf "%s\n" "$after" | grep -q "^h1|find .*shared\.\*/\*" && printf "%s\n" "$after" | grep -q "^h2|find .*h2\.\*/\*" ||
        { printf "%s\n" "$after" >&2; false; }'
t_assert "calibrate: a set whose only latency test is 1MiB still chooses its engine, and the budget counts the engine cells that run" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8
    printf "# report latency\n[global]\nbs=1M\n[a]\nrw=randread\n" > "$d/set/021-a.job"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    case "$out" in *"measuring lat1m read solo on h1 -- at most "*" plus 3 engine cell(s)"*"shape 1: ioengine "*) ;; *) printf "%s\n" "$out" >&2; exit 1;; esac
    # under -b a 4k latency test gains a 1MiB twin search, but no engine cells of its own
    rm -rf "$d/cal" "$d/cal.results" "$d/targets.final"; rm -f "$d/set/021-a.job"
    printf "# report latency\n[global]\nbs=4k\n[a]\nrw=randread\n" > "$d/set/021-b.job"
    out=$( (source ./wekatester
     AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; BULK=1
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    case "$out" in *"measuring lat read, lat1m read solo on h1 -- at most "*" plus 3 engine cell(s)"*) true;; *) printf "%s\n" "$out" >&2; false;; esac'
t_assert "calibrate: in local mode a box named shared cannot take the fleet-shared dataset name" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" localhost
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\n[a]\nrw=read\n" > "$d/set/011-a.job"
    err=$( (source ./wekatester
            AUTO_LEVEL=cal; LOCAL_MODE=1; LOCAL_NAME=shared; WORK_DIR=$d; HOSTS=(localhost); MASTER=localhost; FIO_BIN=fio; ENGINE=libaio
            TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
            SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0
            copy_to_master() { :; }
            run_host() { cal_sim_host "$@"; }
            calibrate) 2>&1 ) && { echo "no stop: $err" >&2; exit 1; }
    case "$err" in *"the host name '"'"'shared'"'"' is reserved for the fleet-shared read dataset (localhost)"*) true;; *) echo "$err" >&2; false;; esac'
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
     calibrate) >>$SUITE_ASIDE 2>&1
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
            cal_seed_rep h1 104 64 0 0 libaio "0-51") 2>&1 )
    f=$d/cal/h1/cal-seed-read.job
    n=$(grep -c "^\[seed-" "$f")
    # per job: one section each for its 5G, 2.5G and 1.25G files, four for the
    # 60 past the nrfiles ladder (at the 80M share the cell itself reads)
    [ "$n" = 728 ] || { echo "sections=$n" >&2; exit 1; }
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
            cal_seed_rep h1 8 2 0 0 libaio "") 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && ! grep -q "cal-seed-" "$d/simlog" &&
    case "$err" in *"h1: the calibration dataset needs 61440MiB and /mnt/weka has 10000MiB free"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "cal_seed_rep: sufficiency is the only test -- a complete file is never rewritten" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/cal"
    (source ./tests/helpers.sh; source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka
     TARGET_DIR=/dev/shm/x; CAL_SETTLE=0; CAL_NS_DIR=/.wekatester-cal; CAL_SEP=.cal.
     copy_to_master() { :; }
     run_host() { case "$2" in (*WEKATESTER_DF*)
         printf "h1.cal.0.0 5368709120\nh1.cal.0.1 99\nh1.cal.1.0 6000000000\nWEKATESTER_DF\nwekafs 1 99999999\n"; return 0;; esac
         cal_sim_host "$@"; }
     cal_seed_rep h1 2 2 0 0 libaio "") >>$SUITE_ASIDE 2>&1
    f=$d/cal/h1/cal-seed-read.job
    [ "$(grep "^filename=" "$f" | tr "\n" " ")" = "filename=h1.cal.0.1 filename=h1.cal.1.1 " ] &&
    grep -q "^\[seed-1-2560M-0\]$" "$f" || { cat "$f" >&2; false; }'

# --- filesystem groups (Frank, 2026-10-02) ---
# Clients that see one destination directory share one fleet-shared read set,
# whatever path they mount it at; a separate directory, even on the same
# filesystem, is a group of its own.
t_assert "fs groups: equal group-file hashes are one group, numbered by first host; the file is removed" bash -c '
    w=$(mktemp -d)
    out=$( (source ./wekatester
        WORK_DIR=$w; HOSTS=(h1 h2 h3 h4); GROUP_FILE=.g.lst; DIRECTORY=/mnt/x
        run_host() { case "$2" in (sha256sum*) case "$1" in (h3) echo "bbbb  f";; (*) echo "aaaa  f";; esac;; (rm*) echo "$1" >> "$w/rm";; esac; }
        collect_fs_groups) 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(tr "\n" " " < "$w/groups")" = "h1 1 h2 1 h3 2 h4 1 " ] &&
    [ "$(sort "$w/rm" | tr "\n" " ")" = "h1 h3 " ] &&
    case "$out" in *"filesystem groups: 2"*"group 1: h1 h2 h4 (at /mnt/x on h1)"*"group 2: h3 (at /mnt/x on h3)"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "fs groups: each group removes its file once, from its first host, after every hash is read" bash -c '
    grp() {   # grp <hosts...>: prints every command sent, then the output; h2 and h4 hash bbbb, the rest aaaa; rm fails on h2
        local w; w=$(mktemp -d)
        (source ./wekatester
         WORK_DIR=$w; HOSTS=("$@"); GROUP_FILE=.g.lst
         load_host_dirs() { local h; HOST_DIRS=(); for h in "${HOSTS[@]}"; do HOST_DIRS+=("/mnt/$h"); done; }
         run_host() { echo "$1 $2" >> "$w/log"; case "$1:$2" in
             (*:sha256sum*) case "$1" in (h2|h4) echo "bbbb  f";; (*) echo "aaaa  f";; esac;;
             (h2:rm*) return 1;; esac; }
         collect_fs_groups) >"$w/out" 2>&1 || { cat "$w/out"; return 1; }
        cat "$w/log" "$w/out"
    }
    one=$(grp h1 h3 h5) && two=$(grp h1 h2 h3 h4) || { echo "$one$two" >&2; exit 1; }
    [ "$(printf "%s\n" "$one" | grep " rm ")" = "h1 rm -f '\''/mnt/h1/.g.lst'\''" ] || { echo "$one" >&2; exit 1; }
    [ "$(printf "%s\n" "$two" | grep " rm " | sort | tr "\n" "|")" = "h1 rm -f '\''/mnt/h1/.g.lst'\''|h2 rm -f '\''/mnt/h2/.g.lst'\''|" ] &&
    printf "%s\n" "$two" | awk "/ sha256sum / {s = NR} / rm / && !r {r = NR} END {exit !(s == 4 && r > s)}" &&
    case "$two" in *"WARNING: h2: could not remove /mnt/h2/.g.lst"*) true;; *) false;; esac || { echo "$two" >&2; false; }'
t_assert "fs groups: a host whose group file cannot be hashed stops the run, naming it" bash -c '
    err=$( (source ./wekatester
        WORK_DIR=$(mktemp -d); HOSTS=(h1 h2); GROUP_FILE=.g.lst; DIRECTORY=/mnt/x
        run_host() { case "$1:$2" in (h2:sha256sum*) return 1;; (*:sha256sum*) echo "aaaa  f";; esac; }
        collect_fs_groups) 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] &&
    case "$err" in *"h2: cannot hash the filesystem-group file /mnt/x/.g.lst"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "fs groups: one directory under two mount paths is one group; a sibling directory on the same filesystem is another" bash -c '
    d=$(mktemp -d); w=$(mktemp -d)
    mkdir -p "$d/fs1/test" "$d/fs1/other" "$d/fs2/test" "$d/mnt"
    ln -s "$d/fs1" "$d/mnt/foo"; ln -s "$d/fs1" "$d/mnt/bar"
    row() { printf "%s\t-\t-\t-\t%s" "$1" "$2"; for i in $(seq 6 37); do printf "\t-"; done; printf "\n"; }
    { row h1 "$d/mnt/foo/test"; row h2 "$d/mnt/bar/test"; row h3 "$d/fs2/test"; row h4 "$d/mnt/foo/other"; } > "$w/targets.final"
    (source ./wekatester
     WORK_DIR=$w; HOSTS=(h1 h2 h3 h4); GROUP_FILE=.g.lst
     run_host() { bash -c "$2"; }
     for h in "${HOSTS[@]}"; do probe_writable "$h" "$(host_dir "$h")" || exit 1; done
     [ "$(cat "$d/fs1/test/.g.lst" | tr "\n" " ")" = "h1 h2 " ] || exit 1
     collect_fs_groups >>$SUITE_ASIDE 2>&1) || exit 1
    [ "$(tr "\n" " " < "$w/groups")" = "h1 1 h2 1 h3 2 h4 3 " ] &&
    [ ! -e "$d/fs1/test/.g.lst" ] && [ ! -e "$d/fs2/test/.g.lst" ] && [ ! -e "$d/fs1/other/.g.lst" ] ||
        { cat "$w/groups" >&2; false; }'
t_assert "fs groups: the hashes come back after every other check and before the fio servers, dry runs included" bash -c '
    m=$(sed -n "/^main() {/,/^}/p" ./wekatester)
    dry=$(printf "%s\n" "$m" | sed -n "/if \[ \"\$DRY_RUN\" -eq 1 \]; then/,/exit 0/p")
    printf "%s\n" "$dry" | grep -q "collect_fs_groups" &&
    printf "%s\n" "$m" | awk "/check_cpu_pinning/ {p = NR} /collect_fs_groups/ {c = NR} /start_fio_servers/ {s = NR} END {exit !(p && c > p && s > c)}"'
t_assert "fs groups: a run that dies after the write probe removes its group file at exit, and nothing else there" bash -c '
    d=$(mktemp -d); : > "$d/keep"
    out=$( (source ./wekatester
        LOCAL_MODE=1; HOSTS=(localhost); DIRECTORY=$d; WORK_DIR=""; PRESSURE_END_DONE=1
        GROUP_FILE=.wekatester-group.1.2.lst; lock_token; RUN_LOCKS[localhost]=1
        trap cleanup EXIT
        probe_writable localhost "$d" && [ -s "$d/$GROUP_FILE" ] && echo PROBED
        die "stopped before collect_fs_groups") 2>&1 )
    case "$out" in *PROBED*"stopped before collect_fs_groups"*) ;; *) echo "$out" >&2; exit 1;; esac
    [ ! -e "$d/.wekatester-group.1.2.lst" ] && [ -e "$d/keep" ] || { ls -A "$d" >&2; false; }'
t_assert "fs groups: once collect_fs_groups has removed the group file, cleanup does not try again" bash -c '
    w=$(mktemp -d)
    (source ./wekatester
     HOSTS=(h1 h2); GROUP_FILE=.g.lst; DIRECTORY=/mnt/x; PRESSURE_END_DONE=1; LOCK_TOKEN=t
     run_host() { echo "$1 $2" >> "$w/log"; case "$2" in (sha256sum*) echo "aaaa  f";; esac; }
     # control: before collect_fs_groups, cleanup removes it on both hosts
     WORK_DIR=""; RUN_LOCKS=([h1]=1 [h2]=1); cleanup
     echo "--" >> "$w/log"
     WORK_DIR=$w; collect_fs_groups || exit 1
     echo "flag $GROUP_FILE_REMOVED" >> "$w/log"
     WORK_DIR=""; RUN_LOCKS=([h1]=1 [h2]=1); cleanup) >>$SUITE_ASIDE 2>&1 || { cat "$w/log" >&2; exit 1; }
    awk "/^--\$/ {s = 1; next} /^flag / {s = 2; f = \$2; next} !s && /\.g\.lst/ {b++} s == 2 {a++} s == 2 && /\.g\.lst/ {bad++} END {exit !(b == 2 && f == 1 && a == 2 && !bad)}" "$w/log" ||
        { cat "$w/log" >&2; false; }'
t_assert "tuner: each filesystem group lays out its own shared set, on its first host" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    cp "$FIX/probe/h1" "$FIX/probe/h3"
    printf "# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\ndirectory=/orig\nioengine=libaio\nfilename_format=\$filenum/\$jobnum\n[bw]\nrw=read\niodepth=1\n" > "$FIX/src/011-bw.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE
    printf "h1 1\nh2 2\nh3 1\n" > "$FIX/groups"
    (source ./wekatester; WEKATESTER_NS="unified \$filenum/\$jobnum" auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2 h3) >>$SUITE_ASIDE 2>&1
    grep -q "^filename_format=shared\." "$FIX/jobs/h1/000-wekatester-layout.job" &&
    grep -q "^filename_format=shared\." "$FIX/jobs/h2/000-wekatester-layout.job" &&
    ! grep -q "^filename_format=shared\." "$FIX/jobs/h3/000-wekatester-layout.job"'
t_assert "capacity: each filesystem group's shared set is priced once, and groups on one filesystem add up" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    cp "$FIX/probe/h1" "$FIX/probe/h3"; cp "$FIX/probe/h1" "$FIX/probe/h4"
    printf "# report bandwidth\n[global]\nfilesize=10G\nnumjobs=4\ndirectory=/orig\nioengine=libaio\nfilename_format=\$filenum/\$jobnum\n[bw]\nrw=read\niodepth=1\n" > "$FIX/src/011-bw.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE
    # 50 GiB free on one weka filesystem; one shared set is 4 jobs x 10G
    printf "Filesystem 1024-blocks Used Available Capacity Mounted on\n10.0.1.1/default 104857600 0 52428800 1%% /mnt/weka\nwekafs\n" > "$FIX/probe/_df"
    chk() { (export WEKATESTER_PROMPT_TTY=/dev/null; source ./wekatester
        IGNORE_CAPACITY=0; WORK_DIR=$FIX; HOSTS=(h1 h2 h3 h4); DIRECTORY=/mnt/weka
        run_host() { cat "$FIX/probe/_df"; }
        WEKATESTER_NS="unified \$filenum/\$jobnum" auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2 h3 h4 >>$SUITE_ASIDE 2>&1 || exit 9
        check_capacity); }
    printf "h1 1\nh2 1\nh3 1\nh4 1\n" > "$FIX/groups"
    out=$(chk 2>&1) || { echo "one group should fit: $out" >&2; exit 1; }
    printf "h1 1\nh2 1\nh3 2\nh4 2\n" > "$FIX/groups"
    err=$(chk 2>&1 >>$SUITE_ASIDE) && { echo "two groups passed: $err" >&2; exit 1; }
    case "$err" in *"weka filesystem default: its 4 hosts (h1 h2 h3 h4) need ~80.0GiB together but only 50.0GiB is available"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "cal_shapes: one representative per shape per filesystem group" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2 h3 h4
    printf "h1 1\nh2 1\nh3 2\nh4 2\n" > "$d/groups"; mkdir -p "$d/cal"
    out=$( (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2 h3 h4); REGEN_LAYOUT=0; ENGINE=""
            cal_shapes "$d/cal/shapes" "bw read") 2>&1 ) || { echo "$out" >&2; exit 1; }
    [ "$(cut -f2 "$d/cal/shapes" | tr "\n" " ")" = "h1 h3 " ] &&
    [ "$(cut -f12 "$d/cal/shapes" | tr "\n" "|")" = "h1 h2|h3 h4|" ] &&
    [ "$(cut -f1,3 "$d/cal/hostinfo" | tr "\t\n" ": ")" = "h1:io_uring h2:io_uring h3:io_uring h4:io_uring " ] &&
    case "$out" in *"filesystem group of h3: reads that group"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "cal_seed_rep: each file is seeded at the largest share a test takes: 2 jobs to nrfiles 4 are 2x5G + 2x2.5G + 4x1.25G" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/cal"
    out=$( (source ./tests/helpers.sh; source ./wekatester
            WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka
            TARGET_DIR=/dev/shm/x; CAL_SETTLE=0; CAL_NS_DIR=/.wekatester-cal; CAL_SEP=.cal.
            copy_to_master() { :; }
            run_host() { cal_sim_host "$@"; }
            cal_seed_rep h1 2 4 0 0 libaio "") 2>&1 ) || { echo "$out" >&2; exit 1; }
    f=$d/cal/h1/cal-seed-read.job
    [ "$(grep -c "^filesize=5120M$" "$f") $(grep -c "^filesize=2560M$" "$f") $(grep -c "^filesize=1280M$" "$f")" = "2 2 2" ] &&
    grep -A2 -x "filename=h1.cal.0.2:h1.cal.0.3" "$f" | grep -qx "filesize=1280M" &&
    case "$out" in *"8 file(s) = 20.0 GiB to write"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "cal_seed_rep: a listed need past the ladder makes its files at least that big" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/cal"
    # nrfiles 3 pinned: file 2 needs 5120/3 = 1706M, more than the ladder 1280M
    printf "4 3 1706\n" > "$d/cal/needs.read.h1"
    (source ./tests/helpers.sh; source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; DIRECTORY=/mnt/weka
     TARGET_DIR=/dev/shm/x; CAL_SETTLE=0; CAL_NS_DIR=/.wekatester-cal; CAL_SEP=.cal.
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     cal_seed_rep h1 1 4 0 0 libaio "") >>$SUITE_ASIDE 2>&1 || exit 1
    f=$d/cal/h1/cal-seed-read.job
    grep -A2 -x "filename=h1.cal.0.2" "$f" | grep -qx "filesize=1706M" &&
    grep -A2 -x "filename=h1.cal.0.3" "$f" | grep -qx "filesize=1280M" || { cat "$f" >&2; false; }'
t_assert "calibration capacity: groups and representatives on one weka filesystem add up before the first cell; files already there count" bash -c '
    d=$(mktemp -d); mkdir -p "$d/cal"
    printf "h1 1\nh2 1\nh3 2\nh4 2\nh5 3\n" > "$d/groups"
    # N=1 everywhere: 4 jobs x 4 files at 1024M + 512M + 256M + 256M = 8 GiB a set;
    # fs1 holds two groups shared sets and two reps write sets (32 GiB), fs2 one of each
    { printf "1\th1\t1\t2\t2\t0\tlibaio\t-\t0\t-\t-\th1 h2\n"
      printf "2\th3\t1\t2\t2\t0\tlibaio\t-\t0\t-\t-\th3 h4\n"
      printf "3\th5\t1\t2\t2\t0\tlibaio\t-\t0\t-\t-\th5\n"; } > "$d/cal/shapes"
    chk() {   # chk <fs1 free MiB> [listing on h1]
        (export WEKATESTER_PROMPT_TTY=/dev/null; source ./wekatester
         WORK_DIR=$d; HOSTS=(h1 h2 h3 h4 h5); DIRECTORY=/mnt/w; IGNORE_CAPACITY=0
         CAL_NS_DIR=""; CAL_FMT="\$jobnum.\$filenum"; CAL_SEP=.; FILESIZE_MIB=1024; CAL_NR=1; CAL_NR_LADDER="1 2 4"
         run_host() { case "$1" in
             (h1) printf "%b" "$LIST1"; printf "WEKATESTER_DF\nfs1 99999999 %s\nwekafs\n" "$FREE1" ;;
             (h3) printf "WEKATESTER_DF\nfs1 99999999 %s\nwekafs\n" "$FREE1" ;;
             (h5) printf "WEKATESTER_DF\nfs2 88888888 20480\nwekafs\n" ;;
         esac; }
         FREE1=$1; LIST1=${2:-}
         cal_capacity_check "$d/cal/shapes" "bw read
bw write"); }
    err=$(chk 30720 2>&1 >>$SUITE_ASIDE) && { echo "passed at 30 GiB: $err" >&2; exit 1; }
    case "$err" in *"calibration needs ~32.0GiB on weka filesystem fs1 (h1 h3) but only 30.0GiB is available"*) ;; *) echo "$err" >&2; exit 1;; esac
    case "$err" in *fs2*) echo "fs2 fits: $err" >&2; exit 1;; esac
    # 1 GiB of the first group shared set already laid out: 31 GiB still to write
    out=$(chk 31744 "shared.0.0 1073741824\n" 2>&1) || { echo "the credit did not count: $out" >&2; false; }'
# The --ignore-capacity confirm runs after main closed the prompt fd, so it
# must close what it reopened, yes or no. /dev/ptmx passes the [ -t 3 ] gate
# with no terminal; asked=1 proves the fd was opened.
t_assert "check_capacity: the --ignore-capacity confirm closes the prompt fd it opened, yes or no" bash -c '
    d=$(mktemp -d)
    chk() {   # chk <confirm status>
        (export WEKATESTER_PROMPT_TTY=/dev/ptmx; source ./wekatester
         WORK_DIR=$d; HOSTS=(h1); DIRECTORY=/mnt/w; IGNORE_CAPACITY=1; ANSWER=$1
         run_host() { :; }; list_staged() { :; }; awkrun() { return 3; }
         confirm_explicit() { echo "asked=$PROMPT_OPENED"; return "$ANSWER"; }
         state() { echo "opened=$PROMPT_OPENED child=$(bash -c "[ -t 3 ] && echo tty || echo none")"; }
         die() { state; exit 1; }
         check_capacity; state) 2>&1; }
    want="asked=1
opened=0 child=none"
    out=$(chk 0); [ "$out" = "$want" ] || { echo "yes: $out" >&2; exit 1; }
    out=$(chk 1); [ "$out" = "$want" ] || { echo "no: $out" >&2; false; }'
t_assert "cal_capacity_check: the --ignore-capacity confirm closes the prompt fd it opened, yes or no" bash -c '
    d=$(mktemp -d); mkdir -p "$d/cal"
    printf "1\th1\t1\t2\t2\t0\tlibaio\t-\t0\t-\t-\th1\n" > "$d/cal/shapes"
    chk() {   # chk <confirm status>
        (export WEKATESTER_PROMPT_TTY=/dev/ptmx; source ./wekatester
         WORK_DIR=$d; HOSTS=(h1); DIRECTORY=/mnt/w; IGNORE_CAPACITY=1; ANSWER=$1
         CAL_NS_DIR=""; CAL_FMT="\$jobnum.\$filenum"; CAL_SEP=.; FILESIZE_MIB=1024; CAL_NR=1; CAL_NR_LADDER="1 2 4"
         run_host() { :; }; awkrun() { return 3; }
         confirm_explicit() { echo "asked=$PROMPT_OPENED"; return "$ANSWER"; }
         state() { echo "opened=$PROMPT_OPENED child=$(bash -c "[ -t 3 ] && echo tty || echo none")"; }
         die() { state; exit 1; }
         cal_capacity_check "$d/cal/shapes" "bw read"; state) 2>&1; }
    want="asked=1
opened=0 child=none"
    out=$(chk 0); [ "$out" = "$want" ] || { echo "yes: $out" >&2; exit 1; }
    out=$(chk 1); [ "$out" = "$want" ] || { echo "no: $out" >&2; false; }'
t_assert "-u: each filesystem group's shared set is removed from that group's first host" bash -c '
    d=$(mktemp -d); printf "h1 1\nh2 2\nh3 1\n" > "$d/groups"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1 h2 h3); DIRECTORY=/mnt/w; CAL_NS_DIR=""; CAL_FMT="\$jobnum.\$filenum"; CAL_SEP=.
     run_host() { printf "%s|%s\n" "$1" "$2" >> "$d/cmds"; }
     cal_remove_dataset) >>$SUITE_ASIDE 2>&1
    [ "$(grep "/mnt/w/shared\." "$d/cmds" | cut -d"|" -f1 | sort | tr "\n" " ")" = "h1 h2 " ] || { cat "$d/cmds" >&2; false; }'
t_assert "-u: a destination given with a trailing slash (-d or the host file) still has its dataset removed (run for real)" bash -c '
    d=$(mktemp -d); t=$d/dest; mkdir -p "$t"
    printf "host,user_login,ioengine,allowed_cpus,destination_folder\nh1,,,,$t//\n" > "$d/hl.csv"
    for via in -d hostfile; do
        for f in shared.0.0 shared.1.0 h1.0.0 h1.0.1 other.0.0; do : > "$t/$f"; done
        rm -f "${d:?}/targets.phase1"
        out=$( (source ./wekatester
         WORK_DIR=$d; LOCAL_MODE=0; CAL_NS_DIR=""; CAL_FMT="\$jobnum.\$filenum"; CAL_SEP=.
         if [ "$via" = -d ]; then parse_args -d "$t/" h1
         else parse_args h1; resolve_targets phase1 "$d/hl.csv" - - - h1 > "$d/targets.phase1"; fi
         run_host() { bash -c "$2"; }
         cal_remove_dataset) 2>&1 ) || { echo "$via: $out" >&2; exit 1; }
        left=$(cd "$t" && find . -type f | LC_ALL=C sort | tr "\n" " ")
        [ "$left" = "./other.0.0 " ] || { echo "$via: left $left; $out" >&2; exit 1; }
    done'

# --- host-file values pin their knobs (Frank, 2026-10-02) ---
# A host-file value is the only value its knob takes in calibration, used as
# written and never capped; open knobs are searched around it.
t_assert "cal_plan: a pinned job count is the only one tried; the open knobs are still searched" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" bw read io_uring 16 0 0 pin_nj=40) || { echo "$out" >&2; exit 1; }
    [ "$(cut -d" " -f2 "$d/asked" | sort -u)" = 40 ] &&
    [ "$(cut -d" " -f3 "$d/asked" | sort -u | wc -l)" -gt 1 ] &&
    case "$out" in "done 40 "*"pinned by the host file: numjobs=40 -- the only value(s) tried"*) true;; *) echo "$out" >&2; false;; esac'
t_assert "cal_plan: a pinned iodepth holds on the qd1 rungs too" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    plan_sim "$d" bw read io_uring 8 0 0 pin_qd=4 >>$SUITE_ASIDE || exit 1
    [ "$(cut -d" " -f3 "$d/asked" | sort -u)" = 4 ] && grep -q "^numjobs 1 4 1$" "$d/asked" || { cat "$d/asked" >&2; false; }'
t_assert "cal_plan: a fully pinned libaio cell runs as written, past the aio room, never refused by a guard" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" iops read libaio 16 0 0 pin_nj=188 pin_qd=512 pin_nr=1 aio=65536) || { echo "$out" >&2; exit 1; }
    [ "$(cut -d" " -f2- "$d/asked" | sort -u)" = "188 512 1" ] &&
    case "$out" in "done 188 512 1 "*) true;; *) echo "$out" >&2; false;; esac &&
    case "$out" in *"stopped short"*) echo "$out" >&2; false;; *) true;; esac'
t_assert "cal_plan: a pinned latency job count replaces N; nrfiles is still searched" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    out=$(plan_sim "$d" lat read io_uring 16 0 0 pin_nj=8) || { echo "$out" >&2; exit 1; }
    [ "$(tr "\n" ";" < "$d/asked")" = "nrfiles 8 1 1;nrfiles 8 1 2;nrfiles 8 1 4;" ] &&
    case "$out" in "done 8 1 1 "*"pinned by the host file: numjobs=8"*) true;; *) echo "$out" >&2; false;; esac &&
    [ "$(source ./wekatester; cal_plan budget lat read x 16 0 0 /dev/null $K pin_nj=8)" = 3 ] &&
    [ "$(source ./wekatester; cal_plan budget lat read x 16 0 0 /dev/null $K pin_nj=8 pin_nr=2)" = 1 ]'
t_assert "stage_cal_cell: a pinned filesize is the cell's, as written" bash -c '
    d=$(mktemp -d)
    (source ./wekatester; CAL_PIN_FS=10G
     stage_cal_cell "$d/c.job" /mnt/w h1 "" bw read libaio 4 1 2 30) || exit 1
    grep -qx "filesize=10G" "$d/c.job" &&
    (source ./wekatester; stage_cal_cell "$d/d.job" /mnt/w h1 "" bw read libaio 4 1 2 30) &&
    grep -qx "filesize=2560M" "$d/d.job"'
t_assert "cal_shapes: pins past the grid become seed needs -- an off-ladder nrfiles, a pinned filesize and its latency twin" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8; mkdir -p "$d/cal"
    # bw_r (cols 6-9) pins nrfiles 3; lat_w (cols 18-21) pins fs 8G at nrfiles 2
    { printf "h1"; for i in $(seq 2 37); do
          case $i in (8) printf "\t3";; (19) printf "\t8G";; (20) printf "\t2";; (*) printf "\t-";; esac
      done; printf "\n"; } > "$d/targets.final"
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=0; ENGINE=""
     cal_shapes "$d/cal/shapes" "$(printf "bw read\nlat write\n")") >>$SUITE_ASIDE 2>&1 || exit 1
    [ "$(cat "$d/cal/needs.read.h1")" = "20 3 1706" ] &&
    [ "$(cat "$d/cal/needs.write.h1" | tr "\n" " ")" = "20 2 8192 1 1 16384 " ] ||
        { head "$d"/cal/needs.* >&2; false; }'
t_assert "cal_shapes: hosts whose host-file values differ calibrate as shapes of their own" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1 h2 h3; mkdir -p "$d/cal"
    { for h in h1 h3; do printf "%s" "$h"; for i in $(seq 2 37); do case $i in (6) printf "\t2";; (*) printf "\t-";; esac; done; printf "\n"; done
      printf "h2"; for i in $(seq 2 37); do printf "\t-"; done; printf "\n"; } > "$d/targets.final"
    (source ./wekatester; WORK_DIR=$d; HOSTS=(h1 h2 h3); REGEN_LAYOUT=0; ENGINE=""
     cal_shapes "$d/cal/shapes" "bw read") >>$SUITE_ASIDE 2>&1 || exit 1
    [ "$(cut -f2,12 "$d/cal/shapes" | tr "\t\n" ":|")" = "h1:h1 h3|h2:h2|" ] || { cat "$d/cal/shapes" >&2; false; }'
t_assert "cal_aio_preflight: a pin past the aio room stops calibration before anything runs; a room it fits, or no libaio, passes" bash -c '
    d=$(mktemp -d)
    row() { printf "1\th1\t5\t2-6\t2-6\t0\t%s\t%s\t0\t%s\t%s\th1\n" "$1" "$2" "$3" "$4"; }
    row "io_uring,libaio" - 65536 "iops_r=512/-/-/188" > "$d/over"
    row "io_uring,libaio" - 1048576 "iops_r=512/-/-/188" > "$d/fits"
    row "io_uring,psync" - 65536 "iops_r=512/-/-/188" > "$d/noaio"
    row "libaio" libaio 100 "bw_r=-/-/-/200" > "$d/nj"
    err=$( (source ./wekatester; cal_aio_preflight "$d/over") 2>&1 ) && { echo "no stop: $err" >&2; exit 1; }
    case "$err" in *"shape 1 (h1): iops_r pinned at numjobs=188 iodepth=512 needs 96256 aio events at once with libaio (one of the engines calibration tries), and the kernel has room for 65536"*"nothing was run and the host file is unchanged"*) ;; *) echo "$err" >&2; exit 1;; esac
    (source ./wekatester; cal_aio_preflight "$d/fits") && (source ./wekatester; cal_aio_preflight "$d/noaio") || exit 1
    err=$( (source ./wekatester; cal_aio_preflight "$d/nj") 2>&1 ) && { echo "no stop: $err" >&2; exit 1; }
    case "$err" in *"bw_r pinned at numjobs=200 iodepth=1 (open) needs 200 aio events at once with libaio (pinned)"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "cal_aio_preflight: an open numjobs costs the fewest jobs its search runs -- 1 for bandwidth, N/2 for IOPS, N for latency" bash -c '
    d=$(mktemp -d)
    row() { printf "1\th1\t16\t2-17\t2-33\t0\tio_uring,libaio\t-\t0\t256\t%s\th1\n" "$1" > "$d/$2"; }
    row "iops_r=64/-/-/-" iops; row "bw_r=64/-/-/-" bw; row "lat_w=64/-/-/-" lat; row "iops_r=32/-/-/-" fits
    err=$( (source ./wekatester; cal_aio_preflight "$d/iops") 2>&1 ) && { echo "no stop: $err" >&2; exit 1; }
    case "$err" in *"iops_r pinned at numjobs=8 (open: the fewest jobs its search runs) iodepth=64 needs 512 aio events"*) ;; *) echo "$err" >&2; exit 1;; esac
    err=$( (source ./wekatester; cal_aio_preflight "$d/lat") 2>&1 ) && { echo "no stop: $err" >&2; exit 1; }
    case "$err" in *"lat_w pinned at numjobs=16 (open: the fewest jobs its search runs) iodepth=64 needs 1024 aio events"*) ;; *) echo "$err" >&2; exit 1;; esac
    (source ./wekatester; cal_aio_preflight "$d/bw") && (source ./wekatester; cal_aio_preflight "$d/fits")'
t_assert "writeback: a host line is commented out and its new version written directly below it; others stay put" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "host,user_login,ioengine\nh2,,,,\nh1,,psync,,,,,\nh9,,,,\n" > "$f"
    (source ./wekatester
     WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1
     host_machine_id() { :; }
     writeback_targets) >>$SUITE_ASIDE
    [ "$(sed -n 3p "$f")" = "# superseded by -a: h1,,psync,,,,," ] &&
    sed -n 4p "$f" | grep -q "^h1,ubuntu,psync,0-3,/mnt/w," &&
    [ "$(sed -n 2p "$f")" = "h2,,,," ] && [ "$(sed -n 5p "$f")" = "h9,,,," ] && [ "$(wc -l < "$f" | tr -d " ")" = 5 ] ||
        { cat "$f" >&2; false; }'
t_assert "writeback: values are compared by meaning -- 1024M is 1G, so the line stays as written, even under -g" bash -c '
    d=$(wb_fixture); f="$d/host.csv"
    printf "h1,ubuntu,libaio,0-3,/mnt/w,,,,,/1024M/8/32,\n" > "$f"
    before=$(cat "$f")
    for g in 0 1; do
        (source ./wekatester
         WORK_DIR=$d; HOSTS=(h1); AUTO_LEVEL=max; TARGETS_FILE=$f; FAST_TRACK=1; REGEN_LAYOUT=$g
         host_machine_id() { :; }
         writeback_targets) >>$SUITE_ASIDE
        [ "$(cat "$f")" = "$before" ] || { echo "-g=$g:"; cat "$f"; exit 1; } >&2
    done'
t_assert "writeback: cpu lists compare as sets -- 2-4 is 2,3,4 but 2,4 is not 2-4" bash -c '
    d=$(mktemp -d)
    r=$(source ./wekatester; awkrun "BEGIN {
        parse_cpulist(\"2-4\", A); parse_cpulist(\"2,3,4\", B); parse_cpulist(\"2,4\", C)
        print (join_sorted(A, \",\") == join_sorted(B, \",\") ? \"True\" : \"False\"), (join_sorted(C, \",\") == join_sorted(A, \",\") ? \"True\" : \"False\")
    }")
    [ "$r" = "True False" ] || { echo "$r" >&2; false; }'

# -l re-tuned calibrated settings for the fleet run, against calibration's
# intent (Frank, 2026-10-05): it is gone, and naming it says why.
t_assert "-l and --load are removed, and say why" bash -c '
    for o in -l --load; do
        err=$( (source ./wekatester; parse_args -a cal "$o" h1) 2>&1 ) && { echo "$o accepted" >&2; exit 1; }
        case "$err" in *"-l/--load was removed: the test runs exactly what calibration measured"*) ;; *) echo "$err" >&2; exit 1;; esac
    done
    ! grep -q "load_check\|LOAD_CHECK" ./wekatester'
t_assert "cal_preflight: the aio pin check runs after the filesystem groups and before the fio servers, dry runs included" bash -c '
    m=$(sed -n "/^main() {/,/^}/p" ./wekatester)
    dry=$(printf "%s\n" "$m" | sed -n "/if \[ \"\$DRY_RUN\" -eq 1 \]; then/,/exit 0/p")
    printf "%s\n" "$dry" | awk "/collect_fs_groups/ {g = NR} /cal_preflight/ {c = NR} /stage_jobfiles/ {s = NR} END {exit !(g && c > g && s > c)}" &&
    printf "%s\n" "$m" | awk "/exit 0/ {d = 1} d && /collect_fs_groups/ {g = NR} d && /cal_preflight/ {c = NR} d && /start_fio_servers/ {s = NR} END {exit !(g && c > g && s > c)}" &&
    ! sed -n "/^calibrate() {/,/^}/p" ./wekatester | grep -q cal_aio_preflight'
t_assert "cal_preflight: a pin past the aio room stops before anything runs, from the probe and the host file alone" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8
    printf "aio_max_nr 65536\naio_nr 0\n" >> "$d/probe/h1"
    printf "# report iops\n[global]\nbs=4k\n[a]\nrw=randread\n" > "$d/set/031-i.job"
    pre() { (source ./wekatester
             AUTO_LEVEL=cal; WORK_DIR=$d; HOSTS=(h1); REGEN_LAYOUT=0; ENGINE=""; SET_DIR_OVERRIDE=$d/set
             run_host() { echo "RAN: $2" >> "$d/ran"; }
             cal_preflight); }
    # iops_r nj (col 22) 188, qd (col 25) 512: 96256 aio events, room 65536
    { printf "h1"; for i in $(seq 2 37); do case $i in (22) printf "\t188";; (25) printf "\t512";; (*) printf "\t-";; esac; done; printf "\n"; } > "$d/targets.final"
    err=$(pre 2>&1) && { echo "no stop: $err" >&2; exit 1; }
    case "$err" in *"iops_r pinned at numjobs=188 iodepth=512 needs 96256 aio events"*"nothing was run and the host file is unchanged"*) ;; *) echo "$err" >&2; exit 1;; esac
    [ ! -e "$d/ran" ] || { cat "$d/ran" >&2; exit 1; }
    # no pins: the shapes are worked out and the run goes on
    { printf "h1"; for i in $(seq 2 37); do printf "\t-"; done; printf "\n"; } > "$d/targets.final"
    pre >>$SUITE_ASIDE 2>&1 && [ "$(cut -f2 "$d/cal/shapes")" = h1 ]'

# --- what the tuner stages from it ---
t_assert "tuner: under -a cal the iops jobs run with latency accounting off, other jobs do not" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report iops\n[global]\nfilesize=10G\nnumjobs=4\nioengine=libaio\n[io]\nbs=4k\nrw=randread\niodepth=8\n" > "$FIX/src/031-iops.job"
    printf "# report latency iops\n[global]\nnumjobs=1\nioengine=libaio\n[l]\nbs=4k\nrw=randread\niodepth=1\n" > "$FIX/src/021-lat.job"
    (source ./wekatester; WEKATESTER_IOPS_NOLAT=1 auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1
    for k in disable_lat disable_clat disable_slat norandommap; do
        grep -qx "$k=1" "$FIX/jobs/h1/031-iops.job" || { echo "iops lacks $k" >&2; exit 1; }
        ! grep -q "^$k=" "$FIX/jobs/h1/021-lat.job" || { echo "lat has $k" >&2; exit 1; }
        ! grep -q "^$k=" "$FIX/jobs/h1/011-bw.job" || { echo "bw has $k" >&2; exit 1; }
    done
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1
    ! grep -q "^disable_lat=" "$FIX/jobs/h1/031-iops.job"'
t_assert "tuner: the shared read set is laid out for the widest reader, on the first host only" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\nnumjobs=4\nioengine=libaio\n[a]\nrw=read\n" > "$FIX/src/011-bw.job"
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE 2>&1
    # h2 reads the shared set with 9 jobs, h1 with 3
    { printf "h1"; for i in $(seq 2 37); do case $i in (6) printf "\t3";; (*) printf "\t-";; esac; done; printf "\n"
      printf "h2"; for i in $(seq 2 37); do case $i in (6) printf "\t9";; (*) printf "\t-";; esac; done; printf "\n"; } > "$FIX/targets.final"
    (source ./wekatester; WEKATESTER_NS="unified \$filenum/\$jobnum" \
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
    l1=$FIX/jobs/h1/000-wekatester-layout.job; l2=$FIX/jobs/h2/000-wekatester-layout.job
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$l1" && grep -qx "numjobs=9" "$l1" &&
    ! grep -q "shared\." "$l2" || { cat "$l1" "$l2" >&2; exit 1; }
    # h2 has nothing of its own to lay out: it sits the layout out, as fio
    # would refuse its section-less jobfile (Cursor Bugbot on PR #47)
    out=$(source ./wekatester; WORK_DIR=$FIX; HOSTS=(h1 h2); FIO_BIN=fio; TARGET_DIR=/t
          job_clients 000-wekatester-layout.job | tr "\n" " "
          echo "| $(fio_client_cmd 000-wekatester-layout.job h1)")
    case "$out" in ("h1 | "*"--client=h1 "*) ;; (*) echo "[$out]" >&2; exit 1;; esac
    case "$out" in (*--client=h2*) echo "h2 still a client: [$out]" >&2; false;; (*) true;; esac'
t_assert "tuner: a file with no report directive keeps its own geometry -- no slot is laid over it" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "[global]\nfilesize=2G\nnumjobs=5\nioengine=libaio\n[plain]\nrw=randread\nbs=4k\niodepth=7\n" > "$FIX/src/041-plain.job"
    # bandwidth, latency and iops read slots all carry a job count
    row=(h1); for i in $(seq 1 36); do row+=(-); done
    row[5]=3; row[13]=4; row[21]=6; row[24]=32
    (IFS=$(printf "\t"); echo "${row[*]}") > "$FIX/targets.final"
    (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) >>$SUITE_ASIDE 2>&1
    v=$FIX/jobs/h1/041-plain.job
    grep -qx "numjobs=5" "$v" && grep -qx "iodepth=7" "$v" && grep -qx "filesize=2G" "$v" &&
    grep -qx "numjobs=3" "$FIX/jobs/h1/011-bw.job" || { cat "$v" >&2; false; }'
t_assert "tuner: a hand-written layout under the reserved name is the operator's layout, staged as authored" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\ndirectory=/orig\n[lay]\ncreate_only=1\nnumjobs=2\nfilesize=1G\n" > "$FIX/src/000-wekatester-layout.job"
    row=(h1); for i in $(seq 1 36); do row+=(-); done; row[5]=3
    (IFS=$(printf "\t"); echo "${row[*]}") > "$FIX/targets.final"
    out=$( (source ./wekatester; auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "$FIX/targets.final" h1 h2) 2>&1 )
    v=$FIX/jobs/h1/000-wekatester-layout.job
    grep -qx "numjobs=2" "$v" && ! grep -qx "numjobs=3" "$v" &&
    case "$out" in (*"000-wekatester-layout.job: user-edited layout staged as-is"*"000-wekatester-layout.job type=layout"*) true;; (*) false;; esac ||
        { echo "$out" >&2; cat "$v" >&2; false; }'
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
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "" h1 h2) >>$SUITE_ASIDE 2>&1
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$FIX/jobs/h1/011-r.job" &&
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$FIX/jobs/h2/011-r.job" &&
    grep -q "^filename_format=\$filenum/\$jobnum$" "$FIX/jobs/h1/012-w.job"'
# A create_only section only lays out: a [global] rw=write it inherits does not
# make the read job mixed, so it still reads the shared dataset.
t_assert "tuner: unified staging reads the shared dataset past a create_only section's inherited rw=" bash -c '
    source ./tests/helpers.sh; tuner_fixture
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\nrw=write\n[create]\ncreate_only=1\n[r]\nrw=read\n" > "$FIX/src/011-r.job"
    (source ./wekatester
     WEKATESTER_NS="unified \$filenum/\$jobnum" \
     auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 "" h1 h2) >>$SUITE_ASIDE 2>&1
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$FIX/jobs/h1/011-r.job" &&
    grep -q "^filename_format=shared.\$filenum/\$jobnum$" "$FIX/jobs/h2/011-r.job" || { cat "$FIX/jobs/h1/011-r.job" >&2; false; }'
# Every read-only job of a unified set reads the grid calibration seeded, in
# the set's format: one with no format of its own, or another one, too. The
# re-derived layout then lays out that grid, never a $jobname namespace.
t_assert "tuner: unified staging gives every read-only job the set's shared format, its own missing or different" bash -c '
    source ./tests/helpers.sh; tuner_fixture; rm -f "$FIX/src/011-bw.job"
    printf "# report bandwidth\n[global]\nfilesize=1G\nnumjobs=4\nioengine=libaio\n[rd]\nrw=read\n" > "$FIX/src/011-r.job"
    printf "# report bandwidth\n[global]\nfilename_format=\$filenum/\$jobnum\nfilesize=1G\nnumjobs=4\nioengine=libaio\n[wr]\nrw=write\n" > "$FIX/src/012-w.job"
    printf "# report iops\n[global]\nfilename_format=\$jobnum.\$filenum\nfilesize=1G\nnumjobs=2\nioengine=libaio\n[rr]\nrw=randread\n" > "$FIX/src/031-r.job"
    ns=$(source ./wekatester; cal_namespace "$FIX/src") && [ "$ns" = "unified \$filenum/\$jobnum" ] || { echo "namespace: $ns" >&2; exit 1; }
    (source ./wekatester; generate_layout "$FIX/src" "$FIX/src") >>$SUITE_ASIDE 2>&1 || exit 1
    (source ./wekatester; WEKATESTER_NS="$ns" auto_tune "$FIX/src" "$FIX" max /mnt/weka 0 - h1 h2) >>$SUITE_ASIDE 2>&1 || exit 1
    for h in h1 h2; do for f in 011-r.job 031-r.job; do
        [ "$(grep "^filename_format=" "$FIX/jobs/$h/$f")" = "filename_format=shared.\$filenum/\$jobnum" ] ||
            { echo "$h/$f:" >&2; cat "$FIX/jobs/$h/$f" >&2; exit 1; }
    done; done
    l="$FIX/jobs/h1/000-wekatester-layout.job"
    grep -qx "filename_format=shared.\$filenum/\$jobnum" "$l" &&
    ! grep -q "\$jobname" "$FIX"/jobs/h1/* "$FIX"/jobs/h2/* || { cat "$l" >&2; false; }'

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
    [ "$a" = "unified \$filenum/\$jobnum" ] || { echo "set: $a" >&2; exit 1; }
    [ "$b" = "scratch \$jobnum.\$filenum" ] || { echo "flat: $b" >&2; exit 1; }
    [ "$c" = "scratch \$jobnum.\$filenum" ] || { echo "named: $c" >&2; false; }'
# A set may ship its own layout job without the generated marker (README):
# named as the layout job, it never chooses the calibration namespace.
t_assert "cal_namespace: an unmarked layout job by its reserved name is skipped" bash -c '
    d=$(mktemp -d); mkdir -p "$d/set"
    printf "[global]\nfallocate=none\n[l]\nfilename_format=x.\$jobnum.\$filenum\ncreate_only=1\n" > "$d/set/000-wekatester-layout.job"
    printf "# report iops\n[global]\n[a]\nrw=randread\n" > "$d/set/031-a.job"
    a=$( (source ./wekatester; cal_namespace "$d/set") )
    [ "$a" = "scratch \$jobnum.\$filenum" ] || { echo "set: $a" >&2; false; }'
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
    ! out=$( (source ./wekatester; parse_args -x 0 h1) 2>&1 );
    a=$?; ! out=$( (source ./wekatester; parse_args -x abc h1) 2>&1 ); b=$?
    [ "$a" -eq 0 ] && [ "$b" -eq 0 ]'
t_assert "-x stamps runtime+time_based on measured variants, never the layout" bash -c '
    source ./tests/helpers.sh; set_fixture; no_ssh_fixture
    d=$(mktemp -d)
    (WEKATESTER_SUITE_TARGET_DIR="$d/target"
     source ./wekatester
     LOCAL_MODE=1; HOSTS=(localhost); MASTER=localhost; AUTO_LEVEL=""
     WORK_DIR="$d/work"; DIRECTORY=/mnt/weka; DURATION=77
     WORKLOAD=smoke; mkdir -p "$WORK_DIR/jobs"
     stage_jobfiles && push_jobfiles) >>$SUITE_ASIDE || exit 1
    v="$d/target/localhost/011-smoke-readbw.job"
    l="$d/target/localhost/000-wekatester-layout.job"
    grep -q "^runtime=77$" "$v" && grep -q "^time_based=1$" "$v" &&
    ! grep -q "^runtime=77$" "$l"'
# Every -a level calibrates (Frank, 2026-10-05). safe and max search numjobs
# N/2, N, 2N at a fixed iodepth and nrfiles, in 15 s cells; cal and brutal
# walk the ladders in 30 s cells; :secs sets any level's cells.
t_assert "levels: safe and max cells default to 15 s, cal and brutal to 30; :secs sets any level; an exported CAL_RUNTIME wins" bash -c '
    rt() { (source ./wekatester; parse_args -a "$1" h1; echo "$CAL_RUNTIME"); }
    [ "$(rt safe)" = 15 ] && [ "$(rt max)" = 15 ] && [ "$(rt cal)" = 30 ] && [ "$(rt brutal)" = 30 ] &&
    [ "$(rt safe:40)" = 40 ] && [ "$(rt max:7)" = 7 ] && [ "$(rt cal:15)" = 15 ] &&
    [ "$( (source ./wekatester; parse_args -a h1; echo "$CAL_RUNTIME") )" = 15 ] &&
    [ "$(CAL_RUNTIME=22 bash -c "source ./wekatester; parse_args -a safe h1; echo \$CAL_RUNTIME")" = 22 ] ||
        { echo "safe=$(rt safe) max=$(rt max) cal=$(rt cal) brutal=$(rt brutal)" >&2; false; }'
t_assert "levels: the knobs each level gives the planner -- safe at 1 and 1, max at the deepest cal has chosen, no confirm pass for either" bash -c '
    k() { (source ./wekatester; AUTO_LEVEL=$1; cal_knobs "$2") | tr " " "\n" | grep -E "^(lvl|fq|fn|confirm|exh)=" | tr "\n" " "; }
    [ "$(k safe bw)" = "lvl=safe fq=1 fn=1 exh=0 confirm=0 " ] &&
    [ "$(k max bw)" = "lvl=max fq=16 fn=4 exh=0 confirm=0 " ] &&
    [ "$(k max iops)" = "lvl=max fq=32 fn=2 exh=0 confirm=0 " ] &&
    [ "$(k max lat)" = "lvl=max fq=- fn=- exh=0 confirm=0 " ] &&
    [ "$(k cal bw)" = "lvl=cal fq=- fn=- exh=0 confirm=3 " ] &&
    [ "$(k brutal iops)" = "lvl=brutal fq=- fn=- exh=1 confirm=5 " ] &&
    [ "$( (source ./wekatester; AUTO_LEVEL=max; cal_wide) )" = 2 ] &&
    [ "$( (source ./wekatester; AUTO_LEVEL=cal; cal_wide) )" = 4 ] ||
        { echo "safe-bw=[$(k safe bw)] max-bw=[$(k max bw)] max-iops=[$(k max iops)] cal-bw=[$(k cal bw)]" >&2; false; }'
t_assert "calibrate -a max: bandwidth and iops measure N/2, N and 2N at the fixed geometry; latency walks nrfiles at N" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8
    printf "# report bandwidth\n[global]\n[a]\nrw=read\n" > "$d/set/011-r.job"
    printf "# report iops\n[global]\nbs=4k\n[a]\nrw=randread\n" > "$d/set/031-i.job"
    printf "# report latency\n[global]\nbs=4k\n[a]\nrw=randread\n" > "$d/set/021-l.job"
    out=$( (source ./wekatester
     AUTO_LEVEL=max; CAL_RUNTIME=15; WORK_DIR=$d; HOSTS=(h1); MASTER=h1; FIO_BIN=fio; ENGINE=io_uring
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; SIMLOG=$d/simlog
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    # 8 cpus, weka on 7, the OS on 0-1: N=5, so N/2=2 and 2N=10
    cells() { grep -o "cal-$1-read-io_uring-nj[0-9]*-qd[0-9]*-nr[0-9]*-15s" "$d/simlog" | sed "s/cal-$1-read-io_uring-//; s/-15s//" | sort -u | tr "\n" " "; }
    [ "$(cells bw)" = "nj10-qd16-nr4 nj2-qd16-nr4 nj5-qd16-nr4 " ] &&
    [ "$(cells iops)" = "nj10-qd32-nr2 nj2-qd32-nr2 nj5-qd32-nr2 " ] &&
    [ "$(cells lat)" = "nj5-qd1-nr1 nj5-qd1-nr2 nj5-qd1-nr4 " ] &&
    case "$out" in *"bw-read: "*"(-a max: numjobs 2, 5, 10 at iodepth 16 nrfiles 4, the best reading wins, ties go heavier"*) true;; *) printf "%s\n" "$out" >&2; false;; esac ||
        { echo "bw=[$(cells bw)] iops=[$(cells iops)] lat=[$(cells lat)]" >&2; false; }'
t_assert "calibrate -a safe: the same three job counts at iodepth 1 and nrfiles 1, recorded for every member" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d)
    cal_sim_fixture "$d" h1:8 h2:8
    printf "# report iops\n[global]\nbs=4k\n[a]\nrw=randwrite\n" > "$d/set/032-w.job"
    out=$( (source ./wekatester
     AUTO_LEVEL=safe; CAL_RUNTIME=15; WORK_DIR=$d; HOSTS=(h1 h2); MASTER=h1; FIO_BIN=fio; ENGINE=io_uring
     TARGET_DIR=/dev/shm/x; DIRECTORY=/mnt/weka; REGEN_LAYOUT=0
     SET_DIR_OVERRIDE=$d/set; AUTH_DIR=$d/auth; CAL_SETTLE=0; SIMLOG=$d/simlog
     copy_to_master() { :; }
     run_host() { cal_sim_host "$@"; }
     calibrate) 2>&1 ) || { printf "%s\n" "$out" >&2; exit 1; }
    [ "$(grep -o "cal-iops-write-io_uring-nj[0-9]*-qd[0-9]*-nr[0-9]*" "$d/simlog" | sort -u | sed "s/.*io_uring-//" | tr "\n" " ")" = "nj10-qd1-nr1 nj2-qd1-nr1 nj5-qd1-nr1 " ] &&
    grep -q "^h1 io_uring " "$d/cal.results" && grep -q "^h2 io_uring " "$d/cal.results" &&
    [ "$(grep "^h1 " "$d/cal.results" | cut -d" " -f2-)" = "$(grep "^h2 " "$d/cal.results" | cut -d" " -f2-)" ] || { cat "$d/simlog" "$d/cal.results" >&2; false; }'

t_assert "calibrate: no-op without -a" bash -c '
    d=$(mktemp -d)
    (source ./wekatester
     AUTO_LEVEL=""; WORK_DIR=$d
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
    [ "$a" = "4 8 64M 64 2 256M" ] && [ "$b" = "8 1 2048M" ] || { echo "a=$a b=$b" >&2; exit 1; }
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
         "=== WEKATESTER_SYSINFO uname ===" "Linux client-a 4.18.0" \
         "=== WEKATESTER_SYSINFO lscpu ===" "CPU(s): 56" \
         "=== WEKATESTER_SYSINFO lspci ===" "lspci: not available" \
         "=== WEKATESTER_SYSINFO free ===" "Mem: 512G" \
         "=== WEKATESTER_SYSINFO fio ===" "fio-3.28"; }
     snapshot_sysinfo)
    grep -q "isolcpus=4-55" "$d/out/sysinfo/h1/cmdline" &&
    grep -q "wekafs" "$d/out/sysinfo/h1/mounts" &&
    grep -q "Linux client-a" "$d/out/sysinfo/h1/uname" &&
    grep -q "CPU(s): 56" "$d/out/sysinfo/h1/lscpu" &&
    grep -q "not available" "$d/out/sysinfo/h1/lspci" &&
    grep -q "Mem: 512G" "$d/out/sysinfo/h1/free" &&
    grep -q "fio-3.28" "$d/out/sysinfo/h1/fio"'

t_assert "pressure: start and end land as labeled files, end pulls the sar slice" bash -c '
    d=$(mktemp -d); mkdir -p "$d/out"
    (source ./wekatester
     WORK_DIR=$d; RUN_DIR=$d/out; HOSTS=(h1); RUN_STAMP=20260820-003501; RUN_EPOCH=1787200501
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
t_assert "sysinfo and pressure, run for real: a tool on PATH runs, a missing one is not available" bash -c '
    d=$(mktemp -d); b=$d/bin; mkdir -p "$b" "$d/w" "$d/run"
    for c in cat uname date; do p=$(type -P "$c") || { echo "no $c on this host" >&2; exit 1; }; ln -s "$p" "$b/$c"; done
    printf "#!/bin/sh\necho up 1 day\n" > "$b/uptime"
    printf "#!/bin/sh\necho sar \"\$@\"\n" > "$b/sar"
    chmod +x "$b/uptime" "$b/sar"
    (source ./wekatester; HOSTS=(h1); WORK_DIR=$d/w; RUN_DIR=$d/run; RUN_STAMP=20261009-120000; RUN_EPOCH=$(date +%s); FIO_BIN=fio
     run_host() { printf "%s" "$2" > "$d/cmd.$1.$CMDK"; }
     CMDK=sysinfo snapshot_sysinfo; CMDK=pressure snapshot_pressure end) >>"$SUITE_ASIDE" 2>&1
    [ -s "$d/cmd.h1.sysinfo" ] && [ -s "$d/cmd.h1.pressure" ] || { echo "strings not captured" >&2; exit 1; }
    bash=$(type -P bash)
    s=$(PATH=$b "$bash" -c "$(cat "$d/cmd.h1.sysinfo")" 2>&1); p=$(PATH=$b "$bash" -c "$(cat "$d/cmd.h1.pressure")" 2>&1)
    printf "%s\n" "$s" | grep -qx "up 1 day" && printf "%s\n" "$s" | grep -qx "lspci: not available" &&
    printf "%s\n" "$s" | grep -qx "weka: not available" && printf "%s\n" "$p" | grep -qE "^sar -A -s [0-9]{2}:[0-9]{2}:[0-9]{2} -e " ||
        { printf "%s\n" "$s" "$p"; exit 1; } >&2'
# The sar window, run for real under bash: the worker's zone and day decide,
# never the controller's (review #8, Frank, 2026-10-11).
wt_sar_cmd() {   # wt_sar_cmd <start-epoch> <out-file>: the end-of-run string
    local d; d=$(mktemp -d)
    (source ./wekatester; HOSTS=(h1); WORK_DIR=$d; RUN_DIR=$d; RUN_EPOCH=$1; SUITE_SAR_OUT=$2
     printf -v RUN_STAMP '%(%Y%m%d-%H%M%S)T' "$1"
     run_host() { printf "%s" "$2" > "$SUITE_SAR_OUT"; }
     snapshot_pressure end) >>"$SUITE_ASIDE" 2>&1
}
wt_sar_bin() {   # wt_sar_bin <dir> [sar]: cat and date, plus a fake sar
    local c p
    mkdir -p "$1"
    for c in cat date; do p=$(type -P "$c") || { echo "no $c on this host" >&2; return 1; }; ln -s "$p" "$1/$c"; done
    [ -z "$2" ] || { printf '#!/bin/sh\necho sar "$@"\n' > "$1/sar"; chmod +x "$1/sar"; }
}
export -f wt_sar_cmd wt_sar_bin
t_assert "pressure sar: -s is the start in the worker zone, not the controller one" bash -c '
    d=$(mktemp -d); bash=$(type -P bash); wt_sar_bin "$d/b" sar || exit 1
    S=$(( $(date +%s) - 5 )); wt_sar_cmd "$S" "$d/cmd" && [ -s "$d/cmd" ] || { echo "no command captured" >&2; exit 1; }
    seen=()
    for z in UTC America/New_York; do
        out=$(TZ=$z PATH=$d/b "$bash" -c "$(cat "$d/cmd")" 2>&1)
        want=$(TZ=$z date -d @$S +%H:%M:%S)
        [ "$(TZ=$z date -d @$S +%F)" = "$(TZ=$z date +%F)" ] || want=00:00:00
        printf "%s\n" "$out" | command grep -qE "^sar -A -s $want -e [0-9]{2}:[0-9]{2}:[0-9]{2}\$" ||
            { echo "$z: want -s $want, got:"; printf "%s\n" "$out"; exit 1; } >&2
        seen+=("$want")
    done
    [ "${seen[0]}" != "${seen[1]}" ] || { echo "both zones gave -s ${seen[0]}" >&2; exit 1; }'
t_assert "pressure sar: a start on an earlier worker day reads from 00:00:00" bash -c '
    d=$(mktemp -d); bash=$(type -P bash); wt_sar_bin "$d/b" sar || exit 1
    wt_sar_cmd $(( $(date +%s) - 2 * 86400 )) "$d/cmd" && [ -s "$d/cmd" ] || { echo "no command captured" >&2; exit 1; }
    out=$(TZ=UTC PATH=$d/b "$bash" -c "$(cat "$d/cmd")" 2>&1)
    printf "%s\n" "$out" | command grep -qE "^sar -A -s 00:00:00 -e [0-9]{2}:[0-9]{2}:[0-9]{2}\$" ||
        { printf "%s\n" "$out"; exit 1; } >&2'
t_assert "pressure sar: no sar on the worker says so" bash -c '
    d=$(mktemp -d); bash=$(type -P bash); wt_sar_bin "$d/b" || exit 1
    wt_sar_cmd $(date +%s) "$d/cmd" && [ -s "$d/cmd" ] || { echo "no command captured" >&2; exit 1; }
    out=$(PATH=$d/b "$bash" -c "$(cat "$d/cmd")" 2>&1)
    printf "%s\n" "$out" | command grep -qx "sar: not available" ||
        { printf "%s\n" "$out"; exit 1; } >&2'

# --- sysinfo receive path: nic-<dev> per device-backed netdev, host knobs ---
t_assert "sysinfo NIC: a device-backed netdev gets nic-<dev> (PCIe, NUMA, IRQs, ethtool -g/-l/-c/-a, mlnx_qos) and the host knobs land" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    nic_sysinfo "$d"; f=$d/out/sysinfo/h1
    [ "$(cat "$f/nics")" = eth0 ] && [ ! -e "$f/nic-lo" ] || { echo "nics: $(cat "$f/nics")" >&2; exit 1; }
    diff <(printf "%s\n" "bus 0000:17:00.0" "driver mlx5_core" "numa_node 1" \
        "current_link_speed 16.0_GT/s_PCIe" "current_link_width 8" "max_link_speed 16.0_GT/s_PCIe" "max_link_width 16" \
        "msi_irqs 2" "irq_cpus 101:4 102:-" \
        "--- ethtool -g" "ethtool -g eth0" "--- ethtool -l" "ethtool -l eth0" \
        "--- ethtool -c" "ethtool -c eth0" "--- ethtool -a" "ethtool -a eth0" \
        "--- mlnx_qos -i" "mlnx_qos -i eth0") "$f/nic-eth0" >&2 || exit 1
    diff <(printf "net.core.netdev_max_backlog 1000\nnet.ipv4.tcp_rmem 4096\t131072\t6291456\n") <(head -n 2 "$f/sysctl") >&2 &&
    grep -qE "^ *2 performance\$" "$f/cpu-governor" && [ "$(cat "$f/irqbalance")" = running ] && [ ! -e "$d/esc" ] ||
        { cat "$f/cpu-governor" "$f/irqbalance"; exit 1; } >&2'
t_assert "sysinfo NIC: no ethtool, mlnx_qos or pgrep on the worker says so per item" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    rm -f "$d/bin/ethtool" "$d/bin/mlnx_qos" "$d/bin/pgrep"
    nic_sysinfo "$d"; f=$d/out/sysinfo/h1
    [ "$(grep -cx "not available: ethtool not installed" "$f/nic-eth0")" = 4 ] &&
    grep -A1 -x -- "--- mlnx_qos -i" "$f/nic-eth0" | grep -qx "not available: mlnx_qos not installed" &&
    [ "$(cat "$f/irqbalance")" = "not available: pgrep not installed" ] && [ ! -e "$d/esc" ] ||
        { cat "$f/nic-eth0" "$f/irqbalance"; exit 1; } >&2'
t_assert "sysinfo NIC: an unreadable value or a silent tool failure is recorded, never blank" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    p=$d/root/sys/devices/pci0000:00/0000:17:00.0
    rm -rf "$p/numa_node" "$p/current_link_speed" "$p/driver" "$p/msi_irqs" \
        "$d/root/proc/sys/net/ipv4/tcp_rmem" "$d/root/sys/devices/system/cpu/cpu0/cpufreq"
    printf "#!/bin/sh\ncase \"\$1\" in -a) exit 94 ;; esac\necho \"ethtool \$*\"\n" > "$d/bin/ethtool"
    printf "#!/bin/sh\nexit 1\n" > "$d/bin/pgrep"
    nic_sysinfo "$d"; f=$d/out/sysinfo/h1; n=$f/nic-eth0; v=/sys/class/net/eth0/device
    grep -qx "numa_node not available: $v/numa_node not readable" "$n" &&
    grep -qx "current_link_speed not available: $v/current_link_speed not readable" "$n" &&
    grep -qx "current_link_width 8" "$n" &&
    grep -qx "driver not available: $v/driver links nowhere" "$n" &&
    grep -qx "msi_irqs not available: $v/msi_irqs not readable" "$n" && grep -qx "irq_cpus not available: no msi_irqs" "$n" &&
    grep -A1 -x -- "--- ethtool -a" "$n" | grep -qx "(ethtool exited 94)" &&
    grep -qx "net.ipv4.tcp_rmem not available: /proc/sys/net/ipv4/tcp_rmem not readable" "$f/sysctl" &&
    grep -qx "net.core.netdev_max_backlog 1000" "$f/sysctl" &&
    [ "$(cat "$f/cpu-governor")" = "not available: /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor not readable" ] &&
    [ "$(cat "$f/irqbalance")" = "not running" ] ||
        { cat "$n" "$f/sysctl" "$f/cpu-governor" "$f/irqbalance"; exit 1; } >&2'
t_assert "sysinfo NIC: no device-backed netdev says so in nics, and no nic- file" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    rm -rf "$d/root/sys/class/net/eth0"
    nic_sysinfo "$d"; f=$d/out/sysinfo/h1
    set -- "$f"/nic-*
    [ "$(cat "$f/nics")" = "not available: no netdev in /sys/class/net has a device link" ] && [ ! -e "$1" ] ||
        { ls "$f"; cat "$f/nics"; exit 1; } >&2'
t_assert "sysinfo NIC: mlnx_qos failing as non-root is retried under the first escalator that works, swept once per host" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    mkdir "$d/root/sys/class/net/eth1"; ln -s "$d/root/sys/devices/pci0000:00/0000:17:00.0" "$d/root/sys/class/net/eth1/device"
    printf "#!/bin/sh\nif [ -n \"\$SUITE_UNDER\" ]; then echo \"PFC under \$SUITE_UNDER\"; else echo \"Operation not permitted\"; exit 1; fi\n" > "$d/bin/mlnx_qos"
    printf "#!/bin/sh\necho \"sudo \$*\" >> \"%s/esc\"\nshift\nSUITE_UNDER=sudo exec \"\$@\"\n" "$d" > "$d/bin/sudo"
    nic_sysinfo "$d"; f=$d/out/sysinfo/h1
    for n in eth0 eth1; do
        diff <(printf "%s\n" "--- mlnx_qos -i" "Operation not permitted" "(mlnx_qos exited 1)" \
            "--- mlnx_qos -i, again under sudo -n" "PFC under sudo") <(sed -n "/^--- mlnx_qos/,\$p" "$f/nic-$n") >&2 || exit 1
    done
    [ "$(grep -cx "sudo -n true" "$d/esc")" = 1 ] && [ "$(grep -c "^sudo -n .*/mlnx_qos -i eth" "$d/esc")" = 2 ] ||
        { cat "$d/esc"; exit 1; } >&2'
t_assert "sysinfo NIC: mlnx_qos failing with no working escalator says so; as root it is not retried" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    printf "#!/bin/sh\necho \"Operation not permitted\"; exit 1\n" > "$d/bin/mlnx_qos"
    nic_sysinfo "$d"; n=$d/out/sysinfo/h1/nic-eth0
    tail -n 1 "$n" | grep -qx "not available: mlnx_qos failed as a non-root user and no passwordless escalator works" &&
    grep -qx "(mlnx_qos exited 1)" "$n" && grep -qx "sudo -n true" "$d/esc" ||
        { cat "$n" "$d/esc"; exit 1; } >&2
    r=$(mktemp -d); nic_fixture "$r" || exit 1
    cp "$d/bin/mlnx_qos" "$r/bin/mlnx_qos"; printf "#!/bin/sh\necho 0\n" > "$r/bin/id"
    nic_sysinfo "$r"; n=$r/out/sysinfo/h1/nic-eth0
    diff <(printf "%s\n" "--- mlnx_qos -i" "Operation not permitted" "(mlnx_qos exited 1)") <(sed -n "/^--- mlnx_qos/,\$p" "$n") >&2 &&
    [ ! -e "$r/esc" ]'
t_assert "sysinfo NIC: rp_filter and arp_* for all, default and each NIC, unreadable ones said; chronyc tracking" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    nic_sysinfo "$d"; f=$d/out/sysinfo/h1; c=/proc/sys/net/ipv4/conf
    grep -qx "net.ipv4.conf.all.rp_filter 1" "$f/sysctl" && grep -qx "net.ipv4.conf.eth0.rp_filter 2" "$f/sysctl" &&
    grep -qx "net.ipv4.conf.eth0.arp_ignore 1" "$f/sysctl" &&
    grep -qx "net.ipv4.conf.default.rp_filter not available: $c/default/rp_filter not readable" "$f/sysctl" &&
    grep -qx "net.ipv4.conf.eth0.arp_announce not available: $c/eth0/arp_announce not readable" "$f/sysctl" &&
    [ "$(grep -c "^net.ipv4.conf\." "$f/sysctl")" = 12 ] && [ "$(cat "$f/chrony")" = "chronyc tracking" ] ||
        { cat "$f/sysctl" "$f/chrony"; exit 1; } >&2
    rm "$d/bin/chronyc"; rm -rf "$d/out"; nic_sysinfo "$d"
    diff <(printf "%s\n" "not available: chronyc not installed; timedatectl instead" "not available: timedatectl not installed") "$f/chrony" >&2'
t_assert "pressure counters: start and end each keep tcp (nstat -asz), ethtool -S and AER per NIC, raw" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    E=$(( $(date +%s) - 100 )); nic_pressure "$d" start "$E"; nic_pressure "$d" end "$E"; f=$d/out/sysinfo/h1
    for s in start end; do
        [ "$(cat "$f/nics-$s")" = eth0 ] && [ "$(cat "$f/tcp-$s")" = "nstat -asz" ] &&
        [ "$(cat "$f/ethtool-S-eth0-$s")" = "ethtool -S eth0" ] &&
        diff <(printf "%s\n" "--- aer_dev_correctable" "RxErr 0" "TOTAL_ERR_COR 3" "--- aer_dev_nonfatal" "TOTAL_ERR_NONFATAL 0" \
            "--- aer_dev_fatal" "not available: /sys/class/net/eth0/device/aer_dev_fatal not readable") "$f/aer-eth0-$s" >&2 ||
            { echo "side $s:"; ls "$f"; exit 1; } >&2
    done
    [ ! -e "$f/kernel-log-start" ] && [ -e "$f/kernel-log-end" ] && [ ! -e "$f/ethtool-S-lo-start" ]'
t_assert "pressure counters: no nstat reads /proc/net raw, no ethtool says so" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    rm "$d/bin/nstat" "$d/bin/ethtool"; mkdir -p "$d/root/proc/net"
    printf "Tcp: RetransSegs\nTcp: 7\n" > "$d/root/proc/net/snmp"
    nic_pressure "$d" start "$(date +%s)"; f=$d/out/sysinfo/h1
    diff <(printf "%s\n" "not available: nstat not installed; /proc/net/snmp and /proc/net/netstat instead" "Tcp: RetransSegs" "Tcp: 7" \
        "not available: /proc/net/netstat not readable") "$f/tcp-start" >&2 &&
    [ "$(cat "$f/ethtool-S-eth0-start")" = "not available: ethtool not installed" ]'
# virtio: the netdev's device is not a PCI function (Frank, 2026-10-23)
t_assert "sysinfo NIC: a virtio NIC reads NUMA, PCIe link and IRQs from its PCI parent, labelled; with no PCI ancestor it says so" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" && nic_virtio "$d" || exit 1
    nic_sysinfo "$d"; f=$d/out/sysinfo/h1; L=" pci_parent=0000:00:06.0"; P=/sys/devices/pci0000:00/0000:00:06.0; v=/sys/class/net/eth2/device
    [ "$(cat "$f/nics")" = "eth0 eth1 eth2" ] && ! grep -q pci_parent "$f/nic-eth0" && grep -qx "numa_node 1" "$f/nic-eth0" || { cat "$f/nics" "$f/nic-eth0"; exit 1; } >&2
    diff <(printf "%s\n" "bus virtio1" "driver virtio_net" "numa_node 0$L" \
        "current_link_speed 8.0_GT/s_PCIe$L" "current_link_width 4$L" "max_link_speed 8.0_GT/s_PCIe$L" \
        "max_link_width not available: $P/max_link_width not readable$L" "msi_irqs 2$L" "irq_cpus 40:0-1 41:-$L") <(head -n 9 "$f/nic-eth1") >&2 &&
    diff <(printf "%s\n" "bus virtio2" "driver virtio_net" \
        "pci_parent not available: $v is not a PCI function and no device above it is" \
        "numa_node not available: $v/numa_node not readable" \
        "current_link_speed not available: $v/current_link_speed not readable" \
        "current_link_width not available: $v/current_link_width not readable" \
        "max_link_speed not available: $v/max_link_speed not readable" \
        "max_link_width not available: $v/max_link_width not readable" \
        "msi_irqs not available: $v/msi_irqs not readable" "irq_cpus not available: no msi_irqs" "--- ethtool -g") <(head -n 11 "$f/nic-eth2") >&2'
t_assert "pressure counters: a virtio NIC reads AER from its PCI parent, labelled; with no PCI ancestor it says so" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" && nic_virtio "$d" || exit 1
    nic_pressure "$d" start "$(date +%s)"; f=$d/out/sysinfo/h1; L=" pci_parent=0000:00:06.0"; P=/sys/devices/pci0000:00/0000:00:06.0
    diff <(printf "%s\n" "--- aer_dev_correctable$L" "TOTAL_ERR_COR 0" "--- aer_dev_nonfatal$L" "not available: $P/aer_dev_nonfatal not readable" \
        "--- aer_dev_fatal$L" "not available: $P/aer_dev_fatal not readable") "$f/aer-eth1-start" >&2 &&
    [ "$(head -n 1 "$f/aer-eth2-start")" = "pci_parent not available: /sys/class/net/eth2/device is not a PCI function and no device above it is" ] &&
    grep -qx "not available: /sys/class/net/eth2/device/aer_dev_fatal not readable" "$f/aer-eth2-start" &&
    grep -qx "TOTAL_ERR_COR 3" "$f/aer-eth0-start" && ! grep -q pci_parent "$f/aer-eth0-start" || { cat "$f"/aer-eth*-start; exit 1; } >&2'
t_assert "kernel log: dmesg windowed from the run start by the uptime, at end only" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    nic_pressure "$d" end "$(( $(date +%s) - 100 ))"; k=$d/out/sysinfo/h1/kernel-log-end
    head -n 1 "$k" | grep -qE "^# dmesg, from 89[89] s after boot \(the run start\)\$" &&
    diff <(printf "%s\n" "[  950.000000] in the run" "no stamp, still in" "[  990.500000] late in the run") <(tail -n +2 "$k") >&2 &&
    [ ! -e "$d/esc" ] || { cat "$k"; exit 1; } >&2'
t_assert "kernel log: dmesg refused as non-root is read under the escalator" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    printf "#!/bin/sh\nif [ -n \"\$SUITE_UNDER\" ]; then cat \"%s/dmesg.out\"; else echo \"dmesg: read kernel buffer failed: Operation not permitted\"; exit 1; fi\n" "$d" > "$d/bin/dmesg"
    printf "#!/bin/sh\necho \"sudo \$*\" >> \"%s/esc\"\nshift\nSUITE_UNDER=sudo exec \"\$@\"\n" "$d" > "$d/bin/sudo"
    nic_pressure "$d" end "$(( $(date +%s) - 100 ))"; k=$d/out/sysinfo/h1/kernel-log-end
    diff <(printf "%s\n" "dmesg: read kernel buffer failed: Operation not permitted" "(dmesg exited 1)") <(head -n 2 "$k") >&2 &&
    sed -n 3p "$k" | grep -qE "^# dmesg under sudo -n, from 89[89] s after boot" &&
    [ "$(tail -n 1 "$k")" = "[  990.500000] late in the run" ] && ! grep -q "before the run" "$k" ||
        { cat "$k"; exit 1; } >&2'
t_assert "kernel log: dmesg refused and no escalator falls back to journalctl -k --since the run start" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    printf "#!/bin/sh\necho \"dmesg: read kernel buffer failed: Operation not permitted\"; exit 1\n" > "$d/bin/dmesg"
    E=$(( $(date +%s) - 100 )); nic_pressure "$d" end "$E"
    diff <(printf "%s\n" "dmesg: read kernel buffer failed: Operation not permitted" "(dmesg exited 1)" \
        "not available: dmesg failed as a non-root user and no passwordless escalator works" \
        "# journalctl -k --since @$E (the run start)" "journalctl -k --no-pager -o short-iso --since @$E") "$d/out/sysinfo/h1/kernel-log-end" >&2'
t_assert "kernel log: the last 2000 lines are kept and the drop is said; an overwritten start, a boot inside the run and an empty window are said" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    for i in $(seq 1 2500); do echo "[  950.000000] line $i"; done > "$d/dmesg.out"
    nic_pressure "$d" end "$(( $(date +%s) - 100 ))"; k=$d/out/sysinfo/h1/kernel-log-end
    [ "$(sed -n 2p "$k")" = "(the oldest line in the buffer is at 950 s, after the run start: earlier lines were overwritten)" ] &&
    [ "$(sed -n 3p "$k")" = "(500 earlier lines dropped: the last 2000 kept)" ] && [ "$(sed -n 4p "$k")" = "[  950.000000] line 501" ] &&
    [ "$(tail -n 1 "$k")" = "[  950.000000] line 2500" ] && [ "$(wc -l < "$k")" -eq 2003 ] || { head -n 4 "$k"; exit 1; } >&2
    echo "[  950.000000] line 1" > "$d/dmesg.out"; rm -rf "$d/out"; nic_pressure "$d" end "$(( $(date +%s) - 2000 ))"
    [ "$(sed -n 2p "$k")" = "(this host booted after the run start: dmesg holds nothing from before the boot)" ] &&
    [ "$(sed -n 3p "$k")" = "[  950.000000] line 1" ] || { head -n 3 "$k"; exit 1; } >&2
    printf "[  100.000000] long before\n" > "$d/dmesg.out"; rm -rf "$d/out"
    nic_pressure "$d" end "$(( $(date +%s) - 100 ))"
    [ "$(tail -n 1 "$k")" = "(no kernel log line in the window)" ] || { cat "$k"; exit 1; } >&2'

# --- the fio server log, read at a failed run's teardown (issue #18, Frank, 2026-10-23) ---
# A daemonized fio server logs only to syslog: its bind failure sits in the
# journal while the port check sees a dead port.
t_assert "fio server log: a failed run's teardown reads journalctl -t fio from the run start under the escalator; start and a clean end have none" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    printf "#!/bin/sh\ncase \"\$*\" in (*\"-t fio\"*) ;; (*) echo \"journalctl \$*\"; exit 0;; esac\nif [ -n \"\$SUITE_UNDER\" ]; then echo \"\$*\"; cat \"%s/fio.log\"; else echo \"user-only line\"; fi\n" "$d" > "$d/bin/journalctl"
    printf "#!/bin/sh\necho \"sudo \$*\" >> \"%s/esc\"\nshift\nSUITE_UNDER=sudo exec \"\$@\"\n" "$d" > "$d/bin/sudo"
    printf "%s\n" "2026-10-23T21:17:06+0000 h1 fio[2541056]: fio: bind: Cannot assign requested address" > "$d/fio.log"
    E=$(( $(date +%s) - 100 )); f=$d/out/sysinfo/h1
    nic_pressure "$d" start "$E"; nic_pressure "$d" end "$E"
    [ ! -e "$f/fio-server-log-start" ] && [ ! -e "$f/fio-server-log-end" ] && [ -e "$f/kernel-log-end" ] || { ls "$f"; exit 1; } >&2
    rm -rf "$d/out"; nic_pressure "$d" end "$E" fio-log
    diff <(printf "%s\n" "# sudo -n journalctl -t fio --since @$E (the run start): every fio that logged in the window, not only this run'"'"'s" \
        "-q -t fio --no-pager -o short-iso --since @$E" "2026-10-23T21:17:06+0000 h1 fio[2541056]: fio: bind: Cannot assign requested address") "$f/fio-server-log-end" >&2 &&
    grep -q "^sudo -n journalctl -q -t fio" "$d/esc"'
t_assert "fio server log: root reads it directly, a non-root login with no escalator says what it misses, an empty window says so" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    printf "#!/bin/sh\ncase \"\$*\" in (*\"-t fio\"*) cat \"%s/fio.log\";; (*) echo \"journalctl \$*\";; esac\n" "$d" > "$d/bin/journalctl"
    printf "%s\n" "2026-10-23T21:16:26+0000 h1 fio[2540986]: fio: server listening on 0.0.0.0,8765" > "$d/fio.log"
    E=$(( $(date +%s) - 100 )); f=$d/out/sysinfo/h1; H="# journalctl -t fio --since @$E (the run start): every fio that logged in the window, not only this run'"'"'s"
    nic_pressure "$d" end "$E" fio-log
    diff <(printf "%s\n" "# read as a non-root user and no passwordless escalator works: only this user'"'"'s entries show, a root fio server'"'"'s are missing" "$H" \
        "2026-10-23T21:16:26+0000 h1 fio[2540986]: fio: server listening on 0.0.0.0,8765") "$f/fio-server-log-end" >&2 || exit 1
    printf "#!/bin/sh\necho 0\n" > "$d/bin/id"; : > "$d/fio.log"; rm -rf "$d/out" "$d/esc"; nic_pressure "$d" end "$E" fio-log
    diff <(printf "%s\n" "$H" "(no fio server log line in the window)") "$f/fio-server-log-end" >&2 && [ ! -e "$d/esc" ]'
t_assert "fio server log: a host without journalctl says not available and reads nothing else" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d" || exit 1
    rm "$d/bin/journalctl"; mkdir -p "$d/root/var/log"; echo "Oct 23 h1 fio[1]: fio: bind: x" > "$d/root/var/log/syslog"
    nic_pressure "$d" end "$(( $(date +%s) - 100 ))" fio-log; f=$d/out/sysinfo/h1/fio-server-log-end
    [ "$(cat "$f")" = "not available: journalctl not installed, so this host keeps no journal to read" ] || { cat "$f"; exit 1; } >&2'
t_assert "fio server log: only a failed run reads it at teardown, and one that stopped before the servers started says it has none" bash -c '
    d=$(mktemp -d)
    grep -q "trap '\''rc=\$?; RUN_RC=\$rc; cleanup; " ./wekatester || { echo "the EXIT trap does not hand cleanup the status" >&2; exit 1; }
    t() {   # t <tag> <RUN_RC> <FIO_STARTED>: cleanup, its end capture string in end.<tag>
        (source ./wekatester
         WORK_DIR=$d/work; RUN_DIR=$d/run; mkdir -p "$WORK_DIR" "$RUN_DIR"
         HOSTS=(h1); TARGET_DIR=/dev/shm/x; RUN_EPOCH=1; RUN_RC=$2; FIO_STARTED=$3; T=$1
         run_host() { case "$2" in (*WEKATESTER_SYSINFO*) printf "%s\n" "$2" > "$d/end.$T";; esac; }
         cleanup) > "$d/console.$1" 2>&1
    }
    t failed 1 1; t clean 0 1; t early 1 0
    grep -q "WEKATESTER_SYSINFO fio-server-log" "$d/end.failed" &&
    grep -q "WEKATESTER_SYSINFO kernel-log" "$d/end.clean" && ! grep -q fio-server-log "$d/end.clean" &&
    grep -q "WEKATESTER_SYSINFO kernel-log" "$d/end.early" && ! grep -q fio-server-log "$d/end.early" &&
    grep -q "note: no fio server log to read: the run stopped before the fio servers started" "$d/console.early" &&
    ! grep -q "fio server log" "$d/console.failed" "$d/console.clean" || { tail -n +1 "$d"/console.* "$d"/end.*; exit 1; } >&2'

# --- whole-host bound on the sysinfo and pressure sessions (Frank, 2026-10-23) ---
t_assert "session bound: a host past WT_SYSINFO_TIMEOUT is cut off and says where, the others finish, the run carries on" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d/h1" && nic_fixture "$d/h2" || exit 1
    s=$(type -P sleep); tag=$$$RANDOM
    printf "#!/bin/sh\ncase \"\$1\" in -g) exec %s 6.%s ;; esac\necho \"ethtool \$*\"\n" "$s" "$tag" > "$d/h1/bin/ethtool"
    SECONDS=0; WT_SYSINFO_TIMEOUT=2 bound_capture "$d" sysinfo h1 h2; took=$SECONDS
    f=$d/out/sysinfo; c=$d/console
    grep -q "WARNING: system info on h1 cut off after 2 s (WT_SYSINFO_TIMEOUT); the partial capture is kept\$" "$c" &&
    ! grep -q "WARNING.*h2" "$c" && [ "$(tail -n 1 "$c")" = "carried on" ] && [ "$took" -lt 6 ] || { echo "took $took s"; cat "$c"; exit 1; } >&2
    [ "$(cat "$f/h1/session-timeout")" = "system info cut off after 2 s (WT_SYSINFO_TIMEOUT)" ] &&
    diff <(printf "%s\n" "--- ethtool -g" "not available: the session was cut off here, after 2 s (WT_SYSINFO_TIMEOUT)") <(tail -n 2 "$f/h1/nic-eth0") >&2 &&
    [ -s "$f/h1/sysctl" ] && [ ! -e "$f/h2/session-timeout" ] && [ "$(tail -n 1 "$f/h2/nic-eth0")" = "mlnx_qos -i eth0" ] ||
        { ls "$f/h1" "$f/h2"; cat "$f/h1/nic-eth0"; exit 1; } >&2
    if pgrep -f "sleep 6\.$tag" >>$SUITE_ASIDE; then echo "the cut-off session left its tool running" >&2; exit 1; fi'
t_assert "session bound: a pressure session past the bound keeps its partial capture and its own session-timeout item" bash -c '
    source ./tests/helpers.sh; d=$(mktemp -d); nic_fixture "$d/h1" || exit 1
    printf "#!/bin/sh\nexec %s 6\n" "$(type -P sleep)" > "$d/h1/bin/dmesg"
    WT_SYSINFO_TIMEOUT=2 bound_capture "$d" end h1; f=$d/out/sysinfo/h1; c=$d/console
    grep -q "WARNING: pressure (end) on h1 cut off after 2 s (WT_SYSINFO_TIMEOUT); the partial capture is kept\$" "$c" &&
    [ "$(tail -n 1 "$c")" = "carried on" ] && [ "$(cat "$f/session-timeout-end")" = "pressure (end) cut off after 2 s (WT_SYSINFO_TIMEOUT)" ] &&
    [ "$(cat "$f/kernel-log-end")" = "not available: the session was cut off here, after 2 s (WT_SYSINFO_TIMEOUT)" ] &&
    [ "$(cat "$f/tcp-end")" = "nstat -asz" ] && [ ! -e "$f/sar-end" ] || { ls "$f"; cat "$c"; exit 1; } >&2'
t_assert "session bound: WT_SYSINFO_TIMEOUT that is not a whole number of seconds above 0 stops the run before it starts" bash -c '
    source ./tests/helpers.sh; uname_fixture Linux
    for v in abc 0 -5 1.5; do
        err=$(WT_SYSINFO_TIMEOUT=$v ./wekatester h1 2>&1 >>$SUITE_ASIDE) && { echo "ran with $v" >&2; exit 1; }
        case "$err" in
            *"WT_SYSINFO_TIMEOUT must be a whole number of seconds above 0, not '\''$v'\''"*) ;;
            *) echo "[$v] $err" >&2; exit 1;;
        esac
    done'

# --- -h documents every option the parser accepts ---
# Drift here is silent: an option added to parse_args works but is invisible,
# which is how -x/--duration shipped undocumented in the synopsis.
t_assert "help: every parsed option appears in -h as its own token" bash -c '
    # Word-boundary matching, not substring: "-c" must not pass because
    # "--ignore-capacity" contains it, and a short option must not pass on
    # the strength of its long form alone.
    h=$(./wekatester -h)
    miss=""
    for o in -d -w -f -s -o -e -p -t -x -r -n -g -u -a -i -v -h \
             --output --engine --password --targets --duration --unlink \
             --auto --ignore-capacity --any-fs --allow-fio-mismatch --identity --version --help; do
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
     writeback_targets) >>$SUITE_ASIDE 2>&1
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
     writeback_targets) >>$SUITE_ASIDE 2>&1
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
            resolve_targets phase1 "$d/hl.csv" - - - node1) 2>&1 >>$SUITE_ASIDE )
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
     run_host() { case "$2" in (t=*) echo "F $1" >> "$d/order"; echo "weka /mnt/weka wekafs rw,forcedirect 0 0";;
                              (p=*) echo "P $1" >> "$d/order";; (*) return 1;; esac; }
     verify_mount_mode) >>$SUITE_ASIDE 2>&1 || { echo "guard failed" >&2; exit 1; }
    [ "$(wc -l < "$d/order")" -eq 6 ] &&
    [ "$(head -3 "$d/order" | cut -c1 | sort -u)" = F ] &&
    [ "$(tail -3 "$d/order" | cut -c1 | sort -u)" = P ] || { cat "$d/order" >&2; false; }'
t_assert "mount guard: per-host failures still come out one per host, in host order" bash -c '
    err=$( (source ./wekatester
            LOCAL_MODE=0; HOSTS=(h1 h2 h3); DIRECTORY=/mnt/weka
            run_host() { case "$1:$2" in
                (h1:t=*)      echo "weka /mnt/weka wekafs rw,forcedirect 0 0";;
                (h1:p=*)      return 1;;
                (h2:t=*)      echo "weka /mnt/weka wekafs rw,readcache 0 0";;
                (h3:*)        return 1;;
                (*)           return 0;; esac; }
            verify_mount_mode) 2>&1 >>$SUITE_ASIDE )
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
t_assert "pinning: one pass over the fleet -- notes in host order, a rowless host pinned off core 0 and weka" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe" "$d/auth"
    printf "ncpus 8\ntaskset 0-7\nbindable 0-7\nbindable_priv -\nweka_allowed 2\n" > "$d/probe/h1"
    printf "ncpus 8\ntaskset 0-7\nbindable 0-7\nbindable_priv -\n" > "$d/probe/h2"
    printf "ncpus 4\ntaskset 0-3\nbindable 0-3\nbindable_priv -\npriv sudo -n\n" > "$d/probe/h3"
    printf "h1\t-\t-\t0-3\t-\nh3\t-\t-\t0-7\t-\n" > "$d/targets.final"
    out=$( (source ./wekatester
        WORK_DIR=$d; HOSTS=(h1 h2 h3); AUTH_DIR=$d/auth
        check_cpu_pinning) 2>&1 ) || { echo "$out" >&2; exit 1; }
    case "$out" in
        *"note: h1: requested cpus (0-3) overlap weka"*"(2); executing on the remainder (1,3)"*"note: h3: requested cpus (0-7) name cpus this host does not have (4-7; the host has 4 cpus: 0-3); executing on the remainder (1-3)"*) true;;
        *) echo "$out" >&2; false;;
    esac &&
    [ "$(cat "$d/auth/h1.cpus")" = "1,3" ] &&
    # h2 has no row: pinned all the same, every cpu but core 0 (no weka here)
    [ "$(cat "$d/auth/h2.cpus")" = "1-7" ] &&
    case "$out" in *"on the 1 host(s) the host file gives no cpu list (h2: 1-7)"*) true;; *) echo "$out" >&2; false;; esac &&
    [ "$(cat "$d/auth/h3.cpus")" = "1-3" ] && [ ! -s "$d/auth/h3.priv" ]'
# The coordinator line is one shell argument on the master; past 128 KiB it
# dies at staging with the count that caused it, and a small fleet passes.
t_assert "staging: a --client list that overflows one shell argument dies before anything runs" bash -c '
    err=$( (source ./wekatester
            FIO_BIN=fio; TARGET_DIR=/dev/shm/fio-jobfiles; JOBFILES=(000-wekatester-layout.job 011-bw.job)
            HOSTS=(); i=0
            while [ $i -lt 1500 ]; do HOSTS+=("client-node-$i.rack.example.internal"); i=$((i + 1)); done
            check_client_cmdline) 2>&1 >>$SUITE_ASIDE ); rc=$?
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

# --- fio JSON in awk (Frank, 2026-10-05: no jq, no python) ---
t_assert "json_flat: fio one-key-per-line and compact JSON flatten alike; strings unescape; an empty object leaves a mark; no JSON is 2, broken JSON is 3" bash -c '
    d=$(mktemp -d)
    printf "fio: a log line first\n{\n  \"fio version\" : \"fio-3.28\",\n  \"client_stats\" : [\n    {\n      \"jobname\" : \"bw\",\n      \"hostname\" : \"h1\",\n      \"read\" : {\n        \"bw_bytes\" : 2147483648,\n        \"lat_ns\" : { \"mean\" : 150000.000000 }\n      },\n      \"trim\" : {}\n    }\n  ]\n}\n" > "$d/pretty.json"
    printf "{\"client_stats\":[{\"jobname\":\"bw\",\"hostname\":\"h1\",\"read\":{\"bw_bytes\":2147483648,\"lat_ns\":{\"mean\":150000.000000}},\"trim\":{}}],\"fio version\":\"fio-3.28\"}" > "$d/compact.json"
    printf "{ \"s\": \"a \\\\\"q\\\\\" b\" }" > "$d/esc.json"
    printf "no json\n" > "$d/none"; printf "{ \"a\": [1, }\n" > "$d/bad"
    (source ./wekatester
     a=$(json_flat "$d/pretty.json" | LC_ALL=C sort); b=$(json_flat "$d/compact.json" | LC_ALL=C sort)
     [ -n "$a" ] && [ "$a" = "$b" ] &&
     printf "%s\n" "$a" | grep -qx "client_stats.0.read.lat_ns.mean	150000.000000" &&
     printf "%s\n" "$a" | grep -qx "client_stats.0.trim	{}" &&
     [ "$(json_flat "$d/esc.json")" = "s	a \"q\" b" ] || { printf "%s\n" "$a"; json_flat "$d/esc.json"; exit 1; } >&2
     json_flat "$d/none" > "$d/o"; [ $? -eq 2 ] && [ ! -s "$d/o" ] || exit 1
     json_flat "$d/bad" > "$d/o" 2> "$d/e"; [ $? -eq 3 ] && grep -q "offset" "$d/e")'
t_assert "json_flat: one pass that grows with the file on every awk here (300 clients well inside 10 s); strings across lines, nested and empty arrays, text after the document" bash -c '
    d=$(mktemp -d)
    # 300 clients of 232 keys each, fio one-key-per-line: ~1.7 MB, 70k lines.
    # The whole-file reader took ~57 s on macOS awk and ~2 s on mawk here.
    LC_ALL=C awk "BEGIN { print \"fio: log text\"; print \"{\"; print \"  \\\"client_stats\\\" : [\"
        for (c = 1; c <= 300; c++) {
            print \"    {\"; print \"      \\\"jobname\\\" : \\\"bw\\\",\"; printf \"      \\\"hostname\\\" : \\\"h%d\\\",\n\", c
            print \"      \\\"read\\\" : {\"
            for (k = 1; k <= 230; k++) printf \"        \\\"k%d\\\" : %d%s\n\", k, k, (k < 230 ? \",\" : \"\")
            print \"      }\"; print (c < 300 ? \"    },\" : \"    }\")
        }
        print \"  ]\"; print \"}\" }" > "$d/big.json"
    printf "{ \"a\": \"multi\nline\", \"n\": [[1, 2], []], \"e\": {} } trailing { junk\n" > "$d/edge.json"
    want=$(printf "a\tmulti\nline\nn.0.0\t1\nn.0.1\t2\nn.1\t[]\ne\t{}")
    mkdir "$d/bin"
    for a in awk mawk gawk; do
        p=$(command -v "$a") || continue
        ln -sf "$p" "$d/bin/awk"
        SECONDS=0
        n=$(PATH="$d/bin:$PATH"; source ./wekatester; json_flat "$d/big.json" | wc -l)
        [ "$SECONDS" -lt 10 ] && [ "$n" -eq 69600 ] || { echo "$a: $n lines in ${SECONDS}s" >&2; exit 1; }
        got=$(PATH="$d/bin:$PATH"; source ./wekatester; json_flat "$d/edge.json")
        [ "$got" = "$want" ] || { echo "$a: [$got]" >&2; exit 1; }
    done'
t_assert "fio JSON: a results file is flattened once -- the error check and the reader after it share the lines" bash -c '
    source ./tests/helpers.sh
    d=$(mktemp -d); fio_json_fixture "$d/r.json"; cal_json_fixture "$d/c.json" h1:100:10:200:20
    (source ./wekatester
     eval "$(declare -f json_flat | sed "1s/json_flat/json_flat_real/")"
     json_flat() { echo x >> "$d/n"; json_flat_real "$@"; }
     check_fio_errors "$d/r.json" measured && summarize "$d/r.json" "" "vega-1 vega-2" > "$d/out" &&
     [ "$(wc -l < "$d/n")" -eq 1 ] && grep -q "total bandwidth: 7.00 GiB/s" "$d/out" &&
     check_fio_errors "$d/c.json" measured && [ "$(cal_values "$d/c.json" bw)" = "h1 300" ] &&
     [ "$(wc -l < "$d/n")" -eq 2 ] &&
     # a check always parses afresh: the same path may hold a new run
     check_fio_errors "$d/c.json" measured && [ "$(wc -l < "$d/n")" -eq 3 ]) ||
        { cat "$d/out" "$d/n" >&2; false; }'
t_assert "fleet phases start as many processes for 40 hosts as for 3: -x/-e stamping, the sysinfo split, the layout directories, the destination table, the machine ids, the seed jobfile push" bash -c '
    count() {   # count <hosts> -> the processes the phases started; their results checked
        local n=$1 d h i hs="" r t
        d=$(mktemp -d); mkdir -p "$d/bin" "$d/w/jobs" "$d/w/probe" "$d/run"
        for t in awk grep mv cat mkdir cp sed tr head tail; do
            r=$(command -v "$t") || continue
            printf "#!/bin/sh\necho %s >> \"%s/calls\"\nexec %s \"\$@\"\n" "$t" "$d" "$r" > "$d/bin/$t"; chmod +x "$d/bin/$t"
        done
        for i in $(seq 1 "$n"); do
            h=h$i; hs="$hs $h"; mkdir -p "$d/w/jobs/$h"
            printf "[global]\nfilename_format=d/\$jobnum/f\nnumjobs=2\ndirectory=/mnt/w\n[a]\nrw=read\n" > "$d/w/jobs/$h/000-wekatester-layout.job"
            printf "[global]\nruntime=10\n[a]\nrw=read\n" > "$d/w/jobs/$h/011-r.job"
            printf "=== WEKATESTER_SYSINFO uname ===\nLinux\n=== WEKATESTER_SYSINFO cmdline ===\nro\n" > "$d/w/sysinfo.$h"
            printf "ncpus 8\nident ABC$i\n" > "$d/w/probe/$h"
            printf "$h\t-\t-\t-\t/mnt/$h\n" >> "$d/w/targets.final"
            mkdir -p "$d/w/cal/$h"; printf "[cell]\nrw=read\n" > "$d/w/cal/$h/c.job"
        done
        : > "$d/calls"
        (export PATH="$d/bin:$PATH"; source ./wekatester
         WORK_DIR=$d/w; RUN_DIR=$d/run; HOSTS=($hs); DIRECTORY=/mnt/x; LOCAL_MODE=0
         run_host() { :; }
         copy_to_master() { :; }
         cal_push c.job $hs &&
         override_staged measured runtime 30 time_based 1 &&
         split_sysinfo "$WORK_DIR/sysinfo." "" &&
         ensure_layout_dirs 000-wekatester-layout.job &&
         load_host_dirs && [ "${HOST_DIRS[$((n - 1))]}" = "/mnt/h$n" ] &&
         ids=$(host_idents) && [ "${ids%%,*}" = "h1=h1/abc1" ]) || { echo "the phases failed at $n hosts" >&2; return 1; }
        cmp -s "$d/w/cal/h$n/c.job" "$d/w/cal/.push/h$n/c.job" &&
        grep -qx "runtime=30" "$d/w/jobs/h$n/011-r.job" && grep -qx "time_based=1" "$d/w/jobs/h$n/011-r.job" &&
        ! grep -q "runtime" "$d/w/jobs/h$n/000-wekatester-layout.job" &&
        grep -qx "Linux" "$d/run/sysinfo/h$n/uname" && grep -qx "ro" "$d/run/sysinfo/h$n/cmdline" &&
        [ "$(grep -c "mkdir -p" "$d/w/layout-dirs.cmd")" -eq "$n" ] &&
        grep -q "^h$n	mkdir -p ./mnt/w/d/0. ./mnt/w/d/1.$" "$d/w/layout-dirs.cmd" ||
            { echo "wrong results at $n hosts" >&2; return 1; }
        wc -l < "$d/calls"
    }
    a=$(count 3) && b=$(count 40) && [ "$a" -eq "$b" ] || { echo "3 hosts: $a processes, 40 hosts: $b" >&2; false; }'
t_assert "targets_column: one line per host in the order given; the first row per host counts; - and no row are empty" bash -c '
    d=$(mktemp -d)
    printf "a\tu1\te1\t-\t/d/a\nb\t-\t-\t-\t-\na\tu2\te2\t-\t/d/a2\n" > "$d/t"
    out=$(source ./wekatester; targets_column 5 "$d/t" b c a | tr "\n" "|")
    [ "$out" = "||/d/a|" ] || { echo "[$out]" >&2; false; }'
t_assert "json_load: the parser message goes through a private file in the run dir, which is gone after" bash -c '
    d=$(mktemp -d); printf "{ \"a\": [1, }\n" > "$d/bad.json"
    (source ./wekatester; WORK_DIR=$d; json_load "$d/bad.json"
     [ "$JSON_RC" -eq 3 ] && case "$JSON_ERR" in "json: unexpected character at offset"*) true;; *) false;; esac) &&
    [ -z "$(ls "$d" | grep jsonerr)" ] || { ls "$d" >&2; false; }'
t_assert "log: the timestamp is formatted by bash, not a date process" bash -c '
    out=$(source ./wekatester; date() { echo DATE-RAN; }; log hello)
    [[ $out =~ ^[0-2][0-9]:[0-5][0-9]:[0-6][0-9]\ hello$ ]] || { echo "[$out]" >&2; false; }'
t_assert "sweep: a dead session fails the sweep instead of reading as nothing laid out" bash -c '
    d=$(mktemp -d)
    err=$( (source ./wekatester
            WORK_DIR=$d; SET_DIR=$d/set; HOSTS=(h1); DIRECTORY=/mnt/weka; DRY_RUN=0
            mkdir -p "$d/jobs/h1" "$SET_DIR"
            printf "# wekatester-layout: generated sha256=abc\n[global]\ndirectory=/mnt/weka\n[l1]\nfilename_format=h1.\$filenum/\$jobnum\nfilesize=1G\nnumjobs=2\n" > "$SET_DIR/000-wekatester-layout.job"
            cp "$SET_DIR/000-wekatester-layout.job" "$d/jobs/h1/"
            JOBFILES=(000-wekatester-layout.job)
            run_host() { return 255; }
            sweep_layout_grid) 2>&1 ) && { echo "a dead session passed: $err" >&2; exit 1; }
    case "$err" in *"layout grid sweep failed on h1"*) true;; *) echo "$err" >&2; false;; esac'
t_assert "limits: the controller raises its soft process limit for a fleet the hard one allows, and stops before connecting when it does not" bash -c '
    d=$(mktemp -d); mkdir "$d/bin"
    printf "#!/bin/sh\nseq 1 36\n" > "$d/bin/ps"; chmod +x "$d/bin/ps"
    run() {   # run <soft> <hard>: 400 hosts need 3 x 400 + 36 + 64 = 1300
        (export PATH="$d/bin:$PATH"; source ./wekatester
         LOCAL_MODE=0; HOSTS=(); for i in $(seq 1 400); do HOSTS+=(h$i); done
         SOFT=$1; HARD=$2
         ulimit() { case "$1" in (-Su) if [ $# -eq 1 ]; then echo "$SOFT"; else echo "RAISED $2"; fi;; (-Hu) echo "$HARD";; esac; }
         check_controller_procs) 2>&1; }
    out=$(run 4096 4096) && [ -z "$out" ] || { echo "enough: [$out]" >&2; exit 1; }
    out=$(run 1024 8192) && case "$out" in *"RAISED 1300"*"raised this run"*"from 1024 to 1300 for 400 hosts"*) ;; *) echo "raise: [$out]" >&2; exit 1;; esac
    out=$(run 1024 unlimited) && case "$out" in *"RAISED 1300"*) ;; *) echo "unlimited hard: [$out]" >&2; exit 1;; esac
    out=$(run 1024 1200) && { echo "short hard passed: [$out]" >&2; exit 1; }
    case "$out" in *"allows"*"1200 processes (ulimit -Hu), and 400 hosts need about 1300 at once"*"limits.conf"*) true;; *) echo "stop: [$out]" >&2; false;; esac'
t_assert "limits: the coordinator gets its open files and port-check processes raised when its hard limits allow, the run stops when they do not" bash -c '
    d=$(mktemp -d); mkdir -p "$d/probe"
    run() {   # run <limits line>: 1100 hosts need 1164 open files and 3364 processes
        (source ./wekatester
         WORK_DIR=$d; MASTER=h1; HOSTS=(); for i in $(seq 1 1100); do HOSTS+=(h$i); done
         FIO_BIN=/usr/bin/fio; TARGET_DIR=/dev/shm/x; FIO_PORT=8765
         printf "ncpus 8\n%s\n" "$1" > "$d/probe/h1"
         check_coordinator_limits || exit 1
         echo "NOFILE=$COORD_NOFILE NPROC=$COORD_NPROC"
         c=$(fio_client_cmd 011-bw.job); echo "CMD=${c:0:40}"
         p=$(port_probe_cmd h1 h2); echo "PORT=${p:0:30}") 2>&1; }
    out=$(run "limits 65536 65536 8192 8192") && case "$out" in *"NOFILE= NPROC="*"CMD="?"/usr/bin/fio"*"PORT=pids="*) ;; *) echo "enough: [$out]" >&2; exit 1;; esac
    out=$(run "limits 1024 1048576 4096 4096") && case "$out" in *"open-file limit raised from 1024 to 1164 for 1100 clients"*"NOFILE=1164 NPROC="*"CMD=ulimit -Sn 1164 && "?"/usr/bin/fio"*) ;; *) echo "nofile: [$out]" >&2; exit 1;; esac
    out=$(run "limits 65536 65536 1024 8192") && case "$out" in *"process limit raised from 1024 to 3364"*"PORT=ulimit -Su 3364; pids="*) ;; *) echo "nproc: [$out]" >&2; exit 1;; esac
    out=$(run "limits 1024 1100 8192 8192") && { echo "short nofile passed: [$out]" >&2; exit 1; }
    case "$out" in *"h1: fio"*"coordinator keeps one connection open per client, so 1100 clients need about 1164 open files, and h1 allows 1100 (ulimit -Hn)"*) ;; *) echo "nofile stop: [$out]" >&2; exit 1;; esac
    out=$(run "limits 65536 65536 1024 2048") && { echo "short nproc passed: [$out]" >&2; exit 1; }
    case "$out" in *"h1: the fio port check probes every client at once"*"need about 3364 processes there, and h1 allows 2048 (ulimit -Hu)"*) true;; *) echo "nproc stop: [$out]" >&2; false;; esac'
t_assert "probe: reports the open-file and process limits, soft and hard" bash -c '
    printf "%s\n" "$(probe_stub)" | grep -qE "^limits [0-9a-z]+ [0-9a-z]+ [0-9a-z]+ [0-9a-z]+$"'
t_assert "fio JSON: the readers run on awk alone -- no python in their bodies" bash -c '
    for f in json_flat errno_text cal_values cal_lat_values check_fio_errors summarize summarize_report summ_one; do
        body=$(sed -n "/^$f() {/,/^}/p" ./wekatester); [ -n "$body" ] || { echo "no $f" >&2; exit 1; }
        printf "%s\n" "$body" | grep -q "python3\|pyrun\|PYEOF" && { echo "$f still uses python" >&2; exit 1; }
    done; true'

# --- the source: src/ builds the one file ---
t_assert "source: no bash function is defined twice" bash -c '
    dup=$(grep -o "^[a-zA-Z_][a-zA-Z0-9_]*() *{" ./wekatester | sed "s/() *{//" | sort | uniq -d)
    [ -z "$dup" ] || { echo "defined twice: $dup" >&2; false; }'
t_assert "build: the committed wekatester is what ./build makes of src/, with no directive left in it" bash -c '
    d=$(mktemp -d); ./build "$d/wekatester" && cmp ./wekatester "$d/wekatester" &&
    ! grep -n -E "#@(include|awk)" ./wekatester'
t_assert "build: every file under src/ is built in exactly once" bash -c '
    used=$( { grep -rh "^#@include " src | sed "s/^#@include //"
              grep -rhoE "#@awk [A-Za-z0-9_.]+" src | sed -E "s|^#@awk (.*)|awk/\1.awk|"; } | sort)
    have=$(cd src && find . -type f ! -path ./wekatester.sh ! -name ".*" | sed "s|^\./||" | sort)
    [ "$used" = "$have" ] || { diff <(printf "%s\n" "$used") <(printf "%s\n" "$have") >&2; false; }'
t_assert "build: a missing include or awk file stops it by name and leaves the target alone" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src/sh" "$d/src/awk"; cp ./build "$d/"; q=$(printf "\\047")
    printf "#!/usr/bin/env bash\n#@include sh/x.sh\n" > "$d/src/wekatester.sh"
    echo keep > "$d/wekatester"
    out=$("$d/build" 2>&1) && { echo "built anyway" >&2; exit 1; }
    [ "$(cat "$d/wekatester")" = keep ] || { echo "target changed" >&2; exit 1; }
    case "$out" in *"cannot read src/sh/x.sh"*) ;; *) echo "[$out]" >&2; exit 1;; esac
    printf "x=%s#@awk y%s\n" "$q" "$q" > "$d/src/sh/x.sh"
    out=$("$d/build" 2>&1) && { echo "built without y.awk" >&2; exit 1; }
    case "$out" in *"cannot read src/awk/y.awk"*) ;; *) echo "[$out]" >&2; exit 1;; esac
    printf "x=1\nwrite_targets_template() { :; }\n" > "$d/src/sh/x.sh"
    "$d/build" && [ "$(sed -n 3p "$d/wekatester")" = "x=1" ] && head -2 "$d/wekatester" | grep -q "^# Built by ./build"'
t_assert "build: an out exported by the caller does not redirect a no-argument build" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src"; cp ./build "$d/"
    printf "#!/usr/bin/env bash\nx=1\nwrite_targets_template() { :; }\n" > "$d/src/wekatester.sh"
    out=$d/leaked "$d/build" || exit 1
    [ ! -e "$d/leaked" ] || { echo "built into the exported out" >&2; exit 1; }
    [ "$(sed -n 3p "$d/wekatester")" = "x=1" ]'
t_assert "build: a default build of a tool with no write_targets_template stops naming it, target and example untouched" bash -c '
    d=$(mktemp -d); cp -R ./src ./build "$d/"; echo keep > "$d/wekatester"
    sed "s/^write_targets_template() /write_targets_templat() /" ./src/sh/hosts.sh > "$d/src/sh/hosts.sh"
    out=$("$d/build" 2>&1) && { echo "built anyway" >&2; exit 1; }
    case "$out" in *"build: the assembly defines no write_targets_template(), which writes hostlist.example.csv; $d/wekatester left alone"*) ;; *) echo "[$out]" >&2; exit 1;; esac
    [ "$(cat "$d/wekatester")" = keep ] && [ ! -e "$d/hostlist.example.csv" ] || { echo "target or example touched" >&2; exit 1; }
    # control: the same tree unrenamed builds the tool and the repo example
    cp ./src/sh/hosts.sh "$d/src/sh/hosts.sh" && "$d/build" && cmp ./wekatester "$d/wekatester" && cmp ./hostlist.example.csv "$d/hostlist.example.csv"'
t_assert "build: an include cycle, an unknown directive or an assembly bash cannot parse stops it, target untouched" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src/sh"; cp ./build "$d/"; echo keep > "$d/wekatester"
    try() {   # try <message>: the build fails within 20 s, saying it
        "$d/build" > "$d/out" 2>&1 & local p=$!
        ( sleep 20; kill "$p" ) & local w=$!
        if wait "$p"; then kill "$w"; echo "built anyway" >&2; return 1; fi
        kill "$w"
        [ "$(cat "$d/wekatester")" = keep ] || { echo "target changed" >&2; return 1; }
        grep -q "$1" "$d/out" || { echo "no [$1] in [$(cat "$d/out")]" >&2; return 1; }
    }
    printf "#!/usr/bin/env bash\n#@include sh/a.sh\n" > "$d/src/wekatester.sh"
    echo "#@include sh/b.sh" > "$d/src/sh/a.sh"; echo "#@include sh/a.sh" > "$d/src/sh/b.sh"
    try "include cycle at src/sh/a.sh" || exit 1
    echo "  #@include sh/b.sh" > "$d/src/sh/a.sh"
    try "not a directive build knows" || exit 1
    echo "if then fi" > "$d/src/sh/a.sh"
    try "does not parse" && [ -s "$d/wekatester.rejected" ]'
t_assert "build: an apostrophe in an awk file reaches awk intact, at either marker position" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src/awk"; cp ./build "$d/"; q=$(printf "\\047")
    printf "#!/usr/bin/env bash\nawk %s#@awk a%s\nawk %s\n    #@awk b%s\nwrite_targets_template() { :; }\n" "$q" "$q" "$q" "$q" > "$d/src/wekatester.sh"
    printf "# it%ss a test\nBEGIN { print \"don%st\" }\n" "$q" "$q" > "$d/src/awk/a.awk"
    printf "BEGIN {\n    print \"it%ss\"\n}\n" "$q" > "$d/src/awk/b.awk"
    "$d/build" && out=$(bash "$d/wekatester") && [ "$out" = "$(printf "don%st\nit%ss" "$q" "$q")" ] || { echo "[$out]" >&2; false; }'
t_assert "build: a marker it cannot place exactly stops it, target untouched" bash -c '
    d=$(mktemp -d); mkdir -p "$d/src/sh" "$d/src/awk"; cp ./build "$d/"; echo keep > "$d/wekatester"; q=$(printf "\\047")
    printf "BEGIN { }\n" > "$d/src/awk/a.awk"; printf "BEGIN { }\n" > "$d/src/awk/b.awk"
    no() {   # no <message> <line>...: a wekatester.sh of those lines fails, saying it
        printf "%s\n" "#!/usr/bin/env bash" "${@:2}" > "$d/src/wekatester.sh"
        out=$("$d/build" 2>&1) && { echo "built: ${*:2}" >&2; return 1; }
        [ "$(cat "$d/wekatester")" = keep ] || { echo "target changed" >&2; return 1; }
        case "$out" in *"$1"*) ;; *) echo "no [$1] in [$out]" >&2; return 1;; esac
    }
    no "not a directive build knows" "x=\"" "    #@awk a${q}\"" || exit 1
    no "not a directive build knows" "# see #@awk a" || exit 1
    no "one directive per line" "awk ${q}#@awk a${q} | awk ${q}#@awk b${q}" || exit 1
    printf "awk %s#@awk a%s\n" "$q" "$q" > "$d/src/sh/m.bash"
    no "unexpanded directive" "#@include sh/m.bash" || exit 1
    printf "\n" > "$d/src/awk/e.awk"
    no "cannot read src/awk/e.awk" "awk ${q}#@awk e${q}" || exit 1
    printf "BEGIN { x = 1 + \\\\\n 2 }\n" > "$d/src/awk/c.awk"
    no "ends in a backslash" "awk ${q}#@awk c${q}"'
# Every multi-line awk program lives in src/awk (Frank, 2026-10-08). A line
# that opens a single-quoted program on an awk, gawk, mawk or awkrun command
# (backslash continuations joined, a marker's own quotes set aside) and does
# not close it must hand it to a marker on the next line. Programs in double
# quotes, in variables or behind -f are not seen.
t_assert "build: no multi-line awk program is left inline in src/" bash -c '
    prog=$(cat <<"EOF"
FNR == 1 { open = 0; cont = "" }
{ line = cont $0; cont = "" }
line ~ /\\$/ { cont = substr(line, 1, length(line) - 1) " "; next }
open {
    if (line !~ /^[ \t]*#@awk [A-Za-z0-9_.]+\047/) print FILENAME ":" FNR - 1
    open = 0; sub(/^[ \t]*#@awk [A-Za-z0-9_.]+\047/, "", line)
}
line ~ /^[ \t]*#/ { next }
{ gsub(/\047#@awk [A-Za-z0-9_.]+\047/, "", line); t = " " line " " }
t ~ /[^A-Za-z_][gm]?awk(run)? / { if (gsub(/\047/, "", t) % 2) { if (line ~ /\047$/) open = 1; else print FILENAME ":" FNR } }
EOF
)
    bad=$(find src -name "*.sh" | sort | xargs awk "$prog") && [ -z "$bad" ] || { echo "inline at: $bad" >&2; false; }'

rm -f -- "${SUITE_ASIDE:?}"
if [ -z "${SUITE_ONLY:-}" ]; then
    echo; echo "passed $PASS, failed $FAIL"
else
    echo; echo "passed $PASS, failed $FAIL, skipped $SKIP"
    # a typo in the pattern must not pass as a clean run
    [ $((PASS + FAIL)) -gt 0 ] || { echo "SUITE_ONLY matched no test: $SUITE_ONLY"; FAIL=1; }
fi
if [ "$FAIL" -eq 0 ]; then
    out=$(rm -rf -- "${SUITE_TMP:?}" 2>&1) || echo "could not remove $SUITE_TMP: $out"
else
    echo "kept the tests' temporary files: $SUITE_TMP"
fi
[ "$FAIL" -eq 0 ]
