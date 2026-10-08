# --- the shared awk layer ----------------------------------------------------
# Rules more than one program needs, spelled once; awkrun prepends this and the
# constants below. The conventions every program keeps: README, Source.
# Host-file schema: host, four identity columns, eight nj/fs/nr/qd slots, the
# 1MiB latency slots last so older files still line up.
GEOM_SLOTS="bw_r bw_w lat_r lat_w iops_r iops_w lat1m_r lat1m_w"
GEOM_NAMES="bandwidthR bandwidthW latencyR latencyW iopsR iopsW latency1mR latency1mW"
# First line of a latency test's one-job twin (-a): stage_floor_twins writes
# it, staging and the writeback read it.
FLOOR_MARKER="# wekatester-floor:"
# The engine a tie goes to, best first, and the one a set that names none
# gets.
ENGINE_ORDER="io_uring libaio psync"
# Measured again under --line-rate even when pinned: a recorded answer does
# not say which line rate it stopped at.
LINE_RATE_SLOTS="bw_r bw_w"

IFS= read -r -d '' WEKA_AWK <<'AWKLIB' || :
#@include awk/lib/base.awk
#@include awk/lib/jobfiles.awk
#@include awk/lib/probe.awk
#@include awk/lib/hostfile.awk
#@include awk/lib/seed.awk
#@include awk/lib/layout.awk
#@include awk/lib/json.awk
AWKLIB

awkrun() {   # awkrun <program> <arg>... -- WEKA_AWK prepended, LC_ALL=C
    LC_ALL=C awk "$WEKA_AWK
function geom_slots() { return \"$GEOM_SLOTS\" }
function geom_names() { return \"$GEOM_NAMES\" }
function layout_job() { return \"$LAYOUT_JOB\" }
function layout_marker() { return \"$LAYOUT_MARKER\" }
function floor_marker() { return \"$FLOOR_MARKER\" }
function engine_order() { return \"$ENGINE_ORDER\" }
function line_rate_slots() { return \"$LINE_RATE_SLOTS\" }
$1" "${@:2}"
}

# stdin's sha256, lowercase hex
sha256_hex() {
    local out
    out=$(sha256sum) || return 1
    printf '%s' "${out%% *}"
}
