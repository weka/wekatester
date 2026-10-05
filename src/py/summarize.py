import json
import os
import re
import sys
import tarfile

path = sys.argv[1]
items = sys.argv[2].split() or ["bandwidth", "latency", "iops"]
expected = sys.argv[3].split()

LAYOUT_MARKER = "# wekatester-layout: generated"
LAYOUT_JOB = "000-wekatester-layout"


def fmt_bytes(n):
    for unit, val in (("TiB", 2**40), ("GiB", 2**30), ("MiB", 2**20), ("KiB", 2**10)):
        if n >= val:
            return f"{n / val:.2f} {unit}/s"
    return f"{n:.0f} bytes/s"


def fmt_lat(ns):
    for unit, val in (("s", 1e9), ("ms", 1e6), ("us", 1e3)):
        if ns >= val:
            return f"{ns / val:.1f} {unit}"
    return f"{ns:.0f} ns"


def fmt_iops(n):
    return f"{n:,.0f}/s"


class Unsummarizable(Exception):
    """No usable fio JSON in this blob; the message says why."""


def parse_stats(raw, label):
    start = raw.find("{")
    if start < 0:
        raise Unsummarizable(f"{label}: no JSON in fio output")
    try:
        data = json.loads(raw[start:])
    except ValueError as exc:
        raise Unsummarizable(f"{label}: cannot parse fio JSON: {exc}")
    # client_stats is a flat list: one entry per (host, job) plus "All
    # clients" aggregates. The measured workload runs last in every jobfile,
    # so the last entry per host -- and the last aggregate -- describe the
    # workload, not the create/layout phase.
    per_host = {}
    alls = None
    for s in data.get("client_stats", []):
        if s.get("jobname") == "All clients":
            alls = s
        else:
            per_host[s.get("hostname", s.get("jobname", "?"))] = s
    if alls is None:
        if len(per_host) == 1:
            alls = next(iter(per_host.values()))  # fio emits no aggregate for one client
        else:
            raise Unsummarizable(f"{label}: no 'All clients' aggregate found")
    return per_host, alls


def render(per_host, alls):
    def spread(metric, fmt):
        """Straggler visibility: per-host min/max of a metric, when it varies."""
        if len(per_host) < 2:
            return ""
        vals = sorted((metric(s), h) for h, s in per_host.items())
        (lo, lo_h), (hi, hi_h) = vals[0], vals[-1]
        if lo == hi:
            return ""
        return f"  (min {fmt(lo)} {lo_h}, max {fmt(hi)} {hi_h})"

    lines = []
    if "bandwidth" in items:
        r, w = alls["read"]["bw_bytes"], alls["write"]["bw_bytes"]
        if r:
            lines.append(f"read bandwidth: {fmt_bytes(r)}")
        if w:
            lines.append(f"write bandwidth: {fmt_bytes(w)}")
        if r and w:
            lines.append(f"total bandwidth: {fmt_bytes(r + w)}")
        if r or w:
            lines.append(
                f"average bandwidth: {fmt_bytes((r + w) / len(per_host))} per host"
                + spread(lambda s: s["read"]["bw_bytes"] + s["write"]["bw_bytes"], fmt_bytes)
            )

    if "iops" in items:
        r, w = alls["read"]["iops"], alls["write"]["iops"]
        if r:
            lines.append(f"read iops: {fmt_iops(r)}")
        if w:
            lines.append(f"write iops: {fmt_iops(w)}")
        if r and w:
            lines.append(f"total iops: {fmt_iops(r + w)}")
        if r or w:
            lines.append(
                f"average iops: {fmt_iops((r + w) / len(per_host))} per host"
                + spread(lambda s: s["read"]["iops"] + s["write"]["iops"], fmt_iops)
            )

    if "latency" in items:
        for d in ("read", "write"):
            mean = alls[d]["lat_ns"]["mean"]
            if mean:
                lines.append(
                    f"{d} latency: {fmt_lat(mean)}"
                    + spread(lambda s, d=d: s[d]["lat_ns"]["mean"], fmt_lat)
                )
        r_lat, w_lat = alls["read"]["lat_ns"]["mean"], alls["write"]["lat_ns"]["mean"]
        r_ios, w_ios = alls["read"]["total_ios"], alls["write"]["total_ios"]
        if r_lat and w_lat and (r_ios + w_ios):
            # weighted by IO count, not a bare mean of the two directions
            weighted = (r_lat * r_ios + w_lat * w_ios) / (r_ios + w_ios)
            lines.append(f"average latency: {fmt_lat(weighted)} (IO-weighted)")

    if not lines:
        lines.append("(no non-zero metrics to report)")
    for line in lines:
        print(f"    {line}")
    print()


def summarize_bundle(path):
    with tarfile.open(path, "r:*") as tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        # Layout results are barriers, not measurements: skip the reserved
        # names (the rebuild variant is deliberately unmarked, so it must be
        # named here) plus any job whose bundled jobfile carries the layout
        # marker (a renamed layout in a custom set).
        layout = {LAYOUT_JOB, "000-wekatester-relayout", "999-wekatester-unlink"}
        for m in members:
            if re.search(r"(^|/)fio-jobfiles/.+\.job$", m.name):
                head = tf.extractfile(m).read(4096).decode(errors="replace")
                if any(l.startswith(LAYOUT_MARKER) for l in head.splitlines()[:3]):
                    layout.add(os.path.basename(m.name)[:-len(".job")])
        results = sorted(
            (m for m in members if re.search(r"(^|/)results_[^/]+\.json$", m.name)),
            key=lambda m: os.path.basename(m.name))
        if not results:
            sys.exit(f"{path}: no results_*.json files in the bundle")
        for m in results:
            job = os.path.basename(m.name)[len("results_"):-len(".json")]
            if job in layout:
                continue
            print(f"==== {job} ====")
            raw = tf.extractfile(m).read().decode(errors="replace")
            try:
                per_host, alls = parse_stats(raw, os.path.basename(m.name))
                render(per_host, alls)
            except Unsummarizable as exc:
                # a failed run's bundle can hold half-written results; show
                # the rest rather than dying on the first casualty
                print(f"    ({exc})")
                print()
            except (KeyError, TypeError, ValueError) as exc:
                # well-formed JSON in another layout (an older fio, a file
                # that is not fio's): the same -- say so, show the rest.
                # render prints nothing until every line is built
                print(f"    ({os.path.basename(m.name)}: not the fio JSON layout "
                      f"this summary reads: {exc!r})")
                print()


if tarfile.is_tarfile(path):
    summarize_bundle(path)
    sys.exit(0)

try:
    per_host, alls = parse_stats(open(path).read(), path)
except Unsummarizable as exc:
    sys.exit(str(exc))

# a worker that dropped out mid-run silently vanishes from fio's output;
# refuse to summarize a benchmark that is quietly missing hosts
if expected:
    missing = [h for h in expected if h not in per_host]
    if missing:
        sys.exit(
            f"{path}: no results from {len(missing)} of {len(expected)} host(s): "
            + ", ".join(missing)
        )
try:
    render(per_host, alls)
except (KeyError, TypeError, ValueError) as exc:
    sys.exit(f"{path}: not the fio JSON layout this summary reads: {exc!r}")
