import json, sys

cur_path, mode = sys.argv[1], sys.argv[2]
if mode not in ("bw", "iops"):
    sys.exit(f"ERROR: cal_values: unknown mode: {mode} (bw|iops)")
KEY = "bw_bytes" if mode == "bw" else "iops"

def values(path):
    try:
        raw = open(path).read()
    except OSError as exc:
        sys.exit(f"ERROR: cal_values: cannot read {path}: {exc}")
    start = raw.find("{")
    if start < 0:
        sys.exit(f"ERROR: cal_values: no JSON in {path}")
    try:
        data = json.loads(raw[start:])
    except ValueError as exc:
        sys.exit(f"ERROR: cal_values: cannot parse fio JSON in {path}: {exc}")
    stats = [s for s in data.get("client_stats", [])
             if str(s.get("jobname", "")).startswith("cal-")]
    if not stats:
        sys.exit(f"ERROR: cal_values: {path} carries no cal job stats")
    out = {}
    for s in stats:
        host = s.get("hostname", "?")
        total = out.get(host, 0.0)
        for d in ("read", "write"):
            io = s.get(d) or {}
            total += float(io.get(KEY) or 0)
        out[host] = total
    return out

cur = values(cur_path)
for host in sorted(cur):
    print(f"{host} {int(cur[host])}")
