import json, sys

path, dirn = sys.argv[1], sys.argv[2]
try:
    raw = open(path).read()
except OSError as exc:
    sys.exit(f"ERROR: cal_lat_values: cannot read {path}: {exc}")
start = raw.find("{")
if start < 0:
    sys.exit(f"ERROR: cal_lat_values: no JSON in {path}")
try:
    data = json.loads(raw[start:])
except ValueError as exc:
    sys.exit(f"ERROR: cal_lat_values: cannot parse fio JSON in {path}: {exc}")
out = {}
for s in data.get("client_stats", []):
    if not str(s.get("jobname", "")).startswith("cal-"):
        continue
    io = s.get(dirn) or {}
    lat_us = float((io.get("lat_ns") or {}).get("mean") or 0) / 1000.0
    ios = float(io.get("total_ios") or 0)
    iops = float(io.get("iops") or 0)
    host = s.get("hostname", "?")
    if host not in out:
        out[host] = [lat_us, iops, ios]
        continue
    prev = out[host]
    tot = prev[2] + ios
    if tot > 0:
        prev[0] = (prev[0] * prev[2] + lat_us * ios) / tot
    prev[1] += iops
    prev[2] = tot
if not out:
    sys.exit(f"ERROR: cal_lat_values: {path} carries no cal job stats")
for host in sorted(out):
    print("%s %.3f %d" % (host, out[host][0], int(out[host][1])))
