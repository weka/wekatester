import json, os, sys

path, mode = sys.argv[1], sys.argv[2]
raw = open(path).read()
start = raw.find("{")
if start < 0:
    sys.exit(f"{path}: no JSON in fio output")
try:
    data = json.loads(raw[start:])
except ValueError as exc:
    sys.exit(f"{path}: cannot parse fio JSON: {exc}")

stats = [s for s in data.get("client_stats", []) if s.get("jobname") != "All clients"]
if not stats:
    sys.exit(f"{path}: fio returned no per-job stats -- the jobs did not run")

bad = []
for s in stats:
    err = int(s.get("error") or 0)
    if err:
        host = s.get("hostname", s.get("jobname", "?"))
        try:
            desc = f" ({os.strerror(err)})"
        except (ValueError, OverflowError):
            desc = ""
        bad.append(f"{host}: job '{s.get('jobname', '?')}' error {err}{desc}")

if mode == "measured" and not bad:
    per_host = {}
    for s in stats:
        per_host[s.get("hostname", s["jobname"])] = s
    for host, s in sorted(per_host.items()):
        moved = 0
        for d in ("read", "write", "trim"):
            io = s.get(d) or {}
            moved += int(io.get("total_ios") or 0)
            moved += int(io.get("io_bytes") or io.get("bw_bytes") or 0)
        if moved == 0:
            bad.append(f"{host}: measured job moved no data (zero bytes, zero ios)")

if bad:
    for b in bad:
        print(f"ERROR: {b}", file=sys.stderr)
    # fio's own log text precedes the JSON and names the underlying cause
    # (e.g. "failed to create dir ...: Permission denied"); surface a few.
    shown = 0
    for l in raw[:start].splitlines():
        if "error" in l.lower() or "failed" in l.lower():
            print(f"ERROR: {l.strip()}", file=sys.stderr)
            shown += 1
            if shown == 3:
                break
    sys.exit(1)
