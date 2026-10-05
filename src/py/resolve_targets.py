import csv, os, sys

phase, path, cli_engine, cli_dir, results = sys.argv[1:6]
hosts = sys.argv[6:]

def warn(msg):
    print(f"WARNING: {msg}", file=sys.stderr)

def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def parse_geom(kind, raw, lineno):
    """'bandwidthR:12/10G/1/8' or bare '12/10G/1/8'; empty parts = unset."""
    raw = raw.strip()
    if not raw:
        return {}
    if ":" in raw:
        pfx, rest = raw.split(":", 1)
        if pfx.strip().lower() != kind.lower():
            die(f"{path}:{lineno}: column for {kind} carries prefix '{pfx}'")
        raw = rest
    parts = (raw.split("/") + ["", "", "", ""])[:4]
    keys = dict(zip(GEOM_NAMES, GEOM_SLOTS))[kind]
    out = {}
    for key, val in zip(("nj", "fs", "nr", "qd"), parts):
        if val.strip():
            out[f"{keys}_{key}"] = val.strip()
    return out

# ---- parse ----
entries = []      # {lineno, host, sel_login, sel_engine, fields{...}, nsel}
host_lines = {}   # host -> lineno (duplicate host lines are fatal)
try:
    fp = open(path, newline="")
except OSError as exc:
    die(f"cannot read host file: {exc}")
for lineno, row in enumerate(csv.reader(fp), start=1):
    if not row or not "".join(row).strip():
        continue
    if row[0].strip().startswith("#"):
        continue
    if lineno == 1 and row[0].strip().lower() == "host":
        continue   # header
    row = [c.strip() for c in (row + [""] * HOSTFILE_COLS)[:HOSTFILE_COLS]]
    host_cell = row[0]
    host, login, engine, cpus, ddir = host_addr(host_cell), row[1], row[2], row[3], row[4]
    fields = {}
    if engine:
        fields["engine"] = engine
    if cpus:
        fields["cpus"] = cpus
    if ddir:
        fields["dir"] = ddir
    for kind, raw in zip(GEOM_NAMES, row[5:HOSTFILE_COLS]):
        fields.update(parse_geom(kind, raw, lineno))
    if host:
        if login:
            fields["login"] = login
        if host in host_lines:
            prev_line, prev_cell = host_lines[host]
            extra = ""
            if prev_cell != host_cell:
                # two spellings of one machine -- most likely the same short
                # name carrying different machine-ids, which the run cannot
                # tell apart because both resolve to the same address
                extra = (f"; '{prev_cell}' and '{host_cell}' both resolve to "
                         f"'{host}' -- keep the row for this machine and drop "
                         f"the other")
            die(f"{path}:{lineno}: duplicate definition for host '{host}' "
                f"(first at line {prev_line}){extra}")
        host_lines[host] = (lineno, host_cell)
        entries.append({"lineno": lineno, "host": host, "sel_login": "",
                        "sel_engine": "", "fields": fields, "nsel": 3})
    else:
        # host-less: login/engine are SELECTORS; login is never assigned.
        nsel = (1 if login else 0) + (1 if engine else 0)
        entries.append({"lineno": lineno, "host": "", "sel_login": login,
                        "sel_engine": engine, "fields": fields, "nsel": nsel})
fp.close()

# ---- phase2 input: engine test results ----
passed = {}   # host -> set(engines that work)
if phase == "phase2" and results != "-":
    for line in open(results):
        parts = line.split()
        if len(parts) == 3 and parts[2] == "ok":
            passed.setdefault(parts[0], set()).add(parts[1])

# ---- resolve per host ----
def resolve(host):
    cfg = {}
    src = {}   # field -> (nsel, lineno) that set it, for conflict warnings
    # host lines first (most specific, unique)
    for e in entries:
        if e["host"] == host:
            for k, v in e["fields"].items():
                cfg[k] = v
                src[k] = (e["nsel"], e["lineno"])
    login = cfg.get("login", "")
    # host-less lines, most selectors first; ties resolved first-line-wins
    # (skipped outright in hostonly: their values are defaults, not the host's)
    for e in sorted((e for e in entries if not e["host"] and phase != "hostonly"),
                    key=lambda e: (-e["nsel"], e["lineno"])):
        if e["sel_login"] and e["sel_login"] != login:
            continue
        if e["sel_engine"]:
            if phase != "phase2":
                continue   # selector needs test results; folds in later
            if e["sel_engine"] not in passed.get(host, set()):
                continue
        for k, v in e["fields"].items():
            if k == "login":
                continue   # selector only, never assigned from host-less lines
            if k not in cfg:
                cfg[k] = v
                src[k] = (e["nsel"], e["lineno"])
            elif src[k][0] == e["nsel"] and cfg[k] != v:
                warn(f"{path}: host '{host}' field '{k}': line {e['lineno']} "
                     f"conflicts with equally specific line {src[k][1]}; "
                     f"keeping line {src[k][1]}")
    # CLI beats the file
    if cli_engine != "-":
        cfg["engine"] = cli_engine
    if cli_dir != "-":
        cfg["dir"] = cli_dir
    return cfg

for host in hosts:
    cfg = resolve(host)
    print("\t".join([host] + [cfg.get(f, "-") or "-" for f in FIELDS]))
