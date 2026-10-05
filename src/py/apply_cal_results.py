import os, sys

res, final, force = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
forced = set(LINE_RATE_SLOTS) if sys.argv[4] != "-" else set()

NCOLS = 1 + len(FIELDS)
ENGINE = 1 + FIELDS.index("engine")

knees = {}
for line in open(res):
    f = line.split()
    if not f:
        continue
    # a malformed line is a schema break, not a skip: silently dropping it
    # discards a 30-45 minute measurement with no diagnostic
    if len(f) != CAL_COLS:
        sys.exit(f"ERROR: cal.results: malformed line "
                 f"(want {CAL_COLS} fields): {line.rstrip()}")
    knees[f[0]] = f[1:]

rows, order = {}, []
if os.path.exists(final):
    for line in open(final):
        f = line.rstrip("\n").split("\t")
        rows[f[0]] = f
        order.append(f[0])
for host in sorted(knees):
    row = rows.get(host)
    if row is None:
        row = [host] + ["-"] * (NCOLS - 1)
        rows[host] = row
        order.append(host)
    while len(row) < NCOLS:
        row.append("-")
    vals = knees[host]
    eng = vals[0]
    if eng != "-" and (force or row[ENGINE] == "-"):
        row[ENGINE] = eng
    tuples = vals[CAL_HEAD - 1:]
    for i, slot in enumerate(CAL_SLOTS):
        qd, nr, fs, nj = tuples[CAL_TUPLE * i:CAL_TUPLE * i + CAL_TUPLE]
        base = slot_base(slot)
        win = force or slot in forced
        # The host file's values pinned the search (cal_shapes), so the
        # measured tuple already carries them: fill mode adds only what was
        # searched, and every field of the row was measured together.
        for off, v in ((3, qd), (2, nr), (1, fs), (0, nj)):   # qd, nr, fs, nj
            if v != "-" and (win or row[base + off] == "-"):
                row[base + off] = v
with open(final, "w") as fp:
    for h in order:
        fp.write("\t".join(rows[h]) + "\n")
