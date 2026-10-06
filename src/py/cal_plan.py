import sys

act, ctype, dirn, eng = sys.argv[1:5]
N = max(1, int(sys.argv[5]))
linerate = float(sys.argv[6])
memcap = float(sys.argv[7])
hist = sys.argv[8]
K = dict(kv.split("=", 1) for kv in sys.argv[9:] if "=" in kv)
EXH = K.get("exh") == "1"
# the level: safe and max search numjobs only, at a fixed iodepth and
# nrfiles (fq/fn, set per type by the caller); cal and brutal walk the
# ladders (Frank, 2026-10-05)
LVL = K.get("lvl", "cal")
FIXED = LVL in ("safe", "max")
LINE = float(K["line"])
THR, STOP, CONFIRM = float(K["thr"]), int(K["stop"]), int(K["confirm"])
RT, NR = K["rt"], int(K["nr"])
def lad(key):
    return sorted(set(int(x) for x in K[key].split(",") if x.strip()))
NRL, BWQD, IOPSQD = lad("nrc"), lad("bwqd"), lad("iopsqd")
SYNC = ("psync", "sync", "pvsync", "pvsync2", "vsync")
sync = eng in SYNC
if sync:
    BWQD, IOPSQD = [1], [1]   # one IO in flight per job, whatever iodepth says
# libaio reserves numjobs x iodepth aio events at setup; past the kernel's
# room (fs.aio-max-nr less what is in use) the cell dies with EAGAIN
AIO = K.get("aio", "-")
AIOCAP = int(AIO) if eng == "libaio" and AIO.isdigit() else None
BS = (1 << 20) if ctype in ("bw", "lat1m") else 4096
N2 = max(1, N // 2)

def doubling(lo, hi):
    """lo, 2lo, 4lo ... and hi itself: the widest point is always measured,
    even when it is not a power of two."""
    out, v = [], lo
    while v < hi:
        out.append(v)
        v *= 2
    if hi >= lo:
        out.append(hi)
    return out

BW_LOW = sorted(set(doubling(1, N) + [N2]))      # at or below N: nrfiles=1 iodepth=1
HIGH = [2 * N, 4 * N]                              # the siblings in: the ladders
IOPS_LOW = sorted(set([N2, N]))
FIXED_NJ = sorted(set([N2, N, 2 * N]))             # safe and max: the only job counts

# Host-file values pin their knob (Frank, 2026-10-02): a pinned value is the
# ONLY value that knob takes, on every rung, whatever the rung's own rule
# says, and it is used as written -- never capped by a guard. The knobs left
# unpinned are searched as usual around it.
def pin(key):
    v = K.get(key, "-")
    return int(v) if v.isdigit() and int(v) > 0 else None
PNJ, PQD, PNR = pin("pin_nj"), pin("pin_qd"), pin("pin_nr")
if PNJ:
    BW_LOW = IOPS_LOW = [PNJ] if PNJ <= N else []
    HIGH = [PNJ] if PNJ > N else []
    FIXED_NJ = [PNJ]
if PQD:
    BWQD, IOPSQD = [PQD], [PQD]
if PNR:
    NRL, NR = [PNR], PNR
QD1 = PQD or 1                                     # the qd of the qd1 rungs
NRX = [x for x in NRL if x != NR]
# safe and max: one iodepth and one nrfiles per type, pins first
def fixed_geom():
    q = K.get("fq", "1")
    n = K.get("fn", "1")
    return (PQD or (int(q) if q.isdigit() else 1), PNR or (int(n) if n.isdigit() else 1))
pinned = ", ".join("%s=%d" % (n, v) for n, v in (("numjobs", PNJ), ("iodepth", PQD),
                                                  ("nrfiles", PNR)) if v)

if act == "budget":
    if ctype in ("lat", "lat1m"):
        n = len(NRL)
    elif FIXED:
        n = len(FIXED_NJ) + CONFIRM
    elif ctype == "bw":
        n = len(BW_LOW) + len(HIGH) * len(NRL) * len(BWQD) + CONFIRM
    elif EXH:
        n = len(IOPS_LOW) + len(HIGH) * len(NRL) * len(IOPSQD) + CONFIRM
    else:
        n = len(IOPS_LOW) + len(HIGH) * (len(IOPSQD) + 2 * len(NRX)) + CONFIRM
    print(n)
    sys.exit(0)

rows = []
for line in open(hist):
    f = line.split()
    if len(f) < 7:
        continue
    rows.append((f[0], (int(f[2]), int(f[3]), int(f[4])), float(f[6]),
                 float(f[7]) if len(f) > 7 else None))

def reads(key, decision=False):
    return [v for p, k, v, a in rows if k == key and not (decision and p == "confirm")]

def best(key, decision=False):
    r = reads(key, decision)
    return max(r) if r else None

def aux(key):
    r = [a for p, k, v, a in rows if k == key and a is not None]
    return max(r) if r else None

def cell(phase, key, rt=None):
    print("cell %s %d %d %d %s" % (phase, key[0], key[1], key[2], rt or RT))
    sys.exit(0)

def finish(key, msg):
    print("done %d %d %d %s" % (key[0], key[1], key[2], msg))
    sys.exit(0)

def ahead(v, lead):
    """The leader rule (Frank, 2026-10-05): a reading takes the lead only
    when it is at least THR percent better than the leader's."""
    return lead <= 0 or v >= lead * (1 + THR / 100)

def plateau(vals):
    """True once STOP consecutive rungs failed to take the lead."""
    top, miss = 0.0, 0
    for v in vals:
        if ahead(v, top):
            top, miss = v, 0
        else:
            miss += 1
            if miss >= STOP:
                return True
    return False

def cheap(k):
    # which of the top cells a confirm pass re-measures first: the least
    # outstanding IO, then fewer jobs, then the shallower queue
    return (k[0] * k[1], k[0], k[1], k[2] != NR, k[2])

def leader(keys, decision=False):
    """Walk the cells in the order the ladder measured them; a cell takes
    the lead only when it beats the leader by THR percent."""
    lead = None
    for k in keys:
        if lead is None or ahead(best(k, decision), best(lead, decision)):
            lead = k
    return lead

def confirm_then_pick(keys):
    for k in sorted(keys, key=lambda k: (-best(k, True),) + cheap(k))[:CONFIRM]:
        if len(reads(k)) < 2:
            cell("confirm", k)
    return leader(keys)

def human(v):
    if ctype == "bw":
        return "%.2f GiB/s" % (v / float(1 << 30))
    return "%s IOPS" % format(int(v), ",")

def geo(k):
    return "numjobs=%d iodepth=%d nrfiles=%d" % k

def where(nj):
    return "one job per physical core" if nj <= N else "siblings in"

def over(k):
    """Every in-flight limit that refuses cell k; neither depends on nrfiles."""
    why = []
    if memcap > 0 and k[0] * k[1] * BS > memcap:
        why.append("its in-flight buffers exceed the memory guard (CAL_MEM_PCT)")
    if AIOCAP is not None and k[0] * k[1] > AIOCAP:
        why.append("libaio would set up %d aio events and the kernel has room for %d"
                   % (k[0] * k[1], AIOCAP))
    return why

def fits(k):
    # a pinned depth at a pinned job count is used as written: no guard
    return bool(PNJ and PQD) or not over(k)

notes = []
if pinned:
    notes.append("pinned by the host file: %s -- the only value(s) tried" % pinned)
def guard(k):
    # one note per job count and depth, naming every limit that refused it;
    # raising fs.aio-max-nr only helps when the room is the sole reason, and
    # the host file keeps the shorter answer until -g re-measures it
    why = over(k)
    n = "the queue ladder stopped short of numjobs=%d iodepth=%d: %s" % (
        k[0], k[1], " and ".join(why))
    if len(why) == 1 and why[0].startswith("libaio"):
        n += " (raise fs.aio-max-nr and re-measure with -g to search deeper)"
    if n not in notes:
        notes.append(n)

def reading(k):
    n = len(reads(k))
    return "%s (best of %d)" % (human(best(k)), n) if n > 1 else human(best(k))

if FIXED and ctype in ("bw", "iops"):
    # safe and max: numjobs N/2, N and 2N at one iodepth and nrfiles (safe
    # 1 and 1; max the largest any cal or brutal search has chosen across
    # the labs and field runs so far), every rung measured, the leader wins
    qd, nr = fixed_geom()
    keys = []
    for nj in FIXED_NJ:
        k = (nj, qd, nr)
        if not fits(k):
            guard(k)
            break    # both guards grow with numjobs: a wider count cannot fit either
        if best(k, True) is None:
            cell("numjobs", k)
        keys.append(k)
    if not keys:
        sys.exit("ERROR: cal_plan: -a %s: no job count fits at iodepth=%d (%s)"
                 % (LVL, qd, "; ".join(notes)))
    k = confirm_then_pick(keys)
    line_note = ""
    if ctype == "bw" and linerate > 0:
        line_note = " = %.1f%% of the %.2f GiB/s line rate" % (
            best(k) * 100 / linerate, linerate / float(1 << 30))
    finish(k, "%s -> %s%s (-a %s: numjobs %s at iodepth %d nrfiles %d, the leader by %g%%; %s)%s"
           % (geo(k), reading(k), line_note, LVL, ", ".join(str(x[0]) for x in keys), qd, nr,
              THR, where(k[0]), ("; " + "; ".join(notes)) if notes else ""))

if ctype == "bw":
    target = linerate * LINE / 100 if linerate > 0 else 0.0
    if target and rows and max(v for p, k, v, a in rows) > linerate * 1.05:
        target = 0.0
        # "the line rate", not the NIC's: it may be the operator's --line-rate
        notes.append("a reading beat the line rate by more than 5%, so line "
                     "rate is not this client's ceiling -- searched for the peak")
    def of_line(k):
        return (" = %.1f%% of the %.2f GiB/s line rate" % (best(k) * 100 / linerate,
                linerate / float(1 << 30))) if linerate > 0 else ""
    def note():
        return ("; " + "; ".join(notes)) if notes else ""
    # at or below N: one job per physical core, nrfiles=1 iodepth=1, nothing else
    done1, vals = [], []
    for nj in BW_LOW:
        k = (nj, QD1, NR)
        if best(k, True) is None:
            cell("numjobs", k)
        done1.append(k)
        vals.append(best(k, True))
        if target and not EXH and best(k, True) >= target:
            finish(k, "%s -> %s%s (the first numjobs at >= %g%% of line rate, "
                   "one job per physical core)%s"
                   % (geo(k), human(best(k)), of_line(k), LINE, note()))
        if not target and not EXH and plateau(vals):
            break
    top1 = max([best(k, True) for k in done1] or [0.0])
    # past N the siblings join, and iodepth x nrfiles are searched
    done2 = []
    for nj in HIGH:
        top2 = 0.0
        for nr in NRL:
            vals2 = []
            for qd in BWQD:
                k = (nj, qd, nr)
                if not fits(k):
                    guard(k)
                    break
                if best(k, True) is None:
                    cell("wide", k)
                done2.append(k)
                v = best(k, True)
                vals2.append(v)
                top2 = max(top2, v)
                if target and not EXH and v >= target:
                    finish(k, "%s -> %s%s (numjobs up to N=%d on the physical cores did "
                           "not reach %g%% of line rate; this is the first cell with the "
                           "siblings in that did)%s"
                           % (geo(k), human(v), of_line(k), N, LINE, note()))
                if not EXH and plateau(vals2):
                    break
        if not any(k[0] == nj for k in done2):
            # a guard refused this job count's first cell at every nrfiles:
            # 2N was never measured (so it did not "lose"), and both guards
            # grow with numjobs x iodepth, so 4N cannot fit either
            break
        if not EXH and nj == 2 * N and not ahead(top2, top1):
            notes.append("2N (%d jobs, siblings in) did not beat N by %g%%; 4N was not tried" % (nj, THR))
            break
    k = confirm_then_pick(done1 + done2)
    if EXH:
        why = "the leader of every rung measured, by %g%%" % THR
    elif target:
        why = "never reached %g%% of line rate; the leader by %g%%" % (LINE, THR)
    else:
        why = "the leader by %g%%" % THR
    finish(k, "%s -> %s%s (%s, %s)%s" % (geo(k), reading(k), of_line(k), why,
                                        where(k[0]), note()))

if ctype == "iops":
    pool, trail = [], []
    # at or below N: one job per physical core at iodepth=1 nrfiles=1, nothing else
    for nj in IOPS_LOW:
        k = (nj, QD1, NR)
        if best(k, True) is None:
            cell("numjobs", k)
        pool.append(k)
        trail.append("%d jobs %s at iodepth %d" % (nj, human(best(k, True)), QD1))
    top_low = max([best(k, True) for k in pool] or [0.0])
    # past N the siblings join, and iodepth x nrfiles are searched
    for nj in HIGH:
        mine = []
        for nr in (NRL if EXH else [NR]):
            vals = []
            for qd in IOPSQD:
                k = (nj, qd, nr)
                if not fits(k):
                    guard(k)
                    break
                if best(k, True) is None:
                    cell("iodepth" if nr == NR else "nrfiles", k)
                pool.append(k)
                mine.append(k)
                vals.append(best(k, True))
                if not EXH and plateau(vals):
                    break
        if not mine:
            break    # a guard (memory or aio room) stopped this job count before its first cell
        top = leader(mine, True)
        if not EXH:
            for nr in NRX:
                for qd in sorted(set([top[1], min(top[1] * 2, max(IOPSQD))])):
                    k = (nj, qd, nr)
                    if not fits(k):
                        continue
                    if best(k, True) is None:
                        cell("nrfiles", k)
                    pool.append(k)
                    mine.append(k)
        top = leader(mine, True)
        trail.append("%d jobs %s at iodepth %d nrfiles %d"
                     % (nj, human(best(top, True)), top[1], top[2]))
        if not EXH and nj == 2 * N and not ahead(best(top, True), top_low):
            notes.append("2N (%d jobs, siblings in) did not beat N by %g%%; 4N was not tried" % (nj, THR))
            break
    k = confirm_then_pick(pool)
    finish(k, "%s -> %s (%s; %s)%s" % (geo(k), reading(k), ", ".join(trail), where(k[0]),
                                      ("; " + "; ".join(notes)) if notes else ""))

if ctype in ("lat", "lat1m"):
    # every level (Frank, 2026-10-05): N jobs -- one per physical core, the
    # siblings idle -- at iodepth 1, and the only ladder is nrfiles; the
    # lowest mean latency wins, no threshold. The one-job test runs beside
    # it in the measured run, so a single stream and full load compare.
    nj = PNJ or N
    keys = [(nj, QD1, nr) for nr in NRL]
    for k in keys:
        if not reads(k):
            cell("nrfiles", k)
    bk = min(keys, key=lambda k: (min(reads(k)), k[2]))
    msg = ("%s%s -> %.1f us, %s IOPS (the lowest mean of nrfiles %s at %d jobs, %s)"
           % ("1MiB " if ctype == "lat1m" else "", geo(bk), min(reads(bk)),
              format(int(aux(bk) or 0), ","), ", ".join(
                  "%d %.1f us" % (k[2], min(reads(k))) for k in keys), nj, where(nj)))
    if notes:
        msg += "; " + "; ".join(notes)
    finish(bk, msg)

sys.exit("ERROR: cal_plan: unknown cell type: %s" % ctype)
