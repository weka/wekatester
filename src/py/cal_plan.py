import sys

act, ctype, dirn, eng = sys.argv[1:5]
N = max(1, int(sys.argv[5]))
linerate = float(sys.argv[6])
memcap = float(sys.argv[7])
hist = sys.argv[8]
K = dict(kv.split("=", 1) for kv in sys.argv[9:] if "=" in kv)
EXH = K.get("exh") == "1"
LINE, FLOORPCT, BAND = float(K["line"]), float(K["floor"]), float(K["band"])
THR, STOP, CONFIRM = float(K["thr"]), int(K["stop"]), int(K["confirm"])
RT, NR = K["rt"], int(K["nr"])
def lad(key):
    return sorted(set(int(x) for x in K[key].split(",") if x.strip()))
NRL, BWQD, IOPSQD = lad("nrc"), lad("bwqd"), lad("iopsqd")
FLOORREPS = max(1, int(K["floorreps"]))
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
LAT_LOW = sorted(set(doubling(2, N) + [N2, N]) - {1}) if N >= 2 else []

# Host-file values pin their knob (Frank, 2026-10-02): a pinned value is the
# ONLY value that knob takes, on every rung, whatever the rung's own rule
# says, and it is used as written -- never capped by a guard. The knobs left
# unpinned are searched as usual around it.
def pin(key):
    v = K.get(key, "-")
    return int(v) if v.isdigit() and int(v) > 0 else None
PNJ, PQD, PNR = pin("pin_nj"), pin("pin_qd"), pin("pin_nr")
if PNJ:
    BW_LOW = IOPS_LOW = LAT_LOW = [PNJ] if PNJ <= N else []
    HIGH = [PNJ] if PNJ > N else []
if PQD:
    BWQD, IOPSQD = [PQD], [PQD]
if PNR:
    NRL, NR = [PNR], PNR
QD1 = PQD or 1                                     # the qd of the qd1 rungs
NRX = [x for x in NRL if x != NR]
pinned = ", ".join("%s=%d" % (n, v) for n, v in (("numjobs", PNJ), ("iodepth", PQD),
                                                  ("nrfiles", PNR)) if v)

if act == "budget":
    if ctype == "bw":
        n = len(BW_LOW) + len(HIGH) * len(NRL) * len(BWQD) + CONFIRM
    elif ctype == "iops":
        if EXH:
            n = len(IOPS_LOW) + len(HIGH) * len(NRL) * len(IOPSQD) + CONFIRM
        else:
            n = len(IOPS_LOW) + len(HIGH) * (len(IOPSQD) + 2 * len(NRX)) + CONFIRM
    elif PNJ:
        n = FLOORREPS * (len(NRL) if PNJ > N else 1)
    else:
        n = FLOORREPS + 2 * (len(LAT_LOW) + len(HIGH) * len(NRL))
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

def plateau(vals):
    """True once STOP consecutive rungs failed to beat the best so far by
    more than THR percent."""
    top, miss = 0.0, 0
    for v in vals:
        if top <= 0 or v > top * (1 + THR / 100):
            top, miss = v, 0
        else:
            miss += 1
            if miss >= STOP:
                return True
    return False

def cheap(k):
    # inside the tie band the cheapest cell wins: the least outstanding IO,
    # then fewer jobs (job threads cost cpu, queue depth does not), then the
    # shallower queue, then the tabled file count
    return (k[0] * k[1], k[0], k[1], k[2] != NR, k[2])

def tiepick(keys, decision=False):
    top = max(best(k, decision) for k in keys)
    return min((k for k in keys if best(k, decision) >= top * BAND / 100), key=cheap)

def confirm_then_pick(keys):
    for k in sorted(keys, key=lambda k: (-best(k, True),) + cheap(k))[:CONFIRM]:
        if len(reads(k)) < 2:
            cell("confirm", k)
    return tiepick(keys)

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
        if not EXH and nj == 2 * N and top2 <= top1 * (1 + THR / 100):
            notes.append("2N (%d jobs, siblings in) did not beat N; 4N was not tried" % nj)
            break
    k = confirm_then_pick(done1 + done2)
    if EXH:
        why = "the peak of every rung measured"
    elif target:
        why = "never reached %g%% of line rate; the peak" % LINE
    else:
        why = "the peak"
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
        top = tiepick(mine, True)
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
        top = tiepick(mine, True)
        trail.append("%d jobs %s at iodepth %d nrfiles %d"
                     % (nj, human(best(top, True)), top[1], top[2]))
        if not EXH and nj == 2 * N and best(top, True) <= top_low * (1 + THR / 100):
            notes.append("2N (%d jobs, siblings in) did not beat N; 4N was not tried" % nj)
            break
    k = confirm_then_pick(pool)
    finish(k, "%s -> %s (%s; %s)%s" % (geo(k), reading(k), ", ".join(trail), where(k[0]),
                                      ("; " + "; ".join(notes)) if notes else ""))

if ctype in ("lat", "lat1m"):
    if PNJ:
        # the job count is pinned: no floor to widen from, no band -- the
        # pinned cell's lowest reading is the answer (each nrfiles past N,
        # unless that is pinned too)
        keys = [(PNJ, QD1, nr) for nr in (NRL if PNJ > N else [NR])]
        for k in keys:
            if len(reads(k)) < FLOORREPS:
                cell("pinned", k)
        bk = min(keys, key=lambda k: (min(reads(k)), k[2]))
        finish(bk, "%s%s -> %.1f us (lowest of %d), %s IOPS; %s"
               % ("1MiB " if ctype == "lat1m" else "", geo(bk), min(reads(bk)),
                  len(reads(bk)), format(int(aux(bk) or 0), ","), "; ".join(notes)))
    fk = (1, QD1, NR)
    fl = reads(fk)
    if len(fl) < FLOORREPS:
        cell("floor", fk)
    floor = min(fl)
    limit = floor * (1 + FLOORPCT / 100)
    last_in, first_out, detail = fk, None, []
    for nj in LAT_LOW + HIGH:
        # at or below N nrfiles=1 only; past it every file count, the lowest counts
        keys = [(nj, QD1, NR)] if nj <= N else [(nj, QD1, nr) for nr in NRL]
        for k in keys:
            if not reads(k):
                cell("widen" if k[2] == NR else "nrfiles", k)
        if first_out is not None:
            continue    # brutal measures on; the answer is already decided
        bk = min(keys, key=lambda k: (min(reads(k)), k[2]))
        if len(keys) > 1:
            detail.append("numjobs=%d: %s" % (nj, ", ".join(
                "nrfiles %d %.1f us" % (k[2], min(reads(k))) for k in keys)))
        if min(reads(bk)) <= limit:
            last_in = bk
            continue
        if len(reads(bk)) < 2:
            cell("recheck", bk)
        first_out = bk
        if not EXH:
            break
    at = min(reads(last_in))
    msg = ("%sfloor %.1f us (lowest of %d at numjobs=1), band <= %.1f us; "
           "numjobs=%d nrfiles=%d stays at the floor (%s): %.1f us, %s IOPS"
           % ("1MiB " if ctype == "lat1m" else "", floor, len(fl), limit, last_in[0],
              last_in[2], where(last_in[0]), at, format(int(aux(last_in) or 0), ",")))
    if first_out is not None:
        msg += "; numjobs=%d left the band at %.1f us (re-measured)" % (
            first_out[0], min(reads(first_out)))
    else:
        msg += "; every rung to numjobs=%d (4N) stayed inside the band" % (4 * N)
    if detail:
        msg += "; " + "; ".join(detail)
    if notes:
        msg += "; " + "; ".join(notes)
    finish(last_in, msg)

sys.exit("ERROR: cal_plan: unknown cell type: %s" % ctype)
