# --- jobfiles ---
# The first key=<value> line, its value up to the first blank; "" when none.
function first_value(L, n, key,    i, v) {
    for (i = 1; i <= n; i++) {
        if (index(L[i], key "=") != 1) continue
        v = substr(L[i], length(key) + 2)
        if (match(v, /^[^ \t\n\013\014\r\034\035\036\037]+/)) return substr(v, 1, RLENGTH)
    }
    return ""
}
function is_layout_marked(L, n,    i) {   # the layout marker in the first three lines
    for (i = 1; i <= 3 && i <= n; i++)
        if (index(L[i], layout_marker()) == 1) return 1
    return 0
}
# override_variant_key on lines L: replace every key= line, else insert after
# the first [global], else create [global]. Returns the new line count.
function override_lines(L, n, key, value,    O, i, m, hit, g) {
    m = 0; hit = 0; g = 0
    for (i = 1; i <= n; i++)
        if (index(L[i], key "=") == 1) hit = 1
        else if (!g && index(L[i], "[global]") == 1) g = i
    if (!hit && !g) { O[++m] = "[global]"; O[++m] = key "=" value }
    for (i = 1; i <= n; i++) {
        O[++m] = (hit && index(L[i], key "=") == 1) ? key "=" value : L[i]
        if (!hit && i == g) O[++m] = key "=" value
    }
    split("", L)
    for (i = 1; i <= m; i++) L[i] = O[i]
    return m
}
# The sha256 a generated layout job's marker carries, "" for another line.
# The body it covers is layout_body's.
function marker_sha(line,    p, h) {
    p = layout_marker() " sha256="
    if (index(line, p) != 1) return ""
    h = rstrip(substr(line, length(p) + 1))
    return (length(h) == 64 && h ~ /^[0-9a-f]+$/) ? h : ""
}
function layout_body(L, n,    i, k, out) {   # every non-marker line, trailing blanks off, \n-joined
    out = ""; k = 0
    for (i = 1; i <= n; i++)
        if (index(L[i], layout_marker()) != 1) out = out (k++ ? "\n" : "") rstrip(L[i])
    return out
}
# Most aio events one jobfile sets up at once via libaio: numjobs x iodepth
# per section ([global] inherited), summed per stonewall group, the largest
# group taken; 0 without libaio.
function libaio_events(L, n,    i, s, p, k, v, G, sec, insec, ng, GS, GN, best) {
    split("", G); split("", sec); insec = 0; ng = 1; GS[1] = 0; GN[1] = 0
    for (i = 1; i <= n + 1; i++) {
        if (i <= n) {
            s = strip(L[i])
            if (s == "" || substr(s, 1, 1) == "#" || substr(s, 1, 1) == ";") continue
            if (s !~ /^\[.+\]$/) {
                if ((p = index(s, "="))) { k = strip(substr(s, 1, p - 1)); v = strip(substr(s, p + 1)) }
                else { k = strip(s); v = "" }
                if (insec) sec[k] = v; else G[k] = v
                continue
            }
        }
        if (insec) {   # a section ends: at the next header, or at the end
            if ((("stonewall" in sec) ? sec["stonewall"] : "0") != "0" && GN[ng] > 0) {
                ng++; GS[ng] = 0; GN[ng] = 0
            }
            if (("ioengine" in sec) && sec["ioengine"] == "libaio") {
                k = ("numjobs" in sec) && sec["numjobs"] != "" ? py_int(sec["numjobs"]) : 1
                v = ("iodepth" in sec) && sec["iodepth"] != "" ? py_int(sec["iodepth"]) : 1
                GS[ng] += (k == "" || v == "") ? 0 : k * v
                GN[ng]++
            }
        }
        if (i > n) break
        insec = strip(substr(s, 2, length(s) - 2)) != "global"
        if (insec) { split("", sec); for (k in G) sec[k] = G[k] }
    }
    best = GS[1]
    for (i = 2; i <= ng; i++) if (GS[i] > best) best = GS[i]
    return best
}

# "5G", "1.5GiB", "4k" as bytes; "" for anything that is not a size
function parse_size(s,    u, m) {
    s = strip(s)
    if (s !~ /^[0-9]+(\.[0-9]+)?[kKmMgGtT]?i?[bB]?$/) return ""
    match(s, /^[0-9]+(\.[0-9]+)?/)
    u = substr(s, RLENGTH + 1, 1)
    m = u == "" ? 0 : index("kmgt", tolower(u))
    return int(substr(s, 1, RLENGTH) * (m ? 2 ^ (10 * m) : 1))
}
# A section header ("[name]", blanks may follow): its name, else ""
function section_name(line,    t) {
    if (line !~ /^\[.+\][ \t\n\013\014\r\034\035\036\037]*$/) return ""
    t = rstrip(line)
    return substr(t, 2, length(t) - 2)
}
function last_section(L, n,    i, s, name) {   # the last section's name, "" for none
    name = ""
    for (i = 1; i <= n; i++) if ((s = section_name(L[i])) != "") name = s
    return name
}
# Does a "# report <items>" line (whitespace after "report") name <word>?
function report_has(L, n, word,    i, F, k, m) {
    for (i = 1; i <= n; i++) {
        if (!match(L[i], /^#[ \t\n\013\014\r\034\035\036\037]*report[ \t\n\013\014\r\034\035\036\037]/)) continue
        m = pysplit(substr(L[i], RLENGTH + 1), F)
        for (k = 1; k <= m; k++) if (F[k] == word) return 1
    }
    return 0
}
# The value of a "<key>=<value>" line whose key matches the anchored ERE
# <keys>, up to the first blank; "" for any other line
function key_value(line, keys,    v) {
    if (!match(line, "^(" keys ")=[^ \t\n\013\014\r\034\035\036\037]+")) return ""
    v = substr(line, 1, RLENGTH)
    return substr(v, index(v, "=") + 1)
}
# Bytes of the measured (last) section bs, else [global], else 4k; a split
# value (4k,8k) by its first entry.
function job_bs(L, n,    i, name, injob, glob, last, v) {
    glob = ""; last = ""; injob = 0
    for (i = 1; i <= n; i++) {
        if ((name = section_name(L[i])) != "") {
            injob = strip(name) != "global"
            if (injob) last = ""
            continue
        }
        if ((v = key_value(L[i], "bs|blocksize")) == "") continue
        if (injob) last = v; else glob = v
    }
    v = last != "" ? last : glob != "" ? glob : "4k"
    sub(/,.*/, "", v); sub(/:.*/, "", v)
    v = parse_size(v)
    return v == "" ? 4096 : v
}
function lat_kind(L, n) { return job_bs(L, n) >= 1048576 ? "lat1m" : "lat" }
# Directions the job sections exercise into D, [global] rw= as the fallback
# (rw= or readwrite=); trim-only mixes have none.
function rw_directions(v, D) {
    v = tolower(v); sub(/:.*/, "", v)   # fio's ":<modifier>" is no direction
    if (v == "read" || v == "randread") D["read"] = 1
    else if (v == "write" || v == "randwrite") D["write"] = 1
    else if (v == "rw" || v == "randrw" || v == "readwrite" || v == "randreadwrite") {
        D["read"] = 1; D["write"] = 1
    }
}
function file_directions(L, n, D,    i, name, ns, cur, glob, RW, v) {
    split("", D); glob = ""; ns = 0; cur = 0
    for (i = 1; i <= n; i++) {
        if ((name = section_name(L[i])) != "") {
            if (strip(name) == "global") cur = 0
            else { RW[++ns] = ""; cur = ns }
            continue
        }
        if ((v = key_value(L[i], "rw|readwrite")) == "") continue
        if (cur) RW[cur] = v; else glob = v
    }
    if (!ns) rw_directions(glob, D)
    for (i = 1; i <= ns; i++) rw_directions(RW[i] != "" ? RW[i] : glob, D)
}
# A resolved host-file row (resolve_targets' tab-separated output, split
# into ROW): the 1-based column of a FIELDS key, and its value ("" for "-")
function field_col(key,    S, n, i) {
    if (key == "login") return 2
    if (key == "engine") return 3
    if (key == "cpus") return 4
    if (key == "dir") return 5
    n = split(geom_slots(), S, " ")
    for (i = 1; i <= n; i++)
        if (index(key, S[i] "_") == 1)
            return 6 + 4 * (i - 1) + (index("nj fs nr qd", substr(key, length(S[i]) + 2)) - 1) / 3
    return 0
}
function row_get(ROW, key,    c) {
    c = field_col(key)
    return (c in ROW) && ROW[c] != "-" ? ROW[c] : ""
}
# A file slot: its own direction, or for a mixed file the one with the deeper
# recorded qd (a whole measured tuple, never a blend); "" for none.
function pick_slot(kind, D, ROW,    r, w) {
    if (("read" in D) && !("write" in D)) return kind "_r"
    if (("write" in D) && !("read" in D)) return kind "_w"
    r = row_get(ROW, kind "_r_qd"); r = r ~ /^[0-9]+$/ ? r + 0 : -1
    w = row_get(ROW, kind "_w_qd"); w = w ~ /^[0-9]+$/ ? w + 0 : -1
    if (r < 0 && w < 0)
        return slot_any(ROW, kind "_r") ? kind "_r" : slot_any(ROW, kind "_w") ? kind "_w" : ""
    return r >= w ? kind "_r" : kind "_w"
}
function slot_any(ROW, slot) {
    return row_get(ROW, slot "_nj") != "" || row_get(ROW, slot "_fs") != "" || row_get(ROW, slot "_nr") != "" || row_get(ROW, slot "_qd") != ""
}
# Most-used engine; ties go by ENGINE_ORDER (io_uring, libaio, psync), an
# unlisted engine last, first seen first.
function pick_engine(TALLY, ORD, n,    O, no, i, j, e, r, best, bc, br) {
    no = split(engine_order(), O, " ")
    if (!n) return O[1]
    for (i = 1; i <= n; i++) {
        e = ORD[i]; r = no
        for (j = 1; j <= no; j++) if (O[j] == e) { r = j - 1; break }
        if (i == 1 || TALLY[e] > bc || (TALLY[e] == bc && r < br)) { best = e; bc = TALLY[e]; br = r }
    }
    return best
}
function is_floor_marked(L, n,    i) {   # the one-job twin's marker in the first three lines
    for (i = 1; i <= 3 && i <= n; i++)
        if (index(L[i], floor_marker()) == 1) return 1
    return 0
}
# INI view: lines stripped, blanks and #/; comments skipped. SN[1..ns] the
# sections, KV[s, key] values, KV["g", key] [global]; ini_get falls back
# section -> [global] -> <dflt>.
function ini_parse(L, n, SN, KV,    i, line, c, cur, ns, p) {
    split("", SN); split("", KV); ns = 0; cur = ""
    for (i = 1; i <= n; i++) {
        line = strip(L[i]); c = substr(line, 1, 1)
        if (line == "" || c == "#" || c == ";") continue
        if (c == "[") {
            SN[++ns] = substr(line, 2, length(line) - 2)
            if (SN[ns] == "global") { cur = "g"; ns-- }
            else cur = ns
            continue
        }
        if ((p = index(line, "=")) && cur != "")
            KV[cur, strip(substr(line, 1, p - 1))] = strip(substr(line, p + 1))
    }
    return ns
}
function ini_get(KV, s, key, dflt) {
    return ((s, key) in KV) ? KV[s, key] : (("g", key) in KV) ? KV["g", key] : dflt
}

