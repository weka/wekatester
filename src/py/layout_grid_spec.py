import os, re, sys

def spec(path):
    glb, sections, cur = {}, [], None
    lines = open(path).read().splitlines()
    for raw in lines:
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("["):
            name = line[1:-1]
            cur = glb if name == "global" else {}
            if name != "global":
                sections.append((name, cur))
            continue
        if "=" in line and cur is not None:
            k, v = line.split("=", 1)
            cur[k.strip()] = v.strip()
    out = []
    for name, sec in sections:
        def get(key, dflt=None):
            return sec.get(key, glb.get(key, dflt))
        fmt = get("filename_format")
        fsz = get("filesize")
        if not fmt or not fsz:
            continue   # nothing statable without both; the fio run still covers it
        size = parse_size(fsz)
        nr = int(get("nrfiles", "1"))
        nj = int(get("numjobs", "1"))
        fmt = fmt.replace("$jobname", name)
        # a singleton counter is an EXACT path component, not a wildcard: with
        # nrfiles=1 the glob $filenum/* would sweep every sibling directory the
        # namespace's OTHER sections own (seen live: two same-format sections,
        # 1G x 502 dirs + 10G in dir 0, each deleting the other's files)
        if nr == 1:
            fmt = fmt.replace("$filenum", "0")
        if nj == 1:
            fmt = fmt.replace("$jobnum", "0")
        glob = re.sub(r"\$\w+", "*", fmt)
        depth = 1 + glob.count("/")
        out.append(f"{size}\t{glob}\t{depth}\t{size * nr * nj}")
    return out, "fallocate=none" in lines

if sys.argv[1] == "-o":
    outdir, rest = sys.argv[2], sys.argv[3:]
    for host, path in zip(rest[::2], rest[1::2]):
        out, has_fallocate = spec(path)
        with open(os.path.join(outdir, host + ".gridspec"), "w") as fh:
            fh.write("".join(l + "\n" for l in out))
        if out and not has_fallocate:
            print(host)
else:
    for l in spec(sys.argv[1])[0]:
        print(l)
