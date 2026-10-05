import os, sys

glb, sections, cur = {}, [], None
for raw in open(sys.argv[1]):
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

dirs = set()
for name, sec in sections:
    fmt = sec.get("filename_format", glb.get("filename_format"))
    if not fmt or "/" not in fmt:
        continue
    sub = fmt.rsplit("/", 1)[0].replace("$jobname", name)
    combos = [sub]
    for var, key in (("$filenum", "nrfiles"), ("$jobnum", "numjobs")):
        if var in sub:
            count = int(sec.get(key, glb.get(key, 1)))
            combos = [c.replace(var, str(n)) for c in combos for n in range(count)]
    if any("$" in c for c in combos):
        print(f"WARNING: cannot pre-create directories for [{name}]: "
              f"unsupported variable in '{sub}'", file=sys.stderr)
        continue
    base = sec.get("directory", glb.get("directory", ""))
    for c in combos:
        dirs.add(os.path.join(base, c))

# chunked so the remote command stays far below ssh's packet limit
dirs = sorted(dirs)
cmds = []
while dirs:
    chunk, dirs = dirs[:400], dirs[400:]
    cmds.append("mkdir -p " + " ".join("'%s'" % d for d in chunk))
print(" && ".join(cmds))
