import os
import sys

host, sep, fmt, nj, maxf = (sys.argv[1], sys.argv[2], sys.argv[3],
                            int(sys.argv[4]), int(sys.argv[5]))
dirs = set()
for j in range(nj):
    for f in range(maxf + 1):
        name = (host + sep + fmt).replace("$jobnum", str(j)).replace("$filenum", str(f))
        d = os.path.dirname(name)
        if d:
            dirs.add(d)
print("\n".join(sorted(dirs)))
