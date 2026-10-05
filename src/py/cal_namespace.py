import os
import re
import sys

src = sys.argv[1]
for job in sorted(f for f in os.listdir(src) if re.match(r"^[0-9]", f)):
    path = os.path.join(src, job)
    try:
        lines = open(path).read().splitlines()
    except OSError:
        continue
    if any(l.startswith("# wekatester-layout: generated") for l in lines[:3]):
        continue          # the layout job mirrors the measured ones
    fmt = first_value(lines, "filename_format")
    if fmt and "$filenum" in fmt and "$jobnum" in fmt and "$jobname" not in fmt:
        print("unified", fmt)
        raise SystemExit(0)
print("scratch", "$jobnum.$filenum")
