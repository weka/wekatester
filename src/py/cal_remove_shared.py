import re
import sys

host, sep, fmt, hd = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
pat = host + sep + fmt
glob = re.sub(r"\$\w+", "*", pat)
depth = 1 + glob.count("/")
cmd = f"find '{hd}' -maxdepth {depth} -type f -path '{hd}/{glob}' -delete"
if "/" in glob:
    dglob = glob.rsplit("/", 1)[0]
    cmd += f" && find '{hd}' -maxdepth {depth - 1} -type d -path '{hd}/{dglob}' -empty -delete"
print(cmd)
