import hashlib, re, sys
lines = open(sys.argv[1]).read().splitlines()
MARKER = "# wekatester-layout: generated"
for l in lines[:3]:
    m = re.match(re.escape(MARKER) + r" sha256=([0-9a-f]{64})\s*$", l)
    if m:
        body = [x for x in lines if not x.startswith(MARKER)]
        digest = hashlib.sha256("\n".join(x.rstrip() for x in body).encode()).hexdigest()
        sys.exit(0 if digest == m.group(1) else 1)
sys.exit(1)
