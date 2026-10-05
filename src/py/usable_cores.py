import sys

path = sys.argv[1]
c = probe_cores(path, sys.argv[3])
if c["n"] < 1:
    sys.exit(f"ERROR: usable_cores: {path} leaves fio no cpus: {cores_summary(c)}")
if sys.argv[2] == "list":
    print(",".join(str(x) for x in c["all"]))
elif sys.argv[2] == "phys":
    print(",".join(str(x) for x in c["phys"]))
else:
    print(c["n"])
