import os, sys

argv = sys.argv[1:]
for i in range(0, len(argv), 3):
    jobsdir, host, cpus = argv[i:i + 3]
    if cpus == "-":
        cpus = ""
    for name in sorted(os.listdir(jobsdir)):
        path = os.path.join(jobsdir, name)
        if not os.path.isfile(path):
            continue
        lines = open(path).read().splitlines()
        has_fmt = any(l.strip().startswith("filename_format=") for l in lines)
        out = []
        for l in lines:
            s = l.strip()
            if s.startswith("filename_format="):
                val = s.split("=", 1)[1]
                if "$clientuid" not in val and not val.startswith("shared."):
                    l = "filename_format=" + host + "." + val
            elif s.startswith("unique_filename="):
                continue   # replaced by the forced 0 below
            out.append(l)
        has_cpus = any(l.strip().startswith("cpus_allowed=") for l in out)
        has_policy = any(l.strip().startswith("cpus_allowed_policy=") for l in out)
        ins = ["unique_filename=0"]
        if not has_fmt:
            ins.append("filename_format=%s.$jobname.$jobnum.$filenum" % host)
        if cpus and not has_cpus:
            ins.append("cpus_allowed=" + cpus)
            has_cpus = True
        if has_cpus and not has_policy:
            ins.append("cpus_allowed_policy=split")
        if any(l.strip() == "[global]" for l in out):
            res, done = [], False
            for l in out:
                res.append(l)
                if not done and l.strip() == "[global]":
                    res.extend(ins)
                    done = True
            out = res
        else:
            out = ["[global]"] + ins + out
        open(path, "w").write("\n".join(out) + "\n")
