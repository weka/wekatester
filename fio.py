#
# fio.py - classes and tools for working with the fio benchmark
#


from configparser import ConfigParser
import json
from logging import getLogger

log = getLogger(__name__)


def formatter(numeric_val, unit_defs):
    unit_str = "ERROR!"
    unit_amount = 0
    for units, unitvalue in unit_defs.items():
        if numeric_val >= unitvalue:
            unit_amount = unitvalue
            unit_str = units
            break

    if unit_amount == 0:
        return numeric_val, unit_str
    else:
        return (numeric_val / unit_amount), unit_str


# format a number of bytes in GiB/MiB/KiB
def format_units_bytes(numbytes):
    val, units = formatter(numbytes, {"TiB": 1024 ** 4, "GiB": 1024 ** 3, "MiB": 1024 ** 2, "KiB": 1024, "bytes": 0})
    return "%0.2f %s" % (val, units)


# format a number of seconds in s/ms/us/ns
def format_units_time(nanosecs):
    val, units = formatter(nanosecs, {"s": 1000 ** 3, "ms": 1000 ** 2, "\u03bcs": 1000, "ns": 0})
    return "%d %s" % (int(val), units)


# format a number of iops
def format_units_iops(iops):
    return f"{int(iops):,}"


# object representing a fio workload from a fio jobfile
class FioJobfile:
    def __init__(self, filename):
        self.filename = filename
        self._find_reportitems()  # reporting items

        self.jobfile = ConfigParser(allow_no_value=True)
        self.jobfile.read(self.filename)

    def _find_reportitems(self):
        # look for report items in the jobfile
        self.reportitem = {"bandwidth": False, "latency": False, "iops": False}  # reset to all off
        with open(self.filename) as jobfile:
            for lineno, line in enumerate(jobfile):
                line.strip()
                linelist = line.split()
                if len(linelist) > 0:
                    if linelist[0][0] == "#":  # first char is '#'
                        if linelist[0] == "#report":
                            linelist.pop(0)  # get rid of the "#report"
                        elif len(linelist) < 2:
                            continue  # blank comment line?
                        elif linelist[1] == "report":  # we're interested
                            linelist.pop(0)  # get rid of the "#"
                            linelist.pop(0)  # get rid of the "report"
                        else:
                            continue

                        # found a "# report" directive in the file
                        for keyword in linelist:
                            if keyword not in self.reportitem.keys():
                                log.error("Syntax error in # report directive in " + self.filename + ", line " + str(
                                    lineno + 1) + ": keyword '" + keyword + "' undefined. Ignored.")
                            else:
                                log.debug(f"found keyword {keyword} in jobfile {self.filename}")
                                self.reportitem[keyword] = True

        if not self.reportitem["bandwidth"] and not self.reportitem["iops"] and not self.reportitem["latency"]:
            log.info(f"NOTE: No valid # report specification in {self.filename}; reporting all")
            self.reportitem = {"bandwidth": True, "latency": True, "iops": True}  # set to all

    def override(self, item, value, nolower=False):
        found = False
        for section in self.jobfile.sections():
            if self.jobfile.has_option(section, item):
                found = True
                if nolower and value.isnumeric() and int(value) < int(self.jobfile.get(section, item)):
                    pass
                else:
                    self.jobfile.set(section, item, value)

        if not found:
            if not self.jobfile.has_section('global'):
                self.jobfile.add_section('global')
            self.jobfile.set('global', item, value)

    def write(self, filename):
        log.debug(f"writing jobfile {filename}")
        with open(filename, 'w') as f:
            self.jobfile.write(f, space_around_delimiters=False)


# store, analyse and print out fio results
def _log_perf(operation, unit, value):
    if unit == "latency":
        log_formatter = format_units_time
        per = ""
    elif unit == "iops":
        log_formatter = format_units_iops
        per = "/s"
    else:
        log_formatter = format_units_bytes
        per = "/s"

    if operation == "average" and unit != "latency":
        per += " per host"

    if value != 0:
        log.info(f"    {operation} {unit}: {log_formatter(value)}{per}")


class FioResult:
    def __init__(self, jobfile, results_str):
        index = results_str.index('{')
        self.fio_output = json.loads(results_str[index:])

        self.version = self.fio_output['fio version']
        self.time = self.fio_output['time']
        self.options = self.fio_output['global options']
        self.client_stats = dict()
        self.jobname = None
        self.jobfile = jobfile
        for stats in self.fio_output['client_stats']:
            if stats["jobname"] == "All clients":
                self.summary = stats
            else:
                if self.jobname is None:
                    self.jobname = stats["jobname"]
                log.debug(f"recording stats for {stats['hostname']}")
                self.client_stats[stats['hostname']] = stats

    def summarize(self):
        bw = dict()
        iops = dict()
        latency = dict()

        # log.debug(f"{self.summary}") - makes logger puke - too long

        bw["read"] = self.summary["read"]["bw_bytes"]
        bw["write"] = self.summary["write"]["bw_bytes"]
        iops["read"] = self.summary["read"]["iops"]
        iops["write"] = self.summary["write"]["iops"]
        latency["read"] = self.summary["read"]["lat_ns"]["mean"]
        latency["write"] = self.summary["write"]["lat_ns"]["mean"]
        hostcount = len(self.client_stats)

        # print(bw)
        log.debug(f"hostcount={hostcount}")

        if self.jobfile.reportitem["bandwidth"]:
            _log_perf("read", "bandwidth", bw["read"])
            _log_perf("write", "bandwidth", bw["write"])
            _log_perf("total", "bandwidth", bw["read"] + bw["write"])
            _log_perf("average", "bandwidth", float(bw["read"] + bw["write"]) / float(hostcount))
        if self.jobfile.reportitem["iops"]:
            _log_perf("read", "iops", iops["read"])
            _log_perf("write", "iops", iops["write"])
            _log_perf("total", "iops", iops["read"] + iops["write"])
            _log_perf("average", "iops", (iops["read"] + iops["write"]) / hostcount)
        if self.jobfile.reportitem["latency"]:
            _log_perf("read", "latency", latency["read"])
            _log_perf("write", "latency", latency["write"])
            if (latency["read"] > 0.0) and (latency["write"] > 0.0):
                _log_perf("average", "latency", latency["read"] + latency["write"] / 2)

        log.info("")

    def dumps(self):
        return json.dumps(self.fio_output, indent=2)





# some debugging functions - show structure of a dict (useful for fio json output)
def print_list(mylist, level=0):
    for item in mylist:
        if type(item) == dict:
            print_dictkeys(item, level + 1)
            log.debug(",")
        elif type(item) == list:
            print_list(item, level + 1)
    # print(f"{' ' * (level * 2)}]")


def print_dictkeys(mydict, level=0):
    if type(mydict) == dict:
        for key, value in mydict.items():
            if type(value) == dict:
                log.debug(f"{' ' * (level * 2)}{key}: ")
                print_dictkeys(value, level=level + 1)
            elif type(value) == list:
                log.debug(f"{' ' * (level * 2)}{key} ")
                print_list(value, level=level + 1)
            else:
                log.debug(f"{' ' * (level * 2)}{key}: ")
