#!/usr/bin/env python3

import json
import decimal
import argparse
import glob
import os, sys, stat
import logging
import platform
import subprocess
import logging.handlers
import time
from subprocess import Popen, PIPE, STDOUT
from shutil import copyfile
from contextlib import contextmanager
import threading
from threading import Lock
from urllib3 import add_stderr_logger
import datetime
from paramiko import SSHClient, AutoAddPolicy, SSHConfig
import paramiko
from wekalib.sthreads import threaded, default_threader
from wekalib.wekacluster import WekaCluster


@contextmanager
def pushd(new_dir):
    """A Python context to move in and out of directories"""
    previous_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)


class SshConfig:
    def __init__(self):
        self.config = SSHConfig()
        try:
            self.config.parse(open(os.path.expanduser('~/.ssh/config')))
            # ssh_config.parse()

        except Exception as exc:
            print(exc)
            raise

    def lookup(self, hostname):
        return self.config.lookup(hostname)


# Connection class to perform SSH commands on remote server
class WorkerServer:
    def __init__(self, hostname, sshconfig):
        self.hostname = hostname
        self.ssh = None
        self.ssh_config = sshconfig

    #@threaded
    def open(self):
        self.ssh = SSHClient()
        self.config = self.ssh_config.lookup(self.hostname)
        self.ssh.set_missing_host_key_policy(AutoAddPolicy())

        try:
            self.ssh.connect(self.hostname, username=self.config["user"], key_filename=self.config["identityfile"],
                             timeout=10, auth_timeout=10)
        except Exception as exc:
            print(f"Exception opening ssh session: {exc}")
        else:
            announce(f"{self.hostname}")

    def close(self):
        if self.ssh:
            self.ssh.close()

    #@threaded
    def run(self, cmd):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            status = stdout.channel.recv_exit_status()
            response = stdout.read().decode("utf-8")
            error = stderr.read().decode("utf-8")
            self.last_output = {'status': status, 'response': response, 'error': error}
            # return {'status': status, 'response': response.decode("utf-8"), 'error': error.decode("utf-8")}
        except Exception as exc:
            self.last_output = {'status': -123,
                                 'description': 'Failed to run command',
                                 'traceback': str(exc)}

    def _linux_to_dict(self, separator):
        output = dict()
        if self.last_output['status'] != 0:
            raise Exception
        lines = self.last_output['response'].split('\n')
        for line in lines:
            if len(line) != 0:
                line_split = line.split(separator)
                output[line_split[0].strip()] = line_split[1].strip()
        return output

    #@threaded
    def gather_facts(self):
        """ build a dict from the output of lscpu """
        self.cpu_info = dict()
        self.run("lscpu")

        cpuinfo = self.last_output['response']
        self.cpu_info = self._linux_to_dict(':')

        self.run("cat /etc/os-release")
        self.os_info = self._linux_to_dict('=')

    def file_exists(self, path):
        """ see if a file exists on another server """
        self.run(f"if [ -f '{path}' ]; then echo 'True'; else echo 'False'; fi")
        if self.last_output['response'][:-1] == "True":
            return True
        else:
            return False

    def last_response(self):
        return self.last_output['response'][:-1]

    @threaded
    def threaded_run(self, cmd):
        self.run(cmd)


@threaded
def threaded_method(instance, method, *args, **kwargs):
    """ makes ANY method of ANY class threaded """
    method(instance, *args, **kwargs)

def parallel(servers, method, *args, **kwargs):
    for server in servers:
        threaded_method(server, method, *args, **kwargs)
    default_threader.run()


def pdsh(servers, command):
    parallel(servers, WorkerServer.run, command)

# print( something without a newline )
announce_lock = Lock()


def announce(text):
    with announce_lock:
        sys.stdout.flush()
        sys.stdout.write(text + " ")


def formatter(numeric_val, unit_defs):
    for units, unitvalue in unit_defs.items():
        if numeric_val > unitvalue:
            return (numeric_val/unitvalue), units


# format a number of bytes in GiB/MiB/KiB
def format_units_bytes(bytes):
    val, units = formatter(bytes, {"TiB": 1024**4, "GiB": 1024**3, "MiB": 1024**2, "KiB": 1024, "bytes": 0})
    return "%0.2f %s" % (val, units)


# format a number of bytes in GiB/MiB/KiB
def format_units_ns(nanosecs):
    val, units = formatter(nanosecs, {"s": 1000**3, "ms": 1000**2, "us": 1000, "ns": 0})
    return "%d %s" % (int(val), units)


def get_clients(wekacluster):
    # get the rest of the cluster (bring back any that had previously disappeared, or have been added)
    clientlist = list()

    try:
        api_return = self.call_api(method="hosts_list", parms={})
    except:
        raise

    for host in api_return:
        hostname = host["hostname"]
        if host["mode"] == "client":
            if host["state"] == "ACTIVE" and host["status"] == "UP":
                clientlist.append(hostname)

    return clientlist


# run a command via the shell, expect json output and return it.
def run_json_shell_command(command):
    tmpvar = json.loads(run_shell_command(command))
    return tmpvar


# run a command via the shell, check return code, exit on error.
def run_shell_command(command):
    try:
        output = subprocess.check_output(command, shell=True)
    except subprocess.CalledProcessError as err:
        print(sys.argv[0] + ": " + str(err))
        sys.exit(1)

    return output


def configure_logging(logger, verbosity):
    if args.verbosity == 0:
        loglevel = logging.ERROR
    elif args.verbosity == 1:
        loglevel = logging.WARNING
    elif args.verbosity == 2:
        loglevel = logging.INFO
    elif args.verbosity > 2:
        loglevel = logging.DEBUG

    FORMAT = "%(process)s:%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
    logger.setLevel(loglevel)

    # create handler to log to syslog
    print(f"setting syslog on {platform.platform()}")
    if platform.platform()[:5] == "macOS":
        syslogaddr = "/var/run/syslog"
    else:
        syslogaddr = "/dev/log"
    syslog_handler = logging.handlers.SysLogHandler(syslogaddr)
    syslog_handler.setFormatter(logging.Formatter(FORMAT))

    # create handler to log to stderr
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(FORMAT))

    # add handlers to root logger
    if syslog_handler is not None:
        logger.addHandler(syslog_handler)
    logger.addHandler(console_handler)

    logging.getLogger("wekalib.wekacluster").setLevel(logging.ERROR)
    logging.getLogger("wekalib.wekaapi").setLevel(logging.ERROR)
    logging.getLogger("wekalib.sthreads").setLevel(logging.ERROR)
    logging.getLogger("wekalib.circular").setLevel(logging.ERROR)

    # paramiko.util.log_to_file("demo.log")

    add_stderr_logger(level=logging.ERROR)

ssh_sessions = {}

if __name__ == '__main__':


    # parse arguments
    progname = sys.argv[0]
    parser = argparse.ArgumentParser(description='Acceptance Test a weka cluster')
    parser.add_argument('servers', metavar='servername', type=str, nargs='+',
                        help='Server Dataplane IPs to execute on')
    parser.add_argument("-c", "--clients", dest='use_clients_flag', action='store_true',
                        help="run fio on weka clients")
    parser.add_argument("-s", "--servers", dest='use_servers_flag', action='store_true',
                        help="run fio on weka servers")
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="increase output verbosity")
    # parser.add_argument("-a", "--al", dest='use_all_flag', action='store_true', help="run fio on weka servers and clients")
    parser.add_argument("-o", "--output", dest='use_output_flag', action='store_true', help="run fio with output")

    args = parser.parse_args()



    # set the root logger
    logger = logging.getLogger()

    configure_logging(logger, args.verbosity)

    # default to servers
    use_all = False
    if not args.use_clients_flag and not args.use_servers_flag and len(args.servers) == 1:  # neither flag
        servers = ["localhost"]
        args.use_servers_flag = True
    elif args.use_clients_flag and args.use_servers_flag:  # both flags
        use_all = True

    # load our ssh configuration
    sshconfig = SshConfig()

    workers = list()

    # clusterspec is <host>,<host>,..,<host>:auth
    if len(args.servers) == 1:  # either they gave us only one server, or it's a clusterspec
        clusterspeclist = args.servers[0].split(':')
        clusterspec = clusterspeclist[0]

        if len(clusterspeclist) == 2:
            auth = clusterspeclist[1]
        else:
            auth = None

        try:
            wekacluster = WekaCluster(clusterspec, authfile=auth)
            print("Testing Weka cluster " + wekacluster.name)

            weka_status = wekacluster.call_api(method="status", parms={})

            if weka_status["io_status"] != "STARTED":
                print("Weka not healthy - not started.")
                sys.exit()
            if weka_status["is_cluster"] != True:
                print("Weka not healthy - cluster not formed?")
                sys.exit()

            print("Cluster is v" + wekacluster.release)

            # inserted to capture the number of servers
            drivecount = weka_status["drives"]["active"]
            nettype = weka_status["net"]["link_layer"]
            clustdrivecap = weka_status["licensing"]["usage"]["drive_capacity_gb"]
            clustobjcap = weka_status["licensing"]["usage"]["obs_capacity_gb"]
            wekaver = weka_status["release"]

        except:
            print(f"Unable to communicate via API with {clusterspec}. Assuming it's not a weka cluster...")
            workers.append(WorkerServer(clusterspec,sshconfig))
        else:
            if args.use_servers_flag:
                for wekahost in wekacluster.hosts.list:  # rats - not a list - a curicular_list :(
                    workers.append(WorkerServer(wekahost.name, sshconfig))
            if args.use_clients_flag:
                for client in get_clients(wekacluster):
                    workers.append(WorkerServer(client, sshconfig))

        weka = True
    else:
        # it's a list of hosts...
        for host in args.servers:
            workers.append(WorkerServer(host, sshconfig))

        weka = False

    # workers should be a list of servers we can ssh to
    if len(workers) == 0:
        print("no servers to work with?")
        sys.exit(1)

    # open ssh sessions to the servers
    parallel(workers, WorkerServer.open)

    print()

    # gather some info about the servers
    parallel(workers, WorkerServer.gather_facts)


    # Display some info about the workers
    arch_list = list()
    archcount = dict()
    for server in workers:
        if server.cpu_info not in arch_list:
            arch_list.append(server.cpu_info)
            archcount[arch_list.index(server.cpu_info)] = 1
        else:
            archcount[arch_list.index(server.cpu_info)] += 1
        print(f"{server.hostname} is running {server.os_info['PRETTY_NAME'][1:-1]}")

    for index in range(0,len(arch_list)):
        print(f"{archcount[index]} workers with {arch_list[index]['Model name']} cpus, {arch_list[index]['CPU(s)']} cores")


    if weka:
        print("This cluster has " + format_units_bytes(weka_status["capacity"]["total_bytes"]) +
                " of capacity and " + format_units_bytes(weka_status["capacity"]["unprovisioned_bytes"]) +
                " of unprovisioned capacity")

    # for server in workers:
    #     server.file_exists("/tmp/fio")
    pdsh(workers, 'date')
    for server in workers:
        print(f"{server.hostname}: {server.last_response()}")

    parallel(workers, WorkerServer.file_exists, "/tmp/fio")
    for server in workers:
        print(f"{server.hostname}: {server.last_response()}")

    # vin - left off here
    sys.exit(1)

    # Get a list of filesystems to work on, create as needed
    weka_fs = run_json_shell_command('weka fs -J')

    # Is there an existing fs?
    wekatester_fs = False
    wekatester_group = False
    if type(weka_fs) == list:
        for fsconfig in weka_fs:  # do we already have a wekatester fs?
            if fsconfig["group_name"] == "wekatester-group":
                wekatester_group = True
            if fsconfig["name"] == "wekatester-fs":
                wekatester_fs = True
    else:
        for fsid, fsconfig in weka_fs.items():  # do we already have a wekatester fs?
            if fsconfig["group_name"] == "wekatester-group":
                wekatester_group = True
            if fsconfig["name"] == "wekatester-fs":
                wekatester_fs = True

    if wekatester_group == False:  # did we find the group when we looked for the fs?
        weka_fs_group = run_json_shell_command('weka fs group -J')

        if type(weka_fs_group) == list:
            for groupconfig in weka_fs_group:  # do we already have a wekatester fs group?
                if groupconfig["name"] == "wekatester-group":
                    wekatester_group = True
                    print("wekatester-group exists")
        else:
            for fsgroupid, groupconfig in weka_fs_group.items():  # do we already have a wekatester fs group?
                # print( "looking at " + fsgroupid + " " + groupconfig["name"] )
                if groupconfig["name"] == "wekatester-group":
                    wekatester_group = True
                    print("wekatester-group exists")

    # do we need to create one?
    if wekatester_group == False:
        print("Creating wekatester-group...")
        run_json_shell_command('weka fs group create wekatester-group -J')
    else:
        print("Using existing wekatester-group")

    if wekatester_fs == False:
        unprovisioned = weka_status["capacity"]["unprovisioned_bytes"] / 1024 / 1024 / 1024 / 1024
        if unprovisioned < 1:  # vince - for testing.  Should be about 5TB?
            print(sys.argv[0] + ": " + "Not enough unprovisioned capacity - please free at least 5TB of capacity")
            sys.exit(1)

        print("Creating wekatester-fs...")
        run_json_shell_command(
            'weka fs create wekatester-fs wekatester-group 5TB -J')  # vince - for testing.  Should be about 5TB?
    else:
        print("Using existing wekatester-fs")

    # make sure the wekatester fs is mounted locally - just in case we're running on a machine not part of the testing.

    print("Mount wekatester fs locally...")
    run_shell_command("sudo bash -c 'if [ ! -d /mnt/wekatester ]; then mkdir /mnt/wekatester; fi'")
    command = "mount | grep wekatester-fs"
    try:
        output = subprocess.check_output(command, shell=True)
    except subprocess.CalledProcessError as err:
        run_shell_command("sudo mount -t wekafs wekatester-fs /mnt/wekatester")
        run_shell_command("sudo chmod 777 /mnt/wekatester")

    # do a pushd so we know where we are
    with pushd(os.path.dirname(progname)):
        # make sure passwordless ssh works to all the servers because nothing will work if not set up
        announce("Opening ssh sessions to all servers\n")
        parallel_threads = {}
        for server in hostips:
            # create and start the threads
            parallel_threads[server] = threading.Thread(target=open_ssh_connection, args=(server,))
            parallel_threads[server].start()

        # wait for and reap threads
        time.sleep(0.1)
        while len(parallel_threads) > 0:
            dead_threads = {}
            for server, thread in parallel_threads.items():
                if not thread.is_alive():  # is it dead?
                    # print( "    Thread on " + server + " is dead, reaping" )
                    thread.join()  # reap it
                    dead_threads[server] = thread

            # remove it from the list so we don't try to reap it twice
            for server, thread in dead_threads.items():
                # print( "    removing " + server + "'s thread from list" )
                parallel_threads.pop(server)

            # sleep a little so we limit cpu use
            time.sleep(0.1)

        # print( ssh_sessions )
        if len(ssh_sessions) == 0:
            print("Error opening ssh sessions")
            sys.exit(1)
        for server, session in ssh_sessions.items():
            if session == None:
                print("Error opening ssh session to " + server)

        print()

        # mount filesystems
        announce("Mounting wekatester-fs on hosts:")
        for host, session in ssh_sessions.items():
            s = session.session()

            retcode = s.run("sudo bash -c 'if [ ! -d /mnt/wekatester ]; then mkdir /mnt/wekatester; fi'")
            if retcode[0] == 1:
                print("Error creating /mnt/wekatester on node " + host)
            retcode = s.run("mount | grep wekatester-fs", retcode=None)
            if retcode[0] == 1:
                # not mounted
                announce(host)
                s.run("sudo mount -t wekafs wekatester-fs /mnt/wekatester")
                s.run("sudo chmod 777 /mnt/wekatester")
            # else:
            #    print( "wekatester-fs already mounted on host " + host )

        print()

        # do we need to build fio?
        if not os.path.exists("fio/fio"):
            with pushd("fio"):
                print("Building fio")
                run_shell_command('./configure')
                run_shell_command('make')

        # do we need to copy fio onto the fs?
        if not os.path.exists("/mnt/wekatester/fio"):
            run_shell_command('cp ./fio/fio /mnt/wekatester/fio; chmod 777 /mnt/wekatester/fio')

        # don't need to copy the fio scripts - we can run them in place

        # start fio --server on all servers
        # for host, s in sorted(host_session.items()):    # make sure it's dead
        for host, session in ssh_sessions.items():
            s = session.session()
            s.run("kill -9 `cat /tmp/fio.pid`", retcode=None)
            s.run("rm -f /tmp/fio.pid", retcode=None)

        time.sleep(1)

        announce("starting fio --server on hosts:")
        # for host, s in sorted(host_session.items()):
        for host, session in ssh_sessions.items():
            s = session.session()
            announce(host)
            s.run("kill -9 `cat /tmp/fio.pid`", retcode=None)
            s.run("rm -f /tmp/fio.pid", retcode=None)
            # s.run( "pkill fio", retcode=None )
            s.run("/mnt/wekatester/fio --server --alloc-size=1048576 --daemonize=/tmp/fio.pid")

        print()
        time.sleep(1)

        # get a list of script files
        fio_scripts = [f for f in glob.glob("./fio-jobfiles/[0-9]*")]
        fio_scripts.sort()

        print("setup complete.")
        print()
        print("Starting tests on " + str(hostcount) + " weka hosts")
        print("On " + numcpu + " cores of " + cpuname + " per host")  # assuming they're all the same... )

        saved_results = {}  # save the results
        for script in fio_scripts:
            # check for comments in the job file, telling us what to output.  Keywords are "report", "bandwidth", "latency", and "iops".
            # example: "# report latency bandwidth"  or "# report iops"
            # can appear anywhere in the job file.  Can be multiple lines.
            reportitem = {"bandwidth": False, "latency": False, "iops": False}  # reset to all off
            with open(script) as jobfile:
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
                                if not keyword in reportitem.keys():
                                    print("Syntax error in # report directive in " + script + ", line " + str(
                                        lineno + 1) + ": keyword '" + keyword + "' undefined. Ignored.")
                                else:
                                    reportitem[keyword] = True

            if not reportitem["bandwidth"] and not reportitem["iops"] and not reportitem["latency"]:
                print("NOTE: No valid # report specification in " + script + "; reporting all")
                reportitem = {"bandwidth": True, "latency": True, "iops": True}  # set to all

            # build the arguments
            script_args = ""
            for host in hostips:
                script_args = script_args + " --client=" + host + " " + script

            print()
            print("starting fio script " + script)
            fio_output = run_json_shell_command('./fio/fio' + script_args + " --output-format=json")

            # print( json.dumps(fio_output, indent=8, sort_keys=True) )
            # print( fio_output )

            jobs = fio_output["client_stats"]
            # print(f"number of jobs = {len(jobs)}")
            # ok, number of jobs - we always get job results, plus aggregate results.  If more than 1 job (such as
            # pre-create + work jobs, there will be 3 or more - we really only want the last "job" and not the aggregate for
            # this name and description
            index = len(jobs) - 2
            print("Job is " + jobs[index]["jobname"] + " " + jobs[index]["desc"])

            bw = {}
            iops = {}
            latency = {}

            # ok, it's a hack, but we're really only interested in the last one - the aggregate
            stats = jobs[len(jobs) - 1]
            saved_results[os.path.basename(script)] = stats  # save for output file
            bw["read"] = stats["read"]["bw_bytes"]
            bw["write"] = stats["write"]["bw_bytes"]
            iops["read"] = stats["read"]["iops"]
            iops["write"] = stats["write"]["iops"]
            latency["read"] = stats["read"]["lat_ns"]["mean"]
            latency["write"] = stats["write"]["lat_ns"]["mean"]

            if reportitem["bandwidth"]:
                print("    read bandwidth: " + format_units_bytes(bw["read"]) + "/s")
                print("    write bandwidth: " + format_units_bytes(bw["write"]) + "/s")
                print("    total bandwidth: " + format_units_bytes(bw["read"] + bw["write"]) + "/s")
                print("    avg bandwidth: " + format_units_bytes(
                    float(bw["read"] + bw["write"]) / float(hostcount)) + "/s per host")
            if reportitem["iops"]:
                reads = int(iops["read"])
                writes = int(iops["write"])
                print(f"    read iops: {reads:,}/s")
                print(f"    write iops: {writes:,}/s")
                print(f"    total iops: {reads + writes:,}/s")
                print(f"    avg iops: {int((reads + writes) / hostcount):,}/s per host")
            if reportitem["latency"]:
                print("    read latency: " + format_units_ns(float(latency["read"])))
                print("    write latency: " + format_units_ns(float(latency["write"])))
                if (latency["read"] > 0.0) and (latency["write"] > 0.0):
                    print("    avg latency: " + format_units_ns(float(latency["write"] + latency["read"] / 2)))

        print()
        print("Tests complete.")

        if args.use_output_flag:
            timestring = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
            fp = open(f"results_{timestring}.json", "a+")  # Vin - add date/time to file name
            fp.write(json.dumps(saved_results, indent=4, sort_keys=True))
            fp.write("\n")
            fp.close()

        print()
        announce("killing fio slaves:")

        for host, session in ssh_sessions.items():
            s = session.session()
            # for host, s in host_session.items():
            announce(host)
            # s.run( "pkill fio" )
            s.run("kill -9 `cat /tmp/fio.pid`")
            s.run("rm -f /tmp/fio.pid")

        print()
        time.sleep(1)

        announce("Unmounting filesystems:")
        for host, session in ssh_sessions.items():
            s = session.session()
            # for host, s in host_session.items():
            announce(host)
            s.run("sudo umount /mnt/wekatester")

        print()
