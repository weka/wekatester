#!/usr/bin/env python3

import argparse
import datetime
import glob
import json
import logging
import logging.handlers
import os
import platform
import sys
import time
import socket
from contextlib import contextmanager

from urllib3 import add_stderr_logger

import fio
from fio import FioJobfile, format_units_bytes, FioResult
from wekalib.wekacluster import WekaCluster
from wekalib.signals import signal_handling

# import paramiko
from workers import WorkerServer, parallel, get_workers, start_fio_servers, pscp, SshConfig, FIO_BIN

import threading

VERSION = "2.1.5"

#FIO_BIN="/tmp/fio"
#FIO_BIN="/usr/bin/fio"

@contextmanager
def pushd(new_dir):
    """A Python context to move in and out of directories"""
    previous_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)


def configure_logging(logger, verbosity):
    loglevel = logging.INFO     # default logging level

    logging.basicConfig(filename='wekatester.log', encoding='utf-8', level=loglevel)

    # default message formats
    console_format = "%(message)s"
    #syslog_format =  "%(levelname)s:%(message)s"

    syslog_format =  "%(process)s:%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"

    if verbosity == 1:
        loglevel = logging.DEBUG
        console_format = "%(levelname)s:%(message)s"
        syslog_format =  "%(process)s:%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
    elif verbosity > 1:
        loglevel = logging.DEBUG
        console_format = "%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
        syslog_format =  "%(process)s:%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"

    # create handler to log to console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(console_format))
    logger.addHandler(console_handler)

    # create handler to log to syslog
    logger.info(f"setting syslog on {platform.platform()}")
    if platform.platform()[:5] == "macOS":
        syslogaddr = "/var/run/syslog"
    else:
        syslogaddr = "/dev/log"
    syslog_handler = logging.handlers.SysLogHandler(syslogaddr)
    syslog_handler.setFormatter(logging.Formatter(syslog_format))

    # add syslog handler to root logger
    if syslog_handler is not None:
        logger.addHandler(syslog_handler)

    # set default loglevel
    logger.setLevel(loglevel)

    logging.getLogger("wekalib.wekacluster").setLevel(loglevel)
    logging.getLogger("wekalib.wekaapi").setLevel(loglevel)
    logging.getLogger("wekalib.sthreads").setLevel(logging.ERROR)
    logging.getLogger("wekalib.circular").setLevel(logging.ERROR)

    # local modules
    logging.getLogger("workers").setLevel(loglevel)
    logging.getLogger("fio").setLevel(loglevel)

    logging.getLogger("paramiko").setLevel(logging.ERROR)

def graceful_exit(workers):
    for server in workers:
        server.close()  # terminates fio --server commands


def main():

    # parse arguments
    progname = sys.argv[0]
    parser = argparse.ArgumentParser(description='Acceptance Test a weka cluster')
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="increase output verbosity")
    parser.add_argument("-c", "--clients", dest='use_clients_flag', action='store_true',
                        help="run fio on weka clients")
    parser.add_argument("-s", "--servers", dest='use_servers_flag', action='store_true',
                        help="run fio on weka servers")
    parser.add_argument("-d", "--directory", dest='directory', default="/mnt/weka",
                        help="target directory for workload (default is /mnt/weka)")
    parser.add_argument("-w", "--workload", dest='workload', default="default",
                        help="workload definition directory (a subdir of fio-jobfiles)")
    parser.add_argument("-o", "--output", dest='use_output_flag', action='store_true', help="run fio with output file")
    parser.add_argument("-a", "--autotune", dest='autotune', action='store_true',
                        help="automatically tune num_jobs to maximize performance (experimental)")
    parser.add_argument("--no-weka", dest='no_weka', action='store_true', default=False,
                        help="force non-weka mode")
    parser.add_argument("--local-fio", dest='local_fio', action='store_true', default=False,
                        help="Use the fio binary on the target servers")
    parser.add_argument("--auth", dest='authfile', default="auth-token.json",
                        help="auth file for authenticating with weka (default is auth-token.json)")
    parser.add_argument('serverlist', metavar="server", type=str, nargs='*', default=['localhost'], #dest='serverlist', 
                        help='One or more Servers to use a workers (weka mode [default] will get names from the cluster)')
    parser.add_argument("--version", dest="version", default=False, action="store_true", help="Display version number")

    args = parser.parse_args()

    if args.version:
        print(f"{sys.argv[0]} version {VERSION}")
        sys.exit(0)

    # set the root logger
    log = logging.getLogger()
    configure_logging(log, args.verbosity)

#    root = logging.getLogger()
#    root.setLevel(logging.DEBUG)
#    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
#    logging.getLogger("paramiko").setLevel(logging.DEBUG)

    # load our ssh configuration
    sshconfig = SshConfig()

    # Figure out if we were given a weka clusterspec or a list of servers...
    use_all = False
    servers = args.serverlist
    #if not args.use_clients_flag and not args.use_servers_flag and len(args.servers) == 1:  # neither flag
    #    args.use_servers_flag = True
    #elif args.use_clients_flag and args.use_servers_flag:  # both flags
    #    use_all = True

    # initialize the list of workers
    workers = list()

    # make sure we close all connections and kill all threads upon ^c or something
    signal_handling(graceful_exit, workers)

    if args.local_fio:
        FIO_BIN = "/usr/bin/fio"
    else:
        FIO_BIN = "/tmp/fio"

    if not args.no_weka:
        log.info(f"Probing for a weka cluster... {args.serverlist}/{args.authfile}")
        try:
            # try to create a weka cluster object.  If this fails, assume it's just a single server
            wekacluster = WekaCluster(args.serverlist, authfile=args.authfile)
            log.info("Found Weka cluster " + wekacluster.name)

            weka_status = wekacluster.call_api(method="status", parms={})

            if weka_status["io_status"] != "STARTED":
                log.critical("Weka Cluster is not healthy - not started.")
                sys.exit()
            if not weka_status["is_cluster"]:
                log.critical("Weka Cluster is not healthy - cluster not formed?")
                sys.exit()

            log.info("Cluster is v" + wekacluster.release)

            # Take some notes
            drivecount = weka_status["drives"]["active"]
            nettype = weka_status["net"]["link_layer"]
            clustdrivecap = weka_status["licensing"]["usage"]["drive_capacity_gb"]
            clustobjcap = weka_status["licensing"]["usage"]["obs_capacity_gb"]
            wekaver = weka_status["release"]

        except Exception as exc:
            log.info(f"Unable to communicate via API with {args.serverlist} - {exc}. If this is not a Weka Cluster, use --no-weka")
            sys.exit(1)
            #workers.append(WorkerServer(args.servers[0], sshconfig))
        else:
            # workers = list()    # re-init workers so we don't duplicate a host
            if args.use_clients_flag and args.use_servers_flag:
                workerlist = get_workers(wekacluster, "backend")
                workerlist += get_workers(wekacluster, "client")
            elif args.use_servers_flag:
                workerlist = get_workers(wekacluster, "backend")
            elif args.use_clients_flag:
                workerlist = get_workers(wekacluster, "client")
            else:
                log.info("No worker type specified, assuming backends")
                workerlist = get_workers(wekacluster, "backend")

            for worker in workerlist:
                workers.append(WorkerServer(worker, sshconfig))

            weka = True
    else:
        # it's a list of hosts...
        log.info("No-Weka Mode selected.  Contacting servers...")
        for host in args.serverlist:
            workers.append(WorkerServer(host, sshconfig))

        weka = False

    # workers should be a list of servers we can ssh to
    if len(workers) == 0:
        log.critical("No servers to work with?")
        sys.exit(1)

    # open ssh sessions to the servers - should puke if any of the open's fail.
    parallel(workers, WorkerServer.open)

    errors = False
    for server in workers:
        if server.ssh is None:
            log.critical(f"Failed to establish ssh session to {server.hostname}")
            errors = True
    if errors:
        log.critical("SSH Errors encountered, exiting")
        sys.exit(1)


    # gather some info about the servers
    log.info("Gathering Facts on servers")
    parallel(workers, WorkerServer.gather_facts, weka)

    if weka:
        abort = False
        for server in workers:
            if not server.weka_mounted:
                log.critical(f"Error: server {server.hostname} does not have a weka filesystem mounted!")
                abort = True
        if abort:
            sys.exit(1)

    # Display some info about the workers, organize things
    arch_list = list()
    archcount = dict()
    sorted_workers = dict()
    oslist = dict()
    for server in workers:
        #log.debug(f"{server.cpu_info}")
        cpu_info = f"{server.cpu_info['Model name']} cpus, {server.cpu_info['CPU(s)']} cores"
        if cpu_info not in archcount:
            archcount[cpu_info] = 1
        else:
            archcount[cpu_info] += 1
        server_os = server.os_info['PRETTY_NAME'].strip('\n')

        log.debug(f"{server.hostname} is running {server_os}")
        if server_os not in oslist:
            oslist[server_os] = [server.hostname]
        else:
            oslist[server_os].append(server.hostname)

        # sort servers into groups with the same number of cores
        workingcores = server.usable_cpus
        if workingcores not in sorted_workers:
            sorted_workers[workingcores] = list()
        sorted_workers[workingcores].append(server)

    for server_os, _servers in oslist.items():
        log.info(f"Servers running {server_os}: {' '.join(servername for servername in _servers)}")

    for arch, count in archcount.items():
        log.info(f"{count} workers with {arch}")

    if weka:
        log.info("This cluster has " + format_units_bytes(weka_status["capacity"]["total_bytes"]) +
                     " of capacity and " + format_units_bytes(weka_status["capacity"]["unprovisioned_bytes"]) +
                     " of unprovisioned capacity")

    log.info("checking if fio is present on the workers...")
    parallel(workers, WorkerServer.file_exists, FIO_BIN)
    needs_fio = list()
    for server in workers:
        log.debug(f"{server.hostname}: {server.last_response()}")
        if server.last_response() == 'False':
            needs_fio.append(server)

    if len(needs_fio) > 0:
        log.info("Copying fio to any servers that need it...")
        pscp(needs_fio, os.path.dirname(progname) + '/fio', FIO_BIN)

        # print()
        parallel(workers, WorkerServer.file_exists, FIO_BIN)

    need_to_exit = False
    for server in workers:
        if server.last_response() != "True":
            log.error(f"{server.hostname}: fio copy did not complete; is present: {server.last_response()}")
            server.close()
            need_to_exit = True
    if need_to_exit:
        sys.exit(1)

    log.info("starting fio servers")
    start_fio_servers(workers, FIO_BIN)

    # get a list of script files
    fio_scripts = [f for f in glob.glob(os.path.dirname(progname) + f"/fio-jobfiles/{args.workload}/[0-9]*")]
    fio_scripts.sort()
    log.debug(f"There are {len(fio_scripts)} scripts in the {args.workload} directory")

    saved_results = {}  # save the results
    jobs = list()
    for script in fio_scripts:
        jobs.append(FioJobfile(script))

    try:
        os.mkdir('/tmp/fio-jobfiles', 0o777)
    except:
        pass

    # copy jobfiles to /tmp, and edit them
    server_count = 0
    for num_cores, serverlist in sorted_workers.items():
        with open(f'/tmp/fio-jobfiles/{num_cores}', "w") as f:
            for server in serverlist:
                f.write(str(server) + "\n")
                server_count += 1
        for job in jobs:
            if args.autotune:
                job.override('numjobs', str(num_cores * 2), nolower=True)
            job.override('directory', args.directory)
            job.write(f'/tmp/fio-jobfiles/{num_cores}.{os.path.basename(job.filename)}')

    # copy the jobfiles to the server that will run the tests
    master_server = workers[0]  # use the first server in the list to run the workload
    try:
        master_server.scp('/tmp/fio-jobfiles', '/tmp')
    except Exception as exc:
        log.error(f"Error copying jobfiles to {master_server}: {exc}")
        sys.exit(1)

    fio_results = dict()
    for job in jobs:
        jobname = os.path.basename(job.filename)
        log.debug(job.reportitem)
        # cmdline = f"{os.path.dirname(progname)}/fio --output-format=json "  # if running locally
        cmdline = FIO_BIN + " --output-format=json "  # if running remotely
        for server in workers:
            cmdline += \
                f"--client={socket.gethostbyname(str(server))} /tmp/fio-jobfiles/{server.usable_cpus}.{jobname} "

        #for num_cores, serverlist in sorted_workers.items():
        #    cmdline += \
        #        f"--client=/tmp/fio-jobfiles/{num_cores} /tmp/fio-jobfiles/{num_cores}.{jobname} "   # multiple --client=<file> doesn't work
        log.info(f"starting test run for job {jobname} on {master_server.hostname} with {server_count} workers:")
        log.debug(f"running on {master_server.hostname}: {cmdline}")
        master_server.run(cmdline)
        # fio_output[jobname] = master_server.last_response()

        # log.debug(master_server.last_response()) # makes logger puke - message too long
        if master_server.last_error() != "":
            log.error(f"Error running fio on {master_server.hostname}: {master_server.last_error()}")
            sys.exit(1)
        try:
            fio_results[jobname] = FioResult(job, master_server.last_response())
            fio_results[jobname].summarize()
        except:
            log.error(f"Error parsing fio output - output was: {master_server.last_response()}")

    time.sleep(1)

    # output log file
    if args.use_output_flag:
        output_dict = dict()
        timestring = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
        for name, result in fio_results.items():
            output_dict[name] = result.fio_output

        with open(f"results_{timestring}.json", "a+") as fp:  # Vin - add date/time to file name
            json.dump(output_dict, fp, indent=2)

    graceful_exit(workers)

if __name__ == '__main__':
    main()
