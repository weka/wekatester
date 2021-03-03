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
from contextlib import contextmanager

from urllib3 import add_stderr_logger

import fio
from fio import FioJobfile, format_units_bytes, FioResult
from wekalib.wekacluster import WekaCluster

# import paramiko
from workers import WorkerServer, parallel, get_clients, start_fio_servers, pscp, SshConfig


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

    # default message formats
    console_format = "%(message)s"
    syslog_format =  "%(levelname)s:%(message)s"

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
    console_handler = logging.StreamHandler()
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

    logging.getLogger("wekalib.wekacluster").setLevel(logging.ERROR)
    logging.getLogger("wekalib.wekaapi").setLevel(logging.ERROR)
    logging.getLogger("wekalib.sthreads").setLevel(logging.ERROR)
    logging.getLogger("wekalib.circular").setLevel(logging.ERROR)

    # paramiko.util.log_to_file("demo.log")
    add_stderr_logger(level=logging.ERROR)  # for paramiko
    logging.getLogger("paramiko").setLevel(logging.ERROR)


if __name__ == '__main__':

    # parse arguments
    progname = sys.argv[0]
    parser = argparse.ArgumentParser(description='Acceptance Test a weka cluster')
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="increase output verbosity")
    parser.add_argument("-c", "--clients", dest='use_clients_flag', action='store_true',
                        help="run fio on weka clients")
    parser.add_argument("-s", "--servers", dest='use_servers_flag', action='store_true',
                        help="run fio on weka servers")
    parser.add_argument("-d", "--directory", dest='directory', default="/mnt/weka",
                        help="target directory for workload")
    parser.add_argument("-w", "--workload", dest='workload', default="default",
                        help="workload definition directory (a subdir of fio-jobfiles)")
    parser.add_argument("-o", "--output", dest='use_output_flag', action='store_true', help="run fio with output file")
    parser.add_argument("-a", "--autotune", dest='autotune', action='store_true',
                        help="automatically tune num_jobs to maximize performance (experimental)")
    parser.add_argument('servers', metavar='servername', type=str, nargs='*', default=['localhost'],
                        help='Weka clusterspec or Server Dataplane IPs to execute on')

    args = parser.parse_args()

    # set the root logger
    log = logging.getLogger()
    configure_logging(log, args.verbosity)

    # load our ssh configuration
    sshconfig = SshConfig()

    # Figure out if we were given a weka clusterspec or a list of servers...
    use_all = False
    if not args.use_clients_flag and not args.use_servers_flag and len(args.servers) == 1:  # neither flag
        servers = ["localhost"]
        args.use_servers_flag = True
    elif args.use_clients_flag and args.use_servers_flag:  # both flags
        use_all = True

    # initialize the list of workers
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
            # try to create a weka cluster object.  If this fails, assume it's just a single server
            log.info("Probing for a weka cluster...")
            wekacluster = WekaCluster(clusterspec, authfile=auth)
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

        except:
            log.info(f"Unable to communicate via API with {clusterspec}. Assuming it's not a weka cluster...")
            workers.append(WorkerServer(args.servers[0], sshconfig))
        else:
            workers = list()    # re-init workers so we don't duplicate a host
            if args.use_servers_flag:
                log.debug(f"workers={workers}, weka hosts: {wekacluster.hosts.list}")
                for wekahost in wekacluster.hosts.list:  # rats - not a list - a curicular_list :(
                    workers.append(WorkerServer(wekahost.name, sshconfig))
            if args.use_clients_flag:
                for client in get_clients(wekacluster):
                    workers.append(WorkerServer(client, sshconfig))

        weka = True
    else:
        # it's a list of hosts...
        log.info("Non-Weka Mode selected.  Contacting servers...")
        for host in args.servers:
            workers.append(WorkerServer(host, sshconfig))

        weka = False

    # workers should be a list of servers we can ssh to
    if len(workers) == 0:
        log.critical("No servers to work with?")
        sys.exit(1)

    # open ssh sessions to the servers
    parallel(workers, WorkerServer.open)

    # print()

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
        if server.cpu_info not in arch_list:
            arch_list.append(server.cpu_info)
            archcount[arch_list.index(server.cpu_info)] = 1
        else:
            archcount[arch_list.index(server.cpu_info)] += 1
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

    for index in range(0, len(arch_list)):
        log.info(
            f"{archcount[index]} workers with {arch_list[index]['Model name']} cpus, {arch_list[index]['CPU(s)']} cores")

    if weka:
        log.info("This cluster has " + format_units_bytes(weka_status["capacity"]["total_bytes"]) +
                     " of capacity and " + format_units_bytes(weka_status["capacity"]["unprovisioned_bytes"]) +
                     " of unprovisioned capacity")

    log.info("checking if fio is present on the workers...")
    parallel(workers, WorkerServer.file_exists, "/tmp/fio")
    needs_fio = list()
    for server in workers:
        log.debug(f"{server.hostname}: {server.last_response()}")
        if server.last_response() == 'False':
            needs_fio.append(server)

    if len(needs_fio) > 0:
        log.info("Copying fio to any servers that need it...")
        pscp(needs_fio, os.path.dirname(progname) + '/fio', '/tmp/fio')

        # print()
        parallel(workers, WorkerServer.file_exists, "/tmp/fio")

    need_to_exit = False
    for server in workers:
        if server.last_response() != "True":
            log.error(f"{server.hostname}: fio copy did not complete; is present: {server.last_response()}")
            server.close()
            need_to_exit = True
    if need_to_exit:
        sys.exit(1)

    log.info("starting fio servers")
    start_fio_servers(workers)
    #time.sleep(1)
    #log.debug(f"{default_threader.num_active()} running")

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
    master_server.scp('/tmp/fio-jobfiles', '/tmp')

    fio_results = dict()
    for job in jobs:
        jobname = os.path.basename(job.filename)
        log.debug(job.reportitem)
        # cmdline = f"{os.path.dirname(progname)}/fio --output-format=json "  # if running locally
        cmdline = "/tmp/fio --output-format=json "  # if running remotely
        for num_cores, serverlist in sorted_workers.items():
            cmdline += \
                f"--client=/tmp/fio-jobfiles/{num_cores} /tmp/fio-jobfiles/{num_cores}.{jobname} "
        log.info(f"starting test run for job {jobname} on {master_server.hostname} with {server_count} workers:")
        log.debug(f"running on {master_server.hostname}: {cmdline}")
        master_server.run(cmdline)
        # fio_output[jobname] = master_server.last_response()

        # log.debug(master_server.last_response()) # makes logger puke - message too long
        fio_results[jobname] = FioResult(job, master_server.last_response())
        fio_results[jobname].summarize()

    time.sleep(1)
    # vin - left off here
    for server in workers:
        server.close()  # terminates fio --server commands

    # output log file
    if args.use_output_flag:
        output_dict = dict()
        timestring = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
        for name, result in fio_results.items():
            output_dict[name] = result.fio_output

        with open(f"results_{timestring}.json", "a+") as fp:  # Vin - add date/time to file name
            json.dump(output_dict, fp, indent=2)

        #     if len(fio_results) > 1:
        #         fp.write('[\n')
        #     for result in fio_results:
        #         fp.write(result.dumps())
        #         fp.write("\n")
