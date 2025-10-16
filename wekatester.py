#!/usr/bin/env python3

import argparse
import datetime
import glob
import json
import logging
import logging.handlers
import os
#import platform
import sys
import time
import socket
from contextlib import contextmanager

#from urllib3 import add_stderr_logger
from wekapyutils.wekalogging import configure_logging, register_module

#import fio
from fio import FioJobfile, format_units_bytes, FioResult
from wekalib.wekacluster import WekaCluster
from wekalib.signals import signal_handling

# import paramiko
#from workers import WorkerServer, parallel, get_workers, start_fio_servers, pscp, SshConfig
from wekapyutils.wekassh import RemoteServer, pscp, parallel

from workers import start_fio_servers, get_workers

#import threading

VERSION = "2025-10-16"

FIO_BIN=None

STAGING_DIR="/tmp/staging"
JOBFILE_DIR="fio-jobfiles"
TARGET_DIR="/tmp/" + JOBFILE_DIR

@contextmanager
def pushd(new_dir):
    """A Python context to move in and out of directories"""
    previous_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)


def graceful_exit(workers):
    for server in workers:
        server.close()  # terminates fio --server commands


def main():

    # parse arguments
    progname = sys.argv[0]
    parser = argparse.ArgumentParser(description='Basic Performance Test a Network/Parallel Filesystem')
    parser.add_argument("-d", "--directory", dest='directory', default="/mnt/weka",
                        help="target directory on the workers for test files")
    parser.add_argument("-w", "--workload", dest='workload', default="default",
                        help="workload definition directory (a subdir of fio-jobfiles)")
    parser.add_argument("--fio-bin", dest='local_fio', default='/usr/bin/fio',
                        help="Specify the fio binary on the target servers (default /usr/bin/fio)")
    parser.add_argument('serverlist', metavar="server", type=str, nargs='*',
                        help='One or more Servers to use a workers')
    parser.add_argument("-V", "--version", dest="version", default=False, action="store_true", help="Display version number")
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="increase output verbosity")

    args = parser.parse_args()

    if args.version:
        print(f"{sys.argv[0]} version {VERSION}")
        sys.exit(0)

    # set the root logger
    log = logging.getLogger()
    register_module("fabric", logging.ERROR)
    register_module("paramiko", logging.ERROR)
    configure_logging(log, args.verbosity)

    if args.directory is None:
        log.error("You must specify a target directory using '-d'")
        sys.exit(1)

    if len(args.serverlist) == 0:
        log.error("You must specify some servers on the command line")
        sys.exit(1)

    # initialize the list of workers
    workers = list()

    # make sure we close all connections and kill all threads upon ^c or something
    signal_handling(graceful_exit, workers)

    FIO_BIN = args.local_fio

    log.info("Contacting worker servers...")
    for host in args.serverlist:
        workers.append(RemoteServer(host))


    # workers should be a list of servers we can ssh to
    if len(workers) == 0:
        log.critical("Unable to contact any worker servers? Please check your ssh configuration")
        sys.exit(1)

    # open ssh sessions to the servers - should puke if any of the open's fail.
    parallel(workers, RemoteServer.connect)

    errors = False
    for server in workers:
        if not server.connected:
            log.critical(f"Failed to establish ssh session to {str(server)}")
            errors = True
        #else:
        #    log.info(f"We appear to have connected to {str(server)}")
    if errors:
        log.critical("SSH Errors encountered, exiting")
        sys.exit(1)


    # Display some info about the workers, organize things
    sorted_workers = dict()
    log.info("checking if fio is present on the workers...")
    parallel(workers, RemoteServer.file_exists, FIO_BIN)
    needs_fio = list()
    for server in workers:
        log.debug(f"{str(server)}: {server.last_response()}")
        if server.last_response().strip('\n') == 'False':
            needs_fio.append(server)

    if len(needs_fio) > 0:
        log.info(f"Some servers do not have {FIO_BIN} installed.  Please install it and re-run.")
        log.info(f"Servers that need fio: {needs_fio}")
        sys.exit(1)

    log.info("starting fio servers")
    start_fio_servers(workers, FIO_BIN)

    # get a list of script files - start with the directory the wekatester binary is in...
    fio_scripts = [f for f in glob.glob(os.path.dirname(progname) + f"/{JOBFILE_DIR}/{args.workload}/[0-9]*")]
    # if nothing there, try the current directory
    if len(fio_scripts) == 0:
        fio_scripts = [f for f in glob.glob(f"./{JOBFILE_DIR}/{args.workload}/[0-9]*")]
    # if nothing in the current directory, complain and exit
    if len(fio_scripts) == 0:
        log.error(f"Unable to locate the fio-jobfiles directory.")
        sys.exit(1)
    fio_scripts.sort()
    log.info(f"There are {len(fio_scripts)} scripts in the {args.workload} directory")

    saved_results = {}  # save the results
    jobs = list()
    for script in fio_scripts:
        jobs.append(FioJobfile(script))

    try:
        os.mkdir(STAGING_DIR, 0o777)
    except:
        pass

    # copy jobfiles to /tmp, and edit them
    #server_count = 0
    master_server = workers[0]  # use the first server in the list to run the workload
    try:

        master_server.run(f'mkdir -p {TARGET_DIR}')  # jobfile dir
        # work around a quirk in 'fabric' - the scp zeros any existing file before copying, so if we're copying
        # from/to the same server, it zeros all the files.   So stage it somewhere else, then copy.
        #with open(f'{STAGING_DIR}/workers', "w") as f:
        #    for server in workers:
        #        f.write(str(server) + "\n")
        #        server_count += 1
        #master_server.scp(f'{STAGING_DIR}/workers', TARGET_DIR)
        for job in jobs:
            job.override('directory', args.directory)
            job.write(f'{STAGING_DIR}/{os.path.basename(job.filename)}')
            master_server.scp(f'{STAGING_DIR}/{os.path.basename(job.filename)}', TARGET_DIR)

    except Exception as exc:
        log.error(f"Error copying jobfiles to {master_server}: {exc}")
        sys.exit(1)

    fio_results = dict()
    for job in jobs:
        jobname = os.path.basename(job.filename)
        log.debug(job.reportitem)
        cmdline = FIO_BIN + " --output-format=json "  # if running remotely
        for server in workers:
            cmdline += \
                f"--client={str(server)} {TARGET_DIR}/{jobname} "
                #f"--client={socket.gethostbyname(str(server))} /tmp/fio-jobfiles/{jobname} "

        # wait a little to make sure the fio servers are ready...
        time.sleep(3)

        log.info(f"starting test run for job {jobname} on {str(master_server)} with {len(workers)} workers:")
        log.debug(f"running on {str(master_server)}: {cmdline}")
        master_server.run(cmdline)

        # log.debug(master_server.last_response()) # makes logger puke - message too long
        if master_server.output.status != 0:
            log.error(f"Error running fio on {str(master_server)}:")
            print(f"stderr:{master_server.output.stderr}")
            print(f"stdout:{master_server.output.stdout}")
            sys.exit(1)
        try:
            fio_results[jobname] = FioResult(job, master_server.last_response())
            fio_results[jobname].summarize()
        except Exception as exc:
            log.error(f"Error parsing fio output: {exc}")
            print(f"stderr:{master_server.output.stderr}")
            print(f"stdout:{master_server.output.stdout}")

    time.sleep(1)

    graceful_exit(workers)

    # output log file
    outfile = f"results_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M')}.json"
    log.info(f"Writing raw fio results to {outfile}")

    output_dict = dict()
    for name, result in fio_results.items():
        output_dict[name] = result.fio_output

    with open(outfile, "a+") as fp:
        json.dump(output_dict, fp, indent=2)

if __name__ == '__main__':
    main()
