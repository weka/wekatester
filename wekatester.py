#!/usr/bin/env python3

import json
import decimal
import argparse
import glob
import os, sys, stat
import logging
import subprocess
import time
from subprocess import Popen, PIPE, STDOUT
from shutil import copyfile
from contextlib import contextmanager
import threading
from threading import Lock
import datetime


"""A Python context to move in and out of directories"""
@contextmanager
def pushd(new_dir):
    previous_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)

# print( something without a newline )
announce_lock = Lock()
def announce( text ):
    with announce_lock:
        sys.stdout.flush()
        sys.stdout.write(text + " ")

# format a number of bytes in GiB/MiB/KiB 
def format_units_bytes( bytes ):
    if bytes > 1024*1024*1024*1024:
        units = "TiB"
        value = float( bytes )/1024/1024/1024/1024
    elif bytes > 1024*1024*1024:
        units = "GiB"
        value = float( bytes )/1024/1024/1024
    elif bytes > 1024*1024:
        units = "MiB"
        value = float( bytes )/1024/1024
    elif bytes > 1024:
        units = "KiB"
        value = float( bytes )/1024
    else:
        units = "bytes"
        value = bytes
        return "%d %s" % (int(value), units)

    return "%0.2f %s" % (value, units)


# format a number of bytes in GiB/MiB/KiB 
def format_units_ns( nanosecs ):
    if nanosecs > 1000*1000*1000:
        units = "s"
        value = float( nanosecs/1000/1000/1000 )
    elif nanosecs > 1000*1000:
        units = "ms"
        value = float( nanosecs/1000/1000 )
    elif nanosecs > 1000:
        units = "us"
        value = float( nanosecs/1000 )
    else:
        units = "nanosecs"
        value = nanosecs
        return "%d %s" % (int(value), units)

    return "%0.2f %s" % (value, units)

# run a command via the shell, expect json output and return it.
def run_json_shell_command( command ):
    #print( command )
    tmpvar = json.loads( run_shell_command( command ) )
    #print( tmpvar )
    return tmpvar
    #return json.loads( run_shell_command( command ) )[0]	# py3 version returns a list of dicts, instead of a dict, so add [0]

# run a command via the shell, check return code, exit on error.
def run_shell_command( command ):
    try:
        output = subprocess.check_output( command, shell=True )
    except subprocess.CalledProcessError as err:
        print( sys.argv[0] + ": " + str( err ) )
        sys.exit(1)

    return output


ssh_sessions={}
def open_ssh_connection( server ):
    global ssh_sessions
    try:
        sys.path.insert( 1, os.getcwd() + "/plumbum-1.6.8" )
        from plumbum import SshMachine, colors
        connection = SshMachine( server )  # open an ssh session
        s = connection.session()
        ssh_sessions[server] = connection      # save the sessions
        announce(server)
    except:
        traceback.print_exc(file=sys.stdout)
        announce( "Error ssh'ing to server " + server )
        announce( "Passwordless ssh not configured properly, exiting" )
        ssh_sessions[server] = None
        return -1

#host_session = {}
#ssh_token = {}
#def open_ssh_session(host):
#    rem = SshMachine( host )  # open an ssh session
#    ssh_token[host] = rem
#    host_session[host] = rem.session()
#    announce( host )

# parse arguments
progname=sys.argv[0]
parser = argparse.ArgumentParser(description='Acceptance Test a weka cluster')
#parser.add_argument('servers', metavar='servername', type=str, nargs='+',
#                    help='Server Dataplane IPs to execute on')
parser.add_argument("-c", "--clients", dest='use_clients_flag', action='store_true', help="run fio on weka clients")
parser.add_argument("-s", "--servers", dest='use_servers_flag', action='store_true', help="run fio on weka servers")
#parser.add_argument("-a", "--al", dest='use_all_flag', action='store_true', help="run fio on weka servers and clients")
parser.add_argument("-o", "--output", dest='use_output_flag', action='store_true', help="run fio with output")

#parser.add_argument("-v", "--verbose", dest='verbose_flag', action='store_true', help="enable verbose mode")

args = parser.parse_args()

#if args.use_clients_flag and args.use_servers_flag:
#    print( "Error: you must specify either clients or servers, not both" )
#    sys.exit(1)

# default to servers
use_all = False
if not args.use_clients_flag and not args.use_servers_flag: # neither flag
    args.use_servers_flag = True
elif args.use_clients_flag and args.use_servers_flag:   # both flags
    use_all = True


# Make sure weka is installed
weka_status = run_json_shell_command( 'weka status -J' )

print( "Testing Weka cluster " + weka_status["name"] )
print( run_shell_command( "date" ).decode("utf-8") )
print( "Cluster is v" + weka_status["release"] )

if weka_status["io_status"] != "STARTED":
    print( "Weka not healthy - not started." )
    sys.exit()

if weka_status["is_cluster"] != True:
    print( "Weka not healthy - cluster not formed?" )
    sys.exit()

# inserted to capture the number of servers
#hostcount = weka_status["hosts"]["active_count"]
drivecount = weka_status["drives"]["active"]
nettype = weka_status["net"]["link_layer"]
clustdrivecap = weka_status["licensing"]["usage"]["drive_capacity_gb"]
clustobjcap = weka_status["licensing"]["usage"]["obs_capacity_gb"]
wekaver = weka_status["release"]

# get cpu information
#lscpu_out = run_json_shell_command( 'lscpu -J' )

#for attrs in lscpu_out["lscpu"]:  # list of dicts, each with 2 entries, "field" and "data"
#    if attrs["field"] == "Model name:":
#        cpuname = attrs["data"]
#    elif attrs["field"] == "CPU(s):":
#        numcpu = attrs["data"]
cpu_attrs = {}
temp_bytes = run_shell_command( 'lscpu' )
#print( temp_bytes )
#print( lscpu_out.split("\n") )
lscpu_out = temp_bytes.decode('utf-8')
#print( lscpu_out )
for line in lscpu_out.split("\n"):
    line_list = line.split(":")
    if len( line_list[0] ) >= 1:    # there's a blank line at the end?
        cpu_attrs[line_list[0]] = line_list[1].strip()

cpuname = cpu_attrs["Model name"]
numcpu = cpu_attrs["CPU(s)"]
#print( cpu_attrs )
    


# get a list of server nodes
#all_hosts = run_json_shell_command( 'weka cluster host -J' )
#weka_hosts = {}
#if type ( all_hosts ) == list:
#    for hostconfig in all_hosts:
#        hostid = hostconfig["host_id"]
#        if hostconfig["cores"] != hostconfig["frontend_dedicated_cores"]:
#        # must be a server - not all FEs
#        weka_hosts[hostid] = hostconfig
#else:
#    for hostid, hostconfig in all_hosts.items():
#        if hostconfig["cores"] != hostconfig["frontend_dedicated_cores"]:
#        # must be a server - not all FEs
#        weka_hosts[hostid] = hostconfig

if use_all:
    print( "Using weka clients and servers to generate load (dedicated and converged mode)" )
    all_hosts = run_json_shell_command( 'weka cluster host -J' )    # all hosts
elif args.use_servers_flag:
    print( "Using weka servers to generate load (converged mode)" )
    all_hosts = run_json_shell_command( 'weka cluster host -b -J' )    # just the backends
else:
    print( "Using weka clients to generate load (dedicated mode)" )
    all_hosts = run_json_shell_command( 'weka cluster host -c -J' )    # just the clients

    
weka_hosts = {}
if type ( all_hosts ) == list:
    for hostconfig in all_hosts:
        hostid = hostconfig["host_id"]
        weka_hosts[hostid] = hostconfig
else:
    for hostid, hostconfig in all_hosts.items():
        weka_hosts[hostid] = hostconfig


hostcount = len( weka_hosts )
hostips = []
#print( "Hosts detected:" )
for hostid, hostconfig in sorted( weka_hosts.items() ):
    #print( "HostId: " + hostid )
    hostips.append( hostconfig["host_ip"] )  # create a list of host ips that we'll mount the fs and run fio on

hostips.sort()
print( str( len( hostips ) ) + " weka hosts detected" )



print( "This cluster has " + str(round((weka_status["capacity"]["total_bytes"]/1024/1024/1024/1024),1)) + " TB of capacity and " + \
    str(round((weka_status["capacity"]["unprovisioned_bytes"]/1024/1024/1024/1024 ),1)) + " TB of unprovisioned capacity" )

# Get a list of filesystems to work on, create as needed
weka_fs = run_json_shell_command( 'weka fs -J' )

#print( json.dumps(weka_fs, indent=8, sort_keys=True) )

# Is there an existing fs?
wekatester_fs = False
wekatester_group = False
if type ( weka_fs ) == list:
    for fsconfig in weka_fs:    # do we already have a wekatester fs?
        #print( "Looking at " + fsid )
        #print( fsconfig["group_name"] )
        if fsconfig["group_name"] == "wekatester-group":
            wekatester_group = True
        if fsconfig["name"] == "wekatester-fs":
            wekatester_fs = True
else:
    for fsid, fsconfig in weka_fs.items():    # do we already have a wekatester fs?
        #print( "Looking at " + fsid )
        #print( fsconfig["group_name"] )
        if fsconfig["group_name"] == "wekatester-group":
            wekatester_group = True
        if fsconfig["name"] == "wekatester-fs":
            wekatester_fs = True

if wekatester_group == False:   # did we find the group when we looked for the fs?
    weka_fs_group = run_json_shell_command( 'weka fs group -J' )

    if type ( weka_fs_group ) == list:
        for groupconfig in weka_fs_group:    # do we already have a wekatester fs group?
            #print( "looking at " + fsgroupid + " " + groupconfig["name"] )
            if groupconfig["name"] == "wekatester-group":
                wekatester_group = True
                print( "wekatester-group exists" )
    else:
        for fsgroupid, groupconfig in weka_fs_group.items():    # do we already have a wekatester fs group?
            #print( "looking at " + fsgroupid + " " + groupconfig["name"] )
            if groupconfig["name"] == "wekatester-group":
                wekatester_group = True
                print( "wekatester-group exists" )


# do we need to create one?
if wekatester_group == False:
    print( "Creating wekatester-group..." )
    run_json_shell_command( 'weka fs group create wekatester-group -J' )
else:
    print( "Using existing wekatester-group" )

if wekatester_fs == False:
    unprovisioned = weka_status["capacity"]["unprovisioned_bytes"]/1024/1024/1024/1024
    if unprovisioned < 1:        # vince - for testing.  Should be about 5TB?
        print( sys.argv[0] + ": " + "Not enough unprovisioned capacity - please free at least 5TB of capacity" )
        sys.exit(1)

    print( "Creating wekatester-fs..." )
    run_json_shell_command( 'weka fs create wekatester-fs wekatester-group 5TB -J' )    # vince - for testing.  Should be about 5TB?
else:
    print( "Using existing wekatester-fs" )

# make sure the wekatester fs is mounted locally - just in case we're running on a machine not part of the testing.

print( "Mount wekatester fs locally..." )
run_shell_command( "sudo bash -c 'if [ ! -d /mnt/wekatester ]; then mkdir /mnt/wekatester; fi'" )
command="mount | grep wekatester-fs"
try:
    output = subprocess.check_output( command, shell=True )
except subprocess.CalledProcessError as err:
    run_shell_command( "sudo mount -t wekafs wekatester-fs /mnt/wekatester" )
    run_shell_command( "sudo chmod 777 /mnt/wekatester" )

# setup phase complete... now we get to work
#        uname = ssh_token[host]["uname"]
#        print( uname )
#        output = (uname)("-a")
#        print( output )
#        sys.exit()

# do a pushd so we know where we are
with pushd( os.path.dirname( progname ) ):
    # make sure passwordless ssh works to all the servers because nothing will work if not set up
    announce( "Opening ssh sessions to all servers\n" )
    parallel_threads={}
    for server in hostips:
        # create and start the threads
        parallel_threads[server] = threading.Thread( target=open_ssh_connection, args=(server,) )
        parallel_threads[server].start()

    # wait for and reap threads
    time.sleep( 0.1 )
    #print( "parallel_threads = " + str( len( parallel_threads ) ) )
    while len( parallel_threads ) > 0:
        #print( "parallel_threads = " + str( len( parallel_threads ) ) )
        dead_threads = {}
        for server, thread in parallel_threads.items():
            if not thread.is_alive():   # is it dead?
                #print( "    Thread on " + server + " is dead, reaping" )
                thread.join()       # reap it
                dead_threads[server] = thread

        #print( "dead_threads = " + str( dead_threads ) )
        # remove it from the list so we don't try to reap it twice
        for server, thread in dead_threads.items():
            #print( "    removing " + server + "'s thread from list" )
            parallel_threads.pop( server )

        # sleep a little so we limit cpu use
        time.sleep( 0.1 )

        #ret = open_ssh_connection( server )
        #if ret == -1:
        #    sys.exit( 1 )

    #print( ssh_sessions )
    if len( ssh_sessions ) == 0:
        print( "Error opening ssh sessions" )
        sys.exit( 1 )
    for server, session in ssh_sessions.items():
        if session == None:
            print( "Error opening ssh session to " + server )

    # use our own version of plumbum - Ubuntu is broken. (one line change from orig plumbum... /bin/sh changed to /bin/bash
    # this works for both ubuntu and centos
    #sys.path.insert( 1, os.getcwd() + "/plumbum-1.6.8" )
    #from plumbum import SshMachine, colors

    # open ssh sessions to all the hosts
    #run_shell_command( "sudo bash -c 'if [ ! -d /mnt/wekatester/weka_fio_out ]; then mkdir /mnt/wekatester/weka_fio_out; fi'" )
    #run_shell_command( "sudo chmod 777 /mnt/wekatester/weka_fio_out" )
    #announce( "Opening ssh session to hosts:" )
    #for host in hostips:
    #    try:
    #        #open_ssh_session(host)
    #        rem = SshMachine( host )  # open an ssh session
    #        ssh_token[host] = rem
    #        host_session[host] = rem.session()
    #        announce( host )
    #    except:
    #        print()
    #        print( "Error opening ssh session - have you configured passwordless ssh?" )
    #        sys.exit( 1 )

    print()

    # mount filesystems
    announce( "Mounting wekatester-fs on hosts:" )
    for host, session in ssh_sessions.items():
        s = session.session()
    #for host, s in sorted(host_session.items()):
        #print( "Check that /mnt/wekatester mountpoint dir is present on host " + host )

        retcode = s.run( "sudo bash -c 'if [ ! -d /mnt/wekatester ]; then mkdir /mnt/wekatester; fi'" )
        if retcode[0] == 1:
            print( "Error creating /mnt/wekatester on node " + host )
        retcode = s.run( "mount | grep wekatester-fs", retcode=None )
        if retcode[0] == 1:
            # not mounted
            announce( host )
            s.run( "sudo mount -t wekafs wekatester-fs /mnt/wekatester" )
            s.run( "sudo chmod 777 /mnt/wekatester" )
        #else:
        #    print( "wekatester-fs already mounted on host " + host )

    print()
        
    # do we need to build fio?
    if not os.path.exists( "./fio/fio" ):
        with pushd( "./fio" ):
            print( "Building fio" )
            run_shell_command( './configure' )
            run_shell_command( 'make' )

    # do we need to copy fio onto the fs?
    if not os.path.exists( "/mnt/wekatester/fio" ):
        run_shell_command( 'cp ./fio/fio /mnt/wekatester/fio; chmod 777 /mnt/wekatester/fio' )

    # don't need to copy the fio scripts - we can run them in place

    # start fio --server on all servers
    #for host, s in sorted(host_session.items()):    # make sure it's dead
    for host, session in ssh_sessions.items():
        s = session.session()
        s.run( "kill -9 `cat /tmp/fio.pid`", retcode=None )
        s.run( "rm -f /tmp/fio.pid", retcode=None )

    time.sleep( 1 )

    announce( "starting fio --server on hosts:" )
    #for host, s in sorted(host_session.items()):
    for host, session in ssh_sessions.items():
        s = session.session()
        announce( host )
        s.run( "kill -9 `cat /tmp/fio.pid`", retcode=None )
        s.run( "rm -f /tmp/fio.pid", retcode=None )
        #s.run( "pkill fio", retcode=None )
        s.run( "/mnt/wekatester/fio --server --alloc-size=1048576 --daemonize=/tmp/fio.pid" )

    print()
    time.sleep( 1 )

    # get a list of script files
    fio_scripts = [f for f in glob.glob( "./fio-jobfiles/[0-9]*")]
    fio_scripts.sort()

    print( "setup complete." )
    print()
    print( "Starting tests on " + str(hostcount) + " weka hosts" )
    print( "On " + numcpu + " cores of " + cpuname + " per host" )  # assuming they're all the same... )

    saved_results = {}    # save the results
    for script in fio_scripts:
        # check for comments in the job file, telling us what to output.  Keywords are "report", "bandwidth", "latency", and "iops".
        # example: "# report latency bandwidth"  or "# report iops"
        # can appear anywhere in the job file.  Can be multiple lines.
        reportitem = { "bandwidth":False, "latency":False, "iops":False }  # reset to all off
        with open( script ) as jobfile:
            for lineno, line in enumerate( jobfile ):
                line.strip()
                linelist = line.split()
                if len(linelist) > 0:
                    if linelist[0][0] == "#":         # first char is '#'
                        if linelist[0] == "#report":
                            linelist.pop(0) # get rid of the "#report"
                        elif len( linelist ) < 2:
                            continue        # blank comment line?
                        elif linelist[1] == "report":      # we're interested
                            linelist.pop(0) # get rid of the "#"
                            linelist.pop(0) # get rid of the "report"
                        else:
                            continue

                        # found a "# report" directive in the file
                        for keyword in linelist:
                            if not keyword in reportitem.keys():
                                print( "Syntax error in # report directive in " + script + ", line " + str( lineno +1 ) + ": keyword '" + keyword + "' undefined. Ignored." )
                            else:
                                reportitem[keyword] = True


        if not reportitem["bandwidth"] and not reportitem["iops"] and not reportitem["latency"]:
            print( "NOTE: No valid # report specification in " + script + "; reporting all" )
            reportitem = { "bandwidth":True, "latency":True, "iops":True }  # set to all


        # build the arguments
        script_args = ""
        for host in hostips:
            script_args = script_args + " --client=" + host + " " + script

        print()
        print( "starting fio script " + script )
        fio_output = run_json_shell_command( './fio/fio' + script_args + " --output-format=json" )

       # print( json.dumps(fio_output, indent=8, sort_keys=True) )
        #print( fio_output )

        jobs = fio_output["client_stats"]
        print(f"number of jobs = {len(jobs)}")
        # ok, number of jobs - we always get job results, plus aggregate results.  If more than 1 job (such as 
        # pre-create + work jobs, there will be 3 or more - we really only want the last "job" and not the aggregate for
        # this name and description
        index = len(jobs) -2
        print( "Job is " + jobs[index]["jobname"] + " " + jobs[index]["desc"] )

        # gather interesting stats so we don't have to hunt for them later
        #for stats in jobs:
        #    bw_bytes.append( stats["read"]["bw_bytes"] )
        #    iops.append( stats["read"]["iops"] )
        #    latency.append( stats["read"]["lat_ns"]["mean"] )

        bw={}
        iops={}
        latency={}

        # ok, it's a hack, but we're really only interested in the last one - the aggregate
        stats = jobs[len(jobs) -1]
        saved_results[script] = stats   # save for output file
        bw["read"] = stats["read"]["bw_bytes"]
        bw["write"] = stats["write"]["bw_bytes"]
        iops["read"] = stats["read"]["iops"]
        iops["write"] = stats["write"]["iops"]
        latency["read"] = stats["read"]["lat_ns"]["mean"]
        latency["write"] = stats["write"]["lat_ns"]["mean"]

        if reportitem["bandwidth"]:
            print( "    read bandwidth: " + format_units_bytes( bw["read"] ) + "/s" )
            print( "    write bandwidth: " + format_units_bytes( bw["write"] ) + "/s" )
            print( "    total bandwidth: " + format_units_bytes( bw["read"] + bw["write"] ) + "/s" )
            print( "    avg bandwidth: " + format_units_bytes( float( bw["read"] + bw["write"] )/float( hostcount) ) + "/s per host" )
        if reportitem["iops"]:
            reads = int(iops["read"])
            writes = int(iops["write"])
            print(f"    read iops: {reads:,}/s" )
            print(f"    write iops: {writes:,}/s" )
            print(f"    total iops: {reads+writes:,}/s" )
            print(f"    avg iops: {int((reads+writes)/hostcount):,}/s per host" )
        if reportitem["latency"]:
            print( "    read latency: " +  format_units_ns( float( latency["read"] ) ) )
            print( "    write latency: " +  format_units_ns( float( latency["write"] ) ) )
            if (latency["read"] > 0.0) and (latency["write"] > 0.0):
                print( "    avg latency: " +  format_units_ns( float( latency["write"] + latency["read"] / 2 ) ) )


    print()
    print( "Tests complete." )

    if args.use_output_flag:
        #timestring = datetime.datetime.now().isoformat()
        timestring = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
        fp = open(f"fio_results_{timestring}.json", "a+" )          # Vin - add date/time to file name
        fp.write( json.dumps(saved_results, indent=4, sort_keys=True) )
        fp.write( "\n" )
        fp.close()

    print()
    announce( "killing fio slaves:" )

    for host, session in ssh_sessions.items():
        s = session.session()
    #for host, s in host_session.items():
        announce( host )
        #s.run( "pkill fio" )
        s.run( "kill -9 `cat /tmp/fio.pid`" )
        s.run( "rm -f /tmp/fio.pid" )

    print()
    time.sleep( 1 )

    announce( "Unmounting filesystems:" )
    for host, session in ssh_sessions.items():
        s = session.session()
    #for host, s in host_session.items():
        announce( host )
        s.run( "sudo umount /mnt/wekatester" )


    print()
    #print( "Unmount fs locally" )
    #try:
    #    run_shell_command( "sudo umount /mnt/wekatester" )
    #except:
    #    print( "FS is not mounted locally" )
    #print()
