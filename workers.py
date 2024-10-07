#import os
from logging import getLogger

#from wekapyutils.wekassh import parallel, RemoteServer

#import getpass

#import paramiko
#from paramiko import SSHClient, AutoAddPolicy, SSHConfig
#from scp import SCPClient

#from wekalib.sthreads import threaded, default_threader

log = getLogger(__name__)

def start_fio_servers(servers, fio_bin='/tmp/fio'):

    for server in servers:
        server.run_unending(fio_bin + " --server")


#def pdsh(servers, command):
#    parallel(servers, RemoteServer.run, command)


#def pscp(servers, source, dest):
#    log.debug(f"setting up parallel copy to {servers}")
#    parallel(servers, RemoteServer.scp, source, dest)


def get_workers(wekacluster, workertype):
    if workertype not in ["backend","client"]:
        raise Exception("invalid workertype - must be 'backend' or 'client'")

    workerlist = list()

    try:
        api_return = wekacluster.call_api(method="hosts_list", parms={})
    except:
        raise

    for host in api_return.values():
        hostname = host["hostname"]
        if host["mode"] == workertype:
            if host["state"] == "ACTIVE" and host["status"] == "UP":
                if hostname not in workerlist:
                    workerlist.append(hostname)

    return workerlist

def get_clients(wekacluster):
    clientlist = list()

    try:
        api_return = wekacluster.call_api(method="hosts_list", parms={})
    except:
        raise

    for host in api_return:
        hostname = host["hostname"]
        if host["mode"] == "client":
            if host["state"] == "ACTIVE" and host["status"] == "UP":
                clientlist.append(hostname)

    return clientlist
