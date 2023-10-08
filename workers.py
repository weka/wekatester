import os
from logging import getLogger
import getpass

import paramiko
from paramiko import SSHClient, AutoAddPolicy, SSHConfig
from scp import SCPClient

from wekalib.sthreads import threaded, default_threader

log = getLogger(__name__)


class SshConfig:
    def __init__(self):
        self.config = SSHConfig()
        self.config_file = True

        # handle missing config file
        try:
            fp = open(os.path.expanduser('~/.ssh/config'))
        except IOError:
            self.config_file = False
        else:
            try:
                self.config.parse(fp)
            except Exception as exc:    # malformed config file?
                log.critical(exc)
                raise

    def lookup(self, hostname):
        return self.config.lookup(hostname) # if self.config_file else None


# Connection class to perform SSH commands on remote server
class WorkerServer:
    def __init__(self, hostname, sshconfig):
        self.hostname = hostname
        self.ssh = None
        self.ssh_config = sshconfig

    def open(self):
        kwargs = dict()
        self.ssh = SSHClient()
        self.hostconfig = self.ssh_config.lookup(self.hostname)
        self.ssh.set_missing_host_key_policy(AutoAddPolicy())

        if "user" in self.hostconfig:
            kwargs["username"] = self.hostconfig["user"]
        else:
            kwargs["username"] = getpass.getuser()

        self.ssh.load_system_host_keys()
        if "identityfile" in self.hostconfig:
            kwargs["key_filename"] = self.hostconfig["identityfile"]
        else:
            kwargs["key_filename"] = None
            kwargs["look_for_keys"] = True # actually the default...

        try:

            self.ssh.connect(self.hostname,**kwargs)
        except paramiko.ssh_exception.AuthenticationException as exc:
            log.critical(f"Authentication error opening ssh session to {self.hostname}: {exc}")
            self.ssh = None
        except Exception as exc:
            log.critical(f"Exception opening ssh session to {self.hostname}: {exc}")
            self.ssh = None

    def close(self):
        if self.ssh:
            self.end_unending()     # kills the fio --server process
            self.ssh.close()

    def scp(self, source, dest):
        log.info(f"copying {source} to {self.hostname}")
        with SCPClient(self.ssh.get_transport()) as scp:
            scp.put(source, recursive=True, remote_path=dest)

    def run(self, cmd):
        status = None
        response = None
        error = None
        try:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            status = stdout.channel.recv_exit_status()
            response = stdout.read().decode("utf-8")
            error = stderr.read().decode("utf-8")
            temp_list = error.split('\n')
            error_list = list()
            for line in temp_list:
                if len(line) > 0 and line.find("setaffinity") == -1: # ignore blank lines and setaffinity errors
                    error_list.append(line + '\n')
            error = ''.join(error_list)
            self.last_output = {'status': status, 'response': response, 'error': error, "exc": None}
            if status != 0:
                log.error(f"run: Bad return code from {cmd}: {status}.  Output is:")
                if len(response) > 0 and len(response) < 5000:
                    log.error(f"stdout is '{response}'")
                if len(error) > 0 and len(error) < 5000:
                    log.error(f"stderr is '{error}'")
            else:
                log.debug(f"run: '{cmd}', status {status}, stdout {len(response)} bytes, stderr {len(error)} bytes")
        except Exception as exc:
            log.error(f"run: '{cmd}', status {status}, stdout {len(response)} bytes, stderr {len(error)} bytes, exception='{exc}'")
            if len(response) > 0 and len(response) < 5000:
                log.error(f"stdout is '{response}'")
            if len(error) > 0 and len(error) < 5000:
                log.error(f"stderr is '{error}'")
            self.last_output = {'status': status, 'response': response, 'error': error, "exc": exc}


    def _linux_to_dict(self, separator):
        output = dict()
        if self.last_output['status'] != 0:
            log.debug(f"last output = {self.last_output}")
            raise Exception
        lines = self.last_output['response'].split('\n')
        for line in lines:
            if len(line) != 0:
                line_split = line.split(separator)
                if len(line_split) == 2:
                    output[line_split[0].strip()] = line_split[1].strip()
        return output

    def _count_cpus(self):
        """ count up the cpus; 0,1-4,7,etc """
        num_cores = 0
        cpulist = self.last_output['response'].strip(' \n').split(',')
        for item in cpulist:
            if '-' in item:
                parts = item.split('-')
                num_cores += int(parts[1]) - int(parts[0]) + 1
            else:
                num_cores += 1
        return num_cores

    def gather_facts(self, weka):
        """ build a dict from the output of lscpu """
        self.cpu_info = dict()
        self.run("lscpu")

        # cpuinfo = self.last_output['response']
        self.cpu_info = self._linux_to_dict(':')

        self.run("cat /etc/os-release")
        self.os_info = self._linux_to_dict('=')

        self.run("cat /sys/fs/cgroup/cpuset/system/cpuset.cpus")
        self.usable_cpus = self._count_cpus()

        if weka:
            self.run('mount | grep wekafs')
            log.debug(f"{self.last_output}")
            if len(self.last_output['response']) == 0:
                log.debug(f"{self.hostname} does not have a weka filesystem mounted.")
                self.weka_mounted = False
            else:
                self.weka_mounted = True

    def file_exists(self, path):
        """ see if a file exists on another server """
        log.debug(f"checking for presence of file {path} on server {self.hostname}")
        self.run(f"if [ -f '{path}' ]; then echo 'True'; else echo 'False'; fi")
        strippedstr = self.last_output['response'].strip(' \n')
        log.debug(f"server responded with {strippedstr}")
        if strippedstr == "True":
            return True
        else:
            return False

    def last_response(self):
        return self.last_output['response'].strip(' \n')

    def last_error(self):
        return self.last_output['error']

    def __str__(self):
        return self.hostname

    def run_unending(self, command):
        """ run a command that never ends - needs to be terminated by ^c or something """
        transport = self.ssh.get_transport()
        self.unending_session = transport.open_session()
        self.unending_session.setblocking(0) # Set to non-blocking mode
        self.unending_session.get_pty()
        self.unending_session.invoke_shell()
        self.unending_session.command = command

        # Send command
        log.debug(f"starting daemon {self.unending_session.command}")
        self.unending_session.send(command + '\n')

    def end_unending(self):
        log.debug(f"terminating daemon {self.unending_session.command}")
        self.unending_session.send(chr(3)) # send a ^C
        self.unending_session.close()

@threaded
def threaded_method(instance, method, *args, **kwargs):
    """ makes ANY method of ANY class threaded """
    method(instance, *args, **kwargs)


def parallel(obj_list, method, *args, **kwargs):
    for instance in obj_list:
        threaded_method(instance, method, *args, **kwargs)
    default_threader.run()  # wait for them



def start_fio_servers(servers, fio_bin='/tmp/fio'):

    for server in servers:
        server.run_unending(fio_bin + " --server")


def pdsh(servers, command):
    parallel(servers, WorkerServer.run, command)


def pscp(servers, source, dest):
    log.debug(f"setting up parallel copy to {servers}")
    parallel(servers, WorkerServer.scp, source, dest)


def get_workers(wekacluster, workertype):
    if workertype not in ["backend","client"]:
        raise Exception("invalid workertype - must be 'backend' or 'client'")

    workerlist = list()

    try:
        api_return = wekacluster.call_api(method="hosts_list", parms={})
    except:
        raise

    for host in api_return:
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
