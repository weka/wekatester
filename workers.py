import os
from logging import getLogger
import getpass

from paramiko import SSHClient, AutoAddPolicy, SSHConfig
from scp import SCPClient

from wekalib.sthreads import threaded, default_threader

log = getLogger(__name__)


class SshConfig:
    def __init__(self):
        self.config = SSHConfig()
        try:
            self.config.parse(open(os.path.expanduser('~/.ssh/config')))
            # ssh_config.parse()

        except Exception as exc:
            log.critical(exc)
            raise

    def lookup(self, hostname):
        return self.config.lookup(hostname)


# Connection class to perform SSH commands on remote server
class WorkerServer:
    def __init__(self, hostname, sshconfig):
        self.hostname = hostname
        self.ssh = None
        self.ssh_config = sshconfig

    def open(self):
        self.ssh = SSHClient()
        self.config = self.ssh_config.lookup(self.hostname)
        self.ssh.set_missing_host_key_policy(AutoAddPolicy())

        if "user" in self.config:
            user = self.config["user"]
        else:
            user = getpass.getuser()

        try:
            self.ssh.connect(self.hostname, username=user, key_filename=self.config["identityfile"],
                             timeout=10, auth_timeout=10)
        except Exception as exc:
            log.critical(f"Exception opening ssh session: {exc}")
            raise

    def close(self):
        if self.ssh:
            self.ssh.close()
        # if self.scp:
        #     self.scp.close()

    def scp(self, source, dest):
        log.info(f"copying {source} to {self.hostname}")
        with SCPClient(self.ssh.get_transport()) as scp:
            scp.put(source, recursive=True, remote_path=dest)

    def run(self, cmd):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)  # , get_pty=True)
            status = stdout.channel.recv_exit_status()
            response = stdout.read().decode("utf-8")
            error = stderr.read().decode("utf-8")
            log.debug(f"run: stdout {len(response)} bytes, stderr {len(error)} bytes")
            self.last_output = {'status': status, 'response': response, 'error': error}
        except Exception as exc:
            self.last_output = {'status': -123,
                                'description': 'Failed to run command',
                                'traceback': str(exc)}
        # log.debug(f"output is: {self.last_output}") # makes logger puke

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

    def __str__(self):
        return self.hostname


@threaded
def threaded_method(instance, method, *args, **kwargs):
    """ makes ANY method of ANY class threaded """
    method(instance, *args, **kwargs)


def parallel(obj_list, method, *args, **kwargs):
    for instance in obj_list:
        threaded_method(instance, method, *args, **kwargs)
    default_threader.run()  # wait for them


def start_fio_servers(servers):
    for server in servers:
        threaded_method(server, WorkerServer.run, "/tmp/fio --output-format=json --server")
    default_threader.starter()


def pdsh(servers, command):
    parallel(servers, WorkerServer.run, command)


def pscp(servers, source, dest):
    log.debug(f"setting up parallel copy to {servers}")
    parallel(servers, WorkerServer.scp, source, dest)


def get_clients(wekacluster):
    # get the rest of the cluster (bring back any that had previously disappeared, or have been added)
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
