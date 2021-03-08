# wekatester
Performance test weka clusters with distributed fio

Includes fio both consistency (versions vary) and convienience. 


```
usage: wekatester [-h] [-v] [-c] [-s] [-d DIRECTORY] [-w WORKLOAD] [-o] [-a]
                  [servername [servername ...]]

Acceptance Test a weka cluster

positional arguments:
  servername            Weka clusterspec or Server Dataplane IPs to execute on

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbosity       increase output verbosity
  -c, --clients         run fio on weka clients
  -s, --servers         run fio on weka servers
  -d DIRECTORY, --directory DIRECTORY
                        target directory for workload
  -w WORKLOAD, --workload WORKLOAD
                        workload definition directory (a subdir of fio-
                        jobfiles)
  -o, --output          run fio with output file
  -a, --autotune        automatically tune num_jobs to maximize performance
                        (experimental)
```                        

# Basics
fio is a benchmark for IO, and is quite popular.  However, running it in a distributed fashion across multiple servers can be a bit of a bear to manage, and the output can be quite difficult to read.

The idea of wekatester is to bring some order to this chaos.   To make running fio in a distributed environment, wekatester automatically distributes and executes fio commands on remote servers, runs a standard set of benchmark workloads, and summarizes the results.  It's also aware of Weka clusters, in particular.

# Options
Clusterspec/Servers - you can list a set of servers (ie: non-weka mode) that will run the workload as workers.   Optionally, you can give a weka 'clusterspec' and it will use the indicated weka cluster.

A Weka Clusterspec is in the form: `<server>,<server>,...,<server>:<authfile>` where <server> is a weka server (ie: weka1,weka2,weka3) and authfile is a ~/weka/auth-token.json file.   An example clusterspec would be "weka1,weka2,weka3" (uses default user/pass), or "weka1,weka2,weka3:~/.weka/auth-token.json" (uses token file from a previous login).

`-c` makes wekatester query the cluster for what clients exist and uses ALL of them as workers

`-s` makes wekatester query the cluster for what backends exist and uses ALL of them as workers

`-d DIRECTORY` sets the directory where the benchmark files will be created.  Default is /mnt/weka

`-w WORKLOAD` get fio jobfile specifications from a subdirectory of fio-jobfiles.   The default is 'default'.  Currently, there are 2 discributed with wekatester, "default" (4-corners tests), and "mixed", a set of 70/30 RW workloads.  You can add your own directories, and use the with -w.

`-o` will create an output file with all the fio output in it in JSON format.  This is useful for later analysis. (Analysis tools forthcoming)

`-a` automatically adjust numjobs= to 2x the number of available cores.  Works on all workloads.

`-v` Sets verbosity.  `-vv`, and `-vvv` are supported to set ever increasing verbosity.
