import sys
import subprocess
import os
import json
import re
import logging
import digitalocean
from .dokit import *
from datetime import datetime
from ruamel import yaml
from time import sleep

######## CONSTANTS #########################################
HEADER = "docluster -- IPython cluster tools for Digital Ocean infrastructure"
HELP_MESSAGE = """
Usage:

docluster [action] [option_1] [option_2] ... [option_n]

Actions:

- start [name] [--accept]:
    - Will look for corresponding config file [name].json and start cluster based on it

- setup [name]:
    - Will create a new cluster configuration based on filled questionnaire

- destroy [name] [--purge]:
    - Will destroy the cluster (destroy all the instances)
    - Options:
        --purge: will destroy the configuration file as well

- reconnect [name] [ipcontroller_engine_file]
    - Will reconnect cluster [name] to [ipcontroller_engine_file]
    - If [ipcontroller_engine_file] is empty, default will be used
        
- status [name]:
    - Will print status of the cluster

- addnode [name] [type] [count]:
    - Will add a [count] node(s) to [name] cluster, [count] defaults to 1

- rmnode [name] [type] [count]:
    - Will remove [count] node(s) of type [type] from [name] cluster, [count] defaults to 1
"""
MAX_CLUSTER_NAME_LEN = 15
DEFAULT_GENERAL_SETTINGS = """
# set this true to stop asking for confirmations
no_confirmations: False

# public part of the ssh keypair to use for ssh authentications (has to be a passwordless key)
public_sshkey: null

# private part of the ssh keypair to use for ssh authentications (has to be a passwordless key)
private_sshkey: null

# default image file to use when creating new nodes (string or id)
default_image: null

# default region to use when creating new clusters
default_region: null

# options: NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL
logging_level: INFO

logging_format: "%(asctime)s [%(levelname)s] %(message)s"

logging_dateformat: "%Y%m%d %H:%M:%S"
"""
######### GLOBAL VARIABLES #######################

# holder for global variables
g = Bunch()

######### EXCEPTIONS ##################

class ClusterAlreadyRunningException(Exception):
    pass

class ClusterDoesntExistException(Exception):
    pass

class EngineFileNotFoundException(Exception):
    pass

#########################################

def check_for_general_settings():
    general_settings_dir = os.path.join(g.docluster_dir, "general")
    general_settings_file = os.path.join(general_settings_dir, "settings.yaml")
    if not os.path.exists(general_settings_dir):
        os.makedirs(general_settings_dir)
    if not os.path.isfile(general_settings_file):
        with open(general_settings_file, 'w') as f:
            f.write(DEFAULT_GENERAL_SETTINGS)
    settings = yaml.load(open(general_settings_file), yaml.RoundTripLoader)
    return settings

def check_for_dokit_settings():
    dokit_settings_file = os.path.join(g.dokit_dir, "settings.yaml")
    if not os.path.isfile(dokit_settings_file):
        with open(dokit_settings_file, 'w') as f:
            f.write(DEFAULT_DOKIT_SETTINGS)
    settings = yaml.load(open(dokit_settings_file), yaml.RoundTripLoader)
    return settings

def get_valid_regions(print_info=True):
    if print_info:
        print("Retrieving list of regions...")
    regions = [x for x in g.do.get_all_regions() if x.available]
    regions = [x for x in regions if 'private_networking' in x.features]
    return sorted(regions, key=lambda x: x.slug)

def get_public_sshkey():
    print("Retrieving list of ssh-keys...")
    keys = g.do.get_all_sshkeys()
    if setting_is_valid(g.settings, 'public_sshkey'):
        key_ids = [x.id for x in keys]
        try:
            idx = key_ids.index(g.settings["public_sshkey"])
            key = keys[idx]
            print("Default public sshkey selected: {}".format(sshkey_to_str(key)))
            return key
        except ValueError:
            pass
    key = choose_from_list(keys, "Choose ssh-key:", sshkey_to_str)
    g.settings['public_sshkey'] = key.id
    save_general_settings()
    return key

def get_private_sshkey():
    if setting_is_valid(g.settings, 'private_sshkey'):
        if os.path.isfile(g.settings['private_sshkey']):
            return g.settings['private_sshkey']
    keyfile = ask_file("Path to private part of they sshkey: ") 
    g.settings['private_sshkey'] = keyfile
    save_general_settings()

def check_for_image():
    print("Retrieving list of images...")
    images = g.do.get_my_images()
    if setting_is_valid(g.settings, "default_image"):
        image_ids = [x.id for x in images]
        try:
            idx = image_ids.index(g.settings["default_image"])
            image = images[idx]
            print("Default image selected: {}".format(image_to_str(image)))
            return image
        except ValueError:
            pass
    #list_images = ask_yes_no("Do you want to see list of available image files?")
    #if list_images:
    return choose_from_list(images, "Choose image for nodes:", image_to_str)
    # else:
    #     while True:
    #         image = input("Image name or ID: ")
    #         try:
    #             image = int(image)
    #             matches = [x for x in images if x.id == image]
    #             if not matches:
    #                 print("Image with given ID not found")
    #                 continue
    #             assert len(matches) == 1
    #             image = matches[0]
    #             return image
    #         except ValueError:
    #             matches = [x for x in images if x.name.lower() == image.lower()]
    #             if not matches:
    #                 print("Image with given name not found")
    #                 continue
    #             assert len(matches) == 1
    #             image = matches[0]
    #             return image

def ask_for_instance():
    return choose_from_list(g.sizes, "Choose instance type for nodes:", instance_to_str)

def save_general_settings():
    general_settings_dir = os.path.join(g.docluster_dir, "general")
    general_settings_file = os.path.join(general_settings_dir, "settings.yaml")
    yaml.dump(g.settings, stream=open(general_settings_file, 'w'), Dumper=yaml.RoundTripDumper)

def save_dokit_settings():
    settings_file = os.path.join(g.dokit_dir, "settings.yaml")
    yaml.dump(g.dokit_settings, stream=open(settings_file, 'w'), Dumper=yaml.RoundTripDumper)

def ask_for_token():
    token = input("Digital Ocean token: ")
    print(token)
    if not re.fullmatch('[a-z0-9]+', token):
        print("Invalid token, only 0-9 and a-z allowed")
        ask_for_token()
        return
    if len(token) != 64:
        print("Token has to be 64 bytes long")
        ask_for_token()
        return
    g.dokit_settings['digitalocean_token'] = token
    save_dokit_settings()

def get_region(regions, instance):
    if not regions:
        regions = get_valid_regions()
    if setting_is_valid(g.settings, 'default_region'):
        reg_slugs = [x.slug for x in regions]
        try:
            idx = reg_slugs.index(g.settings["default_region"])
            region = reg_slugs[idx]
            print("Default region selected: {}".format(region_to_str(region)))
            return region
        except ValueError:
            pass
    while True:
        region = choose_from_list(regions, "Choose region:", region_to_str)
        if instance.slug not in region.sizes:
            print("{} doesn't support instance type {}, choose another region"
                  .format(region.slug, instance.slug))
            continue
        return region

def get_ipcontroller_engine_file():
    homedir = os.path.expanduser('~')
    if setting_is_valid(g.settings, 'default_ipcontroller_engine_file'):
        return g.settings['default_ipcontroller_engine_file']
    suggestion = os.path.join(homedir, '.ipython', 'profile_default', 'security',
                              'ipcontroller-engine.json')
    engfile = input("ipcontroller engine file [{}]: ".format(suggestion))
    if not engfile:
        engfile = suggestion
    return engfile

def get_ipengine_executable():
    if setting_is_valid(g.settings, 'default_ipengine_executable'):
        return g.settings['default_ipengine_executable']
    suggestion = "ipengine"
    executable = input("ipengine executable (on nodes) [{}]: ".format(suggestion))
    if not executable:
        executable = suggestion
    return executable

def get_ipcontroller_executable():
    if setting_is_valid(g.settings, 'default_ipcontroller_executable'):
        if os.path.isfile(g.settings['default_ipcontroller_executable']):
            return g.settings['default_ipcontroller_executable']
    suggestion = "ipcontroller"
    executable = ask_file("ipcontroller executable (on this machine):", suggestion,
                          include_syspath=True)
    if not executable:
        executable = suggestion
    return executable

def get_droplets():
    print("Retrieving list of running droplets...")
    return g.do.get_all_droplets()

def get_account_info():
    print("Retreving account information...")
    return g.do.get_account()

def calculate_cost(nodetuples, sizes):
    slug_to_vcpu = {x.slug: x.vcpus for x in sizes}
    slug_to_ram = {x.slug: x.memory / 1024 for x in sizes}
    slug_to_hourly = {x.slug: x.price_hourly for x in sizes}
    tot_vcpus = 0
    tot_ram = 0
    tot_hourly = 0
    n_nodes = 0
    for t in nodetuples:
        num_instances = t[0]
        slug = t[1]['instance']
        tot_vcpus += num_instances * slug_to_vcpu[slug]
        tot_ram += num_instances * slug_to_ram[slug]
        tot_hourly += num_instances * slug_to_hourly[slug]
        n_nodes += num_instances
    res = {
        'vcpus': tot_vcpus,
        'ram_per_vcpu': tot_ram / tot_vcpus,
        'hourly_rate': tot_hourly,
        'vcpus_usd_hour': tot_vcpus / tot_hourly,
        'n_nodes': n_nodes
    }
    return res

def create_cluster(name, stg):
    droplets = get_droplets()
    for droplet in droplets:
        clustername = droplet.name.split("-")[0].lower()
        if clustername.lower() == name.lower():
            raise ClusterAlreadyRunningException("Cluster '{}' already running".format(name))
    node_names = []
    for t in stg['nodes']:
        num_instances = t[0]
        instance = t[1]['instance']
        image = t[1]['image']
        for i in range(num_instances):
            d = digitalocean.Droplet()
            d.name = "{}-{}-{}".format(name, instance, str(i + 1).zfill(3))
            node_names.append(d.name)
            d.region = stg['region']
            d.size = instance
            d.image = image
            d.token = g.dokit_settings['digitalocean_token']
            d.ssh_keys = [g.settings['public_sshkey']]
            d.private_networking = True
            d.create()
    last_num_launched = 0
    print("Launching {} nodes...".format(len(node_names)))
    while True:
        droplets = g.do.get_all_droplets()
        droplet_names = [x.name for x in droplets if x.status == "active"]
        num_droplets_launched = len(set(node_names).intersection(droplet_names))
        if last_num_launched != num_droplets_launched:
            last_num_launched = num_droplets_launched
            print("{}/{} droplets launched".format(num_droplets_launched, len(node_names)))
        if num_droplets_launched == len(node_names):
            break
        sleep(10)

def setup_cluster(name):
    droplets = get_droplets()
    for droplet in droplets:
        clustername = droplet.name.split("-")[0].lower()
        if clustername.lower() == name.lower():
            raise ClusterAlreadyRunningException("Cluster '{}' already running".format(name))
    cluster_settings_file = os.path.join(g.docluster_dir, name + ".yaml")
    if os.path.isfile(cluster_settings_file):
        overwrite = ask_yes_no("settings for {} already exist, overwrite?")
        if not overwrite:
            return
    ipcontroller_engine_file = get_ipcontroller_engine_file()
    ipengine_executable = get_ipengine_executable()
    ipcontroller_executable = get_ipcontroller_executable()
    image = check_for_image()
    instance = ask_for_instance()
    regions = get_valid_regions()
    region = get_region(regions, instance)
    account = get_account_info()
    free_slots = account.droplet_limit - len(droplets)
    print("Maximum of {} droplets can be created".format(free_slots))
    num_nodes = ask_integer("Number of nodes:", (1, free_slots))
    stg = {}
    stg['ipengine_executable'] = ipengine_executable
    stg['ipcontroller_executable'] = ipcontroller_executable
    stg['ipcontroller_engine_file'] = ipcontroller_engine_file
    stg['region'] = region.slug
    nodespec = {'instance': instance.slug, 'image': image.id}
    stg['nodes'] = [[num_nodes, nodespec]]
    yaml.dump(stg, open(cluster_settings_file, 'w'))
    print("Cluster settings saved")

def initialize_ipcontroller(stg):
    executable = stg['ipcontroller_executable']
    exec_fn = executable.split('/')[-1]
    p = run_shell_process('ps -e | grep {}'.format(exec_fn))
    processes_found = p.stdout.readlines()
    if processes_found:
        print("{} is already running".format(exec_fn))
    else:
        print("Starting {}...".format(exec_fn))
        p = run_shell_process("setsid " + executable + " --ip='*' --log-to-file")
        sleep(5)
    if not os.path.isfile(stg['ipcontroller_engine_file']):
        raise EngineFileNotFoundException(stg['ipcontroller_engine_file'])

def configure_ssh():
    # processes = run_shell_process('ps -e | grep ssh-agent').stdout.readlines()
    # processes = [x.decode() for x in processes if x.split()[-1].strip().decode() == "ssh-agent"]
    # if len(processes) > 1:
    #     print("Too many ssh-agents running, killing {} ssh-agents".format(len(processes)))
    #     for process in processes:
    #         run_shell_process('kill -9 ' + process.split()[0].strip()).wait()
    #     print("Starting ssh-agent...")
    #     run_shell_process('eval `ssh-agent -s`').wait()
    # elif not processes:
    #     print("Starting ssh-agent...")
    #     run_shell_process('eval `ssh-agent -s`').wait()
    # run_shell_process('ssh-add {}'.format(g.settings['private_sshkey']))
    known_hosts_file = "$HOME/.ssh/known_hosts"
    for droplet in g.cluster_droplets: 
        cmd_rem = 'ssh-keygen -f "{}" -R {}'.format(known_hosts_file, droplet.ip_address)
        logging.debug("sending commands to {}:\n{}"
                      .format(droplet.ip_address, cmd_rem))
        p = run_shell_process(cmd_rem)
        errcode = p.wait()
        if errcode != 0:
            raise ShellException("{}: {}\n{}".format(cmd_rem, errcode, p.stdout.read().decode()))
    print("Fingerprints removed from {}".format(known_hosts_file))
    for droplet in g.cluster_droplets:
        # print("=====")
        # run_shell_process('ssh-keyscan -H {}'.format(droplet.ip_address), True)
        # print('------')
        # run_shell_process('ssh-keyscan {}'.format(droplet.ip_address), True)
        # print("=====")
        cmd_add = 'ssh-keyscan -H {} >> "{}"'.format(droplet.ip_address, known_hosts_file)
        while True:
            print("Scanning ssh-keys for {} ...".format(droplet.ip_address))
            p = run_shell_process(cmd_add)
            if p.stdout.readlines():
                break
            sleep(1)
    print("Fingerprints added to {}".format(known_hosts_file))

def get_ipcontroller_ip(stg):
    ipcontroller_engfile = stg['ipcontroller_engine_file']
    conparams = json.load(open(ipcontroller_engfile))
    return conparams['location']

def configure_nodes(stg):
    ipcontroller_ip = get_ipcontroller_ip(stg)
    privkey = g.settings['private_sshkey']
    batchfile = os.path.join(g.docluster_dir, "node_config.sh")
    known_hosts_file = "$HOME/.ssh/known_hosts"
    ss =  "#!/usr/bin/env bash\n"
    # ss += "killall ssh-agent --quiet\n"
    # ss += "eval `ssh-agent -s`\n"
    # ss += "ssh-add $HOME/.docluster_node/clusterkey\n"
    ss += 'ssh-keygen -f "{}" -R {}\n'.format(known_hosts_file, ipcontroller_ip)
    ss += 'ssh-keyscan -H {} >> "{}"\n'.format(ipcontroller_ip, known_hosts_file)
    ss += "num_cpus=$(nproc)\n"
    ss += "killall {}\n".format(stg['ipengine_executable'].split('/')[-1])
    # ss += "mpiexec -n $num_cpus "
    # ss += "{} --file $HOME/.docluster_node/ipcontroller-engine.json --ssh {} "\
    #       .format(stg['ipengine_executable'], ipcontroller_ip)
    # ss += "--sshkey $HOME/.docluster_node/clusterkey --log-to-file\n"
    ss += "echo starting $num_cpus ipengines...\n"
    ss += "for ((i=0; i<$num_cpus; i++))\n"
    ss += "do\n"
    ss += "echo $i\n"
    ss += "{} --file $HOME/.docluster_node/ipcontroller-engine.json --ssh {} "\
          .format(stg['ipengine_executable'], ipcontroller_ip)
    ss += "--sshkey $HOME/.docluster_node/clusterkey --log-to-file &\n"
    ss += "done\n"
    with open(batchfile, 'w') as f:
        f.write(ss)

    #ss += "eval `ssh-agent -s`\\"
    #ss += "ssh-add $HOME/.docluster_node/clusterkey"
    # ss += "ssh-add $HOME/.docluster_node/clusterkey\n"
    #ss += stg['ipengine_executable']
    print("Configuring {} nodes...".format(len(g.cluster_droplets)))
    for i  in range(len(g.cluster_droplets)):
        droplet = g.cluster_droplets[i]
        ip = droplet.ip_address
        # c1 = 'echo ssh {} "/usr/bin/bash \'eval `ssh-agent -s`\'"'.format(ip)
        c1 = "cat {} | ssh -i {} {} 'bash -s'".format(batchfile, privkey, ip)
        # c2 = 'ssh {} "ssh-add $HOME/.docluster_node/clusterkeys"'.format(ip)
        # c3 = 'ssh {} "{}"'.format(ip, stg['ipengine_executable'])
        logging.debug("commands to {}:\n{}".format(ip, ss))
        p = run_shell_process(c1)
        print("remote batch send pid: {}".format(p.pid))
        sleep(5)
        # errcode = p.wait()
        # if errcode != 0:
        #     raise RemoteException("{}: {}\n{}".format(c1, errcode, p.stdout.read().decode()))
        # p = run_shell_process(c2)
        # errcode = p.wait()
        # if errcode != 0:
        #     raise RemoteException("{}: {}\n{}".format(c2, errcode, p.stdout.read().decode()))
        # print(p.stdout.read().decode())
        # p = run_shell_process(c3)
        # errcode = p.wait()
        # if errcode != 0:
        #     raise RemoteException("{}: {}\n{}".format(c3, errcode, p.stdout.read().decode()))
        # print(p.stdout.read().decode())
        # print("{}/{}".format(i + 1, len(g.cluster_droplets)))

def send_keys_and_config_to_nodes(clustername, ipcontroller_engfile):
    droplets = g.cluster_droplets
    privkey = g.settings['private_sshkey']
    print("Sending private ssh keys and ipengine settings to {} nodes...".format(len(droplets)))
    for i in range(len(droplets)):
        droplet = droplets[i]
        sshcmd = 'ssh -i {} {} "mkdir -p .docluster_node"'.format(privkey, droplet.ip_address)
        scpcmd_1 = "scp -i {} {} {}:.docluster_node"\
                   .format(privkey, ipcontroller_engfile, droplet.ip_address)
        scpcmd_2 = "scp -i {} {} {}:.docluster_node/clusterkey"\
                   .format(privkey, privkey, droplet.ip_address)
        logging.debug("sending stuff to {}:\n{}\n{}\n{}"
                      .format(droplet.ip_address, sshcmd, scpcmd_1, scpcmd_2))
        p = run_shell_process(sshcmd, True)
        errcode = p.wait()
        if errcode != 0:
            raise RemoteException("{}: {}\n{}".format(sshcmd, errcode, p.stdout.read().decode()))
        p = run_shell_process(scpcmd_1, True)
        errcode = p.wait()
        if errcode != 0:
            raise RemoteException("{}: {}\n{}".format(scpcmd_1, errcode, p.stdout.read().decode()))
        p = run_shell_process(scpcmd_2, True)
        errcode = p.wait()
        if errcode != 0:
            raise RemoteException("{}: {}\n{}".format(scpcmd_2, errcode, p.stdout.read().decode()))
        print("{}/{}".format(i + 1, len(droplets)))

def start_new_cluster(name, ignore_running=False):
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', name):
        print("Name contains invalid characters, please choose another name")
        sys.exit(EXIT_CODE.INVALID_ARGUMENTS)
    if len(name) > MAX_CLUSTER_NAME_LEN:
        print("Too long name for cluster, maximum length: {}".format(MAX_CLUSTER_NAME_LEN))
    get_public_sshkey()
    get_private_sshkey()
    cluster_settings_file = os.path.join(g.docluster_dir, name + ".yaml")
    if not os.path.isfile(cluster_settings_file):
        setup_cluster(name)
    cluster_settings = yaml.load(open(cluster_settings_file), yaml.RoundTripLoader)
    cost = calculate_cost(cluster_settings['nodes'], g.sizes)
    print("Calculated statistics for new cluster:")
    print("{} Nodes, VCPUs: {}, RAM/VCPU: {:.1f}GB, $/h: {:3f}, VCPUs/1$/h: {:.1f}"
          .format(cost['n_nodes'], cost['vcpus'], cost['ram_per_vcpu'], cost['hourly_rate'], 
                  cost['vcpus_usd_hour']))
    if not setting_is_valid(g.settings, 'no_confirmations'):
        sure = ask_yes_no("Are you sure you want to start this cluster?")
        if not sure:
            return
    start_time = datetime.utcnow()
    try:
        create_cluster(name, cluster_settings)
    except ClusterAlreadyRunningException as ex:
        if ignore_running:
            print("Cluster running already, will reset configuration...")
        else:
            raise ex
    droplets = g.do.get_all_droplets()
    g.cluster_droplets = [x for x in droplets if x.name.split("-")[0] == name]
    initialize_ipcontroller(cluster_settings) 
    configure_ssh()
    send_keys_and_config_to_nodes(name, cluster_settings['ipcontroller_engine_file'])
    configure_nodes(cluster_settings)
    print("Cluster succesfully started")
    print("Time elapsed: {}".format(datetime.utcnow() - start_time))

def destroy_cluster(name, purge=False):
    if not setting_is_valid(g.settings, 'no_confirmations'):
        sure = ask_yes_no("Are you sure you want to destroy '{}'?".format(name))
        if not sure:
            return
    start_time = datetime.utcnow()
    print("Destroying cluster '{}'".format(name))
    if purge:
        cluster_settings_file = os.path.join(g.docluster_dir, name + ".yaml")
        try:
            os.remove(cluster_settings_file)
            print("Deleted settings file: {}".format(cluster_settings_file))
        except FileNotFoundError:
            pass
    droplets = g.do.get_all_droplets()
    names_to_destroy = []
    for droplet in droplets:
        clustername = droplet.name.split("-")[0].lower()
        if clustername.lower() == name.lower():
            droplet.destroy()
            names_to_destroy.append(droplet.name)
    if not names_to_destroy:
        raise ClusterDoesntExistException("Cluster '{}' doesn't exist".format(name))
    last_remaining = len(names_to_destroy)
    while True:
        droplets = g.do.get_all_droplets()
        droplet_names = [x.name for x in droplets]
        remaining_droplets = set(names_to_destroy).intersection(droplet_names)
        if last_remaining != len(remaining_droplets):
            last_remaining = len(remaining_droplets)
            print("{}/{} droplets destroyed"
                  .format(len(names_to_destroy) - len(remaining_droplets), len(names_to_destroy)))
        if not remaining_droplets:
            break
        sleep(10)
    print("Cluster '{}' succesfully destroyed".format(name))
    print("Time elapsed: {}".format(datetime.utcnow() - start_time))

def setup_logging():
    logfile = os.path.join(g.docluster_dir, "docluster.log")
    loglevel = logging.INFO
    if setting_is_valid(g.settings, 'logging_level'):
        loglevel = logging.__dict__[g.settings['logging_level']]
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    if setting_is_valid(g.settings, 'logging_format'):
        fmt = g.settings['logging_format']
    datefmt = "%Y%m%d %H:%M:%S"
    if setting_is_valid(g.settings, 'logging_dateformat'):
        datefmt = g.settings['logging_dateformat']
    r = logging.root
    r.handlers.clear()
    r.filters.clear()
    r.level = logging.NOTSET
    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
    handler = logging.FileHandler(filename=logfile)
    handler.level = loglevel
    handler.setFormatter(formatter)
    r.addHandler(handler)

if __name__ == "__main__":

    if len(sys.argv) == 1:
        print(HEADER + "\n" + HELP_MESSAGE)
        sys.exit(EXIT_CODE.OK)

    args = sys.argv[1:]

    if args[0] == "help" or args[0] == "-h" or args[0] == "--help":
        print(HEADER + "\n" + HELP_MESSAGE)
        sys.exit(EXIT_CODE.OK)

    homedir = os.path.expanduser('~')
    g.dokit_dir = os.path.join(homedir, ".dokit")
    g.docluster_dir = os.path.join(g.dokit_dir, "docluster")
    g.settings = check_for_general_settings()
    g.dokit_settings = check_for_dokit_settings()
    setup_logging()

    if not setting_is_valid(g.dokit_settings, 'digitalocean_token'):
        ask_for_token()
    
    g.do = digitalocean.Manager(token=g.dokit_settings['digitalocean_token'])
    g.sizes = g.do.get_all_sizes()

    action = args[0]
    if action == "start":
        if len(args) == 1 or args[1][:2] == "--":
            print("Usage: docluster start [name]")
            sys.exit(EXIT_CODE.INVALID_ARGUMENTS)
        name = args[1]
        try:
            start_new_cluster(name, ignore_running=True)
        except ClusterAlreadyRunningException as ex:
            print(ex)
            sys.exit(EXIT_CODE.RUNTIME_ERROR)
    elif action == "setup":
        if len(args) == 1 or args[1][:2] == "--":
            print("Usage: docluster setup [name]")
            sys.exit(EXIT_CODE.INVALID_ARGUMENTS)
        name = args[1]
        try:
            setup_cluster(name)
        except ClusterAlreadyRunningException as ex:
            print(ex)
            sys.exit(EXIT_CODE.RUNTIME_ERROR)
    elif action == "destroy":
        if len(args) == 1 or args[1][:2] == "--":
            print("Usage: docluster destroy [name]")
            sys.exit(EXIT_CODE.INVALID_ARGUMENTS)
        name = args[1]
        try:
            destroy_cluster(name)
        except ClusterDoesntExistException as ex:
            print(ex)
            sys.exit(EXIT_CODE.RUNTIME_ERROR)
    elif action == "reconnect":
        print("Not yet implemented")
    elif action == "status":
        print("Not yet implemented")
    elif action == "addnode":
        print("Not yet implemented")
    elif action == "rmnode":
        print("Not yet implemented")
    else:
        print("Unknown action: {}".format(action), file=sys.stderr)
        print(HELP_MESSAGE)
        sys.exit(EXIT_CODE.INVALID_ARGUMENTS)
