import subprocess
import sys
from time import sleep

######### CONSTANTS ###############

DEFAULT_DOKIT_SETTINGS = """
# digital ocean token
digitalocean_token: null
# default public sshkey (id)
public_sshkey: null
"""
ALL_FEATURES = ['virtio', 'private_networking', 'backups', 'ipv6', 'metadata']

class EXIT_CODE:
    OK = 0
    INVALID_ARGUMENTS = 1
    RUNTIME_ERROR = 2

########## USER INPUT ####################

def choose_from_list(items, title=None, formatter=None, idcol=None):
    if title:
        print(title)
    if not formatter:
        def default_formatter(item):
            return str(item)
        formatter = default_formatter
    if idcol:
        ids = [x.__dict__[idcol] for x in items]
    else:
        ids = [str(i+1) for i in range(len(items))]
    while True:
        for i in range(len(items)):
            item = items[i]
            print("{}: {}".format(ids[i], formatter(item)))
        selection = input("> ")
        try:
            idx = ids.index(selection)
        except ValueError:
            print("Invalid selection")
            continue
        return items[idx]

def ask_yes_no(question, show_yn=False):
    q = question + " "
    if show_yn:
        q += "(y/n) "
    while True:
        answer = input(q).lower()
        if answer in ['y', 'yes']:
            return True
        if answer in ['n', 'no']:
            return False

def ask_integer(question, limits=None):
    q = question + " "
    if limits:
        assert len(limits) == 2
        q += "[{}-{}] ".format(limits[0], limits[1])
    while True:
        answer = input(q)
        try:
            answer = int(answer)
        except ValueError:
            print("Invalid selection")
            continue
        if limits[0] <= answer <= limits[1]:
            return answer
        print("Invalid selection")

def ask_file(question, suggestion=None, include_syspath=False):
    while True:
        q = question + " "
        if suggestion:
            q += "[{}] ".format(suggestion)
        answer = input(q)
        if not answer:
            answer = suggestion
            suggestion = None
        if os.path.isfile(answer):
            return answer
        if include_syspath:
            if run_shell_process('which {}'.format(answer)).stdout.readlines():
                return answer
        print("File not found")

######### FORMATTERS ##################

def image_to_str(x):
    s = "{}, id: {}, min_disk_size: {}GB".format(x.name, x.id, x.min_disk_size)
    return s

def instance_to_str(x):
    s = "id: {}, {} VCPUs, {}GB RAM, {} $/h, {:.1f} VCPUs/1$/h"\
        .format(x.slug, x.vcpus, x.memory / 1024, x.price_hourly, x.vcpus / x.price_hourly)
    return s

def sshkey_to_str(x):
    s = "{} (id: {})".format(x.name, x.id)
    return s

def region_to_str(x):
    s = "{} ({})".format(x.name, x.slug)
    return s

########### EXCEPTIONS #################

class RemoteException(Exception):
    pass

class ShellException(Exception):
    pass

##########################################

class Bunch(object):
    """Create C-like structs (basically wrap a dictionary)."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return self.__dict__.__repr__()

def run_shell_process(command, print_output=False):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if print_output:
        while True:
            out = p.stdout.read(1).decode()
            if out == '' and p.poll() != None:
                break
            if out != '':
                sys.stdout.write(out)
                sys.stdout.flush()
    return p

def setting_is_valid(settings, key):
    if key in settings and settings[key]:
        return True
    return False

def wait_for_actions_to_complete(droplet, sleep_time=3, extra_time=0):
    """Wait for all actions to complete.

    Arguments:
    droplet     -- Droplet to wait for
    extra_time  -- Wait extra seconds after finishing to make sure
                   the action is really finished.
                   This is often neccessary due to a bug in Digital Ocean API.
    """
    while True:
        actions = [x for x in droplet.get_actions() if x.status == "in-progress"]
        if not actions:
            break
        sleep(sleep_time)
    sleep(extra_time)
