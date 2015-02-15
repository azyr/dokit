import sys
import json
import re
import os
import digitalocean
import argparse
from dokit import *
from datetime import datetime
from ruamel import yaml
from time import sleep

######### GLOBAL VARIABLES #######################

# holder for global variables
g = Bunch()

#################################################

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

def get_public_sshkey():
    keys = g.do.get_all_sshkeys()
    if setting_is_valid(g.dokit_settings, 'public_sshkey'):
        key_ids = [x.id for x in keys]
        try:
            idx = key_ids.index(g.dokit_settings["public_sshkey"])
            key = keys[idx]
            print("Default public sshkey selected: {}".format(sshkey_to_str(key)))
            return key
        except ValueError:
            pass
    key = choose_from_list(keys, "Choose ssh-key:", sshkey_to_str)
    if ask_yes_no("Save as default sshkey?"):
        g.dokit_settings['public_sshkey'] = key.id
        save_dokit_settings()
    return key

def check_for_dokit_settings():
    dokit_settings_file = os.path.join(g.dokit_dir, "settings.yaml")
    if not os.path.isfile(dokit_settings_file):
        with open(dokit_settings_file, 'w') as f:
            f.write(DEFAULT_DOKIT_SETTINGS)
    settings = yaml.load(open(dokit_settings_file), yaml.RoundTripLoader)
    return settings

def droplet_to_dict(droplet):
    d = {}
    d['name'] = droplet.name
    d['image'] = droplet.image['id']
    d['region'] = droplet.region['slug']
    d['user_data'] = droplet.user_data
    d['size'] = droplet.size_slug
    for feature in ALL_FEATURES:
        if feature in droplet.features:
            d[feature] = True
        else:
            d[feature] = False
    return d 

def droplet_from_dict(d):
    droplet = digitalocean.Droplet()
    droplet.name = d['name']
    droplet.image = d['image']
    droplet.token = g.dokit_settings['digitalocean_token']
    droplet.region = d['region']
    droplet.size = d['size']
    for feature in ALL_FEATURES:
        droplet.__dict__[feature] = d[feature]
    return droplet

def check_for_droplet_files(name):
    fn = os.path.join(g.doswitch_dir, name + ".json")
    if os.path.isfile(fn):
        return json.load(open(fn))
    return None

def save_droplet(droplet, imageid):
    d = droplet_to_dict(droplet)
    d['image'] = imageid
    fn = os.path.join(g.doswitch_dir, droplet.name.lower() + ".json")
    json.dump(d, open(fn, 'w'))
    return fn

def wait_for_droplet(name, predicate, sleep_time=3):
    while True:
        droplets = [x for x in g.do.get_all_droplets() if x.name == name]
        if droplets:
            assert len(droplets) == 1
            droplet = droplets[0]
            if predicate(droplet):
                return droplet
        sleep(sleep_time)

def switch_on(droplet):
    sshkey = get_public_sshkey() 
    start_time = datetime.utcnow()
    droplet.ssh_keys = [sshkey]
    print('Switching on "{}" ({}) ...'.format(droplet.name, droplet.size))
    droplet.create()
    newd = wait_for_droplet(droplet.name, lambda x: x.status == "active")
    print("Droplet is online, ip: {}".format(newd.ip_address))
    known_hosts_file = "$HOME/.ssh/known_hosts"
    print("Modifying {}".format(known_hosts_file))
    cmd_rem = 'ssh-keygen -f "{}" -R {}'.format(known_hosts_file, newd.ip_address)
    run_shell_process(cmd_rem, True)
    cmd_add = 'ssh-keyscan -H {} >> "{}"'.format(newd.ip_address, known_hosts_file)
    while True:
        print("Scanning ssh-keys for {} ...".format(newd.ip_address))
        p = run_shell_process(cmd_add)
        if p.wait() == 0:
            lines = p.stdout.readlines()
            if lines:
                # lines = [x.decode() for x in lines]
                # print("".join(lines))
                break
        sleep(1)
    print("Operation took: {}".format(datetime.utcnow() - start_time))

def switch_off(droplet):
    start_time = datetime.utcnow()
    accepted_statuses = ['active', 'off']
    actions = [x for x in droplet.get_actions() if x.status == "in-progress"]
    if actions:
        print("Cannot switch off droplet, droplet has pending actions:")
        for action in actions:
            print("- {}, status=".format(action.type, action.status))
        return
    if droplet.status not in accepted_statuses:
        print("Aborting switch off operation due to unexpected droplet status: {}"
              .format(droplet.status))
        return
    if droplet.status != "off":
        print('Switching off "{}" ({}) ...'.format(droplet.name, droplet.size_slug))
        print("Turning droplet's power off...")
        droplet.power_off()
        # wait_for_droplet(name, lambda x: x.status == "off")
        wait_for_actions_to_complete(droplet)
    else:
        print("Droplet's power is already turned off")
    img_name = droplet.name + "-" + datetime.utcnow().strftime("%y%m%d_%H%M%S")
    print('Saving a snapshot of the droplet as "{}" ...'.format(img_name))
    droplet.take_snapshot(img_name)
    wait_for_actions_to_complete(droplet)
    img_id = [x.id for x in g.do.get_my_images() if x.name == img_name][0]
    jsonfile = save_droplet(droplet, img_id)
    print("Droplet attributes saved to {}".format(jsonfile))
    img_regex = droplet.name + "-" + "[0-9]{6}_[0-9]{6}"
    images = [x for x in g.do.get_my_images() if re.fullmatch(img_regex, x.name)\
              and x.name != img_name]
    print("Deleting {} old image(s)...".format(len(images)))
    for image in images:
        image.destroy()
    print("Destroying droplet...")
    droplet.destroy()
    wait_for_actions_to_complete(droplet)
    # while True:
    #     droplets = [x for x in g.do.get_all_droplets() if x.name == droplet.name]
    #     if not droplets:
    #         break
    #     sleep(3)
    print("Droplet destroyed")
    print("Operation took: {}".format(datetime.utcnow() - start_time))

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.description = "Digital Ocean Droplet On/Off Switcher"
    parser.add_argument("name", help="name of the droplet")
    args = parser.parse_args()

    name = args.name.lower()

    homedir = os.path.expanduser('~')
    g.dokit_dir = os.path.join(homedir, ".dokit")
    g.doswitch_dir = os.path.join(g.dokit_dir, "doswitch")
    if not os.path.exists(g.doswitch_dir):
        os.makedirs(g.doswitch_dir)
    g.dokit_settings = check_for_dokit_settings()

    if not setting_is_valid(g.dokit_settings, 'digitalocean_token'):
        ask_for_token()

    g.do = digitalocean.Manager(token=g.dokit_settings['digitalocean_token'])

    droplets = [x for x in g.do.get_all_droplets() if x.name.lower() == name.lower()]
    if not droplets:
        droplet_dict = check_for_droplet_files(name)
        if not droplet_dict:
            print("No references for droplet named: {}".format(args.name))
            sys.exit(EXIT_CODE.INVALID_ARGUMENTS)
        droplet = droplet_from_dict(droplet_dict)
        switch_on(droplet)
    else:
        assert len(droplets) == 1
        droplet = droplets[0]
        switch_off(droplet)
