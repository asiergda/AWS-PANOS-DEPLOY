#!/usr/bin/env python

import datetime
import sys
import time
import panos
import panos.firewall
import panos.objects
import json
import urllib3
import urllib
import netmiko
from netmiko import ConnectHandler
import os
import signal
from getpass import getpass
from multiprocessing.dummy import Pool as ThreadPool
import yaml
import textfsm
import argparse
import genie
import argparse
from colorama import Fore, Back, Style
from termcolor import colored, cprint

parser = argparse.ArgumentParser()
parser.add_argument("-fw", "--firewall_name", help="Enter the firewall name")
parser.add_argument("-aws", "--aws_url", help="Enter the url to download json file")
parser.add_argument("-awsreg", "--aws_region", help="Enter the aws region that need to be accessed")
args = parser.parse_args()

if len(sys.argv) < 6:
    print('Usage:\n', os.path.split(sys.argv[0])[-1], '--firewall_name FWNAME --aws_url https://ip-ranges.amazonaws.com/ip-ranges.json --aws_region eu-west-1')
    print('Reduced format usage: \n', os.path.split(sys.argv[0])[-1], '-fw FWNAME -aws https://ip-ranges.amazonaws.com/ip-ranges.json -awsreg eu-west-1')
    exit()

PAN_FW_HOSTNAME = args.firewall_name
AWS_IP_RANGES_URL = args.aws_url
AWS_REGION = args.aws_region

startgathering = datetime.datetime.now()

# Oh my god!, Dirty Deeds Done Dirt Cheap - ACDC

################################################################################
def GatherAWSData(url):
    start = datetime.datetime.now()
    aws_ip_ranges_file_bkp = "/home/nagios/NetDevOps/python3/scripts/staging/SEC_PAN_RPKI_AWS/aws_ip_ranges.json"  # warning a hardcoded shit...remember this is a LAB
    msg_con = str("STEP 1: Downloading AWS ip ranges from {0}".format(url))
    cprint(msg_con, 'white', 'on_blue')
    try:
        response = urllib.request.urlopen(url)
        data = response.read()
        aws_ip_ranges_donwloaded = json.loads(data)
        if len(aws_ip_ranges_donwloaded) >= 4: # Dirty check of downloaded info
            aws_ip_ranges = aws_ip_ranges_donwloaded
            print("Gather and save the AWS networks has taken: {0}".format(datetime.datetime.now() - start))
            cprint("STEP 1 -> OK: Data successfully downloaded, now we will go to the next step...", 'green', attrs=['bold'])
            return(aws_ip_ranges)
        else: # Use a backup file as source of data. We can stop here but to test LAB is useful.
            print(Fore.YELLOW + "WARNING: AWS ip range data does not have the correct format. A local file will be used: \n***{0}***".format(aws_ip_ranges_file_bkp) + Fore.RESET)
            with open(aws_ip_ranges_file_bkp) as net_file:
                aws_ip_ranges = json.load(net_file)
            return(aws_ip_ranges)
    except Exception as e: # Use a backup file as source of data. We can stop here but to test LAB is useful.
        print(Fore.YELLOW + "WARNING: AWS ip range data cannot be downloaded. A local file will be used: \n***{0}***".format(aws_ip_ranges_file_bkp) + Fore.RESET)
        with open(aws_ip_ranges_file_bkp) as net_file:
            aws_ip_ranges = json.load(net_file)
        return(aws_ip_ranges)
        print(e)
    print("Gather and save the AWS networks has taken: {0}".format(datetime.datetime.now() - start))
    msg_con = str("The fist step result is OK: AWS Data successfully downloaded from {0}, now we will go to the next step...".format(url))
    cprint(msg_con, 'green', attrs=['bold'])
    print ('=' * 50)
    print ('=' * 50)

################################################################################
def FwConfig(host):
    try:
        aws_ip_ranges = GatherAWSData(AWS_IP_RANGES_URL) # Ejem..ejem...
        fw = panos.firewall.Firewall(host[0], host[2], host[3])
        print(Back.BLUE + "STEP 2: Starting the bulk modification process over {0}...".format(host[4]) + Back.RESET)

        # We do not want in our firewall the prefixes that are not longer part of AWS
        # Gather data and select objects to delete.
        # "Deletable" objects name starts with PREFIX, take care about the PREFIX value that is chosen for this automation, it should not be used for any other object.
        # The deletion is done mainly to notify the action but really it is not necessary.
        # Gathered objects are not included in the firewall tree (refleshall method to False)
        related_objects = panos.objects.AddressObject.refreshall(fw, add=False)
        obj_to_remove = []
        for related_object in related_objects:
            if related_object.uid.startswith(PREFIX):
                obj_to_remove.append(related_object)
                fw.add(related_object)

        # Delete "deletable" objects.
        # This step can be skipped becasue later we will apply the new objects and the actual objects that do not start with PREFIX...see later
        if len(obj_to_remove) >= 1:
            print("Bulk deleting objects whose name begins with \"{0}\" string...".format(PREFIX))
            obj_to_remove[0].delete_similar()
            start = datetime.datetime.now()
            print("Delete {0} address objects has taken: {1}".format(len(obj_to_remove), datetime.datetime.now() - start))

        # Some name normalization tasks for new objects.
        # Add normalized objects to the firewall...
        obj_to_add = []
        for ip_prefix_dict in aws_ip_ranges["prefixes"]:
            if ip_prefix_dict["region"] == AWS_REGION:
                object_name_pure = ip_prefix_dict["ip_prefix"].replace("/", "_SM_")
                aws_service = ip_prefix_dict["service"]
                object_name = str("{0}_{1}_{2}_{3}".format(PREFIX, AWS_REGION, object_name_pure, aws_service))
                ip_prefix = ip_prefix_dict["ip_prefix"]
                tag_name = "TAG_DAG_AWS"
                addr_obj = panos.objects.AddressObject(object_name, ip_prefix, tag=tag_name)
                # print(addr_obj)
                obj_to_add.append(addr_obj)
                fw.add(addr_obj)

        # Bulk creation...
        print("Creating AWS objects...")
        start = datetime.datetime.now()
        obj_to_add[0].create_similar()
        print("AWS objects created: The creation of {0} address objects has taken: {1}".format(len(obj_to_add), datetime.datetime.now() - start))

        # Add the original objects to the tree (not include the "deletable" objects)...take care about this step.
        # The existing objects whose name start with PREFIX will not be created, the previous bulk deletion could be skipped.
        for related_object in related_objects:
            if not related_object.uid.startswith(PREFIX):
                fw.add(related_object)

        print("Applying {0} objects to the firewall...".format(len(obj_to_add) + len(related_objects)))
        start = datetime.datetime.now()
        obj_to_add[0].apply_similar()
        print("Applied: The bulk apply of {0} address objects has taken: {1}".format(len(obj_to_add) + len(related_objects), datetime.datetime.now() - start))

        print("And now is time of commit...")
        start = datetime.datetime.now()
        fw.commit(sync=True)
        print("Commit preocess has taken: {0}".format(datetime.datetime.now() - start))
        cprint("STEP 2 -> OK: The {} configuration has been updated".format(host[4]), 'green', attrs=['bold'])
        print ('=' * 50)
        print ('=' * 50)
    except Exception as e:
        print("WARNING: {0} cannot be modified".format(PAN_FW_HOSTNAME))
        print(e)
################################################################################

# Oh my god!, more Dirty Deeds Done Dirt Cheap - ACDC

if __name__ == "__main__":
    time.strftime('%Y-%m-%d_%H:%M:%S')
    USERNAME = input('Username: ')
    PASSWORD = getpass()
    device_file = "/home/nagios/NetDevOps/python3/scripts/staging/SEC_PAN_RPKI_AWS/inventory/devices_file_ios.json" # warning another hardcoded shit...
    PREFIX = "AWS" # warning another hardcoded shit...I do not remember why I do not include it as an argument...the life is too hard
    with open(device_file) as dev_file:
        devices = json.load(dev_file)
    for device in devices:
        if device['hostname'] == PAN_FW_HOSTNAME:
            FW_IPADDRESS = device['ip']
            FW_TYPE = device['device_type']
    failed_names = []
    try:
        FW_IPADDRESS
    except NameError:
        failed_names.append(str(Fore.YELLOW + "Firewall name does not exists: {0}".format(PAN_FW_HOSTNAME) + Fore.RESET))

    FW_NODE = (FW_IPADDRESS, FW_TYPE, USERNAME, PASSWORD, PAN_FW_HOSTNAME, PREFIX)
    cprint("The automation work has started, OH mama!!!...(TCPLB|YSOYP)", 'magenta', attrs=['bold'])

    FwConfig(FW_NODE)

    print(colored("The overall process has taken: ", 'blue') + colored("{0}".format(datetime.datetime.now() - startgathering), 'blue', attrs=['bold', 'blink']))
