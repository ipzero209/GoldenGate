#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import getpass
import shelve
import os
import logging

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
os.system('mkdir /var/log/pan')


logger = logging.getLogger("setup")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("/var/log/pan/shim_setup.log")
formatter = logging.Formatter('%(asctime)s %(name)s\t\t%(levelname)s:\t\t\t\t%(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)



def getKey():
    """Used to fetch the API key for use in polling devices"""
    pano_ip = raw_input("Enter the IP address of your Panorama: ")
    user = raw_input("Enter the API username. NOTE: This user must exist and have the proper permissions on both " \
                     "Panorama and all Panorama managed firewalls.\n\nUsername: ")
    passwd = getpass.getpass("\nEnter the password for the API user: ")
    key_string = "https://" + pano_ip + "/api/?type=keygen&user=" + user + "&password=" + passwd
    key_request = requests.get(key_string, verify=False)
    key_xml = et.fromstring(key_request.content)
    if key_request.status_code != 200:
        err_node = key_xml.find('./result/msg')
        logger.critical('Error retrieving API key from {}: {}'.format(pano_ip, err_node.text))
    key_node = key_xml.find('./result/key')
    logger.info("API key successfully retrieved from {}.".format(pano_ip))
    saveInfo('pano_ip', pano_ip)
    return key_node.text

def saveInfo(key_str, data):
    """Used to shelve the API key for later use"""
    loggger.info("Saving API key.")
    s_data = shelve.open('/etc/pan_shim/data')
    s_data[key_str] = data
    s_data.close()
    logger.info("API key saved")
    return

def prepService():
    """Moves files to the appropriate directories and sets the correct permissions"""
    logger.info("Copying shim_svc to /etc/init.d")
    shim_cp = os.system("cp ./shim_svc /etc/init.d/")
    if shim_cp !=:
        logger.critical("Could not copy service file to /etc/init.d. Are we "
                         "running with sudo?")
        return 1
    logger.info("Setting permissions on shim_svc")
    shim_perm = os.system("chmod 755 /etc/shim_svc")
    if shim_perm != 0:
        logger.critical("Could not set permissions on /etc/init.d/shim_svc")
        return 1
    logger.info("Creating /etc/pan_shim")
    shim_etc = os.system("mkdir /etc/pan_shim")
    if shim_etc != 0:
        logger.critical("Could not create directory /etc/pan_shim")
        return 1
    logger.info("Copying conf file to /etc/pan_shim")
    os.system("cp ./pan_shim.conf /etc/pan_shim/")
    logger.info("Copying pan_shim.py to /usr/local/bin")
    py_copy = os.system("cp ./pan_shim.py /usr/local/bin/")
    if py_copy != 0:
        logger.critical("Failed to copy pan_shim.py to /usr/local/bin. Are we "
                         "running with sudo?")
        return 1
    logger.info("Setting permissions on pan_shim.py")
    py_perm = os.system("chmod 755 /usr/local/bin/pan_shim.py")
    if py_perm != 0:
        logger.critical("Could not set permissions on /usr/local/bin/pan_shim.py")
        return 1
    logger.info("Updating rc.d")
    update_rc = os.system("update-rc.d shim_svc defaults")
    if update_rc != 0:
        logger.critical("Failed to update rc.d")
        return 1
    return 0

def svcStart():
    """Starts the service"""
    logger.info("Attempting to start the service")
    svc_start = os.system("service shim_svc start")
    if svc_start != 0:
        logger.critical("Failed to start shim_svc")
        return 1
    return 0




logger.info('Created log directory.')

print "Welcome message" #TODO - print brief description of what the setup program will do.

api_key = getKey()
saveInfo('api_key', api_key)

prep = prepService()
if prep == 1
    logger.critical("Critical error in service set up. See log for details.")
    exit(1)

s_start = svcStart()
if s_start == 1:
    logger.critical("Critical error when starting the service. See log for "
                    "details.")


