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
fh = logging.FileHandler("setup.log") #Todo - change path to /var/log/pan/setup.log
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
    key_node = key.xml.find('./result/key')
    logger.info("API key successfully retrieved from {}.".format(pano_ip))
    return key_node.text

logger.info('Created log directory.')

print "Welcome message" #TODO - print brief description of what the setup program will do.

api_key = getKey()
s_data = shelve.open('./data') #TODO - /etc/pan_shim/data
s_data['api_key'] = api_key
s_data.close()


