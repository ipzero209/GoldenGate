#!/usr/bin/python

import shelve
import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import panFW
# import getData
from threading import Thread
import pudb

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Get the API from /etc/pan_shim

s_data = shelve.open('./data.db') #TODO - /etc/pan_shim/
api_key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09" #s_data['api_key']
pano_ip = "10.3.4.63" #s_data['pano_ip']
s_data.close()

##########################################################
#
#       Functions
#
##########################################################


def getDevices(pano_ip, key):
    """Returns a list of firewall objects for firewalls that are PAN-OS 8.0 or 
    earlier"""
    prefix = "https://{}/api/?".format(pano_ip)
    cmd = "type=op&cmd=<show><devices><connected></connected></devices></show>"
    get_dev_req = requests.get(prefix + cmd + "&key=" + key, verify=False)
    dev_xml = et.fromstring(get_dev_req.content)
    devices = dev_xml.findall('./result/devices/*')
    fw_obj_list = []
    for device in devices:
        os_ver = device.find('sw-version').text
        if os_ver[:3] == "8.1":
            pass
        else:
            serial = device.find('serial').text
            mgmt_ip = device.find('ip-address').text
            family = device.find('family').text
            is_ha = 'no'
            this_dev = panFW.Device(serial, mgmt_ip, os_ver, family, is_ha)
            fw_obj_list.append(this_dev)
    return fw_obj_list


##########################################################
#
#       Main
#
##########################################################

# Get the API from /etc/pan_shim

s_data = shelve.open('./data.db') #TODO - /etc/pan_shim/
api_key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09" #s_data['api_key']
pano_ip = "10.3.4.63" #s_data['pano_ip']
s_data.close()


# Get initial list of devices
dev_list = getDevices(pano_ip, api_key)




