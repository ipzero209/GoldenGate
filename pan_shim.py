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

dev_list = []

def getDevices(pano_ip, key):
    prefix = "https://"
    uri = "/api/?type=op"
    cmd = "&cmd=<show><devices><connected></connected></devices></show>"
    get_dev_req = requests.get(prefix + pano_ip + uri + cmd + "&key=" + key, verify=False)
    dev_xml = et.fromstring(get_dev_req.content)
    devices = dev_xml.findall('./result/devices/*')
    return devices

my_list = getDevices(pano_ip, api_key)

for device in my_list:
    serial = device.find('serial').text
    mgmt_ip = device.find('ip-address').text
    os_ver = device.find('sw-version').text
    is_ha = 'no'
    this_dev = panFW.Device(serial, mgmt_ip, os_ver, is_ha)
    dev_list.append(this_dev)

for device in dev_list:
    print device.ser_num
    print device.mgmt_ip
    print device.os_ver
    print "=============================\n\n"