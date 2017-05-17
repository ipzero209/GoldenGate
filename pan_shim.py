#!/usr/bin/python

import shelve
import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import panFW

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Get the API from /etc/pan_shim

s_data = shelve.open('./data.db') #TODO - /etc/pan_shim/
api_key = "LUFRPT1SdzlWUXE0R0xBQTZTejBkbWJ4OVVvYWFxc0U9OC9kRkpwMWZhUTY2emNrZ3hLaTRSNFBmM0hVdDdMeGlnWHE2UHJ3WXFMbz0=" #s_data['api_key']
pano_ip = "10.3.5.136" #s_data['pano_ip']
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
    this_dev = panFW.Device(serial, mgmt_ip, os_ver)
    dev_list.append(this_dev)

for device in dev_list:
    print device.ser_num
    print device.mgmt_ip
    print device.os_ver
    print "=============================\n\n"