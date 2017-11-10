#!/usr/bin/python

import shelve
import requests
import xml.etree.ElementTree as et
import panFW
import Metrics
import os
import logging
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from time import sleep

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger('pan_shim')
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s  %(module)s:%(levelname)s:%(funcName)s:\t%(message)s')

file_handler = logging.FileHandler('pan_shim.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


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
            hostname = device.find('hostname').text
            serial = device.find('serial').text
            mgmt_ip = device.find('ip-address').text
            family = device.find('family').text
            is_ha = 'no'
            this_dev = panFW.Device(hostname, serial, mgmt_ip, os_ver, family, is_ha)
            fw_obj_list.append(this_dev)
    return fw_obj_list


def upCheck(fw_ip):
    """Checks basic connectivity to the target device"""
    status = os.system('ping -c 1 {}'.format(fw_ip))
    return status


def getData(fw, pano_ip, key):
    update_dict = {}
    update_dict = {'trend': {}}
    update_dict['status'] = {}
    update_dict['trend']['slot'] = {}
    update_dict['trend']['i'] = {}
    update_dict['status']['logging-external'] = {}
    update_dict['status']['logging-external']['external'] = {'autotag': {}, 'http': {},
                                                             'raw': {}, 'email': {},
                                                             'snmp': {}, 'syslog': {}}
    update_dict['status']['ports'] = {}
    update_dict['status']['environmentals'] = {}
    update_dict['status']['environmentals']['mounts'] = {}
    update_dict['status']['environmentals']['disks'] = {}
    update_dict['status']['environmentals']['fans'] = {}
    update_dict['status']['environmentals']['thermal'] = {}
    update_dict['status']['environmentals']['power'] = {}

    update_dict = Metrics.mpCPU(fw, key, update_dict)
    update_dict = Metrics.mpMem(fw, key, update_dict)
    update_dict = Metrics.dpCPU(fw, key, update_dict)
    update_dict = Metrics.sessionInfo(fw, key, update_dict)
    update_dict = Metrics.packetBnD(fw, key, update_dict)
    update_dict = Metrics.intStats(fw, key, update_dict)
    update_dict = Metrics.intErrors(fw, key, update_dict)
    update_dict = Metrics.intState(fw, key, update_dict)
    update_dict = Metrics.logRate(fw, key, update_dict)
    if fw.family in ['vm', '220']:
        pass
    else:
        update_dict = Metrics.envFans(fw, key, update_dict)
    if fw.family in ['200', 'vm', '500', '800', '3000']:
        pass
    else:
        logger.debug(fw.family)
        update_dict = Metrics.envPower(fw, key, update_dict)
    if fw.family == 'vm':
        pass
    else:
        update_dict = Metrics.envThermal(fw, key, update_dict)
    update_dict = Metrics.envPartitions(fw, key, update_dict)
    if fw.family in ['5200', '7000']:
        update_dict = Metrics.envRaid(fw, key, update_dict)
    else:
        pass
    if fw.os_ver[:3] == "8.0":
        update_dict = Metrics.logFwd(fw, key, update_dict)
    send = Metrics.sendData(fw, pano_ip, key, update_dict)
    if send == "success":
        return
    else:
        logger.error("Submission to Panorama failed in for device {}, S/N {} failed"
                     " with status {}".format(fw.h_name, fw.ser_num, send))
        return

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

while True:
    for device in dev_list:
        status = upCheck(device.mgmt_ip)
        if status != 0:
            logger.error("Device {} is not reachable by ping".format(device.h_name))
            pass
        else:
            data_thread = Thread(target=getData, args=(device, pano_ip, api_key))
            data_thread.start()
    sleep(300)





