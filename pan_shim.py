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



formatter = logging.Formatter('%(asctime)s  %(module)s:%(levelname)s:%(funcName)s:\t%(message)s')

#TODO: Change fileHandler back to pan_shim.log
file_handler = logging.FileHandler('gg.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)






##########################################################
#
#       Functions
#
##########################################################


def setOpts(opt_File):
    """Reads options from pan_shim.conf"""
    options_dict = {}
    options_dict['EXCLUDE'] = []
    if os.path.isfile(opt_File):
        c_file = open(opt_File, 'r')
        for line in c_file:
            line = line.split(":")
            if line[0] == "EXCLUDE":
                options_dict['EXCLUDE'].append(str(line[1]))
            options_dict[line[0]] = line[1]
    else:
        """Set defaults for all options"""
        logger.setLevel(logging.ERROR)
        options_dict['LEVEL'] = "error"
    logging_level = options_dict['LEVEL']
    if logging_level == "debug":
        logger.setLevel(logging.DEBUG)
    elif logging_level == "info":
        logger.setLevel(logging.INFO)
    elif logging_level == "warning":
        logger.setLevel(logging.WARNING)
    elif logging_level == "error":
        logger.setLevel(logging.ERROR)
    elif logging_level == "critical":
        logger.setLevel(logging.CRITICAL)
    else:
        options_dict['LEVEL'] = "error"
        logger.setLevel(logging.ERROR)
    return options_dict



def getDevices(pano_ip, key, ex_list):
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
        serial = device.find('serial').text
        if os_ver[:3] == "8.1":
            pass
        elif serial in ex_list:
            pass
        else:
            hostname = device.find('hostname').text
            mgmt_ip = device.find('ip-address').text
            family = device.find('family').text
            is_ha = 'no'
            this_dev = panFW.Device(hostname, serial, mgmt_ip, os_ver, family, is_ha)
            logging.debug("Added device {}, S/N {}:\n\n{}\n".format(this_dev.h_name,
                                                                    this_dev.ser_num,
                                                                    this_dev.prinfo()))
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
        logger.debug("Skipping fan info for {}-{}. Family is {}".format(fw.h_name, fw.ser_num, fw.family))
        pass
    else:
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

# Get the API key from /etc/pan_shim
if os.path.isfile('./data'):
    s_data = shelve.open('./data') #TODO - /etc/pan_shim/
    api_key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09" #s_data['api_key']
    pano_ip = "10.3.4.63" #s_data['pano_ip']
    s_data.close()
else:
    logger.error("No data file found. Please run shim_setup.py")

o_dict = setOpts('./pan_shim.conf')
exclude_list = o_dict['EXCLUDE']

# Get initial list of devices
dev_list = getDevices(pano_ip, api_key, exclude_list)
for device in dev_list:
    logging.info("Device added: Hostname {}, S/N {}".format(device.h_name, device.ser_num))

c_count = 0
while True:
    if c_count == 6:
        logging.info("-----It's been 30 minutes. Rebuilding device list.-----")
        dev_list = getDevices(pano_ip, api_key)
        for device in dev_list:
            logging.info("Device added: Hostname {}, S/N {}".format(device.h_name, device.ser_num))
        c_count = 0
    for device in dev_list:
        logging.info("-----Beginning Poll Cycle-----")
        status = upCheck(device.mgmt_ip)
        if status != 0:
            logger.error("Device {} is not reachable by ping".format(device.h_name))
            pass
        else:
            logging.debug("Gathering data for {}, S/N {}.".format(device.h_name, device.ser_num))
            data_thread = Thread(target=getData, args=(device, pano_ip, api_key))
            data_thread.start()
    c_count += 1
    sleep(300)





