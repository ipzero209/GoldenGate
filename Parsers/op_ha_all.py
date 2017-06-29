#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

ha_xpath = "<show><high-availability><all></all></high-availability></show>&key" \
           "=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0" \
           "srNERUQT09"

ha_req = requests.get(prefix + ha_xpath, verify=False)
ha_xml = et.fromstring(ha_req.content)


# Checking for existance of xpath:
# if ha_xml.find('./result/group/peer-info/conn-ha22-backup/conn-status'):
#     print 'found!!' (assign value)
# else:
#     print 'NOT FOUND' (skip)


cfg_sync = ha_xml.find('./result/group/running-sync').text
print cfg_sync
ha_enabled = ha_xml.find('./result/enabled').text
print ha_enabled
ha1_prime_conn = ha_xml.find('./result/group/peer-info/conn-ha1/conn-status').text
print ha1_prime_conn
ha1_back_conn = ha_xml.find('./result/group/peer-info/conn-ha1-backup/conn-status').text
print ha1_back_conn
ha2_prime_conn = ha_xml.find('./result/group/peer-info/conn-ha2/conn-status').text
print ha2_prime_conn
#TODO: Management link state - './result/group/peer-info/conn-status'?
ha2_back_conn = ha_xml.find('./result/group/peer-info/conn-ha2-backup/conn-status').text
print ha2_back_conn
ha3_conn = ha_xml.find('./result/group/peer-info/conn-ha3/conn-status').text
#TODO: API call for 'last-error-reason'




