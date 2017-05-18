#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.packetbuffers</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


# Slot/DP match criteria
match_pkt_slot = re.compile('(?<=relay\.s)(.*)(?=\.dp)')
match_pkt_dp = re.compile('(?<=\.dp)(.*)(?=\.packet)')

# Match criteria for JSON formatting
match_begin = re.compile(': (?=[a-zA-Z])')
match_end = re.compile('(?<=[a-z]),')
match_end_2 = re.compile(' (?=})')


pkt_req = requests.get(prefix + xpath, verify=False)
pkt_xml = et.fromstring(pkt_req.content)
pkt_text = pkt_xml.find('./result').text
pkt_text = pkt_text.split('\n')

for line in pkt_text:
    if line == "":
        break
    label = line[:line.find('{')]
    pkt_slot_number = re.search(match_pkt_slot, label).group(0)
    pkt_dp_number = re.search(match_pkt_dp, label).group(0)
    print "slot: " + pkt_slot_number + "\tdp: " + pkt_dp_number
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ':"', line)
    line = re.sub(match_end, '", ', line)
    # line = re.sub(match_end_2, '"', line)
    j_line = json.loads(line)
    print "s" + pkt_slot_number + "dp" + pkt_dp_number
    print "hwbuff:\t\tUSED\t\tTOTAL"
    print "\t\t" + str(j_line['hw-buf']['used']) + "\t\t" + str(j_line['hw-buf']['max'])
    # print "swbuff:\t" + str(j_line['sw-buf'])