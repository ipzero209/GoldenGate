#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>sys.s*.p*.rate</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


rate_req = requests.get(prefix + xpath, verify=False)
rate_xml = et.fromstring(rate_req.content)
rate_text = rate_xml.find('./result').text
rate_text = rate_text.split('\n')

match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')
match_slot = re.compile('(?<=sys\.s)(.*)(?=\.p)')
match_interface = re.compile('(?<=\.p)(.*)(?=\.rate)')
int_label = "ethernet"
for line in rate_text:
    if line == "":
        break
    label = line[:line.find('{')]
    slot_number = re.search(match_slot, label).group(0)
    # print slot_number
    print label
    int_number = re.search(match_interface, label).group(0)
    node_label = int_label + slot_number + "/" + int_number
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ':"', line)
    line = re.sub(match_end, '",', line)
    line = re.sub(match_end_2, '"', line)
    j_line = json.loads(line)
    txb = j_line['tx-bytes']
    rxb = j_line['rx-bytes']
    node_string = "\"" + node_label + "\":{\"txb\":" + txb + ",\"rxb\":" + rxb + "}"
    # print node_string


xpath_2 = "<show><system><state><filter>net.s*.eth*.stats</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

stats_req = requests.get(prefix + xpath_2, verify=False)
stats_xml = et.fromstring(stats_req.content)
stats_text = stats_xml.find('./result').text

stats_text = stats_text.split('\n')

for line in stats_text:
    if line == "":
        break
    label = line[:line.find('{')]
    slot_number = re.search(match_slot, label)
    # print slot_number
    print label
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    # print line + "\n"
    j_line = json.loads(line)
    # print j_line['rx-errs']
    print "\n\n\n\n"
