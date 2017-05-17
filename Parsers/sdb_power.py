#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re
import ast

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>env.s*.power.*</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

# Slot/Rail match criteria
pwr_slot_match = re.compile('(?<=env\.s)(.*)(?=\.power)')
pwr_rail_match = re.compile('(?<=power\.)(.*)(?=:)')

# Match criteria for JSON formatting
match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')


pwr_req = requests.get(prefix + xpath, verify=False)
pwr_xml = et.fromstring(pwr_req.content)
pwr_text = pwr_xml.find('./result').text
if pwr_text is None:
    print "No power data"
else:
    pwr_text = pwr_text.split('\n')

for line in pwr_text:
    if line == "":
        break
    label = line[:line.find('{')]
    pwr_slot_number = re.search(pwr_slot_match, label).group(0)
    pwr_rail_number = re.search(pwr_rail_match, label).group(0)
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ': "', line)
    line = re.sub(match_end, '", ', line)
    pwr_dict = ast.literal_eval(line)
    print "s" + pwr_slot_number + "r" + pwr_rail_number + " alarm state: " + pwr_dict['alarm']
    # print pwr_dict['alarm']