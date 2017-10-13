#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.8.49.20/api/?type=op&cmd="

raid_xpath = "<show><system><state><filter>sys.raid.s*.ld*.drives</filter></sta" \
             "te></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6T" \
             "GM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"



match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')

match_raid_slot = re.compile('(?<=raid\.s)(.*)(?=\.ld)')
match_raid_ld = re.compile('(?<=\.ld)(.*)(?=\.drives)')

raid_req = requests.get(prefix + raid_xpath, verify=False)
raid_xml = et.fromstring(raid_req.content)
raid_text = raid_xml.find('./result').text


if raid_text is None:
    print "No RAID data"
else:
    raid_text = raid_text.split('\n')

for line in raid_text:
    if line == "":
        break
    label = line[:line.find('{')]
    raid_slot_number = re.search(match_raid_slot, label).group(0)
    raid_ld_number = re.search(match_raid_ld, label).group(0)
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ':"', line)
    line = re.sub(match_end, '",', line)
    line = re.sub(match_end_2, '"', line)
    line = line.replace('}"', '} ')
    j_line = json.loads(line)
    print j_line
    exit(0)

