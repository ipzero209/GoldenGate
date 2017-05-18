#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>sw.comm.s*.dp*.session-info</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


# Slot/DP match criteria for session-info node
match_ps_slot = re.compile('(?<=comm\.s)(.*)(?=\.dp)')
match_ps_dp = re.compile('(?<=\.dp)(.*)(?=\.session)')

# Match criteria for json formatting
match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')

ps_req = requests.get(prefix + xpath, verify=False)
ps_xml = et.fromstring(ps_req.content)
ps_text = ps_xml.find('./result').text
if ps_text is None:
    print "No CPS/PPS data"
else:
    ps_text = ps_text.split('\n')

for line in ps_text:
    if line == "":
        break
    label = line[:line.find('{')]
    ps_slot_number = re.search(match_ps_slot, label).group(0)
    ps_dp_number = re.search(match_ps_dp, label).group(0)
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ':"', line)
    line = re.sub(match_end, '",', line)
    line = re.sub(match_end_2, '"', line)
    j_line = json.loads(line)
    print j_line['cps'] + "\t" + j_line['pps']