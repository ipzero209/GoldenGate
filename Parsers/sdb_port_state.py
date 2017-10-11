#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.5.138/api/?type=op&cmd="

state_xpath = "<show><system><state><filter>sw.dev.runtime.ifmon.port-states</f" \
              "ilter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpne" \
              "mh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"




match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
#match_end_2 = re.compile(' (?=[0-9a-zA-Z])')
match_brace = re.compile('(?<=[A-Za-z0-9]) }')


state_req = requests.get(prefix + state_xpath, verify=False)
state_xml = et.fromstring(state_req.content)
state_text = state_xml.find('./result').text
if state_text is None:
    print "No port state data"
else:
    state_text = state_text.split('\n')


line = state_text[0]
line = line[line.find('{'):]
line = line.replace('\'', '"')
line = line.replace(', }', ' }')
line = re.sub(match_begin, ':"', line)
line = re.sub(match_end, '",', line)
# line = re.sub(match_end_2, '"', line)
line = re.sub(match_brace, '" }', line)
line = line.replace('}"', '}')
j_line = json.loads(line)

for key in j_line:
    if j_line[key]['link'] == "Up":
        p_status = 1
    else:
        p_status = 0




