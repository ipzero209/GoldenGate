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

xpath = "<show><system><state><filter>env.s*.thermal.*</filter></state></syste" \
        "m></show>&key=LUFRPT1SdzlWUXE0R0xBQTZTejBkbWJ4OVVvYWFxc0U9OC9kRkpwMWZ" \
        "hUTY2emNrZ3hLaTRSNFBmM0hVdDdMeGlnWHE2UHJ3WXFMbz0="

# Slot/Sensor match criteria

match_therm_slot = re.compile('(?<=env\.s)(.*)(?=\.therm)')
match_therm_sensor = re.compile(('(?<=mal\.)(.*)(?=:)'))

# Match criteria for JSON formatting
match_begin = re.compile(': (?=[A-Z0-9\-])')
match_end = re.compile(',(?= ")')


therm_req = requests.get(prefix + xpath, verify=False)
therm_xml = et.fromstring(therm_req.content)
therm_text = therm_xml.find('./result').text
if therm_text == None:
    print "No thermal data"
else:
    therm_text = therm_text.split('\n')

for line in therm_text:
    if line == "":
        break
    label = line[:line.find('{')]
    therm_slot_number = re.search(match_therm_slot, label).group(0)
    therm_sensor_number = re.search(match_therm_sensor, label).group(0)
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = line.replace(', ]', ' ]')
    line = re.sub(match_begin, ': "', line)
    line = re.sub(match_end, '", ', line)
    line_dict = ast.literal_eval(line)
    print line_dict['desc']
