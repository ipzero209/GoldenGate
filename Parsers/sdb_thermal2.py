#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re
import ast

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



# Works for:
#
# 200
# 5200

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.8.49.11/api/?type=op&cmd="

xpath = "<show><system><state><filter>env.s*.thermal.*</filter></state></syste" \
        "m></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVh" \
        "RlNiY0dCR0srNERUQT09"

# Slot/Sensor match criteria

match_therm_slot = re.compile('(?<=env\.s)(.*)(?=\.therm)')
match_therm_sensor = re.compile(('(?<=mal\.)(.*)(?=:)'))

# Match criteria for JSON formatting
match_begin = re.compile(': (?=[A-Z0-9\-])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')
match_wonk = re.compile('[0-9]\](?=,)')

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
    line = line.replace(']"', ']')
    line = re.sub(match_end_2, '" ', line)
    line = re.sub(match_wonk, '"', line)
    # print line
    line_dict = ast.literal_eval(line)
    print line_dict
