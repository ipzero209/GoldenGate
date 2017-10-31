#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re
import pudb

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.8.49.29/api/?type=op&cmd="

ps_xpath = "<show><system><state><filter>env.s*.power-supply.*</filter><" \
            "/state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh" \
            "0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_brace = re.compile('(?= })')

match_power_slot = re.compile('(?<=env\.s)(.*)(?=\.power-supply)')
match_power_number = re.compile('(?<=supply\.)(.*)(?=:)')


ps_req = requests.get(prefix + ps_xpath, verify=False)
ps_text = ps_req.content
ps_text = ''.join([i if ord(i) < 128 else '0' for i in ps_text])
ps_xml = et.fromstring(ps_text)
ps_text = ps_xml.find('./result').text
if ps_text is None:
    print "No power supply data"
else:
    ps_text = ps_text.split('\n')



for line in ps_text:
    if line == "":
        break
    label = line[:line.find('{')]
    power_slot = re.search(match_power_slot, label).group(0)
    power_number = re.search(match_power_number, label).group(0)
    p_string = "power{}/{}".format(str(power_slot), str(power_number))
    print p_string

    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ':"', line)
    line = re.sub(match_end, '",', line)
    line = re.sub(match_brace, '"', line)
    line = line.replace(': ",', ': "",')
    line = line.replace(': " ', ': "" ')
    j_line = json.loads(line)
    # print j_line