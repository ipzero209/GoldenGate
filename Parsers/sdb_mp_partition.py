#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re
import pudb

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

partition_xpath = "<show><system><state><filter>resource.s*.mp.partition</filte" \
                  "r></state></system></show>&key=LUFRPT1SdzlWUXE0R0xBQTZTejBkb" \
                  "WJ4OVVvYWFxc0U9OC9kRkpwMWZhUTY2emNrZ3hLaTRSNFBmM0hVdDdMeGlnW" \
                  "HE2UHJ3WXFMbz0="



match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')
match_brace = re.compile('(?<=[A-Za-z0-9]) }')


part_req = requests.get(prefix + partition_xpath, verify=False)
part_xml = et.fromstring(part_req.content)
part_text = part_xml.find('./result').text


# print part_text

line = part_text[part_text.find('{'):]
line = line.replace('\'', '"')
line = line.replace(', }', ' }')
line = re.sub(match_begin, ':"', line)
line = re.sub(match_end, '",', line)
line = re.sub(match_brace, '" }', line)
line = line.replace('}"', '}')
j_line = json.loads(line)

print j_line

