#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.8.49.29/api/?type=op&cmd="



err_xpath = "<show><system><state><filter>sys.s*.p*.detail</filter></state></sy" \
            "stem></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM" \
            "3JHUGVhRlNiY0dCR0srNERUQT09"



match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')
num_quote = re.compile('(?=, )')

match_err_slot = re.compile('(?<=sys\.s)(.*)(?=\.p)')
match_err_interface = re.compile('(?<=\.p)(.*)(?=\.detail)')




err_req = requests.get(prefix + err_xpath, verify=False)
err_req_xml = et.fromstring(err_req.content)
err_text = err_req_xml.find('./result').text

if err_text is None:
    print "No error data"
else: err_text = err_text.split('\n')

for line in err_text:
    if line == "":
        break
    label = line[:line.find('{')]
    err_slot_number = re.search(match_err_slot, label).group(0)
    err_int_number = re.search(match_err_interface, label).group(0)
    line = line[line.find('{'):]
    if len(line) == 3:
        pass
    else:
        line = line[line.find('{'):]
        line = line.replace('\'', '"')
        line = line.replace(', }', ' }')
        line = re.sub(match_begin, ': "', line)
        line = re.sub(num_quote, '"', line)
        line = re.sub(match_end_2, '"', line)
        j_line = json.loads(line)
        print j_line
        break