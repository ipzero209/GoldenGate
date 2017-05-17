#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.stats.session</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


# Slot/DP match criteria
match_session_slot = re.compile('(?<=mprelay\.s)(.*)(?=\.dp)')
match_session_dp = re.compile('(?<=\.dp)(.*)(?=\.stats)')


session_req = requests.get(prefix + xpath, verify=False)
session_xml = et.fromstring(session_req.content)
session_text = session_xml.find('./result').text
session_text = session_text.split('\n')


for line in session_text:
    if line == "":
        break
    label = line[:line.find('{')]
    session_slot_number = re.search(match_session_slot, label).group(0)
    session_dp_number = re.search(match_session_dp, label).group(0)
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    j_line = json.loads(line)
    # print "s" + session_slot_number + "dp" + session_dp_number + ":\t\t" + str(j_line['session_util'])
    print j_line
    print "\n\n"