#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>sys.monitor.s*.dp*.exports</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


dp_cpu_req = requests.get(prefix + xpath, verify=False)
dp_cpu_xml = et.fromstring(dp_cpu_req.content)
dp_cpu_text = dp_cpu_xml.find('./result').text
dp_cpu_text = dp_cpu_text.split('\n')

for line in dp_cpu_text:
	if line == "":
		break
	line = line[line.find('{'):]
	line = line.replace('\'', '"')
	line = line.replace(', }', ' }')
	j_line = json.loads(line)
	print j_line
