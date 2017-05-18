#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>sys.monitor.s*.mp.exports</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


mp_cpu_req = requests.get(prefix + xpath, verify=False)
mp_cpu_xml = et.fromstring(mp_cpu_req.content)
mp_cpu_text = mp_cpu_xml.find('./result').text
mp_cpu_text = mp_cpu_text[mp_cpu_text.find('{'):]
mp_cpu_text = mp_cpu_text.replace('\'', '"')
mp_cpu_text = mp_cpu_text.replace(', }', ' }')
j_line = json.loads(mp_cpu_text)
print j_line["cpu"]["1minavg"]