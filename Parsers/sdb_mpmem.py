#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>resource.s*.mp.memory</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


mp_mem_req = requests.get(prefix + xpath, verify=False)
mp_mem_xml = et.fromstring(mp_mem_req.content)
mp_mem_text = mp_mem_xml.find('./result').text
mp_mem_text = mp_mem_text[mp_mem_text.find('{'):]
mp_mem_text = mp_mem_text.replace('\'', '"')
mp_mem_text = mp_mem_text.replace(', }', ' }')

match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')
num_quote = re.compile('(?=, )')
mp_mem_text = re.sub(match_begin, ': "', mp_mem_text)
mp_mem_text = re.sub(match_end_2, '"', mp_mem_text)
mp_mem_text = re.sub(num_quote, '"', mp_mem_text)
j_line = json.loads(mp_mem_text)
print j_line