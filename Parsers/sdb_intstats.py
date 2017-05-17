#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>net.s*.eth*.stats</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


rate_req = requests.get(prefix + xpath, verify=False)
rate_xml = et.fromstring(rate_req.content)
rate_text = rate_xml.find('./result').text

rate_text = rate_text.split('\n')

for resp_string in rate_text:
	# print resp_string
	# print "\n\n"
	resp_string = resp_string[resp_string.find('{'):]
	resp_string = resp_string.replace('\'', '"')
	resp_string = resp_string.replace(', }', ' }')
	# resp_string = resp_string.replace('{ }', '\"\"')


	match_begin = re.compile(': (?=[0-9a-fA-Z])')
	match_end = re.compile(',(?= ")')
	match_end_2 = re.compile(' (?=})')
	resp_string = re.sub(match_begin, ': "', resp_string)
	resp_string = re.sub(match_end, '", ', resp_string)
	resp_string = re.sub(match_end_2, '"', resp_string)
	resp_string = resp_string.replace('"""', '""')
	resp_string = resp_string.replace('}"', '}')
	resp_string = resp_string.replace('{"}', '{ }')
	print resp_string + "\n\n"
	j_line = json.loads(resp_string)
	print j_line
	test = raw_input("Continue")
	
