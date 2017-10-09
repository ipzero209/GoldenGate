#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
import ast


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.8.49.29/api/?type=op&cmd="

xpath = "<show><system><state><filter>env.s*.fan.*</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

match_end = re.compile(',(?= ")')
match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_fan_slot = re.compile('(?<=env\.s)(.*)(?=\.fan)')
match_fan_number = re.compile('(?<=fan\.)(.*)(?=:)')
rate_req = requests.get(prefix + xpath, verify=False)
rate_xml = et.fromstring(rate_req.content)
rate_text = rate_xml.find('./result').text
# print rate_text



rate_text = rate_text.split('\n')

for resp_string in rate_text:
	if resp_string == "":
		break
	label = resp_string[:resp_string.find('{')]
	print label
	fan_slot_number = re.search(match_fan_slot, label).group(0)
	fan_number = re.search(match_fan_number, label).group(0)
	print fan_slot_number
	print fan_number
	resp_string = resp_string[resp_string.find('{'):] # Need to pull the slot/fan# for the line before here.
	resp_string = resp_string.replace('\'', '"')
	resp_string = resp_string.replace(', }', ' }')
	resp_string = resp_string.replace(', ]', ' ]')
	resp_string = re.sub(match_begin, ': "', resp_string)
	resp_string = re.sub(match_end, '", ', resp_string)
	j_line = ast.literal_eval(resp_string)
	print j_line
	# print resp_dict["avg"] + "\n==========================\n" # At this point, the sdb node is a dict. You can pull the sub nodes using resp_dict["key"]


