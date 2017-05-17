#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
import ast


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>env.s*.fan.*</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


rate_req = requests.get(prefix + xpath, verify=False)
rate_xml = et.fromstring(rate_req.content)
rate_text = rate_xml.find('./result').text
# print rate_text


match_end = re.compile(',(?= ")')

rate_text = rate_text.split('\n')

for resp_string in rate_text:
	if resp_string == "":
		break
	resp_string = resp_string[resp_string.find('{'):] # Need to pull the slot/fan# for the line before here.
	resp_string = resp_string.replace('\'', '"')
	resp_string = resp_string.replace(', }', ' }')
	resp_string = resp_string.replace(', ]', ' ]')
	match_begin = re.compile(': (?=[0-9a-fA-Z])')
	resp_string = re.sub(match_begin, ': "', resp_string)
	resp_string = re.sub(match_end, '", ', resp_string)
	resp_dict = ast.literal_eval(resp_string)
	# print resp_dict["avg"] + "\n==========================\n" # At this point, the sdb node is a dict. You can pull the sub nodes using resp_dict["key"]
	print resp_dict







	
