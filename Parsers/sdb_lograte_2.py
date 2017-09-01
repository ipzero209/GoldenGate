#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.5.143/api/?type=op&cmd="

xpath = "<show><system><state><filter>sw.logrcvr.runtime.write-lograte</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

# Note: Used for pre-8.0 and VM devices

lograte_req = requests.get(prefix + xpath, verify=False)
lograte_xml = et.fromstring(lograte_req.content)
lograte_text = lograte_xml.find('./result').text
lograte_text = lograte_text[lograte_text.find(':'):]
lograte_text = lograte_text[2:]
print lograte_text