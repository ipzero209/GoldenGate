#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

xpath = "<show><system><state><filter>sw.mgmt.runtime.lograte</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


# Note 1: This is for 8.0 devices ONLY
# Note 2: This SDB node doesn't exist on VM platforms

lograte_req = requests.get(prefix + xpath, verify=False)
lograte_xml = et.fromstring(lograte_req.content)
lograte_text = lograte_xml.find('./result').text
lograte_text = lograte_text[lograte_text.find(':'):]
lograte_text = lograte_text[2:]
print lograte_text