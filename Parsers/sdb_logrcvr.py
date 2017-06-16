#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import re
import pudb

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

prefix = "https://10.3.4.61/api/?type=op&cmd="

"""

All of the following can use this parser:

sw.logrcvr.autotag_avg_send_rate
sw.logrcvr.autotag_sent_count
sw.logrcvr.autotag_drop_count
sw.logrcvr.http_avg_send_rate
sw.logrcvr.http_sent_count
sw.logrcvr.http_drop_count
sw.logrcvr.raw_avg_send_rate
sw.logrcvr.raw_sent_count
sw.logrcvr.raw_drop_count
sw.logrcvr.email_avg_send_rate
sw.logrcvr.email_sent_count
sw.logrcvr.email_drop_count
sw.logrcvr.snmp_avg_send_rate
sw.logrcvr.snmp_sent_count
sw.logrcvr.snmp_drop_count
sw.logrcvr.syslog_avg_send_rate
sw.logrcvr.syslog_sent_count
sw.logrcvr.syslog_drop_count

"""


fwd_xpath = "<show><system><state><filter>sw.logrcvr.raw_avg_send_rate</filte" \
                  "r></state></system></show>&key=LUFRPT1SdzlWUXE0R0xBQTZTejBkb" \
                  "WJ4OVVvYWFxc0U9OC9kRkpwMWZhUTY2emNrZ3hLaTRSNFBmM0hVdDdMeGlnW" \
                  "HE2UHJ3WXFMbz0="

fwd_req = requests.get(prefix + fwd_xpath, verify=False)
fwd_xml = et.fromstring(fwd_req.content)
fwd_text = fwd_xml.find('./result').text
fwd_text = fwd_text[fwd_text.find(': ') + 2:]
print fwd_text

