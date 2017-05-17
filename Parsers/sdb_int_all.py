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

# NOTE: Rate is only supported on 8.0 and later.

rate_xpath = "<show><system><state><filter>sys.s*.p*.rate</filter></state></sy" \
             "stem></show>&key=LUFRPT1SdzlWUXE0R0xBQTZTejBkbWJ4OVVvYWFxc0U9OC9" \
             "kRkpwMWZhUTY2emNrZ3hLaTRSNFBmM0hVdDdMeGlnWHE2UHJ3WXFMbz0="
stats_xpath = "<show><system><state><filter>net.s*.eth*.stats</filter></state>" \
              "</system></show>&key=LUFRPT1SdzlWUXE0R0xBQTZTejBkbWJ4OVVvYWFxc0" \
              "U9OC9kRkpwMWZhUTY2emNrZ3hLaTRSNFBmM0hVdDdMeGlnWHE2UHJ3WXFMbz0="

match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')

# Slot/int match criteria for rate node
match_rate_slot = re.compile('(?<=sys\.s)(.*)(?=\.p)')
match_rate_interface = re.compile('(?<=\.p)(.*)(?=\.rate)')

# Slot/int match criteria for stats node
match_stats_slot = re.compile('(?<=net\.s)(.*)(?=\.eth)')
match_stats_interface = re.compile('(?<=\.eth)(.*)(?=\.stats)')

rate_req = requests.get(prefix + rate_xpath, verify=False)
rate_xml = et.fromstring(rate_req.content)
rate_text = rate_xml.find('./result').text
if rate_text is None:
    print "No rate data"
else:
    rate_text = rate_text.split('\n')

int_dict = {}

rate_dict = {}
stats_dict = {}

# NOTE: Only for 8.0 devices
# TODO: Check OS version
for line in rate_text:
    if line == "":
        break
    label = line[:line.find('{')]
    rate_slot_number = re.search(match_rate_slot, label).group(0)
    rate_int_number = re.search(match_rate_interface, label).group(0)
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ':"', line)
    line = re.sub(match_end, '",', line)
    line = re.sub(match_end_2, '"', line)
    j_line = json.loads(line)
    if rate_slot_number not in int_dict:
        int_dict[rate_slot_number] = {rate_int_number : {'txb' : j_line['tx-bytes']}}
        int_dict[rate_slot_number][rate_int_number]['rxb'] = j_line['rx-bytes']
        # print int_dict
    else:
        int_dict[rate_slot_number][rate_int_number] = {'txb' : j_line['tx-bytes']}
        int_dict[rate_slot_number][rate_int_number]['rxb'] = j_line['rx-bytes']

    # dict_key = rate_slot_number + "/" + rate_int_number
    # rate_dict[dict_key] = label

# Code for label generation

# for key in int_dict:
#     slot = int_dict[key]
#     for sub_key in slot:
#         print "ethernet" + key + "/" + sub_key



stats_req = requests.get(prefix + stats_xpath, verify=False)
stats_xml = et.fromstring(stats_req.content)
stats_text = stats_xml.find('./result').text
if stats_text == None:
    print "No status info"
stats_text = stats_text.split('\n')


for line in stats_text:
    if line == "":
        break
    label = line[:line.find('{')]
    stats_slot_number = re.search(match_stats_slot, label).group(0)
    stats_int_number = re.search(match_stats_interface, label).group(0)
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    j_line = json.loads(line)
    if stats_slot_number not in int_dict:
        int_dict[stats_slot_number] = {stats_int_number : {'txe' : j_line['tx-errs']}}
        int_dict[stats_slot_number][stats_int_number]['rxe'] = j_line['rx-errs']
    elif stats_slot_number in int_dict and stats_int_number not in int_dict[stats_slot_number]:
        int_dict[stats_slot_number][stats_int_number] = {'txe' : j_line['tx-errs']}
        int_dict[stats_slot_number][stats_int_number]['rxe'] = j_line['rx-errs']
    else:
        int_dict[stats_slot_number][stats_int_number]['txe'] = j_line['tx-errs']
        int_dict[stats_slot_number][stats_int_number]['rxe'] = j_line['rx-errs']


update_string = ""
for key in int_dict:
    slot = int_dict[key]
    for sub_key in slot:
        update_string = update_string + "ethernet" + key + "/" + sub_key + str(slot[sub_key])

print update_string



# print rate_dict
# print "\n\n\n\n"
# print stats_dict


# for item in rate_dict:
#     print rate_dict[item]
#
# for item in stats_dict:
#     print rate_dict[item]